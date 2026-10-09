package protocol

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/session"
	"github.com/pgproxy/internal/shaper"
)

func TestQueryOutcomeMetadata(t *testing.T) {
	cases := []struct {
		name, sql, mode, authority, code, strategy, profile string
		success, trap, unavailable, policy, aborted         bool
	}{
		{name: "backend_success", sql: "SELECT * FROM ordinary", mode: "passthrough", authority: "backend", success: true},
		{name: "backend_error", sql: "SELECT * FROM ordinary", mode: "passthrough", authority: "backend", code: "42P01"},
		{name: "unsupported_passthrough", sql: "SELECT 1", authority: "backend", success: true},
		{name: "deception_fake", sql: "SELECT * FROM employees", mode: "fake", authority: "deception", success: true, strategy: "D1", profile: "fake_table_data"},
		{name: "deception_block", sql: "SELECT * FROM employees", mode: "block", authority: "deception", code: "42501", strategy: "D1", profile: "fake_schema"},
		{name: "deception_default_error", sql: "SELECT * FROM employees", mode: "block", authority: "deception", code: "42601"},
		{name: "trap", sql: "SELECT * FROM api_keys_backup", mode: "fake", authority: "deception", success: true, strategy: "D3", profile: "high_value_target", trap: true},
		{name: "unavailable_fallback", sql: "SELECT * FROM ordinary", authority: "backend", success: true, unavailable: true},
		{name: "policy_block", sql: "SELECT 1", authority: "policy", code: "42501", policy: true},
		{name: "aborted_transaction", sql: "SELECT * FROM employees", authority: "policy", code: "25P02", aborted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.unavailable {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				code := tc.code
				if tc.name == "deception_default_error" {
					code = ""
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"mode": tc.mode, "columns": []string{"id"}, "rows": []map[string]interface{}{{"id": 1}},
					"strategy_id": tc.strategy, "profile": tc.profile, "is_trap": tc.trap, "sqlstate": code,
				})
			}))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL)
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, c := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
			}
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			in := interceptor.New(8)
			h := NewHandler(proxyClient, proxyBackend, logger, "", in, nil)
			h.sess = session.NewFromStartup(nil, "192.0.2.1:1234")
			h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(proxyClient), proxyClient)
			h.backendFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(proxyBackend), proxyBackend)
			if tc.policy {
				h.shaper.AddRule(shaper.Rule{Fingerprint: "", Block: true})
			}
			if tc.aborted {
				h.sess.SetTxStatus('E')
			}
			go func() {
				b := pgproto3.NewBackend(pgproto3.NewChunkReader(backend), backend)
				if _, err := b.Receive(); err != nil {
					return
				}
				if tc.success {
					b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				} else {
					b.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: tc.code, Message: "synthetic failure"})
				}
				b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			}()
			done := make(chan error, 1)
			go func() { done <- h.proxyLoop(context.Background()) }()
			front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
			if err := front.Send(&pgproto3.Query{String: tc.sql}); err != nil {
				t.Fatal(err)
			}
			wireCode := ""
			for {
				m, err := front.Receive()
				if err != nil {
					t.Fatal(err)
				}
				if e, ok := m.(*pgproto3.ErrorResponse); ok {
					wireCode = e.Code
				}
				if _, ok := m.(*pgproto3.ReadyForQuery); ok {
					break
				}
			}
			select {
			case event := <-in.Events():
				if !event.OutcomeVerified || event.Success != tc.success || event.Authority != tc.authority || event.ErrorCode != tc.code || event.ErrorCode != wireCode || event.StrategyID != tc.strategy || event.DeceptionProfile != tc.profile || event.IsTrap != tc.trap {
					t.Fatalf("wrong event: %+v; wire code=%s", event, wireCode)
				}
			case <-time.After(time.Second):
				t.Fatal("no query event")
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("proxy did not exit")
			}
		})
	}
}
