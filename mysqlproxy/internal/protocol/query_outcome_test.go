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

	"github.com/mysqlproxy/internal/interceptor"
	"github.com/mysqlproxy/internal/session"
	"github.com/mysqlproxy/internal/shaper"
)

func TestQueryOutcomeMetadata(t *testing.T) {
	cases := []struct {
		name, sql, mode, authority, code, state, strategy, profile string
		success, trap, unavailable, policy, rowError               bool
	}{
		{name: "backend_success", sql: "SELECT * FROM ordinary", mode: "passthrough", authority: "backend", success: true},
		{name: "backend_error", sql: "SELECT * FROM ordinary", mode: "passthrough", authority: "backend", code: "mysql_1146", state: "42S02"},
		{name: "backend_row_error", sql: "SELECT * FROM ordinary", mode: "passthrough", authority: "backend", code: "mysql_1146", state: "42S02", rowError: true},
		{name: "unsupported_passthrough", sql: "SELECT 1", authority: "backend", success: true},
		{name: "deception_fake", sql: "SELECT * FROM employees", mode: "fake", authority: "deception", success: true, strategy: "D1", profile: "fake_table_data"},
		{name: "deception_block", sql: "SELECT * FROM employees", mode: "block", authority: "deception", code: "mysql_1146", state: "42S02", strategy: "D1", profile: "fake_schema"},
		{name: "deception_default_error", sql: "SELECT * FROM employees", mode: "block", authority: "deception", code: "mysql_1064", state: "42000"},
		{name: "trap", sql: "SELECT * FROM api_keys_backup", mode: "fake", authority: "deception", success: true, strategy: "D3", profile: "high_value_target", trap: true},
		{name: "unavailable_fallback", sql: "SELECT * FROM ordinary", authority: "backend", success: true, unavailable: true},
		{name: "policy_block", sql: "SELECT 1", authority: "policy", code: "mysql_1045", state: "28000", policy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.unavailable {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				code, state := 1146, tc.state
				if tc.name == "deception_default_error" {
					code, state = 0, ""
				}
				json.NewEncoder(w).Encode(map[string]interface{}{
					"mode": tc.mode, "columns": []string{"id"}, "rows": []map[string]interface{}{{"id": 1}},
					"strategy_id": tc.strategy, "profile": tc.profile, "is_trap": tc.trap, "error_code": code, "sqlstate": state,
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
			h := NewHandler(proxyClient, proxyBackend, logger, "", 0, in, nil)
			h.sess = session.New("192.0.2.1:1234")
			if tc.policy {
				h.shaper.AddRule(shaper.Rule{Fingerprint: "", Block: true})
			}
			go func() {
				peer := &Handler{}
				if _, err := peer.readPacket(backend); err != nil {
					return
				}
				if tc.success {
					peer.sendPacket(backend, []byte{0, 0, 0, 2, 0, 0, 0}, 1)
					return
				}
				seq := byte(1)
				if tc.rowError {
					for _, p := range [][]byte{{1}, []byte("column"), mysqlEOFPacket()} {
						if peer.sendPacket(backend, p, seq) != nil {
							return
						}
						seq++
					}
				}
				peer.sendPacket(backend, shaper.BuildErrPacket(1146, "42S02", "synthetic failure"), seq)
			}()
			done := make(chan error, 1)
			go func() { done <- h.commandLoop(context.Background()) }()
			peer := &Handler{}
			if err := peer.sendPacket(client, append([]byte{comQuery}, []byte(tc.sql)...), 0); err != nil {
				t.Fatal(err)
			}
			wireCode, wireState := "", ""
			eofCount := 0
			for {
				p, err := peer.readPacket(client)
				if err != nil {
					t.Fatal(err)
				}
				if p[0] == packetERR {
					wireCode, wireState = mysqlErrorCode(p), mysqlSQLState(p)
					break
				}
				if p[0] == packetOK {
					break
				}
				if p[0] == packetEOF && len(p) < 9 {
					eofCount++
					if eofCount == 2 {
						break
					}
				}
			}
			select {
			case event := <-in.Events():
				if !event.OutcomeVerified || event.Success != tc.success || event.Authority != tc.authority || event.ErrorCode != tc.code || event.ErrorCode != wireCode || event.SQLState != tc.state || event.SQLState != wireState || event.StrategyID != tc.strategy || event.DeceptionProfile != tc.profile || event.IsTrap != tc.trap {
					t.Fatalf("wrong event: %+v; wire=%s/%s", event, wireCode, wireState)
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

func TestMySQLUnknownErrorMetadata(t *testing.T) {
	if mysqlErrorCode([]byte{packetERR}) != "" || mysqlSQLState([]byte{packetERR, 1, 0}) != "" {
		t.Fatal("invented unavailable error metadata")
	}
}
