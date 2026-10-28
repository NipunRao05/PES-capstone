package protocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// Proof validation is covered by the Python registry suite. This test exercises
// the real Run/auth/query/EOF/deferred-end wiring with a stub registry service.
func TestPrincipalRunDisconnectCleanup(t *testing.T) {
	for _, ending := range []string{"terminate", "eof", "failed_eof", "auth_failure"} {
		t.Run(ending, func(t *testing.T) {
			calls := make(chan string, 16)
			ids := make(chan string, 16)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				ids <- body["session_id"].(string)
				calls <- r.URL.Path
				switch r.URL.Path {
				case "/principals/scram-start":
					if ending == "auth_failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					w.Write([]byte(`{"token":"fixture","server_first":"fixture"}`))
				case "/principals/scram-finish":
					w.Write([]byte(`{"deceptive_principal_id":"DP-fixture","server_final":"v=fixture"}`))
				case "/principals/query":
					calls <- body["sql"].(string)
					if body["sql"] == "SELECT invalid FROM employees" {
						w.Write([]byte(`{"mode":"block","sqlstate":"42601","tx_status":"E"}`))
					} else {
						w.Write([]byte(`{"mode":"fake","command_tag":"UPDATE 1","tx_status":"T"}`))
					}
				case "/principals/end":
					w.Write([]byte(`{"status":"ok"}`))
				default:
					t.Errorf("unexpected route %s", r.URL.Path)
				}
			}))
			defer srv.Close()
			t.Setenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, conn := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
			}
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
			done := make(chan error, 1)
			go func() { done <- h.Run(context.Background()); proxyClient.Close() }()
			front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
			if err := front.Send(&pgproto3.StartupMessage{ProtocolVersion: 196608,
				Parameters: map[string]string{"user": "fake_fixture", "database": "testdb"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := front.Receive(); err != nil {
				t.Fatal(err)
			}
			if err := front.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte("fixture")}); err != nil {
				t.Fatal(err)
			}
			if _, err := front.Receive(); err != nil {
				t.Fatal(err)
			}
			if ending != "auth_failure" {
				if err := front.Send(&pgproto3.SASLResponse{Data: []byte("fixture")}); err != nil {
					t.Fatal(err)
				}
				for {
					msg, err := front.Receive()
					if err != nil {
						t.Fatal(err)
					}
					if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
						break
					}
				}
				for _, sql := range []string{"BEGIN", "UPDATE employees SET salary=12345 WHERE id=1"} {
					if err := front.Send(&pgproto3.Query{String: sql}); err != nil {
						t.Fatal(err)
					}
					for {
						msg, err := front.Receive()
						if err != nil {
							t.Fatal(err)
						}
						if ready, ok := msg.(*pgproto3.ReadyForQuery); ok {
							if ready.TxStatus != 'T' {
								t.Fatal("pending state was lost")
							}
							break
						}
					}
				}
				if ending == "failed_eof" {
					if err := front.Send(&pgproto3.Query{String: "SELECT invalid FROM employees"}); err != nil {
						t.Fatal(err)
					}
					if _, err := front.Receive(); err != nil {
						t.Fatal(err)
					}
					msg, err := front.Receive()
					if err != nil {
						t.Fatal(err)
					}
					if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'E' {
						t.Fatalf("expected FAILED before disconnect, got %T", msg)
					}
				}
				if ending == "terminate" {
					if err := front.Send(&pgproto3.Terminate{}); err != nil {
						t.Fatal(err)
					}
				} else {
					client.Close()
				}
			}
			if err := <-done; (err != nil) != (ending == "auth_failure") {
				t.Fatalf("Run error=%v", err)
			}
			want := []string{"/principals/scram-start", "/principals/scram-finish",
				"/principals/query", "BEGIN", "/principals/query", "UPDATE employees SET salary=12345 WHERE id=1", "/principals/end"}
			if ending == "failed_eof" {
				want = append(want[:len(want)-1], "/principals/query", "SELECT invalid FROM employees", "/principals/end")
			}
			if ending == "auth_failure" {
				want = []string{"/principals/scram-start", "/principals/end"}
			}
			var got []string
			for len(calls) > 0 {
				got = append(got, <-calls)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("lifecycle=%v want %v", got, want)
			}
			for len(ids) > 0 {
				if id := <-ids; id != h.SessionID() || id == "" {
					t.Fatal("cleanup did not use authenticated session binding")
				}
			}
			// Virtual startup must never have reached the physical backend.
			var b [1]byte
			if n, err := backend.Read(b[:]); n != 0 || err != io.EOF {
				t.Fatal("virtual traffic reached backend")
			}
		})
	}
}
