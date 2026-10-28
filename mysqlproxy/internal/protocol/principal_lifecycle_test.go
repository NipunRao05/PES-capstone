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
)

// Exercise real Run deferred cleanup; the registry's durable discard/restore
// semantics are tested separately through the actual engine end route.
func TestPrincipalRunDisconnectCleanup(t *testing.T) {
	for _, ending := range []string{"quit", "eof", "auth_failure"} {
		t.Run(ending, func(t *testing.T) {
			calls := make(chan string, 8)
			ids := make(chan string, 8)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				ids <- body["session_id"].(string)
				calls <- r.URL.Path
				switch r.URL.Path {
				case "/principals/native-auth":
					if ending == "auth_failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					w.Write([]byte(`{"deceptive_principal_id":"DP-fixture"}`))
				case "/principals/query":
					calls <- body["sql"].(string)
					w.Write([]byte(`{"mode":"fake","command_tag":"UPDATE","tx_status":"T"}`))
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
			backendDone := make(chan error, 1)
			go func() {
				peer := &Handler{}
				greeting := append([]byte{10}, []byte("8.0.32\x00")...)
				greeting = append(greeting, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0x08, 0x82, 0x21, 2, 0, 0x08, 0, 21)
				greeting = append(greeting, make([]byte, 10)...)
				greeting = append(greeting, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0)
				greeting = append(greeting, []byte("mysql_native_password\x00")...)
				if err := peer.sendPacket(backend, greeting, 0); err != nil {
					backendDone <- err
					return
				}
				// The proxy must close without forwarding synthetic credentials/SQL.
				var b [1]byte
				_, err := backend.Read(b[:])
				backendDone <- err
			}()
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0, nil, nil)
			done := make(chan error, 1)
			go func() { done <- h.Run(context.Background()); proxyClient.Close() }()
			peer := &Handler{}
			if _, err := peer.readPacket(client); err != nil {
				t.Fatal(err)
			}
			handshake := make([]byte, 32)
			handshake[0], handshake[1], handshake[2] = 0x08, 0x82, 0x08
			handshake = append(handshake, []byte("fake_fixture\x00")...)
			handshake = append(handshake, 20)
			handshake = append(handshake, make([]byte, 20)...)
			handshake = append(handshake, []byte("testdb\x00")...)
			if err := peer.sendPacket(client, handshake, 1); err != nil {
				t.Fatal(err)
			}
			pkt, err := peer.readPacket(client)
			if err != nil {
				t.Fatal(err)
			}
			if (pkt[0] == packetERR) != (ending == "auth_failure") {
				t.Fatal("unexpected authentication outcome")
			}
			if ending != "auth_failure" {
				for _, sql := range []string{"BEGIN", "UPDATE employees SET salary=12345 WHERE id=1"} {
					if err := peer.sendPacket(client, append([]byte{comQuery}, []byte(sql)...), 0); err != nil {
						t.Fatal(err)
					}
					pkt, err := peer.readPacket(client)
					if err != nil {
						t.Fatal(err)
					}
					if status, ok := mysqlStatusFlags(pkt); !ok || status&1 == 0 {
						t.Fatal("pending transaction flag lost")
					}
				}
				if ending == "quit" {
					if err := peer.sendPacket(client, []byte{comQuit}, 0); err != nil {
						t.Fatal(err)
					}
				} else {
					client.Close()
				}
			}
			if err := <-done; (err != nil) != (ending == "auth_failure") {
				t.Fatalf("Run error=%v", err)
			}
			if err := <-backendDone; err != io.EOF {
				t.Fatalf("virtual traffic reached backend: %v", err)
			}
			want := []string{"/principals/native-auth", "/principals/query", "BEGIN",
				"/principals/query", "UPDATE employees SET salary=12345 WHERE id=1", "/principals/end"}
			if ending == "auth_failure" {
				want = []string{"/principals/native-auth", "/principals/end"}
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
		})
	}
}
