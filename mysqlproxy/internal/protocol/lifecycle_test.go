package protocol

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

// Exercise Run's ordering and deferred cleanup, not just Session setters.
func TestOrdinarySessionLifecycle(t *testing.T) {
	for _, name := range []string{"quit", "abrupt_disconnect", "idle_timeout", "wrong_password", "unknown_user", "disconnect_during_auth"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("MYSQL_DECOY_PASSWORD", "fixture-decoy-password")
			t.Setenv("MYSQL_RUNTIME_PASSWORD", "fixture-runtime-password")
			events := make(chan string, 8)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				events <- r.URL.Path
				w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, c := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
			}
			rejected := name == "wrong_password" || name == "unknown_user"
			go func() {
				peer := &Handler{}
				greeting := append([]byte{10}, []byte("8.0.32\x00")...)
				greeting = append(greeting, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0x08, 0x82, 0x21, 2, 0, 0x08, 0, 21)
				greeting = append(greeting, make([]byte, 10)...)
				greeting = append(greeting, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0)
				greeting = append(greeting, []byte("mysql_native_password\x00")...)
				if peer.sendPacket(backend, greeting, 0) != nil {
					return
				}
				if _, err := peer.readPacket(backend); err != nil {
					return
				}
				pkt := []byte{0, 0, 0, 2, 0, 0, 0}
				if rejected {
					pkt = []byte{0xff, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
				}
				if peer.sendPacket(backend, pkt, 2) != nil {
					return
				}
				if name == "quit" {
					peer.readPacket(backend)
				}
			}()
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 20*time.Millisecond, nil, nil)
			done := make(chan error, 1)
			go func() { done <- h.Run(context.Background()); proxyClient.Close() }()
			peer := &Handler{}
			if _, err := peer.readPacket(client); err != nil {
				t.Fatal(err)
			}
			if name == "disconnect_during_auth" {
				client.Close()
			} else {
				handshake := make([]byte, 32)
				handshake[0], handshake[1], handshake[2] = 0x08, 0x82, 0x08
				username := "proxyuser"
				if name == "unknown_user" {
					username = "unknown"
				}
				handshake = append(handshake, []byte(username)...)
				handshake = append(handshake, 0)
				proof := scrambleSHA1("fixture-decoy-password", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
				if name == "wrong_password" {
					proof[0] ^= 1
				}
				handshake = append(handshake, byte(len(proof)))
				handshake = append(handshake, proof...)
				handshake = append(handshake, []byte("testdb\x00")...)
				if err := peer.sendPacket(client, handshake, 1); err != nil {
					t.Fatal(err)
				}
				pkt, err := peer.readPacket(client)
				if err != nil {
					t.Fatal(err)
				}
				if (pkt[0] == packetERR) != rejected {
					t.Fatalf("authentication response=%v", pkt)
				}
				if name == "quit" {
					if err := peer.sendPacket(client, []byte{comQuit}, 0); err != nil {
						t.Fatal(err)
					}
				}
				if name == "abrupt_disconnect" {
					client.Close()
				}
			}
			err := <-done
			if (err != nil) != (rejected || name == "disconnect_during_auth") {
				t.Fatalf("Run error=%v", err)
			}
			var got []string
			for len(events) > 0 {
				got = append(got, <-events)
			}
			want := []string{"/session/start", "/session/end"}
			if rejected {
				want = []string{"/session/end"}
			}
			if name == "disconnect_during_auth" {
				want = nil
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("lifecycle=%v want %v", got, want)
			}
		})
	}
}
