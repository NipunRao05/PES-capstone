package protocol

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/session"
)

// An ordinary seeded session can stage fake DML and then fail a native query.
// PostgreSQL answers COMMIT in that failed transaction with a ROLLBACK tag.
// The session overlay must follow that outcome, not the submitted command.
func TestMixedTransactionFinalizationFollowsBackendOutcome(t *testing.T) {
	for _, tc := range []struct {
		sql, tag, action string
	}{
		{"COMMIT", "ROLLBACK", "rollback"},
		{"END", "ROLLBACK", "rollback"},
		{"COMMIT", "COMMIT", "commit"},
		{"ROLLBACK", "ROLLBACK", "rollback"},
	} {
		t.Run(tc.sql+"_"+tc.tag, func(t *testing.T) {
			// Model the existing engine overlay/snapshot endpoint, not a SQL engine.
			overlay := "pending"
			actions := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/transaction/rollback" {
					overlay = "prior"
				}
				actions <- r.URL.Path
				w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, conn := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
			}
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
			h.sess = session.New("192.0.2.1:1234", "seeded", "testdb")
			h.sess.SetTxStatus('T')
			if tc.tag == "ROLLBACK" && tc.sql != "ROLLBACK" {
				h.sess.SetTxStatus('E')
			}
			h.deceptionTxDirty = true
			h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(proxyClient), proxyClient)
			h.backendFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(proxyBackend), proxyBackend)
			backendDone := make(chan error, 1)
			go func() {
				peer := pgproto3.NewBackend(pgproto3.NewChunkReader(backend), backend)
				if _, err := peer.Receive(); err != nil {
					backendDone <- err
					return
				}
				if err := peer.Send(&pgproto3.CommandComplete{CommandTag: []byte(tc.tag)}); err != nil {
					backendDone <- err
					return
				}
				backendDone <- peer.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			}()
			done := make(chan error, 1)
			go func() { done <- h.proxyLoop(context.Background()) }()
			front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
			if err := front.Send(&pgproto3.Query{String: tc.sql}); err != nil {
				t.Fatal(err)
			}
			msg, err := front.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if complete, ok := msg.(*pgproto3.CommandComplete); !ok || string(complete.CommandTag) != tc.tag {
				t.Fatalf("backend command tag changed: %T", msg)
			}
			msg, err = front.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'I' {
				t.Fatalf("backend ready state changed: %T", msg)
			}
			client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := <-backendDone; err != nil {
				t.Fatal(err)
			}
			if action := <-actions; action != "/transaction/"+tc.action {
				t.Fatalf("finalized %s, want %s", action, tc.action)
			}
			wantOverlay := "pending"
			if tc.action == "rollback" {
				wantOverlay = "prior"
			}
			if overlay != wantOverlay || h.deceptionTxDirty || h.currentTxStatus() != 'I' {
				t.Fatalf("overlay=%s dirty=%v status=%c", overlay, h.deceptionTxDirty, h.currentTxStatus())
			}
		})
	}
}
