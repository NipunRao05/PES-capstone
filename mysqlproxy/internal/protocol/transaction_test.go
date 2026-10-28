package protocol

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mysqlproxy/internal/session"
)

// Exercise the real ordinary command loop with a wire backend and an engine
// double. Rollback must restore the overlay before its OK reaches the client.
func TestSyntheticTransactionRollback(t *testing.T) {
	var overlay atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/transaction/rollback" {
			overlay.Store(0)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		var req struct {
			SQL              string `json:"query_normalized"`
			TransactionState string `json:"transaction_state"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.SQL == "insert into employees (id) values (999)" {
			if req.TransactionState != "in_transaction" {
				t.Errorf("mutation transaction state = %q", req.TransactionState)
			}
			overlay.Store(1)
			json.NewEncoder(w).Encode(map[string]interface{}{"mode": "fake", "affected_rows": 1})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"mode": "passthrough"})
	}))
	defer srv.Close()
	t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
	proxyClient, client := net.Pipe()
	proxyBackend, backend := net.Pipe()
	for _, conn := range []net.Conn{proxyClient, client, proxyBackend, backend} {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0, nil, nil)
	h.sess = session.New("192.0.2.1:1234")
	go func() {
		peer := &Handler{}
		for _, status := range []byte{3, 2} {
			if _, err := peer.readPacket(backend); err != nil {
				return
			}
			if err := peer.sendPacket(backend, []byte{0, 0, 0, status, 0, 0, 0}, 1); err != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- h.commandLoop(context.Background()) }()
	peer := &Handler{}
	for _, sql := range []string{"BEGIN", "INSERT INTO employees (id) VALUES (999)", "ROLLBACK"} {
		if err := peer.sendPacket(client, append([]byte{comQuery}, []byte(sql)...), 0); err != nil {
			t.Fatal(err)
		}
		pkt, err := peer.readPacket(client)
		if err != nil {
			t.Fatal(err)
		}
		if pkt[0] != packetOK {
			t.Fatalf("%s response = %v", sql, pkt)
		}
	}
	if overlay.Load() != 0 {
		t.Error("ROLLBACK acknowledged but synthetic insert remains visible")
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticTransactionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, sql, action                    string
		beforeTx, beforeAuto, dirty, virtual bool
		status                               byte
		fail                                 bool
	}{
		{"commit", "COMMIT", "commit", true, true, true, false, 2, false},
		{"rollback_work", "ROLLBACK WORK;", "rollback", true, true, true, false, 2, false},
		{"rollback_chain", "ROLLBACK AND CHAIN", "rollback", true, true, true, false, 3, false},
		{"commit_chain", "COMMIT AND CHAIN", "commit", true, true, true, false, 3, false},
		{"begin_commits_previous", "BEGIN", "commit", true, true, true, false, 3, false},
		{"start_commits_previous", "START TRANSACTION READ WRITE", "commit", true, true, true, false, 3, false},
		{"autocommit_off_rollback", "ROLLBACK", "rollback", false, false, true, false, 0, false},
		{"enable_autocommit", "SET autocommit=1", "commit", false, false, true, false, 2, false},
		{"native_implicit_commit", "CREATE TABLE ordinary (id int)", "commit", true, true, true, false, 2, false},
		{"native_only", "COMMIT", "", true, true, false, false, 2, false},
		{"virtual_unchanged", "ROLLBACK", "", true, true, true, true, 2, false},
		{"statement_in_tx", "UPDATE ordinary SET id=2", "", true, true, true, false, 3, false},
		{"read_autocommit_off", "SELECT 1", "", false, false, true, false, 0, false},
		{"rollback_to_is_not_full_rollback", "ROLLBACK TO SAVEPOINT a", "", true, true, true, false, 3, false},
		{"finalize_failure", "COMMIT", "commit", true, true, true, false, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body["session_id"] != "transaction-session" {
					t.Error("wrong session")
				}
				calls = append(calls, r.URL.Path)
				if tc.fail {
					w.WriteHeader(503)
					return
				}
				w.Write([]byte(`{"status":"ok"}`))
			}))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			h := &Handler{sess: session.New("192.0.2.1:1234"), virtual: tc.virtual, deceptionTxDirty: tc.dirty, deceptionTransactionSQL: tc.sql}
			h.sess.ID = "transaction-session"
			h.sess.SetTransactionStatus(tc.beforeTx, tc.beforeAuto)
			pkt := []byte{0, 0, 0, tc.status, 0, 0, 0}
			original := append([]byte(nil), pkt...)
			err := h.finalizeDeceptionTransaction(context.Background(), pkt)
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
			if tc.action == "" && len(calls) != 0 {
				t.Fatalf("unexpected calls: %v", calls)
			}
			if tc.action != "" && !reflect.DeepEqual(calls, []string{"/transaction/" + tc.action}) {
				t.Fatalf("calls=%v", calls)
			}
			if !reflect.DeepEqual(pkt, original) {
				t.Fatal("native backend packet changed")
			}
			if h.sess.Snapshot().InTransaction != tc.beforeTx || h.sess.Snapshot().AutoCommit != tc.beforeAuto {
				t.Fatal("backend state guessed by finalizer")
			}
			wantDirty := tc.dirty && (tc.action == "" || tc.fail)
			if h.deceptionTxDirty != wantDirty {
				t.Fatalf("dirty=%v want %v", h.deceptionTxDirty, wantDirty)
			}
		})
	}
}

func TestSyntheticStatusPreservesTransactionFlags(t *testing.T) {
	for _, tc := range []struct {
		tx, auto, dirty, virtual bool
		flags                    uint16
	}{
		{false, true, false, false, 2}, {true, true, true, false, 3},
		{false, false, true, false, 1}, {false, false, false, false, 0},
		{true, true, false, true, 3}, {false, true, false, true, 2},
	} {
		h := &Handler{sess: session.New("192.0.2.1:1234"), virtual: tc.virtual, deceptionTxDirty: tc.dirty}
		h.sess.SetTransactionStatus(tc.tx, tc.auto)
		if flags := h.deceptionStatus(); flags != tc.flags {
			t.Fatalf("status %d want %d", flags, tc.flags)
		}
		if flags, ok := mysqlStatusFlags(h.deceptionEOFPacket()); !ok || flags != tc.flags {
			t.Fatalf("EOF status %d want %d", flags, tc.flags)
		}
	}
}

func TestSyntheticFinalizationFailureDoesNotSendBackendOK(t *testing.T) {
	for _, backendFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "engine_failure", true: "backend_failure"}[backendFails], func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, c := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
			}
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", 0, nil, nil)
			h.sess = session.New("192.0.2.1:1234")
			h.sess.SetTransactionStatus(true, true)
			h.deceptionTxDirty = true
			go func() {
				peer := &Handler{}
				if _, err := peer.readPacket(backend); err != nil {
					return
				}
				pkt := []byte{0, 0, 0, 2, 0, 0, 0}
				if backendFails {
					pkt = []byte{0xff, 0x28, 0x04, '#', 'H', 'Y', '0', '0', '0'}
				}
				peer.sendPacket(backend, pkt, 1)
			}()
			done := make(chan error, 1)
			go func() { done <- h.commandLoop(context.Background()); proxyClient.Close() }()
			peer := &Handler{}
			if err := peer.sendPacket(client, append([]byte{comQuery}, []byte("COMMIT")...), 0); err != nil {
				t.Fatal(err)
			}
			pkt, err := peer.readPacket(client)
			if backendFails {
				if err != nil || len(pkt) == 0 || pkt[0] != packetERR {
					t.Fatalf("backend error not preserved: %v %v", pkt, err)
				}
				if calls.Load() != 0 {
					t.Fatal("finalized failed native commit")
				}
				client.Close()
			} else if err == nil {
				t.Fatalf("false success after finalize failure: %v", pkt)
			}
			loopErr := <-done
			if !backendFails && loopErr == nil {
				t.Fatal("missing finalization error")
			}
			if !h.deceptionTxDirty {
				t.Fatal("failed operation discarded dirty state")
			}
		})
	}
}
