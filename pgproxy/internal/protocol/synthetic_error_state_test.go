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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/session"
	"github.com/pgproxy/internal/shaper"
)

// The existing net.Pipe + httptest pattern exercises the actual proxy loop.
// Fake engine overlay and native pending state are kept distinct in this fixture.
type errorStateFixture struct {
	h               *Handler
	front           *pgproto3.Frontend
	mu              sync.Mutex
	overlay         int
	nativePending   bool
	nativeCommitted bool
	forwarded       []string
	actions         []string
	events          <-chan interceptor.QueryEvent
}

func newErrorStateFixture(t *testing.T) *errorStateFixture {
	t.Helper()
	f := &errorStateFixture{overlay: 100}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/transaction/") {
			f.actions = append(f.actions, r.URL.Path)
			if r.URL.Path == "/transaction/rollback" {
				f.overlay = 100
			}
			w.Write([]byte(`{"status":"ok"}`))
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		sql, _ := body["query_normalized"].(string)
		if strings.Contains(sql, "invalid") {
			w.Write([]byte(`{"mode":"block","sqlstate":"42601","error_msg":"unsupported synthetic statement"}`))
		} else if strings.HasPrefix(sql, "update employees") {
			f.overlay = 999
			w.Write([]byte(`{"mode":"fake","affected_rows":1}`))
		} else if strings.Contains(sql, "employees") {
			w.Write([]byte(`{"mode":"fake","columns":["id"],"rows":[{"id":1}]}`))
		} else {
			w.Write([]byte(`{"mode":"passthrough"}`))
		}
	}))
	t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
	proxyClient, client := net.Pipe()
	proxyBackend, backend := net.Pipe()
	for _, conn := range []net.Conn{proxyClient, client, proxyBackend, backend} {
		conn.SetDeadline(time.Now().Add(8 * time.Second))
	}
	in := interceptor.New(32)
	f.events = in.Events()
	f.h = NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", in, nil)
	f.h.sess = session.New("192.0.2.1:1", "seeded", "testdb")
	f.h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(proxyClient), proxyClient)
	f.h.backendFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(proxyBackend), proxyBackend)
	f.front = pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		defer backend.Close()
		peer := pgproto3.NewBackend(pgproto3.NewChunkReader(backend), backend)
		status := byte('I')
		for {
			msg, err := peer.Receive()
			if err != nil {
				return
			}
			q, ok := msg.(*pgproto3.Query)
			if !ok {
				return
			}
			sql := strings.ToLower(q.String)
			f.mu.Lock()
			f.forwarded = append(f.forwarded, sql)
			tag, code := "SELECT 1", ""
			switch sql {
			case "begin":
				status, tag = 'T', "BEGIN"
			case "rollback", "abort":
				status, tag, f.nativePending = 'I', "ROLLBACK", false
			case "commit":
				if status == 'E' {
					tag = "ROLLBACK"
				} else {
					tag, f.nativeCommitted = "COMMIT", f.nativePending
				}
				status, f.nativePending = 'I', false
			case "select native_error":
				status, code = 'E', "42P01"
			default:
				if status == 'E' {
					code = "25P02"
				} else if strings.HasPrefix(sql, "update ordinary") {
					f.nativePending, tag = true, "UPDATE 1"
				}
			}
			f.mu.Unlock()
			if code != "" {
				if peer.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: "native error"}) != nil {
					return
				}
			} else if peer.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)}) != nil {
				return
			}
			if peer.Send(&pgproto3.ReadyForQuery{TxStatus: status}) != nil {
				return
			}
		}
	}()
	done := make(chan error, 1)
	go func() { done <- f.h.proxyLoop(context.Background()) }()
	t.Cleanup(func() {
		client.Close()
		proxyClient.Close()
		proxyBackend.Close()
		<-done
		<-backendDone
		srv.Close()
	})
	return f
}

func (f *errorStateFixture) query(t *testing.T, sql string, status byte, code, tag string) {
	t.Helper()
	if err := f.front.Send(&pgproto3.Query{String: sql}); err != nil {
		t.Fatal(err)
	}
	gotCode, gotTag := "", ""
	for {
		msg, err := f.front.Receive()
		if err != nil {
			t.Fatal(err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			gotCode = m.Code
		case *pgproto3.CommandComplete:
			gotTag = string(m.CommandTag)
		case *pgproto3.ReadyForQuery:
			if m.TxStatus != status || gotCode != code || (tag != "" && gotTag != tag) {
				t.Fatalf("%s: status=%c error=%s tag=%s; want %c/%s/%s", sql, m.TxStatus, gotCode, gotTag, status, code, tag)
			}
			select {
			case event := <-f.events:
				wantState := map[byte]string{'I': "idle", 'T': "in_transaction", 'E': "failed_transaction"}[status]
				if event.TransactionState != wantState || event.Success != (code == "") {
					t.Fatalf("inconsistent query event: %+v", event)
				}
			case <-time.After(time.Second):
				t.Fatal("query outcome not emitted")
			}
			return
		}
	}
}

func TestSyntheticErrorStateOutsideTransaction(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "select id from employees", 'I', "", "SELECT 1")
	f.query(t, "select invalid from employees", 'I', "42601", "")
	f.query(t, "select 1", 'I', "", "SELECT 1")
}

func TestSyntheticSuccessCommitsHealthyMixedTransaction(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "begin", 'T', "", "BEGIN")
	f.query(t, "update ordinary set id=1", 'T', "", "UPDATE 1")
	f.query(t, "update employees set salary=999 where id=1", 'T', "", "UPDATE 1")
	f.query(t, "commit", 'I', "", "COMMIT")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overlay != 999 || !f.nativeCommitted || f.nativePending || len(f.actions) != 1 || f.actions[0] != "/transaction/commit" {
		t.Fatal("healthy mixed commit changed")
	}
}

func TestPolicyExtendedErrorDiscardsThroughSync(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "begin", 'T', "", "BEGIN")
	f.h.shaper.AddRule(shaper.Rule{Fingerprint: "", Block: true})
	if err := f.front.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"}); err != nil {
		t.Fatal(err)
	}
	msg, err := f.front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if failure, ok := msg.(*pgproto3.ErrorResponse); !ok || failure.Code != "42501" {
		t.Fatalf("unexpected %T", msg)
	}
	sent := make(chan error, 1)
	go func() {
		if err := f.front.Send(&pgproto3.Bind{PreparedStatement: "stmt"}); err != nil {
			sent <- err
			return
		}
		sent <- f.front.Send(&pgproto3.Sync{})
	}()
	msg, err = f.front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'E' {
		t.Fatalf("policy error did not discard through Sync: %T", msg)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	f.h.shaper.RemoveRule("")
	f.query(t, "rollback", 'I', "", "ROLLBACK")
}

func TestSyntheticErrorAbortSequenceMatrix(t *testing.T) {
	for _, ending := range []string{"commit", "rollback", "end", "abort"} {
		t.Run(ending, func(t *testing.T) {
			f := newErrorStateFixture(t)
			f.query(t, "begin", 'T', "", "BEGIN")
			f.query(t, "update ordinary set id=1", 'T', "", "UPDATE 1")
			f.query(t, "update employees set salary=999 where id=1", 'T', "", "UPDATE 1")
			f.query(t, "select invalid from employees", 'E', "42601", "")
			f.query(t, "select id from employees", 'E', "25P02", "")
			f.query(t, "select 1", 'E', "25P02", "")
			f.query(t, ending, 'I', "", "ROLLBACK")
			f.mu.Lock()
			if f.overlay != 100 || f.nativeCommitted || f.nativePending || len(f.actions) != 1 || f.actions[0] != "/transaction/rollback" {
				t.Errorf("wrong final outcome: overlay=%d native=%v actions=%v", f.overlay, f.nativeCommitted, f.actions)
			}
			for _, sql := range f.forwarded {
				if sql == "select 1" {
					t.Error("healthy backend query escaped failed state")
				}
			}
			f.mu.Unlock()
			f.query(t, "begin", 'T', "", "BEGIN")
			f.query(t, "select id from employees", 'T', "", "SELECT 1")
			f.query(t, "rollback", 'I', "", "ROLLBACK")
		})
	}
}

func TestBackendErrorBlocksSyntheticThenRollsBackOverlay(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "begin", 'T', "", "BEGIN")
	f.query(t, "update employees set salary=999 where id=1", 'T', "", "UPDATE 1")
	f.query(t, "select native_error", 'E', "42P01", "")
	f.query(t, "select id from employees", 'E', "25P02", "")
	f.query(t, "commit", 'I', "", "ROLLBACK")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.overlay != 100 {
		t.Fatal("native rollback retained fake mutation")
	}
}

func TestPolicyErrorAbortsActiveTransaction(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "begin", 'T', "", "BEGIN")
	f.h.shaper.AddRule(shaper.Rule{Fingerprint: "", Block: true})
	f.query(t, "select 1", 'E', "42501", "")
	f.query(t, "commit", 'I', "", "ROLLBACK")
	f.h.shaper.RemoveRule("")
}

func TestSyntheticFailureExtendedSyncDoesNotRestoreHealthyBackendStatus(t *testing.T) {
	f := newErrorStateFixture(t)
	f.query(t, "begin", 'T', "", "BEGIN")
	f.query(t, "select invalid from employees", 'E', "42601", "")
	if err := f.front.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"}); err != nil {
		t.Fatal(err)
	}
	msg, err := f.front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if failure, ok := msg.(*pgproto3.ErrorResponse); !ok || failure.Code != "25P02" {
		t.Fatalf("unexpected message %T", msg)
	}
	// Send the rest of the failed extended cycle, then recover protocol sync.
	sent := make(chan error, 1)
	go func() {
		if err := f.front.Send(&pgproto3.Bind{PreparedStatement: "stmt"}); err != nil {
			sent <- err
			return
		}
		if err := f.front.Send(&pgproto3.Execute{}); err != nil {
			sent <- err
			return
		}
		sent <- f.front.Send(&pgproto3.Sync{})
	}()
	msg, err = f.front.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'E' {
		t.Fatalf("unexpected sync result %T", msg)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	f.query(t, "commit", 'I', "", "ROLLBACK")
}

func TestPrincipalProxyLocalAbortReachesRegistryBeforeCommit(t *testing.T) {
	for _, kind := range []string{"extended", "service_error"} {
		t.Run(kind, func(t *testing.T) {
			states := make(chan string, 2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				json.NewDecoder(r.Body).Decode(&body)
				if body["sql"] != "COMMIT" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				state, _ := body["transaction_state"].(string)
				states <- state
				// Model the registry result only if the local abort was propagated.
				tag := "COMMIT"
				if state == "failed_transaction" {
					tag = "ROLLBACK"
				}
				json.NewEncoder(w).Encode(map[string]string{"mode": "fake", "command_tag": tag, "tx_status": "I"})
			}))
			defer srv.Close()
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			t.Setenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			proxyClient, client := net.Pipe()
			proxyBackend, backend := net.Pipe()
			for _, conn := range []net.Conn{proxyClient, client, proxyBackend, backend} {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
			}
			h := NewHandler(proxyClient, proxyBackend, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
			h.virtual = true
			h.sess = session.New("192.0.2.1:1", "fake_fixture", "testdb")
			h.sess.SetTxStatus('T')
			h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(proxyClient), proxyClient)
			front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
			done := make(chan error, 1)
			go func() { done <- h.principalLoop(context.Background()) }()
			if kind == "extended" {
				if err := front.Send(&pgproto3.Parse{Name: "stmt", Query: "select 1"}); err != nil {
					t.Fatal(err)
				}
				msg, err := front.Receive()
				if err != nil {
					t.Fatal(err)
				}
				if failure, ok := msg.(*pgproto3.ErrorResponse); !ok || failure.Code != "0A000" {
					t.Fatalf("unexpected %T", msg)
				}
				if err := front.Send(&pgproto3.Sync{}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := front.Send(&pgproto3.Query{String: "select id from employees"}); err != nil {
					t.Fatal(err)
				}
				if _, err := front.Receive(); err != nil {
					t.Fatal(err)
				}
			}
			msg, err := front.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'E' {
				t.Fatalf("local error did not leave E: %T", msg)
			}
			if err := front.Send(&pgproto3.Query{String: "COMMIT"}); err != nil {
				t.Fatal(err)
			}
			msg, err = front.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if complete, ok := msg.(*pgproto3.CommandComplete); !ok || string(complete.CommandTag) != "ROLLBACK" {
				t.Fatalf("local failure was committed: %T", msg)
			}
			msg, err = front.Receive()
			if err != nil {
				t.Fatal(err)
			}
			if ready, ok := msg.(*pgproto3.ReadyForQuery); !ok || ready.TxStatus != 'I' {
				t.Fatalf("final status: %T", msg)
			}
			client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if state := <-states; state != "failed_transaction" {
				t.Fatal("registry did not receive local abort")
			}
		})
	}
}
