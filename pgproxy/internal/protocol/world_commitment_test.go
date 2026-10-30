package protocol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/session"
)

func TestWorldCommitmentResponseBoundary(t *testing.T) {
	var baseline []byte
	for _, mode := range []string{"no_candidates", "receipt", "receipt_failure", "write_failure"} {
		t.Run(mode, func(t *testing.T) {
			var receipts atomic.Int32
			queried := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/principals/observe" {
					receipts.Add(1)
					var body struct {
						Session    string   `json:"session_id"`
						Candidates []string `json:"observation_candidates"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Candidates) != 1 || body.Candidates[0] != "testdb.employees" || body.Session == "" {
						t.Error("incorrect receipt payload")
					}
					if mode == "receipt_failure" {
						w.WriteHeader(503)
						return
					}
					w.Write([]byte(`{"status":"ok","inserted":1,"conflicts":0}`))
					return
				}
				var requestBody map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
					t.Error(err)
				}
				if !validExecutionID(requestBody["query_execution_id"].(string)) {
					t.Error("missing execution identity before RPC")
				}
				response := map[string]interface{}{"mode": "fake", "tx_status": "I", "columns": []string{"id"}, "column_types": []string{"integer"}, "rows": []map[string]interface{}{{"id": 1}}}
				if mode != "no_candidates" {
					response["observation_candidates"] = []string{"testdb.employees"}
					response["_correlation"] = map[string]interface{}{"query_execution_id": requestBody["query_execution_id"], "decision_id": "11111111-1111-4111-8111-111111111111", "application_id": "22222222-2222-4222-8222-222222222222"}
				}
				json.NewEncoder(w).Encode(response)
				close(queried)
			}))
			defer srv.Close()
			t.Setenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			t.Setenv("DECEPTION_ENGINE_URL", srv.URL+"/decide")
			proxy, client := net.Pipe()
			defer proxy.Close()
			defer client.Close()
			proxy.SetDeadline(time.Now().Add(4 * time.Second))
			client.SetDeadline(time.Now().Add(4 * time.Second))
			h := NewHandler(proxy, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "", nil, nil)
			h.virtual = true
			h.beginQuery()
			h.sess = session.New("192.0.2.1:1", "fake_fixture", "testdb")
			if mode == "write_failure" {
				client.Close()
			}
			done := make(chan error, 1)
			go func() { done <- h.servePrincipalQuery(context.Background(), "select id from employees") }()
			<-queried
			if receipts.Load() != 0 {
				t.Fatal("receipt preceded response write")
			}
			if mode == "write_failure" {
				if err := <-done; err == nil {
					t.Fatal("missing write error")
				}
				if receipts.Load() != 0 {
					t.Fatal("failed write acknowledged")
				}
				return
			}
			front := pgproto3.NewFrontend(pgproto3.NewChunkReader(client), client)
			var wire []byte
			for {
				msg, err := front.Receive()
				if err != nil {
					t.Fatal(err)
				}
				encoded, err := msg.Encode(nil)
				if err != nil {
					t.Fatal(err)
				}
				wire = append(wire, encoded...)
				if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
					break
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(wire, []byte("_correlation")) || bytes.Contains(wire, []byte(h.queryCorrelation.QueryExecutionID)) || bytes.Contains(wire, []byte("22222222-2222-4222-8222-222222222222")) {
				t.Fatal("private correlation leaked to client")
			}
			if mode != "no_candidates" && h.queryCorrelation.ApplicationID != "22222222-2222-4222-8222-222222222222" {
				t.Fatal("correlation not accepted")
			}
			if mode == "no_candidates" {
				baseline = wire
			} else {
				if receipts.Load() != 1 {
					t.Fatal("missing receipt")
				}
				if !bytes.Equal(wire, baseline) {
					t.Fatal("private receipt changed SQL bytes")
				}
			}
		})
	}
}
