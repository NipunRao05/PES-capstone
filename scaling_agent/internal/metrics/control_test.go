package metrics

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scalingagent/internal/scaler"
)

func controlTestServer() *Server {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(":0", scaler.New(logger), logger)
}

func controlRequest(t *testing.T, server *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	response := httptest.NewRecorder()
	server.srv.Handler.ServeHTTP(response, request)
	return response
}

func TestControlHTTPWorkflow(t *testing.T) {
	server := controlTestServer()

	response := controlRequest(t, server, http.MethodGet, "/control/status", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status endpoint returned %d: %s", response.Code, response.Body.String())
	}
	var initial scaler.ControlStatus
	if err := json.Unmarshal(response.Body.Bytes(), &initial); err != nil {
		t.Fatal(err)
	}
	if initial.EffectiveMode != "automatic" || initial.Control.MaxReplicaBudget != 10 {
		t.Fatalf("unexpected initial controls: %#v", initial)
	}

	response = controlRequest(t, server, http.MethodPost, "/control/safe-mode", `{"enabled":true,"actor":"tester","reason":"review"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("safe mode returned %d: %s", response.Code, response.Body.String())
	}
	response = controlRequest(t, server, http.MethodPost, "/control/manual-target", `{"target":3,"actor":"tester"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("manual target returned %d: %s", response.Code, response.Body.String())
	}
	response = controlRequest(t, server, http.MethodPost, "/control/max-budget", `{"max_replicas":2,"actor":"tester"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("max budget returned %d: %s", response.Code, response.Body.String())
	}
	var clamped scaler.ControlStatus
	if err := json.Unmarshal(response.Body.Bytes(), &clamped); err != nil {
		t.Fatal(err)
	}
	if clamped.CurrentReplicas != 2 || clamped.Control.ManualReplicaTarget == nil || *clamped.Control.ManualReplicaTarget != 2 {
		t.Fatalf("budget did not clamp manual state: %#v", clamped)
	}

	response = controlRequest(t, server, http.MethodPost, "/control/rollback", `{"actor":"tester","reason":"baseline"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("rollback returned %d: %s", response.Code, response.Body.String())
	}
	response = controlRequest(t, server, http.MethodPost, "/control/autoscaling/disable", `{}`)
	if response.Code != http.StatusOK {
		t.Fatalf("disable returned %d: %s", response.Code, response.Body.String())
	}
	response = controlRequest(t, server, http.MethodPost, "/control/autoscaling/enable", `{}`)
	if response.Code != http.StatusOK {
		t.Fatalf("enable returned %d: %s", response.Code, response.Body.String())
	}
}

func TestControlHTTPRejectsInvalidRequests(t *testing.T) {
	server := controlTestServer()
	tests := []struct {
		method string
		path   string
		body   string
		code   int
	}{
		{http.MethodPost, "/control/safe-mode", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/control/safe-mode", `{"enabled":true,"unknown":1}`, http.StatusBadRequest},
		{http.MethodPost, "/control/manual-target", `{"target":11}`, http.StatusBadRequest},
		{http.MethodPost, "/control/max-budget", `{"max_replicas":0}`, http.StatusBadRequest},
		{http.MethodGet, "/control/rollback", "", http.StatusMethodNotAllowed},
	}
	for _, test := range tests {
		response := controlRequest(t, server, test.method, test.path, test.body)
		if response.Code != test.code {
			t.Fatalf("%s %s returned %d, want %d: %s", test.method, test.path, response.Code, test.code, response.Body.String())
		}
	}
}
