package protocol

import (
	"github.com/mysqlproxy/internal/interceptor"
	"github.com/mysqlproxy/internal/session"
	"testing"
	"time"
)

func TestExecutionCorrelationPerRequestAndEvent(t *testing.T) {
	h := &Handler{}
	h.sess = session.New("client")
	h.intercept = interceptor.New(4)
	h.beginQuery()
	first := h.queryCorrelation.QueryExecutionID
	started, err := time.Parse(time.RFC3339Nano, h.queryCorrelation.RequestStartedAt)
	if err != nil || started.After(time.Now()) || !validExecutionID(first) {
		t.Fatal("invalid start context")
	}
	h.acceptCorrelation(&interceptor.QueryCorrelation{QueryExecutionID: first, DecisionID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222"})
	h.emitTextQueryOutcome("select 1", interceptor.QueryOutcome{Verified: true, Success: true})
	event := <-h.intercept.Events()
	if event.QueryExecutionID != first || event.ApplicationID != h.queryCorrelation.ApplicationID {
		t.Fatal("event lost correlation")
	}
	h.beginQuery()
	if h.queryCorrelation.QueryExecutionID == first || h.queryCorrelation.ApplicationID != "" {
		t.Fatal("query identity reused")
	}
	h.acceptCorrelation(&interceptor.QueryCorrelation{QueryExecutionID: first, DecisionID: "11111111-1111-4111-8111-111111111111", ApplicationID: "22222222-2222-4222-8222-222222222222"})
	if h.queryCorrelation.ApplicationID != "" {
		t.Fatal("foreign execution correlation accepted")
	}
}
