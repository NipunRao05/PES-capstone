package interceptor

import (
	"github.com/pgproxy/internal/session"
	"testing"
)

func TestExtendedExecutionRemainsUnverified(t *testing.T) {
	in := New(1)
	sess := session.NewFromStartup(nil, "192.0.2.1:1234")
	in.InterceptParse(sess, "stmt", "SELECT 1")
	in.InterceptBind(sess, "stmt", "portal", nil)
	in.InterceptExecute(sess, "portal", 0)
	event := <-in.Events()
	if event.OutcomeVerified || event.Success || event.StrategyID != "" || event.DeceptionProfile != "" {
		t.Fatal(event)
	}
}
