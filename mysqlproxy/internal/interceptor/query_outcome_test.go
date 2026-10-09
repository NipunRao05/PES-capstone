package interceptor

import (
	"github.com/mysqlproxy/internal/session"
	"testing"
)

func TestPreparedOutcomeMetadata(t *testing.T) {
	in := New(1)
	sess := session.New("192.0.2.1:1234")
	in.InterceptStmtPrepare(sess.ID, 1, "SELECT 1")
	in.InterceptStmtExecuteOutcome(sess, 1, QueryOutcome{Verified: true, Success: false, Authority: "backend", ErrorCode: "mysql_1142", SQLState: "42000"})
	event := <-in.Events()
	if !event.OutcomeVerified || event.Success || event.Authority != "backend" || event.ErrorCode != "mysql_1142" || event.SQLState != "42000" || event.StrategyID != "" {
		t.Fatal(event)
	}
}
