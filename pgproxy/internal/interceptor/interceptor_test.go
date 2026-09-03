package interceptor

import (
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/session"
)

func TestInterceptSimpleCarriesDeclarativeTrapMetadata(t *testing.T) {
	ic := New(10)
	s := session.NewFromStartup(&pgproto3.StartupMessage{Parameters: map[string]string{
		"user": "analyst", "database": "testdb",
	}}, "127.0.0.1:54320")
	outcome := QueryOutcome{
		Verified: true, Success: true, Authority: "deception",
		EventSchemaVersion: "deception-decision-v2", WorldID: "research",
		AssetID: "research.function.legacy_token_export", AssetKind: "function",
		TrapTriggered: true, TrapID: "RESEARCH-FUNCTION-TOKEN-001",
		TrapKind: "credential_function", TrapMitreTechniqueID: "T1555",
		TrapRiskScore: 12, StrategyID: "D3", StrategyRegistryVersion: "registry-v1",
	}
	ic.InterceptSimpleOutcome(s, "select * from legacy_token_export()", outcome)

	select {
	case ev := <-ic.Events():
		if !ev.TrapTriggered || ev.TrapMitreTechniqueID != "T1555" || ev.TrapRiskScore != 12 {
			t.Fatalf("trap metadata not propagated: %+v", ev)
		}
		if ev.TrapID != outcome.TrapID || ev.AssetID != outcome.AssetID || ev.StrategyID != "D3" {
			t.Fatalf("trap identity not propagated: %+v", ev)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}
