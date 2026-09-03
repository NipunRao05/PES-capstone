package interceptor

import (
	"testing"
	"time"

	"github.com/mysqlproxy/internal/session"
)

func TestCleanTextQueryStripsMySQLQueryAttributePrefix(t *testing.T) {
	cases := map[string]string{
		"\x00\x01SHOW DATABASES":                   "SHOW DATABASES",
		"\x00\x01select @@version_comment limit 1": "select @@version_comment limit 1",
	}
	for raw, want := range cases {
		if got := CleanTextQuery(raw); got != want {
			t.Fatalf("CleanTextQuery(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestInterceptTextQueryStoresCleanRawQuery(t *testing.T) {
	ic := New(10)
	s := session.New("127.0.0.1:2223")
	s.SetAuth("alice", "testdb", 0, 0)

	ic.InterceptTextQuery(s, "\x00\x01SHOW TABLES")

	select {
	case ev := <-ic.Events():
		if ev.QueryRaw != "SHOW TABLES" {
			t.Fatalf("expected sanitized QueryRaw, got %q", ev.QueryRaw)
		}
		if ev.QueryNormalized != "show tables" {
			t.Fatalf("expected normalized query, got %q", ev.QueryNormalized)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}

func TestInterceptTextQueryCarriesDeclarativeTrapMetadata(t *testing.T) {
	ic := New(10)
	s := session.New("127.0.0.1:2223")
	s.SetAuth("alice", "testdb", 0, 0)
	outcome := QueryOutcome{
		Verified: true, Success: true, Authority: "deception",
		EventSchemaVersion: "deception-decision-v2", WorldID: "research",
		AssetID: "research.function.legacy_token_export", AssetKind: "function",
		TrapTriggered: true, TrapID: "RESEARCH-FUNCTION-TOKEN-001",
		TrapKind: "credential_function", TrapMitreTechniqueID: "T1555",
		TrapRiskScore: 12, StrategyID: "D3", StrategyRegistryVersion: "registry-v1",
	}
	ic.InterceptTextQueryOutcome(s, "select * from legacy_token_export()", outcome)

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
