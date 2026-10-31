package main

import (
	"log/slog"
	"strings"
	"testing"
)

func TestRuntimeSecretsNeverReachOperationalMessage(t *testing.T) {
	t.Setenv("PG_RUNTIME_PASSWORD", "fixture-operator-runtime-long-value")
	t.Setenv("RESEARCH_OPERATOR_KEY", "fixture-export-operator-long-value")
	t.Setenv("EVIDENCE_IP_HASH_SALT", "fixture-pseudonym-long-value")
	old := operationalSecrets
	operationalSecrets = loadOperationalSecrets()
	defer func() { operationalSecrets = old }()
	for _, text := range []string{"fixture-operator-runtime-long-value", "fixture-export-operator-long-value", "fixture-pseudonym-long-value"} {
		a := safeLogAttr(nil, slog.String("message", "failed: "+text))
		if strings.Contains(a.Value.String(), text) {
			t.Fatal("operational secret leaked")
		}
	}
	if safeLogAttr(nil, slog.String("query", "select 'private'")).Value.String() != "[REDACTED]" {
		t.Fatal("SQL leaked")
	}
}
