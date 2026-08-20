package consumer

import "testing"

func TestDeriveMitreEventIDIsStableAcrossReplay(t *testing.T) {
	base := MitreEvent{
		SessionID:   "session-1",
		Timestamp:   "2026-08-20T09:10:00.100Z",
		Fingerprint: "query-hash",
		TechniqueID: "T1213.006",
		RuleID:      "R001_trap_table_access",
	}
	replay := base
	replay.Timestamp = "2026-08-20T09:10:00.900Z"
	if DeriveMitreEventID(base) != DeriveMitreEventID(replay) {
		t.Fatal("same event timestamp bucket should produce a stable ID")
	}
	replay.Fingerprint = "different-query-hash"
	if DeriveMitreEventID(base) == DeriveMitreEventID(replay) {
		t.Fatal("different query evidence must produce a different ID")
	}
}

func TestDeriveMitreEventIDPrefersUpstreamIdentity(t *testing.T) {
	event := MitreEvent{EventID: "upstream-event-1", SessionID: "session-1"}
	if got := DeriveMitreEventID(event); got != event.EventID {
		t.Fatalf("expected upstream ID %q, got %q", event.EventID, got)
	}
}

func TestDeriveSessionProfileEventIDIsContentStable(t *testing.T) {
	profile := SessionProfile{
		SessionID:     "session-1",
		CreatedAt:     1787217000.25,
		QueryCount:    3,
		FailedAuth:    1,
		Fingerprints:  `["select 1"]`,
		QuerySequence: `["select 1"]`,
	}
	replay := profile
	replay.CreatedAt = 1787217000.75
	if DeriveSessionProfileEventID(profile) != DeriveSessionProfileEventID(replay) {
		t.Fatal("same profile timestamp bucket should produce a stable ID")
	}
}
