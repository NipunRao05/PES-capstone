package tests

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/scalingagent/internal/scaler"
	"github.com/scalingagent/internal/scorer"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func highSignal(sessionID string, at time.Time) scorer.SessionSignal {
	return scorer.SessionSignal{
		SessionID:          sessionID,
		AttackerConfidence: 1,
		SessionDepth:       1,
		QueryEntropy:       1,
		FailedAuthRatio:    1,
		IsTrapTriggered:    true,
		Timestamp:          at,
	}
}

func TestScorerRestorePreservesScaleUpCooldown(t *testing.T) {
	start := time.Now().UTC()
	original := scorer.New()
	first := original.Score(highSignal("cooldown-first", start))
	if first.ReplicaTarget != 3 {
		t.Fatalf("expected first bounded scale-up to 3, got %d", first.ReplicaTarget)
	}

	restored := scorer.New()
	if err := restored.RestoreState(original.ExportState()); err != nil {
		t.Fatalf("restore scorer state: %v", err)
	}
	second := restored.Score(highSignal("cooldown-second", start.Add(10*time.Second)))
	if second.ReplicaTarget != 3 {
		t.Fatalf("cooldown should hold restored target at 3, got %d", second.ReplicaTarget)
	}
	if !strings.Contains(second.Reason, "cooldown active") {
		t.Fatalf("expected restored cooldown reason, got %q", second.Reason)
	}
}

func TestScorerRestorePreservesScaleDownTimer(t *testing.T) {
	start := time.Now().UTC()
	original := scorer.New()
	original.Score(highSignal("timer-high", start))
	lowStart := start.Add(scorer.ScaleUpCooldown + time.Second)
	original.Score(scorer.SessionSignal{SessionID: "timer-low", Timestamp: lowStart})

	restored := scorer.New()
	if err := restored.RestoreState(original.ExportState()); err != nil {
		t.Fatalf("restore scorer state: %v", err)
	}
	result := restored.Score(scorer.SessionSignal{
		SessionID: "timer-low",
		Timestamp: lowStart.Add(scorer.ScaleDownWindow + time.Second),
	})
	if result.ReplicaTarget != 2 {
		t.Fatalf("restored scale-down timer should reduce 3 to 2, got %d", result.ReplicaTarget)
	}
}

func TestScalerPersistentStateRoundTrip(t *testing.T) {
	manualTarget := 5
	now := time.Now().UTC()
	state := scaler.PersistentState{
		Version: scaler.PersistentStateVersion,
		SavedAt: now,
		Metrics: scaler.MetricsSnapshot{
			TotalSignals:    9,
			NoiseSignals:    1,
			ScaleUpEvents:   2,
			ScaleDownEvents: 1,
			TrapTriggers:    4,
			CurrentReplicas: 4,
			ScalePressure:   0.72,
		},
		Scorer: scorer.PersistentState{
			EWMAState:           map[string]float64{"session-a": 0.72},
			Count:               9,
			Mean:                0.5,
			M2:                  0.2,
			CurrentReplicas:     4,
			LastScaleUpAt:       now.Add(-10 * time.Second),
			BelowScaleDownSince: now.Add(-30 * time.Second),
			BelowThresholdSince: map[string]time.Time{"session-low": now.Add(-30 * time.Second)},
		},
		RecentEvents: []scaler.ScalingEvent{{
			SessionID: "session-a", ReplicaTarget: 4, Timestamp: now,
		}},
		Control: scaler.ControlState{
			ManualReplicaTarget: &manualTarget,
			SafeMode:            true,
			AutoscalingEnabled:  false,
		},
		ProcessedEventIDs: []string{"event-1", "event-2"},
	}

	sc := scaler.New(testLogger())
	if err := sc.RestoreState(state); err != nil {
		t.Fatalf("restore scaler state: %v", err)
	}
	roundTrip := sc.ExportState()
	if roundTrip.Metrics != state.Metrics {
		t.Fatalf("metrics mismatch after restore: %#v != %#v", roundTrip.Metrics, state.Metrics)
	}
	if len(roundTrip.RecentEvents) != 1 || roundTrip.RecentEvents[0].SessionID != "session-a" {
		t.Fatalf("recent events were not restored: %#v", roundTrip.RecentEvents)
	}
	if roundTrip.Control.ManualReplicaTarget == nil || *roundTrip.Control.ManualReplicaTarget != manualTarget || !roundTrip.Control.SafeMode || roundTrip.Control.AutoscalingEnabled {
		t.Fatalf("control state was not restored: %#v", roundTrip.Control)
	}
	if len(roundTrip.ProcessedEventIDs) != 2 {
		t.Fatalf("processed event IDs were not restored: %#v", roundTrip.ProcessedEventIDs)
	}
}

func TestScalerRejectsReplicaMismatch(t *testing.T) {
	state := scaler.New(testLogger()).ExportState()
	state.Metrics.CurrentReplicas = 3
	if err := scaler.New(testLogger()).RestoreState(state); err == nil {
		t.Fatal("expected mismatched scorer and metric replicas to be rejected")
	}
}

func TestScalerPersistsAfterSignal(t *testing.T) {
	sc := scaler.New(testLogger())
	saved := make(chan scaler.PersistentState, 2)
	sc.SetStateSaver(func(state scaler.PersistentState) error {
		saved <- state
		return nil
	}, false, "test-key")

	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan scorer.SessionSignal, 1)
	done := make(chan struct{})
	go func() {
		sc.Run(ctx, signals)
		close(done)
	}()
	signals <- highSignal("persist-signal", time.Now().UTC())

	select {
	case persisted := <-saved:
		if persisted.Metrics.CurrentReplicas != 3 || persisted.Metrics.TrapTriggers != 1 {
			t.Fatalf("unexpected persisted signal state: %#v", persisted.Metrics)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for persisted state")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scaler did not stop")
	}
}

func waitForSnapshot(t *testing.T, sc *scaler.Scaler, condition func(scaler.MetricsSnapshot) bool) scaler.MetricsSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := sc.Snapshot()
		if condition(snapshot) {
			return snapshot
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for scaler snapshot: %#v", sc.Snapshot())
	return scaler.MetricsSnapshot{}
}

func TestScalerIgnoresDuplicateEventIDs(t *testing.T) {
	sc := scaler.New(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signals := make(chan scorer.SessionSignal, 6)
	done := make(chan struct{})
	go func() {
		sc.Run(ctx, signals)
		close(done)
	}()

	signal := highSignal("duplicate-session", time.Now().UTC())
	signal.EventID = "mitre:duplicate-event"
	signal.SignalSource = "mitre-events"
	for i := 0; i < 6; i++ {
		signals <- signal
	}

	snapshot := waitForSnapshot(t, sc, func(snapshot scaler.MetricsSnapshot) bool {
		return snapshot.DuplicateEvents == 5
	})
	if snapshot.TotalSignals != 1 || snapshot.TrapTriggers != 1 || snapshot.ScaleUpEvents != 1 {
		t.Fatalf("duplicates changed operational counters: %#v", snapshot)
	}
	if sc.ProcessedEventCount() != 1 || len(sc.RecentEvents(10)) != 1 {
		t.Fatalf("duplicate changed durable IDs or event history: ids=%d events=%d", sc.ProcessedEventCount(), len(sc.RecentEvents(10)))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scaler did not stop")
	}
}

func TestRestoredProcessedEventIDRejectsReplay(t *testing.T) {
	original := scaler.New(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan scorer.SessionSignal, 1)
	done := make(chan struct{})
	go func() {
		original.Run(ctx, signals)
		close(done)
	}()

	signal := highSignal("restart-replay-session", time.Now().UTC())
	signal.EventID = "mitre:restart-replay-event"
	signal.SignalSource = "mitre-events"
	signals <- signal
	want := waitForSnapshot(t, original, func(snapshot scaler.MetricsSnapshot) bool {
		return snapshot.TotalSignals == 1
	})
	cancel()
	<-done

	restored := scaler.New(testLogger())
	if err := restored.RestoreState(original.ExportState()); err != nil {
		t.Fatalf("restore state: %v", err)
	}
	replayCtx, replayCancel := context.WithCancel(context.Background())
	replaySignals := make(chan scorer.SessionSignal, 1)
	replayDone := make(chan struct{})
	go func() {
		restored.Run(replayCtx, replaySignals)
		close(replayDone)
	}()
	replaySignals <- signal
	got := waitForSnapshot(t, restored, func(snapshot scaler.MetricsSnapshot) bool {
		return snapshot.DuplicateEvents == want.DuplicateEvents+1
	})
	if got.TotalSignals != want.TotalSignals || got.TrapTriggers != want.TrapTriggers || got.ScaleUpEvents != want.ScaleUpEvents || got.CurrentReplicas != want.CurrentReplicas {
		t.Fatalf("replay after restore changed operational state: before=%#v after=%#v", want, got)
	}
	if restored.ProcessedEventCount() != 1 || len(restored.RecentEvents(10)) != 1 {
		t.Fatalf("replay after restore changed event state: ids=%d events=%d", restored.ProcessedEventCount(), len(restored.RecentEvents(10)))
	}

	replayCancel()
	select {
	case <-replayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("restored scaler did not stop")
	}
}

func runSignal(t *testing.T, sc *scaler.Scaler, signal scorer.SessionSignal, total int64) scaler.MetricsSnapshot {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan scorer.SessionSignal, 1)
	done := make(chan struct{})
	go func() {
		sc.Run(ctx, signals)
		close(done)
	}()
	signals <- signal
	snapshot := waitForSnapshot(t, sc, func(snapshot scaler.MetricsSnapshot) bool {
		return snapshot.TotalSignals == total
	})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scaler did not stop")
	}
	return snapshot
}

func TestSafeModeBlocksAutomaticScaleUp(t *testing.T) {
	sc := scaler.New(testLogger())
	if _, err := sc.SetSafeMode(true, "test-operator", "freeze during incident review"); err != nil {
		t.Fatalf("enable safe mode: %v", err)
	}
	signal := highSignal("safe-mode-high", time.Now().UTC())
	signal.EventID = "safe-mode-event"
	snapshot := runSignal(t, sc, signal, 1)
	if snapshot.CurrentReplicas != 1 || snapshot.ScaleUpEvents != 0 || snapshot.TrapTriggers != 1 {
		t.Fatalf("safe mode did not freeze automatic scaling: %#v", snapshot)
	}
	events := sc.RecentEvents(1)
	if len(events) != 1 || !strings.Contains(events[0].Reason, "safe mode active") {
		t.Fatalf("safe-mode decision was not observable: %#v", events)
	}
}

func TestManualTargetAndRollbackAreImmediate(t *testing.T) {
	sc := scaler.New(testLogger())
	status, err := sc.SetManualReplicaTarget(4, "test-operator", "capacity override")
	if err != nil {
		t.Fatalf("set manual target: %v", err)
	}
	if status.CurrentReplicas != 4 || status.EffectiveMode != "manual" || status.Control.ManualReplicaTarget == nil || *status.Control.ManualReplicaTarget != 4 {
		t.Fatalf("manual target was not applied: %#v", status)
	}

	signal := highSignal("manual-high", time.Now().UTC())
	signal.EventID = "manual-event"
	snapshot := runSignal(t, sc, signal, 1)
	if snapshot.CurrentReplicas != 4 {
		t.Fatalf("scoring decision overrode manual target: %#v", snapshot)
	}

	status, err = sc.RollbackToBaseline("test-operator", "return to safe baseline")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if status.CurrentReplicas != scorer.ReplicaMin || status.EffectiveMode != "safe_mode" || !status.Control.SafeMode || status.Control.ManualReplicaTarget != nil {
		t.Fatalf("rollback did not establish a safe baseline: %#v", status)
	}
	if len(status.AuditEvents) != 2 || status.AuditEvents[1].Action != "rollback_to_baseline" {
		t.Fatalf("control audit history missing: %#v", status.AuditEvents)
	}
}

func TestAutoscalingDisableAndEnable(t *testing.T) {
	sc := scaler.New(testLogger())
	if _, err := sc.SetAutoscalingEnabled(false, "test-operator", "maintenance"); err != nil {
		t.Fatalf("disable autoscaling: %v", err)
	}
	first := highSignal("disabled-high", time.Now().UTC())
	first.EventID = "disabled-event"
	snapshot := runSignal(t, sc, first, 1)
	if snapshot.CurrentReplicas != 1 || snapshot.ScaleUpEvents != 0 {
		t.Fatalf("disabled autoscaling changed replicas: %#v", snapshot)
	}

	if _, err := sc.SetAutoscalingEnabled(true, "test-operator", "maintenance complete"); err != nil {
		t.Fatalf("enable autoscaling: %v", err)
	}
	second := highSignal("enabled-high", time.Now().UTC().Add(time.Second))
	second.EventID = "enabled-event"
	snapshot = runSignal(t, sc, second, 2)
	if snapshot.CurrentReplicas != 3 || snapshot.ScaleUpEvents != 1 {
		t.Fatalf("autoscaling did not resume: %#v", snapshot)
	}
}

func TestMaxReplicaBudgetCapsAutomaticScaling(t *testing.T) {
	sc := scaler.New(testLogger())
	if _, err := sc.SetMaxReplicaBudget(2, "test-operator", "test budget"); err != nil {
		t.Fatalf("set max budget: %v", err)
	}
	signal := highSignal("budget-high", time.Now().UTC())
	signal.EventID = "budget-event"
	snapshot := runSignal(t, sc, signal, 1)
	if snapshot.CurrentReplicas != 2 || snapshot.ScaleUpEvents != 1 {
		t.Fatalf("max budget was not enforced: %#v", snapshot)
	}
	if _, err := sc.SetManualReplicaTarget(3, "test-operator", "invalid override"); err == nil {
		t.Fatal("manual target above budget should be rejected")
	}
}

func TestControlStateAndAuditSurviveRestore(t *testing.T) {
	original := scaler.New(testLogger())
	if _, err := original.SetSafeMode(true, "alice", "incident"); err != nil {
		t.Fatal(err)
	}
	if _, err := original.SetManualReplicaTarget(3, "alice", "hold capacity"); err != nil {
		t.Fatal(err)
	}

	restored := scaler.New(testLogger())
	if err := restored.RestoreState(original.ExportState()); err != nil {
		t.Fatalf("restore control state: %v", err)
	}
	status := restored.ControlStatus()
	if status.EffectiveMode != "manual" || status.CurrentReplicas != 3 || len(status.AuditEvents) != 2 {
		t.Fatalf("control state or audit was not restored: %#v", status)
	}
	if status.AuditEvents[0].Actor != "alice" || status.AuditEvents[1].Current.ManualReplicaTarget == nil {
		t.Fatalf("restored audit content is incomplete: %#v", status.AuditEvents)
	}
}
