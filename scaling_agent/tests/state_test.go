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
