package tests

import (
	"math"
	"testing"
	"time"

	"github.com/scalingagent/internal/scorer"
)

// ─── Formula tests ────────────────────────────────────────────────────────────

func TestScoreFormulaWeightsSum(t *testing.T) {
	total := scorer.WeightAttackerConfidence +
		scorer.WeightSessionDepth +
		scorer.WeightQueryEntropy +
		scorer.WeightFailedAuthRatio
	if math.Abs(total-1.0) > 1e-9 {
		t.Errorf("weights must sum to 1.0, got %.6f", total)
	}
}

func TestScoreZeroSignalProducesZero(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID: "sess-zero",
		Timestamp: time.Now(),
	}
	result := sc.Score(sig)
	if result.RawScore != 0.0 {
		t.Errorf("zero signal should produce raw score 0, got %f", result.RawScore)
	}
}

func TestScoreMaxSignalProducesOne(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID:          "sess-max",
		AttackerConfidence: 1.0,
		SessionDepth:       1.0,
		QueryEntropy:       1.0,
		FailedAuthRatio:    1.0,
		Timestamp:          time.Now(),
	}
	result := sc.Score(sig)
	if math.Abs(result.RawScore-1.0) > 1e-9 {
		t.Errorf("max signal should produce raw score 1.0, got %f", result.RawScore)
	}
}

func TestScoreWeightsAppliedCorrectly(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID:          "sess-weights",
		AttackerConfidence: 1.0,
		SessionDepth:       0.0,
		QueryEntropy:       0.0,
		FailedAuthRatio:    0.0,
		Timestamp:          time.Now(),
	}
	result := sc.Score(sig)
	expected := scorer.WeightAttackerConfidence // 0.4
	if math.Abs(result.RawScore-expected) > 1e-9 {
		t.Errorf("only attacker_confidence=1: expected %.1f, got %f", expected, result.RawScore)
	}
}

func TestScoreTrapTableFloorsAtThreshold(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID:          "sess-trap",
		AttackerConfidence: 0.0,
		SessionDepth:       0.0,
		QueryEntropy:       0.0,
		FailedAuthRatio:    0.0,
		IsTrapTriggered:    true,
		Timestamp:          time.Now(),
	}
	result := sc.Score(sig)
	if result.RawScore < scorer.ScaleUpThreshold {
		t.Errorf("trap trigger must floor raw score at ScaleUpThreshold=%.1f, got %f",
			scorer.ScaleUpThreshold, result.RawScore)
	}
}

func TestScoreClampedToOneEvenWithTrap(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID:          "sess-clamp",
		AttackerConfidence: 1.0,
		SessionDepth:       1.0,
		QueryEntropy:       1.0,
		FailedAuthRatio:    1.0,
		IsTrapTriggered:    true,
		Timestamp:          time.Now(),
	}
	result := sc.Score(sig)
	if result.RawScore > 1.0 {
		t.Errorf("raw score must never exceed 1.0, got %f", result.RawScore)
	}
}

// ─── EWMA tests ───────────────────────────────────────────────────────────────

func TestEWMAFirstObservationEqualsRaw(t *testing.T) {
	sc := scorer.New()
	sig := scorer.SessionSignal{
		SessionID:          "ewma-first",
		AttackerConfidence: 0.8,
		Timestamp:          time.Now(),
	}
	result := sc.Score(sig)
	// First observation: smoothed = raw (seeded with raw value)
	if math.Abs(result.SmoothedScore-result.RawScore) > 1e-9 {
		t.Errorf("first EWMA observation should equal raw: smoothed=%f raw=%f",
			result.SmoothedScore, result.RawScore)
	}
}

func TestEWMASmoothesSpikeDownward(t *testing.T) {
	sc := scorer.New()
	sessID := "ewma-spike"
	now := time.Now()

	// Establish a low baseline
	for i := 0; i < 5; i++ {
		sc.Score(scorer.SessionSignal{
			SessionID:          sessID,
			AttackerConfidence: 0.1,
			Timestamp:          now,
		})
	}

	// Spike to 1.0
	spike := sc.Score(scorer.SessionSignal{
		SessionID:          sessID,
		AttackerConfidence: 1.0,
		Timestamp:          now,
	})

	// Smoothed should be less than raw due to EWMA
	if spike.SmoothedScore >= spike.RawScore {
		t.Errorf("EWMA should smooth spike downward: smoothed=%f raw=%f",
			spike.SmoothedScore, spike.RawScore)
	}
}

func TestEWMAConvergesOverTime(t *testing.T) {
	sc := scorer.New()
	sessID := "ewma-converge"
	now := time.Now()

	// AttackerConfidence=0.7, all other inputs=0.
	// raw = 0.4 * 0.7 = 0.28
	targetRaw := scorer.WeightAttackerConfidence * 0.7 // 0.28

	var lastSmoothed float64
	for i := 0; i < 20; i++ {
		r := sc.Score(scorer.SessionSignal{
			SessionID:          sessID,
			AttackerConfidence: 0.7,
			Timestamp:          now,
		})
		lastSmoothed = r.SmoothedScore
	}

	// After 20 observations at same raw value, smoothed should be close to raw
	if math.Abs(lastSmoothed-targetRaw) > 0.05 {
		t.Errorf("EWMA should converge to %.4f after 20 iterations, got %.4f",
			targetRaw, lastSmoothed)
	}
}

// ─── Z-score tests ────────────────────────────────────────────────────────────

func TestZScoreRequiresTenSamples(t *testing.T) {
	sc := scorer.New()
	// With fewer than 10 samples, noise detection should not flag anything
	for i := 0; i < 9; i++ {
		r := sc.Score(scorer.SessionSignal{
			SessionID:          "zscore-init",
			AttackerConfidence: 0.0,
			Timestamp:          time.Now(),
		})
		if r.IsNoise {
			t.Errorf("should not flag noise with only %d samples", i+1)
		}
	}
}

func TestZScoreDoesNotFlagHighScoreSessions(t *testing.T) {
	sc := scorer.New()
	now := time.Now()

	// Build up statistics with moderate scores
	for i := 0; i < 20; i++ {
		sc.Score(scorer.SessionSignal{
			SessionID:          "zscore-base",
			AttackerConfidence: 0.5,
			Timestamp:          now,
		})
	}

	// High score session should NOT be flagged as noise
	r := sc.Score(scorer.SessionSignal{
		SessionID:          "zscore-high",
		AttackerConfidence: 1.0,
		SessionDepth:       1.0,
		QueryEntropy:       1.0,
		Timestamp:          now,
	})
	if r.IsNoise {
		t.Error("high-score session should not be flagged as bot flood noise")
	}
}

// ─── Normalisation helpers ────────────────────────────────────────────────────

func TestNormaliseDepthClampsToOne(t *testing.T) {
	v := scorer.NormaliseDepth(100)
	if v != 1.0 {
		t.Errorf("NormaliseDepth(100) should return 1.0, got %f", v)
	}
}

func TestNormaliseDepthZero(t *testing.T) {
	v := scorer.NormaliseDepth(0)
	if v != 0.0 {
		t.Errorf("NormaliseDepth(0) should return 0.0, got %f", v)
	}
}

func TestNormaliseEntropyHalfMax(t *testing.T) {
	v := scorer.NormaliseEntropy(scorer.MaxEntropy / 2)
	if math.Abs(v-0.5) > 1e-9 {
		t.Errorf("NormaliseEntropy(MaxEntropy/2) should return 0.5, got %f", v)
	}
}

func TestNormaliseFailedAuthRatio(t *testing.T) {
	v := scorer.NormaliseFailedAuth(3, 10)
	expected := 3.0 / 13.0
	if math.Abs(v-expected) > 1e-9 {
		t.Errorf("NormaliseFailedAuth(3,10) should return %.6f, got %f", expected, v)
	}
}

func TestNormaliseFailedAuthAuthOnlySession(t *testing.T) {
	v := scorer.NormaliseFailedAuth(5, 0)
	if v != 1.0 {
		t.Errorf("NormaliseFailedAuth(5,0) should return 1.0 for auth-only brute force, got %f", v)
	}
}

// ─── Replica target tests ─────────────────────────────────────────────────────

func TestReplicaTargetMinAtZeroScore(t *testing.T) {
	sc := scorer.New()
	r := sc.Score(scorer.SessionSignal{
		SessionID: "replica-min",
		Timestamp: time.Now(),
	})
	if r.ReplicaTarget < scorer.ReplicaMin {
		t.Errorf("replica target must never go below ReplicaMin=%d, got %d",
			scorer.ReplicaMin, r.ReplicaTarget)
	}
}

func TestReplicaTargetMaxAtFullScore(t *testing.T) {
	sc := scorer.New()
	r := sc.Score(scorer.SessionSignal{
		SessionID:          "replica-max",
		AttackerConfidence: 1.0,
		SessionDepth:       1.0,
		QueryEntropy:       1.0,
		FailedAuthRatio:    1.0,
		Timestamp:          time.Now(),
	})
	if r.ReplicaTarget > scorer.ReplicaMax {
		t.Errorf("replica target must never exceed ReplicaMax=%d, got %d",
			scorer.ReplicaMax, r.ReplicaTarget)
	}
}

func TestCleanupSessionRemovesState(t *testing.T) {
	sc := scorer.New()
	sessID := "sess-cleanup"
	now := time.Now()

	// Establish EWMA state
	for i := 0; i < 3; i++ {
		sc.Score(scorer.SessionSignal{
			SessionID:          sessID,
			AttackerConfidence: 0.9,
			Timestamp:          now,
		})
	}

	// Cleanup
	sc.CleanupSession(sessID)

	// Next score should be seeded as fresh (smoothed == raw)
	r := sc.Score(scorer.SessionSignal{
		SessionID:          sessID,
		AttackerConfidence: 0.5,
		Timestamp:          now,
	})
	if math.Abs(r.SmoothedScore-r.RawScore) > 1e-9 {
		t.Errorf("after cleanup, first score should seed EWMA from raw: smoothed=%f raw=%f",
			r.SmoothedScore, r.RawScore)
	}
}

func TestSnapshotReturnsGlobalStats(t *testing.T) {
	sc := scorer.New()
	for i := 0; i < 5; i++ {
		sc.Score(scorer.SessionSignal{
			SessionID:          "stats-test",
			AttackerConfidence: 0.5,
			Timestamp:          time.Now(),
		})
	}
	mean, _, count, _ := sc.Snapshot()
	if count < 5 {
		t.Errorf("Snapshot count should be >= 5, got %d", count)
	}
	if mean <= 0 {
		t.Errorf("Snapshot mean should be > 0 after positive scores, got %f", mean)
	}
}
func TestNormaliseDepthAcceptsFractionalSessionModuleValue(t *testing.T) {
	v := scorer.NormaliseDepth(2.5)
	if math.Abs(v-0.25) > 0.0001 {
		t.Errorf("NormaliseDepth(2.5) should return 0.25, got %f", v)
	}
}
