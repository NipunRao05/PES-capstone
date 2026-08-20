// scorer.go
//
//	Package scorer implements the scaling intelligence engine.
//
// Formula (from capstone spec):
//
//	scale_score = 0.4 * attacker_confidence
//	            + 0.3 * session_depth
//	            + 0.2 * query_entropy
//	            + 0.1 * failed_auth_ratio
//
// EWMA smoothing prevents sudden scale spikes.
// Z-score anomaly detection collapses bot-flood noise sessions.
package scorer

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// ─── Weights (capstone spec, frozen) ─────────────────────────────────────────

const (
	WeightAttackerConfidence float64 = 0.4
	WeightSessionDepth       float64 = 0.3
	WeightQueryEntropy       float64 = 0.2
	WeightFailedAuthRatio    float64 = 0.1

	// EWMA smoothing factor: 0.3 = conservative, slow to react to spikes.
	// Higher α = more reactive, lower α = smoother.
	EWMAAlpha float64 = 0.3

	// Z-score threshold: sessions with z-score above this are bot floods.
	// Flagged sessions are collapsed to noise and do not drive scaling.
	ZScoreThreshold float64 = 2.5

	// MaxSessionDepth is the normalisation cap for raw depth scores.
	MaxSessionDepth float64 = 10.0

	// MaxEntropy is the normalisation cap for raw entropy values.
	MaxEntropy float64 = 4.0

	// ReplicaMin/Max are the honeypot replica bounds.
	ReplicaMin int = 1
	ReplicaMax int = 10

	// ScaleUpThreshold: scale_score above this triggers replica increase.
	ScaleUpThreshold float64 = 0.6

	// ScaleDownThreshold: score below this for ScaleDownWindow triggers decrease.
	ScaleDownThreshold float64 = 0.3

	// ScaleDownWindow: how long score must stay below threshold before scaling down.
	ScaleDownWindow = 2 * time.Minute

	// ScaleUpCooldown prevents repeated high-risk events from causing rapid repeated scale-up.
	ScaleUpCooldown = 30 * time.Second

	// MaxScaleUpStep bounds each scale-up decision to reduce resource amplification risk.
	MaxScaleUpStep int = 2
)

// ─── Input ───────────────────────────────────────────────────────────────────

// SessionSignal is one data point consumed from mitre-events or session-profiles.
// All fields are already normalised to [0, 1] by the caller.
type SessionSignal struct {
	EventID            string
	SignalSource       string
	SessionID          string
	ClientIP           string
	AttackerConfidence float64 // rule_confidence from MitreEvent (already 0-1)
	SessionDepth       float64 // raw depth_score / MaxSessionDepth
	QueryEntropy       float64 // raw entropy / MaxEntropy
	FailedAuthRatio    float64 // failed_auth / max(total_queries, 1)
	IsTrapTriggered    bool
	IsSessionClosed    bool // true when derived from a final session-profile event
	Timestamp          time.Time
}

// ─── Output ──────────────────────────────────────────────────────────────────

// ScoreResult is the output of one scoring cycle.
type ScoreResult struct {
	SessionID     string
	RawScore      float64 // unsmoothed scale_score
	SmoothedScore float64 // EWMA-smoothed score
	IsNoise       bool    // true = bot flood, do not drive scaling
	ZScore        float64 // how many σ above mean this session is
	ReplicaTarget int     // suggested replica count
	Reason        string  // human-readable scaling reason (capstone spec)
}

// ─── Scorer ──────────────────────────────────────────────────────────────────

// Scorer maintains per-session EWMA state and global statistics for Z-score.
type Scorer struct {
	mu sync.Mutex

	// Per-session EWMA state: session_id -> smoothed score
	ewmaState map[string]float64

	// Global rolling statistics for Z-score anomaly detection
	// (running mean and variance using Welford's algorithm)
	count int64
	mean  float64
	m2    float64 // sum of squared differences from mean (Welford)

	// Current replica count (owned by Scaler, mirrored here for Decide)
	currentReplicas int

	// Last accepted scale-up time. Used as a global cooldown guard.
	lastScaleUpAt time.Time

	// Global time since cluster pressure entered the low-risk zone.
	belowScaleDownSince time.Time

	// Track last scale-down eligible time per session
	belowThresholdSince map[string]time.Time
}

// PersistentState is the complete decision state required to continue
// cooldown, EWMA, anomaly, and scale-down timing behavior after a restart.
type PersistentState struct {
	EWMAState           map[string]float64   `json:"ewma_state"`
	Count               int64                `json:"count"`
	Mean                float64              `json:"mean"`
	M2                  float64              `json:"m2"`
	CurrentReplicas     int                  `json:"current_replicas"`
	LastScaleUpAt       time.Time            `json:"last_scale_up_at"`
	BelowScaleDownSince time.Time            `json:"below_scale_down_since"`
	BelowThresholdSince map[string]time.Time `json:"below_threshold_since"`
}

// New creates a Scorer with sensible defaults.
func New() *Scorer {
	return &Scorer{
		ewmaState:           make(map[string]float64),
		belowThresholdSince: make(map[string]time.Time),
		currentReplicas:     ReplicaMin,
	}
}

// ExportState returns a deep copy suitable for durable JSON persistence.
func (s *Scorer) ExportState() PersistentState {
	s.mu.Lock()
	defer s.mu.Unlock()

	ewma := make(map[string]float64, len(s.ewmaState))
	for sessionID, value := range s.ewmaState {
		ewma[sessionID] = value
	}
	below := make(map[string]time.Time, len(s.belowThresholdSince))
	for sessionID, since := range s.belowThresholdSince {
		below[sessionID] = since
	}

	return PersistentState{
		EWMAState:           ewma,
		Count:               s.count,
		Mean:                s.mean,
		M2:                  s.m2,
		CurrentReplicas:     s.currentReplicas,
		LastScaleUpAt:       s.lastScaleUpAt,
		BelowScaleDownSince: s.belowScaleDownSince,
		BelowThresholdSince: below,
	}
}

// RestoreState validates and restores decision state without resetting timers.
func (s *Scorer) RestoreState(state PersistentState) error {
	if state.CurrentReplicas < ReplicaMin || state.CurrentReplicas > ReplicaMax {
		return fmt.Errorf("scorer replicas out of range: %d", state.CurrentReplicas)
	}
	if state.Count < 0 || state.M2 < 0 || math.IsNaN(state.Mean) || math.IsInf(state.Mean, 0) || math.IsNaN(state.M2) || math.IsInf(state.M2, 0) {
		return fmt.Errorf("invalid scorer rolling statistics")
	}
	ewma := make(map[string]float64, len(state.EWMAState))
	for sessionID, value := range state.EWMAState {
		if sessionID == "" || value < 0 || value > 1 || math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("invalid EWMA entry for session %q", sessionID)
		}
		ewma[sessionID] = value
	}
	below := make(map[string]time.Time, len(state.BelowThresholdSince))
	for sessionID, since := range state.BelowThresholdSince {
		if sessionID == "" {
			return fmt.Errorf("invalid empty session in scale-down state")
		}
		below[sessionID] = since
	}

	s.mu.Lock()
	s.ewmaState = ewma
	s.count = state.Count
	s.mean = state.Mean
	s.m2 = state.M2
	s.currentReplicas = state.CurrentReplicas
	s.lastScaleUpAt = state.LastScaleUpAt
	s.belowScaleDownSince = state.BelowScaleDownSince
	s.belowThresholdSince = below
	s.mu.Unlock()
	return nil
}

// SetCurrentReplicas synchronizes the scorer with an operator-selected target.
// Operator controls own the effective target while this method is in use; the
// scoring model continues to collect EWMA and anomaly telemetry.
func (s *Scorer) SetCurrentReplicas(target int) error {
	if target < ReplicaMin || target > ReplicaMax {
		return fmt.Errorf("scorer replicas out of range: %d", target)
	}
	s.mu.Lock()
	s.currentReplicas = target
	s.mu.Unlock()
	return nil
}

// ResetScaleUpCooldown lets automatic scaling resume immediately after an
// operator releases a hold. A scale-up suppressed by safe mode or a disabled
// autoscaler must not consume the automatic scale-up cooldown.
func (s *Scorer) ResetScaleUpCooldown() {
	s.mu.Lock()
	s.lastScaleUpAt = time.Time{}
	s.mu.Unlock()
}

// Score computes the scale_score for one session signal and returns a decision.
func (s *Scorer) Score(sig SessionSignal) ScoreResult {
	// ── Step 1: raw score ────────────────────────────────────────────────────
	raw := WeightAttackerConfidence*sig.AttackerConfidence +
		WeightSessionDepth*sig.SessionDepth +
		WeightQueryEntropy*sig.QueryEntropy +
		WeightFailedAuthRatio*sig.FailedAuthRatio

	// Trap table access immediately floors the score at ScaleUpThreshold.
	if sig.IsTrapTriggered && raw < ScaleUpThreshold {
		raw = ScaleUpThreshold + 0.1
	}

	// Clamp to [0, 1]
	raw = clamp(raw, 0.0, 1.0)

	s.mu.Lock()
	defer s.mu.Unlock()

	// ── Step 2: EWMA smoothing ───────────────────────────────────────────────
	prev, exists := s.ewmaState[sig.SessionID]
	var smoothed float64
	if !exists {
		smoothed = raw // first observation: seed with raw
	} else {
		smoothed = EWMAAlpha*raw + (1-EWMAAlpha)*prev
	}
	s.ewmaState[sig.SessionID] = smoothed

	// ── Step 3: update global statistics (Welford online algorithm) ──────────
	s.count++
	delta := smoothed - s.mean
	s.mean += delta / float64(s.count)
	delta2 := smoothed - s.mean
	s.m2 += delta * delta2

	// ── Step 4: Z-score anomaly detection ────────────────────────────────────
	var zScore float64
	isNoise := false
	if s.count > 10 { // need enough samples for meaningful statistics
		variance := s.m2 / float64(s.count-1)
		stdDev := math.Sqrt(variance)
		if stdDev > 0 {
			zScore = (smoothed - s.mean) / stdDev
		}
		// High-volume, low-score sessions are bot floods: many sessions
		// all scoring near zero. Flag as noise so they don't trigger scaling.
		if math.Abs(zScore) > ZScoreThreshold && smoothed < ScaleDownThreshold {
			isNoise = true
		}
	}

	// ── Step 5: replica target ───────────────────────────────────────────────
	target, reason := s.replicaTarget(sig.SessionID, smoothed, isNoise, sig.Timestamp)

	return ScoreResult{
		SessionID:     sig.SessionID,
		RawScore:      raw,
		SmoothedScore: smoothed,
		IsNoise:       isNoise,
		ZScore:        zScore,
		ReplicaTarget: target,
		Reason:        reason,
	}
}

// replicaTarget computes the desired replica count based on the smoothed score.
// It respects scale-down hysteresis: replicas only decrease after the score
// has been below ScaleDownThreshold for the full ScaleDownWindow.
func (s *Scorer) replicaTarget(sessionID string, smoothed float64, isNoise bool, now time.Time) (int, string) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if isNoise {
		return s.currentReplicas, "bot flood detected via Z-score - holding current replicas"
	}

	// High-risk zone: scale up with cooldown and bounded step size.
	if smoothed >= ScaleUpThreshold {
		s.belowScaleDownSince = time.Time{}
		delete(s.belowThresholdSince, sessionID)

		proposed := ReplicaMin + int(math.Round(float64(ReplicaMax-ReplicaMin)*smoothed))
		proposed = clampInt(proposed, ReplicaMin, ReplicaMax)

		if proposed <= s.currentReplicas {
			return s.currentReplicas, "score above scale-up threshold - holding current replicas"
		}

		if !s.lastScaleUpAt.IsZero() {
			elapsed := now.Sub(s.lastScaleUpAt)
			if elapsed < ScaleUpCooldown {
				return s.currentReplicas,
					"scale-up cooldown active elapsed_seconds=" + itoa(int(elapsed.Seconds())) +
						" required_seconds=" + itoa(int(ScaleUpCooldown.Seconds())) +
						" proposed_replicas=" + itoa(proposed)
			}
		}

		target := proposed
		if target-s.currentReplicas > MaxScaleUpStep {
			target = s.currentReplicas + MaxScaleUpStep
		}
		target = clampInt(target, ReplicaMin, ReplicaMax)

		reason := formatReason("scaling UP", s.currentReplicas, target, smoothed)
		if target < proposed {
			reason += " proposed_replicas=" + itoa(proposed) + " max_step=" + itoa(MaxScaleUpStep)
		}

		s.lastScaleUpAt = now
		s.currentReplicas = target
		return target, reason
	}

	// Medium-risk zone: hold. This fixes the previous design gap where any score
	// below ScaleUpThreshold could start the scale-down timer.
	if smoothed >= ScaleDownThreshold {
		s.belowScaleDownSince = time.Time{}
		delete(s.belowThresholdSince, sessionID)
		return s.currentReplicas, "score between thresholds - holding current replicas"
	}

	// Low-risk zone: scale down only after sustained low pressure.
	if s.belowScaleDownSince.IsZero() {
		s.belowScaleDownSince = now
		return s.currentReplicas,
			"score below scale-down threshold - starting scale-down timer elapsed_seconds=0 required_seconds=" +
				itoa(int(ScaleDownWindow.Seconds()))
	}

	elapsed := now.Sub(s.belowScaleDownSince)
	if elapsed >= ScaleDownWindow {
		s.belowScaleDownSince = time.Time{}
		delete(s.belowThresholdSince, sessionID)

		target := clampInt(s.currentReplicas-1, ReplicaMin, ReplicaMax)
		if target < s.currentReplicas {
			reason := formatReason("scaling DOWN", s.currentReplicas, target, smoothed) +
				" elapsed_seconds=" + itoa(int(elapsed.Seconds())) +
				" required_seconds=" + itoa(int(ScaleDownWindow.Seconds()))
			s.currentReplicas = target
			return target, reason
		}
	}

	return s.currentReplicas,
		"score below scale-down threshold - within scale-down window elapsed_seconds=" +
			itoa(int(elapsed.Seconds())) +
			" required_seconds=" + itoa(int(ScaleDownWindow.Seconds()))
}

// Snapshot returns a read-safe view of current global statistics.
func (s *Scorer) Snapshot() (mean, stdDev float64, count int64, replicas int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mean = s.mean
	count = s.count
	replicas = s.currentReplicas
	if s.count > 1 {
		stdDev = math.Sqrt(s.m2 / float64(s.count-1))
	}
	return
}

// CleanupSession removes EWMA state for a closed session to prevent memory leak.
func (s *Scorer) CleanupSession(sessionID string) {
	s.mu.Lock()
	delete(s.ewmaState, sessionID)
	delete(s.belowThresholdSince, sessionID)
	s.mu.Unlock()
}

// NormaliseDepth converts a raw depth_score value to a [0,1] float.
// The Python session module emits depth_score as a JSON number that may be
// integral (1) or floating-point (1.0/1.5). Accept float64 here so the scaling
// agent can consume session-profiles without json.Unmarshal failures or lossy
// truncation.
func NormaliseDepth(raw float64) float64 {
	return clamp(raw/MaxSessionDepth, 0.0, 1.0)
}

// NormaliseEntropy converts a raw entropy float to a [0,1] float.
func NormaliseEntropy(raw float64) float64 {
	return clamp(raw/MaxEntropy, 0.0, 1.0)
}

// NormaliseFailedAuth converts auth failures into a [0,1] pressure signal.
// Auth-only brute-force sessions are common in honeypots, so the denominator
// must include failures as activity; otherwise failed-auth-only sessions score 0.
func NormaliseFailedAuth(failedAuth, totalQueries int) float64 {
	if failedAuth <= 0 {
		return 0.0
	}
	denom := failedAuth + totalQueries
	if denom <= 0 {
		return 0.0
	}
	return clamp(float64(failedAuth)/float64(denom), 0.0, 1.0)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func formatReason(action string, from, to int, score float64) string {
	return action + ": " +
		itoa(from) + " -> " + itoa(to) +
		" replicas (smoothed_score=" + ftoa(score) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func ftoa(f float64) string {
	// Simple 3-decimal-place formatter, no stdlib dependency
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	i := int(f)
	frac := int((f-float64(i))*1000 + 0.5)
	return sign + itoa(i) + "." + padLeft(itoa(frac), 3)
}

func padLeft(s string, width int) string {
	for len(s) < width {
		s = "0" + s
	}
	return s
}
