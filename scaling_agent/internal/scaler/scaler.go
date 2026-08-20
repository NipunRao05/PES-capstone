// Package scaler orchestrates the scaling pipeline.
// It receives SessionSignals, runs them through the Scorer,
// and exposes the current replica target for KEDA to consume.
package scaler

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scalingagent/internal/scorer"
)

// ScalingEvent is emitted for every meaningful scaling decision.
type ScalingEvent struct {
	SessionID     string
	RawScore      float64
	SmoothedScore float64
	IsNoise       bool
	ZScore        float64
	ReplicaTarget int
	Reason        string
	Timestamp     time.Time
}

// Metrics holds observable counters.
type Metrics struct {
	TotalSignals      atomic.Int64
	NoiseSignals      atomic.Int64
	ScaleUpEvents     atomic.Int64
	ScaleDownEvents   atomic.Int64
	TrapTriggers      atomic.Int64
	CurrentReplicas   atomic.Int64
	ScalePressureBits atomic.Uint64
}

// Scaler is the central scaling controller.
type Scaler struct {
	scorer  *scorer.Scorer
	logger  *slog.Logger
	metrics Metrics

	mu     sync.RWMutex
	events []ScalingEvent // ring buffer of last 1000 events
}

// New creates a Scaler.
func New(logger *slog.Logger) *Scaler {
	s := &Scaler{
		scorer: scorer.New(),
		logger: logger,
		events: make([]ScalingEvent, 0, 1000),
	}
	s.metrics.CurrentReplicas.Store(int64(scorer.ReplicaMin))
	s.metrics.ScalePressureBits.Store(math.Float64bits(0.0))
	return s
}

// Run consumes signals from the channel and processes them.
// Blocks until ctx is cancelled.
func (s *Scaler) Run(ctx context.Context, signals <-chan scorer.SessionSignal) {
	s.logger.Info("scaling agent started",
		"scale_up_threshold", scorer.ScaleUpThreshold,
		"scale_down_threshold", scorer.ScaleDownThreshold,
		"ewma_alpha", scorer.EWMAAlpha,
		"z_score_threshold", scorer.ZScoreThreshold,
		"replica_min", scorer.ReplicaMin,
		"replica_max", scorer.ReplicaMax,
	)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scaling agent stopping")
			return

		case sig, ok := <-signals:
			if !ok {
				return
			}
			s.process(sig)
			if sig.IsSessionClosed {
				s.CleanupSession(sig.SessionID)
			}
		}
	}
}

func (s *Scaler) process(sig scorer.SessionSignal) {
	s.metrics.TotalSignals.Add(1)

	if sig.IsTrapTriggered {
		s.metrics.TrapTriggers.Add(1)
	}

	result := s.scorer.Score(sig)
	s.metrics.ScalePressureBits.Store(math.Float64bits(result.SmoothedScore))

	if result.IsNoise {
		s.metrics.NoiseSignals.Add(1)
		s.logger.Debug("noise session suppressed",
			"session_id", sig.SessionID,
			"z_score", result.ZScore,
		)
		return
	}

	prevReplicas := s.metrics.CurrentReplicas.Load()
	s.metrics.CurrentReplicas.Store(int64(result.ReplicaTarget))

	if int64(result.ReplicaTarget) > prevReplicas {
		s.metrics.ScaleUpEvents.Add(1)
		s.logger.Info("SCALE UP",
			"session_id", shortID(sig.SessionID),
			"from", prevReplicas,
			"to", result.ReplicaTarget,
			"raw_score", result.RawScore,
			"smoothed_score", result.SmoothedScore,
			"reason", result.Reason,
		)
	} else if int64(result.ReplicaTarget) < prevReplicas {
		s.metrics.ScaleDownEvents.Add(1)
		s.logger.Info("SCALE DOWN",
			"session_id", shortID(sig.SessionID),
			"from", prevReplicas,
			"to", result.ReplicaTarget,
			"smoothed_score", result.SmoothedScore,
			"reason", result.Reason,
		)
	} else {
		s.logger.Debug("scale hold",
			"session_id", shortID(sig.SessionID),
			"replicas", result.ReplicaTarget,
			"smoothed_score", result.SmoothedScore,
		)
	}

	ev := ScalingEvent{
		SessionID:     sig.SessionID,
		RawScore:      result.RawScore,
		SmoothedScore: result.SmoothedScore,
		IsNoise:       result.IsNoise,
		ZScore:        result.ZScore,
		ReplicaTarget: result.ReplicaTarget,
		Reason:        result.Reason,
		Timestamp:     sig.Timestamp,
	}

	s.mu.Lock()
	if len(s.events) >= 1000 {
		s.events = s.events[1:] // evict oldest
	}
	s.events = append(s.events, ev)
	s.mu.Unlock()
}

// CurrentReplicas returns the current desired replica count.
// This is the value KEDA reads via the metrics endpoint.
func (s *Scaler) CurrentReplicas() int {
	return int(s.metrics.CurrentReplicas.Load())
}

// RecentEvents returns the last n scaling events (most recent last).
func (s *Scaler) RecentEvents(n int) []ScalingEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n > len(s.events) {
		n = len(s.events)
	}
	result := make([]ScalingEvent, n)
	copy(result, s.events[len(s.events)-n:])
	return result
}

// ScorerSnapshot proxies the scorer's statistics snapshot.
func (s *Scaler) ScorerSnapshot() (mean, stdDev float64, count int64, replicas int) {
	return s.scorer.Snapshot()
}

// CleanupSession removes state for a closed session.
func (s *Scaler) CleanupSession(sessionID string) {
	s.scorer.CleanupSession(sessionID)
}

// MetricsSnapshot returns a copy of all atomic counters.
type MetricsSnapshot struct {
	TotalSignals    int64
	NoiseSignals    int64
	ScaleUpEvents   int64
	ScaleDownEvents int64
	TrapTriggers    int64
	CurrentReplicas int64
	ScalePressure   float64
}

// Snapshot returns a consistent snapshot of all metrics.
func (s *Scaler) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		TotalSignals:    s.metrics.TotalSignals.Load(),
		NoiseSignals:    s.metrics.NoiseSignals.Load(),
		ScaleUpEvents:   s.metrics.ScaleUpEvents.Load(),
		ScaleDownEvents: s.metrics.ScaleDownEvents.Load(),
		TrapTriggers:    s.metrics.TrapTriggers.Load(),
		CurrentReplicas: s.metrics.CurrentReplicas.Load(),
		ScalePressure:   math.Float64frombits(s.metrics.ScalePressureBits.Load()),
	}
}

func shortID(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}
