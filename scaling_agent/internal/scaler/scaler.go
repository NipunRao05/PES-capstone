// Package scaler orchestrates the scaling pipeline.
// It receives SessionSignals, runs them through the Scorer,
// and exposes the current replica target for KEDA to consume.
package scaler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scalingagent/internal/scorer"
)

// ScalingEvent is emitted for every meaningful scaling decision.
type ScalingEvent struct {
	EventID       string    `json:"event_id,omitempty"`
	SignalSource  string    `json:"signal_source,omitempty"`
	SessionID     string    `json:"session_id"`
	RawScore      float64   `json:"raw_score"`
	SmoothedScore float64   `json:"smoothed_score"`
	IsNoise       bool      `json:"is_noise"`
	ZScore        float64   `json:"z_score"`
	ReplicaTarget int       `json:"replica_target"`
	Reason        string    `json:"reason"`
	Timestamp     time.Time `json:"timestamp"`
}

// Metrics holds observable counters.
type Metrics struct {
	TotalSignals      atomic.Int64
	NoiseSignals      atomic.Int64
	ScaleUpEvents     atomic.Int64
	ScaleDownEvents   atomic.Int64
	TrapTriggers      atomic.Int64
	DuplicateEvents   atomic.Int64
	CurrentReplicas   atomic.Int64
	ScalePressureBits atomic.Uint64
}

const PersistentStateVersion = 1
const maxProcessedEventIDs = 10000

// ControlState reserves durable operator-control fields for the control API.
// Phase 8 will mutate these values; Phase 5 guarantees they survive restarts.
type ControlState struct {
	ManualReplicaTarget *int `json:"manual_replica_target,omitempty"`
	SafeMode            bool `json:"safe_mode"`
	AutoscalingEnabled  bool `json:"autoscaling_enabled"`
}

// PersistentState is the versioned Redis payload for all operational state.
type PersistentState struct {
	Version           int                    `json:"version"`
	SavedAt           time.Time              `json:"saved_at"`
	Metrics           MetricsSnapshot        `json:"metrics"`
	Scorer            scorer.PersistentState `json:"scorer"`
	RecentEvents      []ScalingEvent         `json:"recent_events"`
	Control           ControlState           `json:"control"`
	ProcessedEventIDs []string               `json:"processed_event_ids"`
}

type StateSaver func(PersistentState) error

// PersistenceStatus is exposed in /metrics for restart validation.
type PersistenceStatus struct {
	Enabled     bool      `json:"enabled"`
	Restored    bool      `json:"restored"`
	LastSavedAt time.Time `json:"last_saved_at"`
	LastError   string    `json:"last_error,omitempty"`
	StateKey    string    `json:"state_key,omitempty"`
}

// Scaler is the central scaling controller.
type Scaler struct {
	scorer  *scorer.Scorer
	logger  *slog.Logger
	metrics Metrics

	mu                sync.RWMutex
	events            []ScalingEvent // ring buffer of last 1000 events
	control           ControlState
	processedEventIDs []string
	processedEventSet map[string]struct{}

	saverMu       sync.RWMutex
	saver         StateSaver
	persistenceMu sync.RWMutex
	persistence   PersistenceStatus
}

// New creates a Scaler.
func New(logger *slog.Logger) *Scaler {
	s := &Scaler{
		scorer:            scorer.New(),
		logger:            logger,
		events:            make([]ScalingEvent, 0, 1000),
		control:           ControlState{AutoscalingEnabled: true},
		processedEventIDs: make([]string, 0),
		processedEventSet: make(map[string]struct{}),
	}
	s.metrics.CurrentReplicas.Store(int64(scorer.ReplicaMin))
	s.metrics.ScalePressureBits.Store(math.Float64bits(0.0))
	return s
}

// SetStateSaver enables durable state writes after every processed signal.
func (s *Scaler) SetStateSaver(saver StateSaver, restored bool, stateKey string) {
	s.saverMu.Lock()
	s.saver = saver
	s.saverMu.Unlock()

	s.persistenceMu.Lock()
	s.persistence.Enabled = saver != nil
	s.persistence.Restored = restored
	s.persistence.StateKey = stateKey
	s.persistenceMu.Unlock()
}

// PersistenceStatus returns a race-safe copy for the metrics endpoint.
func (s *Scaler) PersistenceStatus() PersistenceStatus {
	s.persistenceMu.RLock()
	defer s.persistenceMu.RUnlock()
	return s.persistence
}

// ExportState returns a deep copy of all operational state.
func (s *Scaler) ExportState() PersistentState {
	s.mu.RLock()
	events := append([]ScalingEvent(nil), s.events...)
	processed := append([]string(nil), s.processedEventIDs...)
	control := s.control
	if s.control.ManualReplicaTarget != nil {
		target := *s.control.ManualReplicaTarget
		control.ManualReplicaTarget = &target
	}
	s.mu.RUnlock()

	return PersistentState{
		Version:           PersistentStateVersion,
		SavedAt:           time.Now().UTC(),
		Metrics:           s.Snapshot(),
		Scorer:            s.scorer.ExportState(),
		RecentEvents:      events,
		Control:           control,
		ProcessedEventIDs: processed,
	}
}

// RestoreState validates and restores a previously persisted state snapshot.
func (s *Scaler) RestoreState(state PersistentState) error {
	if state.Version != PersistentStateVersion {
		return fmt.Errorf("unsupported scaling state version: %d", state.Version)
	}
	if state.Metrics.CurrentReplicas < int64(scorer.ReplicaMin) || state.Metrics.CurrentReplicas > int64(scorer.ReplicaMax) {
		return fmt.Errorf("persisted replicas out of range: %d", state.Metrics.CurrentReplicas)
	}
	if state.Metrics.TotalSignals < 0 || state.Metrics.NoiseSignals < 0 || state.Metrics.ScaleUpEvents < 0 || state.Metrics.ScaleDownEvents < 0 || state.Metrics.TrapTriggers < 0 || state.Metrics.DuplicateEvents < 0 {
		return fmt.Errorf("persisted counters cannot be negative")
	}
	if state.Metrics.ScalePressure < 0 || state.Metrics.ScalePressure > 1 || math.IsNaN(state.Metrics.ScalePressure) || math.IsInf(state.Metrics.ScalePressure, 0) {
		return fmt.Errorf("persisted scale pressure is invalid")
	}
	if state.Scorer.CurrentReplicas != int(state.Metrics.CurrentReplicas) {
		return fmt.Errorf("scorer replicas %d do not match metrics replicas %d", state.Scorer.CurrentReplicas, state.Metrics.CurrentReplicas)
	}
	if state.Control.ManualReplicaTarget != nil {
		target := *state.Control.ManualReplicaTarget
		if target < scorer.ReplicaMin || target > scorer.ReplicaMax {
			return fmt.Errorf("manual replica target out of range: %d", target)
		}
	}
	if len(state.RecentEvents) > 1000 {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-1000:]
	}
	if len(state.ProcessedEventIDs) > maxProcessedEventIDs {
		state.ProcessedEventIDs = state.ProcessedEventIDs[len(state.ProcessedEventIDs)-maxProcessedEventIDs:]
	}
	processedSet := make(map[string]struct{}, len(state.ProcessedEventIDs))
	for _, eventID := range state.ProcessedEventIDs {
		if eventID == "" {
			return fmt.Errorf("persisted processed event ID cannot be empty")
		}
		if _, duplicate := processedSet[eventID]; duplicate {
			return fmt.Errorf("persisted processed event ID is duplicated: %s", eventID)
		}
		processedSet[eventID] = struct{}{}
	}
	for _, event := range state.RecentEvents {
		if event.ReplicaTarget < scorer.ReplicaMin || event.ReplicaTarget > scorer.ReplicaMax {
			return fmt.Errorf("event replica target out of range: %d", event.ReplicaTarget)
		}
	}
	if err := s.scorer.RestoreState(state.Scorer); err != nil {
		return err
	}

	s.metrics.TotalSignals.Store(state.Metrics.TotalSignals)
	s.metrics.NoiseSignals.Store(state.Metrics.NoiseSignals)
	s.metrics.ScaleUpEvents.Store(state.Metrics.ScaleUpEvents)
	s.metrics.ScaleDownEvents.Store(state.Metrics.ScaleDownEvents)
	s.metrics.TrapTriggers.Store(state.Metrics.TrapTriggers)
	s.metrics.DuplicateEvents.Store(state.Metrics.DuplicateEvents)
	s.metrics.CurrentReplicas.Store(state.Metrics.CurrentReplicas)
	s.metrics.ScalePressureBits.Store(math.Float64bits(state.Metrics.ScalePressure))

	s.mu.Lock()
	s.events = append([]ScalingEvent(nil), state.RecentEvents...)
	s.control = state.Control
	if state.Control.ManualReplicaTarget != nil {
		target := *state.Control.ManualReplicaTarget
		s.control.ManualReplicaTarget = &target
	}
	s.processedEventIDs = append([]string(nil), state.ProcessedEventIDs...)
	s.processedEventSet = processedSet
	s.mu.Unlock()
	return nil
}

// SaveNow writes the current state synchronously when persistence is enabled.
func (s *Scaler) SaveNow() error {
	s.saverMu.RLock()
	saver := s.saver
	s.saverMu.RUnlock()
	if saver == nil {
		return nil
	}

	state := s.ExportState()
	err := saver(state)
	s.persistenceMu.Lock()
	if err != nil {
		s.persistence.LastError = err.Error()
	} else {
		s.persistence.LastSavedAt = state.SavedAt
		s.persistence.LastError = ""
	}
	s.persistenceMu.Unlock()
	return err
}

func (s *Scaler) persistState() {
	if err := s.SaveNow(); err != nil {
		s.logger.Error("failed to persist scaling state", "error", err)
	}
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
			s.persistState()
			s.logger.Info("scaling agent stopping")
			return

		case sig, ok := <-signals:
			if !ok {
				s.persistState()
				return
			}
			if s.process(sig) && sig.IsSessionClosed {
				s.CleanupSession(sig.SessionID)
			}
		}
	}
}

func (s *Scaler) process(sig scorer.SessionSignal) bool {
	if !s.claimEvent(sig.EventID) {
		s.metrics.DuplicateEvents.Add(1)
		s.logger.Info("duplicate event ignored",
			"event_id", sig.EventID,
			"session_id", shortID(sig.SessionID),
			"source", sig.SignalSource,
		)
		s.persistState()
		return false
	}
	defer s.persistState()
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
		return true
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
		EventID:       sig.EventID,
		SignalSource:  sig.SignalSource,
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
	return true
}

func (s *Scaler) claimEvent(eventID string) bool {
	if eventID == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.processedEventSet[eventID]; exists {
		return false
	}
	if len(s.processedEventIDs) >= maxProcessedEventIDs {
		oldest := s.processedEventIDs[0]
		delete(s.processedEventSet, oldest)
		s.processedEventIDs = s.processedEventIDs[1:]
	}
	s.processedEventIDs = append(s.processedEventIDs, eventID)
	s.processedEventSet[eventID] = struct{}{}
	return true
}

// ProcessedEventCount returns the bounded durable idempotency-set size.
func (s *Scaler) ProcessedEventCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.processedEventIDs)
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
	s.persistState()
}

// MetricsSnapshot returns a copy of all atomic counters.
type MetricsSnapshot struct {
	TotalSignals    int64   `json:"total_signals"`
	NoiseSignals    int64   `json:"noise_signals"`
	ScaleUpEvents   int64   `json:"scale_up_events"`
	ScaleDownEvents int64   `json:"scale_down_events"`
	TrapTriggers    int64   `json:"trap_triggers"`
	DuplicateEvents int64   `json:"duplicate_events"`
	CurrentReplicas int64   `json:"current_replicas"`
	ScalePressure   float64 `json:"scale_pressure"`
}

// Snapshot returns a consistent snapshot of all metrics.
func (s *Scaler) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		TotalSignals:    s.metrics.TotalSignals.Load(),
		NoiseSignals:    s.metrics.NoiseSignals.Load(),
		ScaleUpEvents:   s.metrics.ScaleUpEvents.Load(),
		ScaleDownEvents: s.metrics.ScaleDownEvents.Load(),
		TrapTriggers:    s.metrics.TrapTriggers.Load(),
		DuplicateEvents: s.metrics.DuplicateEvents.Load(),
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
