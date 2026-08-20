// Package scaler orchestrates the scaling pipeline.
// It receives SessionSignals, runs them through the Scorer,
// and exposes the current replica target for KEDA to consume.
package scaler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
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
const maxControlAuditEvents = 200

// ControlState is the durable operator policy applied to scaling decisions.
type ControlState struct {
	ManualReplicaTarget *int `json:"manual_replica_target,omitempty"`
	SafeMode            bool `json:"safe_mode"`
	AutoscalingEnabled  bool `json:"autoscaling_enabled"`
	MaxReplicaBudget    int  `json:"max_replica_budget"`
}

// ControlAuditEvent records every operator mutation for later review.
type ControlAuditEvent struct {
	AuditID   string       `json:"audit_id"`
	Action    string       `json:"action"`
	Actor     string       `json:"actor"`
	Reason    string       `json:"reason"`
	Previous  ControlState `json:"previous"`
	Current   ControlState `json:"current"`
	Timestamp time.Time    `json:"timestamp"`
}

// ControlStatus is the public control-plane view returned by the HTTP API.
type ControlStatus struct {
	Control         ControlState        `json:"control"`
	CurrentReplicas int                 `json:"current_replicas"`
	EffectiveMode   string              `json:"effective_mode"`
	AuditEvents     []ControlAuditEvent `json:"audit_events"`
}

// PersistentState is the versioned Redis payload for all operational state.
type PersistentState struct {
	Version           int                    `json:"version"`
	SavedAt           time.Time              `json:"saved_at"`
	Metrics           MetricsSnapshot        `json:"metrics"`
	Scorer            scorer.PersistentState `json:"scorer"`
	RecentEvents      []ScalingEvent         `json:"recent_events"`
	Control           ControlState           `json:"control"`
	ControlAudit      []ControlAuditEvent    `json:"control_audit"`
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
	controlAudit      []ControlAuditEvent
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
		scorer: scorer.New(),
		logger: logger,
		events: make([]ScalingEvent, 0, 1000),
		control: ControlState{
			AutoscalingEnabled: true,
			MaxReplicaBudget:   scorer.ReplicaMax,
		},
		controlAudit:      make([]ControlAuditEvent, 0, maxControlAuditEvents),
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
	control := cloneControlState(s.control)
	audit := make([]ControlAuditEvent, len(s.controlAudit))
	for i, event := range s.controlAudit {
		audit[i] = cloneControlAuditEvent(event)
	}
	s.mu.RUnlock()

	return PersistentState{
		Version:           PersistentStateVersion,
		SavedAt:           time.Now().UTC(),
		Metrics:           s.Snapshot(),
		Scorer:            s.scorer.ExportState(),
		RecentEvents:      events,
		Control:           control,
		ControlAudit:      audit,
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
	// State snapshots written before Phase 8 do not contain this additive
	// field. Migrate those snapshots to the compile-time safety ceiling.
	if state.Control.MaxReplicaBudget == 0 {
		state.Control.MaxReplicaBudget = scorer.ReplicaMax
	}
	if state.Control.MaxReplicaBudget < scorer.ReplicaMin || state.Control.MaxReplicaBudget > scorer.ReplicaMax {
		return fmt.Errorf("max replica budget out of range: %d", state.Control.MaxReplicaBudget)
	}
	if state.Metrics.CurrentReplicas > int64(state.Control.MaxReplicaBudget) {
		return fmt.Errorf("persisted replicas %d exceed max replica budget %d", state.Metrics.CurrentReplicas, state.Control.MaxReplicaBudget)
	}
	if state.Control.ManualReplicaTarget != nil {
		target := *state.Control.ManualReplicaTarget
		if target < scorer.ReplicaMin || target > state.Control.MaxReplicaBudget {
			return fmt.Errorf("manual replica target out of range: %d", target)
		}
	}
	if len(state.RecentEvents) > 1000 {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-1000:]
	}
	if len(state.ProcessedEventIDs) > maxProcessedEventIDs {
		state.ProcessedEventIDs = state.ProcessedEventIDs[len(state.ProcessedEventIDs)-maxProcessedEventIDs:]
	}
	if len(state.ControlAudit) > maxControlAuditEvents {
		state.ControlAudit = state.ControlAudit[len(state.ControlAudit)-maxControlAuditEvents:]
	}
	for _, event := range state.ControlAudit {
		if strings.TrimSpace(event.AuditID) == "" || strings.TrimSpace(event.Action) == "" || event.Timestamp.IsZero() {
			return fmt.Errorf("persisted control audit event is invalid")
		}
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
	s.control = cloneControlState(state.Control)
	s.controlAudit = make([]ControlAuditEvent, len(state.ControlAudit))
	for i, event := range state.ControlAudit {
		s.controlAudit[i] = cloneControlAuditEvent(event)
	}
	s.processedEventIDs = append([]string(nil), state.ProcessedEventIDs...)
	s.processedEventSet = processedSet
	s.mu.Unlock()
	return nil
}

// ControlStatus returns the current durable policy and recent audit history.
func (s *Scaler) ControlStatus() ControlStatus {
	s.mu.RLock()
	control := cloneControlState(s.control)
	audit := make([]ControlAuditEvent, len(s.controlAudit))
	for i, event := range s.controlAudit {
		audit[i] = cloneControlAuditEvent(event)
	}
	s.mu.RUnlock()
	return ControlStatus{
		Control:         control,
		CurrentReplicas: s.CurrentReplicas(),
		EffectiveMode:   effectiveMode(control),
		AuditEvents:     audit,
	}
}

// SetSafeMode freezes automatic decisions at the current effective target.
func (s *Scaler) SetSafeMode(enabled bool, actor, reason string) (ControlStatus, error) {
	return s.mutateControl("set_safe_mode", actor, reason, func(control *ControlState) error {
		control.SafeMode = enabled
		if !enabled {
			s.scorer.ResetScaleUpCooldown()
		}
		return nil
	})
}

// SetManualReplicaTarget applies an immediate operator-selected replica target.
func (s *Scaler) SetManualReplicaTarget(target int, actor, reason string) (ControlStatus, error) {
	return s.mutateControl("set_manual_target", actor, reason, func(control *ControlState) error {
		if target < scorer.ReplicaMin || target > control.MaxReplicaBudget {
			return fmt.Errorf("manual target must be between %d and max replica budget %d", scorer.ReplicaMin, control.MaxReplicaBudget)
		}
		value := target
		control.ManualReplicaTarget = &value
		s.setEffectiveReplicas(target)
		return nil
	})
}

// SetMaxReplicaBudget changes the hard operator ceiling. Lowering the budget
// immediately clamps both the current and manual targets.
func (s *Scaler) SetMaxReplicaBudget(maxReplicas int, actor, reason string) (ControlStatus, error) {
	return s.mutateControl("set_max_replica_budget", actor, reason, func(control *ControlState) error {
		if maxReplicas < scorer.ReplicaMin || maxReplicas > scorer.ReplicaMax {
			return fmt.Errorf("max replica budget must be between %d and %d", scorer.ReplicaMin, scorer.ReplicaMax)
		}
		control.MaxReplicaBudget = maxReplicas
		if control.ManualReplicaTarget != nil && *control.ManualReplicaTarget > maxReplicas {
			value := maxReplicas
			control.ManualReplicaTarget = &value
		}
		if s.CurrentReplicas() > maxReplicas {
			s.setEffectiveReplicas(maxReplicas)
		}
		return nil
	})
}

// SetAutoscalingEnabled enables or freezes deterministic scaling decisions.
func (s *Scaler) SetAutoscalingEnabled(enabled bool, actor, reason string) (ControlStatus, error) {
	return s.mutateControl("set_autoscaling", actor, reason, func(control *ControlState) error {
		control.AutoscalingEnabled = enabled
		if enabled {
			s.scorer.ResetScaleUpCooldown()
		}
		return nil
	})
}

// RollbackToBaseline clears the manual target, returns to one replica, and
// enables safe mode so a queued signal cannot immediately undo the rollback.
func (s *Scaler) RollbackToBaseline(actor, reason string) (ControlStatus, error) {
	return s.mutateControl("rollback_to_baseline", actor, reason, func(control *ControlState) error {
		control.ManualReplicaTarget = nil
		control.SafeMode = true
		s.setEffectiveReplicas(scorer.ReplicaMin)
		return nil
	})
}

func (s *Scaler) mutateControl(action, actor, reason string, mutate func(*ControlState) error) (ControlStatus, error) {
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)
	if actor == "" {
		actor = "operator"
	}
	if reason == "" {
		reason = "operator request"
	}
	if len(actor) > 128 || len(reason) > 512 {
		return s.ControlStatus(), fmt.Errorf("actor or reason exceeds the allowed length")
	}

	s.mu.Lock()
	previous := cloneControlState(s.control)
	if err := mutate(&s.control); err != nil {
		s.mu.Unlock()
		return s.ControlStatus(), err
	}
	event := ControlAuditEvent{
		AuditID:   fmt.Sprintf("control-%d", time.Now().UTC().UnixNano()),
		Action:    action,
		Actor:     actor,
		Reason:    reason,
		Previous:  previous,
		Current:   cloneControlState(s.control),
		Timestamp: time.Now().UTC(),
	}
	if len(s.controlAudit) >= maxControlAuditEvents {
		s.controlAudit = s.controlAudit[1:]
	}
	s.controlAudit = append(s.controlAudit, event)
	s.mu.Unlock()

	status := s.ControlStatus()
	if err := s.SaveNow(); err != nil {
		return status, fmt.Errorf("control applied but persistence failed: %w", err)
	}
	return status, nil
}

func (s *Scaler) setEffectiveReplicas(target int) {
	if err := s.scorer.SetCurrentReplicas(target); err != nil {
		panic(err)
	}
	s.metrics.CurrentReplicas.Store(int64(target))
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
	result.ReplicaTarget, result.Reason = s.applyControlDecision(result.ReplicaTarget, result.Reason)
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

func (s *Scaler) applyControlDecision(proposed int, reason string) (int, string) {
	s.mu.RLock()
	control := cloneControlState(s.control)
	s.mu.RUnlock()

	target := proposed
	current := s.CurrentReplicas()
	switch {
	case control.ManualReplicaTarget != nil:
		target = *control.ManualReplicaTarget
		reason = fmt.Sprintf("manual replica target active target=%d; scorer_reason=%s", target, reason)
	case control.SafeMode:
		target = current
		reason = fmt.Sprintf("safe mode active - holding current replicas=%d; scorer_reason=%s", target, reason)
	case !control.AutoscalingEnabled:
		target = current
		reason = fmt.Sprintf("autoscaling disabled - holding current replicas=%d; scorer_reason=%s", target, reason)
	}
	if target > control.MaxReplicaBudget {
		target = control.MaxReplicaBudget
		reason = fmt.Sprintf("max replica budget enforced target=%d; scorer_reason=%s", target, reason)
	}
	if target < scorer.ReplicaMin {
		target = scorer.ReplicaMin
	}
	s.setEffectiveReplicas(target)
	return target, reason
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

func cloneControlState(control ControlState) ControlState {
	clone := control
	if control.ManualReplicaTarget != nil {
		target := *control.ManualReplicaTarget
		clone.ManualReplicaTarget = &target
	}
	return clone
}

func cloneControlAuditEvent(event ControlAuditEvent) ControlAuditEvent {
	clone := event
	clone.Previous = cloneControlState(event.Previous)
	clone.Current = cloneControlState(event.Current)
	return clone
}

func effectiveMode(control ControlState) string {
	switch {
	case control.ManualReplicaTarget != nil:
		return "manual"
	case control.SafeMode:
		return "safe_mode"
	case !control.AutoscalingEnabled:
		return "autoscaling_disabled"
	default:
		return "automatic"
	}
}
