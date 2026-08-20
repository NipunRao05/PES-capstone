// Package metrics provides the HTTP observability and KEDA integration server.
//
// Endpoints:
//
//	GET /healthz          — liveness probe
//	GET /metrics          — JSON metrics snapshot (all counters)
//	GET /metrics/raw      — Prometheus text format
//	GET /keda             — KEDA metrics-api compatible JSON pressure metric
//	GET /scale/events     — last 50 scaling events
//	GET /scale/stats      — EWMA + Z-score global statistics
//	GET /control/status   — durable operator policy and audit history
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/scalingagent/internal/scaler"
	"github.com/scalingagent/internal/scorer"
)

// Server is the HTTP observability server.
type Server struct {
	sc     *scaler.Scaler
	logger *slog.Logger
	srv    *http.Server
}

// New creates a Server.
func New(addr string, sc *scaler.Scaler, logger *slog.Logger) *Server {
	s := &Server{sc: sc, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/metrics/raw", s.handlePrometheus)
	mux.HandleFunc("/keda", s.handleKEDA)
	mux.HandleFunc("/scale/events", s.handleScaleEvents)
	mux.HandleFunc("/scale/stats", s.handleScaleStats)
	mux.HandleFunc("/control/status", s.handleControlStatus)
	mux.HandleFunc("/control/safe-mode", s.handleSafeMode)
	mux.HandleFunc("/control/manual-target", s.handleManualTarget)
	mux.HandleFunc("/control/max-budget", s.handleMaxBudget)
	mux.HandleFunc("/control/rollback", s.handleRollback)
	mux.HandleFunc("/control/autoscaling/enable", s.handleAutoscalingEnable)
	mux.HandleFunc("/control/autoscaling/disable", s.handleAutoscalingDisable)

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return s
}

// ListenAndServe starts the HTTP server. Blocks until the server stops.
func (s *Server) ListenAndServe() error {
	s.logger.Info("metrics server listening", "addr", s.srv.Addr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(ctx)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	snap := s.sc.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","current_replicas":%d,"total_signals":%d}`,
		snap.CurrentReplicas, snap.TotalSignals)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.sc.Snapshot()
	mean, stdDev, count, replicas := s.sc.ScorerSnapshot()
	persistence := s.sc.PersistenceStatus()
	control := s.sc.ControlStatus()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		// Scaling counters
		"total_signals":         snap.TotalSignals,
		"noise_signals":         snap.NoiseSignals,
		"scale_up_events":       snap.ScaleUpEvents,
		"scale_down_events":     snap.ScaleDownEvents,
		"trap_triggers":         snap.TrapTriggers,
		"duplicate_events":      snap.DuplicateEvents,
		"processed_event_count": s.sc.ProcessedEventCount(),
		"current_replicas":      snap.CurrentReplicas,
		"scale_pressure":        snap.ScalePressure,
		// EWMA / Z-score global statistics
		"scorer_mean":         mean,
		"scorer_std_dev":      stdDev,
		"scorer_count":        count,
		"scorer_replicas":     replicas,
		"state_persistence":   persistence,
		"control":             control.Control,
		"control_mode":        control.EffectiveMode,
		"control_audit_count": len(control.AuditEvents),
		// Config (for dashboards)
		"config": map[string]interface{}{
			"ewma_alpha":                scorer.EWMAAlpha,
			"z_score_threshold":         scorer.ZScoreThreshold,
			"scale_up_threshold":        scorer.ScaleUpThreshold,
			"scale_down_threshold":      scorer.ScaleDownThreshold,
			"scale_down_window_seconds": int(scorer.ScaleDownWindow.Seconds()),
			"scale_up_cooldown_seconds": int(scorer.ScaleUpCooldown.Seconds()),
			"max_scale_up_step":         scorer.MaxScaleUpStep,
			"replica_min":               scorer.ReplicaMin,
			"replica_max":               scorer.ReplicaMax,
			"weights": map[string]float64{
				"attacker_confidence": scorer.WeightAttackerConfidence,
				"session_depth":       scorer.WeightSessionDepth,
				"query_entropy":       scorer.WeightQueryEntropy,
				"failed_auth_ratio":   scorer.WeightFailedAuthRatio,
			},
		},
	})
}

// handlePrometheus emits Prometheus text format metrics.
func (s *Server) handlePrometheus(w http.ResponseWriter, r *http.Request) {
	snap := s.sc.Snapshot()
	mean, stdDev, count, _ := s.sc.ScorerSnapshot()
	persistence := s.sc.PersistenceStatus()
	controlStatus := s.sc.ControlStatus()
	control := controlStatus.Control
	persistenceEnabled := 0
	persistenceRestored := 0
	if persistence.Enabled {
		persistenceEnabled = 1
	}
	if persistence.Restored {
		persistenceRestored = 1
	}
	safeMode := 0
	autoscalingEnabled := 0
	manualOverride := 0
	manualTarget := 0
	if control.SafeMode {
		safeMode = 1
	}
	if control.AutoscalingEnabled {
		autoscalingEnabled = 1
	}
	if control.ManualReplicaTarget != nil {
		manualOverride = 1
		manualTarget = *control.ManualReplicaTarget
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	lines := []string{
		"# HELP scaling_agent_current_replicas Desired honeypot replica count",
		"# TYPE scaling_agent_current_replicas gauge",
		fmt.Sprintf("scaling_agent_current_replicas %d", snap.CurrentReplicas),

		"# HELP scaling_agent_scale_pressure Normalized pressure metric for KEDA metrics-api",
		"# TYPE scaling_agent_scale_pressure gauge",
		fmt.Sprintf("scaling_agent_scale_pressure %f", snap.ScalePressure),

		"# HELP scaling_agent_total_signals Total signals processed",
		"# TYPE scaling_agent_total_signals counter",
		fmt.Sprintf("scaling_agent_total_signals %d", snap.TotalSignals),

		"# HELP scaling_agent_noise_signals Bot-flood sessions suppressed",
		"# TYPE scaling_agent_noise_signals counter",
		fmt.Sprintf("scaling_agent_noise_signals %d", snap.NoiseSignals),

		"# HELP scaling_agent_scale_up_events Total scale-up decisions",
		"# TYPE scaling_agent_scale_up_events counter",
		fmt.Sprintf("scaling_agent_scale_up_events %d", snap.ScaleUpEvents),

		"# HELP scaling_agent_scale_down_events Total scale-down decisions",
		"# TYPE scaling_agent_scale_down_events counter",
		fmt.Sprintf("scaling_agent_scale_down_events %d", snap.ScaleDownEvents),

		"# HELP scaling_agent_trap_triggers Trap table accesses seen",
		"# TYPE scaling_agent_trap_triggers counter",
		fmt.Sprintf("scaling_agent_trap_triggers %d", snap.TrapTriggers),

		"# HELP scaling_agent_duplicate_events_total Duplicate or replayed Kafka events ignored",
		"# TYPE scaling_agent_duplicate_events_total counter",
		fmt.Sprintf("scaling_agent_duplicate_events_total %d", snap.DuplicateEvents),

		"# HELP scaling_agent_processed_event_ids Number of durable event IDs retained for deduplication",
		"# TYPE scaling_agent_processed_event_ids gauge",
		fmt.Sprintf("scaling_agent_processed_event_ids %d", s.sc.ProcessedEventCount()),

		"# HELP scaling_agent_scorer_mean Global mean of smoothed scores",
		"# TYPE scaling_agent_scorer_mean gauge",
		fmt.Sprintf("scaling_agent_scorer_mean %f", mean),

		"# HELP scaling_agent_scorer_std_dev Global std dev of smoothed scores",
		"# TYPE scaling_agent_scorer_std_dev gauge",
		fmt.Sprintf("scaling_agent_scorer_std_dev %f", stdDev),

		"# HELP scaling_agent_scorer_sample_count Total samples in rolling stats",
		"# TYPE scaling_agent_scorer_sample_count counter",
		fmt.Sprintf("scaling_agent_scorer_sample_count %d", count),

		"# HELP scaling_agent_state_persistence_enabled Whether Redis state persistence is enabled",
		"# TYPE scaling_agent_state_persistence_enabled gauge",
		fmt.Sprintf("scaling_agent_state_persistence_enabled %d", persistenceEnabled),

		"# HELP scaling_agent_state_restored Whether startup restored a prior Redis state",
		"# TYPE scaling_agent_state_restored gauge",
		fmt.Sprintf("scaling_agent_state_restored %d", persistenceRestored),

		"# HELP scaling_agent_safe_mode Whether operator safe mode is active",
		"# TYPE scaling_agent_safe_mode gauge",
		fmt.Sprintf("scaling_agent_safe_mode %d", safeMode),

		"# HELP scaling_agent_autoscaling_enabled Whether automatic scaling decisions are enabled",
		"# TYPE scaling_agent_autoscaling_enabled gauge",
		fmt.Sprintf("scaling_agent_autoscaling_enabled %d", autoscalingEnabled),

		"# HELP scaling_agent_manual_override_active Whether a manual replica target is active",
		"# TYPE scaling_agent_manual_override_active gauge",
		fmt.Sprintf("scaling_agent_manual_override_active %d", manualOverride),

		"# HELP scaling_agent_manual_replica_target Current manual target, or zero when inactive",
		"# TYPE scaling_agent_manual_replica_target gauge",
		fmt.Sprintf("scaling_agent_manual_replica_target %d", manualTarget),

		"# HELP scaling_agent_max_replica_budget Operator-defined hard replica ceiling",
		"# TYPE scaling_agent_max_replica_budget gauge",
		fmt.Sprintf("scaling_agent_max_replica_budget %d", control.MaxReplicaBudget),

		"# HELP scaling_agent_control_audit_events Number of retained operator control changes",
		"# TYPE scaling_agent_control_audit_events gauge",
		fmt.Sprintf("scaling_agent_control_audit_events %d", len(controlStatus.AuditEvents)),
	}

	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}

// handleKEDA returns a simple JSON metric for KEDA's metrics-api scaler.
// Configure valueLocation: "scale_pressure" and targetValue according to the
// desired sensitivity. The dashboard can still display recommended_replicas.
func (s *Server) handleKEDA(w http.ResponseWriter, r *http.Request) {
	snap := s.sc.Snapshot()
	replicas := int(snap.CurrentReplicas)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"scale_pressure":       snap.ScalePressure,
		"recommended_replicas": replicas,
		"timestamp":            time.Now().UTC().Format(time.RFC3339),
	})
}

// handleScaleEvents returns the last 50 scaling events as JSON.
func (s *Server) handleScaleEvents(w http.ResponseWriter, r *http.Request) {
	events := s.sc.RecentEvents(50)
	w.Header().Set("Content-Type", "application/json")

	type eventJSON struct {
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

	out := make([]eventJSON, len(events))
	for i, ev := range events {
		out[i] = eventJSON{
			EventID:       ev.EventID,
			SignalSource:  ev.SignalSource,
			SessionID:     ev.SessionID,
			RawScore:      ev.RawScore,
			SmoothedScore: ev.SmoothedScore,
			IsNoise:       ev.IsNoise,
			ZScore:        ev.ZScore,
			ReplicaTarget: ev.ReplicaTarget,
			Reason:        ev.Reason,
			Timestamp:     ev.Timestamp,
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(out),
		"events": out,
	})
}

// handleScaleStats returns the current EWMA and Z-score global statistics.
func (s *Server) handleScaleStats(w http.ResponseWriter, r *http.Request) {
	mean, stdDev, count, replicas := s.sc.ScorerSnapshot()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"global_mean":       mean,
		"global_std_dev":    stdDev,
		"sample_count":      count,
		"current_replicas":  replicas,
		"formula":           "scale_score = 0.4*attacker_confidence + 0.3*session_depth + 0.2*query_entropy + 0.1*failed_auth_ratio",
		"smoothing":         "EWMA α=0.3",
		"anomaly_detection": fmt.Sprintf("Z-score threshold=%.1f", scorer.ZScoreThreshold),
	})
}

type auditRequest struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

type safeModeRequest struct {
	Enabled *bool  `json:"enabled"`
	Actor   string `json:"actor"`
	Reason  string `json:"reason"`
}

type manualTargetRequest struct {
	Target *int   `json:"target"`
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

type maxBudgetRequest struct {
	MaxReplicas *int   `json:"max_replicas"`
	Actor       string `json:"actor"`
	Reason      string `json:"reason"`
}

func (s *Server) handleControlStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, s.sc.ControlStatus())
}

func (s *Server) handleSafeMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request safeModeRequest
	if !decodeControlJSON(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled is required"})
		return
	}
	status, err := s.sc.SetSafeMode(*request.Enabled, request.Actor, request.Reason)
	writeControlResult(w, status, err)
}

func (s *Server) handleManualTarget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request manualTargetRequest
	if !decodeControlJSON(w, r, &request) {
		return
	}
	if request.Target == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}
	status, err := s.sc.SetManualReplicaTarget(*request.Target, request.Actor, request.Reason)
	writeControlResult(w, status, err)
}

func (s *Server) handleMaxBudget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request maxBudgetRequest
	if !decodeControlJSON(w, r, &request) {
		return
	}
	if request.MaxReplicas == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_replicas is required"})
		return
	}
	status, err := s.sc.SetMaxReplicaBudget(*request.MaxReplicas, request.Actor, request.Reason)
	writeControlResult(w, status, err)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request auditRequest
	if !decodeControlJSON(w, r, &request) {
		return
	}
	status, err := s.sc.RollbackToBaseline(request.Actor, request.Reason)
	writeControlResult(w, status, err)
}

func (s *Server) handleAutoscalingEnable(w http.ResponseWriter, r *http.Request) {
	s.handleAutoscaling(w, r, true)
}

func (s *Server) handleAutoscalingDisable(w http.ResponseWriter, r *http.Request) {
	s.handleAutoscaling(w, r, false)
}

func (s *Server) handleAutoscaling(w http.ResponseWriter, r *http.Request, enabled bool) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	var request auditRequest
	if !decodeControlJSON(w, r, &request) {
		return
	}
	status, err := s.sc.SetAutoscalingEnabled(enabled, request.Actor, request.Reason)
	writeControlResult(w, status, err)
}

func decodeControlJSON(w http.ResponseWriter, r *http.Request, target interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body: " + err.Error()})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request body must contain one JSON object"})
		return false
	}
	return true
}

func writeControlResult(w http.ResponseWriter, status scaler.ControlStatus, err error) {
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "persistence failed") {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, map[string]interface{}{"error": err.Error(), "status": status})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func writeMethodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func writeJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
