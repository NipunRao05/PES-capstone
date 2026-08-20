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
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		// Scaling counters
		"total_signals":     snap.TotalSignals,
		"noise_signals":     snap.NoiseSignals,
		"scale_up_events":   snap.ScaleUpEvents,
		"scale_down_events": snap.ScaleDownEvents,
		"trap_triggers":     snap.TrapTriggers,
		"current_replicas":  snap.CurrentReplicas,
		"scale_pressure":    snap.ScalePressure,
		// EWMA / Z-score global statistics
		"scorer_mean":       mean,
		"scorer_std_dev":    stdDev,
		"scorer_count":      count,
		"scorer_replicas":   replicas,
		"state_persistence": persistence,
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
	persistenceEnabled := 0
	persistenceRestored := 0
	if persistence.Enabled {
		persistenceEnabled = 1
	}
	if persistence.Restored {
		persistenceRestored = 1
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
