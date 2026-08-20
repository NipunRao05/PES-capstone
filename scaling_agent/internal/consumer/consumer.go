// Package consumer reads MitreEvents and SessionProfiles from Redpanda
// and converts them into SessionSignals for the scorer.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	kafka "github.com/segmentio/kafka-go"

	"github.com/scalingagent/internal/scorer"
)

// ─── Event schemas ────────────────────────────────────────────────────────────

// MitreEvent mirrors the JSON published to the mitre-events topic.
type MitreEvent struct {
	SessionID       string   `json:"session_id"`
	Timestamp       string   `json:"timestamp"`
	ClientIP        string   `json:"client_ip"`
	Fingerprint     string   `json:"fingerprint"`
	Phase           string   `json:"phase"`
	TechniqueID     string   `json:"technique_id"`
	RuleConfidence  float64  `json:"rule_confidence"`
	RiskScore       float64  `json:"risk_score"`
	RiskLevel       string   `json:"risk_level"`
	DeceptionLevel  int      `json:"deception_level"`
	Tags            []string `json:"tags"`
	IsTrapTriggered bool     `json:"is_trap_triggered"`
}

// SessionProfile mirrors the ACTUAL JSON published by session_module.
// Field names verified from live Redpanda session-profiles topic output.
type SessionProfile struct {
	SessionID          string  `json:"session_id"`
	SourceIP           string  `json:"source_ip"` // session_module uses source_ip
	DBUser             string  `json:"db_user"`   // session_module uses db_user
	Persona            string  `json:"persona"`
	QueryCount         int     `json:"query_count"`
	FailedAuth         int     `json:"failed_auth"` // session_module uses failed_auth
	DepthScore         float64 `json:"depth_score"`
	Entropy            float64 `json:"entropy"`
	TimingVarianceMs   float64 `json:"timing_variance_ms"`
	QueriesPerSecond   float64 `json:"queries_per_second"`
	SuspicionScore     float64 `json:"suspicion_score"`
	UniqueFingerprints int     `json:"unique_fingerprint_count"`
}

// DeadLetterEvent captures malformed or unprocessable Kafka records without
// stopping the scaling consumer.
type DeadLetterEvent struct {
	Timestamp       string `json:"timestamp"`
	Service         string `json:"service"`
	SourceTopic     string `json:"source_topic"`
	SourcePartition int    `json:"source_partition"`
	SourceOffset    int64  `json:"source_offset"`
	Stage           string `json:"stage"`
	Error           string `json:"error"`
	RawPayload      string `json:"raw_payload"`
	DeadLetterID    string `json:"dead_letter_id"`
}

// deriveConfidence estimates attacker_confidence from available session fields.
// The session_module does not publish attacker_confidence directly, so we derive
// it from depth_score, suspicion_score, timing_variance, and queries_per_second.
//
// Heuristic:
//   - High depth + low QPS = deliberate human attacker = high confidence
//   - Non-zero suspicion_score takes priority (set by DBSCAN persona scoring)
//   - Slow, deep, low-frequency sessions are most dangerous
func deriveConfidence(p SessionProfile) float64 {
	// If session_module set a suspicion score, use it directly
	if p.SuspicionScore > 0 {
		return math.Min(p.SuspicionScore/10.0, 1.0)
	}

	// Derive from depth and timing:
	// Deep exploration (depth_score 6+) with slow pace (QPS < 1) = high confidence
	depthNorm := math.Min(p.DepthScore/scorer.MaxSessionDepth, 1.0)

	// Slow QPS increases confidence (deliberate human); fast QPS decreases it (bot)
	var qpsFactor float64
	if p.QueriesPerSecond <= 0 {
		qpsFactor = 0.5 // unknown pace — neutral
	} else if p.QueriesPerSecond < 0.5 {
		qpsFactor = 1.0 // very slow = very deliberate
	} else if p.QueriesPerSecond < 2.0 {
		qpsFactor = 0.7 // moderate pace
	} else {
		qpsFactor = 0.3 // fast = likely automated tool
	}

	// High timing variance = human-like irregular typing rhythm
	var varianceFactor float64
	if p.TimingVarianceMs > 500 {
		varianceFactor = 1.0
	} else if p.TimingVarianceMs > 100 {
		varianceFactor = 0.7
	} else {
		varianceFactor = 0.3
	}

	// Weighted combination
	confidence := 0.5*depthNorm + 0.3*qpsFactor + 0.2*varianceFactor

	// Minimum 0.3 for any session with depth > 1 (they explored something)
	if p.DepthScore > 1 && confidence < 0.3 {
		confidence = 0.3
	}

	return math.Min(confidence, 1.0)
}

// ─── Consumer ─────────────────────────────────────────────────────────────────

// Config holds consumer configuration.
type Config struct {
	Brokers              []string
	TopicMitreEvents     string
	TopicSessionProfiles string
	TopicDeadLetter      string
	GroupID              string
	DialTimeout          time.Duration
	StartOffset          int64
}

func (c *Config) setDefaults() {
	if c.TopicMitreEvents == "" {
		c.TopicMitreEvents = "mitre-events"
	}
	if c.TopicSessionProfiles == "" {
		c.TopicSessionProfiles = "session-profiles"
	}
	if c.TopicDeadLetter == "" {
		c.TopicDeadLetter = "dead-letter-events"
	}
	if c.GroupID == "" {
		c.GroupID = "scaling-agent"
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.StartOffset == 0 {
		c.StartOffset = kafka.LastOffset
	}
}

// ParseStartOffset maps a friendly string to kafka-go reader offsets.
func ParseStartOffset(value string) int64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "earliest", "first", "beginning":
		return kafka.FirstOffset
	case "latest", "last", "":
		return kafka.LastOffset
	default:
		return kafka.LastOffset
	}
}

// Consumer reads from Redpanda and emits SessionSignals.
type Consumer struct {
	cfg       Config
	logger    *slog.Logger
	out       chan scorer.SessionSignal
	done      chan struct{}
	dlqWriter *kafka.Writer
}

// New creates a Consumer. Call Start to begin consuming.
func New(cfg Config, logger *slog.Logger) *Consumer {
	cfg.setDefaults()
	return &Consumer{
		cfg:    cfg,
		logger: logger,
		out:    make(chan scorer.SessionSignal, 10_000),
		done:   make(chan struct{}),
		dlqWriter: &kafka.Writer{
			Addr:         kafka.TCP(cfg.Brokers...),
			Topic:        cfg.TopicDeadLetter,
			Balancer:     &kafka.Hash{},
			RequiredAcks: kafka.RequireAll,
			Async:        false,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Signals returns the read-only channel of parsed SessionSignals.
func (c *Consumer) Signals() <-chan scorer.SessionSignal { return c.out }

// Start launches both consumer goroutines. Non-blocking.
func (c *Consumer) Start(ctx context.Context) {
	go c.consumeMitreEvents(ctx)
	go c.consumeSessionProfiles(ctx)
}

func truncatePayload(value []byte, limit int) string {
	if limit <= 0 {
		limit = 16384
	}
	if len(value) > limit {
		value = value[:limit]
	}
	return string(value)
}

func (c *Consumer) publishDeadLetter(msg kafka.Message, stage string, err error) {
	if c.dlqWriter == nil {
		return
	}
	payload := DeadLetterEvent{
		Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
		Service:         "scaling-agent",
		SourceTopic:     msg.Topic,
		SourcePartition: msg.Partition,
		SourceOffset:    msg.Offset,
		Stage:           stage,
		Error:           err.Error(),
		RawPayload:      truncatePayload(msg.Value, 16384),
		DeadLetterID:    fmt.Sprintf("scaling-agent:%s:%d:%d", msg.Topic, msg.Partition, msg.Offset),
	}
	value, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		c.logger.Error("failed to marshal dead-letter event", "error", marshalErr)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if writeErr := c.dlqWriter.WriteMessages(ctx, kafka.Message{
		Key:   []byte(payload.DeadLetterID),
		Value: value,
	}); writeErr != nil {
		c.logger.Error("failed to publish dead-letter event", "error", writeErr, "source_topic", msg.Topic, "offset", msg.Offset)
	}
}

// ─── mitre-events consumer ────────────────────────────────────────────────────

func (c *Consumer) consumeMitreEvents(ctx context.Context) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        c.cfg.Brokers,
		Topic:          c.cfg.TopicMitreEvents,
		GroupID:        c.cfg.GroupID + "-mitre",
		MinBytes:       1,
		MaxBytes:       1 << 20,
		CommitInterval: time.Second,
		StartOffset:    c.cfg.StartOffset,
		MaxWait:        500 * time.Millisecond,
	})
	defer r.Close()

	c.logger.Info("mitre-events consumer started",
		"brokers", c.cfg.Brokers,
		"topic", c.cfg.TopicMitreEvents,
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Warn("mitre-events read error", "error", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var ev MitreEvent
		if err := json.Unmarshal(msg.Value, &ev); err != nil {
			c.logger.Warn("failed to parse MitreEvent", "error", err, "topic", msg.Topic, "offset", msg.Offset)
			c.publishDeadLetter(msg, "parse_mitre_event", err)
			continue
		}

		if ev.SessionID == "" {
			err := fmt.Errorf("missing required field: session_id")
			c.logger.Warn("invalid MitreEvent", "error", err, "topic", msg.Topic, "offset", msg.Offset)
			c.publishDeadLetter(msg, "validate_mitre_event", err)
			continue
		}

		// MitreEvent carries rule_confidence as attacker_confidence.
		// Depth/entropy/auth come from session-profiles when they arrive.
		sig := scorer.SessionSignal{
			SessionID:          ev.SessionID,
			ClientIP:           ev.ClientIP,
			AttackerConfidence: ev.RuleConfidence,
			SessionDepth:       0.0,
			QueryEntropy:       0.0,
			FailedAuthRatio:    0.0,
			IsTrapTriggered:    ev.IsTrapTriggered,
			Timestamp:          time.Now(),
		}

		c.logger.Debug("mitre signal",
			"session_id", ev.SessionID,
			"technique", ev.TechniqueID,
			"confidence", ev.RuleConfidence,
			"trap", ev.IsTrapTriggered,
		)

		select {
		case c.out <- sig:
		default:
			c.logger.Warn("signal buffer full, dropping mitre signal",
				"session_id", ev.SessionID)
		}
	}
}

// ─── session-profiles consumer ────────────────────────────────────────────────

func (c *Consumer) consumeSessionProfiles(ctx context.Context) {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        c.cfg.Brokers,
		Topic:          c.cfg.TopicSessionProfiles,
		GroupID:        c.cfg.GroupID + "-profiles",
		MinBytes:       1,
		MaxBytes:       1 << 20,
		CommitInterval: time.Second,
		StartOffset:    c.cfg.StartOffset,
		MaxWait:        500 * time.Millisecond,
	})
	defer r.Close()

	c.logger.Info("session-profiles consumer started",
		"brokers", c.cfg.Brokers,
		"topic", c.cfg.TopicSessionProfiles,
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logger.Warn("session-profiles read error", "error", err)
			time.Sleep(2 * time.Second)
			continue
		}

		var profile SessionProfile
		if err := json.Unmarshal(msg.Value, &profile); err != nil {
			c.logger.Warn("failed to parse SessionProfile", "error", err, "topic", msg.Topic, "offset", msg.Offset)
			c.publishDeadLetter(msg, "parse_session_profile", err)
			continue
		}

		if profile.SessionID == "" {
			err := fmt.Errorf("missing required field: session_id")
			c.logger.Warn("invalid SessionProfile", "error", err, "topic", msg.Topic, "offset", msg.Offset)
			c.publishDeadLetter(msg, "validate_session_profile", err)
			continue
		}

		// Derive attacker_confidence from session features since it is not
		// published directly by the session_module.
		confidence := deriveConfidence(profile)

		sig := scorer.SessionSignal{
			SessionID:          profile.SessionID,
			ClientIP:           profile.SourceIP,
			AttackerConfidence: confidence,
			SessionDepth:       scorer.NormaliseDepth(profile.DepthScore),
			QueryEntropy:       scorer.NormaliseEntropy(profile.Entropy),
			FailedAuthRatio:    scorer.NormaliseFailedAuth(profile.FailedAuth, profile.QueryCount),
			IsTrapTriggered:    false, // session_module does not set this — mitre-events does
			IsSessionClosed:    true,
			Timestamp:          time.Now(),
		}

		c.logger.Debug("profile signal",
			"session_id", profile.SessionID,
			"source_ip", profile.SourceIP,
			"db_user", profile.DBUser,
			"depth", profile.DepthScore,
			"entropy", profile.Entropy,
			"derived_confidence", confidence,
			"qps", profile.QueriesPerSecond,
		)

		select {
		case c.out <- sig:
		default:
			c.logger.Warn("signal buffer full, dropping profile signal",
				"session_id", profile.SessionID)
		}
	}
}
