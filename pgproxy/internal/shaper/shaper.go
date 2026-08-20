// Package shaper implements Layer 6: ResponseShaper
// Provides configurable response modification:
//   - Latency injection (per-query or global, deterministic or jittered)
//   - Row limits (cap DataRow messages before CommandComplete)
//   - Query blocking (fingerprint-based allow/deny list)
//
// The shaper sits in the hot path between the backend response stream
// and the client. All operations are designed to be zero-allocation
// when no rules match (the common case).
package shaper

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config controls ResponseShaper behaviour.
type Config struct {
	// GlobalLatency adds a fixed delay before every response flush.
	// Zero means disabled.
	GlobalLatency time.Duration

	// JitterFraction adds random latency on top of GlobalLatency.
	// e.g. 0.2 means ±20% of GlobalLatency.
	JitterFraction float64

	// DefaultRowLimit caps the number of DataRow messages per result set.
	// Zero means unlimited.
	DefaultRowLimit int

	// Rules contains per-fingerprint overrides (applied after global defaults).
	Rules []Rule
}

// Rule is a per-fingerprint shaping override.
type Rule struct {
	// Fingerprint is the FNV-64a hex string from interceptor.FingerprintSQL.
	// Empty string matches ALL queries (use as a catch-all).
	Fingerprint string

	// Latency overrides GlobalLatency for this fingerprint.
	// Negative value disables latency for this fingerprint even if global is set.
	Latency time.Duration

	// RowLimit overrides DefaultRowLimit for this fingerprint.
	// -1 disables row limiting for this fingerprint.
	RowLimit int

	// Block causes the proxy to return an error response instead of forwarding.
	Block bool

	// BlockMessage is the error message sent to the client when Block is true.
	BlockMessage string
}

// ─── Shaper ───────────────────────────────────────────────────────────────────

// Shaper applies response-shaping rules to the backend message stream.
type Shaper struct {
	cfg    Config
	logger *slog.Logger

	// ruleIndex provides O(1) lookup of per-fingerprint rules.
	ruleIndex map[string]*Rule
	mu        sync.RWMutex
}

// New creates a ResponseShaper with the given config.
func New(cfg Config, logger *slog.Logger) *Shaper {
	s := &Shaper{
		cfg:       cfg,
		logger:    logger,
		ruleIndex: make(map[string]*Rule, len(cfg.Rules)),
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Fingerprint != "" {
			s.ruleIndex[r.Fingerprint] = r
		}
	}
	return s
}

// ─── Decision ─────────────────────────────────────────────────────────────────

// Decision is the resolved shaping policy for a single query execution.
// Computed once per query; zero-alloc when no rules match.
type Decision struct {
	// ShouldBlock means return an error to the client immediately.
	ShouldBlock  bool
	BlockMessage string

	// Latency is the resolved delay to inject before forwarding responses.
	Latency time.Duration

	// RowLimit is the maximum number of DataRow messages to forward.
	// 0 means unlimited.
	RowLimit int
}

// Decide returns the shaping Decision for the given fingerprint.
// This is called once per query in the hot path — it must be fast.
func (s *Shaper) Decide(fingerprint string) Decision {
	s.mu.RLock()
	rule, hasRule := s.ruleIndex[fingerprint]
	s.mu.RUnlock()

	d := Decision{
		Latency:  s.resolvedLatency(),
		RowLimit: s.cfg.DefaultRowLimit,
	}

	if !hasRule {
		return d
	}

	// Apply per-fingerprint overrides
	if rule.Block {
		d.ShouldBlock = true
		d.BlockMessage = rule.BlockMessage
		if d.BlockMessage == "" {
			d.BlockMessage = "query blocked by proxy policy"
		}
		return d
	}

	if rule.Latency != 0 {
		if rule.Latency < 0 {
			d.Latency = 0 // explicitly disabled
		} else {
			d.Latency = rule.Latency + s.jitter(rule.Latency)
		}
	}

	if rule.RowLimit != 0 {
		if rule.RowLimit < 0 {
			d.RowLimit = 0 // unlimited
		} else {
			d.RowLimit = rule.RowLimit
		}
	}

	return d
}

// ─── Response Shaping ─────────────────────────────────────────────────────────

// ShapeContext tracks per-result-set state during response forwarding.
type ShapeContext struct {
	decision  Decision
	rowsSeen  int
	truncated bool
}

// NewShapeContext creates a per-query context from a Decision.
func NewShapeContext(d Decision) *ShapeContext {
	return &ShapeContext{decision: d}
}

// ApplyLatency sleeps for the resolved latency duration.
// Called once before forwarding the first response message.
// No-op if latency is zero.
func (sc *ShapeContext) ApplyLatency() {
	if sc.decision.Latency > 0 {
		time.Sleep(sc.decision.Latency)
	}
}

// BlockResponse builds an ErrorResponse to send to the client when the
// query is blocked. Returns nil if the query is not blocked.
func (sc *ShapeContext) BlockResponse() *pgproto3.ErrorResponse {
	if !sc.decision.ShouldBlock {
		return nil
	}
	return &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501", // insufficient_privilege — visible in psql as a proper error
		Message:  sc.decision.BlockMessage,
	}
}

// FilterRow returns true if the DataRow should be forwarded, false if it
// should be dropped (row limit reached).
func (sc *ShapeContext) FilterRow() bool {
	if sc.decision.RowLimit <= 0 {
		// Unlimited
		sc.rowsSeen++
		return true
	}
	if sc.rowsSeen >= sc.decision.RowLimit {
		sc.truncated = true
		return false
	}
	sc.rowsSeen++
	return true
}

// TruncationNotice returns a NoticeResponse to send to the client when
// rows have been truncated, or nil if no truncation occurred.
func (sc *ShapeContext) TruncationNotice() *pgproto3.NoticeResponse {
	if !sc.truncated {
		return nil
	}
	return &pgproto3.NoticeResponse{
		Severity: "NOTICE",
		Code:     "01000",
		Message:  fmt.Sprintf("result set truncated by proxy: row limit %d reached", sc.decision.RowLimit),
	}
}

// RowsSeen returns the number of DataRow messages seen so far.
func (sc *ShapeContext) RowsSeen() int { return sc.rowsSeen }

// WasTruncated returns true if at least one row was dropped.
func (sc *ShapeContext) WasTruncated() bool { return sc.truncated }

// ─── Rule Management ──────────────────────────────────────────────────────────

// AddRule adds or replaces a per-fingerprint rule at runtime.
func (s *Shaper) AddRule(r Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ruleIndex[r.Fingerprint] = &r
}

// RemoveRule removes a rule by fingerprint.
func (s *Shaper) RemoveRule(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ruleIndex, fingerprint)
}

// RuleCount returns the number of active per-fingerprint rules.
func (s *Shaper) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ruleIndex)
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (s *Shaper) resolvedLatency() time.Duration {
	if s.cfg.GlobalLatency <= 0 {
		return 0
	}
	return s.cfg.GlobalLatency + s.jitter(s.cfg.GlobalLatency)
}

func (s *Shaper) jitter(base time.Duration) time.Duration {
	if s.cfg.JitterFraction <= 0 || base <= 0 {
		return 0
	}
	// ±JitterFraction of base, uniformly distributed
	maxJitter := float64(base) * s.cfg.JitterFraction
	return time.Duration((rand.Float64()*2-1)*maxJitter) //nolint:gosec
}
