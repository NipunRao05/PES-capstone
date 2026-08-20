// Package shaper implements Layer 6: ResponseShaper for MySQL proxy.
// Provides per-fingerprint query blocking, latency injection, and row limiting.
// Identical rule semantics to the PostgreSQL proxy shaper.
// Zero overhead in the hot path when no rules are configured.
package shaper

import (
	"fmt"
	"log/slog"
	"math/rand"
	"sync"
	"time"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config controls the ResponseShaper.
type Config struct {
	// GlobalLatency adds a fixed delay before every first response packet.
	GlobalLatency time.Duration

	// JitterFraction adds ±n% random jitter on top of GlobalLatency.
	JitterFraction float64

	// DefaultRowLimit caps the number of data rows per result set. 0 = unlimited.
	DefaultRowLimit int

	// Rules holds per-fingerprint overrides.
	Rules []Rule
}

// Rule is a per-fingerprint shaping override.
type Rule struct {
	// Fingerprint is the FNV-64a hex string from interceptor.FingerprintSQL.
	Fingerprint string

	// Latency overrides GlobalLatency. Negative = disable latency for this fingerprint.
	Latency time.Duration

	// RowLimit overrides DefaultRowLimit. -1 = disable row limiting.
	RowLimit int

	// Block makes the proxy return an error instead of forwarding the query.
	Block bool

	// BlockMessage is the MySQL error message text (default: "query blocked by proxy policy").
	BlockMessage string

	// BlockErrCode is the MySQL error code (default: 1045 = ER_ACCESS_DENIED_ERROR).
	BlockErrCode uint16

	// BlockSQLState is the MySQL SQLSTATE string (default: "28000").
	BlockSQLState string
}

// ─── Shaper ───────────────────────────────────────────────────────────────────

// Shaper applies response-shaping rules to the MySQL response stream.
type Shaper struct {
	cfg       Config
	logger    *slog.Logger
	ruleIndex map[string]*Rule
	mu        sync.RWMutex
}

// New creates a Shaper with the given configuration.
func New(cfg Config, logger *slog.Logger) *Shaper {
	s := &Shaper{
		cfg:       cfg,
		logger:    logger,
		ruleIndex: make(map[string]*Rule, len(cfg.Rules)),
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.Fingerprint != "" {
			s.applyRuleDefaults(r)
			s.ruleIndex[r.Fingerprint] = r
		}
	}
	return s
}

func (s *Shaper) applyRuleDefaults(r *Rule) {
	if r.BlockMessage == "" {
		r.BlockMessage = "query blocked by proxy policy"
	}
	if r.BlockErrCode == 0 {
		r.BlockErrCode = 1045 // ER_ACCESS_DENIED_ERROR
	}
	if r.BlockSQLState == "" {
		r.BlockSQLState = "28000"
	}
}

// ─── Decision ─────────────────────────────────────────────────────────────────

// Decision is the resolved shaping policy for one query execution.
type Decision struct {
	ShouldBlock   bool
	BlockMessage  string
	BlockErrCode  uint16
	BlockSQLState string

	Latency  time.Duration
	RowLimit int
}

// Decide resolves the shaping policy for a given fingerprint.
// O(1) with RLock — designed to be called once per query in the hot path.
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

	if rule.Block {
		d.ShouldBlock = true
		d.BlockMessage = rule.BlockMessage
		d.BlockErrCode = rule.BlockErrCode
		d.BlockSQLState = rule.BlockSQLState
		return d
	}

	if rule.Latency != 0 {
		if rule.Latency < 0 {
			d.Latency = 0
		} else {
			d.Latency = rule.Latency + s.jitter(rule.Latency)
		}
	}
	if rule.RowLimit != 0 {
		if rule.RowLimit < 0 {
			d.RowLimit = 0
		} else {
			d.RowLimit = rule.RowLimit
		}
	}
	return d
}

// ─── ShapeContext ─────────────────────────────────────────────────────────────

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
// Called once before forwarding the first result packet.
func (sc *ShapeContext) ApplyLatency() {
	if sc.decision.Latency > 0 {
		time.Sleep(sc.decision.Latency)
	}
}

// BlockPacket builds a MySQL ERR packet payload for a blocked query.
// The caller is responsible for framing it with a sequence number.
func (sc *ShapeContext) BlockPacket() []byte {
	if !sc.decision.ShouldBlock {
		return nil
	}
	return BuildErrPacket(sc.decision.BlockErrCode, sc.decision.BlockSQLState, sc.decision.BlockMessage)
}

// BuildErrPacket builds a raw MySQL ERR packet body (without the 4-byte frame header).
// Format: 0xFF + error_code(2) + '#' + sqlstate(5) + message
func BuildErrPacket(errCode uint16, sqlState, message string) []byte {
	if sqlState == "" {
		sqlState = "HY000"
	}
	// Pad/truncate sqlState to exactly 5 bytes
	ss := fmt.Sprintf("%-5.5s", sqlState)
	body := make([]byte, 0, 9+len(message))
	body = append(body, 0xFF)
	body = append(body, byte(errCode), byte(errCode>>8))
	body = append(body, '#')
	body = append(body, ss...)
	body = append(body, message...)
	return body
}

// FilterRow returns true if the current data row should be forwarded.
// Returns false when the row limit is exceeded, marking the result as truncated.
func (sc *ShapeContext) FilterRow() bool {
	if sc.decision.RowLimit <= 0 {
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

// WasTruncated returns true if at least one row was dropped.
func (sc *ShapeContext) WasTruncated() bool { return sc.truncated }

// RowsSeen returns the number of rows forwarded so far.
func (sc *ShapeContext) RowsSeen() int { return sc.rowsSeen }

// TruncationWarning returns a MySQL WARNING packet to send after truncation, or nil.
// MySQL uses a warning count in the OK/EOF packet rather than a separate message;
// this returns a human-readable annotation that the handler adds to the OK packet.
func (sc *ShapeContext) TruncationNote() string {
	if !sc.truncated {
		return ""
	}
	return fmt.Sprintf("result set truncated by proxy: row limit %d reached", sc.decision.RowLimit)
}

// ─── Rule Management ──────────────────────────────────────────────────────────

// AddRule adds or replaces a per-fingerprint rule at runtime.
func (s *Shaper) AddRule(r Rule) {
	s.applyRuleDefaults(&r)
	s.mu.Lock()
	s.ruleIndex[r.Fingerprint] = &r
	s.mu.Unlock()
}

// RemoveRule removes a rule by fingerprint.
func (s *Shaper) RemoveRule(fingerprint string) {
	s.mu.Lock()
	delete(s.ruleIndex, fingerprint)
	s.mu.Unlock()
}

// RuleCount returns the number of active rules.
func (s *Shaper) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ruleIndex)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
	maxJitter := float64(base) * s.cfg.JitterFraction
	return time.Duration((rand.Float64()*2 - 1) * maxJitter) //nolint:gosec
}
