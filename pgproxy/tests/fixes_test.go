package tests

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/publisher"
	"github.com/pgproxy/internal/session"
	"github.com/pgproxy/internal/shaper"
)

// ─── Fix 1: FNV-64 Fingerprinting ────────────────────────────────────────────

func TestFingerprintSQLStability(t *testing.T) {
	// Same query shape, different literals → identical fingerprint
	queries := []string{
		"SELECT * FROM users WHERE id = 1",
		"SELECT * FROM users WHERE id = 99",
		"SELECT * FROM users WHERE id = 12345",
	}
	fps := make([]string, len(queries))
	for i, q := range queries {
		norm := interceptor.NormalizeSQL(q)
		fps[i] = interceptor.FingerprintSQL(norm)
	}
	for i := 1; i < len(fps); i++ {
		if fps[i] != fps[0] {
			t.Errorf("fingerprint[%d]=%q != fingerprint[0]=%q — same shape should produce same hash",
				i, fps[i], fps[0])
		}
	}
}

func TestFingerprintSQLDifferentShapes(t *testing.T) {
	// Different query shapes → different fingerprints
	cases := []string{
		"SELECT * FROM users WHERE id = 1",
		"SELECT * FROM orders WHERE id = 1",
		"SELECT id FROM users WHERE id = 1",
		"DELETE FROM users WHERE id = 1",
	}
	seen := make(map[string]string)
	for _, sql := range cases {
		norm := interceptor.NormalizeSQL(sql)
		fp := interceptor.FingerprintSQL(norm)
		if fp == "" {
			t.Errorf("empty fingerprint for: %q", sql)
		}
		if existing, ok := seen[fp]; ok {
			t.Errorf("fingerprint collision:\n  query1: %q\n  query2: %q\n  fp: %q",
				existing, sql, fp)
		}
		seen[fp] = sql
	}
}

func TestFingerprintSQLFormat(t *testing.T) {
	// Fingerprint must be a 16-char lowercase hex string (8 bytes FNV-64a)
	norm := interceptor.NormalizeSQL("SELECT 1")
	fp := interceptor.FingerprintSQL(norm)
	if len(fp) != 16 {
		t.Errorf("expected 16-char hex fingerprint, got %d chars: %q", len(fp), fp)
	}
	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("fingerprint contains non-hex char %q in %q", c, fp)
		}
	}
}

func TestFingerprintSQLEmptyInput(t *testing.T) {
	fp := interceptor.FingerprintSQL("")
	if fp != "" {
		t.Errorf("empty input should return empty fingerprint, got %q", fp)
	}
}

func TestFingerprintSQLConcurrentAccess(t *testing.T) {
	// Hash cache must be safe under concurrent access
	sql := "SELECT * FROM t WHERE id = 42"
	norm := interceptor.NormalizeSQL(sql)
	var wg sync.WaitGroup
	results := make([]string, 50)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = interceptor.FingerprintSQL(norm)
		}(i)
	}
	wg.Wait()
	for i, r := range results {
		if r != results[0] {
			t.Errorf("results[%d]=%q != results[0]=%q under concurrency", i, r, results[0])
		}
	}
}

func TestQueryEventIncludesFingerprint(t *testing.T) {
	ic := interceptor.New(10)
	sess := session.NewFromStartup(&pgproto3.StartupMessage{
		Parameters: map[string]string{"user": "alice", "database": "db"},
	}, "127.0.0.1:1234")

	ic.InterceptSimple(sess, "SELECT * FROM users WHERE id = 42")

	select {
	case ev := <-ic.Events():
		if ev.Fingerprint == "" {
			t.Error("QueryEvent.Fingerprint must not be empty")
		}
		// Fingerprint must match FingerprintSQL(NormalizeSQL(raw))
		want := interceptor.FingerprintSQL(interceptor.NormalizeSQL(ev.QueryRaw))
		if ev.Fingerprint != want {
			t.Errorf("fingerprint mismatch: got %q, want %q", ev.Fingerprint, want)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}

func TestExtendedQueryEventIncludesFingerprint(t *testing.T) {
	ic := interceptor.New(10)
	sess := session.NewFromStartup(&pgproto3.StartupMessage{
		Parameters: map[string]string{"user": "bob", "database": "db"},
	}, "10.0.0.1:9")

	ic.InterceptParse(sess, "s1", "SELECT id FROM orders WHERE user_id = $1")
	ic.InterceptBind(sess, "s1", "p1", [][]byte{[]byte("7")})
	ic.InterceptExecute(sess, "p1", 0)

	select {
	case ev := <-ic.Events():
		if ev.Fingerprint == "" {
			t.Error("extended QueryEvent.Fingerprint must not be empty")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event received")
	}
}

// ─── Fix 2: Deduplicated Publisher ────────────────────────────────────────────

func makeTestEvent(fingerprint, normalized, db, user, mode string) interceptor.QueryEvent {
	return interceptor.QueryEvent{
		SessionID:       "sess-1",
		Timestamp:       time.Now(),
		ClientIP:        "127.0.0.1",
		Username:        user,
		Database:        db,
		QueryRaw:        "SELECT 1",
		QueryNormalized: normalized,
		Fingerprint:     fingerprint,
		ProtocolMode:    mode,
		QueryLength:     8,
		BytesIn:         100,
		BytesOut:        200,
	}
}

func TestPublisherDedupCountsExecutions(t *testing.T) {
	p := publisher.New(publisher.Config{
		DedupWindow:  50 * time.Millisecond,
		DedupMaxKeys: 1000,
	}, noopLogger())

	events := make(chan interceptor.QueryEvent, 100)
	ctx, cancel := cancel2()
	defer cancel()
	p.Start(ctx, events)

	// Send 5 executions of the same fingerprint
	fp := "aabbccddeeff0011"
	for i := 0; i < 5; i++ {
		events <- makeTestEvent(fp, "select ? from t", "mydb", "alice", "simple")
	}
	// Give the ingest loop time to process
	time.Sleep(20 * time.Millisecond)

	// Stats should reflect 5 buffered executions
	// (dedup hasn't flushed yet)
	if got := p.DedupStats(); got != 1 {
		t.Errorf("expected 1 unique fingerprint in dedup table, got %d", got)
	}
}

func TestPublisherDedupFlushClearsTable(t *testing.T) {
	p := publisher.New(publisher.Config{
		DedupWindow:  30 * time.Millisecond,
		DedupMaxKeys: 1000,
	}, noopLogger())

	events := make(chan interceptor.QueryEvent, 100)
	ctx, cancel := cancel2()
	defer cancel()
	p.Start(ctx, events)

	fp := "1122334455667788"
	events <- makeTestEvent(fp, "select ?", "db", "u", "simple")
	time.Sleep(20 * time.Millisecond) // after ingest, before flush

	if p.DedupStats() != 1 {
		t.Error("expected 1 entry before flush")
	}

	// Wait for flush window to elapse
	time.Sleep(50 * time.Millisecond)

	if p.DedupStats() != 0 {
		t.Errorf("expected dedup table to be cleared after flush, got %d", p.DedupStats())
	}
}

func TestPublisherDedupMultipleFingerprints(t *testing.T) {
	p := publisher.New(publisher.Config{
		DedupWindow:  200 * time.Millisecond,
		DedupMaxKeys: 1000,
	}, noopLogger())

	events := make(chan interceptor.QueryEvent, 100)
	ctx, cancel := cancel2()
	defer cancel()
	p.Start(ctx, events)

	// Send 3 different fingerprints, multiple times each
	fps := []string{"aaaa000000000001", "bbbb000000000002", "cccc000000000003"}
	for _, fp := range fps {
		for i := 0; i < 4; i++ {
			events <- makeTestEvent(fp, "select ?", "db", "u", "simple")
		}
	}
	time.Sleep(30 * time.Millisecond)

	if got := p.DedupStats(); got != 3 {
		t.Errorf("expected 3 unique fingerprints, got %d", got)
	}
}

func TestPublisherDedupNonBlocking(t *testing.T) {
	// Publisher must never block even when dedup window is long
	p := publisher.New(publisher.Config{
		DedupWindow:  10 * time.Second, // very long window
		DedupMaxKeys: 1000,
	}, noopLogger())

	events := make(chan interceptor.QueryEvent, 100)
	ctx, cancel := cancel2()
	defer cancel()
	p.Start(ctx, events)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			fp := fmt.Sprintf("%016x", i)
			events <- makeTestEvent(fp, "select ?", "db", "u", "simple")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("publisher blocked while ingesting events")
	}
}

func TestPublisherDedupEviction(t *testing.T) {
	// When DedupMaxKeys is exceeded, eviction should occur without panic
	p := publisher.New(publisher.Config{
		DedupWindow:  10 * time.Second,
		DedupMaxKeys: 10, // tiny cap
	}, noopLogger())

	events := make(chan interceptor.QueryEvent, 1000)
	ctx, cancel := cancel2()
	defer cancel()
	p.Start(ctx, events)

	for i := 0; i < 50; i++ {
		fp := fmt.Sprintf("%016x", i)
		events <- makeTestEvent(fp, "select ?", "db", "u", "simple")
	}
	time.Sleep(50 * time.Millisecond)

	// After eviction, table size should be ≤ DedupMaxKeys
	if got := p.DedupStats(); got > 10 {
		t.Errorf("dedup table exceeded max keys after eviction: %d > 10", got)
	}
}

// ─── Fix 3: ResponseShaper ────────────────────────────────────────────────────

func TestShaperNoRulesIsTransparent(t *testing.T) {
	s := shaper.New(shaper.Config{}, noopLogger())
	d := s.Decide("anyfingerprint")
	if d.ShouldBlock {
		t.Error("default shaper should not block")
	}
	if d.Latency != 0 {
		t.Errorf("default shaper should have zero latency, got %v", d.Latency)
	}
	if d.RowLimit != 0 {
		t.Errorf("default shaper should have no row limit, got %d", d.RowLimit)
	}
}

func TestShaperGlobalLatency(t *testing.T) {
	s := shaper.New(shaper.Config{
		GlobalLatency: 5 * time.Millisecond,
	}, noopLogger())
	d := s.Decide("")
	if d.Latency < 5*time.Millisecond {
		t.Errorf("expected latency ≥ 5ms, got %v", d.Latency)
	}
}

func TestShaperGlobalRowLimit(t *testing.T) {
	s := shaper.New(shaper.Config{DefaultRowLimit: 10}, noopLogger())
	d := s.Decide("")
	if d.RowLimit != 10 {
		t.Errorf("expected row limit 10, got %d", d.RowLimit)
	}
}

func TestShaperBlockRule(t *testing.T) {
	fp := "deadbeefcafebabe"
	s := shaper.New(shaper.Config{
		Rules: []shaper.Rule{
			{Fingerprint: fp, Block: true, BlockMessage: "nope"},
		},
	}, noopLogger())

	d := s.Decide(fp)
	if !d.ShouldBlock {
		t.Error("expected decision to block this fingerprint")
	}
	if d.BlockMessage != "nope" {
		t.Errorf("expected block message 'nope', got %q", d.BlockMessage)
	}

	// Non-blocked fingerprint
	d2 := s.Decide("other")
	if d2.ShouldBlock {
		t.Error("other fingerprint should not be blocked")
	}
}

func TestShaperFingerprintLatencyOverride(t *testing.T) {
	fp := "aabbccddeeff0011"
	s := shaper.New(shaper.Config{
		GlobalLatency: 100 * time.Millisecond,
		Rules: []shaper.Rule{
			{Fingerprint: fp, Latency: -1}, // disabled for this fingerprint
		},
	}, noopLogger())

	// This fingerprint should have latency disabled
	d := s.Decide(fp)
	if d.Latency != 0 {
		t.Errorf("latency should be disabled for this fingerprint, got %v", d.Latency)
	}

	// Global latency still applies to others
	d2 := s.Decide("other")
	if d2.Latency == 0 {
		t.Error("global latency should apply to unmatched fingerprints")
	}
}

func TestShaperFingerprintRowLimitOverride(t *testing.T) {
	fp := "1234567890abcdef"
	s := shaper.New(shaper.Config{
		DefaultRowLimit: 100,
		Rules: []shaper.Rule{
			{Fingerprint: fp, RowLimit: 5},
		},
	}, noopLogger())

	d := s.Decide(fp)
	if d.RowLimit != 5 {
		t.Errorf("expected fingerprint row limit 5, got %d", d.RowLimit)
	}

	d2 := s.Decide("other")
	if d2.RowLimit != 100 {
		t.Errorf("expected default row limit 100 for other, got %d", d2.RowLimit)
	}
}

func TestShaperRowFiltering(t *testing.T) {
	s := shaper.New(shaper.Config{DefaultRowLimit: 3}, noopLogger())
	sc := shaper.NewShapeContext(s.Decide(""))

	// First 3 rows should pass
	for i := 0; i < 3; i++ {
		if !sc.FilterRow() {
			t.Errorf("row %d should pass (limit=3)", i+1)
		}
	}
	// 4th and beyond should be dropped
	for i := 3; i < 6; i++ {
		if sc.FilterRow() {
			t.Errorf("row %d should be dropped (limit=3)", i+1)
		}
	}
	if !sc.WasTruncated() {
		t.Error("WasTruncated should be true after dropping rows")
	}
}

func TestShaperTruncationNotice(t *testing.T) {
	s := shaper.New(shaper.Config{DefaultRowLimit: 2}, noopLogger())
	sc := shaper.NewShapeContext(s.Decide(""))

	sc.FilterRow()
	sc.FilterRow()
	sc.FilterRow() // dropped — triggers truncation flag

	notice := sc.TruncationNotice()
	if notice == nil {
		t.Fatal("expected a truncation notice")
	}
	if notice.Severity != "NOTICE" {
		t.Errorf("expected NOTICE severity, got %q", notice.Severity)
	}
}

func TestShaperNoTruncationNoticeWhenUnderLimit(t *testing.T) {
	s := shaper.New(shaper.Config{DefaultRowLimit: 100}, noopLogger())
	sc := shaper.NewShapeContext(s.Decide(""))
	for i := 0; i < 5; i++ {
		sc.FilterRow()
	}
	if sc.TruncationNotice() != nil {
		t.Error("should be no truncation notice when under row limit")
	}
}

func TestShaperBlockResponse(t *testing.T) {
	fp := "blocked0fingerpr"
	s := shaper.New(shaper.Config{
		Rules: []shaper.Rule{
			{Fingerprint: fp, Block: true, BlockMessage: "query blocked"},
		},
	}, noopLogger())

	sc := shaper.NewShapeContext(s.Decide(fp))
	resp := sc.BlockResponse()
	if resp == nil {
		t.Fatal("expected non-nil block response")
	}
	if resp.Code != "42501" {
		t.Errorf("expected code 42501, got %q", resp.Code)
	}
	if resp.Message != "query blocked" {
		t.Errorf("expected message 'query blocked', got %q", resp.Message)
	}
}

func TestShaperAddRemoveRuleAtRuntime(t *testing.T) {
	s := shaper.New(shaper.Config{}, noopLogger())
	fp := "runtimerule00001"

	// No rule initially
	if s.Decide(fp).ShouldBlock {
		t.Error("should not block before rule is added")
	}

	// Add rule
	s.AddRule(shaper.Rule{Fingerprint: fp, Block: true})
	if !s.Decide(fp).ShouldBlock {
		t.Error("should block after rule is added")
	}
	if s.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", s.RuleCount())
	}

	// Remove rule
	s.RemoveRule(fp)
	if s.Decide(fp).ShouldBlock {
		t.Error("should not block after rule is removed")
	}
	if s.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", s.RuleCount())
	}
}

func TestShaperJitterBounds(t *testing.T) {
	base := 100 * time.Millisecond
	s := shaper.New(shaper.Config{
		GlobalLatency:  base,
		JitterFraction: 0.5, // ±50%
	}, noopLogger())

	// Collect 100 samples; all must be within [50ms, 150ms]
	for i := 0; i < 100; i++ {
		d := s.Decide("")
		if d.Latency < 50*time.Millisecond || d.Latency > 150*time.Millisecond {
			t.Errorf("latency %v outside jitter bounds [50ms, 150ms]", d.Latency)
		}
	}
}

func TestShaperConcurrentDecide(t *testing.T) {
	fp := "concurrent000001"
	s := shaper.New(shaper.Config{
		Rules: []shaper.Rule{{Fingerprint: fp, RowLimit: 10}},
	}, noopLogger())

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := s.Decide(fp)
			if d.RowLimit != 10 {
				t.Errorf("concurrent: expected RowLimit=10, got %d", d.RowLimit)
			}
		}()
	}
	wg.Wait()
}

// ─── Benchmark ────────────────────────────────────────────────────────────────

func BenchmarkFingerprintSQL(b *testing.B) {
	norm := interceptor.NormalizeSQL("SELECT * FROM users WHERE id = 42 AND status = 'active'")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			interceptor.FingerprintSQL(norm)
		}
	})
}

func BenchmarkShaperDecideNoRules(b *testing.B) {
	s := shaper.New(shaper.Config{}, noopLogger())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Decide("anyfingerprint")
		}
	})
}

func BenchmarkShaperDecideWithRule(b *testing.B) {
	fp := "benchmarkfp0001"
	s := shaper.New(shaper.Config{
		Rules: []shaper.Rule{{Fingerprint: fp, RowLimit: 50}},
	}, noopLogger())
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Decide(fp)
		}
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func cancel2() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
