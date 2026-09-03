// Package publisher implements Layer 5: EventPublisher
// Async, non-blocking Kafka producer with local buffering and
// a deduplicated normalized query stream keyed by SQL fingerprint.
//
// Three output streams:
//   - pg-query-events:  one RawEvent per query execution (keyed by session_id for ordering)
//   - pg-query-dedup:   one DedupEvent per fingerprint per 10s window (keyed by fingerprint)
//   - pg-session-events: AuthEvent + SessionStartEvent + SessionEndEvent (keyed by session_id)
package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pgproxy/internal/interceptor"
	"github.com/segmentio/kafka-go"
)

// ─── Event Schemas ────────────────────────────────────────────────────────────

// RawEvent is the full per-execution query event.
// Kafka key: session_id (guarantees ordering within a session)
type RawEvent struct {
	EventType               string `json:"event_type"` // "query"
	Protocol                string `json:"protocol"`
	SessionID               string `json:"session_id"`
	Timestamp               string `json:"timestamp"`
	ClientIP                string `json:"client_ip"`
	Username                string `json:"username"`
	Database                string `json:"database"`
	QueryRaw                string `json:"query_raw"`
	QueryNormalized         string `json:"query_normalized"`
	Fingerprint             string `json:"fingerprint"`
	ProtocolMode            string `json:"protocol_mode"`
	QueryLength             int    `json:"query_length"`
	BytesIn                 int64  `json:"bytes_in"`
	BytesOut                int64  `json:"bytes_out"`
	OutcomeVerified         bool   `json:"outcome_verified"`
	Success                 bool   `json:"success"`
	Authority               string `json:"authority,omitempty"`
	TransactionState        string `json:"transaction_state,omitempty"`
	ErrorCode               string `json:"error_code,omitempty"`
	EventSchemaVersion      string `json:"event_schema_version,omitempty"`
	WorldID                 string `json:"world_id,omitempty"`
	AssetID                 string `json:"asset_id,omitempty"`
	AssetKind               string `json:"asset_kind,omitempty"`
	TrapTriggered           bool   `json:"trap_triggered"`
	TrapID                  string `json:"trap_id,omitempty"`
	TrapKind                string `json:"trap_kind,omitempty"`
	StrategyID              string `json:"strategy_id,omitempty"`
	StrategyRegistryVersion string `json:"strategy_registry_version,omitempty"`
}

// AuthEvent is published on every authentication attempt (success or failure).
// Kafka topic: pg-session-events, key: session_id
type AuthEvent struct {
	EventType  string `json:"event_type"` // "auth"
	Protocol   string `json:"protocol"`
	SessionID  string `json:"session_id"`
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Username   string `json:"username"`
	Database   string `json:"database"`
	AuthMethod string `json:"auth_method"` // "scram-sha-256", "md5", "cleartext", "unknown"
	Success    bool   `json:"success"`
	FailReason string `json:"fail_reason,omitempty"`
}

// SessionStartEvent is published when a session is fully established.
// Kafka topic: pg-session-events, key: session_id
type SessionStartEvent struct {
	EventType  string `json:"event_type"` // "session_start"
	Protocol   string `json:"protocol"`
	SessionID  string `json:"session_id"`
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Username   string `json:"username"`
	Database   string `json:"database"`
	AppName    string `json:"app_name"`
	AuthMethod string `json:"auth_method"`
}

// SessionEndEvent is published when a session closes.
// Kafka topic: pg-session-events, key: session_id
type SessionEndEvent struct {
	EventType   string `json:"event_type"` // "session_end"
	Protocol    string `json:"protocol"`
	SessionID   string `json:"session_id"`
	Timestamp   string `json:"timestamp"`
	ClientIP    string `json:"client_ip"`
	Username    string `json:"username"`
	Database    string `json:"database"`
	DurationMs  int64  `json:"duration_ms"`
	QueryCount  int64  `json:"query_count"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	CloseReason string `json:"close_reason"` // "clean", "error", "timeout"
}

// DedupEvent is a window-collapsed event.
// Kafka topic: pg-query-dedup, key: fingerprint
type DedupEvent struct {
	Fingerprint     string `json:"fingerprint"`
	QueryNormalized string `json:"query_normalized"`
	Database        string `json:"database"`
	Username        string `json:"username"`
	ExecCount       int64  `json:"exec_count"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	TotalBytesIn    int64  `json:"total_bytes_in"`
	TotalBytesOut   int64  `json:"total_bytes_out"`
	SimpleCount     int64  `json:"simple_count"`
	ExtendedCount   int64  `json:"extended_count"`
}

// ─── Config ───────────────────────────────────────────────────────────────────

type Config struct {
	Brokers      []string
	Topic        string // pg-query-events
	DedupTopic   string // pg-query-dedup
	SessionTopic string // pg-session-events
	BatchSize    int
	BufferCap    int
	DedupWindow  time.Duration
	DedupMaxKeys int

	// Kafka publish hardening. SendRetries is the number of retries
	// after the initial attempt, so the default of 2 means 3 attempts total.
	SendRetries      int
	SendRetryBackoff time.Duration
	SendTimeout      time.Duration
}

func (c *Config) setDefaults() {
	if c.BatchSize == 0 {
		c.BatchSize = 100
	}
	if c.BufferCap == 0 {
		c.BufferCap = 100_000
	}
	if c.DedupWindow == 0 {
		c.DedupWindow = 10 * time.Second
	}
	if c.DedupMaxKeys == 0 {
		c.DedupMaxKeys = 50_000
	}
	if c.SendRetries == 0 {
		c.SendRetries = 2
	}
	if c.SendRetryBackoff == 0 {
		c.SendRetryBackoff = 200 * time.Millisecond
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = 2 * time.Second
	}
	if c.Topic == "" {
		c.Topic = "pg-query-events"
	}
	if c.DedupTopic == "" {
		c.DedupTopic = "pg-query-dedup"
	}
	if c.SessionTopic == "" {
		c.SessionTopic = "pg-session-events"
	}
}

// ─── Publisher ────────────────────────────────────────────────────────────────

type Publisher struct {
	cfg        Config
	logger     *slog.Logger
	rawBuf     chan RawEvent
	sessionBuf chan interface{} // AuthEvent | SessionStartEvent | SessionEndEvent
	dedupMu    sync.Mutex
	dedupTable map[string]*dedupBucket
	dedupOut   chan DedupEvent
	wg         sync.WaitGroup

	// Persistent writers avoid reconnecting to Redpanda for every batch.
	rawWriter     *kafka.Writer
	dedupWriter   *kafka.Writer
	sessionWriter *kafka.Writer

	// Best-effort failure counters. These are intentionally in-memory because
	// Kafka outages must not create a new external dependency for the proxy path.
	rawSendFailures      int64
	dedupSendFailures    int64
	sessionSendFailures  int64
	rawEventsDropped     int64
	dedupEventsDropped   int64
	sessionEventsDropped int64
}

type dedupBucket struct {
	fingerprint     string
	queryNormalized string
	database        string
	username        string
	firstSeen       time.Time
	lastSeen        time.Time
	execCount       int64
	totalBytesIn    int64
	totalBytesOut   int64
	simpleCount     int64
	extendedCount   int64
}

func New(cfg Config, logger *slog.Logger) *Publisher {
	cfg.setDefaults()
	p := &Publisher{
		cfg:        cfg,
		logger:     logger,
		rawBuf:     make(chan RawEvent, cfg.BufferCap),
		sessionBuf: make(chan interface{}, 10_000),
		dedupTable: make(map[string]*dedupBucket, 1024),
		dedupOut:   make(chan DedupEvent, 10_000),
	}
	if len(cfg.Brokers) > 0 {
		p.rawWriter = newKafkaWriter(cfg.Brokers, cfg.Topic)
		p.dedupWriter = newKafkaWriter(cfg.Brokers, cfg.DedupTopic)
		p.sessionWriter = newKafkaWriter(cfg.Brokers, cfg.SessionTopic)
	}
	return p
}

func newKafkaWriter(brokers []string, topic string) *kafka.Writer {
	return &kafka.Writer{
		Addr:                   kafka.TCP(brokers...),
		Topic:                  topic,
		Balancer:               &kafka.Hash{},
		AllowAutoTopicCreation: true,
	}
}

func (p *Publisher) Start(ctx context.Context, events <-chan interceptor.QueryEvent) {
	p.wg.Add(3)
	go p.ingestLoop(ctx, events)
	go p.dedupFlushLoop(ctx)
	go p.publishLoop(ctx)
}

// ─── Public emit methods (called directly from handler/manager) ───────────────

func (p *Publisher) EmitAuth(e AuthEvent) {
	if e.Protocol == "" {
		e.Protocol = "postgres"
	}
	select {
	case p.sessionBuf <- e:
	default:
		p.logger.Warn("session buffer full, dropping auth event", "session_id", e.SessionID)
	}
}

func (p *Publisher) EmitSessionStart(e SessionStartEvent) {
	if e.Protocol == "" {
		e.Protocol = "postgres"
	}
	select {
	case p.sessionBuf <- e:
	default:
		p.logger.Warn("session buffer full, dropping session_start", "session_id", e.SessionID)
	}
}

func (p *Publisher) EmitSessionEnd(e SessionEndEvent) {
	if e.Protocol == "" {
		e.Protocol = "postgres"
	}
	select {
	case p.sessionBuf <- e:
	default:
		p.logger.Warn("session buffer full, dropping session_end", "session_id", e.SessionID)
	}
}

// ─── Ingest ───────────────────────────────────────────────────────────────────

func (p *Publisher) ingestLoop(ctx context.Context, events <-chan interceptor.QueryEvent) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case qe, ok := <-events:
			if !ok {
				return
			}
			raw := RawEvent{
				EventType:          "query",
				Protocol:           "postgres",
				SessionID:          qe.SessionID,
				Timestamp:          qe.Timestamp.UTC().Format(time.RFC3339Nano),
				ClientIP:           qe.ClientIP,
				Username:           qe.Username,
				Database:           qe.Database,
				QueryRaw:           qe.QueryRaw,
				QueryNormalized:    qe.QueryNormalized,
				Fingerprint:        qe.Fingerprint,
				ProtocolMode:       qe.ProtocolMode,
				QueryLength:        qe.QueryLength,
				BytesIn:            qe.BytesIn,
				BytesOut:           qe.BytesOut,
				OutcomeVerified:    qe.OutcomeVerified,
				Success:            qe.Success,
				Authority:          qe.Authority,
				TransactionState:   qe.TransactionState,
				ErrorCode:          qe.ErrorCode,
				EventSchemaVersion: qe.EventSchemaVersion,
				WorldID:            qe.WorldID, AssetID: qe.AssetID, AssetKind: qe.AssetKind,
				TrapTriggered: qe.TrapTriggered, TrapID: qe.TrapID, TrapKind: qe.TrapKind,
				StrategyID: qe.StrategyID, StrategyRegistryVersion: qe.StrategyRegistryVersion,
			}
			select {
			case p.rawBuf <- raw:
			default:
				p.logger.Warn("raw buffer full, dropping event", "fingerprint", qe.Fingerprint)
			}
			p.updateDedup(qe)
		}
	}
}

func (p *Publisher) updateDedup(qe interceptor.QueryEvent) {
	if qe.Fingerprint == "" {
		return
	}
	p.dedupMu.Lock()
	defer p.dedupMu.Unlock()

	if len(p.dedupTable) >= p.cfg.DedupMaxKeys {
		p.logger.Warn("dedup table at capacity, evicting", "size", len(p.dedupTable))
		count := 0
		for k := range p.dedupTable {
			delete(p.dedupTable, k)
			count++
			if count >= p.cfg.DedupMaxKeys/2 {
				break
			}
		}
	}

	bucket, exists := p.dedupTable[qe.Fingerprint]
	if !exists {
		bucket = &dedupBucket{
			fingerprint:     qe.Fingerprint,
			queryNormalized: qe.QueryNormalized,
			database:        qe.Database,
			username:        qe.Username,
			firstSeen:       qe.Timestamp,
		}
		p.dedupTable[qe.Fingerprint] = bucket
	}
	bucket.lastSeen = qe.Timestamp
	bucket.execCount++
	bucket.totalBytesIn += qe.BytesIn
	bucket.totalBytesOut += qe.BytesOut
	if qe.ProtocolMode == "simple" {
		bucket.simpleCount++
	} else {
		bucket.extendedCount++
	}
}

// ─── Dedup Flush ──────────────────────────────────────────────────────────────

func (p *Publisher) dedupFlushLoop(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.cfg.DedupWindow)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			p.flushDedup()
			return
		case <-ticker.C:
			p.flushDedup()
		}
	}
}

func (p *Publisher) flushDedup() {
	p.dedupMu.Lock()
	if len(p.dedupTable) == 0 {
		p.dedupMu.Unlock()
		return
	}
	snapshot := p.dedupTable
	p.dedupTable = make(map[string]*dedupBucket, len(snapshot))
	p.dedupMu.Unlock()

	for _, b := range snapshot {
		event := DedupEvent{
			Fingerprint:     b.fingerprint,
			QueryNormalized: b.queryNormalized,
			Database:        b.database,
			Username:        b.username,
			ExecCount:       b.execCount,
			FirstSeen:       b.firstSeen.UTC().Format(time.RFC3339Nano),
			LastSeen:        b.lastSeen.UTC().Format(time.RFC3339Nano),
			TotalBytesIn:    b.totalBytesIn,
			TotalBytesOut:   b.totalBytesOut,
			SimpleCount:     b.simpleCount,
			ExtendedCount:   b.extendedCount,
		}
		select {
		case p.dedupOut <- event:
		default:
			p.logger.Warn("dedup output buffer full, dropping", "fingerprint", b.fingerprint)
		}
	}
}

// ─── Publish ──────────────────────────────────────────────────────────────────

func (p *Publisher) publishLoop(ctx context.Context) {
	defer p.wg.Done()

	rawBatch := make([]RawEvent, 0, p.cfg.BatchSize)
	dedupBatch := make([]DedupEvent, 0, p.cfg.BatchSize)
	sessionBatch := make([]interface{}, 0, p.cfg.BatchSize)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	flushRaw := func(flushCtx context.Context) {
		if len(rawBatch) == 0 {
			return
		}
		if err := p.sendRawBatch(flushCtx, rawBatch); err != nil {
			p.logger.Error("kafka raw send failed; dropping batch after retries", "topic", p.cfg.Topic, "count", len(rawBatch), "error", err)
		}
		rawBatch = rawBatch[:0]
	}
	flushDedup := func(flushCtx context.Context) {
		if len(dedupBatch) == 0 {
			return
		}
		if err := p.sendDedupBatch(flushCtx, dedupBatch); err != nil {
			p.logger.Error("kafka dedup send failed; dropping batch after retries", "topic", p.cfg.DedupTopic, "count", len(dedupBatch), "error", err)
		}
		dedupBatch = dedupBatch[:0]
	}
	flushSession := func(flushCtx context.Context) {
		if len(sessionBatch) == 0 {
			return
		}
		if err := p.sendSessionBatch(flushCtx, sessionBatch); err != nil {
			p.logger.Error("kafka session send failed; dropping batch after retries", "topic", p.cfg.SessionTopic, "count", len(sessionBatch), "error", err)
		}
		sessionBatch = sessionBatch[:0]
	}

	drainBuffers := func() {
		// Best-effort drain on shutdown so queued events are not dropped just
		// because ctx is cancelled. Dedup is flushed first because that emits
		// into dedupOut.
		p.flushDedup()
		for {
			select {
			case e := <-p.rawBuf:
				rawBatch = append(rawBatch, e)
			case e := <-p.dedupOut:
				dedupBatch = append(dedupBatch, e)
			case e := <-p.sessionBuf:
				sessionBatch = append(sessionBatch, e)
			default:
				return
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			drainBuffers()
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flushRaw(flushCtx)
			flushDedup(flushCtx)
			flushSession(flushCtx)
			cancel()
			p.closeWriters()
			return
		case e := <-p.rawBuf:
			rawBatch = append(rawBatch, e)
			if len(rawBatch) >= p.cfg.BatchSize {
				flushRaw(ctx)
			}
		case e := <-p.dedupOut:
			dedupBatch = append(dedupBatch, e)
			if len(dedupBatch) >= p.cfg.BatchSize {
				flushDedup(ctx)
			}
		case e := <-p.sessionBuf:
			sessionBatch = append(sessionBatch, e)
			if len(sessionBatch) >= p.cfg.BatchSize {
				flushSession(ctx)
			}
		case <-ticker.C:
			flushRaw(ctx)
			flushDedup(ctx)
			flushSession(ctx)
		}
	}
}

// ─── Kafka Send ───────────────────────────────────────────────────────────────

func (p *Publisher) sendRawBatch(ctx context.Context, events []RawEvent) error {
	if len(p.cfg.Brokers) == 0 {
		for _, e := range events {
			data, _ := json.Marshal(e)
			p.logger.Debug("raw event (no broker)", "payload", string(data))
		}
		return nil
	}
	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		data, _ := json.Marshal(e)
		// KEY = session_id → guarantees all queries from one session go to same partition
		msgs = append(msgs, kafka.Message{Key: []byte(e.SessionID), Value: data})
	}
	return p.sendWithRetry(ctx, "raw", p.cfg.Topic, p.rawWriter, msgs)
}

func (p *Publisher) sendDedupBatch(ctx context.Context, events []DedupEvent) error {
	if len(p.cfg.Brokers) == 0 {
		for _, e := range events {
			data, _ := json.Marshal(e)
			p.logger.Debug("dedup event (no broker)", "payload", string(data))
		}
		return nil
	}
	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		data, _ := json.Marshal(e)
		// KEY = fingerprint → same query shape always goes to same partition
		msgs = append(msgs, kafka.Message{Key: []byte(e.Fingerprint), Value: data})
	}
	return p.sendWithRetry(ctx, "dedup", p.cfg.DedupTopic, p.dedupWriter, msgs)
}

func (p *Publisher) sendSessionBatch(ctx context.Context, events []interface{}) error {
	if len(p.cfg.Brokers) == 0 {
		for _, e := range events {
			data, _ := json.Marshal(e)
			p.logger.Debug("session event (no broker)", "payload", string(data))
		}
		return nil
	}
	msgs := make([]kafka.Message, 0, len(events))
	for _, e := range events {
		data, _ := json.Marshal(e)
		// Extract session_id as key so all events for one session go to same partition
		key := extractSessionID(e)
		msgs = append(msgs, kafka.Message{Key: []byte(key), Value: data})
	}
	return p.sendWithRetry(ctx, "session", p.cfg.SessionTopic, p.sessionWriter, msgs)
}

func (p *Publisher) sendWithRetry(ctx context.Context, stream, topic string, writer *kafka.Writer, msgs []kafka.Message) error {
	if len(msgs) == 0 {
		return nil
	}
	if writer == nil {
		p.recordKafkaDrop(stream, len(msgs))
		return fmt.Errorf("kafka writer is nil for topic %s", topic)
	}

	attempts := p.cfg.SendRetries + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		attemptCtx := ctx
		cancel := func() {}
		if p.cfg.SendTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, p.cfg.SendTimeout)
		}
		err := writer.WriteMessages(attemptCtx, msgs...)
		cancel()

		if err == nil {
			return nil
		}
		lastErr = err
		p.logger.Warn(
			"kafka publish attempt failed",
			"stream", stream,
			"topic", topic,
			"count", len(msgs),
			"attempt", attempt,
			"max_attempts", attempts,
			"error", err,
		)

		if attempt < attempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(p.cfg.SendRetryBackoff):
			}
		}
	}

	p.recordKafkaDrop(stream, len(msgs))
	return fmt.Errorf("kafka publish failed stream=%s topic=%s attempts=%d: %w", stream, topic, attempts, lastErr)
}

func (p *Publisher) recordKafkaDrop(stream string, count int) {
	switch stream {
	case "raw":
		atomic.AddInt64(&p.rawSendFailures, 1)
		atomic.AddInt64(&p.rawEventsDropped, int64(count))
	case "dedup":
		atomic.AddInt64(&p.dedupSendFailures, 1)
		atomic.AddInt64(&p.dedupEventsDropped, int64(count))
	case "session":
		atomic.AddInt64(&p.sessionSendFailures, 1)
		atomic.AddInt64(&p.sessionEventsDropped, int64(count))
	}
}

func (p *Publisher) closeWriters() {
	if p.rawWriter != nil {
		_ = p.rawWriter.Close()
	}
	if p.dedupWriter != nil {
		_ = p.dedupWriter.Close()
	}
	if p.sessionWriter != nil {
		_ = p.sessionWriter.Close()
	}
}

func extractSessionID(e interface{}) string {
	switch v := e.(type) {
	case AuthEvent:
		return v.SessionID
	case SessionStartEvent:
		return v.SessionID
	case SessionEndEvent:
		return v.SessionID
	}
	return ""
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func (p *Publisher) Wait() { p.wg.Wait() }

func (p *Publisher) DedupStats() int {
	p.dedupMu.Lock()
	defer p.dedupMu.Unlock()
	return len(p.dedupTable)
}

// PublisherFailureStats exposes best-effort Kafka failure counters.
// It is safe to call from metrics/debug endpoints while the publisher is active.
type PublisherFailureStats struct {
	RawSendFailures      int64
	DedupSendFailures    int64
	SessionSendFailures  int64
	RawEventsDropped     int64
	DedupEventsDropped   int64
	SessionEventsDropped int64
}

func (p *Publisher) PublishFailureStats() PublisherFailureStats {
	return PublisherFailureStats{
		RawSendFailures:      atomic.LoadInt64(&p.rawSendFailures),
		DedupSendFailures:    atomic.LoadInt64(&p.dedupSendFailures),
		SessionSendFailures:  atomic.LoadInt64(&p.sessionSendFailures),
		RawEventsDropped:     atomic.LoadInt64(&p.rawEventsDropped),
		DedupEventsDropped:   atomic.LoadInt64(&p.dedupEventsDropped),
		SessionEventsDropped: atomic.LoadInt64(&p.sessionEventsDropped),
	}
}
