// Package interceptor implements Layer 4: QueryInterceptor
// Extracts and normalizes SQL from both simple and extended query protocols.
// Phase 2 feature — wired in but protocol/handler.go has the calls commented out.
package interceptor

import (
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pgproxy/internal/session"
)

// QueryEvent represents a captured query and its metadata.
type QueryEvent struct {
	SessionID       string
	Timestamp       time.Time
	ClientIP        string
	Username        string
	Database        string
	QueryRaw        string
	QueryNormalized string
	// Fingerprint is a stable FNV-64a hex hash of QueryNormalized.
	// Identical query shapes always produce the same fingerprint,
	// regardless of literal values or parameter bindings.
	// Used as the deduplication key in the publisher.
	Fingerprint      string
	ProtocolMode     string // "simple" | "extended"
	QueryLength      int
	BytesIn          int64
	BytesOut         int64
	OutcomeVerified  bool
	Success          bool
	Authority        string // backend | deception | policy
	TransactionState string // idle | in_transaction | failed_transaction
	ErrorCode        string
}

// QueryOutcome is attached only after a deterministic result is known.
type QueryOutcome struct {
	Verified         bool
	Success          bool
	Authority        string
	TransactionState string
	ErrorCode        string
}

// Interceptor captures query events from the protocol stream.
type Interceptor struct {
	mu     sync.Mutex
	events chan QueryEvent

	// In-flight extended query state (per-session, keyed by session ID)
	pending map[string]*extendedQueryState
}

// extendedQueryState tracks state across Parse/Bind/Execute for extended protocol.
type extendedQueryState struct {
	stmtName   string
	portalName string
	query      string
	params     [][]byte
}

// New creates a new Interceptor with a buffered event channel.
func New(bufSize int) *Interceptor {
	if bufSize <= 0 {
		bufSize = 10000
	}
	return &Interceptor{
		events:  make(chan QueryEvent, bufSize),
		pending: make(map[string]*extendedQueryState),
	}
}

// Events returns the read-only event channel.
func (i *Interceptor) Events() <-chan QueryEvent {
	return i.events
}

// CleanupSession removes all in-flight extended query state for the given session.
// Must be called when a session disconnects to prevent memory leaks. Fix 5.
func (i *Interceptor) CleanupSession(sessionID string) {
	i.mu.Lock()
	delete(i.pending, sessionID)
	i.mu.Unlock()
}

// InterceptSimple captures a simple Query message.
func (i *Interceptor) InterceptSimple(sess *session.Session, sql string) {
	i.InterceptSimpleOutcome(sess, sql, QueryOutcome{})
}

// InterceptSimpleOutcome captures a simple query after its response is known.
func (i *Interceptor) InterceptSimpleOutcome(sess *session.Session, sql string, outcome QueryOutcome) {
	snap := sess.Snapshot()
	normalized := NormalizeSQL(sql)
	event := QueryEvent{
		SessionID:        snap.ID,
		Timestamp:        time.Now(),
		ClientIP:         snap.ClientIP,
		Username:         snap.Username,
		Database:         snap.Database,
		QueryRaw:         sql,
		QueryNormalized:  normalized,
		Fingerprint:      FingerprintSQL(normalized),
		ProtocolMode:     "simple",
		QueryLength:      len(sql),
		BytesIn:          snap.BytesIn,
		BytesOut:         snap.BytesOut,
		OutcomeVerified:  outcome.Verified,
		Success:          outcome.Success,
		Authority:        outcome.Authority,
		TransactionState: outcome.TransactionState,
		ErrorCode:        outcome.ErrorCode,
	}

	sess.IncrQueryCount()
	i.emit(event)
}

// InterceptParse captures a Parse message (extended protocol step 1).
func (i *Interceptor) InterceptParse(sess *session.Session, stmtName, query string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.pending[sess.Snapshot().ID] = &extendedQueryState{
		stmtName: stmtName,
		query:    query,
	}
	sess.AddPreparedStatement(stmtName, query)
}

// InterceptBind captures a Bind message (extended protocol step 2).
func (i *Interceptor) InterceptBind(sess *session.Session, stmtName, portalName string, params [][]byte) {
	i.mu.Lock()
	defer i.mu.Unlock()

	snap := sess.Snapshot()
	state, ok := i.pending[snap.ID]
	if !ok {
		// Bind to a previously prepared statement
		ps, exists := sess.GetPreparedStatement(stmtName)
		if exists {
			state = &extendedQueryState{
				stmtName: stmtName,
				query:    ps.Query,
			}
			i.pending[snap.ID] = state
		} else {
			return
		}
	}
	state.portalName = portalName
	state.params = params
	sess.AddPortal(portalName, stmtName, params)
}

// InterceptExecute captures an Execute message and emits the full event (step 3).
func (i *Interceptor) InterceptExecute(sess *session.Session, portalName string, maxRows uint32) {
	i.mu.Lock()
	state, ok := i.pending[sess.Snapshot().ID]
	i.mu.Unlock()

	if !ok {
		return
	}

	snap := sess.Snapshot()
	normalized := NormalizeSQL(state.query)
	event := QueryEvent{
		SessionID:       snap.ID,
		Timestamp:       time.Now(),
		ClientIP:        snap.ClientIP,
		Username:        snap.Username,
		Database:        snap.Database,
		QueryRaw:        state.query,
		QueryNormalized: normalized,
		Fingerprint:     FingerprintSQL(normalized),
		ProtocolMode:    "extended",
		QueryLength:     len(state.query),
		BytesIn:         snap.BytesIn,
		BytesOut:        snap.BytesOut,
	}

	sess.IncrQueryCount()
	i.emit(event)
}

// emit sends an event to the channel without blocking.
func (i *Interceptor) emit(event QueryEvent) {
	select {
	case i.events <- event:
	default:
		// Channel full — drop (Phase 3 publisher handles backpressure)
	}
}

// ─── SQL Normalization ────────────────────────────────────────────────────────

var (
	// Match numeric literals (integers and floats)
	reNumbers = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)

	// Match single-quoted string literals
	reStrings = regexp.MustCompile(`'(?:[^'\\]|\\.)*'`)

	// Match dollar-quoted strings: $tag$...$tag$
	reDollarQuote = regexp.MustCompile(`\$[^$]*\$.*?\$[^$]*\$`)

	// Match positional parameters $1, $2, ...
	reParams = regexp.MustCompile(`\$\d+`)

	// Collapse multiple whitespace
	reWhitespace = regexp.MustCompile(`\s+`)

	// Match IN (...) lists to normalize them
	reInList = regexp.MustCompile(`(?i)\bIN\s*\([^)]+\)`)

	// Match VALUES (...) lists
	reValuesList = regexp.MustCompile(`(?i)\bVALUES\s*\([^)]+\)`)
)

// ─── Bounded Cache ────────────────────────────────────────────────────────────

// boundedCache is a fixed-capacity string→string cache.
// When capacity is exceeded the entire cache is cleared (generation eviction).
// This gives O(1) reads with zero per-entry overhead and prevents unbounded growth.
// Fix 4: replaces the previous unbounded sync.Map.
type boundedCache struct {
	mu       sync.RWMutex
	m        map[string]string
	capacity int
}

func newBoundedCache(capacity int) *boundedCache {
	return &boundedCache{m: make(map[string]string, capacity), capacity: capacity}
}

func (c *boundedCache) get(key string) (string, bool) {
	c.mu.RLock()
	v, ok := c.m[key]
	c.mu.RUnlock()
	return v, ok
}

func (c *boundedCache) set(key, val string) {
	c.mu.Lock()
	if len(c.m) >= c.capacity {
		// Generation eviction: clear everything. Simple and allocation-free.
		c.m = make(map[string]string, c.capacity)
	}
	c.m[key] = val
	c.mu.Unlock()
}

var (
	// normCache: raw SQL → normalized SQL. Bounded at 50k unique raw queries.
	normCache = newBoundedCache(50_000)
	// hashCache: normalized SQL → FNV-64a hex fingerprint. Bounded at 50k templates.
	hashCache = newBoundedCache(50_000)
)

// NormalizeSQL normalizes a SQL string for aggregation/deduplication:
//   - Lowercases keywords
//   - Replaces literal values with ?
//   - Collapses whitespace
//
// Results are cached in a bounded cache (50k entries). Fix 4.
func NormalizeSQL(sql string) string {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return ""
	}
	if cached, ok := normCache.get(sql); ok {
		return cached
	}
	normalized := normalizeSQL(sql)
	normCache.set(sql, normalized)
	return normalized
}

// FingerprintSQL returns a stable 8-byte FNV-64a hex hash of the normalized SQL.
// Results are cached in a bounded cache (50k entries). Fix 4.
func FingerprintSQL(normalized string) string {
	if normalized == "" {
		return ""
	}
	if cached, ok := hashCache.get(normalized); ok {
		return cached
	}
	h := fnv.New64a()
	h.Write([]byte(normalized))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h.Sum64())
	fp := hex.EncodeToString(b[:])
	hashCache.set(normalized, fp)
	return fp
}

func normalizeSQL(sql string) string {
	// Remove comments
	s := removeComments(sql)

	// Replace dollar-quoted strings first (before other replacements)
	s = reDollarQuote.ReplaceAllString(s, "?")

	// Replace single-quoted strings
	s = reStrings.ReplaceAllString(s, "?")

	// Replace positional params
	s = reParams.ReplaceAllString(s, "?")

	// Replace numeric literals
	s = reNumbers.ReplaceAllString(s, "?")

	// Normalize IN (...) lists
	s = reInList.ReplaceAllStringFunc(s, func(m string) string {
		idx := strings.IndexByte(m, '(')
		return m[:idx] + "(?)"
	})

	// Normalize VALUES lists
	s = reValuesList.ReplaceAllStringFunc(s, func(m string) string {
		idx := strings.IndexByte(m, '(')
		return m[:idx] + "(?)"
	})

	// Collapse whitespace
	s = reWhitespace.ReplaceAllString(s, " ")

	// Lowercase
	s = strings.ToLower(strings.TrimSpace(s))

	return s
}

// removeComments strips SQL line and block comments.
func removeComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		// Block comment: /* ... */
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end >= 0 {
				i = i + 2 + end + 2
				b.WriteByte(' ')
				continue
			}
		}
		// Line comment: -- ...
		if i+1 < len(s) && s[i] == '-' && s[i+1] == '-' {
			end := strings.IndexByte(s[i:], '\n')
			if end >= 0 {
				i += end
			} else {
				break
			}
			continue
		}
		// Single-quoted string (don't strip, leave for reStrings)
		if s[i] == '\'' {
			b.WriteByte(s[i])
			i++
			for i < len(s) {
				b.WriteByte(s[i])
				if s[i] == '\'' {
					i++
					break
				}
				if s[i] == '\\' {
					i++
					if i < len(s) {
						b.WriteByte(s[i])
						i++
					}
					continue
				}
				i++
			}
			continue
		}
		if !unicode.IsControl(rune(s[i])) || s[i] == '\n' || s[i] == '\t' {
			b.WriteByte(s[i])
		} else {
			b.WriteByte(' ')
		}
		i++
	}
	return b.String()
}
