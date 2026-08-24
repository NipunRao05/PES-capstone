// Package interceptor implements Layer 4: QueryInterceptor for MySQL proxy.
// Captures SQL from COM_QUERY (text protocol) and COM_STMT_PREPARE/EXECUTE
// (binary prepared statement protocol). Normalizes SQL and computes stable
// FNV-64a fingerprints for deduplication.
//
// All fixes from the PostgreSQL proxy are implemented here:
//   - Fix 4: Bounded normalization and fingerprint caches (50k entries each)
//   - Fix 5: CleanupSession() removes in-flight state on disconnect
package interceptor

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mysqlproxy/internal/session"
)

// ─── QueryEvent ───────────────────────────────────────────────────────────────

// QueryEvent is the captured, normalized query with full session metadata.
// Identical schema to the PostgreSQL proxy's QueryEvent for unified Kafka consumption.
type QueryEvent struct {
	SessionID       string
	Timestamp       time.Time
	ClientIP        string
	Username        string
	Database        string
	QueryRaw        string
	QueryNormalized string
	// Fingerprint is a stable FNV-64a hex hash of QueryNormalized.
	// Same query shape always → same fingerprint, regardless of literals.
	Fingerprint      string
	ProtocolMode     string // "text" (COM_QUERY) | "prepared" (COM_STMT_EXECUTE)
	QueryLength      int
	BytesIn          int64
	BytesOut         int64
	OutcomeVerified  bool
	Success          bool
	Authority        string // backend | deception | policy
	TransactionState string // idle | in_transaction
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

// ─── Interceptor ─────────────────────────────────────────────────────────────

// Interceptor captures and normalizes MySQL query events.
type Interceptor struct {
	mu     sync.Mutex
	events chan QueryEvent

	// In-flight prepared statement SQL per session.
	// Key: sessionID + ":" + stmtID (decimal string)
	// Fix 5: CleanupSession removes all keys for a session on disconnect.
	pending map[string]string // key → raw SQL
}

// New creates a new Interceptor with a buffered event channel.
func New(bufSize int) *Interceptor {
	if bufSize <= 0 {
		bufSize = 10_000
	}
	return &Interceptor{
		events:  make(chan QueryEvent, bufSize),
		pending: make(map[string]string),
	}
}

// Events returns the read-only event channel consumed by the publisher.
func (i *Interceptor) Events() <-chan QueryEvent { return i.events }

// CleanupSession removes all in-flight prepared statement state for a session.
// Must be called when a session disconnects. Fix 5.
func (i *Interceptor) CleanupSession(sessID string) {
	prefix := sessID + ":"
	i.mu.Lock()
	for k := range i.pending {
		if strings.HasPrefix(k, prefix) {
			delete(i.pending, k)
		}
	}
	i.mu.Unlock()
}

// InterceptTextQuery captures a COM_QUERY command.
func (i *Interceptor) InterceptTextQuery(sess *session.Session, sql string) {
	i.InterceptTextQueryOutcome(sess, sql, QueryOutcome{})
}

// InterceptTextQueryOutcome captures a COM_QUERY command after its response is known.
func (i *Interceptor) InterceptTextQueryOutcome(sess *session.Session, sql string, outcome QueryOutcome) {
	sql = CleanTextQuery(sql)
	snap := sess.Snapshot()
	normalized := NormalizeSQL(sql)
	i.emit(QueryEvent{
		SessionID:        snap.ID,
		Timestamp:        time.Now(),
		ClientIP:         snap.ClientIP,
		Username:         snap.Username,
		Database:         snap.Database,
		QueryRaw:         sql,
		QueryNormalized:  normalized,
		Fingerprint:      FingerprintSQL(normalized),
		ProtocolMode:     "text",
		QueryLength:      len(sql),
		BytesIn:          snap.BytesIn,
		BytesOut:         snap.BytesOut,
		OutcomeVerified:  outcome.Verified,
		Success:          outcome.Success,
		Authority:        outcome.Authority,
		TransactionState: outcome.TransactionState,
		ErrorCode:        outcome.ErrorCode,
	})
	sess.IncrQueryCount()
}

// InterceptStmtPrepare records the SQL for a COM_STMT_PREPARE command.
// stmtID is assigned by the backend in the OK response.
func (i *Interceptor) InterceptStmtPrepare(sessID string, stmtID uint32, sql string) {
	key := stmtKey(sessID, stmtID)
	i.mu.Lock()
	i.pending[key] = sql
	i.mu.Unlock()
}

// InterceptStmtExecute emits a QueryEvent for a COM_STMT_EXECUTE command.
func (i *Interceptor) InterceptStmtExecute(sess *session.Session, stmtID uint32) {
	i.InterceptStmtExecuteOutcome(sess, stmtID, QueryOutcome{})
}

// InterceptStmtExecuteOutcome captures a prepared execution after its response is known.
func (i *Interceptor) InterceptStmtExecuteOutcome(sess *session.Session, stmtID uint32, outcome QueryOutcome) {
	snap := sess.Snapshot()
	key := stmtKey(snap.ID, stmtID)

	i.mu.Lock()
	sql, ok := i.pending[key]
	i.mu.Unlock()
	if !ok {
		return
	}

	normalized := NormalizeSQL(sql)
	i.emit(QueryEvent{
		SessionID:        snap.ID,
		Timestamp:        time.Now(),
		ClientIP:         snap.ClientIP,
		Username:         snap.Username,
		Database:         snap.Database,
		QueryRaw:         sql,
		QueryNormalized:  normalized,
		Fingerprint:      FingerprintSQL(normalized),
		ProtocolMode:     "prepared",
		QueryLength:      len(sql),
		BytesIn:          snap.BytesIn,
		BytesOut:         snap.BytesOut,
		OutcomeVerified:  outcome.Verified,
		Success:          outcome.Success,
		Authority:        outcome.Authority,
		TransactionState: outcome.TransactionState,
		ErrorCode:        outcome.ErrorCode,
	})
	sess.IncrQueryCount()
}

// InterceptStmtClose removes prepared statement tracking (COM_STMT_CLOSE).
func (i *Interceptor) InterceptStmtClose(sessID string, stmtID uint32) {
	key := stmtKey(sessID, stmtID)
	i.mu.Lock()
	delete(i.pending, key)
	i.mu.Unlock()
}

func (i *Interceptor) emit(ev QueryEvent) {
	select {
	case i.events <- ev:
	default:
		// Non-blocking drop — publisher handles back-pressure
	}
}

func stmtKey(sessID string, stmtID uint32) string {
	return fmt.Sprintf("%s:%d", sessID, stmtID)
}

// CleanTextQuery removes MySQL client-side COM_QUERY attribute bytes that some
// MySQL 8 clients prepend before the SQL text when CLIENT_QUERY_ATTRIBUTES is
// negotiated. Runtime examples look like "\x00\x01SHOW TABLES". Keeping those
// control bytes in query_raw makes dashboards noisy and can confuse downstream
// parsers, while the original wire payload is still forwarded unchanged by the
// protocol handler.
func CleanTextQuery(sql string) string {
	if sql == "" {
		return sql
	}
	cleaned := strings.TrimLeftFunc(sql, func(r rune) bool {
		return r <= ' ' && r != '\n' && r != '\r' && r != '\t'
	})
	if looksLikeSQL(cleaned) {
		return cleaned
	}
	lower := strings.ToLower(sql)
	best := -1
	keywords := []string{
		"select", "show", "with", "insert", "update", "delete", "replace",
		"create", "alter", "drop", "truncate", "describe", "desc", "explain",
		"use", "set", "call", "begin", "commit", "rollback",
	}
	for _, kw := range keywords {
		idx := strings.Index(lower, kw)
		if idx < 0 {
			continue
		}
		if best < 0 || idx < best {
			best = idx
		}
	}
	if best > 0 {
		candidate := sql[best:]
		if looksLikeSQL(candidate) {
			return candidate
		}
	}
	return cleaned
}

func looksLikeSQL(sql string) bool {
	q := strings.ToLower(strings.TrimSpace(sql))
	if q == "" {
		return false
	}
	for _, prefix := range []string{
		"select", "show", "with", "insert", "update", "delete", "replace",
		"create", "alter", "drop", "truncate", "describe", "desc", "explain",
		"use", "set", "call", "begin", "commit", "rollback",
	} {
		if strings.HasPrefix(q, prefix) {
			return true
		}
	}
	return false
}

// ─── Bounded Cache — Fix 4 ───────────────────────────────────────────────────

// boundedCache is a fixed-capacity string→string cache.
// On overflow, the entire cache clears (generation eviction).
// O(1) reads, no per-entry overhead, prevents unbounded memory growth.
type boundedCache struct {
	mu       sync.RWMutex
	m        map[string]string
	capacity int
}

func newBoundedCache(cap int) *boundedCache {
	return &boundedCache{m: make(map[string]string, cap), capacity: cap}
}

func (c *boundedCache) get(k string) (string, bool) {
	c.mu.RLock()
	v, ok := c.m[k]
	c.mu.RUnlock()
	return v, ok
}

func (c *boundedCache) set(k, v string) {
	c.mu.Lock()
	if len(c.m) >= c.capacity {
		c.m = make(map[string]string, c.capacity) // generation eviction
	}
	c.m[k] = v
	c.mu.Unlock()
}

var (
	normCache = newBoundedCache(50_000) // raw SQL → normalized
	hashCache = newBoundedCache(50_000) // normalized → fingerprint
)

// ─── SQL Normalization ────────────────────────────────────────────────────────

var (
	reNumbers     = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	reStrings     = regexp.MustCompile(`'(?:[^'\\]|\\.)*'`)
	reDblStrings  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`) // MySQL ANSI_QUOTES mode
	rePlaceholder = regexp.MustCompile(`\?`)
	reWhitespace  = regexp.MustCompile(`\s+`)
	reInList      = regexp.MustCompile(`(?i)\bIN\s*\([^)]+\)`)
	reValuesList  = regexp.MustCompile(`(?i)\bVALUES\s*\([^)]+\)`)
)

// NormalizeSQL normalizes a MySQL SQL string:
//   - Strips comments (-- line, /* block */, # MySQL-style)
//   - Replaces literals (strings, numbers, ? placeholders) with ?
//   - Collapses IN/VALUES lists to (?)
//   - Lowercases and collapses whitespace
//
// Results cached in a bounded 50k-entry cache (Fix 4).
func NormalizeSQL(sql string) string {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return ""
	}
	if v, ok := normCache.get(sql); ok {
		return v
	}
	n := doNormalize(sql)
	normCache.set(sql, n)
	return n
}

// FingerprintSQL returns a stable 16-char FNV-64a hex fingerprint.
// Cached in a bounded 50k-entry cache (Fix 4).
func FingerprintSQL(normalized string) string {
	if normalized == "" {
		return ""
	}
	if v, ok := hashCache.get(normalized); ok {
		return v
	}
	h := fnv.New64a()
	h.Write([]byte(normalized))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h.Sum64())
	fp := hex.EncodeToString(b[:])
	hashCache.set(normalized, fp)
	return fp
}

func doNormalize(sql string) string {
	s := removeComments(sql)
	s = reStrings.ReplaceAllString(s, "?")
	s = reDblStrings.ReplaceAllString(s, "?")
	s = rePlaceholder.ReplaceAllString(s, "?")
	s = reNumbers.ReplaceAllString(s, "?")
	s = reInList.ReplaceAllStringFunc(s, func(m string) string {
		idx := strings.IndexByte(m, '(')
		return m[:idx] + "(?)"
	})
	s = reValuesList.ReplaceAllStringFunc(s, func(m string) string {
		idx := strings.IndexByte(m, '(')
		return m[:idx] + "(?)"
	})
	s = reWhitespace.ReplaceAllString(s, " ")
	return strings.ToLower(strings.TrimSpace(s))
}

// removeComments strips MySQL comment styles: --, /* */, and #.
func removeComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		// /* block comment */
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			end := strings.Index(s[i+2:], "*/")
			if end >= 0 {
				i = i + 2 + end + 2
				b.WriteByte(' ')
				continue
			}
		}
		// -- line comment
		if i+1 < len(s) && s[i] == '-' && s[i+1] == '-' {
			end := strings.IndexByte(s[i:], '\n')
			if end >= 0 {
				i += end
			} else {
				break
			}
			continue
		}
		// # MySQL line comment
		if s[i] == '#' {
			end := strings.IndexByte(s[i:], '\n')
			if end >= 0 {
				i += end
			} else {
				break
			}
			continue
		}
		// Single-quoted string — leave for reStrings
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
