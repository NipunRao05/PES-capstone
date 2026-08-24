// Package session implements Layer 3: SessionTracker for MySQL proxy.
// Maintains per-connection state: auth metadata, prepared statements,
// capability flags, and byte/query counters.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Capability flags (subset used by proxy) ─────────────────────────────────

const (
	ClientLongPassword     uint32 = 1 << 0
	ClientConnectWithDB    uint32 = 1 << 3
	ClientProtocol41       uint32 = 1 << 9
	ClientSSL              uint32 = 1 << 11
	ClientTransactions     uint32 = 1 << 13
	ClientSecureConn       uint32 = 1 << 15
	ClientPluginAuth       uint32 = 1 << 19
	ClientConnectAttrs     uint32 = 1 << 20
	ClientPluginAuthLenEnc uint32 = 1 << 21
	ClientDeprecateEOF     uint32 = 1 << 24
)

// ─── Session ─────────────────────────────────────────────────────────────────

// Session holds all per-connection state for one MySQL client.
type Session struct {
	mu sync.RWMutex

	ID        string
	ClientIP  string
	Username  string
	Database  string
	StartedAt time.Time

	// MySQL-specific negotiated state
	ServerCapabilities uint32 // flags advertised by the real server
	ClientCapabilities uint32 // flags negotiated with the client
	CharSet            byte   // negotiated character set
	ConnectionID       uint32 // backend's thread/connection ID (for kill/cancel)

	// Prepared statements: stmtID (uint32) → SQL string
	PreparedStmts map[uint32]string

	// Transaction state
	InTransaction bool
	AutoCommit    bool

	// Counters — use atomic ops where hot, mutex for the rest
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
	queryCount atomic.Int64
}

// New creates a fresh session with a UUID-like random ID.
func New(remoteAddr string) *Session {
	return &Session{
		ID:            newSessionID(),
		ClientIP:      ExtractIP(remoteAddr),
		StartedAt:     time.Now(),
		AutoCommit:    true,
		PreparedStmts: make(map[uint32]string),
	}
}

// SetAuth records the username, database, and negotiated capabilities.
func (s *Session) SetAuth(username, database string, clientCaps, serverCaps uint32) {
	s.mu.Lock()
	s.Username = username
	s.Database = database
	s.ClientCapabilities = clientCaps
	s.ServerCapabilities = serverCaps
	s.mu.Unlock()
}

// SetConnectionID stores the backend's connection/thread ID.
func (s *Session) SetConnectionID(id uint32) {
	s.mu.Lock()
	s.ConnectionID = id
	s.mu.Unlock()
}

// AddPreparedStmt registers a prepared statement ID → SQL mapping.
func (s *Session) AddPreparedStmt(id uint32, sql string) {
	s.mu.Lock()
	s.PreparedStmts[id] = sql
	s.mu.Unlock()
}

// GetPreparedStmt retrieves the SQL for a prepared statement by ID.
func (s *Session) GetPreparedStmt(id uint32) (string, bool) {
	s.mu.RLock()
	sql, ok := s.PreparedStmts[id]
	s.mu.RUnlock()
	return sql, ok
}

// RemovePreparedStmt removes a prepared statement (on COM_STMT_CLOSE).
func (s *Session) RemovePreparedStmt(id uint32) {
	s.mu.Lock()
	delete(s.PreparedStmts, id)
	s.mu.Unlock()
}

// SetDatabase updates the current database (after COM_INIT_DB).
func (s *Session) SetDatabase(db string) {
	s.mu.Lock()
	s.Database = db
	s.mu.Unlock()
}

// SetAutoCommit updates the autocommit flag.
func (s *Session) SetAutoCommit(ac bool) {
	s.mu.Lock()
	s.AutoCommit = ac
	s.mu.Unlock()
}

// SetTransactionStatus records authoritative status flags returned by MySQL.
func (s *Session) SetTransactionStatus(inTransaction, autoCommit bool) {
	s.mu.Lock()
	s.InTransaction = inTransaction
	s.AutoCommit = autoCommit
	s.mu.Unlock()
}

// ClientCapabilities returns the negotiated client capability flags.
func (s *Session) GetClientCapabilities() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ClientCapabilities
}

// ServerCapabilities returns the server capability flags.
func (s *Session) GetServerCapabilities() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ServerCapabilities
}

// IncrBytesIn adds n bytes to the inbound counter.
func (s *Session) IncrBytesIn(n int64) { s.bytesIn.Add(n) }

// IncrBytesOut adds n bytes to the outbound counter.
func (s *Session) IncrBytesOut(n int64) { s.bytesOut.Add(n) }

// IncrQueryCount increments the query counter.
func (s *Session) IncrQueryCount() { s.queryCount.Add(1) }

// Snapshot returns a point-in-time read-only view of the session.
func (s *Session) Snapshot() Snapshot {
	s.mu.RLock()
	snap := Snapshot{
		ID:            s.ID,
		ClientIP:      s.ClientIP,
		Username:      s.Username,
		Database:      s.Database,
		StartedAt:     s.StartedAt,
		AutoCommit:    s.AutoCommit,
		InTransaction: s.InTransaction,
		ConnectionID:  s.ConnectionID,
	}
	s.mu.RUnlock()
	snap.BytesIn = s.bytesIn.Load()
	snap.BytesOut = s.bytesOut.Load()
	snap.QueryCount = s.queryCount.Load()
	return snap
}

// Snapshot is a point-in-time copy of session metadata.
type Snapshot struct {
	ID            string
	ClientIP      string
	Username      string
	Database      string
	StartedAt     time.Time
	AutoCommit    bool
	InTransaction bool
	ConnectionID  uint32
	BytesIn       int64
	BytesOut      int64
	QueryCount    int64
}

// ExtractIP extracts the host portion from "ip:port", "[ipv6]:port", or raw host strings.
func ExtractIP(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func newSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	// RFC 4122 version 4 + variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
