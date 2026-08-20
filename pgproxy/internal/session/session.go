// Package session implements Layer 3: SessionTracker
// Maintains in-memory state for a single PostgreSQL session.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// Session holds all metadata for one client connection.
type Session struct {
	mu sync.RWMutex

	ID        string
	ClientIP  string
	Username  string
	Database  string
	AppName   string
	StartedAt time.Time

	// Backend key for CancelRequest
	BackendPID    uint32
	BackendSecret uint32

	// Transaction state ('I'=idle, 'T'=in-transaction, 'E'=error)
	TxStatus byte

	// Server-reported parameters (TimeZone, client_encoding, etc.)
	Parameters map[string]string

	// Extended query state
	PreparedStatements map[string]*PreparedStatement
	Portals            map[string]*Portal

	// Counters
	BytesIn    int64
	BytesOut   int64
	QueryCount int64
}

// PreparedStatement tracks a named prepared statement.
type PreparedStatement struct {
	Name      string
	Query     string
	CreatedAt time.Time
}

// Portal tracks a named portal (bound prepared statement).
type Portal struct {
	Name              string
	PreparedStatement string
	Parameters        [][]byte
	CreatedAt         time.Time
}

// NewFromStartup creates a Session from the client's startup message.
func NewFromStartup(msg *pgproto3.StartupMessage, remoteAddr string) *Session {
	s := &Session{
		ID:                 newSessionID(),
		ClientIP:           extractIP(remoteAddr),
		StartedAt:          time.Now(),
		TxStatus:           'I',
		Parameters:         make(map[string]string),
		PreparedStatements: make(map[string]*PreparedStatement),
		Portals:            make(map[string]*Portal),
	}

	if msg != nil {
		s.Username = msg.Parameters["user"]
		s.Database = msg.Parameters["database"]
		s.AppName = msg.Parameters["application_name"]
	}

	return s
}

// SetParameter updates a server parameter.
func (s *Session) SetParameter(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Parameters[name] = value
}

// SetBackendKeyData stores the backend PID and secret key.
func (s *Session) SetBackendKeyData(pid, secret uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BackendPID = pid
	s.BackendSecret = secret
}

// SetTxStatus updates the transaction status byte.
func (s *Session) SetTxStatus(status byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TxStatus = status
}

// AddPreparedStatement registers a new prepared statement.
func (s *Session) AddPreparedStatement(name, query string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PreparedStatements[name] = &PreparedStatement{
		Name:      name,
		Query:     query,
		CreatedAt: time.Now(),
	}
}

// GetPreparedStatement retrieves a prepared statement by name.
func (s *Session) GetPreparedStatement(name string) (*PreparedStatement, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.PreparedStatements[name]
	return ps, ok
}

// AddPortal registers a new portal.
func (s *Session) AddPortal(portalName, stmtName string, params [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Portals[portalName] = &Portal{
		Name:              portalName,
		PreparedStatement: stmtName,
		Parameters:        params,
		CreatedAt:         time.Now(),
	}
}

// RemovePreparedStatement removes a named prepared statement (on Close).
func (s *Session) RemovePreparedStatement(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.PreparedStatements, name)
}

// RemovePortal removes a named portal (on Close).
func (s *Session) RemovePortal(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Portals, name)
}

// IncrBytesIn atomically adds n to the bytes-in counter.
func (s *Session) IncrBytesIn(n int64) {
	s.mu.Lock()
	s.BytesIn += n
	s.mu.Unlock()
}

// IncrBytesOut atomically adds n to the bytes-out counter.
func (s *Session) IncrBytesOut(n int64) {
	s.mu.Lock()
	s.BytesOut += n
	s.mu.Unlock()
}

// IncrQueryCount increments the query counter.
func (s *Session) IncrQueryCount() {
	s.mu.Lock()
	s.QueryCount++
	s.mu.Unlock()
}

// Snapshot returns a read-only copy of the session metadata (safe to pass around).
func (s *Session) Snapshot() SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return SessionSnapshot{
		ID:         s.ID,
		ClientIP:   s.ClientIP,
		Username:   s.Username,
		Database:   s.Database,
		AppName:    s.AppName,
		StartedAt:  s.StartedAt,
		TxStatus:   s.TxStatus,
		BytesIn:    s.BytesIn,
		BytesOut:   s.BytesOut,
		QueryCount: s.QueryCount,
	}
}

// SessionSnapshot is a point-in-time copy of session metadata.
type SessionSnapshot struct {
	ID         string
	ClientIP   string
	Username   string
	Database   string
	AppName    string
	StartedAt  time.Time
	TxStatus   byte
	BytesIn    int64
	BytesOut   int64
	QueryCount int64
}

func extractIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(remoteAddr, "[]")
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

// New creates a Session with known username and database (used when startup
// was parsed at raw-bytes level rather than via pgproto3.StartupMessage).
func New(remoteAddr, username, database string) *Session {
	return &Session{
		ID:                 newSessionID(),
		ClientIP:           extractIP(remoteAddr),
		Username:           username,
		Database:           database,
		StartedAt:          time.Now(),
		TxStatus:           'I',
		Parameters:         make(map[string]string),
		PreparedStatements: make(map[string]*PreparedStatement),
		Portals:            make(map[string]*Portal),
	}
}
