
// Package connection implements Layer 1: ConnectionManager
// Handles TLS, connection lifecycle, and goroutine-per-connection model.
//
// Fixes applied in this version:
//   - Fix 1:  CancelRequest forwarding (peek first 8 bytes to detect it)
//   - Fix 3:  Backend health checks with TCP keepalives + periodic ping
//   - Fix 6:  Graceful shutdown with configurable drain timeout
//   - Fix 8:  Metrics counters (active conns, total, errors, cancels)
//   - Fix 9:  HTTP /healthz + /metrics + /ready endpoints
//   - Fix 10: Session context attached to every log line
package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/protocol"
	"github.com/pgproxy/internal/publisher"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds all proxy configuration.
type Config struct {
	ListenAddr  string
	BackendAddr string

	TLSCertFile string
	TLSKeyFile  string

	KafkaBrokers      []string
	KafkaTopic        string
	KafkaDedupTopic   string
	KafkaSessionTopic string

	MaxConnections int
	DialTimeout    time.Duration
	IdleTimeout    time.Duration

	// Fix 6: how long to wait for in-flight conns on shutdown.
	ShutdownTimeout time.Duration

	// Fix 3: how often to probe the backend (0 = disabled).
	BackendPingInterval time.Duration

	// Fix 9: HTTP health+metrics listen addr ("" disables).
	HTTPAddr string
}

func (c *Config) setDefaults() {
	if c.MaxConnections == 0 {
		c.MaxConnections = 10000
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Minute
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.BackendPingInterval == 0 {
		c.BackendPingInterval = 15 * time.Second
	}
	if c.HTTPAddr == "" {
		c.HTTPAddr = "0.0.0.0:9090"
	}
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

// Metrics holds all observable counters. All fields are atomic.
type Metrics struct {
	ActiveConnections  atomic.Int64
	TotalConnections   atomic.Int64
	RejectedConns      atomic.Int64
	BackendDialErrors  atomic.Int64
	CancelRequests     atomic.Int64
	BackendHealthFails atomic.Int64
}

type metricsSnapshot struct {
	ActiveConnections   int64 `json:"active_connections"`
	TotalConnections    int64 `json:"total_connections"`
	RejectedConnections int64 `json:"rejected_connections"`
	BackendDialErrors   int64 `json:"backend_dial_errors"`
	CancelRequests      int64 `json:"cancel_requests"`
	BackendHealthFails  int64 `json:"backend_health_failures"`
	BackendHealthy      bool  `json:"backend_healthy"`
}

// ─── Manager ─────────────────────────────────────────────────────────────────

// Manager is the top-level connection manager.
type Manager struct {
	cfg     Config
	logger  *slog.Logger
	metrics Metrics

	listener   net.Listener
	httpServer *http.Server
	wg         sync.WaitGroup

	// Fix 3: last known backend reachability
	backendHealthy atomic.Bool

	// Phase 3: query pipeline
	intercept *interceptor.Interceptor
	pub       *publisher.Publisher
}

// NewManager creates a new connection manager.
func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
	cfg.setDefaults()
	m := &Manager{cfg: cfg, logger: logger}
	m.backendHealthy.Store(true)

	// Phase 3: boot the query interception + publishing pipeline
	m.intercept = interceptor.New(100_000)
	m.pub = publisher.New(publisher.Config{
		Brokers:      cfg.KafkaBrokers,
		Topic:        cfg.KafkaTopic,
		DedupTopic:   cfg.KafkaDedupTopic,
		SessionTopic: cfg.KafkaSessionTopic,
	}, logger)
	return m, nil
}

// ListenAndServe starts the proxy listener and blocks until ctx is cancelled.
func (m *Manager) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.cfg.ListenAddr, err)
	}
	m.listener = ln
	m.logger.Info("proxy listening", "addr", ln.Addr())

	// Fix 9: HTTP health + metrics server
	if m.cfg.HTTPAddr != "" {
		m.startHTTPServer(ctx)
	}

	// Phase 3: start the publisher goroutines
	m.pub.Start(ctx, m.intercept.Events())

	// Fix 3: backend health monitor
	go m.runBackendHealthCheck(ctx)

	// Close listener when context is cancelled
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return m.gracefulShutdown()
			default:
				m.logger.Error("accept error", "error", err)
				continue
			}
		}

		if m.metrics.ActiveConnections.Load() >= int64(m.cfg.MaxConnections) {
			m.metrics.RejectedConns.Add(1)
			m.logger.Warn("max connections reached, rejecting", "max", m.cfg.MaxConnections)
			clientConn.Close()
			continue
		}

		m.metrics.ActiveConnections.Add(1)
		m.metrics.TotalConnections.Add(1)
		m.wg.Add(1)
		go m.handleConnection(ctx, clientConn)
	}
}

// gracefulShutdown drains active connections up to ShutdownTimeout. Fix 6.
func (m *Manager) gracefulShutdown() error {
	active := m.metrics.ActiveConnections.Load()
	m.logger.Info("shutting down, draining connections",
		"active", active,
		"timeout", m.cfg.ShutdownTimeout,
	)

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("all connections drained cleanly")
	case <-time.After(m.cfg.ShutdownTimeout):
		m.logger.Warn("shutdown timeout exceeded, some connections were forcefully closed",
			"remaining", m.metrics.ActiveConnections.Load(),
		)
	}

	if m.httpServer != nil {
		hctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.httpServer.Shutdown(hctx)
	}
	return nil
}

// handleConnection manages the full lifecycle of one client connection.
func (m *Manager) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		m.metrics.ActiveConnections.Add(-1)
		m.wg.Done()
	}()

	remoteAddr := clientConn.RemoteAddr().String()
	// Fix 10: every subsequent log line from this goroutine carries the client IP
	logger := m.logger.With("client_ip", remoteAddr)
	logger.Debug("new connection")

	// Fix 1: peek 8 bytes to detect a CancelRequest before doing anything else.
	// CancelRequest is a fixed 16-byte message with a special protocol code.
	peeked, conn, err := peekConn(clientConn, 8)
	if err != nil {
		logger.Debug("failed to peek startup bytes", "error", err)
		return
	}

	if isCancelRequest(peeked) {
		m.handleCancelRequest(conn, peeked, logger)
		return
	}

	// Normal startup — dial the backend
	dialer := net.Dialer{Timeout: m.cfg.DialTimeout}
	backendConn, err := dialer.DialContext(ctx, "tcp", m.cfg.BackendAddr)
	if err != nil {
		m.metrics.BackendDialErrors.Add(1)
		// Fix 10: send a proper PG error to the client instead of silent close
		sendStartupError(conn, "proxy: cannot connect to backend: "+err.Error())
		logger.Error("failed to connect to backend",
			"backend_addr", m.cfg.BackendAddr,
			"error", err,
		)
		return
	}
	defer backendConn.Close()

	// Fix 3: TCP keepalive on both sides prevents silent dead connections
	setKeepalive(conn)
	setKeepalive(backendConn)

	handler := protocol.NewHandler(conn, backendConn, logger, m.cfg.BackendAddr, m.intercept, m.pub)

	if err := handler.Run(ctx); err != nil {
		if !isNormalDisconnect(err) {
			// Fix 10: enriched error log with session metadata
			logger.Warn("connection error",
				"session_id", handler.SessionID(),
				"username", handler.Username(),
				"database", handler.Database(),
				"error", err,
			)
		}
	}

	logger.Debug("connection finished",
		"session_id", handler.SessionID(),
		"username", handler.Username(),
		"database", handler.Database(),
	)
}

// ─── Fix 1: CancelRequest ─────────────────────────────────────────────────────

const cancelRequestCode uint32 = 80877102 // PostgreSQL cancel magic (0x04D2162E)

func isCancelRequest(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	code := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	return code == cancelRequestCode
}

// handleCancelRequest reads the full 16-byte CancelRequest and forwards it
// to the real PostgreSQL backend on a fresh TCP connection.
// Per the PG protocol: the server closes the connection immediately after receiving it.
func (m *Manager) handleCancelRequest(clientConn net.Conn, peeked []byte, logger *slog.Logger) {
	defer clientConn.Close()
	m.metrics.CancelRequests.Add(1)

	// Full message is 16 bytes: len(4) + code(4) + pid(4) + secret(4).
	// peeked already contains the first 8 bytes.
	// We must read the remaining 8 bytes from the UNDERLYING connection, not the
	// replayConn wrapper — replayConn would replay the peeked prefix again and
	// corrupt the pid/secret fields.
	rawConn := clientConn
	if rc, ok := clientConn.(*replayConn); ok {
		rawConn = rc.Conn
	}
	tail := make([]byte, 8)
	if err := readExact(rawConn, tail); err != nil {
		logger.Debug("failed to read cancel request tail", "error", err)
		return
	}

	pid := uint32(tail[0])<<24 | uint32(tail[1])<<16 | uint32(tail[2])<<8 | uint32(tail[3])
	secret := uint32(tail[4])<<24 | uint32(tail[5])<<16 | uint32(tail[6])<<8 | uint32(tail[7])

	logger.Debug("forwarding cancel request", "backend_pid", pid)

	dialer := net.Dialer{Timeout: 3 * time.Second}
	bc, err := dialer.Dial("tcp", m.cfg.BackendAddr)
	if err != nil {
		logger.Warn("cancel: failed to dial backend", "error", err)
		return
	}
	defer bc.Close()

	// Re-encode CancelRequest for the backend
	msg := make([]byte, 16)
	putUint32(msg, 0, 16)                // length field
	putUint32(msg, 4, cancelRequestCode) // cancel code
	putUint32(msg, 8, pid)
	putUint32(msg, 12, secret)

	if _, err := bc.Write(msg); err != nil {
		logger.Warn("cancel: write to backend failed", "error", err)
		return
	}
	logger.Debug("cancel request forwarded successfully", "pid", pid)
}

// ─── Fix 3: Backend Health Check ──────────────────────────────────────────────

func (m *Manager) runBackendHealthCheck(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.BackendPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkBackend()
		}
	}
}

func (m *Manager) checkBackend() {
	c, err := net.DialTimeout("tcp", m.cfg.BackendAddr, 3*time.Second)
	if err != nil {
		m.metrics.BackendHealthFails.Add(1)
		if m.backendHealthy.Swap(false) {
			m.logger.Error("backend became unreachable",
				"addr", m.cfg.BackendAddr, "error", err)
		}
		return
	}
	c.Close()
	if !m.backendHealthy.Swap(true) {
		m.logger.Info("backend is reachable again", "addr", m.cfg.BackendAddr)
	}
}

// ─── Fix 9: HTTP Server ───────────────────────────────────────────────────────

func (m *Manager) startHTTPServer(ctx context.Context) {
	mux := http.NewServeMux()

	// /healthz — 200 when backend is reachable, 503 otherwise
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		healthy := m.backendHealthy.Load()
		w.Header().Set("Content-Type", "application/json")
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"status":"unhealthy","backend":"%s"}`, m.cfg.BackendAddr)
			return
		}
		fmt.Fprintf(w, `{"status":"ok","active_connections":%d}`,
			m.metrics.ActiveConnections.Load())
	})

	// /metrics — JSON counters
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snap := metricsSnapshot{
			ActiveConnections:   m.metrics.ActiveConnections.Load(),
			TotalConnections:    m.metrics.TotalConnections.Load(),
			RejectedConnections: m.metrics.RejectedConns.Load(),
			BackendDialErrors:   m.metrics.BackendDialErrors.Load(),
			CancelRequests:      m.metrics.CancelRequests.Load(),
			BackendHealthFails:  m.metrics.BackendHealthFails.Load(),
			BackendHealthy:      m.backendHealthy.Load(),
		}
		_ = json.NewEncoder(w).Encode(snap)
	})

	// /ready — Kubernetes readiness probe (fails when at connection limit)
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if !m.backendHealthy.Load() ||
			m.metrics.ActiveConnections.Load() >= int64(m.cfg.MaxConnections) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	m.httpServer = &http.Server{
		Addr:         m.cfg.HTTPAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	m.logger.Info("HTTP health+metrics server listening", "addr", m.cfg.HTTPAddr)
	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			m.logger.Warn("HTTP server stopped", "error", err)
		}
	}()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// peekConn reads n bytes without consuming them, returning a conn that
// replays those bytes on the first Read call(s).
func peekConn(conn net.Conn, n int) ([]byte, net.Conn, error) {
	buf := make([]byte, n)
	if err := readExact(conn, buf); err != nil {
		return nil, conn, err
	}
	return buf, &replayConn{Conn: conn, buf: buf}, nil
}

// replayConn replays a peeked prefix before delegating Reads to the real conn.
type replayConn struct {
	net.Conn
	buf []byte
	pos int
}

func (r *replayConn) Read(p []byte) (int, error) {
	if r.pos < len(r.buf) {
		n := copy(p, r.buf[r.pos:])
		r.pos += n
		return n, nil
	}
	return r.Conn.Read(p)
}

// setKeepalive enables TCP keepalives to detect silent dead connections. Fix 3.
func setKeepalive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(60 * time.Second)
	}
}

// sendStartupError sends a PostgreSQL ErrorResponse to a pre-handshake client.
// Fix 10: the client sees a proper error instead of a silent connection reset.
func sendStartupError(conn net.Conn, msg string) {
	// ErrorResponse format: 'E' + int32(total_len) + 'S'+"ERROR\0" + 'M'+msg+"\0" + '\0'
	body := append([]byte{'S'}, "ERROR\x00M"...)
	body = append(body, msg...)
	body = append(body, 0, 0) // field terminator + message terminator
	pkt := make([]byte, 5+len(body))
	pkt[0] = 'E'
	putUint32(pkt, 1, uint32(4+len(body)))
	copy(pkt[5:], body)
	_, _ = conn.Write(pkt)
}

// readExact reads exactly len(buf) bytes from conn.
func readExact(conn net.Conn, buf []byte) error {
	for pos := 0; pos < len(buf); {
		n, err := conn.Read(buf[pos:])
		pos += n
		if err != nil {
			return err
		}
	}
	return nil
}

func putUint32(b []byte, offset int, v uint32) {
	b[offset] = byte(v >> 24)
	b[offset+1] = byte(v >> 16)
	b[offset+2] = byte(v >> 8)
	b[offset+3] = byte(v)
}

func isNormalDisconnect(err error) bool {
	return err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// ActiveConnections returns the current number of active connections.
func (m *Manager) ActiveConnections() int64 { return m.metrics.ActiveConnections.Load() }

// ListenAddr returns the address the proxy is actually listening on.
// Returns "" if the listener has not started yet.
func (m *Manager) ListenAddr() string {
	if m.listener == nil {
		return ""
	}
	return m.listener.Addr().String()
}

// BackendHealthy returns the last backend health probe result.
func (m *Manager) BackendHealthy() bool { return m.backendHealthy.Load() }
