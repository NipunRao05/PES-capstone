// Package connection implements Layer 1: ConnectionManager for MySQL proxy.
// All fixes from the PostgreSQL proxy are implemented:
//
//   Fix 1:  COM_PROCESS_KILL detection and forwarding (MySQL's CancelRequest equivalent)
//   Fix 2:  LOCAL INFILE streaming (handled in protocol layer)
//   Fix 3:  Backend health checks (periodic TCP ping + TCP keepalives)
//   Fix 4:  Bounded caches (implemented in interceptor layer)
//   Fix 5:  Session state cleanup on disconnect (interceptor.CleanupSession)
//   Fix 6:  Graceful shutdown with configurable drain timeout
//   Fix 8:  Metrics counters (active, total, rejected, errors, kills)
//   Fix 9:  HTTP /healthz + /metrics + /ready endpoints
//   Fix 10: Session context (client IP, session ID, username) on every log line
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

	"github.com/mysqlproxy/internal/interceptor"
	"github.com/mysqlproxy/internal/protocol"
	"github.com/mysqlproxy/internal/publisher"
	"github.com/mysqlproxy/internal/session"
)

// ─── Config ───────────────────────────────────────────────────────────────────

// Config holds all proxy configuration.
type Config struct {
	ListenAddr  string
	BackendAddr string

	MaxConnections int
	DialTimeout    time.Duration
	IdleTimeout    time.Duration

	// Fix 6: how long to wait for in-flight connections to finish on shutdown.
	ShutdownTimeout time.Duration

	// Fix 3: how often to probe the backend. 0 = disabled.
	BackendPingInterval time.Duration

	// Fix 9: HTTP health+metrics address. "" = disabled.
	HTTPAddr string

	// Phase 3: Kafka
	KafkaBrokers []string
	KafkaTopic        string
	KafkaDedupTopic   string
	KafkaSessionTopic string
}

func (c *Config) setDefaults() {
	if c.MaxConnections == 0 {
		c.MaxConnections = 10_000
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
		c.HTTPAddr = "0.0.0.0:9091" // 9091 to avoid clash with PG proxy on 9090
	}
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

// Metrics holds all observable counters (all atomic, no locking needed).
type Metrics struct {
	ActiveConnections  atomic.Int64
	TotalConnections   atomic.Int64
	RejectedConns      atomic.Int64
	BackendDialErrors  atomic.Int64
	KillRequests       atomic.Int64 // COM_PROCESS_KILL forwarded
	BackendHealthFails atomic.Int64
}

type metricsSnapshot struct {
	ActiveConnections   int64 `json:"active_connections"`
	TotalConnections    int64 `json:"total_connections"`
	RejectedConnections int64 `json:"rejected_connections"`
	BackendDialErrors   int64 `json:"backend_dial_errors"`
	KillRequests        int64 `json:"kill_requests"`
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

	backendHealthy atomic.Bool // Fix 3

	// Phase 3: query pipeline
	intercept *interceptor.Interceptor
	pub       *publisher.Publisher
}

// NewManager creates a new Manager.
func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
	cfg.setDefaults()
	m := &Manager{cfg: cfg, logger: logger}
	m.backendHealthy.Store(true)

	// Phase 3: boot query interception + publishing pipeline
	m.intercept = interceptor.New(100_000)
	m.pub = publisher.New(publisher.Config{
		Brokers:      cfg.KafkaBrokers,
		Topic:        cfg.KafkaTopic,
		DedupTopic:   cfg.KafkaDedupTopic,
		SessionTopic: cfg.KafkaSessionTopic,
	}, logger)
	return m, nil
}

// ListenAndServe starts the proxy and blocks until ctx is cancelled.
func (m *Manager) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.cfg.ListenAddr, err)
	}
	m.listener = ln
	m.logger.Info("mysql proxy listening", "addr", ln.Addr())

	// Fix 9: HTTP health + metrics server
	if m.cfg.HTTPAddr != "" {
		m.startHTTPServer(ctx)
	}

	// Phase 3: start publisher goroutines
	m.pub.Start(ctx, m.intercept.Events())

	// Fix 3: backend health monitor
	go m.runBackendHealthCheck(ctx)

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
			// For MySQL, send an ERR packet before closing so the client gets
			// a proper message instead of a silent connection reset.
			sendStartupError(clientConn, 1040, "HY000", "Too many connections")
			clientConn.Close()
			continue
		}

		m.metrics.ActiveConnections.Add(1)
		m.metrics.TotalConnections.Add(1)
		m.wg.Add(1)
		go m.handleConnection(ctx, clientConn)
	}
}

// gracefulShutdown waits up to ShutdownTimeout for in-flight connections. Fix 6.
func (m *Manager) gracefulShutdown() error {
	m.logger.Info("shutting down, draining connections",
		"active", m.metrics.ActiveConnections.Load(),
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
		m.logger.Warn("shutdown timeout exceeded, forcing close",
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

// handleConnection manages one client connection.
func (m *Manager) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		m.metrics.ActiveConnections.Add(-1)
		m.wg.Done()
	}()

	remoteAddr := clientConn.RemoteAddr().String()
	// Fix 10: every log line from this goroutine carries the client IP
	logger := m.logger.With("client_ip", session.ExtractIP(remoteAddr))
	logger.Debug("new connection")

	// Dial the real MySQL backend
	dialer := net.Dialer{Timeout: m.cfg.DialTimeout}
	backendConn, err := dialer.DialContext(ctx, "tcp", m.cfg.BackendAddr)
	if err != nil {
		m.metrics.BackendDialErrors.Add(1)
		// Fix 10: send a proper MySQL ERR to the client instead of silent close
		sendStartupError(clientConn, 2003, "HY000",
			fmt.Sprintf("proxy: can't connect to backend (%s)", err.Error()))
		logger.Error("failed to connect to backend",
			"backend_addr", m.cfg.BackendAddr,
			"error", err,
		)
		return
	}
	defer backendConn.Close()

	// Fix 3: TCP keepalives on both sides
	setKeepalive(clientConn)
	setKeepalive(backendConn)

	handler := protocol.NewHandler(clientConn, backendConn, logger, m.cfg.BackendAddr, m.cfg.IdleTimeout, m.intercept, m.pub)

	if err := handler.Run(ctx); err != nil {
		if !isNormalDisconnect(err) {
			// Fix 10: enriched error log with all available session context
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
			m.logger.Error("mysql backend became unreachable",
				"addr", m.cfg.BackendAddr, "error", err)
		}
		return
	}
	c.Close()
	if !m.backendHealthy.Swap(true) {
		m.logger.Info("mysql backend is reachable again", "addr", m.cfg.BackendAddr)
	}
}

// ─── Fix 9: HTTP Server ───────────────────────────────────────────────────────

func (m *Manager) startHTTPServer(ctx context.Context) {
	mux := http.NewServeMux()

	// /healthz — 200 OK when backend is reachable, 503 when not
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

	// /metrics — JSON snapshot of all counters
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		snap := metricsSnapshot{
			ActiveConnections:   m.metrics.ActiveConnections.Load(),
			TotalConnections:    m.metrics.TotalConnections.Load(),
			RejectedConnections: m.metrics.RejectedConns.Load(),
			BackendDialErrors:   m.metrics.BackendDialErrors.Load(),
			KillRequests:        m.metrics.KillRequests.Load(),
			BackendHealthFails:  m.metrics.BackendHealthFails.Load(),
			BackendHealthy:      m.backendHealthy.Load(),
		}
		_ = json.NewEncoder(w).Encode(snap)
	})

	// /ready — Kubernetes readiness probe
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

// sendStartupError sends a MySQL ERR packet to a client before the handshake
// completes. Used when we can't reach the backend. Fix 10.
func sendStartupError(conn net.Conn, errCode uint16, sqlState, message string) {
	if sqlState == "" {
		sqlState = "HY000"
	}
	ss := fmt.Sprintf("%-5.5s", sqlState)
	body := make([]byte, 0, 9+len(message))
	body = append(body, 0xFF)
	body = append(body, byte(errCode), byte(errCode>>8))
	body = append(body, '#')
	body = append(body, ss...)
	body = append(body, message...)

	pkt := make([]byte, 4+len(body))
	pkt[0] = byte(len(body))
	pkt[1] = byte(len(body) >> 8)
	pkt[2] = byte(len(body) >> 16)
	pkt[3] = 0 // sequence 0
	copy(pkt[4:], body)
	_, _ = conn.Write(pkt)
}

// setKeepalive enables TCP keepalives. Fix 3.
func setKeepalive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(60 * time.Second)
	}
}

func isNormalDisconnect(err error) bool {
	return err == nil ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// ActiveConnections returns the current live connection count.
func (m *Manager) ActiveConnections() int64 { return m.metrics.ActiveConnections.Load() }

// BackendHealthy returns the last health probe result.
func (m *Manager) BackendHealthy() bool { return m.backendHealthy.Load() }