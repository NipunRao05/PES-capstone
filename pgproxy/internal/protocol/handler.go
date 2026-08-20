// Package protocol implements Layer 2: ProtocolParser
// Transparent PostgreSQL wire protocol proxy.
// Startup and auth are handled at raw-bytes level to avoid pgproto3 buffer
// conflicts. The main proxy loop uses pgproto3 for structured message handling.
package protocol

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/publisher"
	"github.com/pgproxy/internal/session"
	"github.com/pgproxy/internal/shaper"
)

// Handler manages the protocol conversation between one client and one backend.
type Handler struct {
	clientConn  net.Conn
	backendConn net.Conn
	logger      *slog.Logger
	backendAddr string

	// pgproto3 wrappers — initialised AFTER the raw startup exchange completes
	clientBackend   *pgproto3.Backend
	backendFrontend *pgproto3.Frontend

	sess *session.Session

	shaper    *shaper.Shaper
	intercept *interceptor.Interceptor
	pub       *publisher.Publisher

	// auth metadata captured during handshake
	authMethod string
}

// NewHandler constructs a protocol handler.
func NewHandler(clientConn, backendConn net.Conn, logger *slog.Logger, backendAddr string,
	intercept *interceptor.Interceptor, pub *publisher.Publisher) *Handler {
	return &Handler{
		clientConn:  clientConn,
		backendConn: backendConn,
		logger:      logger,
		backendAddr: backendAddr,
		shaper:      shaper.New(shaper.Config{}, logger),
		intercept:   intercept,
		pub:         pub,
	}
}

// Run orchestrates the full connection lifecycle.
func (h *Handler) Run(ctx context.Context) error {
	startTime := time.Now()
	closeReason := "clean"

	defer func() {
		if h.sess != nil {
			if h.intercept != nil {
				h.intercept.CleanupSession(h.sess.ID)
			}
			if h.pub != nil {
				snap := h.sess.Snapshot()
				h.pub.EmitSessionEnd(publisher.SessionEndEvent{
					EventType:   "session_end",
					SessionID:   snap.ID,
					Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
					ClientIP:    snap.ClientIP,
					Username:    snap.Username,
					Database:    snap.Database,
					DurationMs:  time.Since(startTime).Milliseconds(),
					QueryCount:  snap.QueryCount,
					BytesIn:     snap.BytesIn,
					BytesOut:    snap.BytesOut,
					CloseReason: closeReason,
				})
			}
		}
	}()

	if err := h.handleStartup(); err != nil {
		closeReason = "error"
		return fmt.Errorf("startup: %w", err)
	}

	// Emit session_start after successful auth
	if h.pub != nil && h.sess != nil {
		snap := h.sess.Snapshot()
		h.pub.EmitSessionStart(publisher.SessionStartEvent{
			EventType:  "session_start",
			SessionID:  snap.ID,
			Timestamp:  snap.StartedAt.UTC().Format(time.RFC3339Nano),
			ClientIP:   snap.ClientIP,
			Username:   snap.Username,
			Database:   snap.Database,
			AppName:    snap.AppName,
			AuthMethod: h.authMethod,
		})
	}

	if err := h.proxyLoop(ctx); err != nil {
		closeReason = "error"
		return err
	}
	return nil
}

// ─── Startup ─────────────────────────────────────────────────────────────────
//
// The PostgreSQL startup sequence at the raw bytes level:
//
//  Client → Proxy:   [optional SSLRequest] then StartupMessage
//  Proxy  → Client:  [optional 'N' for no-SSL] (we never upgrade client SSL)
//  Proxy  → Backend: SSLRequest (we try SSL to backend; accept N or S)
//  Proxy  → Backend: StartupMessage (forwarded verbatim)
//  Backend→ Proxy:   auth messages (forwarded raw until ReadyForQuery)
//  Proxy  → Client:  all auth messages forwarded raw
//
// Everything is handled at raw []byte level here so there is no state mismatch
// between what we read manually and what pgproto3's ChunkReader buffered.

const (
	sslRequestCode    = 80877103 // 0x04D2162F — SSLRequest magic
	gssRequestCode    = 80877104 // 0x04D2162E — GSSENCRequest magic
	cancelRequestCode = 80877102 // 0x04D2162E — CancelRequest (handled by manager)
)

const maxDeceptionDecisionSQLBytes = 64 * 1024

// pgDeceptionBreaker is process-wide, not connection-local.
// psql -c creates a new TCP connection per command, so per-Handler failure
// counters reset too often and the breaker never opens during outages.
var pgDeceptionBreaker = struct {
	sync.Mutex
	failures  int
	openUntil time.Time
}{}

// handleStartup performs the raw-bytes startup exchange then initialises
// the pgproto3 wrappers for the main proxy loop.
func (h *Handler) handleStartup() error {
	// ── Step 1: read the client's first message ──────────────────────────────
	// PostgreSQL startup messages: 4-byte length + 4-byte version/code + payload
	startupRaw, err := h.readRawMsg(h.clientConn)
	if err != nil {
		return fmt.Errorf("read client startup: %w", err)
	}

	if len(startupRaw) < 8 {
		return fmt.Errorf("startup message too short: %d bytes", len(startupRaw))
	}

	code := binary.BigEndian.Uint32(startupRaw[4:8])

	// If client sent SSLRequest or GSSENCRequest, decline with 'N'
	if code == sslRequestCode || code == gssRequestCode {
		if _, err := h.clientConn.Write([]byte{'N'}); err != nil {
			return fmt.Errorf("send ssl/gss decline: %w", err)
		}
		// Read the real StartupMessage that follows
		startupRaw, err = h.readRawMsg(h.clientConn)
		if err != nil {
			return fmt.Errorf("read startup after ssl decline: %w", err)
		}
		if len(startupRaw) < 8 {
			return fmt.Errorf("startup message too short after ssl decline")
		}
		code = binary.BigEndian.Uint32(startupRaw[4:8])
	}

	// code should now be protocol version 3.0 (196608 = 0x00030000)
	if code != 196608 {
		return fmt.Errorf("unexpected startup code: %d (expected 196608 for protocol 3.0)", code)
	}

	// Parse username and database from startup parameters for session metadata
	username, database := parseStartupParams(startupRaw[8:])
	h.sess = session.New(h.clientConn.RemoteAddr().String(), username, database)
	h.logger = h.logger.With("username", username, "database", database, "session_id", h.sess.ID)
	h.logger.Debug("startup received", "params_len", len(startupRaw)-8)

	// ── Step 2: negotiate SSL with backend, then send startup verbatim ───────
	if err := h.connectToBackend(startupRaw); err != nil {
		return fmt.Errorf("backend connect: %w", err)
	}

	// ── Step 3: relay auth exchange raw until ReadyForQuery ──────────────────
	if err := h.relayAuthRaw(); err != nil {
		return fmt.Errorf("auth relay: %w", err)
	}

	// ── Step 4: init pgproto3 wrappers for the main proxy loop ───────────────
	// Both connections are now in "normal query" mode. pgproto3 wrappers take
	// over from here. No bytes have been left in any buffer by the raw exchange.
	h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(h.clientConn), h.clientConn)
	h.backendFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(h.backendConn), h.backendConn)

	h.logger.Debug("session established")
	return nil
}

// connectToBackend forwards the client's original StartupMessage verbatim.
// MVP intentionally uses plain backend TCP. Do not send SSLRequest unless this
// function is extended to wrap h.backendConn with tls.Client after an 'S' reply.
func (h *Handler) connectToBackend(startupRaw []byte) error {
	if _, err := h.backendConn.Write(startupRaw); err != nil {
		return fmt.Errorf("forward startup to backend: %w", err)
	}
	return nil
}

// relayAuthRaw forwards raw PostgreSQL messages backend→client and client→backend
// until the backend sends ReadyForQuery ('Z' message type).
//
// PostgreSQL AuthenticationRequest messages all have type byte 'R' but differ
// by a 4-byte sub-type in the payload:
//
//	 0  = AuthenticationOk          — no client response needed
//	 2  = AuthenticationKerberos    — no client response needed
//	 3  = AuthenticationCleartextPassword — client sends PasswordMessage
//	 5  = AuthenticationMD5Password       — client sends PasswordMessage
//	 7  = AuthenticationGSS               — client sends GSSResponse
//	 8  = AuthenticationGSSContinue       — client sends GSSResponse
//	 9  = AuthenticationSSPI              — client sends GSSResponse
//	10  = AuthenticationSASL             — client sends SASLInitialResponse
//	11  = AuthenticationSASLContinue     — client sends SASLResponse
//	12  = AuthenticationSASLFinal        — NO client response (server final msg)
//
// We must only read a client response for sub-types that require one.
func (h *Handler) relayAuthRaw() error {
	for {
		// Read one message from backend
		msg, err := h.readRawPGMsg(h.backendConn)
		if err != nil {
			return fmt.Errorf("read backend auth msg: %w", err)
		}

		// Forward to client
		if _, err := h.clientConn.Write(msg); err != nil {
			return fmt.Errorf("forward auth msg to client: %w", err)
		}

		if len(msg) == 0 {
			continue
		}

		msgType := msg[0]
		h.logger.Debug("auth relay", "type", string([]byte{msgType}))

		switch msgType {
		case 'Z': // ReadyForQuery — auth succeeded
			// Emit successful auth event
			if h.pub != nil && h.sess != nil {
				h.pub.EmitAuth(publisher.AuthEvent{
					EventType:  "auth",
					SessionID:  h.sess.ID,
					Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
					ClientIP:   h.sess.ClientIP,
					Username:   h.sess.Username,
					Database:   h.sess.Database,
					AuthMethod: h.authMethod,
					Success:    true,
				})
			}
			return nil

		case 'E': // ErrorResponse — auth failed
			// Emit failed auth event before returning error
			if h.pub != nil && h.sess != nil {
				h.pub.EmitAuth(publisher.AuthEvent{
					EventType:  "auth",
					SessionID:  h.sess.ID,
					Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
					ClientIP:   h.sess.ClientIP,
					Username:   h.sess.Username,
					Database:   h.sess.Database,
					AuthMethod: h.authMethod,
					Success:    false,
					FailReason: "backend rejected credentials",
				})
			}
			return fmt.Errorf("backend rejected auth")

		case 'R': // AuthenticationRequest — check sub-type
			// msg layout: type(1) + length(4) + subtype(4) + optional payload
			if len(msg) < 9 {
				return fmt.Errorf("auth message too short: %d bytes", len(msg))
			}
			subtype := binary.BigEndian.Uint32(msg[5:9])
			h.logger.Debug("auth subtype", "subtype", subtype)

			// Capture auth method from first real auth challenge
			if h.authMethod == "" || h.authMethod == "unknown" {
				switch subtype {
				case 3:
					h.authMethod = "cleartext"
				case 5:
					h.authMethod = "md5"
				case 10:
					h.authMethod = "scram-sha-256"
				case 7, 8, 9:
					h.authMethod = "gss"
				default:
					h.authMethod = "unknown"
				}
			}

			switch subtype {
			case 0: // AuthenticationOk — no client response, keep looping for RFQ
				continue
			case 12: // AuthenticationSASLFinal — server sends final SCRAM msg, no client response
				continue
			case 2, 6: // Kerberos/SCM — rare, no client response
				continue
			default:
				// All other sub-types require the client to send a response.
				clientResp, err := h.readRawPGMsg(h.clientConn)
				if err != nil {
					return fmt.Errorf("read client auth response: %w", err)
				}
				if _, err := h.backendConn.Write(clientResp); err != nil {
					return fmt.Errorf("forward client auth to backend: %w", err)
				}
			}

			// 'S' = ParameterStatus, 'K' = BackendKeyData — forwarded above, keep looping
		}
	}
}

// ─── Raw message I/O ──────────────────────────────────────────────────────────

// readRawMsg reads a complete PostgreSQL startup-format message (length-prefixed,
// no type byte). Used only during startup before the type-byte protocol begins.
// Format: int32 length (includes itself) + payload
func (h *Handler) readRawMsg(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(lenBuf))
	if length < 4 || length > 10*1024*1024 {
		return nil, fmt.Errorf("invalid startup message length: %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	full := make([]byte, length)
	copy(full[:4], lenBuf)
	copy(full[4:], payload)
	return full, nil
}

// readRawPGMsg reads a complete PostgreSQL normal-protocol message.
// Format: type byte (1) + int32 length (includes itself but not type) + payload
func (h *Handler) readRawPGMsg(conn net.Conn) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:5]))
	if length < 4 || length > 256*1024*1024 {
		return nil, fmt.Errorf("invalid message length: %d (type='%c')", length, header[0])
	}
	payloadLen := length - 4
	full := make([]byte, 5+payloadLen)
	copy(full[:5], header)
	if payloadLen > 0 {
		if _, err := io.ReadFull(conn, full[5:]); err != nil {
			return nil, err
		}
	}
	return full, nil
}

// parseStartupParams extracts username and database from the null-terminated
// key=value pairs in the startup message parameter block.
func parseStartupParams(params []byte) (username, database string) {
	for len(params) > 0 {
		// read key
		end := indexNull(params)
		if end < 0 {
			break
		}
		key := string(params[:end])
		params = params[end+1:]
		// read value
		end = indexNull(params)
		if end < 0 {
			break
		}
		val := string(params[:end])
		params = params[end+1:]
		switch key {
		case "user":
			username = val
		case "database":
			database = val
		}
	}
	return
}

func indexNull(b []byte) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return -1
}

// ─── Main proxy loop ──────────────────────────────────────────────────────────

// proxyLoop is the main bidirectional message pump.
func (h *Handler) proxyLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		clientMsg, err := h.clientBackend.Receive()
		if err != nil {
			if isEOF(err) {
				return nil
			}
			return fmt.Errorf("receive client message: %w", err)
		}

		h.logger.Debug("client→proxy", "type", fmt.Sprintf("%T", clientMsg))

		// Phase 3: intercept SQL and emit to publisher via interceptor's internal channel
		var fingerprint string
		if h.intercept != nil {
			switch m := clientMsg.(type) {
			case *pgproto3.Query:
				h.intercept.InterceptSimple(h.sess, m.String)
			case *pgproto3.Parse:
				h.intercept.InterceptParse(h.sess, m.Name, m.Query)
			case *pgproto3.Bind:
				h.intercept.InterceptBind(h.sess, m.PreparedStatement, m.DestinationPortal, m.Parameters)
			case *pgproto3.Execute:
				h.intercept.InterceptExecute(h.sess, m.Portal, m.MaxRows)
			}
		}
		shapingDecision := h.shaper.Decide(fingerprint)
		shapeCtx := shaper.NewShapeContext(shapingDecision)

		if shapingDecision.ShouldBlock {
			errResp := shapeCtx.BlockResponse()
			if err := h.sendToClient(errResp); err != nil {
				return fmt.Errorf("send block response: %w", err)
			}
			if needsReadyForQuery(clientMsg) {
				rfq := &pgproto3.ReadyForQuery{TxStatus: h.sess.TxStatus}
				if err := h.sendToClient(rfq); err != nil {
					return fmt.Errorf("send rfq after block: %w", err)
				}
			}
			continue
		}

		// Synchronous deception-engine response synthesis.
		// If /decide returns mode=fake, build a PostgreSQL result set here and do not
		// forward the query to the real backend. If /decide is unavailable or returns
		// passthrough, the proxy falls back to the native trap path or backend forwarding.
		if q, ok := clientMsg.(*pgproto3.Query); ok {
			if dec, ok := h.decideWithDeceptionEngine(ctx, q.String, "postgres"); ok {
				h.logger.Info(
					"serving deception-engine fake result",
					"protocol", "postgres",
					"profile", dec.Profile,
					"columns", dec.Columns,
					"rows", len(dec.Rows),
					"query", truncateSQL(q.String, 300),
				)
				if err := h.sendPostgresDeceptionResult(dec, q.String); err != nil {
					return fmt.Errorf("send deception-engine fake result: %w", err)
				}
				continue
			}
		}

		// Trap-table deception fallback: publish telemetry above, then return fake rows
		// directly to the client without forwarding the query to the real backend.
		if q, ok := clientMsg.(*pgproto3.Query); ok && isTrapTableReference(q.String) {
			h.logger.Info(
				"serving proxy-native fake trap result",
				"protocol", "postgres",
				"profile", "proxy_native_trap",
				"query", truncateSQL(q.String, 200),
			)
			if err := h.sendPostgresTrapResponse(q.String); err != nil {
				h.logger.Error("failed to send postgres fake trap response", "err", err)
				return fmt.Errorf("send fake trap response: %w", err)
			}
			continue
		}

		if err := h.sendToBackend(clientMsg); err != nil {
			return fmt.Errorf("forward to backend: %w", err)
		}

		if err := h.drainBackendResponses(ctx, clientMsg, shapeCtx); err != nil {
			if isEOF(err) {
				return nil
			}
			return fmt.Errorf("drain backend: %w", err)
		}

		if _, ok := clientMsg.(*pgproto3.Terminate); ok {
			return nil
		}
	}
}

// drainBackendResponses reads all backend messages for one client command.
func (h *Handler) drainBackendResponses(ctx context.Context, trigger pgproto3.FrontendMessage, shapeCtx *shaper.ShapeContext) error {
	needsRFQ := needsReadyForQuery(trigger)
	latencyApplied := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := h.backendFrontend.Receive()
		if err != nil {
			return fmt.Errorf("receive backend: %w", err)
		}

		h.logger.Debug("backend→proxy", "type", fmt.Sprintf("%T", msg))

		// Fix 2: COPY protocol
		switch m := msg.(type) {
		case *pgproto3.CopyOutResponse:
			if err := h.sendToClient(m); err != nil {
				return fmt.Errorf("copy-out response: %w", err)
			}
			if err := h.handleCopyOut(ctx); err != nil {
				return fmt.Errorf("copy-out stream: %w", err)
			}
			continue
		case *pgproto3.CopyInResponse:
			if err := h.sendToClient(m); err != nil {
				return fmt.Errorf("copy-in response: %w", err)
			}
			if err := h.handleCopyIn(ctx); err != nil {
				return fmt.Errorf("copy-in stream: %w", err)
			}
			continue
		case *pgproto3.CopyBothResponse:
			if err := h.sendToClient(m); err != nil {
				return fmt.Errorf("copy-both response: %w", err)
			}
			if err := h.handleCopyBoth(ctx); err != nil {
				return fmt.Errorf("copy-both stream: %w", err)
			}
			continue
		}

		// Layer 6: latency injection
		if !latencyApplied {
			switch msg.(type) {
			case *pgproto3.RowDescription, *pgproto3.DataRow, *pgproto3.CommandComplete:
				shapeCtx.ApplyLatency()
				latencyApplied = true
			}
		}

		// Layer 6: row limiting
		if _, ok := msg.(*pgproto3.DataRow); ok {
			if !shapeCtx.FilterRow() {
				continue
			}
		}
		if _, ok := msg.(*pgproto3.CommandComplete); ok {
			if notice := shapeCtx.TruncationNotice(); notice != nil {
				if err := h.sendToClient(notice); err != nil {
					return fmt.Errorf("send truncation notice: %w", err)
				}
			}
		}

		if err := h.sendToClient(msg); err != nil {
			return fmt.Errorf("send to client: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.ReadyForQuery:
			h.sess.SetTxStatus(m.TxStatus)
			return nil
		case *pgproto3.ErrorResponse:
			h.logger.Debug("backend error response", "msg", m.Message)
			if !needsRFQ {
				return nil
			}
		}

		if !needsRFQ {
			switch msg.(type) {
			case *pgproto3.ParseComplete,
				*pgproto3.BindComplete,
				*pgproto3.CloseComplete,
				*pgproto3.NoData,
				*pgproto3.ParameterDescription,
				*pgproto3.RowDescription:
				return nil
			}
		}
	}
}

// ─── COPY protocol handlers (Fix 2) ──────────────────────────────────────────

func (h *Handler) handleCopyOut(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msg, err := h.backendFrontend.Receive()
		if err != nil {
			return fmt.Errorf("copy-out receive: %w", err)
		}
		if err := h.sendToClient(msg); err != nil {
			return fmt.Errorf("copy-out forward: %w", err)
		}
		switch msg.(type) {
		case *pgproto3.CopyDone, *pgproto3.ErrorResponse:
			return nil
		}
	}
}

func (h *Handler) handleCopyIn(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			_ = h.sendToBackend(&pgproto3.CopyFail{Message: "proxy shutdown"})
			return ctx.Err()
		default:
		}
		msg, err := h.clientBackend.Receive()
		if err != nil {
			return fmt.Errorf("copy-in receive: %w", err)
		}
		if err := h.sendToBackend(msg); err != nil {
			return fmt.Errorf("copy-in forward: %w", err)
		}
		switch msg.(type) {
		case *pgproto3.CopyDone, *pgproto3.CopyFail:
			return nil
		}
	}
}

func (h *Handler) handleCopyBoth(ctx context.Context) error {
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)

	go func() {
		for {
			select {
			case <-copyCtx.Done():
				errs <- nil
				return
			default:
			}
			msg, err := h.backendFrontend.Receive()
			if err != nil {
				errs <- fmt.Errorf("copy-both backend recv: %w", err)
				return
			}
			if err := h.sendToClient(msg); err != nil {
				errs <- fmt.Errorf("copy-both client send: %w", err)
				return
			}
			if _, ok := msg.(*pgproto3.CopyDone); ok {
				errs <- nil
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case <-copyCtx.Done():
				errs <- nil
				return
			default:
			}
			msg, err := h.clientBackend.Receive()
			if err != nil {
				errs <- fmt.Errorf("copy-both client recv: %w", err)
				return
			}
			if err := h.sendToBackend(msg); err != nil {
				errs <- fmt.Errorf("copy-both backend send: %w", err)
				return
			}
			if _, ok := msg.(*pgproto3.CopyDone); ok {
				errs <- nil
				return
			}
		}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

// ─── Deception-engine integration ────────────────────────────────────────────

type deceptionDecisionRequest struct {
	SessionID       string  `json:"session_id"`
	QueryNormalized string  `json:"query_normalized"`
	Fingerprint     string  `json:"fingerprint"`
	EventType       string  `json:"event_type"`
	Phase           string  `json:"phase"`
	Username        string  `json:"username"`
	Database        string  `json:"database"`
	Protocol        string  `json:"protocol"`
	Table           string  `json:"table"`
	DeceptionLevel  int     `json:"deception_level"`
	RiskScore       float64 `json:"risk_score"`
}

type deceptionDecisionResponse struct {
	Mode        string                   `json:"mode"`
	Rows        []map[string]interface{} `json:"rows"`
	Count       *int                     `json:"count"`
	Columns     []string                 `json:"columns"`
	Tables      []string                 `json:"tables"`
	Databases   []string                 `json:"databases"`
	LatencyMS   int                      `json:"latency_ms"`
	ErrorMsg    string                   `json:"error_msg"`
	Profile     string                   `json:"profile"`
	Explanation string                   `json:"explanation"`
	IsTrap      bool                     `json:"is_trap"`
}

func (h *Handler) deceptionBreakerOpen() bool {
	pgDeceptionBreaker.Lock()
	defer pgDeceptionBreaker.Unlock()

	return time.Now().Before(pgDeceptionBreaker.openUntil)
}

func deceptionBreakerOpenUntil() time.Time {
	pgDeceptionBreaker.Lock()
	defer pgDeceptionBreaker.Unlock()

	return pgDeceptionBreaker.openUntil
}

func (h *Handler) recordDeceptionSuccess() {
	pgDeceptionBreaker.Lock()
	defer pgDeceptionBreaker.Unlock()

	pgDeceptionBreaker.failures = 0
	pgDeceptionBreaker.openUntil = time.Time{}
}

func (h *Handler) recordDeceptionFailure(protocol string, errMsg string) {
	pgDeceptionBreaker.Lock()
	defer pgDeceptionBreaker.Unlock()

	pgDeceptionBreaker.failures++
	if pgDeceptionBreaker.failures >= 3 {
		pgDeceptionBreaker.openUntil = time.Now().Add(10 * time.Second)
		h.logger.Warn(
			"deception-engine circuit breaker opened",
			"protocol", protocol,
			"failures", pgDeceptionBreaker.failures,
			"cooldown_seconds", 10,
			"reason", errMsg,
		)
		pgDeceptionBreaker.failures = 0
	}
}

func (h *Handler) decideWithDeceptionEngine(ctx context.Context, sql, protocol string) (*deceptionDecisionResponse, bool) {
	if !shouldConsultDeceptionEngine(sql) {
		return nil, false
	}

	if len(sql) > maxDeceptionDecisionSQLBytes {
		h.logger.Warn(
			"query too large for deception-engine decision; passthrough",
			"protocol", protocol,
			"bytes", len(sql),
			"limit", maxDeceptionDecisionSQLBytes,
		)
		return nil, false
	}

	if h.deceptionBreakerOpen() {
		h.logger.Warn(
			"deception-engine circuit breaker open; passthrough",
			"protocol", protocol,
			"open_until", deceptionBreakerOpenUntil().Format(time.RFC3339),
		)
		return nil, false
	}

	normalized := normalizeDeceptionSQL(sql)
	req := deceptionDecisionRequest{
		SessionID:       safeSessionID(h),
		QueryNormalized: normalized,
		Fingerprint:     deceptionFingerprint(normalized),
		EventType:       "query",
		Phase:           inferDeceptionPhase(normalized),
		Username:        safeUsername(h),
		Database:        safeDatabase(h),
		Protocol:        protocol,
		Table:           extractDeceptionTableName(normalized),
		DeceptionLevel:  inferDeceptionLevel(normalized),
		RiskScore:       inferDeceptionRisk(normalized),
	}

	body, err := json.Marshal(req)
	if err != nil {
		h.logger.Warn("deception request marshal failed; passthrough", "err", err)
		return nil, false
	}

	url := os.Getenv("DECEPTION_ENGINE_URL")
	if url == "" {
		url = "http://deception-engine:8001/decide"
	}

	callCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		h.logger.Warn("deception request create failed; passthrough", "err", err)
		return nil, false
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		h.logger.Warn("deception-engine unavailable; passthrough", "err", err)
		h.recordDeceptionFailure(protocol, err.Error())
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("non-2xx status %d", resp.StatusCode)
		h.logger.Warn("deception-engine non-2xx; passthrough", "status", resp.StatusCode)
		h.recordDeceptionFailure(protocol, msg)
		return nil, false
	}

	var dec deceptionDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&dec); err != nil {
		h.logger.Warn("deception response decode failed; passthrough", "err", err)
		h.recordDeceptionFailure(protocol, err.Error())
		return nil, false
	}

	h.recordDeceptionSuccess()

	if strings.ToLower(dec.Mode) != "fake" {
		return nil, false
	}

	normalizeDecisionShape(&dec, protocol)
	if len(dec.Columns) == 0 {
		return nil, false
	}

	return &dec, true
}

func (h *Handler) sendPostgresDeceptionResult(dec *deceptionDecisionResponse, sql string) error {
	if dec.LatencyMS > 0 {
		time.Sleep(time.Duration(dec.LatencyMS) * time.Millisecond)
	}

	rows := decisionRowsAsBytes(dec)
	messages := make([]pgproto3.BackendMessage, 0, 3+len(rows))

	fields := make([]pgproto3.FieldDescription, 0, len(dec.Columns))
	for _, col := range dec.Columns {
		fields = append(fields, pgproto3.FieldDescription{
			Name:         []byte(col),
			DataTypeOID:  25, // TEXT keeps fake metadata broadly compatible with psql and GUI clients.
			DataTypeSize: -1,
			TypeModifier: -1,
			Format:       0, // text format
		})
	}

	messages = append(messages, &pgproto3.RowDescription{Fields: fields})
	for _, row := range rows {
		messages = append(messages, &pgproto3.DataRow{Values: row})
	}
	messages = append(messages, &pgproto3.CommandComplete{CommandTag: postgresFakeCommandTag(sql, len(rows))})
	messages = append(messages, &pgproto3.ReadyForQuery{TxStatus: h.currentTxStatus()})

	for _, msg := range messages {
		if err := h.sendToClient(msg); err != nil {
			return err
		}
	}
	return nil
}

func normalizeDecisionShape(dec *deceptionDecisionResponse, protocol string) {
	if len(dec.Columns) == 0 && len(dec.Rows) > 0 {
		for k := range dec.Rows[0] {
			dec.Columns = append(dec.Columns, k)
		}
		sort.Strings(dec.Columns)
	}

	if len(dec.Rows) == 0 && len(dec.Tables) > 0 {
		if protocol == "postgres" {
			if len(dec.Columns) == 0 {
				dec.Columns = []string{"schemaname", "tablename"}
			}
			for _, table := range dec.Tables {
				dec.Rows = append(dec.Rows, map[string]interface{}{
					dec.Columns[0]:                  "public",
					dec.Columns[len(dec.Columns)-1]: table,
				})
			}
		} else {
			col := "Tables_in_db"
			if len(dec.Columns) > 0 {
				col = dec.Columns[0]
			} else {
				dec.Columns = []string{col}
			}
			for _, table := range dec.Tables {
				dec.Rows = append(dec.Rows, map[string]interface{}{col: table})
			}
		}
	}

	if len(dec.Rows) == 0 && len(dec.Databases) > 0 {
		col := "datname"
		if protocol != "postgres" {
			col = "Database"
		}
		if len(dec.Columns) > 0 {
			col = dec.Columns[0]
		} else {
			dec.Columns = []string{col}
		}
		for _, db := range dec.Databases {
			dec.Rows = append(dec.Rows, map[string]interface{}{col: db})
		}
	}

	if len(dec.Columns) == 0 && dec.Count != nil {
		dec.Columns = []string{"count"}
		dec.Rows = []map[string]interface{}{{"count": *dec.Count}}
	}
}

func decisionRowsAsBytes(dec *deceptionDecisionResponse) [][][]byte {
	rows := make([][][]byte, 0, len(dec.Rows))
	for _, src := range dec.Rows {
		row := make([][]byte, len(dec.Columns))
		for i, col := range dec.Columns {
			if v, ok := src[col]; ok && v != nil {
				row[i] = []byte(fmt.Sprint(v))
			} else {
				row[i] = []byte("")
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func shouldConsultDeceptionEngine(sql string) bool {
	q := normalizeDeceptionSQL(sql)
	if q == "" || hasMultipleSimpleStatements(q) {
		return false
	}

	if strings.HasPrefix(q, "show ") {
		return true
	}
	if strings.Contains(q, "version()") || strings.Contains(q, "current_database()") {
		return true
	}
	if strings.Contains(q, "information_schema.") || strings.Contains(q, "pg_catalog.") {
		return true
	}
	if strings.Contains(q, "pg_tables") || strings.Contains(q, "pg_class") || strings.Contains(q, "pg_namespace") || strings.Contains(q, "pg_database") {
		return true
	}
	if containsDeceptionTrapTable(q) {
		return true
	}
	if strings.HasPrefix(q, "select ") && extractDeceptionTableName(q) != "" {
		return true
	}
	return false
}

func normalizeDeceptionSQL(sql string) string {
	q := strings.TrimSpace(strings.ToLower(sql))
	q = strings.TrimRight(q, ";")
	return strings.Join(strings.Fields(q), " ")
}

func hasMultipleSimpleStatements(normalized string) bool {
	// Avoid synthesizing a single fake response for a multi-statement Simple Query.
	// The interceptor still sees the query, but the proxy forwards it to the backend.
	return strings.Contains(strings.TrimRight(normalized, ";"), ";")
}

func deceptionFingerprint(normalized string) string {
	sum := sha1.Sum([]byte(normalized))
	return fmt.Sprintf("%x", sum[:8])
}

func inferDeceptionPhase(normalized string) string {
	switch {
	case containsDeceptionTrapTable(normalized):
		return "data_discovery"
	case strings.Contains(normalized, "mysql.user") ||
		strings.Contains(normalized, "show grants") ||
		strings.Contains(normalized, "pg_roles") ||
		strings.Contains(normalized, "has_table_privilege") ||
		strings.Contains(normalized, "has_schema_privilege"):
		return "privilege_discovery"
	case strings.Contains(normalized, "information_schema.") ||
		strings.Contains(normalized, "pg_catalog.") ||
		strings.HasPrefix(normalized, "show ") ||
		strings.Contains(normalized, "pg_tables") ||
		strings.Contains(normalized, "pg_class") ||
		strings.Contains(normalized, "pg_namespace") ||
		strings.Contains(normalized, "pg_database"):
		return "enumeration"
	default:
		return "data_discovery"
	}
}

func inferDeceptionLevel(normalized string) int {
	if containsDeceptionTrapTable(normalized) {
		return 4
	}
	if strings.Contains(normalized, "mysql.user") || strings.Contains(normalized, "show grants") || strings.Contains(normalized, "pg_roles") {
		return 3
	}
	if strings.Contains(normalized, "information_schema.") || strings.Contains(normalized, "pg_catalog.") || strings.HasPrefix(normalized, "show ") {
		return 2
	}
	return 1
}

func inferDeceptionRisk(normalized string) float64 {
	if containsDeceptionTrapTable(normalized) {
		return 12.0
	}
	if strings.Contains(normalized, "information_schema.") || strings.Contains(normalized, "pg_catalog.") || strings.HasPrefix(normalized, "show ") {
		return 7.0
	}
	return 0.0
}

func extractDeceptionTableName(sql string) string {
	tokens := sqlRelationTokens(sql)
	for i, tok := range tokens {
		switch tok {
		case "from", "join", "update", "into", "table":
			if i+1 >= len(tokens) {
				continue
			}
			candidate := tokens[i+1]
			if i+2 < len(tokens) && isLikelySchemaName(candidate) {
				return tokens[i+2]
			}
			return candidate
		case "describe", "desc":
			if i+1 < len(tokens) {
				return tokens[i+1]
			}
		}
	}
	return ""
}

func isLikelySchemaName(token string) bool {
	switch token {
	case "public", "pg_catalog", "information_schema", "mysql", "postgres":
		return true
	default:
		return false
	}
}

func containsDeceptionTrapTable(sql string) bool {
	q := normalizeDeceptionSQL(sql)
	for _, trap := range trapTableNames {
		if strings.Contains(q, trap) {
			return true
		}
	}
	return false
}

func safeSessionID(h *Handler) string {
	if h == nil || h.sess == nil {
		return ""
	}
	return h.sess.ID
}

func safeUsername(h *Handler) string {
	if h == nil || h.sess == nil {
		return ""
	}
	return h.sess.Username
}

func safeDatabase(h *Handler) string {
	if h == nil || h.sess == nil {
		return ""
	}
	return h.sess.Database
}

func postgresFakeCommandTag(sql string, rowCount int) []byte {
	q := strings.TrimSpace(strings.ToLower(sql))
	switch {
	case strings.HasPrefix(q, "insert"):
		return []byte("INSERT 0 0")
	case strings.HasPrefix(q, "update"):
		return []byte("UPDATE 0")
	case strings.HasPrefix(q, "delete"):
		return []byte("DELETE 0")
	default:
		return []byte(fmt.Sprintf("SELECT %d", rowCount))
	}
}

// ─── Trap-table fake result synthesis ─────────────────────────────────────────

var trapTableNames = []string{
	"api_keys_backup",
	"salary_executives",
	"prod_credentials",
	"admin_tokens",
	"backup_passwords",
	"payment_tokens",
	"credit_cards_archive",
	"internal_api_keys",
	"aws_credentials",
}

func isTrapTableReference(sql string) bool {
	tokens := sqlRelationTokens(sql)
	for i, tok := range tokens {
		if !isSQLRelationKeyword(tok) {
			continue
		}

		// Direct reference: FROM api_keys_backup
		if i+1 < len(tokens) && isTrapTableName(tokens[i+1]) {
			return true
		}

		// Schema-qualified reference after punctuation normalization:
		// FROM public.api_keys_backup -> FROM public api_keys_backup
		if i+2 < len(tokens) && !isSQLStopKeyword(tokens[i+1]) && isTrapTableName(tokens[i+2]) {
			return true
		}
	}
	return false
}

func isTrapTableName(token string) bool {
	for _, trap := range trapTableNames {
		if token == trap {
			return true
		}
	}
	return false
}

func isSQLRelationKeyword(token string) bool {
	switch token {
	case "from", "join", "update", "into", "table", "describe", "desc", "truncate":
		return true
	default:
		return false
	}
}

func isSQLStopKeyword(token string) bool {
	switch token {
	case "where", "on", "using", "set", "values", "select", "join", "left", "right", "inner", "outer", "full", "cross":
		return true
	default:
		return false
	}
}

func sqlRelationTokens(sql string) []string {
	q := strings.ToLower(sql)
	var b strings.Builder
	b.Grow(len(q))

	for _, r := range q {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}

	return strings.Fields(b.String())
}

func isSQLSelect(sql string) bool {
	return strings.HasPrefix(strings.TrimSpace(strings.ToLower(sql)), "select")
}

func truncateSQL(sql string, n int) string {
	if len(sql) <= n {
		return sql
	}
	return sql[:n] + "..."
}

func (h *Handler) sendPostgresTrapResponse(sql string) error {
	if isSQLSelect(sql) {
		return h.sendPostgresTrapRows()
	}
	return h.sendPostgresTrapOK(sql)
}

func (h *Handler) sendPostgresTrapRows() error {
	messages := []pgproto3.BackendMessage{
		&pgproto3.RowDescription{
			Fields: []pgproto3.FieldDescription{
				{Name: []byte("id"), DataTypeOID: 23, DataTypeSize: 4, TypeModifier: -1, Format: 0},
				{Name: []byte("service_name"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0},
				{Name: []byte("environment"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0},
				{Name: []byte("api_key"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0},
				{Name: []byte("created_at"), DataTypeOID: 1114, DataTypeSize: 8, TypeModifier: -1, Format: 0},
			},
		},
		&pgproto3.DataRow{Values: [][]byte{
			[]byte("1"),
			[]byte("billing-service"),
			[]byte("production"),
			[]byte("sk_live_FAKE_DO_NOT_USE_8f3a92"),
			[]byte("2026-06-25 06:00:00"),
		}},
		&pgproto3.DataRow{Values: [][]byte{
			[]byte("2"),
			[]byte("admin-panel"),
			[]byte("production"),
			[]byte("ak_prod_FAKE_TRAP_71c9d2"),
			[]byte("2026-06-25 06:00:01"),
		}},
		&pgproto3.DataRow{Values: [][]byte{
			[]byte("3"),
			[]byte("backup-sync"),
			[]byte("staging"),
			[]byte("bk_sync_FAKE_HONEYTOKEN_44ab19"),
			[]byte("2026-06-25 06:00:02"),
		}},
		&pgproto3.CommandComplete{CommandTag: []byte("SELECT 3")},
		&pgproto3.ReadyForQuery{TxStatus: h.currentTxStatus()},
	}

	for _, msg := range messages {
		if err := h.sendToClient(msg); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) sendPostgresTrapOK(sql string) error {
	if err := h.sendToClient(&pgproto3.CommandComplete{CommandTag: postgresTrapCommandTag(sql)}); err != nil {
		return err
	}
	return h.sendToClient(&pgproto3.ReadyForQuery{TxStatus: h.currentTxStatus()})
}

func postgresTrapCommandTag(sql string) []byte {
	q := strings.TrimSpace(strings.ToLower(sql))
	switch {
	case strings.HasPrefix(q, "insert"):
		return []byte("INSERT 0 0")
	case strings.HasPrefix(q, "update"):
		return []byte("UPDATE 0")
	case strings.HasPrefix(q, "delete"):
		return []byte("DELETE 0")
	case strings.HasPrefix(q, "create"):
		return []byte("CREATE TABLE")
	case strings.HasPrefix(q, "drop"):
		return []byte("DROP TABLE")
	case strings.HasPrefix(q, "truncate"):
		return []byte("TRUNCATE TABLE")
	case strings.HasPrefix(q, "alter"):
		return []byte("ALTER TABLE")
	default:
		return []byte("UPDATE 0")
	}
}

func (h *Handler) currentTxStatus() byte {
	if h.sess == nil || h.sess.TxStatus == 0 {
		return 'I'
	}
	return h.sess.TxStatus
}

// ─── Message send helpers ─────────────────────────────────────────────────────

func (h *Handler) sendToClient(msg pgproto3.BackendMessage) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return fmt.Errorf("encode backend message: %w", err)
	}
	_, err = h.clientConn.Write(buf)
	return err
}

func (h *Handler) sendToBackend(msg pgproto3.FrontendMessage) error {
	buf, err := msg.Encode(nil)
	if err != nil {
		return fmt.Errorf("encode frontend message: %w", err)
	}
	_, err = h.backendConn.Write(buf)
	return err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func needsReadyForQuery(msg pgproto3.FrontendMessage) bool {
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Sync:
		return true
	default:
		return false
	}
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

func (h *Handler) getBackendHost() string {
	host, _, err := net.SplitHostPort(h.backendAddr)
	if err != nil {
		return h.backendAddr
	}
	return host
}

var _ = (*Handler).getBackendHost // silence unused warning

// ─── Fix 10: Session accessors ───────────────────────────────────────────────

func (h *Handler) SessionID() string {
	if h.sess == nil {
		return ""
	}
	return h.sess.ID
}

func (h *Handler) Username() string {
	if h.sess == nil {
		return ""
	}
	return h.sess.Username
}

func (h *Handler) Database() string {
	if h.sess == nil {
		return ""
	}
	return h.sess.Database
}
