// Package protocol implements Layer 2: ProtocolParser for MySQL proxy.
// Implements the MySQL Client/Server Protocol (version 41) transparently.
//
// Protocol flow:
//
//	Server greeting → client handshake response → auth OK/ERR → command loop
//
// Supported commands:
//
//	COM_QUERY, COM_PING, COM_QUIT, COM_INIT_DB,
//	COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_CLOSE, COM_STMT_RESET,
//	COM_SET_OPTION, COM_FIELD_LIST, COM_STATISTICS, COM_PROCESS_INFO,
//	COM_PROCESS_KILL (Fix 1 equivalent: forwarded directly to backend)
//
// All fixes from the PostgreSQL proxy are implemented:
//
//	Fix 1:  COM_PROCESS_KILL forwarded; connection ID tracked for kill
//	Fix 2:  Multi-resultset and LOCAL INFILE streaming handled
//	Fix 3:  TCP keepalives on both sockets
//	Fix 5:  interceptor.CleanupSession() called on disconnect
//	Fix 10: Session context (IP, user, DB) on every log line
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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mysqlproxy/internal/interceptor"
	"github.com/mysqlproxy/internal/publisher"
	"github.com/mysqlproxy/internal/session"
	"github.com/mysqlproxy/internal/shaper"
)

// ─── MySQL command bytes ───────────────────────────────────────────────────────

const (
	comSleep         = 0x00
	comQuit          = 0x01
	comInitDB        = 0x02
	comQuery         = 0x03
	comFieldList     = 0x04
	comCreateDB      = 0x05
	comDropDB        = 0x06
	comRefresh       = 0x07
	comStatistics    = 0x09
	comProcessInfo   = 0x0a
	comConnect       = 0x0b
	comProcessKill   = 0x0c
	comDebug         = 0x0d
	comPing          = 0x0e
	comTime          = 0x0f
	comDelayedInsert = 0x10
	comChangeUser    = 0x11
	comSetOption     = 0x1b
	comStmtPrepare   = 0x16
	comStmtExecute   = 0x17
	comStmtClose     = 0x19
	comStmtReset     = 0x1a
	comStmtFetch     = 0x1c
	comResetConn     = 0x1f
)

const (
	// Response packet first bytes
	packetOK  = 0x00
	packetEOF = 0xFE
	packetERR = 0xFF

	// MySQL capability flags used by the proxy. The proxy synthesizes
	// classic text-protocol result sets, so it strips capabilities that
	// require newer result-set metadata handling.
	capClientProtocol41                uint32 = 1 << 9
	capClientSSL                       uint32 = 1 << 11
	capClientDeprecateEOF              uint32 = 1 << 24
	capClientOptionalResultsetMetadata uint32 = 1 << 25
)

const (
	maxDeceptionDecisionSQLBytes = 64 * 1024
	deceptionFailureThreshold    = 3
	deceptionBreakerCooldown     = 10 * time.Second
)

var deceptionBreaker = struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
}{}

// ─── Handler ─────────────────────────────────────────────────────────────────

// Handler manages the full lifecycle of one MySQL client↔backend pair.
type Handler struct {
	clientConn  net.Conn
	backendConn net.Conn
	logger      *slog.Logger
	backendAddr string

	sess *session.Session

	// hdrBuf is a reusable 4-byte buffer for MySQL packet header reads.
	hdrBuf [4]byte

	// idleTimeout is the maximum time to wait for a client command.
	idleTimeout time.Duration

	// Layer 6: always active, zero cost when no rules set
	shaper *shaper.Shaper

	// Phase 3: query interception pipeline
	intercept *interceptor.Interceptor

	// Phase 3: session/auth event publishing
	pub              *publisher.Publisher
	authMethod       string // captured from server greeting auth plugin name
	lastQueryOutcome interceptor.QueryOutcome
}

// NewHandler constructs a Handler.
func NewHandler(client, backend net.Conn, logger *slog.Logger, backendAddr string, idleTimeout time.Duration,
	intercept *interceptor.Interceptor, pub *publisher.Publisher) *Handler {
	return &Handler{
		clientConn:  client,
		backendConn: backend,
		logger:      logger,
		backendAddr: backendAddr,
		idleTimeout: idleTimeout,
		shaper:      shaper.New(shaper.Config{}, logger),
		intercept:   intercept,
		pub:         pub,
	}
}

// Run drives the full connection lifecycle.
func (h *Handler) Run(ctx context.Context) error {
	startTime := time.Now()
	closeReason := "clean"

	// Fix 5: always clean up session state on exit + emit session_end
	defer func() {
		if h.sess != nil {
			h.notifyDeceptionSession(context.Background(), "end")
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

	// Step 1: relay the server greeting to the client
	greeting, serverCaps, connID, authPlugin, authData, err := h.relayServerGreeting()
	if err != nil {
		closeReason = "error"
		return fmt.Errorf("server greeting: %w", err)
	}
	_ = greeting

	// Capture auth method from the plugin name in the greeting
	h.authMethod = authPlugin

	// Step 2: read and relay the client handshake response
	username, database, clientCaps, err := h.relayClientHandshake(serverCaps, authPlugin, authData)
	if err != nil {
		closeReason = "error"
		return fmt.Errorf("client handshake: %w", err)
	}

	// Build session now (needed for auth event emission even on failure)
	h.sess = session.New(h.clientConn.RemoteAddr().String())
	h.sess.SetAuth(username, database, clientCaps, serverCaps)
	h.sess.SetConnectionID(connID)

	// Step 3: relay the auth result (OK or ERR) from backend to client
	if err := h.relayAuthResult(); err != nil {
		closeReason = "error"
		// Emit failed auth event
		if h.pub != nil {
			h.pub.EmitAuth(publisher.AuthEvent{
				EventType:  "auth",
				SessionID:  h.sess.ID,
				Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
				ClientIP:   h.sess.ClientIP,
				Username:   username,
				Database:   database,
				AuthMethod: h.authMethod,
				Success:    false,
				FailReason: err.Error(),
			})
		}
		return fmt.Errorf("auth result: %w", err)
	}

	// Auth succeeded — emit auth + session_start
	if h.pub != nil {
		h.pub.EmitAuth(publisher.AuthEvent{
			EventType:  "auth",
			SessionID:  h.sess.ID,
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
			ClientIP:   h.sess.ClientIP,
			Username:   username,
			Database:   database,
			AuthMethod: h.authMethod,
			Success:    true,
		})
		h.pub.EmitSessionStart(publisher.SessionStartEvent{
			EventType:  "session_start",
			SessionID:  h.sess.ID,
			Timestamp:  h.sess.StartedAt.UTC().Format(time.RFC3339Nano),
			ClientIP:   h.sess.ClientIP,
			Username:   username,
			Database:   database,
			AuthMethod: h.authMethod,
		})
	}
	h.notifyDeceptionSession(ctx, "start")

	// Fix 10: enrich logger with session context
	h.logger = h.logger.With(
		"session_id", h.sess.ID,
		"username", username,
		"database", database,
	)
	h.logger.Debug("session established", "connection_id", connID)

	// Step 4: command loop
	if err := h.commandLoop(ctx); err != nil {
		closeReason = "error"
		return err
	}
	return nil
}

// ─── Fix 10 session accessors ────────────────────────────────────────────────

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
	snap := h.sess.Snapshot()
	return snap.Username
}
func (h *Handler) Database() string {
	if h.sess == nil {
		return ""
	}
	snap := h.sess.Snapshot()
	return snap.Database
}

// ─── Step 1: Server Greeting ─────────────────────────────────────────────────

// relayServerGreeting reads the server's Initial Handshake Packet,
// optionally rewrites it (e.g. to remove SSL capability), and forwards it.
// Returns the server capabilities, connection ID, auth plugin name, and auth data.
func (h *Handler) relayServerGreeting() (raw []byte, serverCaps uint32, connID uint32, authPlugin string, authData []byte, err error) {
	raw, err = h.readPacket(h.backendConn)
	if err != nil {
		return nil, 0, 0, "", nil, fmt.Errorf("read server greeting: %w", err)
	}

	if len(raw) < 1 {
		return nil, 0, 0, "", nil, fmt.Errorf("empty server greeting")
	}

	// Packet type 10 = Handshake v10 (all modern MySQL servers)
	if raw[0] != 10 {
		return nil, 0, 0, "", nil, fmt.Errorf("unexpected protocol version: %d", raw[0])
	}

	// Parse the greeting to extract connection ID, capabilities, and auth data
	p := raw[1:]

	// server version string (null-terminated)
	nullIdx := indexByte(p, 0)
	if nullIdx < 0 {
		return nil, 0, 0, "", nil, fmt.Errorf("malformed greeting: no null after server version")
	}
	p = p[nullIdx+1:]

	if len(p) < 4 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for connection ID")
	}
	connID = binary.LittleEndian.Uint32(p[:4])
	p = p[4:]

	// auth-plugin-data part 1 (8 bytes) + filler
	if len(p) < 9 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for auth data part 1")
	}
	authData1 := make([]byte, 8)
	copy(authData1, p[:8])
	p = p[9:] // skip 8 bytes + 1 filler

	// capability flags lower 2 bytes
	if len(p) < 2 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for capability flags")
	}
	serverCaps = uint32(binary.LittleEndian.Uint16(p[:2]))
	p = p[2:]

	// character set (1 byte)
	if len(p) < 1 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for charset")
	}
	// charSet := p[0]
	p = p[1:]

	// status flags (2 bytes)
	p = p[2:]

	// capability flags upper 2 bytes
	if len(p) < 2 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for upper caps")
	}
	serverCaps |= uint32(binary.LittleEndian.Uint16(p[:2])) << 16
	p = p[2:]

	// auth-plugin-data-len (1 byte)
	var authDataLen byte
	if len(p) >= 1 {
		authDataLen = p[0]
	}
	p = p[1:]

	// reserved (10 bytes)
	if len(p) < 10 {
		return nil, 0, 0, "", nil, fmt.Errorf("greeting too short for reserved bytes")
	}
	p = p[10:]

	// auth-plugin-data part 2
	part2Len := int(authDataLen) - 8
	if part2Len < 13 {
		part2Len = 13
	}
	var authData2 []byte
	if len(p) >= part2Len {
		authData2 = p[:part2Len]
		p = p[part2Len:]
	}
	authData = append(authData1, authData2...)
	if len(authData) > 0 && authData[len(authData)-1] == 0 {
		authData = authData[:len(authData)-1] // strip trailing null
	}

	// auth plugin name (null-terminated string)
	if len(p) > 0 {
		nullIdx = indexByte(p, 0)
		if nullIdx >= 0 {
			authPlugin = string(p[:nullIdx])
		} else {
			authPlugin = string(p)
		}
	}
	if authPlugin == "" {
		authPlugin = "mysql_native_password"
	}

	// Strip CLIENT_SSL from the greeting we send to the client.
	// If the client sees SSL advertised, it sends an SSLRequest packet before
	// the handshake response, which the proxy cannot relay transparently.
	// The proxy-to-backend connection is plaintext on the internal Docker network.
	strippedRaw := stripSSLCapability(raw)
	if err := h.sendPacket(h.clientConn, strippedRaw, 0); err != nil {
		return nil, 0, 0, "", nil, fmt.Errorf("forward greeting: %w", err)
	}
	// Return original serverCaps (with SSL) so we know what the backend supports
	return raw, serverCaps, connID, authPlugin, authData, nil
}

// ─── Step 2: Client Handshake ─────────────────────────────────────────────────

// relayClientHandshake reads the client's HandshakeResponse41, forwards it to
// the backend, and returns the username, database, and negotiated capabilities.
func (h *Handler) relayClientHandshake(serverCaps uint32, authPlugin string, authData []byte) (username, database string, clientCaps uint32, err error) {
	raw, err := h.readPacket(h.clientConn)
	if err != nil {
		return "", "", 0, fmt.Errorf("read client handshake: %w", err)
	}

	if len(raw) < 4 {
		return "", "", 0, fmt.Errorf("client handshake too short")
	}

	p := raw
	clientCaps = uint32(binary.LittleEndian.Uint32(p[:4]))

	// Keep the client/backend negotiation aligned with the classic result-set
	// format that this proxy can synthesize for deception responses.
	clientCaps &^= capClientSSL
	clientCaps &^= capClientDeprecateEOF
	clientCaps &^= capClientOptionalResultsetMetadata
	binary.LittleEndian.PutUint32(raw[:4], clientCaps)

	p = p[4:]

	// max packet size (4 bytes)
	p = p[4:]

	// character set (1 byte)
	p = p[1:]

	// reserved (23 bytes)
	if len(p) < 23 {
		return "", "", 0, fmt.Errorf("client handshake missing reserved bytes")
	}
	p = p[23:]

	// username (null-terminated)
	nullIdx := indexByte(p, 0)
	if nullIdx >= 0 {
		username = string(p[:nullIdx])
		p = p[nullIdx+1:]
	}

	// auth response length + data
	if len(p) > 0 {
		authRespLen := int(p[0])
		p = p[1:]
		if len(p) >= authRespLen {
			p = p[authRespLen:]
		}
	}

	// database (null-terminated)
	if clientCaps&capClientConnectWithDB != 0 && len(p) > 0 {
		nullIdx = indexByte(p, 0)
		if nullIdx >= 0 {
			database = string(p[:nullIdx])
		}
	}

	// Forward the handshake response to the backend unchanged
	if err := h.sendPacket(h.backendConn, raw, 1); err != nil {
		return "", "", 0, fmt.Errorf("forward client handshake: %w", err)
	}
	return username, database, clientCaps, nil
}

const capClientConnectWithDB uint32 = 1 << 3

// ─── Step 3: Auth Result ──────────────────────────────────────────────────────

// relayAuthResult reads the auth OK/ERR/AuthSwitch response from the backend
// and forwards it to the client. Handles multi-round auth plugin switch.
//
// MySQL auth sequence numbers:
//
//	seq 0: server greeting
//	seq 1: client HandshakeResponse
//	seq 2: server OK / ERR / AuthSwitchRequest
//	seq 3: client auth switch response (if AuthSwitchRequest)
//	seq 4: server OK / ERR / AuthMoreData (for caching_sha2_password)
//	…and so on for caching_sha2 full-auth rounds
//
// Fix: seq starts at 2 (first server response after client handshake at seq 1)
// and increments with each packet exchanged, so clients receive correct headers.
func (h *Handler) relayAuthResult() error {
	seq := byte(2) // first auth result packet from server is always seq 2
	for {
		pkt, err := h.readPacket(h.backendConn)
		if err != nil {
			return fmt.Errorf("read auth result: %w", err)
		}
		if err := h.sendPacket(h.clientConn, pkt, seq); err != nil {
			return fmt.Errorf("forward auth result: %w", err)
		}
		seq++

		if len(pkt) == 0 {
			return fmt.Errorf("empty auth result packet")
		}
		switch pkt[0] {
		case packetOK:
			return nil
		case packetERR:
			return fmt.Errorf("auth rejected: %s", extractErrMessage(pkt))
		case 0xFE: // AuthSwitchRequest — relay client's response back to backend
			switchResp, err := h.readPacket(h.clientConn)
			if err != nil {
				return fmt.Errorf("read auth switch response: %w", err)
			}
			if err := h.sendPacket(h.backendConn, switchResp, seq); err != nil {
				return fmt.Errorf("forward auth switch response: %w", err)
			}
			seq++
			// Loop: read next server packet (OK/ERR/AuthMoreData)
		case 0x01: // AuthMoreData (caching_sha2_password)
			// Subtype byte (pkt[1]) tells us what the server is saying:
			//   0x03 = fast auth success  → next packet is OK, no client response needed
			//   0x04 = full auth required → client must send plaintext password
			if len(pkt) >= 2 && pkt[1] == 0x03 {
				// Fast-auth succeeded — loop to read the final OK packet
				break
			}
			// Full-auth or other: relay client's next response back to backend
			moreResp, err := h.readPacket(h.clientConn)
			if err != nil {
				return fmt.Errorf("read auth more data response: %w", err)
			}
			if err := h.sendPacket(h.backendConn, moreResp, seq); err != nil {
				return fmt.Errorf("forward auth more data response: %w", err)
			}
			seq++
			// Loop: read next server packet
		default:
			return fmt.Errorf("unexpected auth packet type: 0x%02x", pkt[0])
		}
	}
}

// ─── Step 4: Command Loop ─────────────────────────────────────────────────────

// commandLoop is the main bidirectional message pump after authentication.
// It reads one command from the client, processes it, drains the backend
// response, then loops. MySQL sequences reset to 0 at each command boundary.
func (h *Handler) commandLoop(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Apply idle timeout: if the client sends nothing within this window,
		// the read will return a timeout error and the connection is closed cleanly.
		// Fix 3: prevents goroutine leaks from idle clients holding connections forever.
		if h.idleTimeout > 0 {
			_ = h.clientConn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		}

		// Read next command from client (sequence always resets to 0)
		cmdPkt, err := h.readPacket(h.clientConn)
		if err != nil {
			if isEOF(err) {
				return nil
			}
			if isTimeout(err) {
				h.logger.Debug("client idle timeout, closing connection")
				return nil
			}
			return fmt.Errorf("read client command: %w", err)
		}

		// Clear the read deadline for the duration of the command execution.
		if h.idleTimeout > 0 {
			_ = h.clientConn.SetReadDeadline(time.Time{})
		}

		if len(cmdPkt) == 0 {
			continue
		}

		h.sess.IncrBytesIn(int64(len(cmdPkt)))

		cmd := cmdPkt[0]
		payload := cmdPkt[1:]

		h.logger.Debug("client→proxy", "cmd", fmt.Sprintf("0x%02x", cmd))

		// ── Layer 6: ResponseShaper decision ─────────────────────────────────
		// Phase 2: fingerprint = h.interceptor.LastFingerprint(h.sess)
		var fingerprint string
		shapingDecision := h.shaper.Decide(fingerprint)
		shapeCtx := shaper.NewShapeContext(shapingDecision)

		// ─────────────────────────────────────────────────────────────────────

		switch cmd {
		case comQuit:
			// Forward COM_QUIT, then close — no response expected
			_ = h.sendPacket(h.backendConn, cmdPkt, 0)
			return nil

		case comPing:
			// Forward ping to backend, relay OK back
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, false); err != nil {
				return err
			}

		case comQuery:
			sql := cleanMySQLQueryPayload(payload)
			h.logger.Debug("COM_QUERY", "sql", truncate(sql, 200))
			// Query-level proxy log evidence.
			// This makes proxy logs show the actual SQL received by the proxy.
			if h.sess != nil {
				snap := h.sess.Snapshot()
				h.logger.Info(
					"query intercepted",
					"protocol", "mysql",
					"mode", "text",
					"session_id", snap.ID,
					"username", snap.Username,
					"database", snap.Database,
					"query_raw", truncate(sql, 300),
				)
			}

			if shapingDecision.ShouldBlock {
				if err := h.sendBlockResponse(shapeCtx); err != nil {
					return err
				}
				h.emitTextQueryOutcome(sql, interceptor.QueryOutcome{Verified: true, Success: false, Authority: "policy", TransactionState: h.mysqlTransactionState(), ErrorCode: "blocked"})
				continue
			}
			// Synchronous deception-engine response synthesis.
			// If /decide returns mode=fake, build a MySQL result set here and do not
			// forward the query to the real backend.
			if dec, ok := h.decideWithDeceptionEngine(ctx, sql, "mysql"); ok {
				h.logger.Info(
					"serving deception-engine fake result",
					"protocol", "mysql",
					"profile", dec.Profile,
					"columns", dec.Columns,
					"rows", len(dec.Rows),
					"query", truncate(sql, 300),
				)
				if err := h.sendMySQLDeceptionResult(dec); err != nil {
					return fmt.Errorf("send deception-engine fake result: %w", err)
				}
				success := strings.EqualFold(dec.Mode, "fake")
				errorCode := ""
				if !success {
					errorCode = fmt.Sprintf("mysql_%d", dec.ErrorCode)
				}
				h.emitTextQueryOutcome(sql, interceptor.QueryOutcome{
					Verified: true, Success: success, Authority: "deception",
					TransactionState: h.mysqlTransactionState(), ErrorCode: errorCode,
					EventSchemaVersion: dec.EventSchemaVersion,
					WorldID:            dec.WorldID, AssetID: dec.AssetID, AssetKind: dec.AssetKind,
					TrapTriggered: success && dec.TrapTriggered,
					TrapID:        dec.TrapID, TrapKind: dec.TrapKind,
					TrapMitreTechniqueID: dec.TrapMitreTechniqueID, TrapRiskScore: dec.TrapRiskScore,
					StrategyID:              dec.StrategyID,
					StrategyRegistryVersion: dec.StrategyRegistryVersion,
				})
				continue
			}

			// The engine is the exposure authority.  If it is unavailable, fail
			// closed instead of exposing a guessed trap through a native fallback.
			if isTrapTableReference(sql) {
				if err := h.sendMySQLDeceptionError(1146, "42S02", "Table doesn't exist"); err != nil {
					return fmt.Errorf("send hidden table response: %w", err)
				}
				h.emitTextQueryOutcome(sql, interceptor.QueryOutcome{Verified: true, Success: false, Authority: "deception", TransactionState: h.mysqlTransactionState(), ErrorCode: "mysql_1146"})
				continue
			}

			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, true); err != nil {
				return err
			}
			h.emitTextQueryOutcome(sql, h.lastQueryOutcome)

		case comInitDB:
			db := string(payload)
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, false); err != nil {
				return err
			}
			h.sess.SetDatabase(db)
			h.logger.Debug("database changed", "db", db)

		case comChangeUser:
			// Fix 4: COM_CHANGE_USER re-runs a full auth exchange.
			// Forward the command, relay the embedded auth round-trips, then
			// update the session with the new username/database.
			newUser, newDB, err := h.handleChangeUser(ctx, cmdPkt)
			if err != nil {
				return err
			}
			if newUser != "" {
				h.sess.SetAuth(newUser, newDB,
					h.sess.GetClientCapabilities(), h.sess.GetServerCapabilities())
				if newDB != "" {
					h.sess.SetDatabase(newDB)
				}
				// Enrich logger with new identity
				h.logger = h.logger.With(
					"new_username", newUser,
					"new_database", newDB,
				)
				h.logger.Debug("COM_CHANGE_USER completed")
			}

		case comStmtPrepare:
			sql := string(payload)
			h.logger.Debug("COM_STMT_PREPARE", "sql", truncate(sql, 200))
			stmtID, err := h.handleStmtPrepare(ctx, cmdPkt, sql)
			if err != nil {
				return err
			}
			if stmtID > 0 {
				h.sess.AddPreparedStmt(stmtID, sql)
				if h.intercept != nil {
					h.intercept.InterceptStmtPrepare(h.sess.ID, stmtID, sql)
				}
			}

		case comStmtExecute:
			if len(payload) < 4 {
				_ = h.forwardAndDrain(ctx, cmdPkt, shapeCtx, true)
				continue
			}
			stmtID := binary.LittleEndian.Uint32(payload[:4])
			h.logger.Debug("COM_STMT_EXECUTE", "stmt_id", stmtID)

			if shapingDecision.ShouldBlock {
				if err := h.sendBlockResponse(shapeCtx); err != nil {
					return err
				}
				if h.intercept != nil {
					h.intercept.InterceptStmtExecuteOutcome(h.sess, stmtID, interceptor.QueryOutcome{Verified: true, Success: false, Authority: "policy", TransactionState: h.mysqlTransactionState(), ErrorCode: "blocked"})
				}
				continue
			}
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, true); err != nil {
				return err
			}
			if h.intercept != nil {
				h.intercept.InterceptStmtExecuteOutcome(h.sess, stmtID, h.lastQueryOutcome)
			}

		case comStmtClose:
			if len(payload) >= 4 {
				stmtID := binary.LittleEndian.Uint32(payload[:4])
				h.sess.RemovePreparedStmt(stmtID)
				if h.intercept != nil {
					h.intercept.InterceptStmtClose(h.sess.ID, stmtID)
				}
			}
			// COM_STMT_CLOSE has no server response
			_ = h.sendPacket(h.backendConn, cmdPkt, 0)

		case comStmtReset:
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, false); err != nil {
				return err
			}

		case comProcessKill:
			// Fix 1 equivalent: forward COM_PROCESS_KILL to the real backend
			// so kill signals actually reach the right backend thread
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, false); err != nil {
				return err
			}

		default:
			// Forward all other commands (COM_FIELD_LIST, COM_STATISTICS, etc.)
			if err := h.forwardAndDrain(ctx, cmdPkt, shapeCtx, false); err != nil {
				return err
			}
		}
	}
}

// ─── COM_STMT_PREPARE handling ────────────────────────────────────────────────

// handleStmtPrepare forwards a COM_STMT_PREPARE to the backend, reads the
// prepared statement OK response to extract the statement ID, then relays
// all column/param definition packets to the client.
// Returns the assigned statement ID on success, 0 on error response.
func (h *Handler) handleStmtPrepare(ctx context.Context, cmdPkt []byte, sql string) (uint32, error) {
	_ = sql
	if err := h.sendPacket(h.backendConn, cmdPkt, 0); err != nil {
		return 0, fmt.Errorf("send stmt prepare: %w", err)
	}

	// Read the prepare OK or ERR response
	pkt, err := h.readPacket(h.backendConn)
	if err != nil {
		return 0, fmt.Errorf("read prepare result: %w", err)
	}

	if err := h.sendPacket(h.clientConn, pkt, 1); err != nil {
		return 0, fmt.Errorf("forward prepare result: %w", err)
	}

	if len(pkt) == 0 || pkt[0] == packetERR {
		return 0, nil
	}

	// Prepare OK: 0x00 + stmt_id(4) + num_columns(2) + num_params(2) + reserved(1) + warning_count(2)
	if len(pkt) < 12 {
		return 0, fmt.Errorf("prepare OK packet too short")
	}
	stmtID := binary.LittleEndian.Uint32(pkt[1:5])
	numColumns := int(binary.LittleEndian.Uint16(pkt[5:7]))
	numParams := int(binary.LittleEndian.Uint16(pkt[7:9]))

	seqNum := byte(2)

	// Forward param definition packets (if any) + EOF
	if numParams > 0 {
		for i := 0; i < numParams; i++ {
			p, err := h.readAndRelay(h.backendConn, h.clientConn, seqNum)
			_ = p
			if err != nil {
				return 0, err
			}
			seqNum++
		}
		// EOF after params
		if _, err := h.readAndRelay(h.backendConn, h.clientConn, seqNum); err != nil {
			return 0, err
		}
		seqNum++
	}

	// Forward column definition packets (if any) + EOF
	if numColumns > 0 {
		for i := 0; i < numColumns; i++ {
			if _, err := h.readAndRelay(h.backendConn, h.clientConn, seqNum); err != nil {
				return 0, err
			}
			seqNum++
		}
		// EOF after columns
		if _, err := h.readAndRelay(h.backendConn, h.clientConn, seqNum); err != nil {
			return 0, err
		}
	}

	return stmtID, nil
}

// ─── Response Forwarding ──────────────────────────────────────────────────────

// forwardAndDrain sends a client command to the backend and drains all
// response packets back to the client. isQuery=true enables row counting.
// Fix 2 equivalent: handles multi-resultset, LOCAL INFILE, and all edge cases.
func (h *Handler) forwardAndDrain(ctx context.Context, cmdPkt []byte, sc *shaper.ShapeContext, isQuery bool) error {
	h.lastQueryOutcome = interceptor.QueryOutcome{Verified: isQuery, Success: true, Authority: "backend", TransactionState: h.mysqlTransactionState()}
	if err := h.sendPacket(h.backendConn, cmdPkt, 0); err != nil {
		return fmt.Errorf("send to backend: %w", err)
	}
	return h.drainResponse(ctx, sc, isQuery)
}

// drainResponse reads and forwards all packets for one command response.
// MySQL response types:
//   - OK packet       → single packet, done
//   - ERR packet      → single packet, done
//   - LOCAL INFILE    → read local file data from client, stream to backend
//   - Result set      → column count + column defs + EOF + rows + EOF/OK
//   - Multi-resultset → multiple result sets separated by EOF with MORE_RESULTS flag
func (h *Handler) drainResponse(ctx context.Context, sc *shaper.ShapeContext, isQuery bool) error {
	seqNum := byte(1)
	latencyApplied := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		pkt, err := h.readPacket(h.backendConn)
		if err != nil {
			return fmt.Errorf("read backend response: %w", err)
		}

		h.sess.IncrBytesOut(int64(len(pkt)))
		h.logger.Debug("backend→proxy", "pkt_type", fmt.Sprintf("0x%02x", firstByte(pkt)), "len", len(pkt))

		// ── Fix 2 (MySQL): LOCAL INFILE request ──────────────────────────────
		// 0xFB = LOCAL INFILE request — client must send file data
		if len(pkt) > 0 && pkt[0] == 0xFB {
			if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
				return fmt.Errorf("forward local infile request: %w", err)
			}
			seqNum++
			if err := h.handleLocalInfile(ctx, seqNum); err != nil {
				return fmt.Errorf("local infile stream: %w", err)
			}
			seqNum = 0 // reset for result after INFILE
			continue
		}
		// ─────────────────────────────────────────────────────────────────────

		// Apply latency before first real response packet
		if !latencyApplied && isQuery {
			switch {
			case len(pkt) > 0 && pkt[0] != packetOK && pkt[0] != packetERR:
				sc.ApplyLatency()
				latencyApplied = true
			}
		}

		if len(pkt) == 0 {
			if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
				return err
			}
			return nil
		}

		switch pkt[0] {
		case packetOK:
			h.updateMySQLStatus(pkt)
			// Check for more results (SERVER_MORE_RESULTS_EXISTS in status flags)
			if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
				return err
			}
			if isQuery && hasMoreResults(pkt) {
				seqNum++
				continue // another result set follows
			}
			return nil

		case packetERR:
			h.lastQueryOutcome.Success = false
			h.lastQueryOutcome.ErrorCode = mysqlErrorCode(pkt)
			h.lastQueryOutcome.TransactionState = h.mysqlTransactionState()
			return h.sendPacket(h.clientConn, pkt, seqNum)

		case packetEOF:
			h.updateMySQLStatus(pkt)
			if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
				return err
			}
			if hasMoreResults(pkt) {
				seqNum++
				continue
			}
			return nil

		default:
			// Could be: column count (varint), column def, or row data
			// We distinguish rows from column defs by tracking state:
			// After we see column defs + EOF, everything until next EOF/OK is a row.
			// For row limiting, we need to know if this is a data row.
			// We use a two-phase approach:
			//   phase 0: column count + column definitions + EOF
			//   phase 1: data rows until EOF/OK

			// First non-special packet after command = column count
			colCount, _, err := readLenEnc(pkt, 0)
			if err != nil || colCount == 0 {
				// Not a valid column count — forward as-is
				if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
					return err
				}
				seqNum++
				continue
			}

			// Forward column count packet
			if err := h.sendPacket(h.clientConn, pkt, seqNum); err != nil {
				return err
			}
			seqNum++

			// Forward column definition packets
			for i := uint64(0); i < colCount; i++ {
				colPkt, err := h.readPacket(h.backendConn)
				if err != nil {
					return fmt.Errorf("read column def: %w", err)
				}
				if err := h.sendPacket(h.clientConn, colPkt, seqNum); err != nil {
					return err
				}
				seqNum++
			}

			// EOF after column defs
			eofPkt, err := h.readPacket(h.backendConn)
			if err != nil {
				return fmt.Errorf("read col EOF: %w", err)
			}
			if err := h.sendPacket(h.clientConn, eofPkt, seqNum); err != nil {
				return err
			}
			seqNum++

			// Apply latency before first row
			if !latencyApplied {
				sc.ApplyLatency()
				latencyApplied = true
			}

			// Data rows until EOF/OK/ERR. Do not classify by first byte alone:
			// a valid text row can start with 0x00 when the first column is an
			// empty string. Parse the row shape first, then treat non-row packets
			// as terminators.
			for {
				rowPkt, err := h.readPacket(h.backendConn)
				if err != nil {
					return fmt.Errorf("read row: %w", err)
				}
				if len(rowPkt) == 0 {
					return nil
				}

				if isTextResultRow(rowPkt, colCount) {
					// ── Layer 6: Row limiting ─────────────────────────────
					if !sc.FilterRow() {
						// Drop the row — keep draining backend
						continue
					}
					// ─────────────────────────────────────────────────────

					if err := h.sendPacket(h.clientConn, rowPkt, seqNum); err != nil {
						return err
					}
					seqNum++
					continue
				}

				if isResultSetTerminator(rowPkt) {
					h.updateMySQLStatus(rowPkt)
					// End of rows — always forward terminator
					if err := h.sendPacket(h.clientConn, rowPkt, seqNum); err != nil {
						return err
					}
					seqNum++
					if hasMoreResults(rowPkt) {
						break // outer loop continues
					}
					return nil
				}

				// Unknown packet while inside a result set. Forward it instead of
				// tearing down the connection; this preserves transparency for edge
				// cases the lightweight parser does not understand.
				if err := h.sendPacket(h.clientConn, rowPkt, seqNum); err != nil {
					return err
				}
				seqNum++
			}
			// More results — outer loop continues
		}
	}
}

func (h *Handler) emitTextQueryOutcome(sql string, outcome interceptor.QueryOutcome) {
	if h.intercept != nil && h.sess != nil {
		h.intercept.InterceptTextQueryOutcome(h.sess, sql, outcome)
	}
}

func (h *Handler) mysqlTransactionState() string {
	if h.sess != nil && h.sess.Snapshot().InTransaction {
		return "in_transaction"
	}
	return "idle"
}

func (h *Handler) updateMySQLStatus(pkt []byte) {
	status, ok := mysqlStatusFlags(pkt)
	if !ok || h.sess == nil {
		return
	}
	h.sess.SetTransactionStatus(status&0x0001 != 0, status&0x0002 != 0)
	h.lastQueryOutcome.TransactionState = h.mysqlTransactionState()
}

func mysqlErrorCode(pkt []byte) string {
	if len(pkt) < 3 || pkt[0] != packetERR {
		return "mysql_error"
	}
	return fmt.Sprintf("mysql_%d", uint16(pkt[1])|uint16(pkt[2])<<8)
}

// handleLocalInfile implements Fix 2 (MySQL): streams LOCAL INFILE data from
// client to backend. The client sends the file content as raw data packets
// followed by an empty packet to signal end-of-file.
func (h *Handler) handleLocalInfile(ctx context.Context, startSeq byte) error {
	seqNum := startSeq
	for {
		select {
		case <-ctx.Done():
			// Send empty packet to backend to signal abort
			_ = h.sendPacket(h.backendConn, []byte{}, seqNum)
			return ctx.Err()
		default:
		}
		pkt, err := h.readPacket(h.clientConn)
		if err != nil {
			return fmt.Errorf("read local infile data: %w", err)
		}
		if err := h.sendPacket(h.backendConn, pkt, seqNum); err != nil {
			return fmt.Errorf("forward local infile data: %w", err)
		}
		seqNum++
		if len(pkt) == 0 {
			// Empty packet = end of file; backend will now send OK/ERR
			break
		}
	}
	// Drain the OK/ERR result after INFILE
	return h.drainResponse(ctx, shaper.NewShapeContext(shaper.Decision{}), false)
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
		// FROM mysql.api_keys_backup -> FROM mysql api_keys_backup
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

func (h *Handler) sendMySQLTrapRows() error {
	columns := []mysqlTrapColumn{
		{Name: "id", Type: 0x03, Charset: 63, Length: 11},            // MYSQL_TYPE_LONG
		{Name: "service_name", Type: 0xfd, Charset: 33, Length: 255}, // MYSQL_TYPE_VAR_STRING
		{Name: "environment", Type: 0xfd, Charset: 33, Length: 255},
		{Name: "api_key", Type: 0xfd, Charset: 33, Length: 255},
		{Name: "created_at", Type: 0xfd, Charset: 33, Length: 255},
	}
	rows := [][]string{
		{"1", "billing-service", "production", "sk_live_FAKE_DO_NOT_USE_8f3a92", "2026-06-25 06:00:00"},
		{"2", "admin-panel", "production", "ak_prod_FAKE_TRAP_71c9d2", "2026-06-25 06:00:01"},
		{"3", "backup-sync", "staging", "bk_sync_FAKE_HONEYTOKEN_44ab19", "2026-06-25 06:00:02"},
	}

	seq := byte(1)

	if err := h.sendPacket(h.clientConn, writeLenEncInt(uint64(len(columns))), seq); err != nil {
		return err
	}
	seq++

	for _, col := range columns {
		pkt := buildMySQLColumnDefinition(col)
		if err := h.sendPacket(h.clientConn, pkt, seq); err != nil {
			return err
		}
		seq++
	}

	if err := h.sendPacket(h.clientConn, mysqlEOFPacket(), seq); err != nil {
		return err
	}
	seq++

	for _, row := range rows {
		pkt := buildMySQLTextRow(row)
		if err := h.sendPacket(h.clientConn, pkt, seq); err != nil {
			return err
		}
		seq++
	}

	if err := h.sendPacket(h.clientConn, mysqlEOFPacket(), seq); err != nil {
		return err
	}

	h.sess.IncrBytesOut(1)
	return nil
}

func (h *Handler) sendMySQLTrapOK() error {
	// OK packet:
	// 0x00 + affected_rows(0) + last_insert_id(0) + status_flags(autocommit) + warnings(0)
	return h.sendPacket(h.clientConn, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 1)
}

type mysqlTrapColumn struct {
	Name    string
	Type    byte
	Charset uint16
	Length  uint32
}

func buildMySQLColumnDefinition(col mysqlTrapColumn) []byte {
	var pkt []byte
	pkt = append(pkt, writeLenEncString("def")...)             // catalog
	pkt = append(pkt, writeLenEncString("")...)                // schema
	pkt = append(pkt, writeLenEncString("api_keys_backup")...) // table
	pkt = append(pkt, writeLenEncString("api_keys_backup")...) // org_table
	pkt = append(pkt, writeLenEncString(col.Name)...)          // name
	pkt = append(pkt, writeLenEncString(col.Name)...)          // org_name
	pkt = append(pkt, 0x0c)                                    // fixed-length fields length

	fixed := make([]byte, 12)
	binary.LittleEndian.PutUint16(fixed[0:2], col.Charset)
	binary.LittleEndian.PutUint32(fixed[2:6], col.Length)
	fixed[6] = col.Type
	binary.LittleEndian.PutUint16(fixed[7:9], 0) // flags
	fixed[9] = 0                                 // decimals
	// fixed[10:12] filler
	pkt = append(pkt, fixed...)
	return pkt
}

func buildMySQLTextRow(values []string) []byte {
	var pkt []byte
	for _, value := range values {
		pkt = append(pkt, writeLenEncString(value)...)
	}
	return pkt
}

func mysqlEOFPacket() []byte {
	// EOF + warnings(0) + SERVER_STATUS_AUTOCOMMIT
	return []byte{0xfe, 0x00, 0x00, 0x02, 0x00}
}

func writeLenEncString(s string) []byte {
	out := writeLenEncInt(uint64(len(s)))
	out = append(out, []byte(s)...)
	return out
}

func writeLenEncInt(n uint64) []byte {
	switch {
	case n < 251:
		return []byte{byte(n)}
	case n <= 0xffff:
		return []byte{0xfc, byte(n), byte(n >> 8)}
	case n <= 0xffffff:
		return []byte{0xfd, byte(n), byte(n >> 8), byte(n >> 16)}
	default:
		out := make([]byte, 9)
		out[0] = 0xfe
		binary.LittleEndian.PutUint64(out[1:9], n)
		return out
	}
}

// ─── Block Response ───────────────────────────────────────────────────────────

// sendBlockResponse sends a MySQL ERR packet to the client without touching
// the backend. Equivalent to PG's ErrorResponse + ReadyForQuery.
func (h *Handler) sendBlockResponse(sc *shaper.ShapeContext) error {
	pkt := sc.BlockPacket()
	if pkt == nil {
		return nil
	}
	h.logger.Debug("query blocked by shaper")
	return h.sendPacket(h.clientConn, pkt, 1)
}

// ─── Packet I/O ───────────────────────────────────────────────────────────────

// maxMySQLPayload is the maximum payload per MySQL packet frame.
// When a payload is exactly this size, the server sends a continuation packet.
const maxMySQLPayload = 0xFFFFFF // 16,777,215 bytes

// readPacket reads one complete MySQL logical message from conn.
//
// MySQL wire format per frame: 3-byte payload length (LE) + 1-byte seq + payload.
// If a frame payload is exactly maxMySQLPayload (0xFFFFFF) bytes, the message is
// split across multiple frames (continuation packets). This method reassembles them
// into a single slice so callers never see partial messages. Fix: large-packet support.
//
// The wire sequence byte is discarded; callers track their own seqNum for replies.
// Perf: reuses h.hdrBuf for the 4-byte header read to avoid a heap alloc per packet.
func (h *Handler) readPacket(conn net.Conn) ([]byte, error) {
	if _, err := io.ReadFull(conn, h.hdrBuf[:]); err != nil {
		return nil, err
	}
	length := int(h.hdrBuf[0]) | int(h.hdrBuf[1])<<8 | int(h.hdrBuf[2])<<16

	if length == 0 {
		return []byte{}, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	// Reassemble continuation frames (Fix: large-packet support)
	for length == maxMySQLPayload {
		if _, err := io.ReadFull(conn, h.hdrBuf[:]); err != nil {
			return nil, fmt.Errorf("read continuation header: %w", err)
		}
		length = int(h.hdrBuf[0]) | int(h.hdrBuf[1])<<8 | int(h.hdrBuf[2])<<16
		if length == 0 {
			break
		}
		extra := make([]byte, length)
		if _, err := io.ReadFull(conn, extra); err != nil {
			return nil, fmt.Errorf("read continuation payload: %w", err)
		}
		payload = append(payload, extra...)
	}

	return payload, nil
}

// sendPacket writes one MySQL packet to conn with the given sequence number.
// For payloads larger than maxMySQLPayload the message is automatically split into
// continuation frames with incrementing sequence numbers. Fix: large-packet support.
//
// Perf: builds the framed packet in a single Write call using a stack-allocated
// header to avoid the extra heap alloc from the previous []byte{...} literal.
func (h *Handler) sendPacket(conn net.Conn, payload []byte, seq byte) error {
	for {
		chunk := payload
		if len(chunk) > maxMySQLPayload {
			chunk = payload[:maxMySQLPayload]
		}
		length := len(chunk)
		h.hdrBuf[0] = byte(length)
		h.hdrBuf[1] = byte(length >> 8)
		h.hdrBuf[2] = byte(length >> 16)
		h.hdrBuf[3] = seq

		// Single Write: header + payload avoids two syscalls
		buf := make([]byte, 4+length)
		copy(buf[:4], h.hdrBuf[:])
		copy(buf[4:], chunk)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		seq++
		payload = payload[length:]
		if len(payload) == 0 && length < maxMySQLPayload {
			return nil
		}
		if len(payload) == 0 {
			// Sent exactly maxMySQLPayload bytes — must send empty terminator
			h.hdrBuf[0], h.hdrBuf[1], h.hdrBuf[2], h.hdrBuf[3] = 0, 0, 0, seq
			_, err := conn.Write(h.hdrBuf[:])
			return err
		}
	}
}

// readAndRelay reads a packet from src and forwards it to dst with the given seq.
func (h *Handler) readAndRelay(src, dst net.Conn, seq byte) ([]byte, error) {
	pkt, err := h.readPacket(src)
	if err != nil {
		return nil, err
	}
	if err := h.sendPacket(dst, pkt, seq); err != nil {
		return nil, err
	}
	return pkt, nil
}

// ─── COM_CHANGE_USER handling ─────────────────────────────────────────────────

// handleChangeUser forwards COM_CHANGE_USER and relays the embedded auth exchange.
// COM_CHANGE_USER carries a new username, database, auth response, and optionally
// a new auth plugin. The backend responds with the same sequence as normal auth
// (OK / ERR / AuthSwitchRequest / AuthMoreData).
//
// Fix 4: previously fell through to forwardAndDrain which doesn't handle the
// auth sub-exchange. This method correctly manages the multi-packet auth dance.
//
// Returns the new username and database on success; empty strings if the backend
// rejected the change (ERR packet — the session remains on the old identity).
func (h *Handler) handleChangeUser(ctx context.Context, cmdPkt []byte) (username, database string, err error) {
	_ = ctx

	// Parse the new username and database from the command payload
	// COM_CHANGE_USER payload: user(NTS) + auth_response(len+data) + database(NTS) + ...
	if len(cmdPkt) > 1 {
		p := cmdPkt[1:]
		nullIdx := indexByte(p, 0)
		if nullIdx >= 0 {
			username = string(p[:nullIdx])
			p = p[nullIdx+1:]
			// skip auth response: 1-byte length + data
			if len(p) > 0 {
				authLen := int(p[0])
				p = p[1:]
				if len(p) >= authLen {
					p = p[authLen:]
				}
			}
			// database
			nullIdx = indexByte(p, 0)
			if nullIdx >= 0 {
				database = string(p[:nullIdx])
			} else {
				database = string(p)
			}
		}
	}

	// Forward the command to the backend
	if err := h.sendPacket(h.backendConn, cmdPkt, 0); err != nil {
		return "", "", fmt.Errorf("send COM_CHANGE_USER: %w", err)
	}

	// Relay the auth exchange (same pattern as relayAuthResult)
	// Sequence starts at 1 (server's first response to our seq-0 command)
	seq := byte(1)
	for {
		pkt, err := h.readPacket(h.backendConn)
		if err != nil {
			return "", "", fmt.Errorf("read change_user auth result: %w", err)
		}
		if err := h.sendPacket(h.clientConn, pkt, seq); err != nil {
			return "", "", fmt.Errorf("forward change_user auth result: %w", err)
		}
		seq++

		if len(pkt) == 0 {
			return "", "", fmt.Errorf("empty change_user auth packet")
		}
		switch pkt[0] {
		case packetOK:
			return username, database, nil
		case packetERR:
			// Auth rejected — session identity unchanged
			h.logger.Warn("COM_CHANGE_USER rejected by backend",
				"new_username", username, "error", extractErrMessage(pkt))
			return "", "", nil
		case 0xFE: // AuthSwitchRequest
			switchResp, err := h.readPacket(h.clientConn)
			if err != nil {
				return "", "", fmt.Errorf("read change_user switch response: %w", err)
			}
			if err := h.sendPacket(h.backendConn, switchResp, seq); err != nil {
				return "", "", fmt.Errorf("forward change_user switch response: %w", err)
			}
			seq++
		case 0x01: // AuthMoreData (caching_sha2_password)
			moreResp, err := h.readPacket(h.clientConn)
			if err != nil {
				return "", "", fmt.Errorf("read change_user more data response: %w", err)
			}
			if err := h.sendPacket(h.backendConn, moreResp, seq); err != nil {
				return "", "", fmt.Errorf("forward change_user more data response: %w", err)
			}
			seq++
		default:
			return "", "", fmt.Errorf("unexpected change_user auth packet: 0x%02x", pkt[0])
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
func cleanMySQLQueryPayload(payload []byte) string {
	for len(payload) > 0 && payload[0] < 0x20 {
		payload = payload[1:]
	}
	return string(payload)
}

func isEOF(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed)
}

// isResultSetTerminator returns true for protocol-level row terminators.
// EOF packets are only terminators when they are short; 0xFE can also be the
// marker for an 8-byte length-encoded integer. OK packets are terminators only
// after isTextResultRow has already failed, which prevents empty-string rows
// from being misclassified as OK.
func isResultSetTerminator(pkt []byte) bool {
	if len(pkt) == 0 {
		return true
	}
	switch pkt[0] {
	case packetERR:
		return true
	case packetEOF:
		return len(pkt) < 9
	case packetOK:
		return true
	default:
		return false
	}
}

// isTextResultRow validates a MySQL text-protocol row against the known column
// count. Each column is encoded as a length-encoded string or 0xFB NULL.
func isTextResultRow(pkt []byte, colCount uint64) bool {
	pos := 0
	for i := uint64(0); i < colCount; i++ {
		if pos >= len(pkt) {
			return false
		}
		if pkt[pos] == 0xFB { // NULL column value
			pos++
			continue
		}
		valueLen, n, err := readLenEnc(pkt, pos)
		if err != nil || n <= 0 {
			return false
		}
		pos += n
		if valueLen > uint64(len(pkt)-pos) {
			return false
		}
		pos += int(valueLen)
	}
	return pos == len(pkt)
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func firstByte(pkt []byte) byte {
	if len(pkt) == 0 {
		return 0
	}
	return pkt[0]
}

// hasMoreResults checks the SERVER_MORE_RESULTS_EXISTS flag (bit 3) in an OK/EOF packet.
func hasMoreResults(pkt []byte) bool {
	status, ok := mysqlStatusFlags(pkt)
	return ok && status&0x0008 != 0
}

func mysqlStatusFlags(pkt []byte) (uint16, bool) {
	if len(pkt) < 3 {
		return 0, false
	}
	var statusOffset int
	if pkt[0] == packetOK {
		pos := 1
		_, n, err := readLenEnc(pkt, pos)
		if err != nil {
			return 0, false
		}
		pos += n
		_, n, err = readLenEnc(pkt, pos)
		if err != nil {
			return 0, false
		}
		pos += n
		statusOffset = pos
	} else if pkt[0] == packetEOF {
		statusOffset = 3
	} else {
		return 0, false
	}
	if statusOffset+2 > len(pkt) {
		return 0, false
	}
	return uint16(pkt[statusOffset]) | uint16(pkt[statusOffset+1])<<8, true
}

// readLenEnc reads a length-encoded integer from b at position pos.
// Returns (value, bytes_consumed, error).
func readLenEnc(b []byte, pos int) (uint64, int, error) {
	if pos >= len(b) {
		return 0, 0, fmt.Errorf("lenenc: out of bounds")
	}
	switch b[pos] {
	case 0xFB:
		return 0, 1, nil // NULL
	case 0xFC:
		if pos+3 > len(b) {
			return 0, 0, fmt.Errorf("lenenc 2-byte: truncated")
		}
		return uint64(b[pos+1]) | uint64(b[pos+2])<<8, 3, nil
	case 0xFD:
		if pos+4 > len(b) {
			return 0, 0, fmt.Errorf("lenenc 3-byte: truncated")
		}
		return uint64(b[pos+1]) | uint64(b[pos+2])<<8 | uint64(b[pos+3])<<16, 4, nil
	case 0xFE:
		if pos+9 > len(b) {
			return 0, 0, fmt.Errorf("lenenc 8-byte: truncated")
		}
		return binary.LittleEndian.Uint64(b[pos+1 : pos+9]), 9, nil
	default:
		return uint64(b[pos]), 1, nil
	}
}

func extractErrMessage(pkt []byte) string {
	// ERR: 0xFF + error_code(2) + '#' + sqlstate(5) + message
	if len(pkt) < 9 {
		return "unknown error"
	}
	return string(pkt[9:])
}

// stripSSLCapability removes the CLIENT_SSL bit from the server greeting payload
// so the client does not attempt an SSL handshake through the proxy.
// The capability flags are at a fixed offset inside the greeting payload:
//
//	1 byte  protocol version
//	N bytes server version (null-terminated)
//	4 bytes connection ID
//	8 bytes auth-plugin-data-1
//	1 byte  filler
//	2 bytes capability flags lower  ← clear bit 11 here
//	1 byte  character set
//	2 bytes status flags
//	2 bytes capability flags upper  ← clear bit (11-16)=none needed, SSL is bit 11 (lower)
func stripSSLCapability(raw []byte) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)

	// Locate capability-flags-lower in the MySQL greeting payload.
	// Layout:
	//   protocol_version(1)
	//   server_version(null-terminated)
	//   connection_id(4)
	//   auth_plugin_data_part_1(8)
	//   filler(1)
	//   capability_flags_lower(2)
	pos := 1
	for pos < len(out) && out[pos] != 0 {
		pos++
	}
	pos++    // null terminator
	pos += 4 // connection ID
	pos += 8 // auth-plugin-data part 1
	pos += 1 // filler

	// Need lower caps at pos and upper caps at pos+5.
	// Between them are charset(1) and status_flags(2).
	if pos+7 > len(out) {
		return out
	}

	lower := binary.LittleEndian.Uint16(out[pos : pos+2])
	upper := binary.LittleEndian.Uint16(out[pos+5 : pos+7])
	caps := uint32(lower) | uint32(upper)<<16

	// Strip capabilities the proxy cannot synthesize correctly.
	caps &^= capClientSSL
	caps &^= capClientDeprecateEOF
	caps &^= capClientOptionalResultsetMetadata

	binary.LittleEndian.PutUint16(out[pos:pos+2], uint16(caps&0xffff))
	binary.LittleEndian.PutUint16(out[pos+5:pos+7], uint16(caps>>16))

	return out
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
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
	Mode                    string                   `json:"mode"`
	Rows                    []map[string]interface{} `json:"rows"`
	Count                   *int                     `json:"count"`
	AffectedRows            *int                     `json:"affected_rows"`
	Columns                 []string                 `json:"columns"`
	ColumnTypes             []string                 `json:"column_types"`
	Tables                  []string                 `json:"tables"`
	Databases               []string                 `json:"databases"`
	LatencyMS               int                      `json:"latency_ms"`
	ErrorMsg                string                   `json:"error_msg"`
	ErrorCode               int                      `json:"error_code"`
	SQLState                string                   `json:"sqlstate"`
	Profile                 string                   `json:"profile"`
	Explanation             string                   `json:"explanation"`
	IsTrap                  bool                     `json:"is_trap"`
	EventSchemaVersion      string                   `json:"event_schema_version"`
	WorldID                 string                   `json:"world_id"`
	AssetID                 string                   `json:"asset_id"`
	AssetKind               string                   `json:"asset_kind"`
	TrapTriggered           bool                     `json:"trap_triggered"`
	TrapID                  string                   `json:"trap_id"`
	TrapKind                string                   `json:"trap_kind"`
	TrapMitreTechniqueID    string                   `json:"trap_mitre_technique_id"`
	TrapRiskScore           float64                  `json:"trap_risk_score"`
	StrategyID              string                   `json:"strategy_id"`
	StrategyRegistryVersion string                   `json:"strategy_registry_version"`
}

func (h *Handler) deceptionBreakerOpen() (bool, time.Time) {
	deceptionBreaker.mu.Lock()
	defer deceptionBreaker.mu.Unlock()

	now := time.Now()
	if now.Before(deceptionBreaker.openUntil) {
		return true, deceptionBreaker.openUntil
	}

	if !deceptionBreaker.openUntil.IsZero() {
		deceptionBreaker.failures = 0
		deceptionBreaker.openUntil = time.Time{}
	}

	return false, time.Time{}
}

func (h *Handler) recordDeceptionSuccess() {
	deceptionBreaker.mu.Lock()
	defer deceptionBreaker.mu.Unlock()

	deceptionBreaker.failures = 0
	deceptionBreaker.openUntil = time.Time{}
}

func (h *Handler) recordDeceptionFailure(protocol string, reason string) {
	deceptionBreaker.mu.Lock()
	defer deceptionBreaker.mu.Unlock()

	deceptionBreaker.failures++
	if deceptionBreaker.failures >= deceptionFailureThreshold {
		deceptionBreaker.openUntil = time.Now().Add(deceptionBreakerCooldown)
		h.logger.Warn(
			"deception-engine circuit breaker opened",
			"protocol", protocol,
			"failures", deceptionBreaker.failures,
			"cooldown_seconds", int(deceptionBreakerCooldown/time.Second),
			"reason", reason,
		)
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

	if open, openUntil := h.deceptionBreakerOpen(); open {
		h.logger.Warn(
			"deception-engine circuit breaker open; passthrough",
			"protocol", protocol,
			"open_until", openUntil.Format(time.RFC3339),
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
		h.logger.Debug("deception request marshal failed", "err", err)
		return nil, false
	}

	url := os.Getenv("DECEPTION_ENGINE_URL")
	if url == "" {
		url = "http://deception-engine:8001/decide"
	}

	callCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		h.logger.Debug("deception request create failed", "err", err)
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

	mode := strings.ToLower(dec.Mode)
	if mode != "fake" && mode != "block" {
		return nil, false
	}
	if mode == "block" {
		return &dec, true
	}

	normalizeDecisionShape(&dec, protocol)
	if len(dec.Columns) == 0 && !isDeceptionMutationSQL(normalized) {
		return nil, false
	}

	return &dec, true
}

func (h *Handler) sendMySQLDeceptionResult(dec *deceptionDecisionResponse) error {
	if dec.LatencyMS > 0 {
		time.Sleep(time.Duration(dec.LatencyMS) * time.Millisecond)
	}
	if strings.EqualFold(dec.Mode, "block") {
		return h.sendMySQLDeceptionError(dec.ErrorCode, dec.SQLState, dec.ErrorMsg)
	}
	if len(dec.Columns) == 0 && dec.AffectedRows != nil {
		return h.sendMySQLDeceptionOK(*dec.AffectedRows)
	}

	rows := decisionRowsAsMySQLBytes(dec)

	columns := make([]mysqlTrapColumn, 0, len(dec.Columns))
	for index, name := range dec.Columns {
		columns = append(columns, mysqlDecisionColumn(name, decisionColumnType(dec, index)))
	}

	seq := byte(1)

	// Result-set header: column count.
	if err := h.sendPacket(h.clientConn, writeLenEncInt(uint64(len(columns))), seq); err != nil {
		return err
	}
	seq++

	// Column definitions. These must be full MySQL ColumnDefinition41 packets;
	// sending only the raw column name causes ERROR 2027: Malformed packet.
	for _, col := range columns {
		if err := h.sendPacket(h.clientConn, buildMySQLColumnDefinition(col), seq); err != nil {
			return err
		}
		seq++
	}

	// EOF after column definitions.
	if err := h.sendPacket(h.clientConn, mysqlEOFPacket(), seq); err != nil {
		return err
	}
	seq++

	// Text rows.
	for _, row := range rows {
		if err := h.sendPacket(h.clientConn, buildMySQLNullableTextRow(row), seq); err != nil {
			return err
		}
		seq++
	}

	// EOF after rows.
	if err := h.sendPacket(h.clientConn, mysqlEOFPacket(), seq); err != nil {
		return err
	}

	if h.sess != nil {
		h.sess.IncrBytesOut(1)
	}
	return nil
}

func (h *Handler) sendMySQLDeceptionOK(affectedRows int) error {
	if affectedRows < 0 {
		affectedRows = 0
	}
	pkt := []byte{packetOK}
	pkt = append(pkt, writeLenEncInt(uint64(affectedRows))...)
	pkt = append(pkt, 0x00)                   // last insert id
	pkt = append(pkt, 0x02, 0x00, 0x00, 0x00) // autocommit, warnings=0
	return h.sendPacket(h.clientConn, pkt, 1)
}

func (h *Handler) sendMySQLDeceptionError(code int, sqlState, message string) error {
	if code <= 0 || code > 65535 {
		code = 1064
	}
	if len(sqlState) != 5 {
		sqlState = "42000"
	}
	if message == "" {
		message = "You have an error in your SQL syntax"
	}
	pkt := []byte{packetERR, byte(code), byte(code >> 8), '#'}
	pkt = append(pkt, []byte(sqlState)...)
	pkt = append(pkt, []byte(message)...)
	return h.sendPacket(h.clientConn, pkt, 1)
}

func (h *Handler) notifyDeceptionSession(ctx context.Context, action string) {
	if h.sess == nil || (action != "start" && action != "end") {
		return
	}
	baseURL := os.Getenv("DECEPTION_ENGINE_URL")
	if baseURL == "" {
		baseURL = "http://deception-engine:8001/decide"
	}
	url := strings.TrimSuffix(baseURL, "/decide") + "/session/" + action
	body, _ := json.Marshal(map[string]string{"session_id": safeSessionID(h)})
	callCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.logger.Warn("deception session lifecycle notification failed", "action", action)
		return
	}
	resp.Body.Close()
}

func normalizeDecisionShape(dec *deceptionDecisionResponse, protocol string) {
	_ = protocol
	if len(dec.Columns) == 0 && len(dec.Rows) > 0 {
		for k := range dec.Rows[0] {
			dec.Columns = append(dec.Columns, k)
		}
		sort.Strings(dec.Columns)
	}

	if len(dec.Rows) == 0 && len(dec.Tables) > 0 {
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

	if len(dec.Rows) == 0 && len(dec.Databases) > 0 {
		col := "Database"
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
		dec.Columns = []string{"COUNT(*)"}
		dec.Rows = []map[string]interface{}{{"COUNT(*)": *dec.Count}}
	}
}

func decisionRowsAsMySQLBytes(dec *deceptionDecisionResponse) [][][]byte {
	rows := make([][][]byte, 0, len(dec.Rows))
	for _, src := range dec.Rows {
		row := make([][]byte, len(dec.Columns))
		for i, col := range dec.Columns {
			if v, ok := src[col]; ok && v != nil {
				row[i] = []byte(formatDecisionValue(v, decisionColumnType(dec, i)))
			} else {
				row[i] = nil
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func decisionColumnType(dec *deceptionDecisionResponse, index int) string {
	if index >= 0 && index < len(dec.ColumnTypes) {
		return strings.ToLower(dec.ColumnTypes[index])
	}
	return "text"
}

func mysqlDecisionColumn(name, typeName string) mysqlTrapColumn {
	column := mysqlTrapColumn{Name: name, Type: 0xfd, Charset: 33, Length: 255}
	switch typeName {
	case "integer", "int", "int4":
		column.Type, column.Charset, column.Length = 0x03, 63, 11
	case "bigint", "int8":
		column.Type, column.Charset, column.Length = 0x08, 63, 20
	case "numeric", "decimal", "double precision":
		column.Type, column.Charset, column.Length = 0xf6, 63, 32
	case "boolean", "bool":
		column.Type, column.Charset, column.Length = 0x01, 63, 1
	case "date":
		column.Type, column.Charset, column.Length = 0x0a, 63, 10
	case "timestamp", "timestamp without time zone", "datetime":
		column.Type, column.Charset, column.Length = 0x0c, 63, 19
	}
	return column
}

func formatDecisionValue(value interface{}, typeName string) string {
	switch typed := value.(type) {
	case bool:
		if typed {
			return "1"
		}
		return "0"
	case float64:
		switch typeName {
		case "integer", "int", "int4", "bigint", "int8":
			return fmt.Sprintf("%.0f", typed)
		case "numeric", "decimal":
			return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.10f", typed), "0"), ".")
		default:
			return fmt.Sprintf("%v", typed)
		}
	default:
		return fmt.Sprint(value)
	}
}

func buildMySQLNullableTextRow(values [][]byte) []byte {
	var pkt []byte
	for _, value := range values {
		if value == nil {
			pkt = append(pkt, 0xfb)
			continue
		}
		pkt = append(pkt, writeLenEncInt(uint64(len(value)))...)
		pkt = append(pkt, value...)
	}
	return pkt
}

func shouldConsultDeceptionEngine(sql string) bool {
	q := normalizeDeceptionSQL(sql)

	if strings.HasPrefix(q, "show ") {
		return true
	}
	if strings.HasPrefix(q, "describe ") || strings.HasPrefix(q, "desc ") {
		return true
	}
	if strings.Contains(q, "@@") || strings.Contains(q, "version()") || strings.Contains(q, "database()") {
		return true
	}
	if strings.Contains(q, "information_schema.") || strings.Contains(q, "pg_catalog.") {
		return true
	}
	if strings.Contains(q, "pg_tables") || strings.Contains(q, "pg_class") || strings.Contains(q, "pg_namespace") || strings.Contains(q, "pg_database") {
		return true
	}
	if strings.HasPrefix(q, "select ") && extractDeceptionTableName(q) != "" {
		return true
	}
	if strings.HasPrefix(q, "insert ") || strings.HasPrefix(q, "update ") || strings.HasPrefix(q, "delete ") {
		return true
	}
	return false
}

func normalizeDeceptionSQL(sql string) string {
	q := strings.TrimSpace(strings.ToLower(sql))
	q = strings.TrimSuffix(q, ";")
	return strings.Join(strings.Fields(q), " ")
}

func deceptionFingerprint(normalized string) string {
	sum := sha1.Sum([]byte(normalized))
	return fmt.Sprintf("%x", sum[:8])
}

func inferDeceptionPhase(normalized string) string {
	switch {
	case strings.Contains(normalized, "information_schema.") ||
		strings.Contains(normalized, "pg_catalog.") ||
		strings.HasPrefix(normalized, "show databases") ||
		strings.HasPrefix(normalized, "show schemas") ||
		strings.HasPrefix(normalized, "show tables") ||
		strings.HasPrefix(normalized, "show full tables") ||
		strings.HasPrefix(normalized, "show columns") ||
		strings.Contains(normalized, "pg_tables") ||
		strings.Contains(normalized, "pg_class") ||
		strings.Contains(normalized, "pg_namespace") ||
		strings.Contains(normalized, "pg_database"):
		return "enumeration"
	case containsDeceptionTrapTable(normalized):
		return "data_discovery"
	case strings.Contains(normalized, "mysql.user") ||
		strings.Contains(normalized, "show grants") ||
		strings.Contains(normalized, "pg_roles") ||
		strings.Contains(normalized, "has_table_privilege") ||
		strings.Contains(normalized, "has_schema_privilege"):
		return "privilege_discovery"
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
	if strings.Contains(normalized, "information_schema.") ||
		strings.Contains(normalized, "pg_catalog.") ||
		strings.HasPrefix(normalized, "show ") {
		return 2
	}
	return 1
}

func inferDeceptionRisk(normalized string) float64 {
	if containsDeceptionTrapTable(normalized) {
		return 12.0
	}
	if strings.Contains(normalized, "information_schema.") ||
		strings.Contains(normalized, "pg_catalog.") ||
		strings.HasPrefix(normalized, "show ") {
		return 7.0
	}
	return 0.0
}

func extractDeceptionTableName(sql string) string {
	if match := regexp.MustCompile(`(?i)\b(?:from|join|update|into)\s+(?:[a-z_][a-z0-9_$]*\.)?([a-z_][a-z0-9_$]*)`).FindStringSubmatch(sql); len(match) == 2 {
		return strings.ToLower(match[1])
	}
	tokens := sqlRelationTokensForDeception(sql)
	for i, tok := range tokens {
		switch tok {
		case "from", "join", "update", "into", "table":
			if i+1 < len(tokens) {
				return tokens[i+1]
			}
		case "describe", "desc":
			if i+1 < len(tokens) {
				return tokens[i+1]
			}
		}
	}

	if len(tokens) >= 4 && tokens[0] == "show" && (tokens[1] == "columns" || tokens[1] == "fields") && tokens[2] == "from" {
		return tokens[3]
	}

	return ""
}

func isDeceptionMutationSQL(sql string) bool {
	q := strings.TrimSpace(strings.ToLower(sql))
	return strings.HasPrefix(q, "insert ") || strings.HasPrefix(q, "update ") || strings.HasPrefix(q, "delete ")
}

func sqlRelationTokensForDeception(sql string) []string {
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

func containsDeceptionTrapTable(sql string) bool {
	q := normalizeDeceptionSQL(sql)
	traps := []string{
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
	for _, trap := range traps {
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// scrambleSHA1 produces mysql_native_password challenge response.
// Kept for reference — actual auth is forwarded transparently.
func scrambleSHA1(password string, seed []byte) []byte {
	if password == "" {
		return nil
	}
	hash1 := sha1.Sum([]byte(password))
	hash2 := sha1.Sum(hash1[:])

	combined := append(seed, hash2[:]...)
	hash3 := sha1.Sum(combined)

	result := make([]byte, sha1.Size)
	for i := range result {
		result[i] = hash1[i] ^ hash3[i]
	}
	return result
}

// Ensure scrambleSHA1 is referenced to avoid compiler complaint
var _ = scrambleSHA1
