package protocol

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/jackc/pgproto3/v2"
	"github.com/pgproxy/internal/interceptor"
	"github.com/pgproxy/internal/principal"
	"github.com/pgproxy/internal/publisher"
	"io"
	"strings"
	"time"
)

func (h *Handler) readPrincipalPassword() ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(h.clientConn, header); err != nil {
		return nil, errors.New("authentication failed")
	}
	n := int(binary.BigEndian.Uint32(header[1:]))
	if header[0] != 'p' || n < 4 || n > 1024 {
		return nil, errors.New("authentication failed")
	}
	payload := make([]byte, n-4)
	_, err := io.ReadFull(h.clientConn, payload)
	return payload, err
}

func (h *Handler) authenticatePrincipal() (err error) {
	h.virtual = true
	_ = h.backendConn.Close() // No synthetic username/startup is ever sent to a backend.
	h.authMethod = "scram-sha-256"
	_ = h.clientConn.SetDeadline(time.Now().Add(15 * time.Second))
	defer h.clientConn.SetDeadline(time.Time{})
	defer func() {
		if err != nil {
			_ = h.sendToClient(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		}
		if h.pub != nil {
			h.pub.EmitAuth(publisher.AuthEvent{Context: h.sess.Context, EventType: "auth", SessionID: h.sess.ID,
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ClientIP: h.sess.ClientIP, Username: h.sess.Username,
				Database: h.sess.Database, AuthMethod: h.authMethod, Success: err == nil})
		}
	}()
	if h.sess.Database != "testdb" {
		return errors.New("authentication failed")
	}
	if err = h.sendToClient(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}}); err != nil {
		return err
	}
	first, e := h.readPrincipalPassword()
	if e != nil {
		return e
	}
	index := strings.IndexByte(string(first), 0)
	if index < 0 || string(first[:index]) != "SCRAM-SHA-256" || len(first) < index+5 {
		return errors.New("authentication failed")
	}
	n := int(binary.BigEndian.Uint32(first[index+1 : index+5]))
	if n != len(first)-index-5 {
		return errors.New("authentication failed")
	}
	var challenge principal.Reply
	if err = principal.Call(context.Background(), "scram-start", map[string]interface{}{
		"session_id": h.sess.ID, "username": h.sess.Username, "client_first": string(first[index+5:])}, &challenge); err != nil {
		return err
	}
	if err = h.sendToClient(&pgproto3.AuthenticationSASLContinue{Data: []byte(challenge.ServerFirst)}); err != nil {
		return err
	}
	final, e := h.readPrincipalPassword()
	if e != nil {
		return e
	}
	var reply principal.Reply
	if err = principal.Call(context.Background(), "scram-finish", map[string]interface{}{
		"session_id": h.sess.ID, "token": challenge.Token, "client_final": string(final)}, &reply); err != nil {
		return err
	}
	if reply.DeceptivePrincipalID == "" || !strings.HasPrefix(reply.ServerFinal, "v=") {
		return errors.New("authentication failed")
	}
	h.sess.Context = reply.Context
	for _, msg := range []pgproto3.BackendMessage{
		&pgproto3.AuthenticationSASLFinal{Data: []byte(reply.ServerFinal)}, &pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"},
		&pgproto3.ParameterStatus{Name: "server_encoding", Value: "UTF8"},
		&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
		&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"},
		&pgproto3.ParameterStatus{Name: "integer_datetimes", Value: "on"},
		&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	} {
		if err = h.sendToClient(msg); err != nil {
			return err
		}
	}
	h.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(h.clientConn), h.clientConn)
	h.publishPrincipalEvents(reply.Events)
	return nil
}

func (h *Handler) servePrincipalQuery(ctx context.Context, sql string) error {
	result := h.principalQuery(ctx, sql)
	if h.virtual && len(result.TxStatus) == 1 {
		h.sess.SetTxStatus(result.TxStatus[0])
	}
	var err error
	if result.Mode == "fake" && result.CommandTag != "" {
		err = h.sendToClient(&pgproto3.CommandComplete{CommandTag: []byte(result.CommandTag)})
		if err == nil {
			err = h.sendToClient(&pgproto3.ReadyForQuery{TxStatus: h.currentTxStatus()})
		}
	} else {
		err = h.sendPostgresDeceptionResult(&result.deceptionDecisionResponse, sql)
	}
	if err != nil {
		return err
	}
	code := ""
	if result.Mode != "fake" {
		code = result.SQLState
	}
	h.emitSimpleOutcome(principal.Redact(sql), interceptor.QueryOutcome{Verified: true, Success: result.Mode == "fake",
		Authority: "deception", ErrorCode: code, TransactionState: h.postgresTransactionState(), StrategyID: result.StrategyID,
		DeceptionProfile: result.Profile, IsTrap: result.IsTrap, PostReturnExplorationDepth: result.Depth})
	return nil
}

// Extended account statements are rejected before Parse/Bind can retain secrets.
// PostgreSQL requires discarding subsequent messages through Sync after this error.
func (h *Handler) rejectPrincipalExtended() error {
	h.principalExtendedError = true
	if h.currentTxStatus() == 'T' {
		h.sess.SetTxStatus('E')
	}
	return h.sendToClient(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "0A000", Message: "Use a single simple query for this operation"})
}

func (h *Handler) principalLoop(ctx context.Context) error {
	for {
		msg, err := h.clientBackend.Receive()
		if err != nil {
			if isEOF(err) {
				return nil
			}
			return err
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			return nil
		}
		if _, ok := msg.(*pgproto3.Sync); ok {
			h.principalExtendedError = false
			if err = h.sendToClient(&pgproto3.ReadyForQuery{TxStatus: h.currentTxStatus()}); err != nil {
				return err
			}
			continue
		}
		if h.principalExtendedError {
			continue
		}
		if q, ok := msg.(*pgproto3.Query); ok {
			if err = h.servePrincipalQuery(ctx, q.String); err != nil {
				return err
			}
			continue
		}
		if err = h.rejectPrincipalExtended(); err != nil {
			return err
		}
	}
}
