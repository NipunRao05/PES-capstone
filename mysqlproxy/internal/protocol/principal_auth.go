package protocol

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/mysqlproxy/internal/interceptor"
	"github.com/mysqlproxy/internal/principal"
	"github.com/mysqlproxy/internal/shaper"
	"time"
)

func (h *Handler) authenticatePrincipal() error {
	var result principal.Reply
	err := errors.New("authentication failed")
	if h.authMethod == "mysql_native_password" && h.sess.Database == "testdb" {
		err = principal.Call(context.Background(), "native-auth", map[string]interface{}{
			"session_id": h.sess.ID, "username": h.sess.Username,
			"salt":       base64.StdEncoding.EncodeToString(h.principalAuthSalt),
			"auth_token": base64.StdEncoding.EncodeToString(h.principalAuthToken)}, &result)
	}
	h.principalAuthSalt = nil
	h.principalAuthToken = nil
	if err != nil || result.DeceptivePrincipalID == "" {
		_ = h.sendPacket(h.clientConn, shaper.BuildErrPacket(1045, "28000", "Access denied"), 2)
		return errors.New("authentication failed")
	}
	h.sess.Context = result.Context
	if err = h.sendPacket(h.clientConn, []byte{0, 0, 0, 2, 0, 0, 0}, 2); err != nil {
		return err
	}
	h.publishPrincipalEvents(result.Events)
	return nil
}

func (h *Handler) principalStatus() uint16 {
	if h.sess.Snapshot().InTransaction {
		return 3
	}
	return 2
}
func (h *Handler) principalOK(rows int) error {
	if rows < 0 {
		rows = 0
	}
	pkt := append([]byte{0}, writeLenEncInt(uint64(rows))...)
	status := h.principalStatus()
	pkt = append(pkt, 0, byte(status), byte(status>>8), 0, 0)
	return h.sendPacket(h.clientConn, pkt, 1)
}

func (h *Handler) servePrincipalQuery(ctx context.Context, sql string) error {
	result := h.principalQuery(ctx, sql)
	if h.virtual && result.TxStatus != "" {
		h.sess.SetTransactionStatus(result.TxStatus != "I", true)
	}
	var err error
	if result.Mode == "fake" && result.CommandTag != "" {
		err = h.principalOK(0)
	} else {
		err = h.sendMySQLDeceptionResult(&result.deceptionDecisionResponse)
	}
	if err != nil {
		return err
	}
	code, state := "", ""
	if result.Mode != "fake" {
		code = fmt.Sprintf("mysql_%d", result.ErrorCode)
		state = result.SQLState
	}
	h.emitTextQueryOutcome(principal.Redact(sql), interceptor.QueryOutcome{Verified: true, Success: result.Mode == "fake",
		Authority: "deception", ErrorCode: code, SQLState: state, TransactionState: h.mysqlTransactionState(),
		StrategyID: result.StrategyID, DeceptionProfile: result.Profile, IsTrap: result.IsTrap, PostReturnExplorationDepth: result.Depth})
	return nil
}

func (h *Handler) principalLoop(ctx context.Context) error {
	for {
		if h.idleTimeout > 0 {
			_ = h.clientConn.SetReadDeadline(time.Now().Add(h.idleTimeout))
		}
		pkt, err := h.readPacket(h.clientConn)
		if err != nil {
			if isEOF(err) {
				return nil
			}
			return err
		}
		if len(pkt) == 0 {
			return errors.New("empty command")
		}
		switch pkt[0] {
		case comQuit:
			return nil
		case comQuery:
			err = h.servePrincipalQuery(ctx, cleanMySQLQueryPayload(pkt[1:]))
		case comPing:
			err = h.principalOK(0)
		default:
			err = h.sendMySQLDeceptionError(1235, "0A000", "Unsupported synthetic operation")
		}
		if err != nil {
			return err
		}
	}
}
