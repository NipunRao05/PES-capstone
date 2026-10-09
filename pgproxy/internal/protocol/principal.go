package protocol

import (
	"context"
	"github.com/pgproxy/internal/principal"
)

type principalDecision struct {
	deceptionDecisionResponse
	principal.Context
	Token       string                   `json:"token"`
	ServerFirst string                   `json:"server_first"`
	ServerFinal string                   `json:"server_final"`
	CommandTag  string                   `json:"command_tag"`
	TxStatus    string                   `json:"tx_status"`
	Depth       int                      `json:"post_return_exploration_depth"`
	Events      []map[string]interface{} `json:"events"`
}

func (h *Handler) principalQuery(ctx context.Context, sql string) principalDecision {
	action := "query"
	if !h.virtual {
		action = "command"
	}
	body := map[string]interface{}{"session_id": safeSessionID(h), "protocol": "postgres",
		"username": safeUsername(h), "database": safeDatabase(h), "sql": sql, "transaction_active": h.currentTxStatus() != 'I'}
	var result principalDecision
	if err := principal.Call(ctx, action, body, &result); err != nil {
		result.Mode = "block"
		result.ErrorCode = 1045
		result.SQLState = "58000"
		result.ErrorMsg = "Account service unavailable"
	}
	if result.Mode != "fake" && result.Mode != "block" {
		result.Mode = "block"
		result.ErrorCode = 1235
		result.SQLState = "0A000"
		result.ErrorMsg = "Unsupported operation"
	}
	if result.Mode == "fake" {
		h.publishPrincipalEvents(result.Events)
	}
	return result
}

func (h *Handler) publishPrincipalEvents(events []map[string]interface{}) {
	if h.pub == nil {
		return
	}
	for _, event := range events {
		h.pub.EmitPrincipal(event)
	}
}
