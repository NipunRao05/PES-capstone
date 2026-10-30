package protocol

import (
	"context"
	"github.com/pgproxy/internal/principal"
)

type principalDecision struct {
	deceptionDecisionResponse
	principal.Context
	Token                 string                   `json:"token"`
	ServerFirst           string                   `json:"server_first"`
	ServerFinal           string                   `json:"server_final"`
	CommandTag            string                   `json:"command_tag"`
	TxStatus              string                   `json:"tx_status"`
	Depth                 int                      `json:"post_return_exploration_depth"`
	Events                []map[string]interface{} `json:"events"`
	ObservationCandidates []string                 `json:"observation_candidates"`
}

// Called only after the complete synthetic response writes succeed. Failure is
// internal: the SQL response has already been sent and must not be rewritten.
func (h *Handler) acknowledgeObservations(ctx context.Context, result principalDecision) {
	if !h.virtual || result.Mode != "fake" || len(result.ObservationCandidates) == 0 {
		return
	}
	var receipt struct {
		Status    string `json:"status"`
		Conflicts int    `json:"conflicts"`
	}
	err := principal.Call(ctx, "observe", map[string]interface{}{
		"session_id": safeSessionID(h), "observation_candidates": result.ObservationCandidates}, &receipt)
	if err != nil || receipt.Status != "ok" || receipt.Conflicts != 0 {
		h.logger.Warn("principal observation acknowledgement failed")
	}
}

func (h *Handler) principalQuery(ctx context.Context, sql string) principalDecision {
	action := "query"
	if !h.virtual {
		action = "command"
	}
	body := map[string]interface{}{"session_id": safeSessionID(h), "protocol": "postgres",
		"username": safeUsername(h), "database": safeDatabase(h), "sql": sql, "transaction_active": h.currentTxStatus() != 'I',
		"transaction_state": h.postgresTransactionState()}
	body["query_execution_id"] = h.queryCorrelation.QueryExecutionID
	body["request_started_at"] = h.queryCorrelation.RequestStartedAt
	var result principalDecision
	if err := principal.Call(ctx, action, body, &result); err != nil {
		result.Correlation = nil
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
	h.acceptCorrelation(result.Correlation)
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
