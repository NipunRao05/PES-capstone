package protocol

import (
	"context"
	"github.com/mysqlproxy/internal/principal"
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

// Receipt follows successful response writes; persistence failures never rewrite
// SQL output or mark the transaction failed. No payload/error details are logged.
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
	body := map[string]interface{}{"session_id": safeSessionID(h), "protocol": "mysql",
		"username": safeUsername(h), "database": safeDatabase(h), "sql": sql, "transaction_active": h.sess.Snapshot().InTransaction}
	body["traffic_origin"] = h.evidenceContext().TrafficOrigin
	body["deployment_manifest_id"] = h.evidenceContext().DeploymentManifestID
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
		event["traffic_origin"] = h.evidenceContext().TrafficOrigin
		event["deployment_manifest_id"] = h.evidenceContext().DeploymentManifestID
		h.pub.EmitPrincipal(event)
	}
}
