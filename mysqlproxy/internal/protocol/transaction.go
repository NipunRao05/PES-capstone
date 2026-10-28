package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var mysqlTransactionEnd = regexp.MustCompile(`^(commit|rollback)(?: work)?(?: and (?:no )?chain)?(?: (?:no )?release)?$`)

func (h *Handler) deceptionStatus() uint16 {
	if h.virtual {
		return h.principalStatus()
	}
	if h.sess == nil {
		return 2
	}
	snap := h.sess.Snapshot()
	var status uint16
	if snap.AutoCommit {
		status |= 2
	}
	if snap.InTransaction || h.deceptionTxDirty {
		status |= 1
	}
	return status
}

// A synthetic write with autocommit disabled needs a snapshot even if no
// physical table has yet caused MySQL to set SERVER_STATUS_IN_TRANS.
func (h *Handler) deceptionTransactionState() string {
	if h.sess != nil {
		snap := h.sess.Snapshot()
		if snap.InTransaction || !snap.AutoCommit || h.deceptionTxDirty {
			return "in_transaction"
		}
	}
	return "idle"
}

// Called only for a successful backend OK, before that OK is sent to the client.
// Physical commit/rollback stays with MySQL; we finalize only the session overlay.
func (h *Handler) finalizeDeceptionTransaction(ctx context.Context, pkt []byte) error {
	if !h.deceptionTxDirty || h.virtual || len(pkt) == 0 || pkt[0] != packetOK || h.deceptionTransactionSQL == "" {
		return nil
	}
	status, ok := mysqlStatusFlags(pkt)
	if !ok || hasMoreResults(pkt) {
		return nil
	}
	q := normalizeDeceptionSQL(h.deceptionTransactionSQL)
	action := ""
	if match := mysqlTransactionEnd.FindStringSubmatch(q); match != nil {
		action = match[1]
	} else if q == "begin" || q == "begin work" || strings.HasPrefix(q, "start transaction") {
		// MySQL starts a fresh transaction by committing the previous one.
		action = "commit"
	} else if h.sess != nil && status&1 == 0 && (h.sess.Snapshot().InTransaction || status&2 != 0) {
		// A successful native implicit commit (including SET autocommit=1).
		action = "commit"
	}
	if action == "" {
		return nil
	}
	baseURL := os.Getenv("DECEPTION_ENGINE_URL")
	if baseURL == "" {
		baseURL = "http://deception-engine:8001/decide"
	}
	body, err := json.Marshal(map[string]string{"session_id": safeSessionID(h)})
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost,
		strings.TrimSuffix(baseURL, "/decide")+"/transaction/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("finalize deceptive transaction: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("deception transaction endpoint returned %d", resp.StatusCode)
	}
	h.deceptionTxDirty = false
	return nil
}
