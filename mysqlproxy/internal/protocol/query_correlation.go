package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/mysqlproxy/internal/interceptor"
	"strings"
	"time"
)

func validExecutionID(id string) bool {
	if id != strings.ToLower(id) || len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil
}
func (h *Handler) beginQuery() {
	h.queryCorrelation = interceptor.QueryCorrelation{RequestStartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		h.queryCorrelation = interceptor.QueryCorrelation{}
		return
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h.queryCorrelation.QueryExecutionID = fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}
func (h *Handler) acceptCorrelation(c *interceptor.QueryCorrelation) {
	if c == nil || c.QueryExecutionID != h.queryCorrelation.QueryExecutionID || !validExecutionID(c.QueryExecutionID) || !validExecutionID(c.DecisionID) || !validExecutionID(c.ApplicationID) {
		return
	}
	h.queryCorrelation.DecisionID = c.DecisionID
	h.queryCorrelation.ApplicationID = c.ApplicationID
}
