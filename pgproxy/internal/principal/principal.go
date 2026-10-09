// Package principal implements the private, fail-closed deception registry boundary.
package principal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Context struct {
	DeceptivePrincipalID string `json:"deceptive_principal_id,omitempty"`
	PrincipalOrigin      string `json:"principal_origin,omitempty"`
	CreatorSessionID     string `json:"creator_session_id,omitempty"`
	IsReturnSession      bool   `json:"is_return_session,omitempty"`
}

type Reply struct {
	Context
	Token       string                   `json:"token"`
	ServerFirst string                   `json:"server_first"`
	ServerFinal string                   `json:"server_final"`
	Mode        string                   `json:"mode"`
	CommandTag  string                   `json:"command_tag"`
	TxStatus    string                   `json:"tx_status"`
	Depth       int                      `json:"post_return_exploration_depth"`
	Events      []map[string]interface{} `json:"events"`
}

var client = &http.Client{Timeout: 4 * time.Second}
var executableComments = regexp.MustCompile(`(?s)/\*![0-9]*\s*(.*?)\*/`)
var comments = regexp.MustCompile(`(?s)/\*.*?\*/|--[^\r\n]*`)
var accountSQL = regexp.MustCompile(`(?i)\b(create|alter|drop)\s+(user|role)\b|\b(grant|revoke)\b|\bset\s+password\b|\bidentified\s+by\b|\bpassword\s*(=|')|^\s*(do|call|prepare|execute)\b`)

// The namespace is reserved even during registry outages. Never backend-fallback.
func Reserved(username string) bool { return strings.HasPrefix(strings.ToLower(username), "fake_") }
func AccountSQL(sql string) bool {
	return accountSQL.MatchString(sql) || accountSQL.MatchString(comments.ReplaceAllString(executableComments.ReplaceAllString(sql, "$1"), " "))
}
func Redact(sql string) string {
	if AccountSQL(sql) {
		return "/* credential/account statement redacted */"
	}
	return sql
}

func Call(ctx context.Context, action string, body map[string]interface{}, result interface{}) error {
	secret := os.Getenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET")
	decoded, err := base64.StdEncoding.DecodeString(secret)
	if err != nil || len(decoded) < 32 {
		return errors.New("account service unavailable")
	}
	url := strings.TrimSuffix(os.Getenv("DECEPTION_ENGINE_URL"), "/decide")
	if url == "" {
		return errors.New("account service unavailable")
	}
	if body == nil {
		body = map[string]interface{}{}
	}
	body["deadline_ms"] = time.Now().Add(2500 * time.Millisecond).UnixMilli()
	raw, err := json.Marshal(body)
	if err != nil {
		return errors.New("invalid account request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/principals/"+action, bytes.NewReader(raw))
	if err != nil {
		return errors.New("account service unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Deceptive-Principal-Key", secret)
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("account service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("account operation rejected")
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(result); err != nil {
		return errors.New("invalid account response")
	}
	return nil
}
