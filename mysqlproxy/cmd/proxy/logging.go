package main

import (
	"log/slog"
	"os"
	"regexp"
	"strings"
)

var operationalSecretPattern = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b["']?\s*[:=]\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}]+)`)
var operationalSecrets = []string{
	os.Getenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET"), os.Getenv("POSTGRES_PASSWORD"),
	os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_ROOT_PASSWORD"),
}

func safeLogAttr(_ []string, a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if key == "time" {
		a.Key = "timestamp"
	}
	if key == "msg" {
		a.Key = "message"
	}
	if key == "sql" || key == "query" || key == "query_raw" || key == "query_normalized" ||
		key == "fingerprint" || key == "payload" || key == "raw_payload" || key == "columns" || strings.Contains(key, "password") ||
		strings.Contains(key, "secret") || strings.Contains(key, "verifier") ||
		strings.Contains(key, "token") || strings.Contains(key, "credential") ||
		key == "authorization" || key == "api_key" || key == "pwd" || key == "passwd" {
		return slog.String(a.Key, "[REDACTED]")
	}
	// Error objects may include backend-controlled messages. Keep the category
	// and fixed surrounding event text, not an arbitrary error's payload.
	if key == "err" || key == "error" {
		return slog.String("error_category", "operation_failed")
	}
	if a.Value.Kind() == slog.KindString {
		value := a.Value.String()
		for _, secret := range operationalSecrets {
			if len(secret) >= 4 {
				value = strings.ReplaceAll(value, secret, "[REDACTED]")
			}
		}
		value = operationalSecretPattern.ReplaceAllString(value, "$1=[REDACTED]")
		a.Value = slog.StringValue(value)
	}
	return a
}
