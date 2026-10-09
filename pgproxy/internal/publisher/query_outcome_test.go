package publisher

import (
	"context"
	"encoding/json"
	"github.com/pgproxy/internal/interceptor"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestQueryOutcomeSerialization(t *testing.T) {
	p := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	events := make(chan interceptor.QueryEvent, 1)
	events <- interceptor.QueryEvent{SessionID: "synthetic", OutcomeVerified: true, Success: false, Authority: "deception", ErrorCode: "test_error", StrategyID: "D3", DeceptionProfile: "high_value_target", IsTrap: true}
	close(events)
	p.wg.Add(1)
	p.ingestLoop(context.Background(), events)
	select {
	case raw := <-p.rawBuf:
		if !raw.OutcomeVerified || raw.Success || raw.Authority != "deception" || raw.ErrorCode != "test_error" || raw.StrategyID != "D3" || raw.DeceptionProfile != "high_value_target" || !raw.IsTrap {
			t.Fatal(raw)
		}

		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]interface{}
		json.Unmarshal(data, &decoded)
		for _, key := range []string{"trap_id", "asset_id", "world_id"} {
			if decoded[key] != "" {
				t.Fatalf("invented %s: %v", key, decoded[key])
			}
		}
		if _, ok := decoded["result_source"]; ok {
			t.Fatal("duplicate authority field")
		}
	case <-time.After(time.Second):
		t.Fatal("no raw event")
	}
}
func TestUnverifiedQuerySerialization(t *testing.T) {
	p := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	events := make(chan interceptor.QueryEvent, 1)
	events <- interceptor.QueryEvent{}
	close(events)
	p.wg.Add(1)
	p.ingestLoop(context.Background(), events)
	raw := <-p.rawBuf
	if raw.OutcomeVerified || raw.Success || raw.Authority != "unknown" || raw.StrategyID != "" || raw.DeceptionProfile != "" {
		t.Fatal(raw)
	}
}
