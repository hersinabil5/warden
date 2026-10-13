package session

import (
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRedisLoggerWritesJSON(t *testing.T) {
	var b strings.Builder
	RedisLogger{Logger: slog.New(slog.NewJSONHandler(&b, nil))}.Printf(t.Context(), "dial %s: %v", "127.0.0.1:6379", "refused")
	var m map[string]any
	if err := json.Unmarshal([]byte(b.String()), &m); err != nil {
		t.Fatalf("not JSON: %q", b.String())
	}
	if m["level"] != "WARN" || m["detail"] != "dial 127.0.0.1:6379: refused" {
		t.Errorf("log = %v", m)
	}
}
