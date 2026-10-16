package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventJSONSchema(t *testing.T) {
	ev := Event{
		Time:      time.Date(2026, 10, 16, 14, 0, 0, 123456789, time.FixedZone("CEST", 2*3600)),
		RequestID: "req-1",
		User:      "alice",
		Session:   "0123456789ab",
		Host:      "grafana.warden.localhost",
		Method:    "GET",
		Path:      "/admin/users",
		Decision:  Allow,
		Rule:      "paths[/admin]",
		Reason:    "allowed",
		Latency:   1500 * time.Microsecond,
		Status:    200,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"time":       "2026-10-16T12:00:00.123456789Z", // UTC
		"request_id": "req-1",
		"user":       "alice",
		"session":    "0123456789ab",
		"host":       "grafana.warden.localhost",
		"method":     "GET",
		"path":       "/admin/users",
		"decision":   "allow",
		"rule":       "paths[/admin]",
		"reason":     "allowed",
		"latency_ms": 1.5,
		"status":     float64(200),
	}
	if len(got) != len(want) {
		t.Errorf("fields = %v, want exactly %d", got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
}

// Anything that is not an explicit allow is recorded as a deny, so a
// forgotten or corrupted decision never reads as access granted.
func TestDecisionFailsClosed(t *testing.T) {
	for _, d := range []Decision{"", "ALLOW", "allowed", "maybe", Deny} {
		b, err := json.Marshal(Event{Decision: d})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"decision":"deny"`) {
			t.Errorf("decision %q encoded as %s", d, b)
		}
	}
}

func TestSessionPrefix(t *testing.T) {
	full := strings.Repeat("ab", 32) // a 64-hex SHA-256
	if got := SessionPrefix(full); got != full[:SessionPrefixLen] || len(got) != 12 {
		t.Errorf("SessionPrefix = %q", got)
	}
	for _, short := range []string{"", "abc"} {
		if got := SessionPrefix(short); got != short {
			t.Errorf("SessionPrefix(%q) = %q", short, got)
		}
	}
}
