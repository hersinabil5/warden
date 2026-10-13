package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// proxyThrough sends req to a Handler in front of the echo upstream and
// returns what the upstream saw plus the client-side response.
func proxyThrough(t *testing.T, req *http.Request) (seenRequest, *httptest.ResponseRecorder) {
	t.Helper()
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL))
	rec := serve(h, req)
	return decodeSeen(t, rec), rec
}

func appRequest(t *testing.T) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test:8443"
	req.RemoteAddr = "198.51.100.7:51234"
	return req
}

// Client-supplied forwarding headers are replaced, never appended to, so an
// upstream cannot be fooled about the client's address, host, or scheme.
func TestForwardingHeadersAreOverwritten(t *testing.T) {
	req := appRequest(t)
	req.TLS = &tls.ConnectionState{ServerName: "app.example.test"}
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	req.Header.Add("X-Forwarded-For", "5.6.7.8, 9.9.9.9")
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("Forwarded", "for=1.2.3.4;host=evil.example;proto=http")
	req.Header.Set("X-Real-IP", "1.2.3.4")

	seen, _ := proxyThrough(t, req)
	want := map[string][]string{
		"X-Forwarded-For":   {"198.51.100.7"},
		"X-Forwarded-Host":  {"app.example.test:8443"},
		"X-Forwarded-Proto": {"https"},
	}
	for name, v := range want {
		if got := seen.Header.Values(name); strings.Join(got, "|") != strings.Join(v, "|") {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	for _, name := range []string{"Forwarded", "X-Real-Ip"} {
		if got := seen.Header.Values(name); len(got) != 0 {
			t.Errorf("%s reached the upstream: %q", name, got)
		}
	}
}

func TestForwardedProtoWithoutTLS(t *testing.T) {
	seen, _ := proxyThrough(t, appRequest(t))
	if got := seen.Header.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http for a non-TLS request", got)
	}
}

func TestHopByHopRequestHeadersStripped(t *testing.T) {
	req := appRequest(t)
	req.Header.Set("Connection", "keep-alive, X-Secret-Hop")
	req.Header.Set("X-Secret-Hop", "must not pass")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic dXNlcjpwYXNz")
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Set("X-Normal", "kept")

	seen, _ := proxyThrough(t, req)
	for _, name := range []string{"X-Secret-Hop", "Keep-Alive", "Proxy-Authorization", "Proxy-Connection", "Upgrade"} {
		if got := seen.Header.Values(name); len(got) != 0 {
			t.Errorf("hop-by-hop %s reached the upstream: %q", name, got)
		}
	}
	if seen.Header.Get("X-Normal") != "kept" {
		t.Error("end-to-end header X-Normal was dropped")
	}
}

func TestHopByHopResponseHeadersStripped(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "internal")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Normal", "kept")
	}))
	defer up.Close()
	h := newTestHandler(t, testConfig(t, up.URL))

	rec := serve(h, appRequest(t))
	for _, name := range []string{"X-Upstream-Hop", "Keep-Alive"} {
		if got := rec.Header().Values(name); len(got) != 0 {
			t.Errorf("hop-by-hop %s reached the client: %q", name, got)
		}
	}
	if rec.Header().Get("X-Normal") != "kept" {
		t.Error("end-to-end response header dropped")
	}
}

var requestIDPattern = regexp.MustCompile(`^[A-Z2-7]{26,}$`)

// The request ID is Warden's: a client-supplied one is discarded, the
// upstream and client see the same value, and an upstream cannot override it.
func TestRequestIDIsWardens(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(RequestIDHeader, "upstream-chosen-id")
		_ = json.NewEncoder(w).Encode(seenRequest{Header: r.Header})
	}))
	defer up.Close()
	h := newTestHandler(t, testConfig(t, up.URL))

	req := appRequest(t)
	req.Header.Set(RequestIDHeader, "attacker-chosen-id")
	rec := serve(h, req)
	seen := decodeSeen(t, rec)

	clientIDs := rec.Header().Values(RequestIDHeader)
	if len(clientIDs) != 1 || !requestIDPattern.MatchString(clientIDs[0]) {
		t.Fatalf("client X-Request-ID = %q, want exactly one Warden ID", clientIDs)
	}
	if got := seen.Header.Values(RequestIDHeader); len(got) != 1 || got[0] != clientIDs[0] {
		t.Errorf("upstream X-Request-ID = %q, want %q", got, clientIDs[0])
	}
}

func TestRequestIDsAreUnique(t *testing.T) {
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL))
	seen := make(map[string]bool)
	for range 200 {
		req := appRequest(t)
		req.Host = "unknown.example" // cheap 404 path; still gets an ID
		id := serve(h, req).Header().Get(RequestIDHeader)
		if seen[id] {
			t.Fatalf("duplicate request ID %q", id)
		}
		seen[id] = true
	}
}

// One log line per request, without the query string (it can carry tokens or
// codes; invariant 9).
func TestRequestLogLine(t *testing.T) {
	up := newEcho(t)
	var buf bytes.Buffer
	h, err := New(testConfig(t, up.URL), Options{Identity: testIdentity(t),
		Authenticator: allowAll{},
		Logger:        slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login?code=SECRETCODE&token=SECRETTOKEN", nil)
	req.Host = "app.example.test"
	rec := serve(h, req)

	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil && m["msg"] == "request" {
			entry = m
		}
	}
	if entry == nil {
		t.Fatalf("no request log line in:\n%s", buf.String())
	}
	want := map[string]any{
		"request_id": rec.Header().Get(RequestIDHeader),
		"host":       "app.example.test",
		"method":     "POST",
		"path":       "/login",
		"status":     float64(200),
	}
	for k, v := range want {
		if entry[k] != v {
			t.Errorf("log %s = %v, want %v", k, entry[k], v)
		}
	}
	if _, ok := entry["duration_ms"]; !ok {
		t.Error("log line has no duration_ms")
	}
	if strings.Contains(buf.String(), "SECRET") {
		t.Errorf("query string leaked into logs:\n%s", buf.String())
	}
}
