package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// countingMain returns a fixed session and counts lookups, so tests can see
// whether a request got as far as the session store.
type countingMain struct {
	s     *session.Session
	calls atomic.Int64
}

func (c *countingMain) MainSession(*http.Request, string) (*session.Session, error) {
	c.calls.Add(1)
	return c.s, nil
}

// switchMain returns whichever session the test points it at.
type switchMain struct {
	s atomic.Pointer[session.Session]
}

func (m *switchMain) MainSession(*http.Request, string) (*session.Session, error) {
	return m.s.Load(), nil
}

var adminSess = &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins"},
	AMR: []string{"pwd", "otp"}, AuthTime: testNow.Add(-time.Minute), Hash: testSessionHash}

func limitedAdmin(t *testing.T, m MainAuthenticator, ip, sess config.RateLimit) (*Handler, *adminSpy, *auditLog, *echoUpstream) {
	t.Helper()
	up := newEcho(t)
	cfg := testConfig(t, up.URL)
	cfg.RateLimits = config.RateLimits{AdminIP: &ip, AdminSession: &sess}
	spy := &adminSpy{}
	log := &auditLog{}
	h, err := New(cfg, Options{
		Identity: testIdentity(t), Authenticator: allowAll{}, Audit: log,
		Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return testNow },
		Admin: &AdminRoute{Handler: spy, Policy: adminPolicy(t), Sessions: m, LoginPath: "/.warden/login"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, spy, log, up
}

func adminReq(t *testing.T, remote, path string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test"+path, nil)
	req.RemoteAddr = remote
	return req
}

var plenty = config.RateLimit{PerMinute: 100_000, Burst: 10_000}

// Floods from one client stop before the session lookup, so they never load
// Redis.
func TestAdminPerIPLimit(t *testing.T) {
	m := &countingMain{s: adminSess}
	h, spy, log, _ := limitedAdmin(t, m, config.RateLimit{PerMinute: 1, Burst: 2}, plenty)
	for range 2 {
		if rec := serve(h, adminReq(t, "192.0.2.7:1", "/.warden/api/me")); rec.Code != http.StatusOK {
			t.Fatalf("within burst: status %d", rec.Code)
		}
		log.only(t)
	}
	rec := serve(h, adminReq(t, "192.0.2.7:2", "/.warden/api/me"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("past burst: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %q, want 60", rec.Header().Get("Retry-After"))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("API 429 Content-Type = %q, want JSON", ct)
	}
	if m.calls.Load() != 2 || len(spy.got) != 2 {
		t.Errorf("session lookups %d, handler calls %d; want 2 and 2", m.calls.Load(), len(spy.got))
	}
	if ev := log.only(t); ev.Decision != audit.Deny || ev.Reason != "rate limited" || ev.Status != http.StatusTooManyRequests {
		t.Errorf("event = %+v, want a rate-limited deny", ev)
	}
	// A forged forwarding header is not a new client.
	req := adminReq(t, "192.0.2.7:3", "/.warden/api/me")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if rec := serve(h, req); rec.Code != http.StatusTooManyRequests {
		t.Errorf("X-Forwarded-For escaped the limit: status %d", rec.Code)
	}
	log.only(t)
	if rec := serve(h, adminReq(t, "198.51.100.1:1", "/.warden/api/me")); rec.Code != http.StatusOK {
		t.Errorf("other client: status %d, want 200", rec.Code)
	}
}

// A signed-in session is limited wherever it connects from.
func TestAdminPerSessionLimit(t *testing.T) {
	m := &switchMain{}
	m.s.Store(adminSess)
	h, _, log, _ := limitedAdmin(t, m, plenty, config.RateLimit{PerMinute: 1, Burst: 2})
	for i, ip := range []string{"192.0.2.1:1", "192.0.2.2:1"} {
		if rec := serve(h, adminReq(t, ip, "/.warden/api/me")); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, rec.Code)
		}
		log.only(t)
	}
	if rec := serve(h, adminReq(t, "192.0.2.3:1", "/.warden/api/me")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same session from a fresh IP: status %d, want 429", rec.Code)
	}
	if ev := log.only(t); ev.Reason != "rate limited" || ev.User != "alice" {
		t.Errorf("event = %+v, want a rate-limited deny for alice", ev)
	}
	other := *adminSess
	other.Hash = strings.Repeat("b", 64)
	m.s.Store(&other)
	if rec := serve(h, adminReq(t, "192.0.2.3:1", "/.warden/api/me")); rec.Code != http.StatusOK {
		t.Errorf("another session: status %d, want 200", rec.Code)
	}
}

func TestAdminLimitOnDashboardIsAPage(t *testing.T) {
	h, _, _, _ := limitedAdmin(t, &countingMain{s: adminSess}, config.RateLimit{PerMinute: 1, Burst: 1}, plenty)
	serve(h, adminReq(t, "192.0.2.7:1", "/.warden/admin/"))
	rec := serve(h, adminReq(t, "192.0.2.7:1", "/.warden/admin/"))
	if rec.Code != http.StatusTooManyRequests || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("dashboard 429: status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "Too many requests") {
		t.Errorf("429 page does not say why: %s", rec.Body.String())
	}
}

// The admin limits cover the admin endpoints only, not the apps.
func TestAdminLimitDoesNotTouchRoutes(t *testing.T) {
	one := config.RateLimit{PerMinute: 1, Burst: 1}
	h, _, _, up := limitedAdmin(t, &countingMain{s: adminSess}, one, one)
	for range 5 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Host = "app.example.test"
		req.RemoteAddr = "192.0.2.7:1"
		if rec := serve(h, req); rec.Code != http.StatusOK {
			t.Fatalf("app request: status %d", rec.Code)
		}
	}
	if up.hits.Load() != 5 {
		t.Errorf("upstream hits = %d", up.hits.Load())
	}
	if rec := serve(h, adminReq(t, "192.0.2.7:1", "/.warden/api/me")); rec.Code != http.StatusOK {
		t.Errorf("admin after app traffic: status %d, want 200", rec.Code)
	}
}
