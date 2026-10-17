package authn

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hersinabil5/warden/internal/config"
)

func limitedFlow(t *testing.T, perMinute, burst int) *flowEnv {
	t.Helper()
	return newFlowEnv(t, func(c *config.Config) {
		c.RateLimits.Login = &config.RateLimit{PerMinute: perMinute, Burst: burst}
	})
}

// from serves one request as the client at remote, with extra headers.
func (e *flowEnv) from(t *testing.T, remote, target string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

const loginURL = "https://" + testAuthDomain + LoginPath

func TestLoginFloodIsLimited(t *testing.T) {
	e := limitedFlow(t, 1, 3)
	for i := range 3 {
		if rec := e.from(t, "192.0.2.7:1000", loginURL, nil); rec.Code != http.StatusFound {
			t.Fatalf("login %d within burst: status %d", i+1, rec.Code)
		}
	}
	rec := e.from(t, "192.0.2.7:1001", loginURL, nil) // another port, same client
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login past the burst: status %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60 (1/min)", got)
	}
	if rec.Header().Get("Location") != "" || len(rec.Result().Cookies()) != 0 {
		t.Error("a limited login still started a flow")
	}
	if !strings.Contains(e.logs.String(), `"msg":"rate limited"`) {
		t.Error("rate limiting was not logged")
	}
	// Another client is unaffected.
	if rec := e.from(t, "198.51.100.1:1000", loginURL, nil); rec.Code != http.StatusFound {
		t.Errorf("other client: status %d, want 302", rec.Code)
	}
}

// Forwarding headers are client-written; they must not pick the bucket.
func TestLoginLimitIgnoresForwardingHeaders(t *testing.T) {
	e := limitedFlow(t, 1, 1)
	e.from(t, "192.0.2.7:1000", loginURL, nil)
	for i, hdr := range []map[string]string{
		{"X-Forwarded-For": "203.0.113.1"},
		{"X-Real-IP": "203.0.113.2"},
		{"Forwarded": "for=203.0.113.3"},
		{"True-Client-IP": "203.0.113.4", "CF-Connecting-IP": "203.0.113.5"},
	} {
		if rec := e.from(t, "192.0.2.7:1000", loginURL, hdr); rec.Code != http.StatusTooManyRequests {
			t.Errorf("headers %d %v escaped the limit: status %d", i, hdr, rec.Code)
		}
	}
}

func TestLoginLimitGroupsIPv6By64(t *testing.T) {
	e := limitedFlow(t, 1, 1)
	e.from(t, "[2001:db8:1:2::1]:1000", loginURL, nil)
	if rec := e.from(t, "[2001:db8:1:2:dead:beef:0:1]:1000", loginURL, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("new address in the same /64: status %d, want 429", rec.Code)
	}
	if rec := e.from(t, "[2001:db8:1:3::1]:1000", loginURL, nil); rec.Code != http.StatusFound {
		t.Errorf("another /64: status %d, want 302", rec.Code)
	}
}

// The callback shares the login bucket and is refused before anything
// reaches the IdP or the session store.
func TestCallbackIsLimitedBeforeCodeExchange(t *testing.T) {
	e := limitedFlow(t, 1, 1)
	cb, pre := e.begin(t, "") // spends the only token
	rec := e.from(t, "192.0.2.1:1234", cb, nil, pre)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("callback: status %d, want 429", rec.Code)
	}
	if e.idp.TokenHits() != 0 {
		t.Error("a limited callback reached the token endpoint")
	}
	if e.sessionCount() != 0 {
		t.Error("a limited callback created a session")
	}
}

// Only the IdP-facing endpoints are limited; the session page is not.
func TestSessionPageIsNotLimited(t *testing.T) {
	e := limitedFlow(t, 1, 1)
	e.from(t, "192.0.2.7:1000", loginURL, nil)
	if rec := e.from(t, "192.0.2.7:1000", "https://"+testAuthDomain+SessionPath, nil); rec.Code != http.StatusOK {
		t.Errorf("session page: status %d, want 200", rec.Code)
	}
}
