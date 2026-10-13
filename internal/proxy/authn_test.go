package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hersinabil5/warden/internal/session"
)

// allowAll authenticates every request as a fixed user.
type allowAll struct{}

func (allowAll) Authenticate(http.ResponseWriter, *http.Request, string) (*session.Session, bool) {
	return &session.Session{Subject: "test-user"}, true
}

// denyAll rejects every request the way authn does for a missing session.
type denyAll struct{ hosts []string }

func (d *denyAll) Authenticate(w http.ResponseWriter, _ *http.Request, host string) (*session.Session, bool) {
	d.hosts = append(d.hosts, host)
	w.Header().Set("Location", "https://auth.example.test/.warden/login")
	w.WriteHeader(http.StatusFound)
	return nil, false
}

func TestUnauthenticatedRequestsNeverReachUpstream(t *testing.T) {
	up := newEcho(t)
	deny := &denyAll{}
	h, err := New(testConfig(t, up.URL), Options{Authenticator: deny, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		req := httptest.NewRequestWithContext(t.Context(), m, "/anything", nil)
		req.Host = "app.example.test"
		rec := serve(h, req)
		if rec.Code != http.StatusFound {
			t.Errorf("%s: status = %d, want the authenticator's response", m, rec.Code)
		}
	}
	if up.hits.Load() != 0 {
		t.Errorf("upstream got %d unauthenticated requests", up.hits.Load())
	}
	if len(deny.hosts) != 3 || deny.hosts[0] != "app.example.test" {
		t.Errorf("authenticator saw hosts %v", deny.hosts)
	}
}

func TestNilAuthenticatorFailsClosed(t *testing.T) {
	up := newEcho(t)
	h, err := New(testConfig(t, up.URL), Options{Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	if rec := serve(h, req); rec.Code != http.StatusForbidden || up.hits.Load() != 0 {
		t.Errorf("status = %d, upstream hits = %d; want 403 and none", rec.Code, up.hits.Load())
	}
}

func TestWardenCookiesNotForwarded(t *testing.T) {
	up := newEcho(t)
	h, err := New(testConfig(t, up.URL), Options{
		Authenticator: allowAll{}, Logger: slog.New(slog.DiscardHandler),
		CookieNames: []string{"_warden", "__Host-warden_*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	req.Header.Add("Cookie", "_warden=secret-session; app=1")
	req.Header.Add("Cookie", "__Host-warden_hs_abc=hs-secret;  grafana_session=g ; _warden2=keep")
	seen := decodeSeen(t, serve(h, req))
	got := strings.Join(seen.Header.Values("Cookie"), "; ")
	if strings.Contains(got, "secret") {
		t.Errorf("upstream saw Warden cookies: %q", got)
	}
	for _, want := range []string{"app=1", "grafana_session=g", "_warden2=keep"} {
		if !strings.Contains(got, want) {
			t.Errorf("app cookie %q dropped: %q", want, got)
		}
	}

	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	req.Header.Set("Cookie", "_warden=only-warden")
	if seen := decodeSeen(t, serve(h, req)); seen.Header.Get("Cookie") != "" {
		t.Errorf("empty Cookie header forwarded: %q", seen.Header.Get("Cookie"))
	}
}

func TestUpstreamCannotSetWardenCookies(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "_warden=attacker-session; Path=/")
		w.Header().Add("Set-Cookie", "__Host-warden_hs_x=planted; Path=/; Secure")
		w.Header().Add("Set-Cookie", "app=ok; Path=/")
	}))
	defer up.Close()
	h, err := New(testConfig(t, up.URL), Options{
		Authenticator: allowAll{}, Logger: slog.New(slog.DiscardHandler),
		CookieNames: []string{"_warden", "__Host-warden_*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	got := serve(h, req).Header().Values("Set-Cookie")
	if len(got) != 1 || !strings.HasPrefix(got[0], "app=ok") {
		t.Errorf("Set-Cookie = %q, want only the app's own cookie", got)
	}
}
