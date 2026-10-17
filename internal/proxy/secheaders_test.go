package proxy

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

const testHSTS = "max-age=31536000"

// secHandler serves policyConfig as bob, with every kind of Warden endpoint
// mounted: auth, JWKS, and admin (logged out). The fake handlers set no
// headers, so whatever arrives was added by the proxy.
func secHandler(t *testing.T, upstream string, hsts time.Duration) *Handler {
	t.Helper()
	cfg := policyConfig(t, upstream, false)
	down, _ := url.Parse("http://127.0.0.1:1") // nothing listens there
	cfg.Routes = append(cfg.Routes, config.Route{Host: "down.example.test", UpstreamURL: down, Policy: anyUser})
	blank := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h, err := New(cfg, Options{
		Audit: nopAudit{}, Identity: testIdentity(t), Authenticator: asUser{bobSess},
		Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return testNow },
		Auth: blank, JWKS: blank, HSTSMaxAge: hsts,
		Admin: &AdminRoute{Handler: blank, Policy: adminPolicy(t), Sessions: mainAs{}, LoginPath: "/.warden/login"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// wardenResponses are responses Warden writes itself, one per kind of
// endpoint and failure.
var wardenResponses = []struct {
	name, host, target string
	sni                string
	want               int
}{
	{"unknown host", "evil.example", "/", "", http.StatusNotFound},
	{"ambiguous path", "whoami.example.test", "/a%2Fb", "", http.StatusBadRequest},
	{"misdirected", "whoami.example.test", "/", "grafana.example.test", http.StatusMisdirectedRequest},
	{"policy deny", "grafana.example.test", "/", "", http.StatusForbidden},
	{"upstream down", "down.example.test", "/", "", http.StatusBadGateway},
	{"reserved path on route host", "whoami.example.test", "/.warden/nothing", "", http.StatusOK},
	{"healthz", "whoami.example.test", HealthzPath, "", http.StatusOK},
	{"jwks", "auth.example.test", JWKSPath, "", http.StatusOK},
	{"auth endpoint", "auth.example.test", "/.warden/login", "", http.StatusOK},
	{"admin api logged out", "auth.example.test", "/.warden/api/me", "", http.StatusUnauthorized},
	{"dashboard logged out", "auth.example.test", "/.warden/admin/", "", http.StatusFound},
	{"auth host unknown path", "auth.example.test", "/", "", http.StatusNotFound},
}

func TestWardenResponsesCarrySecurityHeaders(t *testing.T) {
	h := secHandler(t, newEcho(t).URL, 365*24*time.Hour)
	for _, tt := range wardenResponses {
		t.Run(tt.name, func(t *testing.T) {
			req, ok := wireRequest(t, tt.target, tt.host)
			if !ok {
				t.Fatalf("bad test request %q", tt.target)
			}
			if tt.sni != "" {
				req.TLS = &tls.ConnectionState{ServerName: tt.sni}
			}
			rec := serve(h, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			want := map[string]string{
				"Strict-Transport-Security":  testHSTS,
				"X-Content-Type-Options":     "nosniff",
				"Referrer-Policy":            "no-referrer",
				"X-Frame-Options":            "DENY",
				"Cross-Origin-Opener-Policy": "same-origin",
			}
			for k, v := range want {
				if got := rec.Header().Values(k); len(got) != 1 || got[0] != v {
					t.Errorf("%s = %q, want exactly %q", k, got, v)
				}
			}
			csp := rec.Header().Values("Content-Security-Policy")
			if len(csp) != 1 || !strings.Contains(csp[0], "frame-ancestors 'none'") || !strings.Contains(csp[0], "default-src 'none'") {
				t.Errorf("Content-Security-Policy = %q, want one policy with default-src and frame-ancestors 'none'", csp)
			}
		})
	}
}

// A handler's own, stricter CSP wins over the default.
func TestWardenHandlerCSPIsKept(t *testing.T) {
	const own = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"
	h, err := New(testConfig(t, newEcho(t).URL), Options{
		Audit: nopAudit{}, Identity: testIdentity(t), Authenticator: allowAll{}, Logger: slog.New(slog.DiscardHandler),
		Auth: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Security-Policy", own)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.warden/session", nil)
	req.Host = "auth.example.test"
	if got := serve(h, req).Header().Values("Content-Security-Policy"); len(got) != 1 || got[0] != own {
		t.Errorf("CSP = %q, want the handler's own", got)
	}
}

// Apps keep their own page headers; only HSTS is Warden's, and an upstream
// cannot weaken or widen it.
func TestProxiedResponsesKeepAppHeaders(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hdr := w.Header()
		hdr.Set("Strict-Transport-Security", "max-age=0")
		hdr.Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		hdr.Set("X-Frame-Options", "SAMEORIGIN")
		hdr.Set("Content-Security-Policy", "frame-ancestors 'self'")
		hdr.Set("Referrer-Policy", "strict-origin")
	}))
	t.Cleanup(up.Close)
	h := secHandler(t, up.URL, 365*24*time.Hour)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "whoami.example.test"
	rec := serve(h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	for k, want := range map[string]string{
		"Strict-Transport-Security": testHSTS,
		"X-Frame-Options":           "SAMEORIGIN",
		"Content-Security-Policy":   "frame-ancestors 'self'",
		"Referrer-Policy":           "strict-origin",
	} {
		if got := rec.Header().Values(k); len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want exactly %q", k, got, want)
		}
	}
	// Headers the app did not send are not invented for it.
	for _, k := range []string{"Cross-Origin-Opener-Policy", "X-Content-Type-Options"} {
		if got := rec.Header().Values(k); len(got) != 0 {
			t.Errorf("%s = %q on a proxied response, want none", k, got)
		}
	}
}

func TestHSTSOff(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}))
	t.Cleanup(up.Close)
	h := secHandler(t, up.URL, 0)
	for _, host := range []string{"whoami.example.test", "evil.example"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Host = host
		// Warden is the only HSTS authority for its hosts, on or off.
		if got := serve(h, req).Header().Values("Strict-Transport-Security"); len(got) != 0 {
			t.Errorf("%s: Strict-Transport-Security = %q, want none", host, got)
		}
	}
}

func TestHSTSWholeSeconds(t *testing.T) {
	h := secHandler(t, newEcho(t).URL, 90*time.Minute+500*time.Millisecond)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "evil.example"
	if got := serve(h, req).Header().Get("Strict-Transport-Security"); got != "max-age=5400" {
		t.Errorf("Strict-Transport-Security = %q, want max-age=5400", got)
	}
}

func TestNewRejectsNegativeHSTS(t *testing.T) {
	_, err := New(testConfig(t, newEcho(t).URL), Options{
		Audit: nopAudit{}, Identity: testIdentity(t), Logger: slog.New(slog.DiscardHandler), HSTSMaxAge: -time.Second,
	})
	if err == nil {
		t.Fatal("New accepted a negative HSTS max-age")
	}
}
