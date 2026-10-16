package proxy

import (
	"bufio"
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// asUser authenticates every request as the given session.
type asUser struct{ s *session.Session }

func (a asUser) Authenticate(http.ResponseWriter, *http.Request, string) (*session.Session, bool) {
	return a.s, true
}

var (
	testNow   = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	aliceSess = &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins", "sre"},
		AMR: []string{"pwd", "otp"}, AuthTime: testNow.Add(-time.Minute)}
	bobSess = &session.Session{Subject: "b-1", Username: "bob", Groups: []string{"dev"},
		AMR: []string{"pwd"}, AuthTime: testNow.Add(-time.Minute)}
)

// policyConfig has whoami (any user) and grafana (sre/admins; /admin needs
// admins with recent MFA), as in config/warden.example.yaml.
func policyConfig(t *testing.T, upstream string, caseInsensitive bool) *config.Config {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Auth:     config.Auth{Domain: "auth.example.test"},
		Identity: config.Identity{Header: "X-Warden-Identity"},
		Routes: []config.Route{
			{Host: "whoami.example.test", UpstreamURL: u, Policy: anyUser},
			{Host: "grafana.example.test", UpstreamURL: u, Policy: config.Policy{
				Allow: []config.Rule{{Groups: []string{"sre", "admins"}}},
				Paths: []config.PathRule{{Prefix: "/admin", Allow: []config.Rule{
					{Groups: []string{"admins"}, RequireMFAWithin: ptr(10 * time.Minute)},
				}}},
				CaseInsensitivePaths: caseInsensitive,
			}},
			{Host: "app.example.test", UpstreamURL: u, Policy: config.Policy{
				Allow:                []config.Rule{{Authenticated: ptr(true)}},
				Paths:                []config.PathRule{{Prefix: "/admin", Allow: []config.Rule{{Groups: []string{"admins"}}}}},
				CaseInsensitivePaths: caseInsensitive,
			}},
		},
	}
}

func policyHandler(t *testing.T, cfg *config.Config, s *session.Session, logs *bytes.Buffer) *Handler {
	t.Helper()
	h, err := New(cfg, Options{Audit: nopAudit{}, Identity: testIdentity(t),
		Authenticator: asUser{s},
		Logger:        slog.New(slog.NewJSONHandler(logs, nil)),
		Now:           func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// wireRequest parses target from a raw request line, as the server does, so
// RequestURI and URL agree. ok is false if net/http itself rejects it.
func wireRequest(t *testing.T, target, host string) (req *http.Request, ok bool) {
	t.Helper()
	raw := "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		return nil, false
	}
	return req.WithContext(t.Context()), true
}

// PLAN.md M3 acceptance: bob reaches whoami but not Grafana; alice both.
func TestPolicyGatesRoutes(t *testing.T) {
	up := newEcho(t)
	cfg := policyConfig(t, up.URL, false)
	for _, tt := range []struct {
		user *session.Session
		host string
		want int
	}{
		{bobSess, "whoami.example.test", http.StatusOK},
		{bobSess, "grafana.example.test", http.StatusForbidden},
		{aliceSess, "whoami.example.test", http.StatusOK},
		{aliceSess, "grafana.example.test", http.StatusOK},
		{aliceSess, "grafana.example.test/admin/users", http.StatusOK},
	} {
		var logs bytes.Buffer
		h := policyHandler(t, cfg, tt.user, &logs)
		host, path, _ := strings.Cut(tt.host, "/")
		before := up.hits.Load()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/"+path, nil)
		req.Host = host
		rec := serve(h, req)
		if rec.Code != tt.want {
			t.Errorf("%s on %s: status %d, want %d", tt.user.Username, tt.host, rec.Code, tt.want)
		}
		if reached := up.hits.Load() != before; reached != (tt.want == http.StatusOK) {
			t.Errorf("%s on %s: reached upstream = %v", tt.user.Username, tt.host, reached)
		}
	}
}

// A denial shows the request ID and nothing about the policy; the rule and
// reason go to the log.
func TestDeniedPageHidesRuleDetails(t *testing.T) {
	up := newEcho(t)
	var logs bytes.Buffer
	h := policyHandler(t, policyConfig(t, up.URL, false), bobSess, &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/admin/users", nil)
	req.Host = "grafana.example.test"
	rec := serve(h, req)

	id := rec.Header().Get(RequestIDHeader)
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden || id == "" || !strings.Contains(body, id) {
		t.Fatalf("status %d, body %q; want 403 page with request ID", rec.Code, body)
	}
	for _, leak := range []string{"admins", "paths[", "allow[", "group", "mfa", "MFA", "bob", "/admin"} {
		if strings.Contains(body, leak) {
			t.Errorf("403 page reveals %q:\n%s", leak, body)
		}
	}
	log := logs.String()
	for _, want := range []string{`"msg":"access denied"`, `"rule":"paths[/admin]"`, `"user":"bob"`, `"request_id":"` + id + `"`} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %s:\n%s", want, log)
		}
	}
}

// PLAN.md M3 acceptance: with a rule protecting /admin, every spelling of it
// is denied for bob, by policy (403) or as an ambiguous path (400). None
// reaches the upstream.
func TestAdminPathSpellingsDenied(t *testing.T) {
	up := newEcho(t)
	for _, ci := range []bool{false, true} {
		var logs bytes.Buffer
		h := policyHandler(t, policyConfig(t, up.URL, ci), bobSess, &logs)
		paths := []string{
			"/admin", "//admin", "/foo/../admin", "/%61dmin", "/admin/", "/admin/x",
			"/admin%2F", "/admin%2fx", "/%252e%252e/admin", "/./admin", "/x/%2e%2e/admin",
			"/admin;x", "/..;/admin", `/admin\`, "/%2e%2e%5cadmin", "/admin%00",
		}
		if ci {
			paths = append(paths, "/ADMIN", "/Admin/x", "//aDmIn/")
		}
		for _, p := range paths {
			before := up.hits.Load()
			req, ok := wireRequest(t, p, "app.example.test")
			if !ok {
				continue // net/http refuses it before Warden runs
			}
			rec := serve(h, req)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusBadRequest {
				t.Errorf("case-insensitive=%v %q: status %d, want 403 or 400", ci, p, rec.Code)
			}
			if up.hits.Load() != before {
				t.Errorf("case-insensitive=%v %q reached the upstream", ci, p)
			}
		}
	}
	// Control: the same handler lets bob through elsewhere, and alice in.
	var logs bytes.Buffer
	h := policyHandler(t, policyConfig(t, up.URL, true), bobSess, &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/administrator", nil)
	req.Host = "app.example.test"
	if rec := serve(h, req); rec.Code != http.StatusOK {
		t.Errorf("bob /administrator: %d, want 200", rec.Code)
	}
	// Case-sensitive by default: /ADMIN is a different path from /admin.
	h = policyHandler(t, policyConfig(t, up.URL, false), bobSess, &logs)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ADMIN", nil)
	req.Host = "app.example.test"
	if rec := serve(h, req); rec.Code != http.StatusOK {
		t.Errorf("bob /ADMIN (case-sensitive): %d, want 200", rec.Code)
	}
	h = policyHandler(t, policyConfig(t, up.URL, true), aliceSess, &logs)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ADMIN", nil)
	req.Host = "app.example.test"
	if rec := serve(h, req); rec.Code != http.StatusOK {
		t.Errorf("alice /ADMIN: %d, want 200", rec.Code)
	}
}

// Invariant 6: the upstream receives the path policy evaluated.
func TestUpstreamReceivesNormalizedPath(t *testing.T) {
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL))
	for in, want := range map[string]string{
		"/a//b/../c?q=1":                  "/a/c?q=1",
		"/%61dmin":                        "/admin",
		"/x/%2e%2e/y":                     "/y",
		"/a%20b":                          "/a%20b",
		"/caf%C3%A9":                      "/caf%C3%A9",
		"/100%25":                         "/100%25",
		"/a%3Fb?x=%2F&y=..":               "/a%3Fb?x=%2F&y=..", // the query is passed through untouched
		"https://app.example.test//x/./y": "/x/y",              // absolute-form
		"https://app.example.test?z=1":    "/?z=1",
	} {
		req, ok := wireRequest(t, in, "app.example.test")
		if !ok {
			t.Fatalf("%q: not a valid request target", in)
		}
		if seen := decodeSeen(t, serve(h, req)); seen.URI != want {
			t.Errorf("%q: upstream got %q, want %q", in, seen.URI, want)
		}
	}
}

// Ambiguous paths are refused before authentication or routing.
func TestAmbiguousPathRejectedFirst(t *testing.T) {
	up := newEcho(t)
	deny := &denyAll{}
	h, err := New(testConfig(t, up.URL), Options{Audit: nopAudit{}, Identity: testIdentity(t), Authenticator: deny, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/a%2Fb", "/%252e", "/a;b", "*"} {
		req, ok := wireRequest(t, p, "app.example.test")
		if !ok {
			t.Fatalf("%q: not a valid request target", p)
		}
		rec := serve(h, req)
		id := rec.Header().Get(RequestIDHeader)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), id) {
			t.Errorf("%q: status %d, want 400 page with request ID", p, rec.Code)
		}
	}
	if len(deny.hosts) != 0 || up.hits.Load() != 0 {
		t.Errorf("ambiguous paths reached authentication (%d) or the upstream (%d)", len(deny.hosts), up.hits.Load())
	}
}

// A session without policy-relevant data is denied, not allowed.
func TestNilSessionIsDenied(t *testing.T) {
	up := newEcho(t)
	var logs bytes.Buffer
	h := policyHandler(t, testConfig(t, up.URL), nil, &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	if rec := serve(h, req); rec.Code != http.StatusForbidden || up.hits.Load() != 0 {
		t.Errorf("status %d, upstream hits %d; want 403 and none", rec.Code, up.hits.Load())
	}
}
