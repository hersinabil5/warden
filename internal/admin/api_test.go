package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

const authOrigin = "https://auth.example.test:8443"

type fixture struct {
	h       http.Handler
	store   *session.Store
	recent  *audit.Recent
	admin   *session.Session
	adminID string
	bobIDs  []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := session.NewClient(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb, session.Options{AbsoluteTTL: 8 * time.Hour, IdleTimeout: time.Hour})
	f := &fixture{store: store, recent: audit.NewRecent(100)}
	var err error
	f.adminID, err = store.Create(t.Context(), session.Session{Subject: "sub-alice", Username: "alice",
		Groups: []string{"admins"}, AMR: []string{"pwd", "otp"}, RefreshToken: "alice-refresh-secret"})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		id, cerr := store.Create(t.Context(), session.Session{Subject: "sub-bob", Username: "bob", //nolint:gosec // G101: fake test token
			Groups: []string{"dev"}, RefreshToken: "bob-refresh-secret"})
		if cerr != nil {
			t.Fatal(cerr)
		}
		f.bobIDs = append(f.bobIDs, id)
	}
	if f.admin, err = store.Get(t.Context(), f.adminID); err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{Sessions: store, Decisions: f.recent, AuthOrigin: authOrigin, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

// do serves a request as the admin session (as the proxy would after
// authentication and policy).
func (f *fixture) do(t *testing.T, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequestWithContext(t.Context(), method, authOrigin+target, rd)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req = req.WithContext(WithSession(req.Context(), f.admin))
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// mutation returns the headers a legitimate dashboard request carries.
func (f *fixture) mutation() map[string]string {
	return map[string]string{
		"Content-Type":   "application/json",
		CSRFHeader:       f.admin.CSRFToken,
		"Origin":         authOrigin,
		"Sec-Fetch-Site": "same-origin",
	}
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("response not JSON: %v\n%s", err, rec.Body.String())
	}
	return v
}

func TestMe(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodGet, "/.warden/api/me", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	me := decode[map[string]any](t, rec)
	if me["user"] != "alice" || me["csrf_token"] != f.admin.CSRFToken || me["session"] != session.HashID(f.adminID)[:12] {
		t.Errorf("me = %v", me)
	}
	if strings.Contains(rec.Body.String(), "refresh") {
		t.Errorf("me leaks the refresh token: %s", rec.Body.String())
	}
	for k, want := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Type": "application/json",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestListSessions(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodGet, "/.warden/api/sessions?limit=2", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, secret := range []string{"refresh-secret", f.admin.CSRFToken, f.adminID, f.bobIDs[0], f.bobIDs[1]} {
		if strings.Contains(body, secret) {
			t.Errorf("listing leaks %q: %s", secret, body)
		}
	}
	page := decode[struct {
		Sessions []struct {
			ID      string `json:"id"`
			User    string `json:"user"`
			Current bool   `json:"current"`
		} `json:"sessions"`
		Total      int `json:"total"`
		NextOffset int `json:"next_offset"`
	}](t, rec)
	if len(page.Sessions) != 2 || page.Total != 3 || page.NextOffset != 2 {
		t.Fatalf("page = %+v", page)
	}
	rec = f.do(t, http.MethodGet, "/.warden/api/sessions?sub=sub-alice", "", nil)
	mine := decode[struct {
		Sessions []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"sessions"`
	}](t, rec)
	if len(mine.Sessions) != 1 || !mine.Sessions[0].Current || mine.Sessions[0].ID != session.HashID(f.adminID) {
		t.Errorf("alice's sessions = %+v", mine)
	}
	for _, bad := range []string{"?offset=-1", "?limit=x", "?offset=1e9x"} {
		if rec := f.do(t, http.MethodGet, "/.warden/api/sessions"+bad, "", nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, rec.Code)
		}
	}
}

func TestRevokeSession(t *testing.T) {
	f := newFixture(t)
	target := session.HashID(f.bobIDs[0])
	rec := f.do(t, http.MethodPost, "/.warden/api/sessions/revoke", `{"id":"`+target+`"}`, f.mutation())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := f.store.Get(t.Context(), f.bobIDs[0]); err == nil {
		t.Error("session survived revocation")
	}
	if _, err := f.store.Get(t.Context(), f.bobIDs[1]); err != nil {
		t.Errorf("other session revoked: %v", err)
	}
	// Again: it is gone.
	if rec := f.do(t, http.MethodPost, "/.warden/api/sessions/revoke", `{"id":"`+target+`"}`, f.mutation()); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke: %d, want 404", rec.Code)
	}
}

// PLAN.md M5 acceptance (API half): revoking bob's sessions ends all of them.
func TestRevokeUser(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodPost, "/.warden/api/users/revoke", `{"sub":"sub-bob"}`, f.mutation())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got := decode[map[string]int](t, rec); got["revoked"] != 2 {
		t.Errorf("revoked = %v", got)
	}
	for _, id := range f.bobIDs {
		if _, err := f.store.Get(t.Context(), id); err == nil {
			t.Error("bob session survived")
		}
	}
	if _, err := f.store.Get(t.Context(), f.adminID); err != nil {
		t.Errorf("admin session revoked: %v", err)
	}
}

// Every mutating endpoint refuses requests that lack any one of the CSRF
// defenses, and leaves the sessions alone.
func TestMutationsRequireCSRFDefenses(t *testing.T) {
	for _, ep := range []struct{ path, body string }{
		{"/.warden/api/sessions/revoke", `{"id":"ID"}`},
		{"/.warden/api/users/revoke", `{"sub":"sub-bob"}`},
	} {
		for _, tt := range []struct {
			name string
			edit func(h map[string]string, s *session.Session)
			body string
			want int
		}{
			{"no CSRF header", func(h map[string]string, _ *session.Session) { delete(h, CSRFHeader) }, "", http.StatusForbidden},
			{"wrong CSRF token", func(h map[string]string, _ *session.Session) { h[CSRFHeader] = "guess" }, "", http.StatusForbidden},
			{"token of another session", func(h map[string]string, _ *session.Session) { h[CSRFHeader] = strings.Repeat("A", 43) }, "", http.StatusForbidden},
			{"session without a token", func(h map[string]string, s *session.Session) { h[CSRFHeader] = ""; s.CSRFToken = "" }, "", http.StatusForbidden},
			{"cross-site fetch", func(h map[string]string, _ *session.Session) { h["Sec-Fetch-Site"] = "cross-site" }, "", http.StatusForbidden},
			{"same-site sibling", func(h map[string]string, _ *session.Session) { h["Sec-Fetch-Site"] = "same-site" }, "", http.StatusForbidden},
			{"foreign Origin", func(h map[string]string, _ *session.Session) { h["Origin"] = "https://evil.example" }, "", http.StatusForbidden},
			{"null Origin", func(h map[string]string, _ *session.Session) { h["Origin"] = "null" }, "", http.StatusForbidden},
			{"form content type", func(h map[string]string, _ *session.Session) { h["Content-Type"] = "application/x-www-form-urlencoded" }, "", http.StatusUnsupportedMediaType},
			{"text/plain", func(h map[string]string, _ *session.Session) { h["Content-Type"] = "text/plain" }, "", http.StatusUnsupportedMediaType},
			{"unknown field", nil, `{"sub":"sub-bob","id":"x","all":true}`, http.StatusBadRequest},
			{"trailing data", nil, `{"sub":"sub-bob"}{"sub":"sub-alice"}`, http.StatusBadRequest},
			{"oversized body", nil, `{"sub":"` + strings.Repeat("a", 8<<10) + `"}`, http.StatusBadRequest},
			{"not JSON", nil, `sub=sub-bob`, http.StatusBadRequest},
		} {
			t.Run(ep.path+"/"+tt.name, func(t *testing.T) {
				f := newFixture(t)
				h := f.mutation()
				if tt.edit != nil {
					tt.edit(h, f.admin)
				}
				body := strings.ReplaceAll(ep.body, "ID", session.HashID(f.bobIDs[0]))
				if tt.body != "" {
					body = tt.body
				}
				rec := f.do(t, http.MethodPost, ep.path, body, h)
				if rec.Code != tt.want {
					t.Errorf("status %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
				}
				for _, id := range f.bobIDs {
					if _, err := f.store.Get(t.Context(), id); err != nil {
						t.Errorf("session revoked despite refusal: %v", err)
					}
				}
			})
		}
	}
}

func TestMutationsAreNotGETs(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/.warden/api/sessions/revoke?id=" + session.HashID(f.bobIDs[0]), "/.warden/api/users/revoke?sub=sub-bob"} {
		if rec := f.do(t, http.MethodGet, p, "", nil); rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
			t.Errorf("GET %s: %d", p, rec.Code)
		}
	}
	if _, err := f.store.Get(t.Context(), f.bobIDs[0]); err != nil {
		t.Errorf("GET revoked a session: %v", err)
	}
}

// Without a session in the context (a wiring mistake) nothing is served.
func TestNoSessionFailsClosed(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, authOrigin+"/.warden/api/me", nil)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "alice") {
		t.Errorf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDecisions(t *testing.T) {
	f := newFixture(t)
	for i, e := range []audit.Event{
		{User: "bob", Host: "grafana.example.test", Decision: audit.Deny, Reason: "no allow rule matched"},
		{User: "bob", Host: "whoami.example.test", Decision: audit.Allow},
		{User: "alice", Host: "grafana.example.test", Decision: audit.Allow},
	} {
		e.RequestID = string(rune('a' + i))
		f.recent.Record(t.Context(), e)
	}
	rec := f.do(t, http.MethodGet, "/.warden/api/decisions?user=bob&limit=1", "", nil)
	page := decode[struct {
		Decisions []map[string]any `json:"decisions"`
		Next      uint64           `json:"next_before"`
	}](t, rec)
	if len(page.Decisions) != 1 || page.Decisions[0]["host"] != "whoami.example.test" || page.Next != 2 {
		t.Fatalf("page = %+v", page)
	}
	rec = f.do(t, http.MethodGet, "/.warden/api/decisions?user=bob&before=2", "", nil)
	page2 := decode[struct {
		Decisions []map[string]any `json:"decisions"`
	}](t, rec)
	if len(page2.Decisions) != 1 || page2.Decisions[0]["decision"] != "deny" || page2.Decisions[0]["reason"] != "no allow rule matched" {
		t.Errorf("page 2 = %+v", page2)
	}
	for _, bad := range []string{"?decision=maybe", "?before=-1", "?limit=abc"} {
		if rec := f.do(t, http.MethodGet, "/.warden/api/decisions"+bad, "", nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, rec.Code)
		}
	}
}

func TestUnknownEndpointIsJSON404(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, http.MethodGet, "/.warden/api/nope", "", nil)
	if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}

func TestRoutes(t *testing.T) {
	routes := []config.Route{
		{Host: "grafana.example.test", Upstream: "http://127.0.0.1:9002", Policy: config.Policy{
			Allow: []config.Rule{{Groups: []string{"sre", "admins"}}},
			Paths: []config.PathRule{{Prefix: "/admin", Allow: []config.Rule{{Groups: []string{"admins"}, RequireMFAWithin: ptr(10 * time.Minute)}}}},
		}},
		{Host: "app.example.test", Upstream: "https://127.0.0.1:9003",
			UpstreamTLS: &config.UpstreamTLS{CAFile: "/secret/ca.pem", ClientCertFile: "/secret/client.pem", ClientKeyFile: "/secret/client-key.pem"},
			Policy:      config.Policy{Allow: []config.Rule{{Authenticated: ptr(true)}, {EmailDomains: []string{"warden.local"}}}, CaseInsensitivePaths: true}},
	}
	f := newFixture(t)
	h, err := New(Options{Sessions: f.store, Decisions: f.recent, AuthOrigin: authOrigin, Routes: routes})
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	rec := f.do(t, http.MethodGet, "/.warden/api/routes", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/secret/") {
		t.Errorf("routes leak TLS file paths: %s", rec.Body.String())
	}
	got := decode[struct {
		Routes []struct {
			Host        string `json:"host"`
			Upstream    string `json:"upstream"`
			UpstreamTLS bool   `json:"upstream_tls"`
			Policy      struct {
				Allow []map[string]any `json:"allow"`
				Paths []struct {
					Prefix string           `json:"prefix"`
					Allow  []map[string]any `json:"allow"`
				} `json:"paths"`
				CaseInsensitive bool `json:"case_insensitive_paths"`
			} `json:"policy"`
		} `json:"routes"`
	}](t, rec)
	if len(got.Routes) != 2 {
		t.Fatalf("routes = %+v", got)
	}
	g, a := got.Routes[0], got.Routes[1]
	if g.Host != "grafana.example.test" || len(g.Policy.Paths) != 1 || g.Policy.Paths[0].Prefix != "/admin" ||
		g.Policy.Paths[0].Allow[0]["require_mfa_within"] != "10m0s" {
		t.Errorf("grafana = %+v", g)
	}
	domains, _ := a.Policy.Allow[1]["email_domains"].([]any)
	if !a.UpstreamTLS || !a.Policy.CaseInsensitive || a.Policy.Allow[0]["authenticated"] != true ||
		len(domains) != 1 || domains[0] != "warden.local" {
		t.Errorf("app = %+v", a)
	}
	if _, ok := g.Policy.Allow[0]["users"]; ok {
		t.Errorf("absent conditions should be omitted: %v", g.Policy.Allow[0])
	}
}

func ptr[T any](v T) *T { return &v }
