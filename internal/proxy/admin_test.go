package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/admin"
	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/policy"
	"github.com/hersinabil5/warden/internal/session"
)

// mainAs returns a fixed main session (or error) for every request.
type mainAs struct {
	s   *session.Session
	err error
}

func (m mainAs) MainSession(*http.Request, string) (*session.Session, error) { return m.s, m.err }

// adminSpy records what reached the admin handler.
type adminSpy struct{ got []*http.Request }

func (a *adminSpy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.got = append(a.got, r)
	w.WriteHeader(http.StatusOK)
}

func adminPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.Compile(config.Policy{Allow: []config.Rule{{Groups: []string{"admins"}, RequireMFAWithin: ptr(time.Hour)}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func adminHandler(t *testing.T, m mainAs) (*Handler, *adminSpy, *auditLog) {
	t.Helper()
	spy := &adminSpy{}
	log := &auditLog{}
	h, err := New(testConfig(t, newEcho(t).URL), Options{
		Identity: testIdentity(t), Authenticator: allowAll{}, Audit: log,
		Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return testNow },
		Auth:  http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
		Admin: &AdminRoute{Handler: spy, Policy: adminPolicy(t), Sessions: m},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, spy, log
}

func TestAdminAccess(t *testing.T) {
	recentMFA := &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins"},
		AMR: []string{"pwd", "otp"}, AuthTime: testNow.Add(-10 * time.Minute), Hash: testSessionHash}
	noMFA := *recentMFA
	noMFA.AMR = []string{"pwd"}
	staleMFA := *recentMFA
	staleMFA.AuthTime = testNow.Add(-2 * time.Hour)
	for _, tt := range []struct {
		name       string
		m          mainAs
		wantStatus int
		wantReason string
	}{
		{"admin with recent MFA", mainAs{s: recentMFA}, http.StatusOK, "matched"},
		{"no session", mainAs{}, http.StatusUnauthorized, "unauthenticated"},
		{"not an admin", mainAs{s: bobSess}, http.StatusForbidden, ""},
		{"admin without MFA", mainAs{s: &noMFA}, http.StatusForbidden, ""},
		{"admin with stale MFA", mainAs{s: &staleMFA}, http.StatusForbidden, ""},
		{"session store down", mainAs{err: errors.New("redis down")}, http.StatusInternalServerError, "session store error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, spy, log := adminHandler(t, tt.m)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/api/sessions", nil)
			rec := serve(h, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			if reached := len(spy.got) > 0; reached != (tt.wantStatus == http.StatusOK) {
				t.Errorf("reached admin handler = %v", reached)
			}
			if tt.wantStatus != http.StatusOK {
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" || !strings.Contains(rec.Body.String(), rec.Header().Get(RequestIDHeader)) {
					t.Errorf("error response %q: %s", ct, rec.Body.String())
				}
			}
			ev := log.only(t)
			wantDecision := audit.Deny
			if tt.wantStatus == http.StatusOK {
				wantDecision = audit.Allow
			}
			if ev.Host != "auth.example.test" || ev.Path != "/.warden/api/sessions" || ev.Decision != wantDecision || ev.Status != tt.wantStatus {
				t.Errorf("event = %+v", ev)
			}
			if tt.wantReason != "" && ev.Reason != tt.wantReason {
				t.Errorf("reason %q, want %q", ev.Reason, tt.wantReason)
			}
		})
	}
}

// fakeSessions is an empty store for the real admin handler.
type fakeSessions struct{}

func (fakeSessions) List(context.Context, int, int) ([]session.Session, int, error) {
	return nil, 0, nil
}
func (fakeSessions) ListUser(context.Context, string) ([]session.Session, error) { return nil, nil }
func (fakeSessions) DeleteHash(context.Context, string) error                    { return nil }
func (fakeSessions) RevokeUser(context.Context, string) (int, error)             { return 0, nil }

// The real admin handler, behind the proxy, serves the authenticated
// session's identity.
func TestAdminGetsSession(t *testing.T) {
	s := &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins"}, //nolint:gosec // G101: fake test token
		AMR: []string{"otp", "pwd"}, AuthTime: testNow, Hash: testSessionHash, CSRFToken: "csrf-value"}
	api, err := admin.New(admin.Options{Sessions: fakeSessions{}, Decisions: audit.NewRecent(1), AuthOrigin: "https://auth.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(testConfig(t, newEcho(t).URL), Options{
		Identity: testIdentity(t), Audit: nopAudit{}, Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return testNow },
		Admin: &AdminRoute{Policy: adminPolicy(t), Sessions: mainAs{s: s}, Handler: api},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/api/me", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"user":"alice"`) || !strings.Contains(rec.Body.String(), "csrf-value") {
		t.Errorf("status %d: %s", rec.Code, rec.Body.String())
	}
}

// Admin paths exist only on the auth host, exactly under the API prefix,
// after normalization.
func TestAdminPathsAreScoped(t *testing.T) {
	alice := &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins"},
		AMR: []string{"pwd", "otp"}, AuthTime: testNow}
	h, spy, _ := adminHandler(t, mainAs{s: alice})
	for _, tt := range []struct {
		host, path string
		admin      bool
	}{
		{"auth.example.test", "/.warden/api/me", true},
		{"auth.example.test", "/.warden/x/../api/me", true}, // normalized first
		{"auth.example.test", "//.warden//api/me", true},
		{"auth.example.test", "/.warden/API/me", false},
		{"auth.example.test", "/.warden/apis", false},
		{"auth.example.test", "/.warden/api", false},
		{"auth.example.test", "/.warden/%61pi/me", true}, // decoded, then matched
		{"app.example.test", "/.warden/api/me", false},   // a route host
	} {
		spy.got = nil
		req, ok := wireRequest(t, tt.path, tt.host)
		if !ok {
			t.Fatalf("%s%s: bad request", tt.host, tt.path)
		}
		serve(h, req)
		if reached := len(spy.got) > 0; reached != tt.admin {
			t.Errorf("%s%s: reached admin = %v, want %v", tt.host, tt.path, reached, tt.admin)
		}
		if tt.admin && len(spy.got) == 1 && spy.got[0].URL.Path != "/.warden/api/me" {
			t.Errorf("%s: admin handler saw %q", tt.path, spy.got[0].URL.Path)
		}
	}
}

// Without admin config the API does not exist.
func TestAdminOffWithoutConfig(t *testing.T) {
	h := newTestHandler(t, testConfig(t, newEcho(t).URL))
	rec := serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/api/me", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

func TestNewValidatesAdminRoute(t *testing.T) {
	for _, ar := range []*AdminRoute{
		{Policy: adminPolicy(t), Sessions: mainAs{}},
		{Handler: &adminSpy{}, Sessions: mainAs{}},
		{Handler: &adminSpy{}, Policy: adminPolicy(t)},
	} {
		if _, err := New(testConfig(t, "http://127.0.0.1:1"), Options{Identity: testIdentity(t), Audit: nopAudit{},
			Logger: slog.New(slog.DiscardHandler), Admin: ar}); err == nil {
			t.Errorf("New accepted incomplete admin route %+v", ar)
		}
	}
}
