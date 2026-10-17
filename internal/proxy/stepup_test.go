package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

// stepUpAuth authenticates as a fixed session and records step-up requests,
// answering them the way authn does.
type stepUpAuth struct {
	s     *session.Session
	hosts []string
}

func (a *stepUpAuth) Authenticate(http.ResponseWriter, *http.Request, string) (*session.Session, bool) {
	return a.s, true
}

func (a *stepUpAuth) StepUp(w http.ResponseWriter, _ *http.Request, host string) {
	a.hosts = append(a.hosts, host)
	w.Header().Set("Location", "https://auth.example.test/.warden/login?step_up=1")
	w.WriteHeader(http.StatusFound)
}

var staleAdmin = &session.Session{Subject: "a-1", Username: "alice", Groups: []string{"admins"},
	AMR: []string{"pwd", "otp"}, AuthTime: testNow.Add(-time.Hour), Hash: testSessionHash}

func TestStaleMFAStepsUp(t *testing.T) {
	auth := &stepUpAuth{s: staleAdmin}
	h, log, up := auditHandler(t, nil, Options{Authenticator: auth})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/admin/users", nil)
	req.Host = "grafana.example.test"
	rec := serve(h, req)
	if rec.Code != http.StatusFound || len(auth.hosts) != 1 || auth.hosts[0] != "grafana.example.test" {
		t.Fatalf("status %d, step-ups %v; want one step-up for grafana", rec.Code, auth.hosts)
	}
	if up.hits.Load() != 0 {
		t.Error("the upstream was reached")
	}
	if rec.Header().Get("X-Warden-Identity") != "" {
		t.Error("an identity assertion was issued")
	}
	ev := log.only(t)
	if ev.Decision != audit.Deny || ev.Reason != "step-up required" || ev.Status != http.StatusFound || ev.User != "alice" {
		t.Errorf("event = %+v", ev)
	}
}

func TestNoStepUpWhenItCannotHelp(t *testing.T) {
	fresh := *staleAdmin
	fresh.AMR = []string{"pwd"}
	fresh.AuthTime = testNow.Add(-30 * time.Second) // just logged in, still no OTP
	for _, tt := range []struct {
		name string
		s    *session.Session
		path string
	}{
		{"not an admin", bobSess, "/admin"},
		{"fresh login still without MFA", &fresh, "/admin"},
		{"denied without an MFA rule", &session.Session{Subject: "c", Username: "carol", AuthTime: testNow.Add(-time.Hour)}, "/"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auth := &stepUpAuth{s: tt.s}
			h, log, _ := auditHandler(t, nil, Options{Authenticator: auth})
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			req.Host = "grafana.example.test"
			if rec := serve(h, req); rec.Code != http.StatusForbidden || len(auth.hosts) != 0 {
				t.Errorf("status %d, step-ups %v; want a plain 403", rec.Code, auth.hosts)
			}
			if ev := log.only(t); ev.Reason == "step-up required" {
				t.Errorf("event = %+v", ev)
			}
		})
	}
}

// An Authenticator that can't step up leaves the deny a 403.
func TestStepUpNeedsAStepUpper(t *testing.T) {
	h, _, _ := auditHandler(t, nil, Options{Authenticator: asUser{staleAdmin}})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/admin", nil)
	req.Host = "grafana.example.test"
	if rec := serve(h, req); rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rec.Code)
	}
}

func TestDashboardStepsUp(t *testing.T) {
	older := *staleAdmin
	older.AuthTime = testNow.Add(-2 * time.Hour) // the admin policy allows an hour
	h, spy, log := adminHandler(t, mainAs{s: &older})
	rec := serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/admin/", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/.warden/login?step_up=1" {
		t.Fatalf("status %d to %q, want a step-up login", rec.Code, rec.Header().Get("Location"))
	}
	if len(spy.got) != 0 {
		t.Error("the admin handler was reached")
	}
	if ev := log.only(t); ev.Reason != "step-up required" || ev.Decision != audit.Deny {
		t.Errorf("event = %+v", ev)
	}
	// The API can't redirect a fetch() into a login; it stays a 403.
	rec = serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/api/me", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("API: status %d, want 403", rec.Code)
	}
}
