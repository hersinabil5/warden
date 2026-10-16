package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

// nopAudit discards audit events, for tests that are not about them.
type nopAudit struct{}

func (nopAudit) Record(context.Context, audit.Event) {}

// auditLog collects audit events.
type auditLog struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *auditLog) Record(_ context.Context, e audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

// only returns the single event recorded since the last call.
func (l *auditLog) only(t *testing.T) audit.Event {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	evs := l.events
	l.events = nil
	if len(evs) != 1 {
		t.Fatalf("got %d audit events, want 1: %+v", len(evs), evs)
	}
	return evs[0]
}

func (l *auditLog) none(t *testing.T) {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) != 0 {
		t.Errorf("got audit events %+v, want none", l.events)
	}
	l.events = nil
}

const testSessionHash = "3f9a0c7be1d24a6f8c0b5e7d9a1f3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a"

func auditHandler(t *testing.T, s *session.Session, opts Options) (*Handler, *auditLog, *echoUpstream) {
	t.Helper()
	up := newEcho(t)
	log := &auditLog{}
	opts.Audit = log
	opts.Logger = slog.New(slog.DiscardHandler)
	opts.Now = func() time.Time { return testNow }
	if opts.Identity == nil {
		opts.Identity = testIdentity(t)
	}
	if opts.Authenticator == nil {
		opts.Authenticator = asUser{s}
	}
	h, err := New(policyConfig(t, up.URL, false), opts)
	if err != nil {
		t.Fatal(err)
	}
	return h, log, up
}

func TestAuditDecisions(t *testing.T) {
	bob := *bobSess
	bob.Hash = testSessionHash
	alice := *aliceSess
	alice.Hash = testSessionHash
	for _, tt := range []struct {
		name         string
		sess         *session.Session
		authn        Authenticator
		identity     Asserter
		method, host string
		target       string
		wantStatus   int
		want         audit.Event
	}{
		{
			name: "allow", sess: &alice, method: http.MethodGet, host: "grafana.example.test", target: "/admin/users",
			wantStatus: http.StatusOK,
			want:       audit.Event{User: "alice", Session: "3f9a0c7be1d2", Path: "/admin/users", Decision: audit.Allow, Rule: "paths[/admin].allow[0]"},
		},
		{
			name: "policy deny", sess: &bob, method: http.MethodGet, host: "grafana.example.test", target: "/",
			wantStatus: http.StatusForbidden,
			want:       audit.Event{User: "bob", Session: "3f9a0c7be1d2", Path: "/", Decision: audit.Deny, Rule: "allow"},
		},
		{
			name: "unauthenticated GET", authn: &denyAll{}, method: http.MethodGet, host: "whoami.example.test", target: "/x",
			wantStatus: http.StatusFound,
			want:       audit.Event{Path: "/x", Decision: audit.Deny, Reason: "unauthenticated"},
		},
		{
			name: "unauthenticated POST", authn: unauthorized{}, method: http.MethodPost, host: "whoami.example.test", target: "/x",
			wantStatus: http.StatusUnauthorized,
			want:       audit.Event{Path: "/x", Decision: audit.Deny, Reason: "unauthenticated"},
		},
		{
			// The path policy saw, not the one the client sent (invariant 6).
			name: "normalized path", sess: &bob, method: http.MethodGet, host: "grafana.example.test", target: "/public/../admin",
			wantStatus: http.StatusForbidden,
			want:       audit.Event{User: "bob", Session: "3f9a0c7be1d2", Path: "/admin", Decision: audit.Deny, Rule: "paths[/admin]"},
		},
		{
			name: "encoded traversal", sess: &alice, method: http.MethodGet, host: "grafana.example.test", target: "/x/%252e%252e/admin",
			wantStatus: http.StatusBadRequest,
			want:       audit.Event{Path: "/x/%252e%252e/admin", Decision: audit.Deny, Reason: "invalid path"},
		},
		{
			name: "encoded slash", sess: &alice, method: http.MethodGet, host: "grafana.example.test", target: "/admin%2Fusers",
			wantStatus: http.StatusBadRequest,
			want:       audit.Event{Path: "/admin%2Fusers", Decision: audit.Deny, Reason: "invalid path"},
		},
		{
			// Policy allowed, but nothing reached the upstream: that is a deny.
			name: "signing failure", sess: &alice, identity: failingAsserter{}, method: http.MethodGet, host: "whoami.example.test", target: "/",
			wantStatus: http.StatusInternalServerError,
			want:       audit.Event{User: "alice", Session: "3f9a0c7be1d2", Path: "/", Decision: audit.Deny, Rule: "allow[0]", Reason: "identity assertion failed"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h, log, up := auditHandler(t, tt.sess, Options{Authenticator: tt.authn, Identity: tt.identity})
			req, ok := wireRequest(t, tt.target, tt.host)
			if !ok {
				t.Fatalf("%q: not a valid request target", tt.target)
			}
			req.Method = tt.method
			rec := serve(h, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status %d, want %d", rec.Code, tt.wantStatus)
			}
			if reached := up.hits.Load() != 0; reached != (tt.want.Decision == audit.Allow) {
				t.Errorf("reached upstream = %v with decision %q", reached, tt.want.Decision)
			}
			ev := log.only(t)
			if ev.RequestID == "" || ev.RequestID != rec.Header().Get(RequestIDHeader) {
				t.Errorf("request ID %q, response has %q", ev.RequestID, rec.Header().Get(RequestIDHeader))
			}
			if ev.Host != tt.host || ev.Method != tt.method || ev.Status != tt.wantStatus {
				t.Errorf("host/method/status = %s %s %d", ev.Host, ev.Method, ev.Status)
			}
			if ev.Time.IsZero() || ev.Latency < 0 {
				t.Errorf("time %v, latency %v", ev.Time, ev.Latency)
			}
			if ev.User != tt.want.User || ev.Session != tt.want.Session || ev.Path != tt.want.Path ||
				ev.Decision != tt.want.Decision || ev.Rule != tt.want.Rule {
				t.Errorf("event = %+v\nwant    %+v", ev, tt.want)
			}
			if tt.want.Reason != "" && ev.Reason != tt.want.Reason {
				t.Errorf("reason %q, want %q", ev.Reason, tt.want.Reason)
			}
			if ev.Reason == "" {
				t.Error("event has no reason")
			}
		})
	}
}

// unauthorized answers like authn does for a non-GET without a session.
type unauthorized struct{}

func (unauthorized) Authenticate(w http.ResponseWriter, _ *http.Request, _ string) (*session.Session, bool) {
	w.WriteHeader(http.StatusUnauthorized)
	return nil, false
}

// The event's request ID is Warden's own; a client-supplied one is ignored
// (T20).
func TestAuditIgnoresClientRequestID(t *testing.T) {
	h, log, _ := auditHandler(t, aliceSess, Options{})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "whoami.example.test"
	req.Header.Set(RequestIDHeader, "forged-id")
	rec := serve(h, req)
	if ev := log.only(t); ev.RequestID == "forged-id" || ev.RequestID != rec.Header().Get(RequestIDHeader) {
		t.Errorf("event request ID %q, response %q", ev.RequestID, rec.Header().Get(RequestIDHeader))
	}
}

// Invariant 9: no cookie, session ID, full session hash, token, or query
// string reaches the audit event.
func TestAuditHoldsNoSecrets(t *testing.T) {
	s := *aliceSess
	s.Hash = testSessionHash
	s.RefreshToken = "refresh-secret-value"
	h, log, _ := auditHandler(t, &s, Options{})
	secrets := []string{"session-cookie-value", "code-secret-value", "token-secret-value", "bearer-secret-value", s.RefreshToken, testSessionHash}
	req, ok := wireRequest(t, "/page?code=code-secret-value&access_token=token-secret-value", "whoami.example.test")
	if !ok {
		t.Fatal("bad request")
	}
	req.Header.Set("Cookie", "_warden_app=session-cookie-value")
	req.Header.Set("Authorization", "Bearer bearer-secret-value")
	serve(h, req)
	b, err := json.Marshal(log.only(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range append(secrets, "code=", "access_token") {
		if strings.Contains(string(b), secret) {
			t.Errorf("audit event contains %q: %s", secret, b)
		}
	}
}

// Warden's own endpoints and unknown hosts are not access decisions on a
// route, so they produce no event.
func TestAuditSkipsWardenEndpoints(t *testing.T) {
	h, log, _ := auditHandler(t, aliceSess, Options{
		Auth: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		JWKS: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	})
	for _, u := range []string{
		"https://whoami.example.test" + HealthzPath,
		"https://whoami.example.test/.warden/handshake",
		"https://auth.example.test/.warden/login",
		"https://auth.example.test" + JWKSPath,
		"https://unknown.example/",
		"https://unknown.example/a%2Fb",
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		serve(h, req)
		log.none(t)
	}
}

// A TLS session negotiated for one host and used for another is a deny.
func TestAuditMisdirectedRequest(t *testing.T) {
	h, log, up := auditHandler(t, aliceSess, Options{})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://grafana.example.test/admin", nil)
	req.TLS = &tls.ConnectionState{ServerName: "whoami.example.test"}
	rec := serve(h, req)
	ev := log.only(t)
	if rec.Code != http.StatusMisdirectedRequest || ev.Decision != audit.Deny || ev.Reason != "misdirected request" ||
		ev.Status != http.StatusMisdirectedRequest || ev.Host != "grafana.example.test" || up.hits.Load() != 0 {
		t.Errorf("status %d, event %+v", rec.Code, ev)
	}
}

func TestNewRequiresAudit(t *testing.T) {
	_, err := New(testConfig(t, "http://127.0.0.1:1"), Options{Identity: testIdentity(t), Logger: slog.New(slog.DiscardHandler)})
	if err == nil {
		t.Error("New accepted no audit recorder")
	}
}
