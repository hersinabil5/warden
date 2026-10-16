package authn

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// refreshEvery makes every request past login due for a group refresh.
func refreshEvery(cfg *config.Config) { cfg.Auth.GroupRefreshInterval = time.Nanosecond }

func (e *flowEnv) signIn(t *testing.T) jar {
	t.Helper()
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login failed")
	}
	return j
}

func (e *flowEnv) mainSession(t *testing.T, j jar) (*session.Session, error) {
	t.Helper()
	return e.sessions.Get(t.Context(), j[testAuthDomain][sessionCookie].Value)
}

// PLAN.md M5 acceptance: a group change at the IdP reaches the session at
// the next refresh.
func TestRefreshUpdatesGroups(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	before, _ := e.mainSession(t, j)
	hits := e.idp.RefreshHits()
	e.idp.SetUser(func() map[string]any { return map[string]any{"groups": []string{"dev"}} })

	sess, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
	_ = resp.Body.Close()
	if !ok || strings.Join(sess.Groups, ",") != "dev" {
		t.Fatalf("after refresh: ok=%v groups=%v", ok, sess)
	}
	if e.idp.RefreshHits() != hits+1 {
		t.Errorf("refresh hits = %d, want %d", e.idp.RefreshHits(), hits+1)
	}
	stored, err := e.mainSession(t, j)
	if err != nil || strings.Join(stored.Groups, ",") != "dev" || stored.RefreshToken == before.RefreshToken ||
		!stored.Refreshed.After(before.Refreshed) || stored.CSRFToken != before.CSRFToken {
		t.Errorf("stored session not updated: %+v (err %v)", stored, err)
	}
}

func TestNoRefreshWithinInterval(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	for range 3 {
		_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
		_ = resp.Body.Close()
		if !ok {
			t.Fatal("not authenticated")
		}
	}
	if e.idp.RefreshHits() != 0 {
		t.Errorf("refreshed %d times within the interval", e.idp.RefreshHits())
	}
}

// If the IdP refuses the refresh or returns anything not fully valid, the
// session is revoked and the next step is a fresh login.
func TestRefreshFailureRevokes(t *testing.T) {
	for _, tt := range []struct {
		name string
		mod  func(e *flowEnv)
	}{
		{"user disabled (invalid_grant)", func(e *flowEnv) { e.idp.RevokeRefreshTokens() }},
		{"IdP error", func(e *flowEnv) { e.idp.FailToken(http.StatusServiceUnavailable) }},
		{"different subject", func(e *flowEnv) { e.idp.EditIDToken(func(c map[string]any) { c["sub"] = "mallory" }) }},
		{"nonce mismatch", func(e *flowEnv) { e.idp.EditIDToken(func(c map[string]any) { c["nonce"] = "other" }) }},
		{"wrong audience", func(e *flowEnv) { e.idp.EditIDToken(func(c map[string]any) { c["aud"] = "other-client" }) }},
		{"expired", func(e *flowEnv) {
			e.idp.EditIDToken(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		}},
		{"iat in the future", func(e *flowEnv) {
			e.idp.EditIDToken(func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() })
		}},
		{"alg none", func(e *flowEnv) {
			e.idp.SignIDTokenWith(func(map[string]any) string { return "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyLTEifQ." })
		}},
		{"no id_token", func(e *flowEnv) { e.idp.SignIDTokenWith(func(map[string]any) string { return "" }) }},
		{"malformed groups", func(e *flowEnv) { e.idp.EditIDToken(func(c map[string]any) { c["groups"] = "admins" }) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newFlowEnv(t, refreshEvery)
			j := e.signIn(t)
			tt.mod(e)
			_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
			_ = resp.Body.Close()
			if ok || resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), LoginPath) {
				t.Fatalf("ok=%v status=%d, want a login redirect", ok, resp.StatusCode)
			}
			if c := cookieNamed(resp, sessionCookie); c == nil || c.MaxAge >= 0 {
				t.Error("app cookie not cleared")
			}
			if _, err := e.mainSession(t, j); !errors.Is(err, session.ErrNotFound) {
				t.Errorf("main session survived: %v", err)
			}
			if !strings.Contains(e.logs.String(), "session revoked") {
				t.Errorf("revocation not logged:\n%s", e.logs.String())
			}
		})
	}
}

func TestRefreshWithoutRefreshTokenRevokes(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	s, _ := e.mainSession(t, j)
	s.RefreshToken = ""
	if err := e.sessions.Update(t.Context(), *s); err != nil {
		t.Fatal(err)
	}
	_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
	_ = resp.Body.Close()
	if ok {
		t.Error("session without a refresh token stayed valid past the interval")
	}
}

// The admin lookup refreshes too.
func TestMainSessionRefreshes(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	e.idp.RevokeRefreshTokens()
	req := (&http.Request{Header: http.Header{}, Host: testAuthDomain}).WithContext(t.Context())
	req.AddCookie(j[testAuthDomain][sessionCookie])
	if s, err := e.h.MainSession(req, "req-1"); s != nil || err != nil {
		t.Errorf("MainSession = %+v, %v; want none after a failed refresh", s, err)
	}
	if _, err := e.mainSession(t, j); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("main session survived: %v", err)
	}
}

// Parallel requests must not spend a rotated refresh token twice (which
// the IdP would answer with invalid_grant, revoking a healthy session).
func TestConcurrentRefreshKeepsSession(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for range 10 {
		wg.Go(func() {
			_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
			_ = resp.Body.Close()
			if !ok {
				mu.Lock()
				failed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if failed != 0 {
		t.Errorf("%d of 10 parallel requests lost the session", failed)
	}
	if _, err := e.mainSession(t, j); err != nil {
		t.Errorf("session revoked by concurrent refreshes: %v", err)
	}
}

func TestRefreshDoesNotLogSecrets(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	before, _ := e.mainSession(t, j)
	e.idp.RevokeRefreshTokens()
	_, _, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
	_ = resp.Body.Close()
	for _, secret := range []string{before.RefreshToken, j[testAuthDomain][sessionCookie].Value, j[appHost][sessionCookie].Value} {
		if strings.Contains(e.logs.String(), secret) {
			t.Errorf("log contains a secret")
		}
	}
}
