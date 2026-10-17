package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stepUp asks the handler for a step-up on appHost, as the proxy does after
// a policy deny, and returns the response.
func (e *flowEnv) stepUp(t *testing.T, method, target string, j jar) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, c := range j.forHost(appHost) {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.StepUp(rec, req, appHost)
	resp := rec.Result()
	_ = resp.Body.Close()
	j.update(appHost, resp)
	return rec
}

const appAdmin = "https://" + appHost + ":8443/admin?x=1"

func TestStepUpRedirectsToLogin(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	resp := e.stepUp(t, http.MethodGet, appAdmin, j)
	if resp.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", resp.Code)
	}
	loc, err := url.Parse(resp.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if loc.Host != testAuthDomain+":8443" || loc.Path != LoginPath || q.Get("step_up") != "1" ||
		q.Get("rd") != appAdmin || !validToken(q.Get("hs")) {
		t.Errorf("Location = %s", loc)
	}
	if resp.Header().Get("Cache-Control") != "no-store" {
		t.Error("step-up redirect is cacheable")
	}
}

// A POST can't be replayed after a redirect through the IdP.
func TestStepUpRefusesNonGET(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		resp := e.stepUp(t, m, appAdmin, j)
		if resp.Code != http.StatusForbidden || resp.Header().Get("Location") != "" {
			t.Errorf("%s: status %d, Location %q; want 403 and no redirect", m, resp.Code, resp.Header().Get("Location"))
		}
	}
}

// A signed-in browser normally skips the IdP (single sign-on); a step-up
// must not, and must ask the IdP to authenticate again.
func TestStepUpLoginForcesReauthentication(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	if q := e.idp.LastAuthorize(); q.Has("prompt") || q.Has("max_age") {
		t.Fatalf("a normal login sent prompt/max_age: %v", q)
	}
	loc := e.stepUp(t, http.MethodGet, appAdmin, j).Header().Get("Location")
	resp := e.serve(t, http.MethodGet, loc, j.forHost(testAuthDomain)...)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.idp.Server.URL+"/auth?") {
		t.Fatalf("step-up login: status %d to %q, want the IdP", resp.StatusCode, resp.Header.Get("Location"))
	}
	authz, _ := url.Parse(resp.Header.Get("Location"))
	if q := authz.Query(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Errorf("authorize query %v, want prompt=login and max_age=0", q)
	}
}

func TestStepUpFullFlow(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	old, err := e.mainSession(t, j)
	if err != nil {
		t.Fatal(err)
	}
	e.idp.SetUser(func() map[string]any { return map[string]any{"amr": []string{"pwd", "otp"}} })
	loc := e.stepUp(t, http.MethodGet, appAdmin, j).Header().Get("Location")
	chain, sess := e.browse(t, j, loc)
	if sess == nil {
		t.Fatalf("step-up did not end signed in: %v", chain)
	}
	if got := chain[len(chain)-1]; got != "https://"+appHost+":8443/admin" {
		t.Errorf("landed on %s, want the original URL", got)
	}
	if strings.Join(sess.AMR, ",") != "pwd,otp" || time.Since(sess.AuthTime) > time.Minute {
		t.Errorf("session AMR %v, auth_time %v; want the fresh MFA login", sess.AMR, sess.AuthTime)
	}
	// The step-up replaced the old main session (T2): it is gone.
	if _, err := e.sessions.GetByHash(t.Context(), old.Hash); err == nil {
		t.Error("the pre-step-up session still exists")
	}
}

// The IdP must have actually re-authenticated: an ID token whose auth_time
// predates the step-up (the IdP ignored prompt=login) is refused, which also
// stops a redirect loop.
func TestStepUpRejectsStaleAuthTime(t *testing.T) {
	for name, claims := range map[string]map[string]any{
		"auth_time before the step-up": {"auth_time": time.Now().Add(-time.Hour).Unix(), "amr": []string{"pwd", "otp"}},
		"no auth_time":                 {"auth_time": nil, "amr": []string{"pwd", "otp"}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newFlowEnv(t)
			j := e.signIn(t)
			before := e.sessionCount()
			e.idp.SetUser(func() map[string]any { return claims })
			e.idp.EditIDToken(func(c map[string]any) {
				if claims["auth_time"] == nil {
					delete(c, "auth_time")
				}
			})
			loc := e.stepUp(t, http.MethodGet, appAdmin, j).Header().Get("Location")
			resp := e.serve(t, http.MethodGet, loc, j.forHost(testAuthDomain)...)
			_ = resp.Body.Close()
			cb, pre := e.authorize(t, resp.Header.Get("Location")), resp.Cookies()
			out := e.serve(t, http.MethodGet, cb, append(pre, j.forHost(testAuthDomain)...)...)
			_ = out.Body.Close()
			if out.StatusCode != http.StatusBadRequest {
				t.Fatalf("callback: status %d, want 400", out.StatusCode)
			}
			if e.sessionCount() != before {
				t.Error("a stale step-up changed the sessions")
			}
			if !strings.Contains(e.logs.String(), "not re-authenticated") {
				t.Error("rejection reason not logged")
			}
		})
	}
}

// Ordinary logins keep accepting an older auth_time (an existing IdP session).
func TestNormalLoginAcceptsOlderAuthTime(t *testing.T) {
	e := newFlowEnv(t)
	e.idp.SetUser(func() map[string]any { return map[string]any{"auth_time": time.Now().Add(-time.Hour).Unix()} })
	if _, s := e.browse(t, jar{}, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login with an hour-old IdP session failed")
	}
}

func TestStepUpParameterIsStrict(t *testing.T) {
	e := newFlowEnv(t)
	rd := url.QueryEscape("https://" + appHost + ":8443/")
	for _, q := range []string{
		"?step_up=0",
		"?step_up=true",
		"?step_up=",
		"?step_up=1&step_up=1",
		"?step_up=1&rd=https%3A%2F%2Fevil.example%2F", // the return URL is still checked
		"?step_up=1&rd=" + rd + "&hs=short",
	} {
		resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+LoginPath+q)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, resp.StatusCode)
		}
	}
	// Without a return URL it is still a valid step-up (the dashboard).
	resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+LoginPath+"?step_up=1")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.idp.Server.URL) {
		t.Errorf("step_up=1 alone: status %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
