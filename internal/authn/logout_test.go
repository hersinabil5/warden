package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hersinabil5/warden/internal/authn/testidp"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// logoutResult is a logout response without a body to close.
type logoutResult struct {
	StatusCode int
	Header     http.Header
	resp       *http.Response
}

func (l logoutResult) cookie(name string) *http.Cookie { return cookieNamed(l.resp, name) }

func (e *flowEnv) logout(t *testing.T, headers map[string]string, cookies ...*http.Cookie) logoutResult {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+testAuthDomain+":8443"+LogoutPath, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	resp := rec.Result()
	_ = resp.Body.Close()
	return logoutResult{StatusCode: resp.StatusCode, Header: resp.Header, resp: resp}
}

func TestLogoutRevokesEverything(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login failed")
	}
	mainCookie, appCookie := j[testAuthDomain][sessionCookie], j[appHost][sessionCookie]

	resp := e.logout(t, map[string]string{"Origin": "https://" + testAuthDomain + ":8443", "Sec-Fetch-Site": "same-origin"}, mainCookie)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != SessionPath {
		t.Errorf("logout = %d -> %q, want 303 -> %s", resp.StatusCode, resp.Header.Get("Location"), SessionPath)
	}
	if c := resp.cookie(sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("session cookie not cleared")
	}
	if _, err := e.sessions.Get(t.Context(), mainCookie.Value); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("main session survived logout: %v", err)
	}
	// App sessions die with it, on the very next request.
	if _, ok, r := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", appCookie); ok {
		t.Error("app session survived logout")
	} else {
		_ = r.Body.Close()
	}
	if !strings.Contains(e.logs.String(), "logout") {
		t.Error("logout not logged")
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	e := newFlowEnv(t)
	resp := e.logout(t, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", resp.StatusCode)
	}
}

// Logout CSRF: a cross-site page must not be able to sign the user out.
func TestLogoutRejectsCrossSite(t *testing.T) {
	for _, hdr := range []map[string]string{
		{"Origin": "https://evil.com"},
		{"Origin": "null"},
		{"Origin": "https://app.example.test:8443"},
		{"Origin": "http://" + testAuthDomain + ":8443"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
	} {
		e := newFlowEnv(t)
		cb, pre := e.begin(t, "")
		login := e.serve(t, http.MethodGet, cb, pre)
		_ = login.Body.Close()
		mainCookie := cookieNamed(login, sessionCookie)

		resp := e.logout(t, hdr, mainCookie)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%v: status = %d, want 403", hdr, resp.StatusCode)
		}
		if _, err := e.sessions.Get(t.Context(), mainCookie.Value); err != nil {
			t.Errorf("%v: session revoked by a cross-site request: %v", hdr, err)
		}
	}
}

func TestLogoutRequiresPOST(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	login := e.serve(t, http.MethodGet, cb, pre)
	_ = login.Body.Close()
	mainCookie := cookieNamed(login, sessionCookie)
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete} {
		resp := e.serve(t, m, "https://"+testAuthDomain+LogoutPath, mainCookie)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
			t.Errorf("%s: status = %d, Allow %q", m, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
	if _, err := e.sessions.Get(t.Context(), mainCookie.Value); err != nil {
		t.Errorf("session revoked by a non-POST: %v", err)
	}
}

func TestLogoutOnlyOnAuthHost(t *testing.T) {
	e := newFlowEnv(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+appHost+LogoutPath, nil)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestLogoutAtIdP(t *testing.T) {
	e := newFlowEnv(t, func(c *config.Config) { c.Auth.LogoutAtIdP = true })
	cb, pre := e.begin(t, "")
	login := e.serve(t, http.MethodGet, cb, pre)
	_ = login.Body.Close()
	mainCookie := cookieNamed(login, sessionCookie)

	resp := e.logout(t, map[string]string{"Origin": "https://" + testAuthDomain + ":8443"}, mainCookie)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if loc.Scheme+"://"+loc.Host+loc.Path != e.idp.Server.URL+"/logout" ||
		q.Get("client_id") != testidp.ClientID ||
		q.Get("post_logout_redirect_uri") != "https://"+testAuthDomain+":8443"+SessionPath {
		t.Errorf("IdP logout redirect = %s", loc)
	}
	if strings.Contains(loc.String(), mainCookie.Value) {
		t.Error("session ID sent to the IdP")
	}
	if _, err := e.sessions.Get(t.Context(), mainCookie.Value); !errors.Is(err, session.ErrNotFound) {
		t.Error("local session not revoked before IdP logout")
	}
}

func TestLogoutAtIdPRequiresEndSessionEndpoint(t *testing.T) {
	idp := testidp.New(t)
	idp.EditDiscovery(func(d map[string]any) { delete(d, "end_session_endpoint") })
	auth := authConfig(idp.Issuer)
	auth.Domain = testAuthDomain
	auth.LogoutAtIdP = true
	p, err := Discover(t.Context(), auth, fastOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewCookieKey()
	store := session.NewStore(session.NewClient("127.0.0.1:1"), session.Options{})
	_, err = NewHandler(&config.Config{Listen: "127.0.0.1:8443", Auth: auth}, p, HandlerOptions{CookieKey: key, Sessions: store})
	if err == nil || !strings.Contains(err.Error(), "end_session_endpoint") {
		t.Errorf("err = %v, want end_session_endpoint error", err)
	}
}

func TestLogoutRedisDownStillClearsCookie(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	login := e.serve(t, http.MethodGet, cb, pre)
	_ = login.Body.Close()
	e.mr.Close()
	resp := e.logout(t, nil, cookieNamed(login, sessionCookie))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 so the user knows logout failed", resp.StatusCode)
	}
	if c := resp.cookie(sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("cookie not cleared")
	}
}

func TestSessionPageHasLogoutForm(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	login := e.serve(t, http.MethodGet, cb, pre)
	_ = login.Body.Close()
	resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+SessionPath, cookieNamed(login, sessionCookie))
	defer func() { _ = resp.Body.Close() }()
	body := readBody(t, resp)
	if !strings.Contains(body, `<form method="post" action="`+LogoutPath+`"`) {
		t.Errorf("no logout form:\n%s", body)
	}
}
