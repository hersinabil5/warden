package authn

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/session"
)

const appHost = "app.example.test"

// authenticate runs Authenticate for a request to target with cookies.
func (e *flowEnv) authenticate(t *testing.T, method, target string, cookies ...*http.Cookie) (*session.Session, bool, *http.Response) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sess, ok := e.h.Authenticate(rec, req, hostOf(req))
	resp := rec.Result()
	t.Cleanup(func() { _ = resp.Body.Close() })
	return sess, ok, resp
}

func hostOf(r *http.Request) string {
	h := r.Host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// jar is a minimal per-host cookie store for driving the whole flow.
type jar map[string]map[string]*http.Cookie

func (j jar) update(host string, resp *http.Response) {
	if j[host] == nil {
		j[host] = map[string]*http.Cookie{}
	}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			delete(j[host], c.Name)
		} else {
			j[host][c.Name] = c
		}
	}
}

func (j jar) forHost(host string) []*http.Cookie {
	var cs []*http.Cookie
	for _, c := range j[host] {
		cs = append(cs, c)
	}
	return cs
}

// browse follows Warden redirects from an app URL until the app request is
// authenticated, the way a browser would, and returns the redirect chain.
func (e *flowEnv) browse(t *testing.T, j jar, start string) (chain []string, sess *session.Session) {
	t.Helper()
	target := start
	for range 10 {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		host := u.Hostname()
		chain = append(chain, u.Scheme+"://"+u.Host+u.Path)
		var resp *http.Response
		switch {
		case strings.HasPrefix(target, e.idp.Server.URL):
			target = e.authorize(t, target)
			continue
		case host == appHost && !strings.HasPrefix(u.Path, "/.warden/"), host == "other.example.test" && !strings.HasPrefix(u.Path, "/.warden/"):
			s, ok, r := e.authenticate(t, http.MethodGet, target, j.forHost(host)...)
			_ = r.Body.Close()
			if ok {
				return chain, s
			}
			resp = r
		default:
			resp = e.serve(t, http.MethodGet, target, j.forHost(host)...)
			_ = resp.Body.Close()
		}
		j.update(host, resp)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("%s: status %d (chain %v)", target, resp.StatusCode, chain)
		}
		target = resp.Header.Get("Location")
		if strings.HasPrefix(target, "/") {
			target = u.Scheme + "://" + u.Host + target
		}
	}
	t.Fatalf("redirect loop: %v", chain)
	return nil, nil
}

func TestHandshakeFullFlowLandsOnOriginalURL(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	start := "https://" + appHost + ":8443/dash/x?tab=2"
	chain, sess := e.browse(t, j, start)
	if sess == nil || sess.Username != "alice" {
		t.Fatalf("not authenticated: %+v", sess)
	}
	want := []string{
		"https://app.example.test:8443/dash/x",
		"https://" + testAuthDomain + ":8443" + LoginPath,
		e.idp.Server.URL + "/auth",
		"https://" + testAuthDomain + ":8443" + CallbackPath,
		"https://app.example.test:8443" + HandshakePath,
		"https://app.example.test:8443/dash/x",
	}
	if strings.Join(chain, "\n") != strings.Join(want, "\n") {
		t.Errorf("chain:\n%s\nwant:\n%s", strings.Join(chain, "\n"), strings.Join(want, "\n"))
	}
	// The app cookie is host-only and distinct from the main session.
	app := j[appHost][sessionCookie]
	main := j[testAuthDomain][sessionCookie]
	if app == nil || main == nil || app.Value == main.Value || app.Domain != "" || !app.HttpOnly || !app.Secure {
		t.Errorf("cookies: app %+v main %+v", app, main)
	}
}

func TestHandshakeSingleSignOnAcrossHosts(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("first login failed")
	}
	hits := e.idp.TokenHits()
	chain, s := e.browse(t, j, "https://other.example.test:8443/page")
	if s == nil || s.Username != "alice" {
		t.Fatal("second host not authenticated")
	}
	if e.idp.TokenHits() != hits {
		t.Error("second host went back to the IdP despite a live main session")
	}
	for _, c := range chain {
		if strings.HasPrefix(c, e.idp.Server.URL) {
			t.Errorf("visited IdP: %v", chain)
		}
	}
}

func TestAuthenticateUnauthenticated(t *testing.T) {
	e := newFlowEnv(t)
	_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/a/b?c=d")
	defer func() { _ = resp.Body.Close() }()
	if ok || resp.StatusCode != http.StatusFound {
		t.Fatalf("ok=%v status=%d, want redirect", ok, resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != testAuthDomain+":8443" || loc.Path != LoginPath {
		t.Errorf("redirect to %s", loc)
	}
	if rd := loc.Query().Get("rd"); rd != "https://app.example.test:8443/a/b?c=d" {
		t.Errorf("rd = %q", rd)
	}
	hs := cookieNamed(resp, handshakeCookie)
	if hs == nil || !hs.HttpOnly || !hs.Secure || hs.SameSite != http.SameSiteLaxMode || hs.Path != "/" || hs.Domain != "" {
		t.Fatalf("handshake cookie: %+v", hs)
	}
	if loc.Query().Get("hs") != s256(hs.Value) || strings.Contains(resp.Header.Get("Location"), hs.Value) {
		t.Error("hs parameter must be the hash of the cookie, never the cookie value")
	}

	// A browser that already has a binding cookie keeps it (no pile-up of
	// cookies from parallel subresource requests).
	_, _, again := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/img.png", hs)
	defer func() { _ = again.Body.Close() }()
	if cookieNamed(again, handshakeCookie) != nil {
		t.Error("binding cookie replaced on every request")
	}
	loc2, _ := url.Parse(again.Header.Get("Location"))
	if loc2.Query().Get("hs") != s256(hs.Value) {
		t.Error("existing binding cookie not reused")
	}
}

func TestAuthenticateNonGETIs401(t *testing.T) {
	e := newFlowEnv(t)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		_, ok, resp := e.authenticate(t, m, "https://"+appHost+"/api")
		defer func() { _ = resp.Body.Close() }()
		if ok || resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("Location") != "" {
			t.Errorf("%s: ok=%v status=%d", m, ok, resp.StatusCode)
		}
	}
}

func TestAuthenticateOversizedURLReturnsToRoot(t *testing.T) {
	e := newFlowEnv(t)
	_, _, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/"+strings.Repeat("a", 5000))
	defer func() { _ = resp.Body.Close() }()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if rd := loc.Query().Get("rd"); rd != "https://app.example.test:8443/" {
		t.Errorf("rd = %q, want the host root", rd)
	}
}

// startHandshake drives a login from an app request up to the handshake
// redirect, returning the handshake URL and the browser's cookies.
func (e *flowEnv) startHandshake(t *testing.T) (string, jar) {
	t.Helper()
	j := jar{}
	_, _, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/")
	defer func() { _ = resp.Body.Close() }()
	j.update(appHost, resp)
	login := resp.Header.Get("Location")
	lr := e.serve(t, http.MethodGet, login)
	_ = lr.Body.Close()
	j.update(testAuthDomain, lr)
	cb := e.authorize(t, lr.Header.Get("Location"))
	cr := e.serve(t, http.MethodGet, cb, j.forHost(testAuthDomain)...)
	_ = cr.Body.Close()
	j.update(testAuthDomain, cr)
	if cr.StatusCode != http.StatusFound || !strings.Contains(cr.Header.Get("Location"), HandshakePath) {
		t.Fatalf("callback = %d %q", cr.StatusCode, cr.Header.Get("Location"))
	}
	return cr.Header.Get("Location"), j
}

func TestHandshakeAttacks(t *testing.T) {
	tests := []struct {
		name string
		do   func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response
	}{
		{"code replayed", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			first := e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
			_ = first.Body.Close()
			if first.StatusCode != http.StatusFound {
				t.Fatalf("first redemption = %d", first.StatusCode)
			}
			return e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
		}},
		{"victim has no binding cookie (login CSRF)", func(t *testing.T, e *flowEnv, hsURL string, _ jar) *http.Response {
			return e.serve(t, http.MethodGet, hsURL)
		}},
		{"victim's own binding cookie", func(t *testing.T, e *flowEnv, hsURL string, _ jar) *http.Response {
			_, _, r := e.authenticate(t, http.MethodGet, "https://"+appHost+"/")
			_ = r.Body.Close()
			return e.serve(t, http.MethodGet, hsURL, cookieNamed(r, handshakeCookie))
		}},
		{"code redeemed on another host", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			return e.serve(t, http.MethodGet, strings.Replace(hsURL, appHost, "other.example.test", 1), j.forHost(appHost)...)
		}},
		{"code expired", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			e.mr.FastForward(31 * time.Second)
			return e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
		}},
		{"guessed code", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			u, _ := url.Parse(hsURL)
			return e.serve(t, http.MethodGet, "https://"+u.Host+HandshakePath+"?code=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", j.forHost(appHost)...)
		}},
		{"duplicate code parameter", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			return e.serve(t, http.MethodGet, hsURL+"&code=x", j.forHost(appHost)...)
		}},
		{"main session revoked before redemption", func(t *testing.T, e *flowEnv, hsURL string, j jar) *http.Response {
			if err := e.sessions.Delete(t.Context(), j[testAuthDomain][sessionCookie].Value); err != nil {
				t.Fatal(err)
			}
			return e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFlowEnv(t)
			hsURL, j := e.startHandshake(t)
			resp := tt.do(t, e, hsURL, j)
			_ = resp.Body.Close()
			if c := cookieNamed(resp, sessionCookie); c != nil && c.MaxAge > 0 {
				t.Errorf("app session cookie issued (status %d)", resp.StatusCode)
			}
			if resp.StatusCode == http.StatusFound && !strings.Contains(resp.Header.Get("Location"), LoginPath) &&
				!strings.HasPrefix(resp.Header.Get("Location"), "https://"+appHost) {
				t.Errorf("redirected to %q", resp.Header.Get("Location"))
			}
			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusFound {
				t.Errorf("status = %d", resp.StatusCode)
			}
		})
	}
}

func TestLoginHandshakeParameterValidation(t *testing.T) {
	e := newFlowEnv(t)
	rd := url.QueryEscape("https://" + appHost + ":8443/")
	good := s256("binding")
	for _, q := range []string{
		"hs=" + good,                       // hs without rd
		"rd=" + rd + "&hs=short",           // not a SHA-256
		"rd=" + rd + "&hs=" + good + "%3D", // padded
		"rd=" + rd + "&hs=" + good + "&hs=" + good,
	} {
		resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+LoginPath+"?"+q)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, resp.StatusCode)
		}
	}
}

// Without a binding (a hand-made login?rd= link), Warden never hands out a
// code: it returns to the app, which starts a bound handshake.
func TestLoginWithoutBindingBouncesToApp(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "?rd="+url.QueryEscape("https://"+appHost+":8443/x"))
	resp := e.serve(t, http.MethodGet, cb, pre)
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "https://app.example.test:8443/x" {
		t.Errorf("callback redirect = %q, want the app URL itself", loc)
	}
	for _, k := range e.mr.Keys() {
		if strings.Contains(k, "once:handshake") {
			t.Error("handshake code issued without a browser binding")
		}
	}
}

func TestRevocationTakesEffectOnNextRequest(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login failed")
	}
	if err := e.sessions.Delete(t.Context(), j[testAuthDomain][sessionCookie].Value); err != nil {
		t.Fatal(err)
	}
	_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+":8443/", j.forHost(appHost)...)
	defer func() { _ = resp.Body.Close() }()
	if ok || resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), LoginPath) {
		t.Errorf("revoked session: ok=%v status=%d", ok, resp.StatusCode)
	}
	if c := cookieNamed(resp, sessionCookie); c == nil || c.MaxAge >= 0 {
		t.Error("dead app cookie not cleared")
	}
}

func TestSessionCookiesAreNotInterchangeable(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login failed")
	}
	mainCookie, appCookie := j[testAuthDomain][sessionCookie], j[appHost][sessionCookie]
	// Main session ID presented on an app host.
	_, ok, r1 := e.authenticate(t, http.MethodGet, "https://"+appHost+"/", mainCookie)
	_ = r1.Body.Close()
	if ok {
		t.Error("main session accepted on app host")
	}
	// App session from one host on another.
	_, ok, r2 := e.authenticate(t, http.MethodGet, "https://other.example.test/", appCookie)
	_ = r2.Body.Close()
	if ok {
		t.Error("app session accepted on another host")
	}
	// App session as the main session on the auth host.
	resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+SessionPath, appCookie)
	defer func() { _ = resp.Body.Close() }()
	if body := readBody(t, resp); !strings.Contains(body, "Not signed in") {
		t.Error("app session accepted on auth host")
	}
}

func TestEndpointsAreHostScoped(t *testing.T) {
	e := newFlowEnv(t)
	for _, target := range []string{
		"https://" + appHost + LoginPath,
		"https://" + appHost + CallbackPath,
		"https://" + appHost + SessionPath,
		"https://" + testAuthDomain + HandshakePath + "?code=x",
		"https://unknown.example.test" + LoginPath,
	} {
		resp := e.serve(t, http.MethodGet, target)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", target, resp.StatusCode)
		}
	}
}

func TestAuthenticateRedisDown(t *testing.T) {
	e := newFlowEnv(t)
	e.mr.Close()
	planted := &http.Cookie{Name: sessionCookie, Value: "x"} //nolint:gosec // G124: request cookie; attributes are not sent by clients
	_, ok, resp := e.authenticate(t, http.MethodGet, "https://"+appHost+"/", planted)
	defer func() { _ = resp.Body.Close() }()
	if ok || resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("ok=%v status=%d, want deny with 500", ok, resp.StatusCode)
	}
}

func TestHandshakeDoesNotLogSecrets(t *testing.T) {
	e := newFlowEnv(t)
	hsURL, j := e.startHandshake(t)
	resp := e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
	_ = resp.Body.Close()
	u, _ := url.Parse(hsURL)
	logs := e.logs.String()
	for _, s := range []string{u.Query().Get("code"), j[appHost][handshakeCookie].Value, cookieNamed(resp, sessionCookie).Value, j[testAuthDomain][sessionCookie].Value} {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain %q", s)
		}
	}
	if !strings.Contains(logs, "handshake completed") {
		t.Errorf("no handshake log:\n%s", logs)
	}
}

// The one-time code travels in a URL: keep it out of Referer and caches.
func TestHandshakeResponsesHideTheCode(t *testing.T) {
	e := newFlowEnv(t)
	hsURL, j := e.startHandshake(t)
	resp := e.serve(t, http.MethodGet, hsURL, j.forHost(appHost)...)
	_ = resp.Body.Close()
	if resp.Header.Get("Referrer-Policy") != "no-referrer" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("redeem headers: Referrer-Policy %q, Cache-Control %q", resp.Header.Get("Referrer-Policy"), resp.Header.Get("Cache-Control"))
	}
}
