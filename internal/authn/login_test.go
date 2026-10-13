package authn

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/hersinabil5/warden/internal/authn/testidp"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

const testAuthDomain = "auth.example.test"

type loginEnv struct {
	idp  *testidp.IdP
	h    *Handler
	logs *syncBuffer
}

func newLoginEnv(t *testing.T, listen string) loginEnv {
	t.Helper()
	idp := testidp.New(t)
	auth := authConfig(idp.Issuer)
	auth.Domain = testAuthDomain
	auth.Scopes = []string{"openid", "email", "profile"}
	var logs syncBuffer
	opts := fastOptions(&logs)
	p, err := Discover(t.Context(), auth, opts)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewCookieKey()
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := session.NewClient(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	h, err := NewHandler(&config.Config{Listen: listen, Auth: auth, Routes: []config.Route{{Host: "app.example.test"}}}, p, HandlerOptions{
		CookieKey: key,
		Sessions:  session.NewStore(rdb, session.Options{AbsoluteTTL: time.Hour, IdleTimeout: time.Hour}),
		Logger:    opts.Logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return loginEnv{idp: idp, h: h, logs: &logs}
}

func (e loginEnv) do(t *testing.T, method, target string) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Result()
}

// login performs GET /.warden/login and returns the redirect URL and the
// pre-auth cookie.
func (e loginEnv) login(t *testing.T, target string) (*url.URL, *http.Cookie) {
	t.Helper()
	resp := e.do(t, http.MethodGet, target)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	return loc, cookies[0]
}

func TestLoginRedirectsToIdPWithPKCE(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	loc, c := e.login(t, "https://"+testAuthDomain+LoginPath)

	if got, want := loc.Scheme+"://"+loc.Host+loc.Path, e.idp.Server.URL+"/auth"; got != want {
		t.Errorf("redirect target = %q, want %q", got, want)
	}
	q := loc.Query()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             testidp.ClientID,
		"redirect_uri":          "https://" + testAuthDomain + ":8443" + CallbackPath,
		"scope":                 "openid email profile",
		"code_challenge_method": "S256",
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(k) == "" {
			t.Errorf("%s missing", k)
		}
	}

	pa, err := e.h.sealer.open(c.Name, c.Value)
	if err != nil {
		t.Fatalf("pre-auth cookie does not open: %v", err)
	}
	if pa.State != q.Get("state") || pa.Nonce != q.Get("nonce") {
		t.Error("cookie state/nonce differ from the authorize request")
	}
	sum := sha256.Sum256([]byte(pa.Verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Error("code_challenge is not S256(verifier)")
	}
	if q.Get("code_challenge") == pa.Verifier {
		t.Error("verifier sent as the challenge (plain PKCE)")
	}
	if c.Name != preAuthCookieName(pa.State) {
		t.Errorf("cookie name %q not bound to state", c.Name)
	}
}

func TestLoginRedirectURIOmitsDefaultPort(t *testing.T) {
	e := newLoginEnv(t, ":443")
	loc, _ := e.login(t, "https://"+testAuthDomain+LoginPath)
	if got, want := loc.Query().Get("redirect_uri"), "https://"+testAuthDomain+CallbackPath; got != want {
		t.Errorf("redirect_uri = %q, want %q", got, want)
	}
}

func TestLoginCookieAttributes(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	_, c := e.login(t, "https://"+testAuthDomain+LoginPath)
	switch {
	case !strings.HasPrefix(c.Name, "__Host-"):
		t.Errorf("name %q lacks __Host- prefix", c.Name)
	case !c.HttpOnly:
		t.Error("cookie not HttpOnly")
	case !c.Secure:
		t.Error("cookie not Secure")
	case c.SameSite != http.SameSiteLaxMode:
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	case c.Path != "/":
		t.Errorf("Path = %q, want /", c.Path)
	case c.Domain != "":
		t.Errorf("Domain = %q, want host-only", c.Domain)
	case c.MaxAge <= 0 || c.MaxAge > 600:
		t.Errorf("Max-Age = %d, want (0, 600]", c.MaxAge)
	}
}

func TestLoginResponseIsNotCacheable(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	resp := e.do(t, http.MethodGet, "https://"+testAuthDomain+LoginPath)
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// Nothing in the login request may influence the authorize request.
func TestLoginIgnoresSmuggledParameters(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	smuggled := url.Values{
		"redirect_uri":          {"https://evil.com/cb"},
		"client_id":             {"evil-client"},
		"scope":                 {"openid admin"},
		"response_type":         {"token"},
		"code_challenge_method": {"plain"},
		"code_challenge":        {"attacker"},
		"state":                 {"attacker-state"},
		"nonce":                 {"attacker-nonce"},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://"+testAuthDomain+LoginPath+"?"+smuggled.Encode(), nil)
	req.Host = "evil.com" // a spoofed Host must not reach redirect_uri either
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if strings.Contains(loc.String(), "evil") || strings.Contains(loc.String(), "attacker") {
		t.Errorf("smuggled value reached the authorize URL: %s", loc)
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != testidp.ClientID || len(q["state"]) != 1 {
		t.Errorf("authorize params altered: %v", q)
	}
}

func TestLoginRejectsOtherMethods(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		resp := e.do(t, m, "https://"+testAuthDomain+LoginPath)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, resp.StatusCode)
		}
		if len(resp.Cookies()) != 0 {
			t.Errorf("%s: set a cookie", m)
		}
		if resp.Header.Get("Allow") != http.MethodGet {
			t.Errorf("%s: Allow = %q, want GET", m, resp.Header.Get("Allow"))
		}
	}
}

func TestHandlerUnknownPathIs404(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	for _, p := range []string{"/.warden/", "/.warden/login/", "/.warden/Login", "/.warden/loginx", "/.warden/nope", "/.warden/callback/", "/.warden/session/"} {
		resp := e.do(t, http.MethodGet, "https://"+testAuthDomain+p)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", p, resp.StatusCode)
		}
	}
}

func TestLoginDoesNotLogSecrets(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	loc, c := e.login(t, "https://"+testAuthDomain+LoginPath)
	pa, err := e.h.sealer.open(c.Name, c.Value)
	if err != nil {
		t.Fatal(err)
	}
	logs := e.logs.String()
	for _, s := range []string{pa.State, pa.Nonce, pa.Verifier, c.Value, loc.Query().Get("code_challenge"), testSecret} {
		if strings.Contains(logs, s) {
			t.Errorf("logs contain a secret value %q:\n%s", s, logs)
		}
	}
	if !strings.Contains(logs, "login started") {
		t.Errorf("no login log line:\n%s", logs)
	}
}

func TestLoginLogsWardenRequestIDNotClients(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testAuthDomain+LoginPath, nil)
	req.Header.Set("X-Request-ID", "forged-by-client")
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "warden-generated-id") // as the proxy does before routing
	e.h.ServeHTTP(rec, req)
	logs := e.logs.String()
	if strings.Contains(logs, "forged-by-client") || !strings.Contains(logs, "warden-generated-id") {
		t.Errorf("login log uses the wrong request ID:\n%s", logs)
	}
}

func TestNewHandlerValidatesInputs(t *testing.T) {
	idp := testidp.New(t)
	auth := authConfig(idp.Issuer)
	auth.Domain = testAuthDomain
	p, err := Discover(t.Context(), auth, fastOptions(nil))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Listen: "127.0.0.1:8443", Auth: auth}
	if _, err := NewHandler(cfg, p, HandlerOptions{CookieKey: make([]byte, 16)}); err == nil {
		t.Error("short cookie key accepted")
	}
	if _, err := NewHandler(cfg, nil, HandlerOptions{CookieKey: make([]byte, 32)}); err == nil {
		t.Error("nil provider accepted")
	}
}

func TestLoginStoresValidatedReturnURL(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	rd := url.QueryEscape("https://APP.example.test/x?y=1")
	_, c := e.login(t, "https://"+testAuthDomain+LoginPath+"?rd="+rd)
	pa, err := e.h.sealer.open(c.Name, c.Value)
	if err != nil {
		t.Fatal(err)
	}
	if pa.ReturnTo != "https://app.example.test:8443/x?y=1" {
		t.Errorf("ReturnTo = %q, want the canonical URL", pa.ReturnTo)
	}
}

func TestLoginRejectsBadReturnURLs(t *testing.T) {
	e := newLoginEnv(t, "127.0.0.1:8443")
	for _, q := range []string{
		"rd=" + url.QueryEscape("https://evil.com"),
		"rd=" + url.QueryEscape("//evil.com"),
		"rd=" + url.QueryEscape("https:evil.com"),
		"rd=" + url.QueryEscape(`/\evil.com`),
		"rd=" + url.QueryEscape("javascript:alert(1)"),
		"rd=",
		"rd=" + url.QueryEscape("https://app.example.test/") + "&rd=" + url.QueryEscape("https://evil.com"),
	} {
		resp := e.do(t, http.MethodGet, "https://"+testAuthDomain+LoginPath+"?"+q)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, resp.StatusCode)
		}
		if len(resp.Cookies()) != 0 || resp.Header.Get("Location") != "" {
			t.Errorf("%s: started a login anyway", q)
		}
	}
}
