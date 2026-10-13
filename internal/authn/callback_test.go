package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/hersinabil5/warden/internal/authn/testidp"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

const sessionCookie = "_warden"

// flowEnv is a Handler wired to a fake IdP and an in-memory Redis.
type flowEnv struct {
	idp      *testidp.IdP
	mr       *miniredis.Miniredis
	sessions *session.Store
	h        *Handler
	logs     *syncBuffer
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	idp := testidp.New(t)
	auth := authConfig(idp.Issuer)
	auth.Domain = testAuthDomain
	auth.Scopes = []string{"openid", "email", "profile"}
	auth.ClientSecret = config.NewSecret(testidp.ClientSecret)
	auth.GroupsClaim = "groups"
	var logs syncBuffer
	opts := fastOptions(&logs)
	p, err := Discover(t.Context(), auth, opts)
	if err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rdb := session.NewClient(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb, session.Options{AbsoluteTTL: 8 * time.Hour, IdleTimeout: time.Hour})
	key, err := NewCookieKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Listen:  "127.0.0.1:8443",
		Auth:    auth,
		Session: config.Session{CookieName: sessionCookie, AbsoluteTTL: 8 * time.Hour, IdleTimeout: time.Hour},
		Routes:  []config.Route{{Host: "app.example.test"}, {Host: "other.example.test"}},
	}
	h, err := NewHandler(cfg, p, HandlerOptions{CookieKey: key, Sessions: store, Logger: opts.Logger})
	if err != nil {
		t.Fatal(err)
	}
	return &flowEnv{idp: idp, mr: mr, sessions: store, h: h, logs: &logs}
}

// serve runs one request through the handler with the given cookies.
func (e *flowEnv) serve(t *testing.T, method, target string, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Result()
}

// authorize follows the login redirect to the fake IdP and returns the
// callback URL it redirects back to.
func (e *flowEnv) authorize(t *testing.T, authURL string) string {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP authorize status = %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// begin starts a login and returns the IdP's callback URL and the pre-auth
// cookie, without calling the callback.
func (e *flowEnv) begin(t *testing.T, loginQuery string) (callback string, preauth *http.Cookie) {
	t.Helper()
	resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+LoginPath+loginQuery)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound || len(resp.Cookies()) != 1 {
		t.Fatalf("login: status %d, %d cookies", resp.StatusCode, len(resp.Cookies()))
	}
	return e.authorize(t, resp.Header.Get("Location")), resp.Cookies()[0]
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (e *flowEnv) sessionCount() int {
	n := 0
	for _, k := range e.mr.Keys() {
		if strings.HasPrefix(k, "warden:s:") {
			n++
		}
	}
	return n
}

func TestCallbackCreatesSession(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	resp := e.serve(t, http.MethodGet, cb, pre)
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != SessionPath {
		t.Fatalf("callback = %d -> %q, want 302 -> %s", resp.StatusCode, resp.Header.Get("Location"), SessionPath)
	}
	sc := cookieNamed(resp, sessionCookie)
	if sc == nil {
		t.Fatal("no session cookie")
	}
	if !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" {
		t.Errorf("session cookie attributes: %+v", sc)
	}
	if sc.MaxAge <= 0 || sc.MaxAge > int((8*time.Hour).Seconds()) {
		t.Errorf("session cookie Max-Age = %d", sc.MaxAge)
	}
	if cleared := cookieNamed(resp, pre.Name); cleared == nil || cleared.MaxAge >= 0 {
		t.Error("pre-auth cookie not cleared")
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}

	sess, err := e.sessions.Get(t.Context(), sc.Value)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}
	if sess.Subject != "user-1" || sess.Username != "alice" || sess.Email != "alice@example.test" ||
		strings.Join(sess.Groups, ",") != "admins,sre" || strings.Join(sess.AMR, ",") != "pwd" ||
		sess.AuthTime.IsZero() || !strings.HasPrefix(sess.RefreshToken, "rt-") {
		t.Errorf("session = %+v (groups %v)", sess, sess.Groups)
	}
	if q := e.idp.LastAuthorize(); q.Get("code_challenge_method") != "S256" {
		t.Errorf("authorize used %q", q.Get("code_challenge_method"))
	}
}

func TestCallbackRejectsReusedState(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	first := e.serve(t, http.MethodGet, cb, pre)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusFound {
		t.Fatalf("first callback = %d", first.StatusCode)
	}
	// Replay with the same URL and a kept copy of the pre-auth cookie. It
	// must be refused by Warden's state check, before the IdP sees the code.
	hits := e.idp.TokenHits()
	replay := e.serve(t, http.MethodGet, cb, pre)
	_ = replay.Body.Close()
	if e.idp.TokenHits() != hits {
		t.Error("replayed state reached the token endpoint")
	}
	if replay.StatusCode != http.StatusBadRequest || cookieNamed(replay, sessionCookie) != nil {
		t.Errorf("replay = %d, want 400 and no session", replay.StatusCode)
	}
	if e.sessionCount() != 1 {
		t.Errorf("%d sessions, want 1", e.sessionCount())
	}
}

func TestCallbackRejectsBadRequests(t *testing.T) {
	base := "https://" + testAuthDomain + CallbackPath
	// Each case gets a fresh login, so one case's state use cannot mask
	// another's rejection reason.
	type login struct {
		cb, state, code string
		pre, otherPre   *http.Cookie
	}
	tests := []struct {
		name  string
		build func(l login) (string, []*http.Cookie)
	}{
		{"missing state", func(l login) (string, []*http.Cookie) {
			return base + "?code=" + l.code, []*http.Cookie{l.pre}
		}},
		{"empty state", func(l login) (string, []*http.Cookie) {
			return base + "?state=&code=" + l.code, []*http.Cookie{l.pre}
		}},
		{"duplicate state", func(l login) (string, []*http.Cookie) {
			return base + "?state=" + l.state + "&state=" + l.state + "&code=" + l.code, []*http.Cookie{l.pre}
		}},
		{"missing code", func(l login) (string, []*http.Cookie) {
			return base + "?state=" + l.state, []*http.Cookie{l.pre}
		}},
		{"duplicate code", func(l login) (string, []*http.Cookie) {
			return base + "?state=" + l.state + "&code=" + l.code + "&code=x", []*http.Cookie{l.pre}
		}},
		{"no pre-auth cookie (login CSRF)", func(l login) (string, []*http.Cookie) { return l.cb, nil }},
		{"other login's cookie", func(l login) (string, []*http.Cookie) { return l.cb, []*http.Cookie{l.otherPre} }},
		{"forged cookie value", func(l login) (string, []*http.Cookie) {
			f := *l.pre //nolint:gosec // G124: request cookie; attributes are not sent by clients
			f.Value = strings.Repeat("A", len(l.pre.Value))
			return l.cb, []*http.Cookie{&f}
		}},
		{"cookie value moved between logins", func(l login) (string, []*http.Cookie) {
			m := *l.otherPre //nolint:gosec // G124: request cookie; attributes are not sent by clients
			m.Name = l.pre.Name
			return l.cb, []*http.Cookie{&m}
		}},
		{"state differs from cookie", func(l login) (string, []*http.Cookie) {
			return base + "?state=" + l.state[:len(l.state)-1] + "x&code=" + l.code, []*http.Cookie{l.pre}
		}},
		{"IdP error", func(l login) (string, []*http.Cookie) {
			return base + "?state=" + l.state + "&error=access_denied", []*http.Cookie{l.pre}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFlowEnv(t)
			cb, pre := e.begin(t, "")
			_, otherPre := e.begin(t, "")
			u, _ := url.Parse(cb)
			target, cookies := tt.build(login{cb: cb, state: u.Query().Get("state"), code: u.Query().Get("code"), pre: pre, otherPre: otherPre})
			resp := e.serve(t, http.MethodGet, target, cookies...)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if cookieNamed(resp, sessionCookie) != nil || e.sessionCount() != 0 {
				t.Error("session created")
			}
			if n := e.idp.TokenHits(); n != 0 {
				t.Errorf("token endpoint called %d times", n)
			}
			if !strings.Contains(e.logs.String(), "login rejected") {
				t.Error("rejection not logged")
			}
		})
	}
}

func TestCallbackRejectsBadIDTokens(t *testing.T) {
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tests := []struct {
		name string
		edit func(c map[string]any)
		sign func(e *flowEnv) func(map[string]any) string
	}{
		{name: "wrong nonce", edit: func(c map[string]any) { c["nonce"] = "attacker-nonce" }},
		{name: "missing nonce", edit: func(c map[string]any) { delete(c, "nonce") }},
		{name: "expired", edit: func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() }},
		{name: "wrong audience", edit: func(c map[string]any) { c["aud"] = "other-client" }},
		{name: "extra audience without azp", edit: func(c map[string]any) { c["aud"] = []string{testidp.ClientID, "other"} }},
		{name: "azp is another client", edit: func(c map[string]any) { c["azp"] = "other-client" }},
		{name: "wrong issuer", edit: func(c map[string]any) { c["iss"] = "https://evil.example.test/realms/test" }},
		{name: "issued in the future", edit: func(c map[string]any) { c["iat"] = now.Add(10 * time.Minute).Unix() }},
		{name: "issued before login started", edit: func(c map[string]any) { c["iat"] = now.Add(-time.Hour).Unix() }},
		{name: "missing iat", edit: func(c map[string]any) { delete(c, "iat") }},
		{name: "missing sub", edit: func(c map[string]any) { delete(c, "sub") }},
		{name: "groups not a list", edit: func(c map[string]any) { c["groups"] = "admins" }},
		{name: "bad signature", sign: func(*flowEnv) func(map[string]any) string {
			return func(c map[string]any) string { return signWithKey(otherKey, c) }
		}},
		{name: "alg none", sign: func(*flowEnv) func(map[string]any) string {
			return func(c map[string]any) string { return noneToken(c) }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newFlowEnv(t)
			if tt.edit != nil {
				e.idp.EditIDToken(tt.edit)
			}
			if tt.sign != nil {
				e.idp.SignIDTokenWith(tt.sign(e))
			}
			cb, pre := e.begin(t, "")
			resp := e.serve(t, http.MethodGet, cb, pre)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || cookieNamed(resp, sessionCookie) != nil {
				t.Errorf("status = %d, want 400 and no session", resp.StatusCode)
			}
			if e.sessionCount() != 0 {
				t.Error("session created")
			}
		})
	}
}

func signWithKey(key *rsa.PrivateKey, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: testidp.KeyID}}, nil)
	if err != nil {
		panic(err)
	}
	p, _ := json.Marshal(claims)
	jws, err := signer.Sign(p)
	if err != nil {
		panic(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

func noneToken(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": testidp.KeyID})
	p, _ := json.Marshal(claims)
	return b64(h) + "." + b64(p) + "."
}

func TestCallbackAcceptsAzpForMultipleAudiences(t *testing.T) {
	e := newFlowEnv(t)
	e.idp.EditIDToken(func(c map[string]any) {
		c["aud"] = []string{testidp.ClientID, "other"}
		c["azp"] = testidp.ClientID
	})
	cb, pre := e.begin(t, "")
	resp := e.serve(t, http.MethodGet, cb, pre)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
}

// Unverified email must not reach the session, where email_domains rules
// would trust it.
func TestCallbackDropsUnverifiedEmail(t *testing.T) {
	for _, verified := range []any{false, "true", nil} {
		e := newFlowEnv(t)
		e.idp.EditIDToken(func(c map[string]any) {
			if verified == nil {
				delete(c, "email_verified")
			} else {
				c["email_verified"] = verified
			}
		})
		cb, pre := e.begin(t, "")
		resp := e.serve(t, http.MethodGet, cb, pre)
		_ = resp.Body.Close()
		sc := cookieNamed(resp, sessionCookie)
		if sc == nil {
			t.Fatalf("email_verified=%v: no session", verified)
		}
		sess, err := e.sessions.Get(t.Context(), sc.Value)
		if err != nil {
			t.Fatal(err)
		}
		if sess.Email != "" {
			t.Errorf("email_verified=%v: email %q kept", verified, sess.Email)
		}
	}
}

func TestCallbackTokenEndpointFailures(t *testing.T) {
	t.Run("IdP rejects the code", func(t *testing.T) {
		e := newFlowEnv(t)
		e.idp.FailToken(http.StatusBadRequest)
		cb, pre := e.begin(t, "")
		resp := e.serve(t, http.MethodGet, cb, pre)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || e.sessionCount() != 0 {
			t.Errorf("status = %d, sessions = %d", resp.StatusCode, e.sessionCount())
		}
	})
	t.Run("wrong client secret", func(t *testing.T) {
		e := newFlowEnv(t)
		e.idp.SetClientSecret("rotated")
		cb, pre := e.begin(t, "")
		resp := e.serve(t, http.MethodGet, cb, pre)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusFound || e.sessionCount() != 0 {
			t.Errorf("status = %d, sessions = %d", resp.StatusCode, e.sessionCount())
		}
	})
	t.Run("IdP down", func(t *testing.T) {
		e := newFlowEnv(t)
		cb, pre := e.begin(t, "")
		e.idp.Server.Close()
		resp := e.serve(t, http.MethodGet, cb, pre)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || e.sessionCount() != 0 {
			t.Errorf("status = %d, want 502", resp.StatusCode)
		}
	})
}

func TestCallbackRedisDownDenies(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	e.mr.Close()
	resp := e.serve(t, http.MethodGet, cb, pre)
	_ = resp.Body.Close()
	if resp.StatusCode < 500 || cookieNamed(resp, sessionCookie) != nil {
		t.Errorf("status = %d, want 5xx and no session", resp.StatusCode)
	}
}

// T2: a session ID planted before login is never adopted, and is revoked.
func TestCallbackRotatesSession(t *testing.T) {
	e := newFlowEnv(t)
	oldID, err := e.sessions.Create(t.Context(), session.Session{Subject: "attacker"})
	if err != nil {
		t.Fatal(err)
	}
	cb, pre := e.begin(t, "")
	planted := &http.Cookie{Name: sessionCookie, Value: oldID} //nolint:gosec // G124: request cookie; attributes are not sent by clients
	resp := e.serve(t, http.MethodGet, cb, pre, planted)
	_ = resp.Body.Close()
	sc := cookieNamed(resp, sessionCookie)
	if sc == nil || sc.Value == oldID {
		t.Fatal("session ID not rotated")
	}
	if _, err := e.sessions.Get(t.Context(), oldID); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("old session still valid: %v", err)
	}
}

func TestCallbackDoesNotLogSecrets(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	resp := e.serve(t, http.MethodGet, cb, pre)
	_ = resp.Body.Close()
	sc := cookieNamed(resp, sessionCookie)
	if sc == nil {
		t.Fatal("no session")
	}
	sess, _ := e.sessions.Get(t.Context(), sc.Value)
	u, _ := url.Parse(cb)
	logs := e.logs.String()
	for _, s := range []string{u.Query().Get("code"), u.Query().Get("state"), pre.Value, sc.Value, sess.RefreshToken, testidp.ClientSecret} {
		if s != "" && strings.Contains(logs, s) {
			t.Errorf("logs contain secret %q", s)
		}
	}
	if !strings.Contains(logs, "login succeeded") {
		t.Errorf("no success log:\n%s", logs)
	}
}

func TestCallbackRejectsOtherMethods(t *testing.T) {
	e := newFlowEnv(t)
	cb, pre := e.begin(t, "")
	resp := e.serve(t, http.MethodPost, cb, pre)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestSessionPage(t *testing.T) {
	e := newFlowEnv(t)
	resp := e.serve(t, http.MethodGet, "https://"+testAuthDomain+SessionPath)
	defer func() { _ = resp.Body.Close() }()
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Not signed in") {
		t.Errorf("logged out page = %d %q", resp.StatusCode, body)
	}

	e.idp.EditIDToken(func(c map[string]any) { c["preferred_username"] = "<script>alert(1)</script>" })
	cb, pre := e.begin(t, "")
	login := e.serve(t, http.MethodGet, cb, pre)
	_ = login.Body.Close()
	signedIn := e.serve(t, http.MethodGet, "https://"+testAuthDomain+SessionPath, cookieNamed(login, sessionCookie))
	defer func() { _ = signedIn.Body.Close() }()
	body = readBody(t, signedIn)
	resp = signedIn
	if !strings.Contains(body, "Signed in as") || strings.Contains(body, "<script>") {
		t.Errorf("session page not escaped or missing user: %q", body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
}

// readBody reads the body; callers close it.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
