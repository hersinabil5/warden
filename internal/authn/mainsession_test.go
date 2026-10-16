package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// MainSession accepts only the auth host's main session cookie.
func TestMainSession(t *testing.T) {
	e := newFlowEnv(t)
	j := jar{}
	if _, s := e.browse(t, j, "https://"+appHost+":8443/"); s == nil {
		t.Fatal("login failed")
	}
	mainCookie, appCookie := j[testAuthDomain][sessionCookie], j[appHost][sessionCookie]
	get := func(cookies ...*http.Cookie) *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+testAuthDomain+"/.warden/api/me", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return req
	}
	s, err := e.h.MainSession(get(mainCookie), "req-1")
	if err != nil || s == nil || s.Username != "alice" || s.Hash == "" {
		t.Fatalf("main cookie: %+v, %v", s, err)
	}
	for name, req := range map[string]*http.Request{
		"no cookie":  get(),
		"app cookie": get(appCookie),
		"garbage":    get(&http.Cookie{Name: sessionCookie, Value: "x"}), //nolint:gosec // G124: request cookie; attributes are not sent by clients
	} {
		if s, err := e.h.MainSession(req, "req-1"); s != nil || err != nil {
			t.Errorf("%s: %+v, %v; want no session", name, s, err)
		}
	}
	if err := e.sessions.Delete(t.Context(), mainCookie.Value); err != nil {
		t.Fatal(err)
	}
	if s, err := e.h.MainSession(get(mainCookie), "req-1"); s != nil || err != nil {
		t.Errorf("revoked: %+v, %v", s, err)
	}
	e.mr.Close()
	if _, err := e.h.MainSession(get(mainCookie), "req-1"); err == nil {
		t.Error("Redis down: no error")
	}
}
