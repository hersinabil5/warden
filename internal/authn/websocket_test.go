package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hersinabil5/warden/internal/session"
)

func wsRequest(t *testing.T, target string, cookies ...*http.Cookie) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

const appWS = "https://" + appHost + ":8443/ws"

// A WebSocket can't follow a login redirect; it gets a 401, and no
// handshake cookie is planted.
func TestWebSocketWithoutSessionIs401(t *testing.T) {
	e := newFlowEnv(t)
	rec := httptest.NewRecorder()
	if _, ok := e.h.Authenticate(rec, wsRequest(t, appWS), appHost); ok {
		t.Fatal("authenticated without a session")
	}
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("status %d, Location %q, Set-Cookie %q; want a bare 401",
			rec.Code, rec.Header().Get("Location"), rec.Header().Get("Set-Cookie"))
	}
}

func TestWebSocketStepUpIs403(t *testing.T) {
	e := newFlowEnv(t)
	rec := httptest.NewRecorder()
	e.h.StepUp(rec, wsRequest(t, appWS), appHost)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Location") != "" {
		t.Errorf("status %d, Location %q; want 403 and no redirect", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRecheck(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	req := wsRequest(t, appWS, j.forHost(appHost)...)
	sess, err := e.h.Recheck(t.Context(), req, appHost, "req-1")
	if err != nil || sess.Username != "alice" {
		t.Fatalf("Recheck = %+v, %v", sess, err)
	}
	// Recheck writes nothing: the connection is hijacked by then.
	if _, err := e.h.Recheck(t.Context(), wsRequest(t, appWS), appHost, "req-2"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("no cookie: %v, want ErrNotFound", err)
	}
	// The app cookie is only good on its own host.
	if _, err := e.h.Recheck(t.Context(), req, "other.example.test", "req-3"); err == nil {
		t.Error("app cookie accepted for another host")
	}
	main, _ := e.mainSession(t, j)
	if err := e.sessions.DeleteHash(t.Context(), main.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := e.h.Recheck(t.Context(), req, appHost, "req-4"); err == nil {
		t.Error("revoked session still passes Recheck")
	}
}

func TestRecheckFailsClosedWhenStoreIsDown(t *testing.T) {
	e := newFlowEnv(t)
	j := e.signIn(t)
	e.mr.Close()
	if _, err := e.h.Recheck(t.Context(), wsRequest(t, appWS, j.forHost(appHost)...), appHost, "req-1"); err == nil {
		t.Error("Recheck passed with the session store down")
	}
}

// Group refresh applies to sockets too: a user removed at the IdP fails the
// next check.
func TestRecheckRefreshesGroups(t *testing.T) {
	e := newFlowEnv(t, refreshEvery)
	j := e.signIn(t)
	e.idp.RevokeRefreshTokens()
	if _, err := e.h.Recheck(t.Context(), wsRequest(t, appWS, j.forHost(appHost)...), appHost, "req-1"); err == nil {
		t.Error("Recheck passed after the IdP revoked the user")
	}
}
