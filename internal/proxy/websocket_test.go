package proxy

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // G505: RFC 6455 defines Sec-WebSocket-Accept with SHA-1
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// wsUpstream accepts RFC 6455 handshakes (and, if h2c is set, h2c
// upgrades), then echoes bytes until either side closes.
type wsUpstream struct {
	*httptest.Server
	hits   atomic.Int64
	mu     sync.Mutex
	seen   []*http.Request
	closed chan struct{} // one value per finished connection
}

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // G401: the RFC 6455 handshake, not a security use
	return base64.StdEncoding.EncodeToString(sum[:])
}

func newWSUpstream(t *testing.T, h2c bool) *wsUpstream {
	t.Helper()
	u := &wsUpstream{closed: make(chan struct{}, 16)}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		u.mu.Lock()
		u.seen = append(u.seen, r)
		u.mu.Unlock()
		up := strings.ToLower(r.Header.Get("Upgrade"))
		switch {
		case up == "websocket" && r.Header.Get("Sec-Websocket-Key") != "":
			w.Header().Set("Sec-WebSocket-Accept", wsAccept(r.Header.Get("Sec-Websocket-Key")))
		case up == "h2c" && h2c:
		default:
			_, _ = io.WriteString(w, "plain response to "+r.URL.Path) //nolint:gosec // G705: test upstream echoing its path
			return
		}
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", up)
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() {
			_ = conn.Close()
			u.closed <- struct{}{}
		}()
		_ = brw.Flush()
		_, _ = io.Copy(conn, brw)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *wsUpstream) last(t *testing.T) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.seen) == 0 {
		t.Fatal("upstream saw no request")
	}
	return u.seen[len(u.seen)-1]
}

// wsAuth authenticates as a fixed session and answers Recheck with whatever
// the test sets.
type wsAuth struct {
	sess    atomic.Pointer[session.Session]
	failErr atomic.Pointer[error]
	checks  atomic.Int64
}

func newWSAuth(s *session.Session) *wsAuth {
	a := &wsAuth{}
	a.sess.Store(s)
	return a
}

func (a *wsAuth) Authenticate(w http.ResponseWriter, r *http.Request, _ string) (*session.Session, bool) {
	if s := a.sess.Load(); s != nil {
		return s, true
	}
	w.WriteHeader(http.StatusUnauthorized)
	return nil, false
}

func (a *wsAuth) Recheck(context.Context, *http.Request, string, string) (*session.Session, error) {
	a.checks.Add(1)
	if e := a.failErr.Load(); e != nil {
		return nil, *e
	}
	if s := a.sess.Load(); s != nil {
		return s, nil
	}
	return nil, session.ErrNotFound
}

func (a *wsAuth) fail(err error) { a.failErr.Store(&err) }

// wsConfig is testConfig with /admin limited to admins with MFA within 10m.
func wsConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()
	cfg := testConfig(t, upstream)
	cfg.Routes[0].Policy = config.Policy{
		Allow: []config.Rule{{Authenticated: ptr(true)}},
		Paths: []config.PathRule{{Prefix: "/admin", Allow: []config.Rule{{Groups: []string{"admins"}, RequireMFAWithin: ptr(10 * time.Minute)}}}},
	}
	return cfg
}

type wsEnv struct {
	warden *httptest.Server
	up     *wsUpstream
	auth   *wsAuth
	log    *auditLog
	now    *atomic.Pointer[time.Time]
}

func newWSEnv(t *testing.T, s *session.Session, h2c bool, authn Authenticator) *wsEnv {
	t.Helper()
	up := newWSUpstream(t, h2c)
	e := &wsEnv{up: up, auth: newWSAuth(s), log: &auditLog{}, now: &atomic.Pointer[time.Time]{}}
	start := testNow
	e.now.Store(&start)
	if authn == nil {
		authn = e.auth
	}
	h, err := New(wsConfig(t, up.URL), Options{
		Identity: testIdentity(t), Authenticator: authn, Audit: e.log,
		Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return *e.now.Load() },
		WebSocketRecheck: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.warden = httptest.NewServer(h)
	t.Cleanup(e.warden.Close)
	return e
}

func (l *auditLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 5s")
		}
		time.Sleep(5 * time.Millisecond) //nolint:forbidigo // polling in a test
	}
}

// dial sends one raw request to Warden and returns the response and the
// open connection.
func (e *wsEnv) dial(t *testing.T, path string, hdr map[string]string) (*http.Response, net.Conn, *bufio.Reader) {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(e.warden.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: app.example.test\r\n")
	for k, v := range hdr {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	if _, werr := io.WriteString(conn, b.String()); werr != nil {
		t.Fatal(werr)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, conn, br
}

const wsKey = "dGhlIHNhbXBsZSBub25jZQ=="

func wsHeaders(extra map[string]string) map[string]string {
	h := map[string]string{
		"Connection": "Upgrade", "Upgrade": "websocket",
		"Sec-WebSocket-Key": wsKey, "Sec-WebSocket-Version": "13",
		"Origin": "https://app.example.test:8443",
	}
	for k, v := range extra {
		if v == "" {
			delete(h, k)
			continue
		}
		h[k] = v
	}
	return h
}

func echo(t *testing.T, conn net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
	}
}

// waitClosed fails unless the proxied socket closes within d: the client
// sees EOF, and the upstream connection ends too.
func waitClosed(t *testing.T, e *wsEnv, conn net.Conn, br *bufio.Reader, d time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(d))
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("client connection still open (read: %v)", err)
	}
	select {
	case <-e.up.closed:
	case <-time.After(d):
		t.Fatal("upstream connection still open")
	}
}

func TestWebSocketProxied(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, nil)
	resp, conn, br := e.dial(t, "/ws?room=1", wsHeaders(map[string]string{"X-Warden-Identity": "forged", "X-Forwarded-User": "root"}))
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols || resp.Header.Get("Sec-Websocket-Accept") != wsAccept(wsKey) {
		t.Fatalf("status %d, accept %q", resp.StatusCode, resp.Header.Get("Sec-Websocket-Accept"))
	}
	echo(t, conn, br, "hello over the socket")
	got := e.up.last(t)
	if got.URL.Path != "/ws" || got.Header.Get("X-Forwarded-User") != "" {
		t.Errorf("upstream saw %s with X-Forwarded-User %q", got.URL.Path, got.Header.Get("X-Forwarded-User"))
	}
	if tok := got.Header.Get("X-Warden-Identity"); tok == "" || tok == "forged" {
		t.Errorf("identity header %q, want Warden's assertion", tok)
	}
	_ = conn.Close()
	select {
	case <-e.up.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not closed after the client left")
	}
	waitFor(t, func() bool { return e.log.count() == 1 })
	if ev := e.log.only(t); ev.Decision != audit.Allow || ev.Status != http.StatusSwitchingProtocols || ev.Path != "/ws" {
		t.Errorf("event = %+v, want an allow with status 101", ev)
	}
}

// Only WebSocket upgrades: anything else could turn the connection into a
// raw channel to the upstream (h2c smuggling), where per-path policy no
// longer applies.
func TestUnsupportedUpgradesRefused(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"h2c":            {"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c", "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA", "Origin": ""},
		"h2c, websocket": {"Upgrade": "h2c, websocket"},
		"websocket, h2c": {"Upgrade": "websocket, h2c"},
		"tls":            {"Upgrade": "TLS/1.2"},
		"websocket/2":    {"Upgrade": "websocket/2"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWSEnv(t, aliceSess, true, nil)
			resp, _, _ := e.dial(t, "/", wsHeaders(hdr))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
			if e.up.hits.Load() != 0 {
				t.Error("the upstream was reached")
			}
			if ev := e.log.only(t); ev.Decision != audit.Deny || ev.Reason != "unsupported upgrade" {
				t.Errorf("event = %+v", ev)
			}
		})
	}
}

// Half an upgrade (Upgrade without Connection: upgrade, or the reverse) is a
// plain request: nothing switches and the Upgrade header doesn't pass.
func TestHalfUpgradeIsPlainRequest(t *testing.T) {
	for name, hdr := range map[string]map[string]string{
		"h2c without connection token": {"Connection": "keep-alive", "Upgrade": "h2c"},
		"websocket without connection": {"Connection": ""},
		"connection without upgrade":   {"Upgrade": ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWSEnv(t, aliceSess, true, nil)
			resp, _, _ := e.dial(t, "/page", wsHeaders(hdr))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}
			if got := e.up.last(t).Header.Values("Upgrade"); len(got) != 0 {
				t.Errorf("upstream got Upgrade %q", got)
			}
		})
	}
}

// Case-insensitive token, as RFC 6455 allows.
func TestWebSocketUpgradeTokenCase(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, nil)
	resp, _, _ := e.dial(t, "/", wsHeaders(map[string]string{"Upgrade": "WebSocket", "Connection": "keep-alive, Upgrade"}))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("status %d, want 101", resp.StatusCode)
	}
}

// Cross-site WebSocket hijacking: another site, or a sibling app on the same
// site (SameSite=Lax cookies still flow), must not open a socket with the
// user's cookies.
func TestWebSocketOriginChecked(t *testing.T) {
	for _, origin := range []string{
		"https://evil.example",
		"https://other.example.test:8443",
		"https://app.example.test.evil.example:8443",
		"http://app.example.test:8443",
		"https://app.example.test:9443",
		"https://app.example.test",
		"null",
		"https://app.example.test:8443/path",
		"https://user@app.example.test:8443",
		"not a url",
	} {
		t.Run(origin, func(t *testing.T) {
			e := newWSEnv(t, aliceSess, false, nil)
			resp, _, _ := e.dial(t, "/", wsHeaders(map[string]string{"Origin": origin}))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || e.up.hits.Load() != 0 {
				t.Errorf("status %d, upstream hits %d; want 403 and none", resp.StatusCode, e.up.hits.Load())
			}
			if ev := e.log.only(t); ev.Reason != "cross-origin websocket" {
				t.Errorf("event = %+v", ev)
			}
		})
	}
	for _, origin := range []string{"https://APP.example.test:8443", ""} {
		e := newWSEnv(t, aliceSess, false, nil)
		resp, _, _ := e.dial(t, "/", wsHeaders(map[string]string{"Origin": origin}))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Errorf("Origin %q: status %d, want 101", origin, resp.StatusCode)
		}
	}
}

func TestWebSocketDenied(t *testing.T) {
	stale := *aliceSess
	stale.AuthTime = testNow.Add(-time.Hour)
	for _, tt := range []struct {
		name string
		s    *session.Session
		path string
		want int
	}{
		{"no session", nil, "/", http.StatusUnauthorized},
		{"policy deny", bobSess, "/admin", http.StatusForbidden},
		{"stale MFA", &stale, "/admin", http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newWSEnv(t, tt.s, false, nil)
			resp, _, _ := e.dial(t, tt.path, wsHeaders(nil))
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want || resp.Header.Get("Location") != "" || e.up.hits.Load() != 0 {
				t.Errorf("status %d, Location %q, upstream hits %d; want %d", resp.StatusCode, resp.Header.Get("Location"), e.up.hits.Load(), tt.want)
			}
		})
	}
}

// Without a way to re-check sessions, an open socket would outlive a
// revocation; so no sockets at all.
func TestWebSocketNeedsRechecker(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, asUser{aliceSess})
	resp, _, _ := e.dial(t, "/", wsHeaders(nil))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || e.up.hits.Load() != 0 {
		t.Errorf("status %d, upstream hits %d; want 403 and none", resp.StatusCode, e.up.hits.Load())
	}
	// Ordinary requests still work.
	resp, _, _ = e.dial(t, "/", nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("plain request: status %d", resp.StatusCode)
	}
}

// Revocation reaches open sockets (invariant 8): the periodic re-check
// closes them.
func TestWebSocketClosedOnRevocation(t *testing.T) {
	for name, change := range map[string]func(e *wsEnv){
		"session revoked": func(e *wsEnv) { e.auth.sess.Store(nil) },
		"store down":      func(e *wsEnv) { e.auth.fail(errors.New("redis: connection refused")) },
		"groups changed":  func(e *wsEnv) { e.auth.sess.Store(bobSess) }, // /admin needs admins
		"MFA window lapsed": func(e *wsEnv) {
			later := testNow.Add(time.Hour)
			e.now.Store(&later)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newWSEnv(t, aliceSess, false, nil)
			resp, conn, br := e.dial(t, "/admin/live", wsHeaders(nil))
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status %d", resp.StatusCode)
			}
			echo(t, conn, br, "before")
			waitFor(t, func() bool { return e.auth.checks.Load() >= 2 }) // checks keep passing meanwhile
			echo(t, conn, br, "still open")
			change(e)
			waitClosed(t, e, conn, br, 2*time.Second)
		})
	}
}

// The socket ends when the request does: no re-check goroutine outlives it.
func TestWebSocketRecheckStopsWithConnection(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, nil)
	resp, conn, br := e.dial(t, "/", wsHeaders(nil))
	_ = resp.Body.Close()
	echo(t, conn, br, "x")
	_ = conn.Close()
	<-e.up.closed
	waitFor(t, func() bool { return e.log.count() == 1 })
	n := e.auth.checks.Load()
	time.Sleep(100 * time.Millisecond) //nolint:forbidigo // several re-check intervals
	if got := e.auth.checks.Load(); got != n {
		t.Errorf("re-checks continued after close: %d -> %d", n, got)
	}
}

// HTTP/2 extended CONNECT (RFC 8441) is off in Go's server; a CONNECT on
// HTTP/1.1 is refused before routing.
func TestConnectRefused(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, nil)
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", strings.TrimPrefix(e.warden.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "CONNECT app.example.test:443 HTTP/1.1\r\nHost: app.example.test:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || e.up.hits.Load() != 0 {
		t.Errorf("CONNECT: status %d, upstream hits %d", resp.StatusCode, e.up.hits.Load())
	}
}

func TestPlainRequestToWebSocketUpstream(t *testing.T) {
	e := newWSEnv(t, aliceSess, false, nil)
	resp, _, br := e.dial(t, "/page", nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(br, int64(len("plain response to /page"))))
	if resp.StatusCode != http.StatusOK || string(body) != "plain response to /page" {
		t.Errorf("status %d body %q", resp.StatusCode, body)
	}
}
