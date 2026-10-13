package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

var fastTimeouts = TransportTimeouts{
	Dial:           200 * time.Millisecond,
	TLSHandshake:   200 * time.Millisecond,
	ResponseHeader: 100 * time.Millisecond,
	ExpectContinue: 100 * time.Millisecond,
	IdleConn:       time.Second,
}

func newFastHandler(t *testing.T, cfg *config.Config, logs *bytes.Buffer) *Handler {
	t.Helper()
	h, err := New(cfg, Options{
		SkipPolicy: true, Authenticator: allowAll{},
		Logger:            slog.New(slog.NewJSONHandler(logs, nil)),
		TransportTimeouts: fastTimeouts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// assertBadGateway checks the generic 502 page: request ID present, no
// internal error details.
func assertBadGateway(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	id := rec.Header().Get(RequestIDHeader)
	body := rec.Body.String()
	if id == "" || !strings.Contains(body, id) {
		t.Errorf("502 page missing request ID %q", id)
	}
	for _, leak := range []string{"127.0.0.1", "dial", "timeout", "refused", "certificate", "tls:"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("502 page leaks internal detail %q:\n%s", leak, body)
		}
	}
}

func TestSlowUpstreamTimesOut(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer up.Close()
	defer close(release)

	var logs bytes.Buffer
	h := newFastHandler(t, testConfig(t, up.URL), &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/cb?code=SECRETCODE", nil)
	req.Host = "app.example.test"

	start := time.Now()
	rec := serve(h, req)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v; response header timeout not enforced", elapsed)
	}
	assertBadGateway(t, rec)

	if !strings.Contains(logs.String(), `"msg":"upstream error"`) ||
		!strings.Contains(logs.String(), rec.Header().Get(RequestIDHeader)) {
		t.Errorf("upstream error not logged with request ID:\n%s", logs.String())
	}
	// Regression guard: the query string must never reach logs (invariant 9).
	if strings.Contains(logs.String(), "SECRETCODE") {
		t.Errorf("query string leaked into logs:\n%s", logs.String())
	}
}

func TestUnreachableUpstream(t *testing.T) {
	// Reserve a port, then close it so connections are refused.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var logs bytes.Buffer
	h := newFastHandler(t, testConfig(t, "http://"+addr), &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	assertBadGateway(t, serve(h, req))
}

// HTTPS upstreams are verified; an untrusted certificate is a 502, never a
// silent InsecureSkipVerify.
func TestUntrustedUpstreamCertificate(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer up.Close()

	var logs bytes.Buffer
	h := newFastHandler(t, testConfig(t, up.URL), &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	assertBadGateway(t, serve(h, req))
}

// Until mTLS lands (M4), routes with upstream_tls fail closed rather than
// falling back to the system roots.
func TestUpstreamTLSFailsClosedUntilM4(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer up.Close()

	cfg := testConfig(t, up.URL)
	cfg.Routes[0].UpstreamTLS = &config.UpstreamTLS{CAFile: "ca.pem"}
	var logs bytes.Buffer
	h := newFastHandler(t, cfg, &logs)
	if !strings.Contains(logs.String(), "fails closed") {
		t.Errorf("no startup warning for upstream_tls:\n%s", logs.String())
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	assertBadGateway(t, serve(h, req))
}

func TestTransportSettings(t *testing.T) {
	tr := newTransport(DefaultTransportTimeouts, false)
	// http.DefaultTransport honors HTTP_PROXY; ours must not.
	if tr.Proxy != nil {
		t.Error("transport reads proxy settings from the environment")
	}
	if tr.TLSHandshakeTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 || tr.IdleConnTimeout <= 0 ||
		tr.ExpectContinueTimeout <= 0 || tr.DialContext == nil {
		t.Errorf("transport timeouts must all be set (invariant 10): %+v", DefaultTransportTimeouts)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("upstream TLS must verify certificates and require TLS 1.2+")
	}
}

// A client that never finishes its headers is disconnected (slow-loris).
func TestServerDropsSlowHeaders(t *testing.T) {
	srv := NewServer(http.NotFoundHandler(), ServerTimeouts{
		ReadHeader: 100 * time.Millisecond, Read: time.Second, Write: time.Second, Idle: time.Second,
	}, slog.New(slog.DiscardHandler))
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	d := net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\n"); err != nil { // headers never end
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, _ = io.ReadAll(conn) // returns when the server closes the connection
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("server held a slow-header connection for %v", elapsed)
	}
}
