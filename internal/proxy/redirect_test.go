package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestRedirect() http.Handler {
	return NewRedirectHandler([]string{"app.example.test", "auth.example.test"}, 8443, slog.New(slog.DiscardHandler))
}

func TestRedirectToHTTPS(t *testing.T) {
	tests := []struct {
		name, method, target, host, want string
	}{
		{"root", http.MethodGet, "/", "app.example.test", "https://app.example.test:8443/"},
		{"path and query", http.MethodGet, "/a/b?x=1&y=2", "app.example.test", "https://app.example.test:8443/a/b?x=1&y=2"},
		{"host with port", http.MethodGet, "/", "app.example.test:8080", "https://app.example.test:8443/"},
		{"host mixed case", http.MethodGet, "/", "APP.Example.test", "https://app.example.test:8443/"},
		{"auth domain", http.MethodGet, "/x", "auth.example.test", "https://auth.example.test:8443/x"},
		{"escaped path kept", http.MethodGet, "/a%2Fb", "app.example.test", "https://app.example.test:8443/a%2Fb"},
		// The path cannot change the destination host: it is always ours.
		{"double-slash path", http.MethodGet, "//evil.example/x", "app.example.test", "https://app.example.test:8443//evil.example/x"},
		{"post keeps method via 308", http.MethodPost, "/form", "app.example.test", "https://app.example.test:8443/form"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.target, nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			newTestRedirect().ServeHTTP(rec, req)
			if rec.Code != http.StatusPermanentRedirect {
				t.Fatalf("status = %d, want 308", rec.Code)
			}
			if got := rec.Header().Get("Location"); got != tt.want {
				t.Errorf("Location = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedirectDefaultPortOmitted(t *testing.T) {
	h := NewRedirectHandler([]string{"app.example.test"}, 443, slog.New(slog.DiscardHandler))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	req.Host = "app.example.test"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Location"); got != "https://app.example.test/x" {
		t.Errorf("Location = %q, want no :443", got)
	}
}

// The Host header is attacker-controlled. Redirecting to it would make
// Warden an open redirect (invariant 5).
func TestRedirectRejectsUnknownHosts(t *testing.T) {
	for _, host := range []string{
		"evil.example",
		"evil.example:8080",
		"app.example.test.evil.example",
		"app.example.test.", // trailing dot: not the configured spelling
		"",
		"127.0.0.1",
		"app.example.test:8080:1",
	} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Host = host
			rec := httptest.NewRecorder()
			newTestRedirect().ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("Location = %q, want none", loc)
			}
		})
	}
}

// An absolute-form request line overrides the Host header in Go's server.
// Exercise the real parser over a socket to be sure it can't smuggle a host.
func TestRedirectAbsoluteFormRequest(t *testing.T) {
	srv := httptest.NewServer(newTestRedirect())
	defer srv.Close()

	for _, tt := range []struct {
		name, requestLine, wantStatus, wantLocation string
	}{
		{"evil absolute URI", "GET http://evil.example/x HTTP/1.1", "400", ""},
		{"own absolute URI", "GET http://app.example.test/x HTTP/1.1", "308", "https://app.example.test:8443/x"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := net.Dialer{Timeout: time.Second}
			conn, err := d.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, err = io.WriteString(conn, tt.requestLine+"\r\nHost: app.example.test\r\nConnection: close\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if !strings.HasPrefix(resp.Status, tt.wantStatus) {
				t.Errorf("status = %q, want %s", resp.Status, tt.wantStatus)
			}
			if got := resp.Header.Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
		})
	}
}

func TestRedirectErrorPageHasRequestID(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "evil.example"
	rec := httptest.NewRecorder()
	newTestRedirect().ServeHTTP(rec, req)
	id := rec.Header().Get("X-Request-ID")
	if id == "" || !strings.Contains(rec.Body.String(), id) {
		t.Errorf("request ID %q missing from header or body:\n%s", id, rec.Body.String())
	}
}

// HSTS over plain HTTP is ignored by browsers and forbidden by RFC 6797
// (section 7.2); the redirect listener never sends it.
func TestRedirectSendsNoHSTS(t *testing.T) {
	for _, host := range []string{"app.example.test", "evil.example"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		newTestRedirect().ServeHTTP(rec, req)
		if got := rec.Header().Values("Strict-Transport-Security"); len(got) != 0 {
			t.Errorf("%s: Strict-Transport-Security = %q over plain HTTP", host, got)
		}
	}
}
