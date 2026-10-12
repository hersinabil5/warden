package proxy

import (
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hersinabil5/warden/internal/config"
)

// seenRequest is what the echo upstream reports about the request it got.
type seenRequest struct {
	Method string      `json:"method"`
	URI    string      `json:"uri"`
	Host   string      `json:"host"`
	Header http.Header `json:"header"`
}

type echoUpstream struct {
	*httptest.Server
	hits atomic.Int64
}

func newEcho(t *testing.T) *echoUpstream {
	t.Helper()
	e := &echoUpstream{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(seenRequest{r.Method, r.RequestURI, r.Host, r.Header})
	}))
	t.Cleanup(e.Close)
	return e
}

func testConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		Listen:             "127.0.0.1:8443",
		HTTPRedirectListen: "127.0.0.1:8080",
		Auth:               config.Auth{Domain: "auth.example.test"},
		Routes:             []config.Route{{Host: "app.example.test", UpstreamURL: u}},
	}
}

func newTestHandler(t *testing.T, cfg *config.Config, allowUnauth bool) *Handler {
	t.Helper()
	h, err := New(cfg, Options{AllowUnauthenticated: allowUnauth, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeSeen(t *testing.T, rec *httptest.ResponseRecorder) seenRequest {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", rec.Code, rec.Body.String())
	}
	var s seenRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("upstream response not JSON: %v\n%s", err, rec.Body.String())
	}
	return s
}

func TestRoutesByHost(t *testing.T) {
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL), true)

	for _, host := range []string{"app.example.test", "APP.example.TEST", "app.example.test:8443"} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/some/path?q=1", nil)
			req.Host = host
			seen := decodeSeen(t, serve(h, req))
			if seen.URI != "/some/path?q=1" {
				t.Errorf("upstream URI = %q, want /some/path?q=1", seen.URI)
			}
		})
	}
}

func TestUnroutableRequestsAreNotProxied(t *testing.T) {
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL), true)

	tests := []struct {
		name, host, path string
		want             int
	}{
		{"unknown host", "evil.example", "/", http.StatusNotFound},
		{"suffix of known host", "x.app.example.test", "/", http.StatusNotFound},
		{"known host as suffix", "app.example.test.evil.example", "/", http.StatusNotFound},
		{"trailing dot", "app.example.test.", "/", http.StatusNotFound},
		{"empty host", "", "/", http.StatusNotFound},
		{"IP host", "127.0.0.1", "/", http.StatusNotFound},
		{"auth domain has no upstream", "auth.example.test", "/", http.StatusNotFound},
		// /.warden/ belongs to Warden on every host and never reaches an upstream.
		{"reserved prefix", "app.example.test", "/.warden/anything", http.StatusNotFound},
		{"reserved prefix bare", "app.example.test", "/.warden", http.StatusNotFound},
		{"reserved prefix encoded dot", "app.example.test", "/%2Ewarden/anything", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := up.hits.Load()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			req.Host = tt.host
			rec := serve(h, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if up.hits.Load() != before {
				t.Error("request reached the upstream")
			}
			id := rec.Header().Get(RequestIDHeader)
			if id == "" || !strings.Contains(rec.Body.String(), id) {
				t.Errorf("error page missing request ID %q", id)
			}
		})
	}
}

// A TLS connection established for one name must not be used to reach another
// host (cert/policy confusion, domain fronting).
func TestSNIMustMatchHost(t *testing.T) {
	up := newEcho(t)
	cfg := testConfig(t, up.URL)
	u2, _ := url.Parse(up.URL)
	cfg.Routes = append(cfg.Routes, config.Route{Host: "other.example.test", UpstreamURL: u2})
	h := newTestHandler(t, cfg, true)

	tests := []struct {
		name, sni, host string
		want            int
	}{
		{"match", "app.example.test", "app.example.test", http.StatusOK},
		{"match case-insensitive", "APP.example.test", "app.example.test:8443", http.StatusOK},
		{"no SNI", "", "app.example.test", http.StatusOK},
		{"mismatch", "other.example.test", "app.example.test", http.StatusMisdirectedRequest},
		{"mismatch to unknown", "app.example.test", "evil.example", http.StatusMisdirectedRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := up.hits.Load()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			req.Host = tt.host
			req.TLS = &tls.ConnectionState{ServerName: tt.sni}
			rec := serve(h, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want != http.StatusOK && up.hits.Load() != before {
				t.Error("request reached the upstream")
			}
		})
	}
}

// Without the dev flag there is no way to authenticate yet, so every proxied
// request is denied (invariant 1).
func TestDefaultDenyWithoutDevFlag(t *testing.T) {
	up := newEcho(t)
	h := newTestHandler(t, testConfig(t, up.URL), false)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	rec := serve(h, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if up.hits.Load() != 0 {
		t.Error("request reached the upstream")
	}
}

func TestDevFlagRequiresLoopbackListeners(t *testing.T) {
	tests := []struct {
		name, listen, redirect string
		wantErr                bool
	}{
		{"loopback v4", "127.0.0.1:8443", "127.0.0.1:8080", false},
		{"localhost", "localhost:8443", "localhost:8080", false},
		{"loopback v6", "[::1]:8443", "", false},
		{"all interfaces", ":8443", "127.0.0.1:8080", true},
		{"unspecified v4", "0.0.0.0:8443", "127.0.0.1:8080", true},
		{"public address", "192.0.2.10:8443", "127.0.0.1:8080", true},
		{"redirect on all interfaces", "127.0.0.1:8443", ":8080", true},
		{"localhost lookalike", "localhost.evil.example:8443", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, "http://127.0.0.1:1")
			cfg.Listen, cfg.HTTPRedirectListen = tt.listen, tt.redirect

			_, err := New(cfg, Options{AllowUnauthenticated: true, Logger: slog.New(slog.DiscardHandler)})
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			// Without the flag, any listener is fine.
			if _, err := New(cfg, Options{Logger: slog.New(slog.DiscardHandler)}); err != nil {
				t.Errorf("without dev flag: %v", err)
			}
		})
	}
}

func TestNewRejectsRouteWithoutUpstream(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	cfg.Routes[0].UpstreamURL = nil
	if _, err := New(cfg, Options{Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("New accepted a route with no parsed upstream")
	}
}
