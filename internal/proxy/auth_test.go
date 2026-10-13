package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAuth records what reaches the auth handler and the request ID it sees.
type fakeAuth struct {
	paths []string
	ids   []string
}

func (f *fakeAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.URL.Path)
	f.ids = append(f.ids, w.Header().Get(RequestIDHeader))
	w.WriteHeader(http.StatusTeapot)
}

func TestAuthHandlerOnlyOnAuthHost(t *testing.T) {
	echo := newEcho(t)
	auth := &fakeAuth{}
	h, err := New(testConfig(t, echo.URL), Options{Auth: auth, SkipPolicy: true, Authenticator: allowAll{}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, url  string
		wantStatus int
		wantAuth   bool
	}{
		{"login on auth host", "https://auth.example.test/.warden/login", http.StatusTeapot, true},
		{"unknown warden path on auth host", "https://auth.example.test/.warden/nope", http.StatusTeapot, true},
		{"auth host port in Host", "https://auth.example.test:8443/.warden/login", http.StatusTeapot, true},
		{"auth host upper case", "https://AUTH.example.test/.warden/login", http.StatusTeapot, true},
		{"healthz still served by proxy", "https://auth.example.test/.warden/healthz", http.StatusOK, false},
		{"non-warden path on auth host", "https://auth.example.test/login", http.StatusNotFound, false},
		{"warden lookalike prefix", "https://auth.example.test/.wardenx/login", http.StatusNotFound, false},
		// Route hosts reach the auth handler too (for the handshake); it
		// decides what exists there (authn tests cover login being 404).
		{"warden path on app host", "https://app.example.test/.warden/handshake", http.StatusTeapot, true},
		{"login on unknown host", "https://evil.example/.warden/login", http.StatusNotFound, false},
		{"auth host lookalike", "https://auth.example.test.evil/.warden/login", http.StatusNotFound, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(auth.paths)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.url, nil)
			req.TLS.ServerName = req.URL.Hostname() // real SNI never carries a port
			rec := serve(h, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := len(auth.paths) > before; got != tt.wantAuth {
				t.Errorf("reached auth handler = %v, want %v", got, tt.wantAuth)
			}
		})
	}
	if echo.hits.Load() != 0 {
		t.Errorf("upstream got %d requests, want 0", echo.hits.Load())
	}
}

func TestAuthHandlerSeesWardenRequestID(t *testing.T) {
	auth := &fakeAuth{}
	h, err := New(testConfig(t, newEcho(t).URL), Options{Auth: auth, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.warden/login", nil)
	req.Header.Set(RequestIDHeader, "forged")
	rec := serve(h, req)
	if len(auth.ids) != 1 || auth.ids[0] == "" || auth.ids[0] == "forged" || auth.ids[0] != rec.Header().Get(RequestIDHeader) {
		t.Errorf("auth handler saw request ID %v, response has %q", auth.ids, rec.Header().Get(RequestIDHeader))
	}
}

func TestErrorPageUsesRequestID(t *testing.T) {
	h, err := New(testConfig(t, newEcho(t).URL), Options{
		Auth: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ErrorPage(w, r, http.StatusMethodNotAllowed)
		}),
		Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(h, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://auth.example.test/.warden/login", nil))
	id := rec.Header().Get(RequestIDHeader)
	if rec.Code != http.StatusMethodNotAllowed || id == "" || !strings.Contains(rec.Body.String(), id) {
		t.Errorf("status %d, body %q, want 405 page with request ID %q", rec.Code, rec.Body.String(), id)
	}
}
