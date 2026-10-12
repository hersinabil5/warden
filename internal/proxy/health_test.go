package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	up := newEcho(t)
	cfg := testConfig(t, up.URL)

	tests := []struct {
		name        string
		allowUnauth bool
		method      string
		host, path  string
		wantStatus  int
		wantBody    string
	}{
		{"GET on route host", true, http.MethodGet, "app.example.test", "/.warden/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"works without dev flag", false, http.MethodGet, "app.example.test", "/.warden/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"auth domain", false, http.MethodGet, "auth.example.test", "/.warden/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"unknown host", false, http.MethodGet, "anything.example", "/.warden/healthz", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"query ignored", false, http.MethodGet, "app.example.test", "/.warden/healthz?x=1", http.StatusOK, `{"status":"ok"}` + "\n"},
		{"HEAD", false, http.MethodHead, "app.example.test", "/.warden/healthz", http.StatusOK, ""},
		{"POST not allowed", false, http.MethodPost, "app.example.test", "/.warden/healthz", http.StatusMethodNotAllowed, ""},
		{"trailing slash", false, http.MethodGet, "app.example.test", "/.warden/healthz/", http.StatusNotFound, ""},
		{"longer name", false, http.MethodGet, "app.example.test", "/.warden/healthzz", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(t, cfg, tt.allowUnauth)
			before := up.hits.Load()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
			req.Host = tt.host
			rec := serve(h, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if up.hits.Load() != before {
				t.Error("health check reached the upstream")
			}
			if rec.Header().Get(RequestIDHeader) == "" {
				t.Error("no request ID")
			}
			switch tt.wantStatus {
			case http.StatusOK:
				if got := rec.Body.String(); got != tt.wantBody {
					t.Errorf("body = %q, want %q", got, tt.wantBody)
				}
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q", ct)
				}
				if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
					t.Errorf("Cache-Control = %q, want no-store", cc)
				}
			case http.StatusMethodNotAllowed:
				if allow := rec.Header().Get("Allow"); allow != "GET, HEAD" {
					t.Errorf("Allow = %q, want \"GET, HEAD\"", allow)
				}
			}
		})
	}
}
