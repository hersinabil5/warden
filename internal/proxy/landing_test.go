package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLandingOnlyAtAuthRoot(t *testing.T) {
	up := newEcho(t)
	landing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h, err := New(testConfig(t, up.URL), Options{Audit: nopAudit{}, Identity: testIdentity(t), Authenticator: allowAll{},
		Logger: slog.New(slog.DiscardHandler), Landing: landing})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		host, path string
		want       int
	}{
		{"auth.example.test", "/", http.StatusTeapot},
		{"auth.example.test", "/x", http.StatusNotFound},
		{"auth.example.test", "//", http.StatusTeapot}, // normalized to "/"
		{"app.example.test", "/", http.StatusOK},       // the app's own root
		{"evil.example", "/", http.StatusNotFound},
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
		req.Host = tt.host
		if rec := serve(h, req); rec.Code != tt.want {
			t.Errorf("%s%s: %d, want %d", tt.host, tt.path, rec.Code, tt.want)
		}
	}
}

func TestNoLandingOutsideDemo(t *testing.T) {
	h := newTestHandler(t, testConfig(t, newEcho(t).URL))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "auth.example.test"
	if rec := serve(h, req); rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}
