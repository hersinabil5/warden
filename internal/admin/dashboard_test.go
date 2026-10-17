package admin

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

var builtFS = fstest.MapFS{
	"index.html":           {Data: []byte(`<!doctype html><script type="module" src="/.warden/admin/assets/app.js"></script>`)},
	"assets/app.js":        {Data: []byte(`console.log("app")`)},
	"assets/app.css":       {Data: []byte(`body{}`)},
	".gitkeep":             {Data: nil},
	"assets/.hidden":       {Data: []byte("secret")},
	"assets/nested/x.json": {Data: []byte(`{}`)},
}

func dashboardHandler(t *testing.T, files fstest.MapFS) http.Handler {
	t.Helper()
	opts := Options{Sessions: fakeStore{}, Decisions: audit.NewRecent(1), AuthOrigin: authOrigin, Logger: slog.New(slog.DiscardHandler)}
	if files != nil {
		opts.Dashboard = files
	}
	h, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func getAsAdmin(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, authOrigin+target, nil)
	req = req.WithContext(WithSession(req.Context(), &session.Session{Username: "alice"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDashboardServesIndexWithStrictHeaders(t *testing.T) {
	h := dashboardHandler(t, builtFS)
	rec := getAsAdmin(t, h, http.MethodGet, DashboardPrefix)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app.js") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	want := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Content-Security-Policy": DashboardCSP,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
		"X-Frame-Options":         "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(DashboardCSP, directive) {
			t.Errorf("CSP lacks %q", directive)
		}
	}
	if strings.Contains(DashboardCSP, "unsafe") {
		t.Errorf("CSP allows unsafe sources: %s", DashboardCSP)
	}
}

func TestDashboardRootRedirects(t *testing.T) {
	rec := getAsAdmin(t, dashboardHandler(t, builtFS), http.MethodGet, "/.warden/admin")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != DashboardPrefix {
		t.Errorf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestDashboardAssets(t *testing.T) {
	h := dashboardHandler(t, builtFS)
	for name, ctype := range map[string]string{"assets/app.js": "text/javascript; charset=utf-8", "assets/app.css": "text/css; charset=utf-8"} {
		rec := getAsAdmin(t, h, http.MethodGet, DashboardPrefix+name)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ctype {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get("Content-Type"))
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "private") || !strings.Contains(cc, "immutable") {
			t.Errorf("%s: Cache-Control %q", name, cc)
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no CSP", name)
		}
	}
	if rec := getAsAdmin(t, h, http.MethodHead, DashboardPrefix+"assets/app.js"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

// Only regular, non-hidden embedded files are served; nothing else is
// reachable.
func TestDashboardRefusesEverythingElse(t *testing.T) {
	h := dashboardHandler(t, builtFS)
	for _, p := range []string{
		"missing.js",
		"assets",
		"assets/",
		"assets/nested",
		".gitkeep",
		"assets/.hidden",
		"assets/../index.html",
		"../api/me",
		"assets/../../api/me",
		"./index.html",
		"assets//app.js",
		`assets\app.js`,
		"/etc/passwd",
	} {
		rec := getAsAdmin(t, h, http.MethodGet, DashboardPrefix+p)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%q: status %d, want 404", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "console.log") {
			t.Errorf("%q leaked content", p)
		}
	}
}

func TestDashboardIsReadOnly(t *testing.T) {
	h := dashboardHandler(t, builtFS)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := getAsAdmin(t, h, m, DashboardPrefix); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", m, rec.Code)
		}
	}
}

func TestDashboardNotBuilt(t *testing.T) {
	rec := getAsAdmin(t, dashboardHandler(t, fstest.MapFS{".gitkeep": {}}), http.MethodGet, DashboardPrefix)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "make build") {
		t.Errorf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("not-built page has no CSP")
	}
}

func TestDashboardOffWithoutFiles(t *testing.T) {
	if rec := getAsAdmin(t, dashboardHandler(t, nil), http.MethodGet, DashboardPrefix); rec.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", rec.Code)
	}
}

func TestDashboardNeedsSession(t *testing.T) {
	h := dashboardHandler(t, builtFS)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, authOrigin+DashboardPrefix, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "app.js") {
		t.Errorf("status %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOwns(t *testing.T) {
	for p, want := range map[string]bool{
		"/.warden/api/me":     true,
		"/.warden/admin":      true,
		"/.warden/admin/":     true,
		"/.warden/admin/x.js": true,
		"/.warden/adminx":     false,
		"/.warden/api":        false,
		"/.warden/login":      false,
		"/admin":              false,
	} {
		if Owns(p) != want {
			t.Errorf("Owns(%q) = %v", p, !want)
		}
	}
	if !IsDashboard("/.warden/admin/") || IsDashboard("/.warden/api/me") {
		t.Error("IsDashboard misclassifies")
	}
}

// fakeStore is an empty session store for tests that don't touch sessions.
type fakeStore struct{}

func (fakeStore) List(context.Context, int, int) ([]session.Session, int, error) { return nil, 0, nil }
func (fakeStore) ListUser(context.Context, string) ([]session.Session, error)    { return nil, nil }
func (fakeStore) DeleteHash(context.Context, string) error                       { return nil }
func (fakeStore) RevokeUser(context.Context, string) (int, error)                { return 0, nil }
func (fakeStore) ListVisitor(context.Context, string) ([]session.Session, error) { return nil, nil }
