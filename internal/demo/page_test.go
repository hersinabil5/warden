package demo

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

var pageNow = time.Unix(1111111111, 0) // alice's code below is "050471"

func testPage(t *testing.T, next func() time.Time) http.Handler {
	t.Helper()
	h, err := NewPage(PageOptions{
		Accounts: []Account{
			{Username: "alice", Password: "alice", Description: "admins, sre; has OTP", OTPKey: []byte("12345678901234567890")},
			{Username: "bob", Password: "bob", Description: "dev; no OTP"},
		},
		Links: []Link{
			{Label: "whoami", URL: "https://whoami.example.test/", Note: "any signed-in user"},
			{Label: "dashboard", URL: "https://auth.example.test/.warden/admin/", Note: "admins with MFA"},
		},
		NextReset: next,
		Now:       func() time.Time { return pageNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(t *testing.T, h http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, "https://auth.example.test/", nil))
	return rec
}

func TestPageShowsAccountsAndCurrentCode(t *testing.T) {
	rec := get(t, testPage(t, nil), http.MethodGet)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{"alice", "bob", "050471", "admins, sre; has OTP", "whoami", "https://whoami.example.test/", "any signed-in user"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Reloads when the code changes: 1111111111 is 1 s into its 30 s step.
	if !strings.Contains(body, `<meta http-equiv="refresh" content="29">`) {
		t.Errorf("no refresh at the next code:\n%s", body)
	}
	if strings.Count(body, "050471") != 1 {
		t.Error("bob, who has no OTP, got a code")
	}
}

func TestPageHeaders(t *testing.T) {
	rec := get(t, testPage(t, nil), http.MethodGet)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP %q lacks %q", csp, d)
		}
	}
	if strings.Contains(csp, "unsafe") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP allows scripts or unsafe sources: %s", csp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("headers = %v", rec.Header())
	}
	// The one inline style is allowed by its hash; nothing else is inline.
	body := rec.Body.String()
	styles := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(body, -1)
	if len(styles) != 1 {
		t.Fatalf("%d style blocks, want 1", len(styles))
	}
	sum := sha256.Sum256([]byte(styles[0][1]))
	if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("CSP does not allow the page's style by hash")
	}
	for _, bad := range []string{"<script", "style=", "onload", "onclick", "javascript:"} {
		if strings.Contains(strings.ToLower(body), bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestPageResetCountdown(t *testing.T) {
	body := get(t, testPage(t, func() time.Time { return pageNow.Add(42*time.Minute + 10*time.Second) }), http.MethodGet).Body.String()
	if !strings.Contains(body, "42 minutes") {
		t.Errorf("no reset countdown:\n%s", body)
	}
}

func TestPageMethods(t *testing.T) {
	h := testPage(t, nil)
	if rec := get(t, h, http.MethodHead); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := get(t, h, m); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, rec.Code)
		}
	}
}

// Config values are text, never markup.
func TestPageEscapes(t *testing.T) {
	h, err := NewPage(PageOptions{
		Accounts: []Account{{Username: `<img src=x onerror=alert(1)>`, Password: `"><script>`}},
		Links:    []Link{{Label: "x", URL: "javascript:alert(1)"}},
		Now:      func() time.Time { return pageNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	body := get(t, h, http.MethodGet).Body.String()
	if strings.Contains(body, "<img") || strings.Contains(body, "<script>") || strings.Contains(body, `href="javascript:`) {
		t.Errorf("unescaped config value:\n%s", body)
	}
}

func TestNewPageValidates(t *testing.T) {
	if _, err := NewPage(PageOptions{}); err == nil {
		t.Error("page without accounts accepted")
	}
}
