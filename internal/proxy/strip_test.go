package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// Invariant 2: no client-supplied identity header reaches an upstream, under
// any spelling an upstream might treat as the same name.
func TestIdentityHeadersStripped(t *testing.T) {
	up := newEcho(t)
	cfg := testConfig(t, up.URL)
	cfg.StripHeaders = []string{"X-Remote-Team", "X-Custom-Identity"}
	h := newTestHandler(t, cfg)

	forged := []string{
		// Invariant 2's list.
		"X-Warden-Identity", "X-Warden-User", "X-Warden-Anything",
		"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Groups",
		"X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token",
		"X-Auth-Request-User", "X-Auth-Request-Email", "X-Auth-Request-Groups", "X-Auth-Request-Access-Token",
		// Common auth-proxy headers (Grafana's auth proxy, Apache, ...).
		"Remote-User", "X-Remote-User", "X-Webauth-User", "X-Webauth-Email", "X-Webauth-Groups",
		// Configured extras.
		"X-Remote-Team", "X-Custom-Identity",
		// Spelling variants: case, and "_" that WSGI, CGI, and some proxies read as "-".
		"x-warden-identity", "X-WARDEN-USER", "x-forwarded-email",
		"X_Forwarded_Email", "x_auth_request_user", "X_Warden_Identity", "remote_user", "X_Custom_Identity",
	}
	req := appRequest(t)
	for _, name := range forged {
		req.Header[name] = []string{"forged-" + name}
	}
	req.Header.Set("X-App-Header", "kept")
	req.Header.Set("Authorization", "Bearer app-token") // the app's own credential, not identity

	seen, _ := proxyThrough2(t, h, req)
	for name, vals := range seen.Header {
		for _, v := range vals {
			if strings.HasPrefix(v, "forged-") {
				t.Errorf("upstream got %s: %q", name, v)
			}
		}
	}
	if seen.Header.Get("X-App-Header") != "kept" || seen.Header.Get("Authorization") != "Bearer app-token" {
		t.Errorf("unrelated headers dropped: %v", seen.Header)
	}
	// Warden's own forwarding headers are still set after stripping.
	if seen.Header.Get("X-Forwarded-Proto") == "" || seen.Header.Get("X-Forwarded-For") == "" {
		t.Errorf("forwarding headers missing: %v", seen.Header)
	}
}

func TestIsIdentityHeader(t *testing.T) {
	m := newIdentityHeaders([]string{"X-Extra"}, "X-Warden-Identity")
	for name, want := range map[string]bool{
		"X-Warden-Identity": true, "X-Warden-": true, "x_warden_x": true,
		"X-Forwarded-Email": true, "X-Auth-Request-Foo": true, "X-Extra": true, "x_extra": true,
		"X-Forwarded-For": false, "X-Forwarded-Host": false, "X-Forwarded-Proto": false,
		"X-Wardenx": false, "Authorization": false, "Cookie": false, "X-Request-Id": false,
		"X-Extras": false,
	} {
		if got := m.match(name); got != want {
			t.Errorf("match(%q) = %v, want %v", name, got, want)
		}
	}
}

// proxyThrough2 is proxyThrough with a caller-built handler.
func proxyThrough2(t *testing.T, h http.Handler, req *http.Request) (seenRequest, int) {
	t.Helper()
	rec := serve(h, req)
	return decodeSeen(t, rec), rec.Code
}
