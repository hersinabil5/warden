package authn

import (
	"strings"
	"testing"
)

func testReturnURLs(port string) *returnURLs {
	return newReturnURLs([]string{"whoami.warden.localhost", "grafana.warden.localhost"}, port)
}

func TestReturnURLAccepts(t *testing.T) {
	v := testReturnURLs("8443")
	tests := []struct{ in, want string }{
		{"https://whoami.warden.localhost:8443/", "https://whoami.warden.localhost:8443/"},
		{"https://whoami.warden.localhost:8443", "https://whoami.warden.localhost:8443/"},
		{"https://whoami.warden.localhost/x", "https://whoami.warden.localhost:8443/x"}, // port normalized
		{"https://WHOAMI.warden.localhost:8443/Path?q=1&r=%2F", "https://whoami.warden.localhost:8443/Path?q=1&r=%2F"},
		{"HTTPS://grafana.warden.localhost:8443/d/abc", "https://grafana.warden.localhost:8443/d/abc"},
		{"https://whoami.warden.localhost:8443/a#frag", "https://whoami.warden.localhost:8443/a"},          // fragment dropped
		{"https://whoami.warden.localhost:8443/%2e%2e/x", "https://whoami.warden.localhost:8443/%2e%2e/x"}, // same host; path is the app's business
	}
	for _, tt := range tests {
		got, err := v.validate(tt.in)
		if err != nil {
			t.Errorf("validate(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("validate(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReturnURLDefaultPort(t *testing.T) {
	v := testReturnURLs("443")
	for in, want := range map[string]string{
		"https://whoami.warden.localhost/x":     "https://whoami.warden.localhost/x",
		"https://whoami.warden.localhost:443/x": "https://whoami.warden.localhost/x",
	} {
		if got, err := v.validate(in); err != nil || got != want {
			t.Errorf("validate(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

// Invariant 5: everything that does not resolve to a configured route host
// is rejected.
func TestReturnURLRejects(t *testing.T) {
	v := testReturnURLs("8443")
	for _, in := range []string{
		// PLAN.md M2 acceptance list.
		"https://evil.com",
		"//evil.com",
		"https:evil.com",
		`/\evil.com`,
		"javascript:alert(1)",

		// Relative and scheme tricks.
		"",
		"/",
		"/path",
		"evil.com",
		"///evil.com",
		`\\evil.com`,
		"https:/evil.com",
		"https:///evil.com",
		"http://whoami.warden.localhost:8443/",
		"ftp://whoami.warden.localhost/",
		"JaVaScRiPt:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"//whoami.warden.localhost/",

		// Host confusion.
		"https://whoami.warden.localhost.evil.com/",
		"https://evil.com/whoami.warden.localhost",
		"https://evil.com?https://whoami.warden.localhost",
		"https://whoami.warden.localhost@evil.com/",
		"https://user:pass@whoami.warden.localhost/",
		"https://whoami.warden.localhost:8443@evil.com/",
		`https://whoami.warden.localhost\@evil.com/`,
		`https://evil.com\.whoami.warden.localhost/`,
		"https://whoami.warden.localhost./",
		"https://auth.warden.localhost:8443/",
		"https://127.0.0.1:8443/",
		"https://[::1]:8443/",
		"https://xn--whoami-evil.warden.localhost/",
		"https://whoami%2ewarden.localhost/",
		"https://whoami.warden.localhost%00.evil.com/",
		"https://whoami.warden.localhost%2F@evil.com/",

		// Wrong port.
		"https://whoami.warden.localhost:9443/",
		"https://whoami.warden.localhost:443/",
		"https://whoami.warden.localhost:08443/",
		"https://whoami.warden.localhost:/",

		// Whitespace, control characters, and header injection.
		" https://whoami.warden.localhost/",
		"https://whoami.warden.localhost/ ",
		"\thttps://whoami.warden.localhost/",
		"https://whoami.warden.localhost/\r\nSet-Cookie: x=y",
		"https://whoami.warden.localhost/\x00",
		"https://who\tami.warden.localhost/",
		"https://whoami.warden.localhost/a\\b",

		// Oversized.
		"https://whoami.warden.localhost/" + strings.Repeat("a", 4096),
	} {
		if got, err := v.validate(in); err == nil {
			t.Errorf("validate(%q) = %q, want rejection", in, got)
		}
	}
}

func FuzzReturnURL(f *testing.F) {
	for _, s := range []string{"https://whoami.warden.localhost:8443/", "//evil.com", `/\evil.com`, "https://a@b/"} {
		f.Add(s)
	}
	v := testReturnURLs("8443")
	f.Fuzz(func(t *testing.T, in string) {
		got, err := v.validate(in)
		if err != nil {
			return
		}
		// Whatever is accepted must start with an allowed origin and
		// re-validate to itself.
		if !strings.HasPrefix(got, "https://whoami.warden.localhost:8443/") &&
			!strings.HasPrefix(got, "https://grafana.warden.localhost:8443/") {
			t.Fatalf("accepted %q -> %q: not an allowed origin", in, got)
		}
		again, err := v.validate(got)
		if err != nil || again != got {
			t.Fatalf("output %q does not re-validate: %q, %v", got, again, err)
		}
	})
}
