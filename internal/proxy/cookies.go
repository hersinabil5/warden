package proxy

import (
	"net/http"
	"strings"
)

// cookieMatcher matches Warden's own cookie names: exact names, or prefixes
// written with a trailing "*".
type cookieMatcher struct {
	exact    map[string]bool
	prefixes []string
}

func newCookieMatcher(names []string) cookieMatcher {
	m := cookieMatcher{exact: map[string]bool{}}
	for _, n := range names {
		if p, ok := strings.CutSuffix(n, "*"); ok {
			m.prefixes = append(m.prefixes, p)
		} else {
			m.exact[n] = true
		}
	}
	return m
}

func (m cookieMatcher) match(name string) bool {
	if m.exact[name] {
		return true
	}
	for _, p := range m.prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// stripCookies removes Warden's cookies from an outbound request, so an
// upstream never sees a session ID it could replay.
func stripCookies(h http.Header, m cookieMatcher) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var kept []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			name, _, _ := strings.Cut(part, "=")
			if !m.match(strings.TrimSpace(name)) {
				kept = append(kept, part)
			}
		}
	}
	h.Del("Cookie")
	if len(kept) > 0 {
		h.Set("Cookie", strings.Join(kept, "; "))
	}
}

// stripSetCookies drops upstream Set-Cookie headers for Warden's cookie
// names, so an upstream cannot overwrite or fix a Warden session.
func stripSetCookies(h http.Header, m cookieMatcher) {
	lines := h.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, line := range lines {
		name, _, _ := strings.Cut(line, "=")
		if !m.match(strings.TrimSpace(name)) {
			h.Add("Set-Cookie", line)
		}
	}
}
