package proxy

import (
	"net/http"
	"strings"
)

// builtinIdentityHeaders are always stripped from requests to upstreams
// (invariant 2): the invariant's list plus the names common auth proxies
// and apps trust for the user's identity.
var builtinIdentityHeaders = []string{
	"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Groups",
	"X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token",
	"Remote-User", "X-Remote-User",
	"X-Webauth-User", "X-Webauth-Email", "X-Webauth-Name", "X-Webauth-Groups",
}

// builtinIdentityPrefixes strip whole header families.
var builtinIdentityPrefixes = []string{"X-WARDEN-", "X-AUTH-REQUEST-"}

// identityHeaders matches header names an upstream could read as identity.
// Names are compared case-insensitively with "_" folded to "-", because
// WSGI, CGI, and some proxies treat X_Forwarded_Email as X-Forwarded-Email.
type identityHeaders struct {
	names map[string]bool
}

func newIdentityHeaders(extra []string, assertionHeader string) identityHeaders {
	m := identityHeaders{names: map[string]bool{}}
	for _, l := range [][]string{builtinIdentityHeaders, extra, {assertionHeader}} {
		for _, n := range l {
			if n != "" {
				m.names[foldHeaderName(n)] = true
			}
		}
	}
	return m
}

func foldHeaderName(name string) string {
	return strings.ToUpper(strings.ReplaceAll(name, "_", "-"))
}

func (m identityHeaders) match(name string) bool {
	f := foldHeaderName(name)
	if m.names[f] {
		return true
	}
	for _, p := range builtinIdentityPrefixes {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	return false
}

// strip removes every matching header. It must run before Warden injects its
// own identity header.
func (m identityHeaders) strip(h http.Header) {
	for name := range h {
		if m.match(name) {
			delete(h, name)
		}
	}
}
