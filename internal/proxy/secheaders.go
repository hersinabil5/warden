package proxy

import (
	"net/http"
	"strconv"
	"time"
)

// PageCSP is the default policy for Warden's responses: nothing loads and
// nothing may frame it. Handlers that render more set their own, which must
// keep frame-ancestors 'none'.
const PageCSP = "default-src 'none'; frame-ancestors 'none'"

const hstsHeader = "Strict-Transport-Security"

// pageHeaders are set on every response Warden writes itself, and on none it
// proxies: apps own their page headers (docs/DECISIONS.md D26).
var pageHeaders = [...]struct{ name, value string }{
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"}, // login URLs carry state and codes
	{"X-Frame-Options", "DENY"},        // for browsers without frame-ancestors
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"Content-Security-Policy", PageCSP},
}

func setPageHeaders(h http.Header) {
	for _, p := range pageHeaders {
		h.Set(p.name, p.value)
	}
}

// clearPageHeaders undoes setPageHeaders before a response is proxied, so
// the app's own values are the only ones the client sees.
func clearPageHeaders(h http.Header) {
	for _, p := range pageHeaders {
		h.Del(p.name)
	}
}

// hstsValue is the Strict-Transport-Security value for maxAge, or "" for off.
// No includeSubDomains or preload: those would bind hosts Warden doesn't
// serve.
func hstsValue(maxAge time.Duration) string {
	if maxAge <= 0 {
		return ""
	}
	return "max-age=" + strconv.FormatInt(int64(maxAge/time.Second), 10)
}
