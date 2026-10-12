package proxy

import (
	"context"
	"crypto/rand"
	"net"
	"strings"
)

// RequestIDHeader carries the request ID to the upstream and back to the client.
const RequestIDHeader = "X-Request-ID"

type requestIDKey struct{}

// newRequestID returns a fresh random ID (at least 128 bits). Warden always
// generates its own; a client-supplied X-Request-ID is never trusted, since it
// ends up in logs and audit events.
func newRequestID() string { return rand.Text() }

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the request ID stored in ctx, or "" if there is none.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// hostOnly lowercases a Host header value and drops a valid :port suffix.
// Anything malformed is returned as-is, so it fails exact-match lookups.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = h
	}
	return strings.ToLower(hostport)
}
