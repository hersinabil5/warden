package demo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/hersinabil5/warden/internal/ratelimit"
)

// VisitorTagLen is the length of a visitor tag in hex characters (64 bits).
const VisitorTagLen = 16

// Visitors tags requests and sessions with an opaque visitor ID in demo
// mode, so each visitor's admin views show only their own activity. The ID
// is a keyed hash of the client IP (IPv6 by /64, as for rate limits); the
// key is random per process, so tags can't be turned back into addresses.
type Visitors struct{ key []byte }

// NewVisitors returns a tagger with a fresh random key.
func NewVisitors() (*Visitors, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("demo: generating visitor key: %w", err)
	}
	return &Visitors{key: k}, nil
}

// Of returns the visitor tag for a connection's remote address
// (http.Request.RemoteAddr). Forwarding headers are never consulted.
func (v *Visitors) Of(remoteAddr string) string {
	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(ratelimit.ClientKey(remoteAddr)))
	return hex.EncodeToString(mac.Sum(nil))[:VisitorTagLen]
}
