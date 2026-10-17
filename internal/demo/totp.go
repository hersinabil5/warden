// Package demo is Warden's public demo mode: a landing page with the demo
// accounts and their current OTP codes, per-visitor scoping, and periodic
// resets (docs/DECISIONS.md D30).
package demo

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP as Keycloak computes it (HmacSHA1)
	"encoding/binary"
	"fmt"
	"time"
)

// Period is the TOTP time step Keycloak uses by default.
const Period = 30 * time.Second

// Code is the 6-digit TOTP code (RFC 6238, HMAC-SHA1, 30 s) for secret at
// t. Warden only displays it; Keycloak is what verifies codes.
func Code(secret []byte, t time.Time) string { return totp(secret, t, 6) }

// Remaining is how long the code for t stays current.
func Remaining(t time.Time) time.Duration {
	return Period - time.Duration(t.UnixNano()%int64(Period))
}

// totp is RFC 6238 over RFC 4226's HOTP with dynamic truncation, on the
// standard library's HMAC.
func totp(secret []byte, t time.Time, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/int64(Period/time.Second))) //nolint:gosec // G115: Unix time is positive here
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, v%mod)
}
