package authn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
)

// preAuthTTL bounds how long a login may take between /login and the
// callback. It is the cookie's Max-Age and the sealed expiry.
const preAuthTTL = 10 * time.Minute

// preAuthCookiePrefix uses __Host-, so browsers only accept the cookie with
// Secure, Path=/ and no Domain: host-only by construction (invariant 7).
const preAuthCookiePrefix = "__Host-warden_login_"

// preAuthNameStateChars is how much of state goes into the cookie name. It
// keeps concurrent logins (two tabs) from overwriting each other's cookie.
const preAuthNameStateChars = 16

// preAuth is the per-login state bound to the browser (invariant 4).
type preAuth struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`           // PKCE code verifier
	Expires  int64  `json:"e"`           // Unix seconds
	ReturnTo string `json:"r,omitempty"` // validated return URL; empty means the auth host's session page
	Binding  string `json:"b,omitempty"` // hash of the app host's handshake cookie (D13)
	// StepUp marks a forced re-authentication: the ID token must show a
	// login made after this one started (D28).
	StepUp bool `json:"u,omitempty"`
}

// newPreAuth returns fresh random login state: 256-bit state and nonce from
// crypto/rand (invariant 11) and an oauth2-generated PKCE verifier.
func newPreAuth(now time.Time) (preAuth, error) {
	state, err := randomToken()
	if err != nil {
		return preAuth{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return preAuth{}, err
	}
	return preAuth{
		State:    state,
		Nonce:    nonce,
		Verifier: oauth2.GenerateVerifier(),
		Expires:  now.Add(preAuthTTL).Unix(),
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func preAuthCookieName(state string) string {
	if len(state) > preAuthNameStateChars {
		state = state[:preAuthNameStateChars]
	}
	return preAuthCookiePrefix + state
}

// NewCookieKey returns a random 256-bit key for sealing pre-auth cookies.
// Warden generates one per process (docs/DECISIONS.md D9).
func NewCookieKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("generating cookie key: %w", err)
	}
	return k, nil
}

var errBadPreAuth = errors.New("invalid pre-auth cookie")

// cookieSealer encrypts and authenticates pre-auth cookies with AES-256-GCM.
// The cookie name is the associated data, so a value only opens under the
// name it was sealed for.
type cookieSealer struct {
	aead cipher.AEAD
	now  func() time.Time
}

func newCookieSealer(key []byte, now func() time.Time) (*cookieSealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cookie key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cookie cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cookie cipher: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	return &cookieSealer{aead: aead, now: now}, nil
}

func (s *cookieSealer) seal(name string, pa preAuth) (string, error) {
	plain, err := json.Marshal(pa)
	if err != nil {
		return "", fmt.Errorf("encoding pre-auth state: %w", err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating cookie nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte(name))), nil
}

// open authenticates and decrypts a cookie value sealed under name and
// rejects it once expired. Every failure is the same opaque error.
func (s *cookieSealer) open(name, value string) (preAuth, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < s.aead.NonceSize()+s.aead.Overhead() {
		return preAuth{}, errBadPreAuth
	}
	n := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(name))
	if err != nil {
		return preAuth{}, errBadPreAuth
	}
	var pa preAuth
	if err = json.Unmarshal(plain, &pa); err != nil {
		return preAuth{}, errBadPreAuth
	}
	if pa.State == "" || pa.Nonce == "" || pa.Verifier == "" ||
		preAuthCookieName(pa.State) != name || !s.now().Before(time.Unix(pa.Expires, 0)) {
		return preAuth{}, errBadPreAuth
	}
	return pa, nil
}
