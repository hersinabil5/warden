package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// TokenType is the assertion's JOSE "typ". Verifiers require it, so no other
// JWT (an ID token, an access token) can pass as an identity assertion and
// vice versa (RFC 8725, section 3.11).
const TokenType = "warden-identity+jwt"

// MaxTTL caps the assertion lifetime (PLAN.md M4).
const MaxTTL = 60 * time.Second

// Claims is the identity Warden asserts to an upstream.
type Claims struct {
	Subject  string
	Username string
	Email    string // verified email or empty
	Groups   []string
}

// SignerOptions configures a Signer.
type SignerOptions struct {
	Issuer string        // Warden's auth origin, e.g. https://auth.warden.localhost:8443
	TTL    time.Duration // in (0, MaxTTL]
	Now    func() time.Time
}

// Signer issues identity assertions with the active key and publishes the
// JWKS: the active key plus previous keys kept for verification during
// rotation.
type Signer struct {
	signer jose.Signer
	kid    string
	issuer string
	ttl    time.Duration
	now    func() time.Time
	jwks   []byte
}

// NewSigner builds a Signer. Every key must be P-256, and kids (RFC 7638
// thumbprints) must be distinct.
func NewSigner(active *ecdsa.PrivateKey, previous []*ecdsa.PublicKey, opts SignerOptions) (*Signer, error) {
	switch {
	case active == nil:
		return nil, errors.New("identity: no signing key")
	case opts.Issuer == "":
		return nil, errors.New("identity: no issuer")
	case opts.TTL <= 0 || opts.TTL > MaxTTL:
		return nil, fmt.Errorf("identity: TTL must be in (0, %v], got %v", MaxTTL, opts.TTL)
	}
	set := jose.JSONWebKeySet{}
	seen := map[string]bool{}
	for i, pub := range append([]*ecdsa.PublicKey{&active.PublicKey}, previous...) {
		if pub == nil || pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("identity: key %d is not P-256", i)
		}
		kid, err := keyID(pub)
		if err != nil {
			return nil, err
		}
		if seen[kid] {
			return nil, fmt.Errorf("identity: key %d duplicates another key (kid %s)", i, kid)
		}
		seen[kid] = true
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: pub, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"})
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("identity: encoding JWKS: %w", err)
	}
	kid := set.Keys[0].KeyID
	sg, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: active, KeyID: kid}},
		(&jose.SignerOptions{}).WithType(TokenType),
	)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Signer{signer: sg, kid: kid, issuer: opts.Issuer, ttl: opts.TTL, now: now, jwks: jwks}, nil
}

// keyID is the RFC 7638 thumbprint of pub, so the same key always has the
// same kid without any configuration.
func keyID(pub *ecdsa.PublicKey) (string, error) {
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("identity: key thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// KeyID is the kid of the active signing key.
func (s *Signer) KeyID() string { return s.kid }

// assertionClaims are the non-registered claims of an assertion.
type assertionClaims struct {
	Username string   `json:"preferred_username"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups"`
}

// Assert signs an assertion of c for one upstream host (the audience).
func (s *Signer) Assert(c Claims, audience string) (string, error) {
	if c.Subject == "" {
		return "", errors.New("identity: no subject")
	}
	if audience == "" {
		return "", errors.New("identity: no audience")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("identity: jti: %w", err)
	}
	now := s.now()
	std := jwt.Claims{
		Issuer:    s.issuer,
		Subject:   c.Subject,
		Audience:  jwt.Audience{audience},
		Expiry:    jwt.NewNumericDate(now.Add(s.ttl)),
		NotBefore: jwt.NewNumericDate(now),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        base64.RawURLEncoding.EncodeToString(jti),
	}
	groups := c.Groups
	if groups == nil {
		groups = []string{}
	}
	raw, err := jwt.Signed(s.signer).Claims(std).Claims(assertionClaims{c.Username, c.Email, groups}).Serialize()
	if err != nil {
		return "", fmt.Errorf("identity: signing: %w", err)
	}
	return raw, nil
}

// JWKS returns the public key set as JSON.
func (s *Signer) JWKS() []byte { return s.jwks }

// JWKSHandler serves the key set. It is public by design: upstreams fetch it
// to verify assertions.
func (s *Signer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodGet {
			_, _ = w.Write(s.jwks)
		}
	})
}
