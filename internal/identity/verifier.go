package identity

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// verifyLeeway tolerates small clock skew. It is far below the 60 s
// lifetime, so an expired assertion cannot live on through the leeway.
const verifyLeeway = 5 * time.Second

// ErrUnknownKey means no published key has the assertion's kid.
var ErrUnknownKey = errors.New("identity: unknown signing key")

// KeyFunc returns the verification key for a kid, or ErrUnknownKey.
type KeyFunc func(ctx context.Context, kid string) (*ecdsa.PublicKey, error)

// Identity is a verified assertion.
type Identity struct {
	Subject  string
	Username string
	Email    string
	Groups   []string
	ID       string // jti
	Expiry   time.Time
}

// Verifier checks assertions for one upstream (the audience).
type Verifier struct {
	Issuer   string
	Audience string
	Keys     KeyFunc
	Now      func() time.Time // nil means time.Now
}

// Verify checks raw fully: ES256 only, the assertion typ, a known kid, the
// signature, iss, a single aud equal to Audience, exp/nbf/iat with a small
// leeway, a lifetime of at most MaxTTL, and the presence of sub and jti.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Identity, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("identity: parsing: %w", err)
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("identity: want exactly one signature")
	}
	h := tok.Headers[0]
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !strings.EqualFold(typ, TokenType) {
		return nil, fmt.Errorf("identity: typ %q is not %s", typ, TokenType)
	}
	if h.KeyID == "" {
		return nil, errors.New("identity: no kid")
	}
	key, err := v.Keys(ctx, h.KeyID)
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	var extra assertionClaims
	if err := tok.Claims(key, &std, &extra); err != nil {
		return nil, fmt.Errorf("identity: signature: %w", err)
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	switch {
	case std.Expiry == nil || std.IssuedAt == nil:
		return nil, errors.New("identity: exp and iat are required")
	case std.Expiry.Time().Sub(std.IssuedAt.Time()) > MaxTTL:
		return nil, fmt.Errorf("identity: lifetime exceeds %v", MaxTTL)
	case len(std.Audience) != 1:
		return nil, errors.New("identity: want exactly one audience")
	case std.Subject == "" || std.ID == "":
		return nil, errors.New("identity: sub and jti are required")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      v.Issuer,
		AnyAudience: jwt.Audience{v.Audience},
		Time:        now(),
	}, verifyLeeway); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return &Identity{
		Subject:  std.Subject,
		Username: extra.Username,
		Email:    extra.Email,
		Groups:   extra.Groups,
		ID:       std.ID,
		Expiry:   std.Expiry.Time(),
	}, nil
}
