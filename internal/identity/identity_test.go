package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	testIssuer = "https://auth.example.test:8443"
	testAud    = "app.example.test"
)

var t0 = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newSigner(t testing.TB, key *ecdsa.PrivateKey, previous ...*ecdsa.PublicKey) *Signer {
	t.Helper()
	s, err := NewSigner(key, previous, SignerOptions{Issuer: testIssuer, TTL: 60 * time.Second, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// staticKeys serves keys from a Signer's JWKS, as an upstream would see them.
func staticKeys(t testing.TB, s *Signer) KeyFunc {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(s.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
		for _, k := range set.Key(kid) {
			if pub, ok := k.Key.(*ecdsa.PublicKey); ok {
				return pub, nil
			}
		}
		return nil, ErrUnknownKey
	}
}

func newVerifier(keys KeyFunc, now time.Time) *Verifier {
	return &Verifier{Issuer: testIssuer, Audience: testAud, Keys: keys, Now: func() time.Time { return now }}
}

var alice = Claims{Subject: "u-1", Username: "alice", Email: "alice@warden.local", Groups: []string{"admins", "sre"}}

func TestAssertAndVerify(t *testing.T) {
	s := newSigner(t, newKey(t))
	raw, err := s.Assert(alice, testAud)
	if err != nil {
		t.Fatal(err)
	}
	got, err := newVerifier(staticKeys(t, s), t0.Add(30*time.Second)).Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "u-1" || got.Username != "alice" || got.Email != "alice@warden.local" ||
		strings.Join(got.Groups, ",") != "admins,sre" || got.ID == "" || !got.Expiry.Equal(t0.Add(60*time.Second)) {
		t.Errorf("identity = %+v", got)
	}
}

func TestAssertionShape(t *testing.T) {
	s := newSigner(t, newKey(t))
	raw, err := s.Assert(Claims{Subject: "u-2", Username: "bob"}, testAud)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", raw)
	}
	var hdr, body map[string]any
	decodeSeg(t, parts[0], &hdr)
	decodeSeg(t, parts[1], &body)
	if hdr["alg"] != "ES256" || hdr["typ"] != TokenType || hdr["kid"] != s.KeyID() {
		t.Errorf("header = %v", hdr)
	}
	for k, want := range map[string]any{
		"iss": testIssuer, "aud": testAud, "sub": "u-2", "preferred_username": "bob",
		"iat": float64(t0.Unix()), "nbf": float64(t0.Unix()), "exp": float64(t0.Add(60 * time.Second).Unix()),
	} {
		if body[k] != want {
			t.Errorf("claim %s = %v, want %v", k, body[k], want)
		}
	}
	if _, ok := body["email"]; ok {
		t.Error("empty email should be omitted")
	}
	if g, ok := body["groups"].([]any); !ok || len(g) != 0 {
		t.Errorf("groups = %v, want an empty list", body["groups"])
	}
	if jti, _ := body["jti"].(string); len(jti) < 22 {
		t.Errorf("jti = %q, want 128+ random bits", jti)
	}
	other, _ := s.Assert(Claims{Subject: "u-2", Username: "bob"}, testAud)
	var body2 map[string]any
	decodeSeg(t, strings.Split(other, ".")[1], &body2)
	if body2["jti"] == body["jti"] {
		t.Error("jti repeated")
	}
}

func decodeSeg(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestAssertRejectsBadInput(t *testing.T) {
	s := newSigner(t, newKey(t))
	for name, c := range map[string]struct {
		claims Claims
		aud    string
	}{
		"no subject":  {Claims{Username: "x"}, testAud},
		"no audience": {alice, ""},
	} {
		if _, err := s.Assert(c.claims, c.aud); err == nil {
			t.Errorf("%s: Assert succeeded", name)
		}
	}
}

func TestNewSignerRejects(t *testing.T) {
	k := newKey(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, tt := range map[string]struct {
		key  *ecdsa.PrivateKey
		prev []*ecdsa.PublicKey
		opts SignerOptions
	}{
		"nil key":           {nil, nil, SignerOptions{Issuer: testIssuer, TTL: time.Minute}},
		"P-384":             {p384, nil, SignerOptions{Issuer: testIssuer, TTL: time.Minute}},
		"P-384 previous":    {k, []*ecdsa.PublicKey{&p384.PublicKey}, SignerOptions{Issuer: testIssuer, TTL: time.Minute}},
		"previous = active": {k, []*ecdsa.PublicKey{&k.PublicKey}, SignerOptions{Issuer: testIssuer, TTL: time.Minute}},
		"TTL over 60s":      {k, nil, SignerOptions{Issuer: testIssuer, TTL: 61 * time.Second}},
		"zero TTL":          {k, nil, SignerOptions{Issuer: testIssuer}},
		"no issuer":         {k, nil, SignerOptions{TTL: time.Minute}},
	} {
		if _, err := NewSigner(tt.key, tt.prev, tt.opts); err == nil {
			t.Errorf("%s: NewSigner succeeded", name)
		}
	}
}

// The JWKS publishes public keys only: the active key and the previous ones.
func TestJWKS(t *testing.T) {
	oldKey, newKey_ := newKey(t), newKey(t)
	s := newSigner(t, newKey_, &oldKey.PublicKey)
	raw := s.JWKS()
	if strings.Contains(string(raw), `"d"`) {
		t.Fatalf("JWKS contains private key material: %s", raw)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 || set.Keys[0].KeyID != s.KeyID() {
		t.Fatalf("keys = %+v, want active first then previous", set.Keys)
	}
	for _, k := range set.Keys {
		if k.Algorithm != "ES256" || k.Use != "sig" || k.KeyID == "" || !k.IsPublic() {
			t.Errorf("key %+v", k)
		}
	}

	rec := httptest.NewRecorder()
	s.JWKSHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/jwk-set+json" || rec.Body.String() != string(raw) {
		t.Errorf("handler: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = httptest.NewRecorder()
	s.JWKSHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", rec.Code)
	}
}

// Rotation: a token signed with the old key still verifies once the old key
// is moved to the previous list, and new tokens use the new key.
func TestRotation(t *testing.T) {
	oldKey := newKey(t)
	before := newSigner(t, oldKey)
	tok, _ := before.Assert(alice, testAud)

	after := newSigner(t, newKey(t), &oldKey.PublicKey)
	v := newVerifier(staticKeys(t, after), t0)
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Errorf("old-key token rejected after rotation: %v", err)
	}
	fresh, _ := after.Assert(alice, testAud)
	if _, err := v.Verify(context.Background(), fresh); err != nil {
		t.Errorf("new-key token rejected: %v", err)
	}
	if after.KeyID() == before.KeyID() {
		t.Error("kid did not change with the key")
	}
	// Dropping the old key ends its tokens.
	if _, err := newVerifier(staticKeys(t, newSigner(t, newKey(t))), t0).Verify(context.Background(), tok); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("token for a retired key: %v, want ErrUnknownKey", err)
	}
}

// Every forged, expired, or misdirected assertion is rejected.
func TestVerifyRejects(t *testing.T) {
	key := newKey(t)
	s := newSigner(t, key)
	keys := staticKeys(t, s)
	good, _ := s.Assert(alice, testAud)

	sign := func(t *testing.T, alg jose.SignatureAlgorithm, k any, typ string, kid string, claims map[string]any) string {
		t.Helper()
		opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
		if kid != "" {
			opts = opts.WithHeader("kid", kid)
		}
		sg, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, opts)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := jwt.Signed(sg).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	base := func() map[string]any {
		return map[string]any{
			"iss": testIssuer, "aud": testAud, "sub": "u-1", "jti": "abcdefghijklmnopqrstuv",
			"iat": t0.Unix(), "nbf": t0.Unix(), "exp": t0.Add(time.Minute).Unix(),
		}
	}
	with := func(k string, v any) map[string]any {
		m := base()
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)

	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + parts[2]
	unsigned := parts[0] + "." + parts[1] + "."
	noneHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"` + TokenType + `"}`))

	kid := s.KeyID()
	for name, raw := range map[string]string{
		"empty":                           "",
		"garbage":                         "not.a.jwt",
		"tampered payload":                tampered,
		"no signature":                    unsigned,
		"alg none":                        noneHdr + "." + parts[1] + ".",
		"HS256 keyed with the public key": sign(t, jose.HS256, pubDER, TokenType, kid, base()),
		"RS256":                           sign(t, jose.RS256, rsaKey, TokenType, kid, base()),
		"other ES256 key":                 sign(t, jose.ES256, newKey(t), TokenType, kid, base()),
		"unknown kid":                     sign(t, jose.ES256, key, TokenType, "nope", base()),
		"no kid":                          sign(t, jose.ES256, key, TokenType, "", base()),
		"wrong typ":                       sign(t, jose.ES256, key, "JWT", kid, base()),
		"no typ":                          sign(t, jose.ES256, key, "", kid, base()),
		"wrong audience":                  sign(t, jose.ES256, key, TokenType, kid, with("aud", "other.example.test")),
		"two audiences":                   sign(t, jose.ES256, key, TokenType, kid, with("aud", []string{testAud, "other.example.test"})),
		"no audience":                     sign(t, jose.ES256, key, TokenType, kid, with("aud", nil)),
		"wrong issuer":                    sign(t, jose.ES256, key, TokenType, kid, with("iss", "https://evil.example")),
		"expired":                         sign(t, jose.ES256, key, TokenType, kid, with("exp", t0.Add(-time.Minute).Unix())),
		"no exp":                          sign(t, jose.ES256, key, TokenType, kid, with("exp", nil)),
		"no iat":                          sign(t, jose.ES256, key, TokenType, kid, with("iat", nil)),
		"lifetime over 60s":               sign(t, jose.ES256, key, TokenType, kid, with("exp", t0.Add(10*time.Minute).Unix())),
		"issued in the future": sign(t, jose.ES256, key, TokenType, kid, func() map[string]any {
			m := base()
			m["iat"], m["nbf"], m["exp"] = t0.Add(5*time.Minute).Unix(), t0.Add(5*time.Minute).Unix(), t0.Add(6*time.Minute).Unix()
			return m
		}()),
		"no sub": sign(t, jose.ES256, key, TokenType, kid, with("sub", nil)),
		"no jti": sign(t, jose.ES256, key, TokenType, kid, with("jti", nil)),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := newVerifier(keys, t0.Add(10*time.Second)).Verify(context.Background(), raw); err == nil {
				t.Errorf("Verify accepted it: %+v", got)
			}
		})
	}
	// Control: the genuine token passes with the same verifier.
	if _, err := newVerifier(keys, t0.Add(10*time.Second)).Verify(context.Background(), good); err != nil {
		t.Errorf("genuine token rejected: %v", err)
	}
	// A verifier for another host rejects it.
	v := newVerifier(keys, t0)
	v.Audience = "grafana.example.test"
	if _, err := v.Verify(context.Background(), good); err == nil {
		t.Error("token for app accepted by grafana")
	}
}

func TestLoadKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b *pem.Block) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(b), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	k := newKey(t)
	sec1, _ := x509.MarshalECPrivateKey(k)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalECPrivateKey(p384)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaDER, _ := x509.MarshalPKCS8PrivateKey(rk)

	for _, path := range []string{
		write("sec1.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		write("pkcs8.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		got, err := LoadSigningKey(path)
		if err != nil || !got.Equal(k) {
			t.Errorf("LoadSigningKey(%s) = %v", filepath.Base(path), err)
		}
	}
	// Previous keys may be private (the old signing key file) or public.
	for _, path := range []string{
		write("prev-sec1.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		write("prev-pub.pem", &pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
	} {
		got, err := LoadVerificationKey(path)
		if err != nil || !got.Equal(&k.PublicKey) {
			t.Errorf("LoadVerificationKey(%s) = %v", filepath.Base(path), err)
		}
	}
	for name, path := range map[string]string{
		"public key as signing key": write("pub-as-priv.pem", &pem.Block{Type: "PUBLIC KEY", Bytes: pub}),
		"P-384":                     write("p384.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: p384der}),
		"RSA":                       write("rsa.pem", &pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}),
		"missing file":              filepath.Join(dir, "missing.pem"),
		"wrong PEM type":            write("junk.pem", &pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"garbage DER":               write("bad.pem", &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("junk")}),
	} {
		if _, err := LoadSigningKey(path); err == nil {
			t.Errorf("%s: LoadSigningKey succeeded", name)
		}
	}
}

func TestRemoteKeys(t *testing.T) {
	s := newSigner(t, newKey(t))
	var hits atomic.Int64
	body := s.JWKS()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	now := t0
	rk := NewRemoteKeys(srv.Client(), srv.URL, RemoteKeysOptions{MinRefresh: 30 * time.Second, Now: func() time.Time { return now }})
	if _, err := rk.Key(context.Background(), s.KeyID()); err != nil {
		t.Fatalf("Key: %v", err)
	}
	if _, err := rk.Key(context.Background(), s.KeyID()); err != nil || hits.Load() != 1 {
		t.Errorf("cached lookup refetched (hits %d): %v", hits.Load(), err)
	}
	// Unknown kids refetch at most once per MinRefresh.
	for range 5 {
		if _, err := rk.Key(context.Background(), "unknown"); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("unknown kid: %v", err)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d after unknown-kid storm within MinRefresh, want 1", hits.Load())
	}
	// After rotation the new kid is picked up on the next allowed refresh.
	s2 := newSigner(t, newKey(t))
	body = s2.JWKS()
	now = now.Add(31 * time.Second)
	if _, err := rk.Key(context.Background(), s2.KeyID()); err != nil {
		t.Errorf("rotated key not fetched: %v", err)
	}
}

func TestRemoteKeysRejectsBadSets(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	k := newKey(t)
	set := func(keys ...jose.JSONWebKey) []byte {
		b, _ := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		return b
	}
	for name, tt := range map[string]struct {
		body   []byte
		status int
	}{
		"RSA key":      {set(jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "a", Algorithm: "ES256", Use: "sig"}), 200},
		"P-384 key":    {set(jose.JSONWebKey{Key: &p384.PublicKey, KeyID: "a", Algorithm: "ES256", Use: "sig"}), 200},
		"wrong alg":    {set(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "a", Algorithm: "ES384", Use: "sig"}), 200},
		"enc use":      {set(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "a", Algorithm: "ES256", Use: "enc"}), 200},
		"server error": {set(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "a", Algorithm: "ES256", Use: "sig"}), 500},
		// Valid JSON (a good key, then whitespace) that is only too big.
		"oversized": {append(set(jose.JSONWebKey{Key: &k.PublicKey, KeyID: "a", Algorithm: "ES256", Use: "sig"}), bytes.Repeat([]byte(" "), 2<<20)...), 200},
		"not JSON":  {[]byte("<html>"), 200},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write(tt.body)
			}))
			defer srv.Close()
			rk := NewRemoteKeys(srv.Client(), srv.URL, RemoteKeysOptions{})
			if pub, err := rk.Key(context.Background(), "a"); err == nil {
				t.Errorf("accepted key %v", pub)
			}
		})
	}
}
