// Package testidp is a fake OIDC identity provider for tests: an
// httptest.Server serving a discovery document and a JWKS backed by a
// generated RSA signing key. Tests can rewrite the discovery document, inject
// failures, and sign ID tokens with arbitrary claims.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	DiscoveryPath = "/.well-known/openid-configuration"
	JWKSPath      = "/jwks"
	KeyID         = "testidp-key-1"
	ClientID      = "warden-proxy"

	issuerPath = "/realms/test"
)

// IdP is a running fake identity provider. Its methods are safe for
// concurrent use with the server.
type IdP struct {
	Server *httptest.Server
	Issuer string
	Key    *rsa.PrivateKey

	mu            sync.Mutex
	editDiscovery func(map[string]any)
	discoveryFail []int // statuses to return on the next discovery requests
	jwksOverride  []byte
	discoveryHits int
	jwksHits      int
}

// New starts a fake IdP that is closed when the test ends.
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &IdP{Key: key}
	mux := http.NewServeMux()
	// Discovery lives under the issuer path, as with Keycloak realms.
	mux.HandleFunc("GET "+issuerPath+DiscoveryPath, idp.serveDiscovery)
	mux.HandleFunc("GET "+JWKSPath, idp.serveJWKS)
	idp.Server = httptest.NewServer(mux)
	idp.Issuer = idp.Server.URL + issuerPath
	t.Cleanup(idp.Server.Close)
	return idp
}

// Discovery returns the default discovery document, as served before any
// EditDiscovery call.
func (idp *IdP) Discovery() map[string]any {
	base := idp.Server.URL
	return map[string]any{
		"issuer":                                idp.Issuer,
		"authorization_endpoint":                base + "/auth",
		"token_endpoint":                        base + "/token",
		"jwks_uri":                              base + JWKSPath,
		"userinfo_endpoint":                     base + "/userinfo",
		"end_session_endpoint":                  base + "/logout",
		"response_types_supported":              []string{"code", "id_token", "code id_token"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"subject_types_supported":               []string{"public"},
	}
}

// EditDiscovery installs fn to modify the default document before each
// discovery response (for example, to delete or replace a field).
func (idp *IdP) EditDiscovery(fn func(doc map[string]any)) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.editDiscovery = fn
}

// FailDiscovery makes the next len(statuses) discovery requests return those
// HTTP statuses, in order, before serving normally again.
func (idp *IdP) FailDiscovery(statuses ...int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.discoveryFail = append(idp.discoveryFail, statuses...)
}

// SetJWKS serves raw as the JWKS body instead of the real public key.
func (idp *IdP) SetJWKS(raw []byte) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.jwksOverride = raw
}

// DiscoveryHits and JWKSHits count requests to each endpoint.
func (idp *IdP) DiscoveryHits() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.discoveryHits
}

func (idp *IdP) JWKSHits() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.jwksHits
}

// PublicJWKS returns the JWKS document for the signing key.
func (idp *IdP) PublicJWKS() []byte {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &idp.Key.PublicKey, KeyID: KeyID, Algorithm: string(jose.RS256), Use: "sig",
	}}}
	b, err := json.Marshal(set)
	if err != nil {
		panic(err) // marshaling a valid RSA public key cannot fail
	}
	return b
}

// Claims returns a valid set of ID token claims for this IdP, issued now and
// expiring in five minutes.
func (idp *IdP) Claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   idp.Issuer,
		"aud":   ClientID,
		"sub":   "user-1",
		"email": "alice@example.test",
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": "test-nonce",
	}
}

// SignIDToken signs claims with the IdP's RS256 key.
func (idp *IdP) SignIDToken(t testing.TB, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: idp.Key, KeyID: KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (idp *IdP) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	idp.mu.Lock()
	idp.discoveryHits++
	var status int
	if len(idp.discoveryFail) > 0 {
		status, idp.discoveryFail = idp.discoveryFail[0], idp.discoveryFail[1:]
	}
	edit := idp.editDiscovery
	idp.mu.Unlock()

	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	doc := idp.Discovery()
	if edit != nil {
		edit(doc)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (idp *IdP) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	idp.mu.Lock()
	idp.jwksHits++
	body := idp.jwksOverride
	idp.mu.Unlock()

	if body == nil {
		body = idp.PublicJWKS()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}
