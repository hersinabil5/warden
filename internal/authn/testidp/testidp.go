// Package testidp is a fake OIDC identity provider for tests: an
// httptest.Server serving discovery, JWKS, an authorize endpoint that signs
// the user in immediately, and a token endpoint that enforces PKCE S256,
// single-use codes, redirect_uri matching, and client authentication. Tests
// can rewrite the discovery document, inject failures, and tamper with the
// ID token the token endpoint returns.
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// ClientSecret is what the token endpoint expects by default.
	ClientSecret = "testidp-client-secret"

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

	codes         map[string]authRequest
	userClaims    func() map[string]any
	editIDToken   func(map[string]any)
	signIDToken   func(claims map[string]any) string
	tokenFail     []int
	tokenHits     int
	lastAuthorize url.Values
	clientSecret  string
	refreshTokens map[string]string // live refresh token -> login nonce
	refreshHits   int
}

// authRequest is what /auth recorded for an issued code.
type authRequest struct {
	redirectURI, nonce, challenge string
}

// New starts a fake IdP that is closed when the test ends.
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &IdP{Key: key, codes: map[string]authRequest{}, clientSecret: ClientSecret, refreshTokens: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", idp.serveAuthorize)
	mux.HandleFunc("POST /token", idp.serveToken)
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
		"iss":                idp.Issuer,
		"aud":                ClientID,
		"sub":                "user-1",
		"email":              "alice@example.test",
		"email_verified":     true,
		"preferred_username": "alice",
		"groups":             []string{"admins", "sre"},
		"auth_time":          now.Unix(),
		"amr":                []string{"pwd"},
		"iat":                now.Unix(),
		"exp":                now.Add(5 * time.Minute).Unix(),
		"nonce":              "test-nonce",
	}
}

// SignIDToken signs claims with the IdP's RS256 key.
func (idp *IdP) SignIDToken(t testing.TB, claims map[string]any) string {
	t.Helper()
	tok, err := idp.sign(claims)
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

// SetClientSecret changes the secret the token endpoint requires.
func (idp *IdP) SetClientSecret(secret string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.clientSecret = secret
}

// SetUser makes /auth sign in a user with these claims (merged over Claims;
// the authorize request's nonce is added).
func (idp *IdP) SetUser(claims func() map[string]any) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.userClaims = claims
}

// EditIDToken modifies the claims of every ID token the token endpoint
// issues, after the nonce is set (for example, to break aud or nonce).
func (idp *IdP) EditIDToken(fn func(claims map[string]any)) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.editIDToken = fn
}

// SignIDTokenWith replaces RS256 signing of issued ID tokens (for example,
// to return alg=none or a token signed by another key).
func (idp *IdP) SignIDTokenWith(fn func(claims map[string]any) string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.signIDToken = fn
}

// FailToken makes the next len(statuses) token requests fail with those
// statuses and an OAuth error body.
func (idp *IdP) FailToken(statuses ...int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.tokenFail = append(idp.tokenFail, statuses...)
}

// TokenHits counts token endpoint requests.
func (idp *IdP) TokenHits() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.tokenHits
}

// LastAuthorize returns the query of the most recent /auth request.
func (idp *IdP) LastAuthorize() url.Values {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.lastAuthorize
}

// serveAuthorize validates the request like a strict IdP, then "signs the
// user in" at once and redirects back with a code.
func (idp *IdP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	idp.mu.Lock()
	idp.lastAuthorize = q
	idp.mu.Unlock()
	if q.Get("client_id") != ClientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("redirect_uri") == "" || q.Get("state") == "" {
		http.Error(w, "invalid authorize request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	idp.mu.Lock()
	idp.codes[code] = authRequest{redirectURI: q.Get("redirect_uri"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
	idp.mu.Unlock()

	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // G710: an IdP redirects to the client's redirect_uri by design; test-only
}

func oauthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// serveToken implements the authorization_code grant with client_secret_basic
// or client_secret_post, enforcing PKCE S256 and single-use codes.
func (idp *IdP) serveToken(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	idp.tokenHits++
	var fail int
	if len(idp.tokenFail) > 0 {
		fail, idp.tokenFail = idp.tokenFail[0], idp.tokenFail[1:]
	}
	secret := idp.clientSecret
	idp.mu.Unlock()
	if fail != 0 {
		oauthError(w, fail, "server_error")
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, pw, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		pw, _ = url.QueryUnescape(pw)
	} else {
		id, pw = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != ClientID || subtle.ConstantTimeCompare([]byte(pw), []byte(secret)) != 1 {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
	case "refresh_token":
		idp.serveRefresh(w, r)
		return
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	code := r.PostForm.Get("code")
	idp.mu.Lock()
	req, found := idp.codes[code]
	delete(idp.codes, code) // single use, even when the rest fails
	userClaims, edit, sign := idp.userClaims, idp.editIDToken, idp.signIDToken
	idp.mu.Unlock()
	if !found || r.PostForm.Get("redirect_uri") != req.redirectURI {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	idp.issue(w, req.nonce, userClaims, edit, sign)
}

// serveRefresh implements the refresh_token grant with rotation: the old
// refresh token dies, and the new ID token carries the current user claims
// (so tests can change groups) and the login's nonce.
func (idp *IdP) serveRefresh(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	idp.refreshHits++
	rt := r.PostForm.Get("refresh_token")
	nonce, ok := idp.refreshTokens[rt]
	delete(idp.refreshTokens, rt)
	userClaims, edit, sign := idp.userClaims, idp.editIDToken, idp.signIDToken
	idp.mu.Unlock()
	if !ok {
		oauthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	idp.issue(w, nonce, userClaims, edit, sign)
}

// RevokeRefreshTokens invalidates every issued refresh token, as when the
// user is disabled or their IdP session ends.
func (idp *IdP) RevokeRefreshTokens() {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.refreshTokens = map[string]string{}
}

// RefreshHits counts refresh_token grant requests.
func (idp *IdP) RefreshHits() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.refreshHits
}

func (idp *IdP) issue(w http.ResponseWriter, nonce string, userClaims func() map[string]any,
	edit func(map[string]any), sign func(map[string]any) string) {
	claims := idp.Claims()
	if userClaims != nil {
		for k, v := range userClaims() {
			claims[k] = v
		}
	}
	claims["nonce"] = nonce
	if nonce == "" {
		delete(claims, "nonce")
	}
	if edit != nil {
		edit(claims)
	}
	var idToken string
	if sign != nil {
		idToken = sign(claims)
	} else {
		var err error
		if idToken, err = idp.sign(claims); err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	refresh := "rt-" + rand.Text()
	idp.mu.Lock()
	idp.refreshTokens[refresh] = nonce
	idp.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  "at-" + rand.Text(),
		"token_type":    "Bearer",
		"expires_in":    300,
		"refresh_token": refresh,
		"id_token":      idToken,
	})
}

func (idp *IdP) sign(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: idp.Key, KeyID: KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
