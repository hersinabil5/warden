package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hersinabil5/warden/internal/authn/testidp"
	"github.com/hersinabil5/warden/internal/config"
)

const testSecret = "client-secret-must-not-be-logged"

func authConfig(issuer string, algs ...string) config.Auth {
	if len(algs) == 0 {
		algs = []string{"RS256"}
	}
	return config.Auth{
		Issuer:       issuer,
		ClientID:     testidp.ClientID,
		ClientSecret: config.NewSecret(testSecret),
		Scopes:       []string{"openid"},
		IDTokenAlgs:  algs,
		// Long enough that no test refreshes unless it shortens it.
		GroupRefreshInterval: 5 * time.Minute,
	}
}

// syncBuffer collects log output written from Discover.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fastOptions keeps retry tests quick: short backoff and a small budget.
func fastOptions(logs io.Writer) DiscoverOptions {
	if logs == nil {
		logs = io.Discard
	}
	return DiscoverOptions{
		Logger:         slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Budget:         2 * time.Second,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     40 * time.Millisecond,
	}
}

func TestDiscoverSuccess(t *testing.T) {
	idp := testidp.New(t)
	var logs syncBuffer
	p, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(&logs))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	base := idp.Server.URL
	if p.Endpoint.AuthURL != base+"/auth" || p.Endpoint.TokenURL != base+"/token" {
		t.Errorf("endpoint = %+v", p.Endpoint)
	}
	if p.EndSessionURL != base+"/logout" {
		t.Errorf("end session URL = %q", p.EndSessionURL)
	}
	if p.HTTPClient == nil {
		t.Error("HTTPClient is nil")
	}
	if _, err := p.Verifier.Verify(t.Context(), idp.SignIDToken(t, idp.Claims())); err != nil {
		t.Errorf("valid token rejected: %v", err)
	}
	if strings.Contains(logs.String(), testSecret) {
		t.Errorf("client secret logged:\n%s", logs.String())
	}
}

func TestDiscoverEndSessionIsOptional(t *testing.T) {
	idp := testidp.New(t)
	idp.EditDiscovery(func(d map[string]any) { delete(d, "end_session_endpoint") })
	p, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if p.EndSessionURL != "" {
		t.Errorf("end session URL = %q, want empty", p.EndSessionURL)
	}
}

// Every case here is a permanent failure: a misconfigured or malicious IdP
// must fail startup immediately, without retrying.
func TestDiscoverRejectsBadMetadata(t *testing.T) {
	set := func(k string, v any) func(map[string]any) { return func(d map[string]any) { d[k] = v } }
	del := func(k string) func(map[string]any) { return func(d map[string]any) { delete(d, k) } }

	tests := []struct {
		name string
		edit func(idp *testidp.IdP) func(map[string]any)
		want string
	}{
		// Issuer mix-up: the document must name exactly the configured issuer.
		{"issuer other host", func(*testidp.IdP) func(map[string]any) {
			return set("issuer", "https://evil.example.test/realms/test")
		}, "issuer"},
		{"issuer trailing slash", func(idp *testidp.IdP) func(map[string]any) { return set("issuer", idp.Issuer+"/") }, "issuer"},
		{"issuer different case", func(idp *testidp.IdP) func(map[string]any) {
			return set("issuer", strings.Replace(idp.Issuer, "/realms/test", "/realms/TEST", 1))
		}, "issuer"},
		{"issuer missing", func(*testidp.IdP) func(map[string]any) { return del("issuer") }, "issuer"},

		// PKCE S256 (invariant 4) and the code flow.
		{"S256 not offered", func(*testidp.IdP) func(map[string]any) {
			return set("code_challenge_methods_supported", []string{"plain"})
		}, "S256"},
		{"code challenge methods absent", func(*testidp.IdP) func(map[string]any) { return del("code_challenge_methods_supported") }, "S256"},
		{"no code response type", func(*testidp.IdP) func(map[string]any) {
			return set("response_types_supported", []string{"id_token", "token id_token"})
		}, "response_types_supported"},

		// Algorithm downgrade (invariant 3).
		{"IdP offers only HS256", func(*testidp.IdP) func(map[string]any) {
			return set("id_token_signing_alg_values_supported", []string{"HS256"})
		}, "id_token_algs"},
		{"IdP offers only none", func(*testidp.IdP) func(map[string]any) {
			return set("id_token_signing_alg_values_supported", []string{"none"})
		}, "id_token_algs"},
		{"IdP algs absent", func(*testidp.IdP) func(map[string]any) { return del("id_token_signing_alg_values_supported") }, "id_token_algs"},

		// Endpoints: present, absolute, https (plain http only on loopback), no credentials.
		{"jwks_uri missing", func(*testidp.IdP) func(map[string]any) { return del("jwks_uri") }, "jwks_uri"},
		{"jwks_uri relative", func(*testidp.IdP) func(map[string]any) { return set("jwks_uri", "/jwks") }, "jwks_uri"},
		{"jwks_uri http on remote host", func(*testidp.IdP) func(map[string]any) {
			return set("jwks_uri", "http://idp.example.test/jwks")
		}, "jwks_uri"},
		{"jwks_uri http on localhost lookalike", func(*testidp.IdP) func(map[string]any) {
			return set("jwks_uri", "http://localhost.evil.test/jwks")
		}, "jwks_uri"},
		{"jwks_uri http on .localhost lookalike", func(*testidp.IdP) func(map[string]any) {
			return set("jwks_uri", "http://keycloak.localhost.evil.test/jwks")
		}, "jwks_uri"},
		{"jwks_uri with credentials", func(idp *testidp.IdP) func(map[string]any) {
			return set("jwks_uri", strings.Replace(idp.Server.URL, "http://", "http://u:p@", 1)+"/jwks")
		}, "jwks_uri"},
		{"jwks_uri other scheme", func(*testidp.IdP) func(map[string]any) { return set("jwks_uri", "file:///etc/passwd") }, "jwks_uri"},
		{"token_endpoint missing", func(*testidp.IdP) func(map[string]any) { return del("token_endpoint") }, "token_endpoint"},
		{"token_endpoint http on remote host", func(*testidp.IdP) func(map[string]any) {
			return set("token_endpoint", "http://idp.example.test/token")
		}, "token_endpoint"},
		{"authorization_endpoint missing", func(*testidp.IdP) func(map[string]any) { return del("authorization_endpoint") }, "authorization_endpoint"},
		{"authorization_endpoint javascript", func(*testidp.IdP) func(map[string]any) {
			return set("authorization_endpoint", "javascript:alert(1)")
		}, "authorization_endpoint"},
		{"end_session_endpoint http on remote host", func(*testidp.IdP) func(map[string]any) {
			return set("end_session_endpoint", "http://idp.example.test/logout")
		}, "end_session_endpoint"},
		{"field has wrong type", func(*testidp.IdP) func(map[string]any) { return set("jwks_uri", 42) }, "discovery"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testidp.New(t)
			idp.EditDiscovery(tt.edit(idp))
			_, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(nil))
			if err == nil {
				t.Fatal("Discover succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			if n := idp.DiscoveryHits(); n != 1 {
				t.Errorf("discovery fetched %d times, want 1 (permanent errors must not be retried)", n)
			}
		})
	}
}

func TestDiscoverPermanentHTTPFailures(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			idp := testidp.New(t)
			idp.FailDiscovery(status, status, status)
			_, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(nil))
			if err == nil {
				t.Fatal("Discover succeeded, want error")
			}
			if n := idp.DiscoveryHits(); n != 1 {
				t.Errorf("discovery fetched %d times, want 1", n)
			}
		})
	}
}

func TestDiscoverRejectsMalformedDocument(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.WriteString(w, `{"issuer": "unterminated`)
	}))
	defer srv.Close()
	_, err := Discover(t.Context(), authConfig(srv.URL), fastOptions(nil))
	if err == nil || !strings.Contains(err.Error(), "discovery") {
		t.Fatalf("err = %v, want discovery parse error", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("fetched %d times, want 1", hits)
	}
}

func TestDiscoverRejectsOversizedDocument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"x":"`+strings.Repeat("a", 2<<20)+`"}`)
	}))
	defer srv.Close()
	_, err := Discover(t.Context(), authConfig(srv.URL), fastOptions(nil))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want size error", err)
	}
}

func marshalJWKS(t *testing.T, keys ...jose.JSONWebKey) []byte {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDiscoverRejectsBadJWKS(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		algs []string // pinned; default RS256
		jwks func(idp *testidp.IdP) []byte
		want string
	}{
		{"empty key set", nil, func(*testidp.IdP) []byte { return []byte(`{"keys":[]}`) }, "no usable"},
		{"not JSON", nil, func(*testidp.IdP) []byte { return []byte(`<html>`) }, "JWKS"},
		{"symmetric key only", nil, func(*testidp.IdP) []byte {
			return marshalJWKS(t, jose.JSONWebKey{Key: []byte("0123456789abcdef0123456789abcdef"), KeyID: "k", Algorithm: "HS256"})
		}, "symmetric"},
		{"encryption key only", nil, func(idp *testidp.IdP) []byte {
			return marshalJWKS(t, jose.JSONWebKey{Key: &idp.Key.PublicKey, KeyID: "k", Use: "enc"})
		}, "no usable"},
		{"key alg not pinned", nil, func(idp *testidp.IdP) []byte {
			return marshalJWKS(t, jose.JSONWebKey{Key: &idp.Key.PublicKey, KeyID: "k", Algorithm: "PS512"})
		}, "no usable"},
		{"RSA key but only ES256 pinned", []string{"ES256"}, func(idp *testidp.IdP) []byte { return idp.PublicJWKS() }, "no usable"},
		{"EC P-256 key but only ES384 pinned", []string{"ES384"}, func(*testidp.IdP) []byte {
			return marshalJWKS(t, jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "k"})
		}, "no usable"},
		{"private key published", nil, func(idp *testidp.IdP) []byte {
			return marshalJWKS(t, jose.JSONWebKey{Key: idp.Key, KeyID: "k", Algorithm: "RS256"})
		}, "private"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := testidp.New(t)
			if tt.algs != nil {
				idp.EditDiscovery(func(d map[string]any) {
					d["id_token_signing_alg_values_supported"] = []string{"RS256", "ES256", "ES384"}
				})
			}
			idp.SetJWKS(tt.jwks(idp))
			_, err := Discover(t.Context(), authConfig(idp.Issuer, tt.algs...), fastOptions(nil))
			if err == nil {
				t.Fatal("Discover succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
			if n := idp.JWKSHits(); n != 1 {
				t.Errorf("JWKS fetched %d times, want 1", n)
			}
		})
	}
}

func TestDiscoverSkipsUnknownJWKSKeyTypes(t *testing.T) {
	idp := testidp.New(t)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(idp.PublicJWKS(), &set); err != nil {
		t.Fatal(err)
	}
	set.Keys = append([]json.RawMessage{json.RawMessage(`{"kty":"OKP-future","kid":"x"}`)}, set.Keys...)
	b, _ := json.Marshal(set)
	idp.SetJWKS(b)
	if _, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(nil)); err != nil {
		t.Fatalf("Discover: %v", err)
	}
}

func TestDiscoverRetriesTransientFailures(t *testing.T) {
	for _, statuses := range [][]int{
		{http.StatusServiceUnavailable, http.StatusServiceUnavailable},
		{http.StatusBadGateway, http.StatusTooManyRequests, http.StatusInternalServerError},
	} {
		idp := testidp.New(t)
		idp.FailDiscovery(statuses...)
		var logs syncBuffer
		if _, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(&logs)); err != nil {
			t.Fatalf("statuses %v: Discover: %v", statuses, err)
		}
		if got, want := idp.DiscoveryHits(), len(statuses)+1; got != want {
			t.Errorf("statuses %v: discovery hits = %d, want %d", statuses, got, want)
		}
		if n := strings.Count(logs.String(), "OIDC discovery failed; retrying"); n != len(statuses) {
			t.Errorf("statuses %v: %d retry log lines, want %d:\n%s", statuses, n, len(statuses), logs.String())
		}
		if strings.Contains(logs.String(), testSecret) {
			t.Errorf("client secret logged:\n%s", logs.String())
		}
	}
}

func TestDiscoverGivesUpWhenUnreachable(t *testing.T) {
	idp := testidp.New(t)
	issuer := idp.Issuer
	idp.Server.Close() // connection refused from now on

	opts := fastOptions(nil)
	opts.Budget = 300 * time.Millisecond
	start := time.Now()
	_, err := Discover(t.Context(), authConfig(issuer), opts)
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("err = %v, want unreachable error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("gave up after %v, want about the 300ms budget", elapsed)
	}
}

func TestDiscoverBoundsHungServer(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	opts := fastOptions(nil)
	opts.Budget = 300 * time.Millisecond
	start := time.Now()
	_, err := Discover(t.Context(), authConfig(srv.URL), opts)
	if err == nil {
		t.Fatal("Discover succeeded against a hung server")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned after %v, want about the 300ms budget", elapsed)
	}
}

func TestDiscoverDoesNotFollowRedirects(t *testing.T) {
	idp := testidp.New(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, idp.Issuer+testidp.DiscoveryPath, http.StatusFound)
	}))
	defer redirector.Close()

	_, err := Discover(t.Context(), authConfig(redirector.URL), fastOptions(nil))
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("err = %v, want redirect error", err)
	}
	if n := idp.DiscoveryHits(); n != 0 {
		t.Errorf("redirect was followed (%d hits on target)", n)
	}
}

func TestDiscoverStopsOnCancel(t *testing.T) {
	idp := testidp.New(t)
	idp.FailDiscovery(http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusServiceUnavailable)
	opts := fastOptions(nil)
	opts.Budget = time.Minute
	opts.InitialBackoff = 30 * time.Second
	opts.MaxBackoff = 30 * time.Second

	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := Discover(ctx, authConfig(idp.Issuer), opts)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("returned after %v, want prompt return on cancel", elapsed)
	}
}

func TestNewHTTPClientHasTimeoutsAndNoProxy(t *testing.T) {
	c := NewHTTPClient()
	if c.Timeout <= 0 {
		t.Error("client has no overall timeout")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy != nil {
		t.Error("transport honors proxy environment variables")
	}
	if tr.TLSHandshakeTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 || tr.DialContext == nil {
		t.Error("transport is missing dial, TLS handshake, or response header timeouts")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("transport allows TLS below 1.2")
	}
	if c.CheckRedirect == nil {
		t.Error("client follows redirects")
	}
}

// --- Verifier wiring (invariant 3). The callback task adds nonce and iat. ---

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unsignedToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": testidp.KeyID})
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64(h) + "." + b64(p) + "."
}

func signWith(t *testing.T, alg jose.SignatureAlgorithm, key any, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: testidp.KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(p)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifierRejectsForgedTokens(t *testing.T) {
	idp := testidp.New(t)
	p, err := Discover(t.Context(), authConfig(idp.Issuer), fastOptions(nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&idp.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	with := func(k string, v any) map[string]any {
		c := idp.Claims()
		c[k] = v
		return c
	}

	tests := []struct {
		name  string
		token string
	}{
		{"expired", idp.SignIDToken(t, with("exp", time.Now().Add(-time.Minute).Unix()))},
		{"wrong audience", idp.SignIDToken(t, with("aud", "some-other-client"))},
		{"audience list without us", idp.SignIDToken(t, with("aud", []string{"a", "b"}))},
		{"wrong issuer", idp.SignIDToken(t, with("iss", "https://evil.example.test/realms/test"))},
		{"issuer trailing slash", idp.SignIDToken(t, with("iss", idp.Issuer+"/"))},
		{"signed by another key with our kid", signWith(t, jose.RS256, otherKey, idp.Claims())},
		{"alg none", unsignedToken(t, idp.Claims())},
		{"HS256 keyed with the RSA public key", signWith(t, jose.HS256, pubDER, idp.Claims())},
		{"tampered payload", func() string {
			parts := strings.Split(idp.SignIDToken(t, idp.Claims()), ".")
			parts[1] = b64([]byte(`{"iss":"` + idp.Issuer + `","aud":"warden-proxy","sub":"admin","exp":9999999999}`))
			return strings.Join(parts, ".")
		}()},
		{"garbage", "not.a.jwt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := p.Verifier.Verify(t.Context(), tt.token); err == nil {
				t.Fatal("forged token accepted")
			}
		})
	}
}

func TestVerifierRejectsUnpinnedAlgorithm(t *testing.T) {
	idp := testidp.New(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The JWKS holds both keys and the IdP advertises both algorithms, but
	// only ES256 is pinned: a validly signed RS256 token must still fail.
	idp.SetJWKS(marshalJWKS(t,
		jose.JSONWebKey{Key: &idp.Key.PublicKey, KeyID: testidp.KeyID, Algorithm: "RS256", Use: "sig"},
		jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec-1", Algorithm: "ES256", Use: "sig"},
	))
	p, err := Discover(t.Context(), authConfig(idp.Issuer, "ES256"), fastOptions(nil))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err = p.Verifier.Verify(t.Context(), idp.SignIDToken(t, idp.Claims())); err == nil {
		t.Fatal("RS256 token accepted with only ES256 pinned")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: ecKey, KeyID: "ec-1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(idp.Claims())
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jws.CompactSerialize()
	if _, err := p.Verifier.Verify(t.Context(), tok); err != nil {
		t.Errorf("valid ES256 token rejected: %v", err)
	}
}

// Plain http is allowed only for names that can never be public (RFC 6761
// localhost names, loopback IPs), e.g. Keycloak inside the dev compose stack.
func TestCheckEndpointLocalHTTP(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://localhost:8180/realms/warden/protocol/openid-connect/certs":          true,
		"http://keycloak.localhost:8180/realms/warden/protocol/openid-connect/certs": true,
		"http://127.0.0.1:8180/x":                true,
		"http://keycloak.localhost.evil.test/x":  false,
		"http://keycloaklocalhost/x":             false,
		"http://keycloak.localhost./x":           false,
		"http://idp.example.test/x":              false,
		"https://keycloak.localhost.evil.test/x": true, // https anywhere is fine
	} {
		if err := checkEndpoint(raw); (err == nil) != ok {
			t.Errorf("checkEndpoint(%q) = %v, want ok=%v", raw, err, ok)
		}
	}
}
