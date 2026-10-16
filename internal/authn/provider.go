package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/hersinabil5/warden/internal/config"
)

// Discovery retry and IdP client limits; see docs/DECISIONS.md D8.
const (
	DefaultDiscoveryBudget = 60 * time.Second
	DefaultInitialBackoff  = 500 * time.Millisecond
	DefaultMaxBackoff      = 10 * time.Second

	idpClientTimeout     = 10 * time.Second
	idpDialTimeout       = 5 * time.Second
	idpTLSTimeout        = 5 * time.Second
	idpResponseHeaderTTL = 10 * time.Second
	idpIdleConnTimeout   = 90 * time.Second

	maxMetadataBytes = 1 << 20 // discovery documents and JWKS are a few KiB
)

// Provider is a discovered, validated OIDC provider.
type Provider struct {
	Issuer        string
	Endpoint      oauth2.Endpoint
	EndSessionURL string // empty if the IdP does not advertise RP-initiated logout
	// Verifier checks signature (pinned algorithms, keys from jwks_uri), iss,
	// aud, and exp. The callback must additionally check nonce and iat.
	Verifier *oidc.IDTokenVerifier
	// HTTPClient is the client for every IdP request (token exchange, refresh).
	HTTPClient *http.Client
}

// DiscoverOptions configures Discover. Zero values select the defaults.
type DiscoverOptions struct {
	Logger         *slog.Logger
	HTTPClient     *http.Client // defaults to NewHTTPClient()
	Budget         time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Now            func() time.Time // clock for token expiry checks
}

// metadata is the subset of the OIDC discovery document Warden relies on.
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	ResponseTypes         []string `json:"response_types_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	IDTokenSigningAlgs    []string `json:"id_token_signing_alg_values_supported"`
}

// discovered is the result of one successful discovery attempt.
type discovered struct {
	md       metadata
	algs     []string // pinned algorithms the IdP also offers; the verifier's list
	jwksKeys int
	keyAlgs  []string // algorithms the current JWKS can verify
}

// permanentError marks a failure that retrying cannot fix (a misconfigured
// or misbehaving IdP), so Discover fails immediately.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanent(format string, args ...any) error {
	return &permanentError{fmt.Errorf(format, args...)}
}

// NewHTTPClient returns the client used for all IdP traffic. It has
// timeouts on every phase (invariant 10), ignores HTTP_PROXY/HTTPS_PROXY,
// requires TLS 1.2+, and never follows redirects.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: idpClientTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: idpDialTimeout}).DialContext,
			TLSHandshakeTimeout:   idpTLSTimeout,
			ResponseHeaderTimeout: idpResponseHeaderTTL,
			IdleConnTimeout:       idpIdleConnTimeout,
			MaxIdleConns:          10,
			ForceAttemptHTTP2:     true,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Discover fetches and validates the IdP's discovery document and JWKS, and
// builds a token verifier pinned to the configured algorithms. Transient
// failures (network errors, 5xx, 429) are retried with exponential backoff
// until opts.Budget runs out; anything else fails immediately.
func Discover(ctx context.Context, cfg config.Auth, opts DiscoverOptions) (*Provider, error) {
	opts = opts.withDefaults()
	log := opts.Logger.With("issuer", cfg.Issuer)

	budgetCtx, cancel := context.WithTimeout(ctx, opts.Budget)
	defer cancel()

	backoff := opts.InitialBackoff
	for attempt := 1; ; attempt++ {
		d, err := discoverOnce(budgetCtx, opts.HTTPClient, cfg)
		if err == nil {
			log.Info("OIDC provider discovered", "attempt", attempt,
				"id_token_algs", d.algs, "jwks_keys", d.jwksKeys, "jwks_key_algs", d.keyAlgs)
			return newProvider(cfg, d, opts), nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("OIDC discovery for %s interrupted: %w", cfg.Issuer, ctxErr)
		}
		if pe := (*permanentError)(nil); errors.As(err, &pe) {
			return nil, fmt.Errorf("OIDC provider %s: %w", cfg.Issuer, err)
		}

		wait := jitter(backoff)
		log.Warn("OIDC discovery failed; retrying", "attempt", attempt, "retry_in", wait.String(), "err", err)
		t := time.NewTimer(wait)
		select {
		case <-budgetCtx.Done():
			t.Stop()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, fmt.Errorf("OIDC discovery for %s interrupted: %w", cfg.Issuer, ctxErr)
			}
			return nil, fmt.Errorf("OIDC provider %s unreachable after %d attempts in %v: %w",
				cfg.Issuer, attempt, opts.Budget, err)
		case <-t.C:
		}
		backoff = min(backoff*2, opts.MaxBackoff)
	}
}

func (o DiscoverOptions) withDefaults() DiscoverOptions {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = NewHTTPClient()
	}
	if o.Budget <= 0 {
		o.Budget = DefaultDiscoveryBudget
	}
	if o.InitialBackoff <= 0 {
		o.InitialBackoff = DefaultInitialBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = DefaultMaxBackoff
	}
	return o
}

// jitter returns a duration in [d/2, d] so restarting instances don't retry
// in lockstep.
func jitter(d time.Duration) time.Duration {
	half := d / 2
	return half + rand.N(half+1) //nolint:gosec // G404: retry jitter is not a secret
}

func discoverOnce(ctx context.Context, client *http.Client, cfg config.Auth) (*discovered, error) {
	body, err := fetch(ctx, client, strings.TrimSuffix(cfg.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	var md metadata
	if err = json.Unmarshal(body, &md); err != nil {
		return nil, permanent("parsing discovery document: %w", err)
	}
	algs, err := md.validate(cfg)
	if err != nil {
		return nil, err
	}

	body, err = fetch(ctx, client, md.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	keys, keyAlgs, err := checkJWKS(body, algs)
	if err != nil {
		return nil, err
	}
	return &discovered{md: md, algs: algs, jwksKeys: keys, keyAlgs: keyAlgs}, nil
}

// validate checks the discovery document against the config and returns the
// algorithms the verifier will accept: the pinned ones the IdP also offers.
func (md *metadata) validate(cfg config.Auth) ([]string, error) {
	// Exact match (OIDC Discovery §4.3): this is also the iss every token
	// must carry, so a mismatch is a mix-up or misconfiguration.
	if md.Issuer != cfg.Issuer {
		return nil, permanent("discovery issuer %q does not exactly match configured issuer", md.Issuer)
	}
	for _, e := range []struct {
		field, value string
		required     bool
	}{
		{"authorization_endpoint", md.AuthorizationEndpoint, true},
		{"token_endpoint", md.TokenEndpoint, true},
		{"jwks_uri", md.JWKSURI, true},
		{"userinfo_endpoint", md.UserinfoEndpoint, false},
		{"end_session_endpoint", md.EndSessionEndpoint, false},
	} {
		if e.value == "" && !e.required {
			continue
		}
		if err := checkEndpoint(e.value); err != nil {
			return nil, permanent("discovery %s: %w", e.field, err)
		}
	}
	if !slices.Contains(md.ResponseTypes, "code") {
		return nil, permanent("discovery response_types_supported %q lacks \"code\"", md.ResponseTypes)
	}
	// RFC 8414: an absent list means PKCE is not supported (invariant 4).
	if !slices.Contains(md.CodeChallengeMethods, "S256") {
		return nil, permanent("IdP does not advertise PKCE S256 (code_challenge_methods_supported %q)", md.CodeChallengeMethods)
	}
	var algs []string
	for _, a := range cfg.IDTokenAlgs {
		if slices.Contains(md.IDTokenSigningAlgs, a) {
			algs = append(algs, a)
		}
	}
	if len(algs) == 0 {
		return nil, permanent("IdP signs ID tokens with %q; none of auth.id_token_algs %q",
			md.IDTokenSigningAlgs, cfg.IDTokenAlgs)
	}
	return algs, nil
}

// checkEndpoint applies the issuer rule to discovered endpoints: absolute,
// https (plain http only on loopback), no credentials, query, or fragment.
func checkEndpoint(raw string) error {
	if raw == "" {
		return errors.New("is missing")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a valid URL", raw)
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("%q must be an https URL", raw)
	case u.Opaque != "" || u.Host == "":
		return fmt.Errorf("%q must be an absolute URL with a host", raw)
	case u.User != nil:
		return errors.New("must not contain credentials")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return fmt.Errorf("%q must not have a fragment", raw)
	case u.Scheme == "http" && !isLocalHost(u.Hostname()):
		return fmt.Errorf("%q must use https (plain http is allowed only for localhost names)", raw)
	}
	return nil
}

// isLocalHost reports whether host can only ever name this machine or a
// local network peer: localhost, a *.localhost name (RFC 6761 reserves them;
// the container stack uses keycloak.localhost, D25), or a loopback IP. Plain
// http is tolerated only for these.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || (strings.HasSuffix(h, ".localhost") && len(h) > len(".localhost")) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkJWKS confirms the key set can verify at least one pinned algorithm.
// Keys of unknown types are skipped (as go-oidc does); private key material
// is a hard error. It returns the key count and the usable algorithms.
func checkJWKS(body []byte, algs []string) (int, []string, error) {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, nil, permanent("parsing JWKS: %w", err)
	}
	var usable []string
	for _, r := range raw.Keys {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(r); err != nil {
			continue
		}
		if !k.IsPublic() {
			return 0, nil, permanent("JWKS publishes private or symmetric key material (kid %q)", k.KeyID)
		}
		if k.Use == "enc" || !k.Valid() {
			continue
		}
		for _, a := range algs {
			if keyFits(k, a) && !slices.Contains(usable, a) {
				usable = append(usable, a)
			}
		}
	}
	if len(usable) == 0 {
		return 0, nil, permanent("JWKS has no usable signing key for %q", algs)
	}
	return len(raw.Keys), usable, nil
}

// keyFits reports whether k can verify signatures made with alg.
func keyFits(k jose.JSONWebKey, alg string) bool {
	if k.Algorithm != "" && k.Algorithm != alg {
		return false
	}
	switch pub := k.Key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
		return want != nil && pub.Curve == want
	default:
		return false
	}
}

// fetch GETs url and returns the body of a 200 response. Network errors,
// 5xx, 408, and 429 are retryable; any other status is permanent.
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, permanent("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err // retryable; callers add context
	}
	defer func() { _ = resp.Body.Close() }()

	switch s := resp.StatusCode; {
	case s == http.StatusOK:
	case s >= 300 && s < 400:
		return nil, permanent("unexpected redirect (%d to %q); configure the exact issuer URL", s, resp.Header.Get("Location"))
	case s >= 500, s == http.StatusTooManyRequests, s == http.StatusRequestTimeout:
		return nil, fmt.Errorf("HTTP %d", s)
	default:
		return nil, permanent("HTTP %d", s)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(body) > maxMetadataBytes {
		return nil, permanent("response too large (over %d bytes)", maxMetadataBytes)
	}
	return body, nil
}

func newProvider(cfg config.Auth, d *discovered, opts DiscoverOptions) *Provider {
	md := d.md
	// go-oidc reads the HTTP client from this context for every later JWKS
	// refresh, so the bounded client applies to key rotation too.
	clientCtx := oidc.ClientContext(context.Background(), opts.HTTPClient)
	p := (&oidc.ProviderConfig{
		IssuerURL:   md.Issuer,
		AuthURL:     md.AuthorizationEndpoint,
		TokenURL:    md.TokenEndpoint,
		JWKSURL:     md.JWKSURI,
		UserInfoURL: md.UserinfoEndpoint,
		Algorithms:  d.algs,
	}).NewProvider(clientCtx)

	// Never set any Skip* or Insecure* option here (invariant 3).
	verifier := p.Verifier(&oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: d.algs,
		Now:                  opts.Now,
	})
	return &Provider{
		Issuer:        md.Issuer,
		Endpoint:      p.Endpoint(),
		EndSessionURL: md.EndSessionEndpoint,
		Verifier:      verifier,
		HTTPClient:    opts.HTTPClient,
	}
}
