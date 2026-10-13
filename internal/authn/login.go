package authn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// Warden's endpoints on the auth host, under the reserved /.warden/ prefix.
const (
	LoginPath    = "/.warden/login"
	CallbackPath = "/.warden/callback"
	SessionPath  = "/.warden/session"
)

// HandlerOptions configures a Handler.
type HandlerOptions struct {
	// CookieKey seals pre-auth cookies; 32 bytes from NewCookieKey.
	CookieKey []byte
	Sessions  *session.Store
	Logger    *slog.Logger
	// ErrorPage writes Warden's generic error page. Nil falls back to a plain
	// status text response.
	ErrorPage func(w http.ResponseWriter, r *http.Request, code int)
	Now       func() time.Time
}

// Handler serves the OIDC endpoints on the auth host.
type Handler struct {
	oauth       oauth2.Config
	provider    *Provider
	sessions    *session.Store
	cookieName  string
	groupsClaim string
	returns     *returnURLs
	authDomain  string
	port        string
	// idpLogoutURL is set when auth.logout_at_idp is on.
	idpLogoutURL string
	// formAction is the CSP form-action for pages with the logout form.
	formAction string
	sealer     *cookieSealer
	logger     *slog.Logger
	errorPage  func(http.ResponseWriter, *http.Request, int)
	now        func() time.Time
}

// NewHandler builds the auth-host handler from a validated config and a
// discovered provider.
func NewHandler(cfg *config.Config, p *Provider, opts HandlerOptions) (*Handler, error) {
	if p == nil {
		return nil, errors.New("authn: provider is required")
	}
	if opts.Sessions == nil {
		return nil, errors.New("authn: session store is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	sealer, err := newCookieSealer(opts.CookieKey, opts.Now)
	if err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.ErrorPage == nil {
		opts.ErrorPage = func(w http.ResponseWriter, _ *http.Request, code int) {
			http.Error(w, http.StatusText(code), code)
		}
	}
	port, err := publicPort(cfg.Listen)
	if err != nil {
		return nil, err
	}
	// client_secret_basic: one fixed method, no auto-detect retries that
	// would send the secret twice.
	endpoint := p.Endpoint
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	hosts := make([]string, 0, len(cfg.Routes))
	for _, r := range cfg.Routes {
		hosts = append(hosts, r.Host)
	}
	h := &Handler{
		oauth: oauth2.Config{
			ClientID:     cfg.Auth.ClientID,
			ClientSecret: cfg.Auth.ClientSecret.Reveal(),
			Endpoint:     endpoint,
			RedirectURL:  origin(cfg.Auth.Domain, port) + CallbackPath,
			Scopes:       cfg.Auth.Scopes,
		},
		provider:    p,
		sessions:    opts.Sessions,
		cookieName:  cfg.Session.CookieName,
		groupsClaim: cfg.Auth.GroupsClaim,
		returns:     newReturnURLs(hosts, port),
		authDomain:  cfg.Auth.Domain,
		port:        port,
		sealer:      sealer,
		logger:      opts.Logger,
		errorPage:   opts.ErrorPage,
		now:         opts.Now,
	}
	h.formAction = "'self'"
	if cfg.Auth.LogoutAtIdP {
		h.idpLogoutURL, err = idpLogoutURL(p, cfg.Auth.ClientID, origin(cfg.Auth.Domain, port)+SessionPath)
		if err != nil {
			return nil, err
		}
		// Chrome applies form-action to the redirect after the POST.
		if u, perr := url.Parse(h.idpLogoutURL); perr == nil {
			h.formAction += " " + u.Scheme + "://" + u.Host
		}
	}
	return h, nil
}

// AuthOrigin is the public https origin of the auth host, for example
// https://auth.warden.localhost:8443. It is the identity assertion issuer.
func AuthOrigin(cfg *config.Config) (string, error) {
	port, err := publicPort(cfg.Listen)
	if err != nil {
		return "", err
	}
	return origin(cfg.Auth.Domain, port), nil
}

// publicPort is the HTTPS port browsers use, taken from the listen address.
// URLs Warden builds (redirect_uri, return URLs) come from config, never from
// the request's Host header.
func publicPort(listen string) (string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("authn: listen address %q: %w", listen, err)
	}
	return port, nil
}

// origin returns https://host[:port], omitting the default port.
func origin(host, port string) string {
	if port == "443" {
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(host, port)
}

// ServeHTTP serves Warden's endpoints. Which exist depends on the host: the
// OIDC endpoints only on the auth host, the handshake only on route hosts.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := requestHost(r)
	method := http.MethodGet
	var serve http.HandlerFunc
	switch {
	case host == h.authDomain && r.URL.Path == LoginPath:
		serve = h.login
	case host == h.authDomain && r.URL.Path == CallbackPath:
		serve = h.callback
	case host == h.authDomain && r.URL.Path == SessionPath:
		serve = h.sessionPage
	case h.returns.hosts[host] && r.URL.Path == HandshakePath:
		serve = func(w http.ResponseWriter, r *http.Request) { h.redeemHandshake(w, r, host) }
	case host == h.authDomain && r.URL.Path == LogoutPath:
		method = http.MethodPost
		serve = h.logout
	default:
		h.errorPage(w, r, http.StatusNotFound)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		h.errorPage(w, r, http.StatusMethodNotAllowed)
		return
	}
	serve(w, r)
}

// login starts the authorization code flow: fresh state, nonce, and PKCE
// verifier sealed into a pre-auth cookie, then a redirect to the IdP. Nothing
// from the request feeds the authorize URL.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	returnTo, ok := h.returnTo(w, r)
	if !ok {
		return
	}
	binding, ok := h.binding(w, r, returnTo)
	if !ok {
		return
	}
	// Already signed in on the auth host: no IdP round trip (single sign-on).
	if c, err := r.Cookie(h.cookieName); err == nil && c.Value != "" {
		_, gerr := h.sessions.Get(r.Context(), c.Value)
		switch {
		case gerr == nil:
			h.continueTo(w, r, c.Value, returnTo, binding)
			return
		case !errors.Is(gerr, session.ErrNotFound):
			h.fail(w, r, "loading session", gerr)
			return
		}
	}
	pa, err := newPreAuth(h.now())
	if err != nil {
		h.fail(w, r, "generating login state", err)
		return
	}
	pa.ReturnTo, pa.Binding = returnTo, binding
	name := preAuthCookieName(pa.State)
	value, err := h.sealer.seal(name, pa)
	if err != nil {
		h.fail(w, r, "sealing pre-auth cookie", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(preAuthTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := h.oauth.AuthCodeURL(pa.State, oidc.Nonce(pa.Nonce), oauth2.S256ChallengeOption(pa.Verifier))
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	h.logger.Info("login started", "request_id", requestID(w), "state_hash", hashPrefix(pa.State))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// returnTo reads and validates the optional rd parameter (invariant 5). On
// failure it writes a 400 and returns false.
func (h *Handler) returnTo(w http.ResponseWriter, r *http.Request) (string, bool) {
	rds := r.URL.Query()["rd"]
	switch len(rds) {
	case 0:
		return "", true
	case 1:
		if v, err := h.returns.validate(rds[0]); err == nil {
			return v, true
		}
	}
	h.logger.Warn("rejected return URL", "request_id", requestID(w), "count", len(rds))
	h.errorPage(w, r, http.StatusBadRequest)
	return "", false
}

// binding reads the optional hs parameter: the hash of the app host's
// handshake cookie. It is only meaningful with a return URL.
func (h *Handler) binding(w http.ResponseWriter, r *http.Request, returnTo string) (string, bool) {
	hss := r.URL.Query()["hs"]
	switch {
	case len(hss) == 0:
		return "", true
	case len(hss) == 1 && returnTo != "" && validToken(hss[0]):
		return hss[0], true
	}
	h.logger.Warn("rejected handshake binding", "request_id", requestID(w))
	h.errorPage(w, r, http.StatusBadRequest)
	return "", false
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.logger.Error("login failed", "request_id", requestID(w), "step", what, "err", err)
	h.errorPage(w, r, http.StatusInternalServerError)
}

// hashPrefix is a short, non-reversible correlation ID for a secret value
// (invariant 9).
func hashPrefix(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// requestID returns the ID the proxy already set on the response. The
// request's own X-Request-ID header is client-controlled and never used.
func requestID(w http.ResponseWriter) string {
	return w.Header().Get("X-Request-ID")
}
