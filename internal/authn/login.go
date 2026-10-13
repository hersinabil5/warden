package authn

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hersinabil5/warden/internal/config"
)

// Warden's endpoints on the auth host, under the reserved /.warden/ prefix.
const (
	LoginPath    = "/.warden/login"
	CallbackPath = "/.warden/callback"
)

// HandlerOptions configures a Handler.
type HandlerOptions struct {
	// CookieKey seals pre-auth cookies; 32 bytes from NewCookieKey.
	CookieKey []byte
	Logger    *slog.Logger
	// ErrorPage writes Warden's generic error page. Nil falls back to a plain
	// status text response.
	ErrorPage func(w http.ResponseWriter, r *http.Request, code int)
	Now       func() time.Time
}

// Handler serves the OIDC endpoints on the auth host.
type Handler struct {
	oauth     oauth2.Config
	sealer    *cookieSealer
	logger    *slog.Logger
	errorPage func(http.ResponseWriter, *http.Request, int)
	now       func() time.Time
}

// NewHandler builds the auth-host handler from a validated config and a
// discovered provider.
func NewHandler(cfg *config.Config, p *Provider, opts HandlerOptions) (*Handler, error) {
	if p == nil {
		return nil, errors.New("authn: provider is required")
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
	redirectURL, err := callbackURL(cfg.Auth.Domain, cfg.Listen)
	if err != nil {
		return nil, err
	}
	return &Handler{
		// The secret is not needed to build the authorize URL; the token
		// exchange (callback) adds it.
		oauth: oauth2.Config{
			ClientID:    cfg.Auth.ClientID,
			Endpoint:    p.Endpoint,
			RedirectURL: redirectURL,
			Scopes:      cfg.Auth.Scopes,
		},
		sealer:    sealer,
		logger:    opts.Logger,
		errorPage: opts.ErrorPage,
		now:       opts.Now,
	}, nil
}

// callbackURL is the fixed redirect_uri registered at the IdP. It comes from
// config, never from the request's Host header.
func callbackURL(domain, listen string) (string, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("authn: listen address %q: %w", listen, err)
	}
	host := domain
	if port != "443" {
		host = net.JoinHostPort(domain, port)
	}
	return "https://" + host + CallbackPath, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case LoginPath:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			h.errorPage(w, r, http.StatusMethodNotAllowed)
			return
		}
		h.login(w, r)
	default:
		h.errorPage(w, r, http.StatusNotFound)
	}
}

// login starts the authorization code flow: fresh state, nonce, and PKCE
// verifier sealed into a pre-auth cookie, then a redirect to the IdP. Nothing
// from the request feeds the authorize URL.
func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	pa, err := newPreAuth(h.now())
	if err != nil {
		h.fail(w, r, "generating login state", err)
		return
	}
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
