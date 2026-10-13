package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/identity"
	"github.com/hersinabil5/warden/internal/pathnorm"
	"github.com/hersinabil5/warden/internal/policy"
	"github.com/hersinabil5/warden/internal/session"
)

// reservedPrefix is Warden's own path namespace on every host. Requests under
// it are handled by Warden and never proxied (docs/DECISIONS.md D7).
const reservedPrefix = "/.warden"

// JWKSPath serves the identity assertion keys on the auth host. It is the
// standard well-known location, outside /.warden/, so upstreams and tools
// find it without configuration.
const JWKSPath = "/.well-known/jwks.json"

// Asserter signs the identity assertion for one upstream host
// (identity.Signer).
type Asserter interface {
	Assert(c identity.Claims, audience string) (string, error)
}

// assertionKey carries the signed assertion from route to Rewrite.
type assertionKey struct{}

// HealthzPath is a liveness check served on every host, with or without
// authentication. It reports only that the process is serving.
const HealthzPath = reservedPrefix + "/healthz"

// Authenticator decides whether a request to a route host carries a valid
// session. When it returns false it has already written the response (a
// login redirect, 401, or error page) and the request must not be proxied.
type Authenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request, host string) (*session.Session, bool)
}

// Options configures a Handler.
type Options struct {
	Logger *slog.Logger
	// Auth serves Warden's endpoints under /.warden/ on the auth host and on
	// route hosts (the handshake). Nil leaves them 404.
	Auth http.Handler
	// Authenticator checks sessions on route hosts. Nil denies every
	// proxied request (fail closed).
	Authenticator Authenticator
	// CookieNames are Warden's own cookies: never forwarded to upstreams,
	// and upstreams may not set them. Names ending in "*" match a prefix.
	CookieNames []string
	// Transport timeouts for upstream connections; zero means
	// DefaultTransportTimeouts.
	TransportTimeouts TransportTimeouts
	// Now is the clock for policy evaluation; nil means time.Now.
	Now func() time.Time
	// Identity signs the assertion sent to upstreams. Required.
	Identity Asserter
	// JWKS serves the assertion keys at JWKSPath on the auth host. Nil
	// leaves that path 404.
	JWKS http.Handler
}

// Handler routes requests by Host to upstream reverse proxies.
type Handler struct {
	routes     map[string]route
	authDomain string
	auth       http.Handler
	authn      Authenticator
	identity   Asserter
	jwks       http.Handler
	now        func() time.Time
	logger     *slog.Logger
}

// route is one configured host: its compiled policy and its reverse proxy.
type route struct {
	policy *policy.Policy
	proxy  *httputil.ReverseProxy
}

// New builds a Handler from a validated config.
func New(cfg *config.Config, opts Options) (*Handler, error) {
	if opts.Identity == nil {
		return nil, errors.New("no identity asserter")
	}
	idHeader := cfg.Identity.Header
	if idHeader == "" {
		return nil, errors.New("no identity header configured")
	}
	h := &Handler{
		routes:     make(map[string]route, len(cfg.Routes)),
		authDomain: cfg.Auth.Domain,
		auth:       opts.Auth,
		authn:      opts.Authenticator,
		identity:   opts.Identity,
		jwks:       opts.JWKS,
		now:        opts.Now,
		logger:     opts.Logger,
	}
	if h.now == nil {
		h.now = time.Now
	}
	cookies := newCookieMatcher(opts.CookieNames)
	idHeaders := newIdentityHeaders(cfg.StripHeaders, cfg.Identity.Header)
	tt := opts.TransportTimeouts
	if tt == (TransportTimeouts{}) {
		tt = DefaultTransportTimeouts
	}
	for _, r := range cfg.Routes {
		if r.UpstreamURL == nil {
			return nil, fmt.Errorf("route %s: upstream URL not parsed", r.Host)
		}
		pol, err := policy.Compile(r.Policy)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Host, err)
		}
		transport, err := newTransport(tt, r.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Host, err)
		}
		target, host := r.UpstreamURL, r.Host
		h.routes[r.Host] = route{policy: pol, proxy: &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				// In.URL carries the normalized path (ServeHTTP), so the
				// upstream gets exactly the path policy saw (invariant 6).
				pr.SetURL(target)
				// Strip, then inject (invariant 2).
				idHeaders.strip(pr.Out.Header)
				rewriteHeaders(pr)
				if tok, ok := pr.In.Context().Value(assertionKey{}).(string); ok {
					pr.Out.Header.Set(idHeader, tok)
				}
				stripCookies(pr.Out.Header, cookies)
			},
			ModifyResponse: func(res *http.Response) error {
				// ServeHTTP already set Warden's ID on the response; drop any
				// value the upstream sent so the client sees exactly one.
				res.Header.Del(RequestIDHeader)
				stripSetCookies(res.Header, cookies)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
				h.upstreamError(w, req, host, err)
			},
			Transport: transport,
			ErrorLog:  slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
		}}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id := newRequestID()
	r = r.WithContext(withRequestID(r.Context(), id))
	w.Header().Set(RequestIDHeader, id)

	host := hostOnly(r.Host)
	rec := &statusRecorder{ResponseWriter: w}
	defer func() {
		// Path only: the query string can carry tokens or codes (invariant 9).
		h.logger.Info("request",
			"request_id", id,
			"host", host,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.statusCode(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()
	// The TLS session was negotiated for ServerName; refuse to use it for a
	// different host.
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host) {
		writePage(rec, http.StatusMisdirectedRequest, id)
		return
	}
	// Everything below, routing, Warden's endpoints, policy, and the
	// upstream, sees only the normalized path (invariant 6).
	norm, err := normalizedPath(r)
	if err != nil {
		h.logger.Info("request path rejected", "request_id", id, "host", host, "reason", err.Error())
		writePage(rec, http.StatusBadRequest, id)
		return
	}
	r = withPath(r, norm)
	h.route(rec, r, host, id)
}

// normalizedPath normalizes the path exactly as the client sent it.
// r.URL.Path is already decoded, so an encoded "/" would be invisible there;
// the raw request target still has it.
func normalizedPath(r *http.Request) (string, error) {
	raw, _, _ := strings.Cut(r.RequestURI, "?")
	if !strings.HasPrefix(raw, "/") {
		// Absolute-form ("https://host/path"), which servers must accept
		// (RFC 9112, section 3.2.2). net/http already parsed it, so the path
		// starts at the first "/" after the authority.
		scheme, rest, ok := strings.Cut(raw, "://")
		if !ok || scheme == "" {
			// "*" (OPTIONS) or no request target at all.
			return "", fmt.Errorf("%w: unsupported request target", pathnorm.ErrInvalid)
		}
		raw = "/"
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			raw = rest[i:]
		}
	}
	return pathnorm.Normalize(raw)
}

// withPath returns a shallow copy of r whose URL has path p and no RawPath,
// so the URL re-encodes p unambiguously.
func withPath(r *http.Request, p string) *http.Request {
	r2 := *r
	u := *r.URL
	u.Path, u.RawPath = p, ""
	r2.URL = &u
	r2.RequestURI = u.RequestURI()
	return &r2
}

func (h *Handler) route(w http.ResponseWriter, r *http.Request, host, id string) {

	if r.URL.Path == HealthzPath {
		serveHealthz(w, r, id)
		return
	}
	if host == h.authDomain && r.URL.Path == JWKSPath {
		if h.jwks == nil {
			writePage(w, http.StatusNotFound, id)
			return
		}
		h.jwks.ServeHTTP(w, r)
		return
	}
	rt, isRoute := h.routes[host]
	if r.URL.Path == reservedPrefix || strings.HasPrefix(r.URL.Path, reservedPrefix+"/") {
		// Warden's own endpoints, on hosts Warden serves. The auth handler
		// decides which endpoint exists on which host.
		if (host == h.authDomain || isRoute) && h.auth != nil {
			h.auth.ServeHTTP(w, r)
			return
		}
		writePage(w, http.StatusNotFound, id)
		return
	}
	if !isRoute {
		writePage(w, http.StatusNotFound, id)
		return
	}

	if h.authn == nil {
		writePage(w, http.StatusForbidden, id)
		return
	}
	sess, ok := h.authn.Authenticate(w, r, host)
	if !ok {
		return
	}
	d := rt.policy.Evaluate(policy.Input{Path: r.URL.Path, Subject: subject(sess), Now: h.now()})
	if !d.Allow {
		// The rule and reason go to the log only; the client sees a generic
		// 403 page with the request ID.
		h.logger.Info("access denied", "request_id", id, "host", host, "path", r.URL.Path,
			"user", username(sess), "rule", d.Rule, "reason", d.Reason)
		writePage(w, http.StatusForbidden, id)
		return
	}
	h.logger.Debug("access allowed", "request_id", id, "host", host, "path", r.URL.Path,
		"user", username(sess), "rule", d.Rule)
	// Signed per request, for this host only (aud), so an assertion one
	// upstream receives is useless at another.
	tok, err := h.identity.Assert(identity.Claims{
		Subject: sess.Subject, Username: sess.Username, Email: sess.Email, Groups: sess.Groups,
	}, host)
	if err != nil {
		h.logger.Error("signing identity assertion", "request_id", id, "host", host, "err", err)
		writePage(w, http.StatusInternalServerError, id)
		return
	}
	rt.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), assertionKey{}, tok)))
}

// subject is the policy view of a session; nil stays nil (and is denied).
func subject(s *session.Session) *policy.Subject {
	if s == nil {
		return nil
	}
	return &policy.Subject{
		Username: s.Username,
		Email:    s.Email,
		Groups:   s.Groups,
		AMR:      s.AMR,
		AuthTime: s.AuthTime,
	}
}

func username(s *session.Session) string {
	if s == nil {
		return ""
	}
	return s.Username
}

func serveHealthz(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writePage(w, http.StatusMethodNotAllowed, id)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, `{"status":"ok"}`+"\n")
	}
}

// upstreamError logs the real cause and shows the client a generic 502 page.
func (h *Handler) upstreamError(w http.ResponseWriter, r *http.Request, host string, err error) {
	id := RequestID(r.Context())
	level := slog.LevelWarn
	if errors.Is(err, context.Canceled) {
		level = slog.LevelDebug // the client went away; not an upstream fault
	}
	h.logger.Log(r.Context(), level, "upstream error", "request_id", id, "host", host, "err", err)
	writePage(w, http.StatusBadGateway, id)
}
