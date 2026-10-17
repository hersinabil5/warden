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

	"github.com/hersinabil5/warden/internal/admin"
	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/identity"
	"github.com/hersinabil5/warden/internal/pathnorm"
	"github.com/hersinabil5/warden/internal/policy"
	"github.com/hersinabil5/warden/internal/ratelimit"
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

// StepUpper is an Authenticator that can send a signed-in user back to the
// IdP for a fresh multi-factor login when the policy asks for one
// (policy.Decision.StepUp). It writes the whole response.
type StepUpper interface {
	StepUp(w http.ResponseWriter, r *http.Request, host string)
}

// stepUpReason is the audit reason for a deny answered with a step-up.
const stepUpReason = "step-up required"

// MainAuthenticator finds the auth host's main session for a request; nil
// without error means none.
type MainAuthenticator interface {
	MainSession(r *http.Request, requestID string) (*session.Session, error)
}

// AdminRoute serves the admin endpoints on the auth host. Like a route, every
// request is authenticated (with the main session), checked against Policy,
// and audited before Handler sees it (docs/DECISIONS.md D22).
type AdminRoute struct {
	Handler  http.Handler
	Policy   *policy.Policy
	Sessions MainAuthenticator
	// LoginPath is where a logged-out browser is sent from the dashboard.
	LoginPath string
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
	// Audit receives one event per request to a route host or the admin
	// endpoints. Required.
	Audit audit.Recorder
	// Admin serves the admin endpoints; nil leaves them 404.
	Admin *AdminRoute
	// HSTSMaxAge is the Strict-Transport-Security max-age sent on every
	// response, proxied or not; zero sends none. Handler serves HTTPS only.
	HSTSMaxAge time.Duration
	// WebSocketRecheck is how often open WebSockets are re-checked; zero
	// means DefaultWebSocketRecheck. WebSockets also need an Authenticator
	// that implements Rechecker.
	WebSocketRecheck time.Duration
}

// Handler routes requests by Host to upstream reverse proxies.
type Handler struct {
	routes     map[string]route
	authDomain string
	auth       http.Handler
	authn      Authenticator
	identity   Asserter
	jwks       http.Handler
	audit      audit.Recorder
	admin      *AdminRoute
	// Admin endpoint limits: per client IP before the session lookup, then
	// per session (docs/DECISIONS.md D27).
	adminIPLimit, adminSessionLimit *ratelimit.Limiter
	hsts                            string
	port                            string        // public HTTPS port, for WebSocket Origin checks
	wsRecheck                       time.Duration // see Options.WebSocketRecheck // Strict-Transport-Security value; "" for off
	now                             func() time.Time
	logger                          *slog.Logger
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
	if opts.Audit == nil {
		return nil, errors.New("no audit recorder")
	}
	if opts.HSTSMaxAge < 0 {
		return nil, errors.New("negative HSTS max-age")
	}
	if a := opts.Admin; a != nil && (a.Handler == nil || a.Policy == nil || a.Sessions == nil) {
		return nil, errors.New("admin route needs a handler, a policy, and a session lookup")
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
		audit:      opts.Audit,
		admin:      opts.Admin,
		hsts:       hstsValue(opts.HSTSMaxAge),
		now:        opts.Now,
		logger:     opts.Logger,
	}
	if h.now == nil {
		h.now = time.Now
	}
	port, err := publicPortOf(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen address: %w", err)
	}
	h.port = port
	h.wsRecheck = opts.WebSocketRecheck
	if h.wsRecheck <= 0 {
		h.wsRecheck = DefaultWebSocketRecheck
	}
	if h.admin != nil {
		var err error
		if h.adminIPLimit, err = newLimiter(cfg.RateLimits.AdminIP, config.DefaultAdminIPRate, h.now); err != nil {
			return nil, fmt.Errorf("admin IP rate limit: %w", err)
		}
		if h.adminSessionLimit, err = newLimiter(cfg.RateLimits.AdminSession, config.DefaultAdminSessionRate, h.now); err != nil {
			return nil, fmt.Errorf("admin session rate limit: %w", err)
		}
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
				// Warden terminates TLS for this host and alone decides its
				// HSTS policy; an app cannot turn it off or widen it.
				res.Header.Del(hstsHeader)
				if res.StatusCode == http.StatusSwitchingProtocols {
					if up, ok := res.Request.Context().Value(upgradedKey{}).(*bool); ok {
						*up = true
					}
				}
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
	if h.hsts != "" {
		w.Header().Set(hstsHeader, h.hsts)
	}
	// Until route hands the request to an upstream, the response is Warden's.
	setPageHeaders(w.Header())

	host := hostOnly(r.Host)
	rec := &statusRecorder{ResponseWriter: w}
	_, isRoute := h.routes[host]
	// Every request to a route host is audited unless route() says it is one
	// of Warden's own endpoints. Until a decision is made, it is a deny.
	ae := &auditState{on: isRoute, reason: "no decision"}
	rawPath, _, _ := strings.Cut(r.RequestURI, "?")
	defer func() {
		status := rec.statusCode()
		if ae.upgraded {
			status = http.StatusSwitchingProtocols
		}
		if ae.on {
			path := r.URL.Path
			if ae.rawPath {
				path = rawPath // rejected: there is no normalized path
			}
			h.audit.Record(r.Context(), audit.Event{
				Time: start, RequestID: id, User: ae.user, Session: ae.session,
				Host: host, Method: r.Method, Path: path,
				Decision: ae.decision, Rule: ae.rule, Reason: ae.reason,
				Latency: time.Since(start), Status: status,
			})
		}
		// Path only: the query string can carry tokens or codes (invariant 9).
		h.logger.Info("request",
			"request_id", id,
			"host", host,
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()
	// The TLS session was negotiated for ServerName; refuse to use it for a
	// different host.
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host) {
		ae.deny("", "misdirected request")
		ae.rawPath = true
		writePage(rec, http.StatusMisdirectedRequest, id)
		return
	}
	// Everything below, routing, Warden's endpoints, policy, and the
	// upstream, sees only the normalized path (invariant 6).
	norm, err := normalizedPath(r)
	if err != nil {
		h.logger.Info("request path rejected", "request_id", id, "host", host, "reason", err.Error())
		ae.deny("", "invalid path")
		ae.rawPath = true
		writePage(rec, http.StatusBadRequest, id)
		return
	}
	r = withPath(r, norm)
	h.route(rec, r, host, id, ae)
}

// auditState is what route decides about a request, for its audit event.
// ServeHTTP adds the outcome once the response is written.
type auditState struct {
	on            bool // record an event for this request
	rawPath       bool // record the path as sent: it was never normalized
	upgraded      bool // switched protocols: the status is 101
	decision      audit.Decision
	rule, reason  string
	user, session string
}

func (a *auditState) deny(rule, reason string) {
	a.decision, a.rule, a.reason = audit.Deny, rule, reason
}

func (a *auditState) subject(s *session.Session) {
	if s != nil {
		a.user, a.session = s.Username, audit.SessionPrefix(s.Hash)
	}
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

func (h *Handler) route(w http.ResponseWriter, r *http.Request, host, id string, ae *auditState) {
	if r.URL.Path == HealthzPath {
		ae.on = false
		serveHealthz(w, r, id)
		return
	}
	if host == h.authDomain && r.URL.Path == JWKSPath {
		ae.on = false
		if h.jwks == nil {
			writePage(w, http.StatusNotFound, id)
			return
		}
		h.jwks.ServeHTTP(w, r)
		return
	}
	if host == h.authDomain && h.admin != nil && admin.Owns(r.URL.Path) {
		h.serveAdmin(w, r, id, ae)
		return
	}
	rt, isRoute := h.routes[host]
	if r.URL.Path == reservedPrefix || strings.HasPrefix(r.URL.Path, reservedPrefix+"/") {
		// Warden's own endpoints, on hosts Warden serves. The auth handler
		// decides which endpoint exists on which host.
		ae.on = false
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
		ae.deny("", "no authenticator")
		writePage(w, http.StatusForbidden, id)
		return
	}
	ws, err := webSocketUpgrade(r)
	if err != nil {
		h.logger.Info("upgrade refused", "request_id", id, "host", host, "upgrade", r.Header.Values("Upgrade"))
		ae.deny("", reasonBadUpgrade)
		writePage(w, http.StatusBadRequest, id)
		return
	}
	rc, canRecheck := h.authn.(Rechecker)
	if ws && !h.sameOrigin(r, host) {
		h.logger.Info("websocket refused", "request_id", id, "host", host, "reason", reasonCrossOrigin)
		ae.deny("", reasonCrossOrigin)
		writePage(w, http.StatusForbidden, id)
		return
	}
	sess, ok := h.authn.Authenticate(w, r, host)
	if !ok {
		ae.deny("", "unauthenticated")
		return
	}
	ae.subject(sess)
	d := rt.policy.Evaluate(policy.Input{Path: r.URL.Path, Subject: subject(sess), Now: h.now()})
	ae.deny(d.Rule, d.Reason)
	if !d.Allow {
		// The rule and reason go to the log only; the client sees a generic
		// 403 page with the request ID.
		h.logger.Info("access denied", "request_id", id, "host", host, "path", r.URL.Path,
			"user", username(sess), "rule", d.Rule, "reason", d.Reason, "step_up", d.StepUp)
		if su, ok := h.authn.(StepUpper); ok && d.StepUp {
			ae.reason = stepUpReason
			su.StepUp(w, r, host)
			return
		}
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
		ae.reason = "identity assertion failed"
		writePage(w, http.StatusInternalServerError, id)
		return
	}
	if ws && !canRecheck {
		// Without re-checks an open socket would outlive revocation.
		ae.reason = reasonNoRecheck
		writePage(w, http.StatusForbidden, id)
		return
	}
	ae.decision = audit.Allow
	clearPageHeaders(w.Header())
	ctx := context.WithValue(r.Context(), assertionKey{}, tok)
	if !ws {
		rt.proxy.ServeHTTP(w, r.WithContext(ctx))
		return
	}
	// Cancelling the request context closes both ends of a switched
	// connection (httputil.ReverseProxy), so the watcher can end it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	upgraded := new(bool)
	ctx = context.WithValue(ctx, upgradedKey{}, upgraded)
	go h.watchWebSocket(ctx, cancel, rc, r, host, id, rt.policy)
	rt.proxy.ServeHTTP(w, r.WithContext(ctx))
	ae.upgraded = *upgraded
}

// upgradedKey carries a *bool that ModifyResponse sets on a 101 response.
type upgradedKey struct{}

// serveAdmin applies the route checks to an admin endpoint: main session,
// admin policy (default deny), audit. API failures are JSON errors;
// dashboard failures are pages, and a logged-out browser goes to login.
func (h *Handler) serveAdmin(w http.ResponseWriter, r *http.Request, id string, ae *auditState) {
	ae.on = true
	page := admin.IsDashboard(r.URL.Path) && (r.Method == http.MethodGet || r.Method == http.MethodHead)
	fail := func(code int) {
		if page {
			writePage(w, code, id)
			return
		}
		admin.WriteError(w, code)
	}
	limited := func(l *ratelimit.Limiter, key, by string) bool {
		ok, wait := l.Allow(key)
		if ok {
			return false
		}
		h.logger.Warn("rate limited", "request_id", id, "path", r.URL.Path, "by", by,
			"client", ratelimit.ClientKey(r.RemoteAddr))
		ae.deny("", "rate limited")
		w.Header().Set("Retry-After", ratelimit.RetryAfterSeconds(wait))
		fail(http.StatusTooManyRequests)
		return true
	}
	// Before the session lookup, so a flood never reaches Redis.
	if limited(h.adminIPLimit, ratelimit.ClientKey(r.RemoteAddr), "ip") {
		return
	}
	sess, err := h.admin.Sessions.MainSession(r, id)
	if err != nil {
		h.logger.Error("loading admin session", "request_id", id, "err", err)
		ae.deny("", "session store error")
		fail(http.StatusInternalServerError)
		return
	}
	if sess == nil {
		ae.deny("", "unauthenticated")
		if page && h.admin.LoginPath != "" {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, h.admin.LoginPath, http.StatusFound)
			return
		}
		admin.WriteError(w, http.StatusUnauthorized)
		return
	}
	ae.subject(sess)
	if limited(h.adminSessionLimit, sess.Hash, "session") {
		return
	}
	d := h.admin.Policy.Evaluate(policy.Input{Path: r.URL.Path, Subject: subject(sess), Now: h.now()})
	ae.deny(d.Rule, d.Reason)
	if !d.Allow {
		h.logger.Info("admin access denied", "request_id", id, "path", r.URL.Path,
			"user", sess.Username, "rule", d.Rule, "reason", d.Reason, "step_up", d.StepUp)
		// Only a page navigation can go through the IdP; it lands on the
		// session page, since return URLs are route hosts only (D28).
		if page && d.StepUp && h.admin.LoginPath != "" {
			ae.reason = stepUpReason
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, h.admin.LoginPath+"?step_up=1", http.StatusFound)
			return
		}
		fail(http.StatusForbidden)
		return
	}
	ae.decision = audit.Allow
	h.admin.Handler.ServeHTTP(w, r.WithContext(admin.WithSession(r.Context(), sess)))
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

// newLimiter builds a limiter from a configured rate; nil (a config that
// skipped validation) gets the default, never no limit.
func newLimiter(rate *config.RateLimit, def config.RateLimit, now func() time.Time) (*ratelimit.Limiter, error) {
	if rate != nil {
		def = *rate
	}
	return ratelimit.New(ratelimit.Limit(def), ratelimit.DefaultMaxKeys, now)
}
