package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/session"
)

// reservedPrefix is Warden's own path namespace on every host. Requests under
// it are handled by Warden and never proxied (docs/DECISIONS.md D7).
const reservedPrefix = "/.warden"

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
	// SkipPolicy proxies any authenticated request without evaluating route
	// policy. It exists only until the policy engine lands (M3), requires
	// loopback-only listeners, and is off by default (docs/DECISIONS.md D13).
	// Authentication is always required.
	SkipPolicy bool
	Logger     *slog.Logger
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
}

// Handler routes requests by Host to upstream reverse proxies.
type Handler struct {
	routes     map[string]*httputil.ReverseProxy
	authDomain string
	auth       http.Handler
	authn      Authenticator
	skipPolicy bool
	logger     *slog.Logger
}

// New builds a Handler from a validated config.
func New(cfg *config.Config, opts Options) (*Handler, error) {
	if opts.SkipPolicy {
		for _, addr := range []string{cfg.Listen, cfg.HTTPRedirectListen} {
			if addr != "" && !isLoopbackAddr(addr) {
				return nil, fmt.Errorf("dev mode without policy requires loopback listeners; %q is not", addr)
			}
		}
	}

	h := &Handler{
		routes:     make(map[string]*httputil.ReverseProxy, len(cfg.Routes)),
		authDomain: cfg.Auth.Domain,
		auth:       opts.Auth,
		authn:      opts.Authenticator,
		skipPolicy: opts.SkipPolicy,
		logger:     opts.Logger,
	}
	cookies := newCookieMatcher(opts.CookieNames)
	tt := opts.TransportTimeouts
	if tt == (TransportTimeouts{}) {
		tt = DefaultTransportTimeouts
	}
	for _, r := range cfg.Routes {
		if r.UpstreamURL == nil {
			return nil, fmt.Errorf("route %s: upstream URL not parsed", r.Host)
		}
		if r.UpstreamTLS != nil {
			opts.Logger.Warn("upstream_tls is not implemented until M4; route fails closed (every request gets 502)",
				"host", r.Host)
		}
		target, host := r.UpstreamURL, r.Host
		h.routes[r.Host] = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				rewriteHeaders(pr)
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
			Transport: newTransport(tt, r.UpstreamTLS != nil),
			ErrorLog:  slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
		}
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
	h.route(rec, r, host, id)
}

func (h *Handler) route(w http.ResponseWriter, r *http.Request, host, id string) {
	// The TLS session was negotiated for ServerName; refuse to use it for a
	// different host.
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host) {
		writePage(w, http.StatusMisdirectedRequest, id)
		return
	}

	if r.URL.Path == HealthzPath {
		serveHealthz(w, r, id)
		return
	}
	rp, isRoute := h.routes[host]
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
	if _, ok := h.authn.Authenticate(w, r, host); !ok {
		return
	}
	// Default deny (invariant 1): no policy engine yet (M3), so an
	// authenticated request is proxied only in loopback dev mode.
	if !h.skipPolicy {
		writePage(w, http.StatusForbidden, id)
		return
	}
	rp.ServeHTTP(w, r)
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

func isLoopbackAddr(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
