package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/hersinabil5/warden/internal/config"
)

// reservedPrefix is Warden's own path namespace on every host. Requests under
// it are handled by Warden and never proxied (docs/DECISIONS.md D7).
const reservedPrefix = "/.warden"

// Options configures a Handler.
type Options struct {
	// AllowUnauthenticated proxies requests without authentication. It exists
	// only until login and policy land (M2/M3), requires loopback-only
	// listeners, and is off by default (docs/DECISIONS.md D6).
	AllowUnauthenticated bool
	Logger               *slog.Logger
	// Transport timeouts for upstream connections; zero means
	// DefaultTransportTimeouts.
	TransportTimeouts TransportTimeouts
}

// Handler routes requests by Host to upstream reverse proxies.
type Handler struct {
	routes      map[string]*httputil.ReverseProxy
	allowUnauth bool
	logger      *slog.Logger
}

// New builds a Handler from a validated config.
func New(cfg *config.Config, opts Options) (*Handler, error) {
	if opts.AllowUnauthenticated {
		for _, addr := range []string{cfg.Listen, cfg.HTTPRedirectListen} {
			if addr != "" && !isLoopbackAddr(addr) {
				return nil, fmt.Errorf("unauthenticated dev mode requires loopback listeners; %q is not", addr)
			}
		}
	}

	h := &Handler{
		routes:      make(map[string]*httputil.ReverseProxy, len(cfg.Routes)),
		allowUnauth: opts.AllowUnauthenticated,
		logger:      opts.Logger,
	}
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
		target := r.UpstreamURL
		h.routes[r.Host] = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
			},
			Transport: newTransport(tt, r.UpstreamTLS != nil),
			ErrorLog:  slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
		}
	}
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := newRequestID()
	r = r.WithContext(withRequestID(r.Context(), id))
	w.Header().Set(RequestIDHeader, id)

	host := hostOnly(r.Host)

	// The TLS session was negotiated for ServerName; refuse to use it for a
	// different host.
	if r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host) {
		writePage(w, http.StatusMisdirectedRequest, id)
		return
	}

	if r.URL.Path == reservedPrefix || strings.HasPrefix(r.URL.Path, reservedPrefix+"/") {
		writePage(w, http.StatusNotFound, id)
		return
	}

	rp, ok := h.routes[host]
	if !ok {
		writePage(w, http.StatusNotFound, id)
		return
	}

	// Default deny: until authentication exists, nothing is allowed unless
	// the dev flag says otherwise.
	if !h.allowUnauth {
		writePage(w, http.StatusForbidden, id)
		return
	}
	rp.ServeHTTP(w, r)
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
