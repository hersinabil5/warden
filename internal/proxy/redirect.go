package proxy

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
)

// RedirectHandler sends plain-HTTP requests to the HTTPS listener.
type RedirectHandler struct {
	hosts     map[string]bool
	httpsPort int
	logger    *slog.Logger
}

// NewRedirectHandler redirects requests for the given hosts to
// https://host[:httpsPort]. hosts must already be lowercase.
func NewRedirectHandler(hosts []string, httpsPort int, logger *slog.Logger) *RedirectHandler {
	m := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		m[h] = true
	}
	return &RedirectHandler{hosts: m, httpsPort: httpsPort, logger: logger}
}

func (h *RedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := newRequestID()
	w.Header().Set(RequestIDHeader, id)

	// The Host header is attacker-controlled; redirecting to an arbitrary one
	// would make Warden an open redirect. Only configured hosts are allowed.
	host := hostOnly(r.Host)
	if !h.hosts[host] {
		h.logger.Info("http redirect refused", "request_id", id, "reason", "unknown host")
		writePage(w, http.StatusBadRequest, id)
		return
	}

	target := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	if h.httpsPort != 443 {
		target.Host = host + ":" + strconv.Itoa(h.httpsPort)
	}
	// 308 keeps the method and body, unlike 301.
	http.Redirect(w, r, target.String(), http.StatusPermanentRedirect)
}
