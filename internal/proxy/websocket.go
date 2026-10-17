package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/policy"
	"github.com/hersinabil5/warden/internal/session"
)

// Rechecker re-validates the session behind an open WebSocket without
// writing a response (the connection is hijacked). Any error closes it.
type Rechecker interface {
	Recheck(ctx context.Context, r *http.Request, host, requestID string) (*session.Session, error)
}

// DefaultWebSocketRecheck is how often an open WebSocket's session and
// policy are re-checked: the longest a revocation takes to reach it
// (docs/DECISIONS.md D29).
const DefaultWebSocketRecheck = config.DefaultWebSocketRecheck

// Audit reasons for refused upgrades.
const (
	reasonBadUpgrade  = "unsupported upgrade"
	reasonCrossOrigin = "cross-origin websocket"
	reasonNoRecheck   = "websocket re-check unavailable"
)

var errBadUpgrade = errors.New("unsupported upgrade")

// webSocketUpgrade reports whether r asks to switch protocols. The only
// switch allowed is a GET to exactly "websocket"; anything else is an error,
// because after a 101 the connection is an opaque pipe to the upstream and
// per-path policy no longer applies (h2c smuggling). Without both Upgrade
// and a Connection "upgrade" token it is not an upgrade: ReverseProxy drops
// both as hop-by-hop headers and never switches.
func webSocketUpgrade(r *http.Request) (bool, error) {
	upgrade := r.Header.Values("Upgrade")
	switch {
	case len(upgrade) == 0 || !hasToken(r.Header.Values("Connection"), "upgrade"):
		return false, nil
	case len(upgrade) != 1 || r.Method != http.MethodGet:
		return false, errBadUpgrade
	case !strings.EqualFold(strings.TrimSpace(upgrade[0]), "websocket"):
		return false, errBadUpgrade
	}
	return true, nil
}

// hasToken reports whether a comma-separated header lists token,
// case-insensitively.
func hasToken(values []string, token string) bool {
	for _, v := range values {
		for f := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

// sameOrigin reports whether a WebSocket's Origin is the route itself. Origin
// is the browser's, so this stops another site, or a sibling app on the same
// site that SameSite=Lax cookies still reach, from opening a socket with the
// user's cookies. No Origin means a non-browser client, which a header check
// couldn't stop anyway.
func (h *Handler) sameOrigin(r *http.Request, host string) bool {
	o := r.Header.Values("Origin")
	if len(o) == 0 {
		return true
	}
	if len(o) != 1 {
		return false
	}
	u, err := url.Parse(o[0])
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return strings.EqualFold(u.Hostname(), host) && port == h.port
}

// watchWebSocket re-checks an open WebSocket every interval and cancels its
// context, which closes both ends, once the session or the policy says no.
// It returns when ctx ends.
func (h *Handler) watchWebSocket(ctx context.Context, cancel context.CancelFunc, rc Rechecker,
	r *http.Request, host, id string, pol *policy.Policy) {
	t := time.NewTicker(h.wsRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		why := ""
		sess, err := rc.Recheck(ctx, r, host, id)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			why = "session no longer valid"
			if !errors.Is(err, session.ErrNotFound) {
				h.logger.Error("re-checking websocket session", "request_id", id, "err", err)
			}
		default:
			if d := pol.Evaluate(policy.Input{Path: r.URL.Path, Subject: subject(sess), Now: h.now()}); !d.Allow {
				why = "policy: " + d.Reason
			}
		}
		if why != "" {
			h.logger.Info("websocket closed", "request_id", id, "host", host, "path", r.URL.Path, "reason", why)
			cancel()
			return
		}
	}
}

// publicPortOf is the listen address's port, "443" when unset (tests).
func publicPortOf(listen string) (string, error) {
	if listen == "" {
		return "443", nil
	}
	_, port, err := net.SplitHostPort(listen)
	return port, err
}
