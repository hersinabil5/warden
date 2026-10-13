package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/session"
)

// HandshakePath is served on route hosts: it redeems a one-time code for a
// host-only app session cookie (docs/DECISIONS.md D1, D13).
const HandshakePath = "/.warden/handshake"

const (
	// handshakeCodeTTL bounds how long a code is redeemable (D1).
	handshakeCodeTTL = 30 * time.Second
	// handshakeCookie binds a handshake to the browser that started it on
	// the app host, so a code cannot be redeemed in someone else's browser.
	handshakeCookie    = "__Host-warden_hs"
	handshakeCookieTTL = preAuthTTL
	handshakeNS        = "handshake"
)

// CookieNames lists every cookie Warden sets, for the proxy to keep away
// from upstreams: the session cookie and the __Host-warden_* family (pre-auth
// and handshake binding). A trailing "*" is a prefix match.
func CookieNames(sessionCookie string) []string {
	return []string{sessionCookie, "__Host-warden_*"}
}

// handshake is what a one-time code redeems to. Only hashes of secrets are
// stored: the main session hash and the binding cookie hash.
type handshake struct {
	Main     string `json:"m"`
	Host     string `json:"h"`
	ReturnTo string `json:"r"`
	Binding  string `json:"b"`
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validToken reports whether v is 32 bytes, base64url-encoded: the shape of
// randomToken output and of s256 output.
func validToken(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == 32
}

// Authenticate implements proxy.Authenticator: it returns the session behind
// the request's app cookie for host, or writes a login redirect (GET/HEAD),
// a 401 (other methods), or an error page.
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request, host string) (*session.Session, bool) {
	if c, err := r.Cookie(h.cookieName); err == nil && c.Value != "" {
		sess, gerr := h.sessions.GetApp(r.Context(), c.Value, host)
		switch {
		case gerr == nil:
			return sess, true
		case errors.Is(gerr, session.ErrNotFound):
			session.ClearCookie(w, h.cookieName)
		default:
			h.fail(w, r, "loading app session", gerr)
			return nil, false
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.errorPage(w, r, http.StatusUnauthorized)
		return nil, false
	}

	// Reuse the browser's binding if it has one, so parallel requests do
	// not each plant a cookie.
	binding := ""
	if c, err := r.Cookie(handshakeCookie); err == nil && validToken(c.Value) {
		binding = c.Value
	} else {
		v, rerr := randomToken()
		if rerr != nil {
			h.fail(w, r, "generating handshake binding", rerr)
			return nil, false
		}
		binding = v
		http.SetCookie(w, &http.Cookie{
			Name: handshakeCookie, Value: binding, Path: "/", MaxAge: int(handshakeCookieTTL / time.Second),
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
	}

	rd, err := h.returns.validate(origin(host, h.port) + r.URL.RequestURI())
	if err != nil {
		rd = origin(host, h.port) + "/"
	}
	q := url.Values{"rd": {rd}, "hs": {s256(binding)}}
	http.Redirect(w, r, origin(h.authDomain, h.port)+LoginPath+"?"+q.Encode(), http.StatusFound)
	return nil, false
}

// continueTo sends a signed-in browser on from the auth host: to the session
// page, back to the app (which will start a bound handshake), or into the
// handshake when the browser binding is known.
func (h *Handler) continueTo(w http.ResponseWriter, r *http.Request, mainID, returnTo, binding string) {
	switch {
	case returnTo == "":
		http.Redirect(w, r, SessionPath, http.StatusFound)
	case binding == "":
		http.Redirect(w, r, returnTo, http.StatusFound)
	default:
		h.issueHandshake(w, r, mainID, returnTo, binding)
	}
}

func (h *Handler) issueHandshake(w http.ResponseWriter, r *http.Request, mainID, returnTo, binding string) {
	u, err := url.Parse(returnTo)
	if err != nil {
		h.fail(w, r, "parsing return URL", err)
		return
	}
	host := strings.ToLower(u.Hostname())
	code, err := randomToken()
	if err != nil {
		h.fail(w, r, "generating handshake code", err)
		return
	}
	payload, err := json.Marshal(handshake{Main: session.HashID(mainID), Host: host, ReturnTo: returnTo, Binding: binding})
	if err != nil {
		h.fail(w, r, "encoding handshake", err)
		return
	}
	if err := h.sessions.PutOnce(r.Context(), handshakeNS, code, payload, handshakeCodeTTL); err != nil {
		h.fail(w, r, "storing handshake code", err)
		return
	}
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, origin(host, h.port)+HandshakePath+"?"+url.Values{"code": {code}}.Encode(), http.StatusFound)
}

// redeemHandshake runs on a route host: it trades a one-time code, presented
// by the browser that holds the matching binding cookie, for an app session.
func (h *Handler) redeemHandshake(w http.ResponseWriter, r *http.Request, host string) {
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	codes := r.URL.Query()["code"]
	if len(codes) != 1 || codes[0] == "" {
		h.rejectHandshake(w, r, "missing or repeated code")
		return
	}
	// Redeem first: a code is spent by any attempt, valid or not.
	raw, err := h.sessions.TakeOnce(r.Context(), handshakeNS, codes[0])
	if errors.Is(err, session.ErrNotFound) {
		h.rejectHandshake(w, r, "unknown, used, or expired code")
		return
	}
	if err != nil {
		h.fail(w, r, "redeeming handshake code", err)
		return
	}
	var hs handshake
	if err = json.Unmarshal(raw, &hs); err != nil {
		h.fail(w, r, "decoding handshake", err)
		return
	}
	if hs.Host != host {
		h.rejectHandshake(w, r, "code issued for another host")
		return
	}
	c, err := r.Cookie(handshakeCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(s256(c.Value)), []byte(hs.Binding)) != 1 {
		h.rejectHandshake(w, r, "browser binding does not match")
		return
	}
	returnTo, err := h.returns.validate(hs.ReturnTo)
	if err != nil {
		h.rejectHandshake(w, r, "stored return URL no longer valid")
		return
	}

	appID, err := h.sessions.CreateApp(r.Context(), hs.Main, host)
	if errors.Is(err, session.ErrNotFound) {
		// The main session ended meanwhile: start over from the app.
		http.Redirect(w, r, returnTo, http.StatusFound)
		return
	}
	if err != nil {
		h.fail(w, r, "creating app session", err)
		return
	}
	if old, cerr := r.Cookie(h.cookieName); cerr == nil && old.Value != "" {
		if derr := h.sessions.DeleteApp(r.Context(), old.Value); derr != nil {
			h.fail(w, r, "revoking previous app session", derr)
			return
		}
	}
	session.SetCookie(w, h.cookieName, appID, h.sessions.AbsoluteTTL())
	h.logger.Info("handshake completed", "request_id", requestID(w), "host", host,
		"session_hash", hs.Main[:12], "app_session_hash", session.HashID(appID)[:12])
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (h *Handler) rejectHandshake(w http.ResponseWriter, r *http.Request, reason string) {
	h.logger.Warn("handshake rejected", "request_id", requestID(w), "reason", reason)
	h.errorPage(w, r, http.StatusBadRequest)
}

// requestHost is the lowercased Host without a port, as the proxy routes it.
func requestHost(r *http.Request) string {
	host := r.Host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		host = hh
	}
	return strings.ToLower(host)
}
