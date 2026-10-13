package authn

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/hersinabil5/warden/internal/session"
)

// LogoutPath ends the session. POST only, on the auth host.
const LogoutPath = "/.warden/logout"

// logout revokes the main session (and with it every app session, D10),
// clears the cookie, and optionally ends the IdP session too.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// The SameSite=Lax cookie is not sent on cross-site POSTs; refusing
	// cross-site requests outright also covers browsers that do send it.
	if !h.sameOrigin(r) {
		h.logger.Warn("logout rejected: cross-site request", "request_id", requestID(w))
		h.errorPage(w, r, http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	session.ClearCookie(w, h.cookieName)
	if c, err := r.Cookie(h.cookieName); err == nil && c.Value != "" {
		if err := h.sessions.Delete(r.Context(), c.Value); err != nil {
			h.fail(w, r, "revoking session", err)
			return
		}
		h.logger.Info("logout", "request_id", requestID(w), "session_hash", session.HashID(c.Value)[:12])
	}
	if h.idpLogoutURL != "" {
		http.Redirect(w, r, h.idpLogoutURL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, SessionPath, http.StatusSeeOther)
}

// sameOrigin rejects requests a browser marks as cross-origin. Requests with
// neither header (non-browser clients) are allowed: they carry no ambient
// cookies an attacker could ride on.
func (h *Handler) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != origin(h.authDomain, h.port) {
		return false
	}
	return true
}

// idpLogoutURL builds the RP-initiated logout URL (OIDC RP-Initiated Logout
// 1.0): client_id and a fixed post_logout_redirect_uri, no ID token.
func idpLogoutURL(p *Provider, clientID, postLogout string) (string, error) {
	if p.EndSessionURL == "" {
		return "", errors.New("authn: auth.logout_at_idp is set but the IdP has no end_session_endpoint")
	}
	u, err := url.Parse(p.EndSessionURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", clientID)
	q.Set("post_logout_redirect_uri", postLogout)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
