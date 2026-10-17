package authn

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hersinabil5/warden/internal/session"
)

// clockSkew tolerates small clock differences between Warden and the IdP
// when checking iat.
const clockSkew = time.Minute

// idClaims are the ID token claims Warden reads beyond what go-oidc checks.
type idClaims struct {
	Subject           string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     any      `json:"email_verified"`
	PreferredUsername string   `json:"preferred_username"`
	AuthTime          *int64   `json:"auth_time"`
	AMR               []string `json:"amr"`
	AZP               string   `json:"azp"`
	IssuedAt          *int64   `json:"iat"`
}

// callback completes the authorization code flow. Every check runs before
// a session exists; any failure is a deny.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Referrer-Policy", "no-referrer")
	q := r.URL.Query()

	states := q["state"]
	if len(states) != 1 || states[0] == "" {
		h.reject(w, r, "missing or repeated state")
		return
	}
	state := states[0]
	name := preAuthCookieName(state)
	c, err := r.Cookie(name)
	if err != nil {
		// No cookie for this state: not this browser's login (login CSRF).
		h.reject(w, r, "no pre-auth cookie for state")
		return
	}
	// From here on the pre-auth cookie is spent, whatever happens.
	clearPreAuth(w, name)
	pa, err := h.sealer.open(name, c.Value)
	if err != nil {
		h.reject(w, r, "invalid pre-auth cookie")
		return
	}
	if subtle.ConstantTimeCompare([]byte(pa.State), []byte(state)) != 1 {
		h.reject(w, r, "state does not match pre-auth cookie")
		return
	}
	// Single use (invariant 4): the sealed cookie alone could be replayed
	// until it expires, so record the state server-side.
	first, err := h.sessions.MarkUsed(r.Context(), "state", state, time.Until(time.Unix(pa.Expires, 0))+clockSkew)
	if err != nil {
		h.fail(w, r, "recording state use", err)
		return
	}
	if !first {
		h.reject(w, r, "state already used")
		return
	}
	if e := q.Get("error"); e != "" {
		h.reject(w, r, "IdP returned an error", "idp_error", truncate(e, 64))
		return
	}
	codes := q["code"]
	if len(codes) != 1 || codes[0] == "" {
		h.reject(w, r, "missing or repeated code")
		return
	}

	ctx := oidc.ClientContext(r.Context(), h.provider.HTTPClient)
	tok, err := h.oauth.Exchange(ctx, codes[0], oauth2.VerifierOption(pa.Verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			// Log the OAuth error code only; the body is IdP-controlled.
			h.reject(w, r, "token exchange refused", "status", re.Response.StatusCode, "oauth_error", truncate(re.ErrorCode, 64))
			return
		}
		h.logger.Error("token exchange failed", "request_id", requestID(w), "err", err)
		h.errorPage(w, r, http.StatusBadGateway)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		h.reject(w, r, "token response has no id_token")
		return
	}
	sess, err := h.verifyIDToken(r, rawID, pa)
	if err != nil {
		h.reject(w, r, "ID token rejected", "reason", err.Error())
		return
	}
	sess.RefreshToken = tok.RefreshToken
	sess.Nonce = pa.Nonce

	// Never adopt a session ID from before login (T2); revoke it instead.
	if old, cerr := r.Cookie(h.cookieName); cerr == nil && old.Value != "" {
		if derr := h.sessions.Delete(r.Context(), old.Value); derr != nil {
			h.fail(w, r, "revoking previous session", derr)
			return
		}
	}
	id, err := h.sessions.Create(r.Context(), *sess)
	if err != nil {
		h.fail(w, r, "creating session", err)
		return
	}
	session.SetCookie(w, h.cookieName, id, h.sessions.AbsoluteTTL())
	h.logger.Info("login succeeded", "request_id", requestID(w), "session", *sess,
		"session_hash", session.HashID(id)[:12], "state_hash", hashPrefix(state))
	h.continueTo(w, r, id, pa.ReturnTo, pa.Binding)
}

// verifyIDToken completes invariant 3 on top of go-oidc (signature with the
// pinned algorithms, iss, aud, exp): nonce, iat, azp, sub, and claim types.
func (h *Handler) verifyIDToken(r *http.Request, raw string, pa preAuth) (*session.Session, error) {
	idt, err := h.provider.Verifier.Verify(r.Context(), raw)
	if err != nil {
		return nil, err
	}
	if idt.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(pa.Nonce)) != 1 {
		return nil, errors.New("nonce mismatch")
	}
	var c idClaims
	if err = idt.Claims(&c); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	now := h.now()
	started := time.Unix(pa.Expires, 0).Add(-preAuthTTL)
	switch {
	case c.IssuedAt == nil:
		return nil, errors.New("missing iat")
	case time.Unix(*c.IssuedAt, 0).After(now.Add(clockSkew)):
		return nil, errors.New("iat in the future")
	case time.Unix(*c.IssuedAt, 0).Before(started.Add(-clockSkew)):
		return nil, errors.New("iat before this login started")
	}
	// A step-up asked the IdP to authenticate again (prompt=login, max_age=0).
	// Only a login made after the step-up started proves it did; an older
	// auth_time means it reused its session, and accepting that would also
	// send the browser straight back into another step-up.
	if pa.StepUp && (c.AuthTime == nil || time.Unix(*c.AuthTime, 0).Before(started.Add(-clockSkew))) {
		return nil, errors.New("step-up: user not re-authenticated (auth_time missing or before the step-up)")
	}
	clientID := h.oauth.ClientID
	if (len(idt.Audience) > 1 && c.AZP != clientID) || (c.AZP != "" && c.AZP != clientID) {
		return nil, errors.New("azp does not match client")
	}
	if c.Subject == "" {
		return nil, errors.New("missing sub")
	}
	groups, err := h.groups(idt)
	if err != nil {
		return nil, err
	}

	sess := &session.Session{
		Subject:  c.Subject,
		Username: c.PreferredUsername,
		Groups:   groups,
		AMR:      c.AMR,
	}
	if sess.Username == "" {
		sess.Username = c.Subject
	}
	// Only a verified email may feed email_domains rules.
	if verified, ok := c.EmailVerified.(bool); ok && verified {
		sess.Email = c.Email
	}
	if c.AuthTime != nil {
		sess.AuthTime = time.Unix(*c.AuthTime, 0).UTC()
	}
	return sess, nil
}

// groups reads the configured groups claim. Absent means no groups; any
// shape other than a list of strings is rejected rather than guessed at.
func (h *Handler) groups(idt *oidc.IDToken) ([]string, error) {
	var all map[string]json.RawMessage
	if err := idt.Claims(&all); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	raw, ok := all[h.groupsClaim]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var groups []string
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, fmt.Errorf("claim %q is not a list of strings", h.groupsClaim)
	}
	if slices.Contains(groups, "") {
		return nil, fmt.Errorf("claim %q has an empty group", h.groupsClaim)
	}
	return groups, nil
}

func clearPreAuth(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

// reject denies a login the client can influence: 400, reason in the log.
func (h *Handler) reject(w http.ResponseWriter, r *http.Request, reason string, attrs ...any) {
	h.logger.Warn("login rejected", append([]any{"request_id", requestID(w), "reason", reason}, attrs...)...)
	h.errorPage(w, r, http.StatusBadRequest)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
