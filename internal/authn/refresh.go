package authn

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/hersinabil5/warden/internal/session"
)

// refreshLockTTL bounds one group refresh. It is longer than the IdP client
// timeout, so a lock only outlives its holder if Warden crashed.
const refreshLockTTL = 30 * time.Second

// errRevoked means the session ended during a refresh check: treat the
// request as unauthenticated.
var errRevoked = errors.New("authn: session revoked")

// fresh returns sess with groups confirmed by the IdP within the refresh
// interval (docs/DECISIONS.md D23). When a refresh is due it redeems the
// refresh token; if that fails for any reason, the session is revoked and
// fresh returns errRevoked. Other errors are store failures.
func (h *Handler) fresh(ctx context.Context, sess *session.Session, reqID string) (*session.Session, error) {
	if h.now().Sub(sess.Refreshed) < h.refreshInterval {
		return sess, nil
	}
	lock := "refresh:" + sess.Hash
	got, err := h.sessions.TryLock(ctx, lock, refreshLockTTL)
	if err != nil {
		return nil, err
	}
	if !got {
		// Another request is refreshing this session right now; this one
		// proceeds on groups at most one refresh old.
		return sess, nil
	}
	defer h.sessions.Unlock(context.WithoutCancel(ctx), lock)

	// Re-read under the lock: a request that finished refreshing meanwhile
	// rotated the refresh token, and spending the old one would fail.
	current, err := h.sessions.GetByHash(ctx, sess.Hash)
	if errors.Is(err, session.ErrNotFound) {
		return nil, errRevoked
	}
	if err != nil {
		return nil, err
	}
	if h.now().Sub(current.Refreshed) < h.refreshInterval {
		return current, nil
	}
	updated, why := h.refresh(ctx, current)
	if why != nil {
		h.logger.Warn("group refresh failed; session revoked", "request_id", reqID,
			"session_hash", current.Hash[:12], "user", current.Username, "reason", why.Error())
		if derr := h.sessions.DeleteHash(ctx, current.Hash); derr != nil && !errors.Is(derr, session.ErrNotFound) {
			return nil, derr
		}
		return nil, errRevoked
	}
	err = h.sessions.Update(ctx, *updated)
	if errors.Is(err, session.ErrNotFound) {
		return nil, errRevoked // revoked while we were at the IdP
	}
	if err != nil {
		return nil, err
	}
	h.logger.Info("groups refreshed", "request_id", reqID, "session_hash", current.Hash[:12],
		"user", updated.Username, "groups", updated.Groups)
	return updated, nil
}

// refresh redeems sess's refresh token and validates the new ID token as
// strictly as a login's (invariant 3), with the refresh-specific rules of
// OIDC Core 12.2: same sub, and the login's nonce if one is present.
func (h *Handler) refresh(ctx context.Context, sess *session.Session) (*session.Session, error) {
	if sess.RefreshToken == "" {
		return nil, errors.New("no refresh token")
	}
	ctx = oidc.ClientContext(ctx, h.provider.HTTPClient)
	tok, err := h.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: sess.RefreshToken}).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			// The OAuth error code only; the body is IdP-controlled.
			return nil, fmt.Errorf("refresh refused: %d %s", re.Response.StatusCode, truncate(re.ErrorCode, 64))
		}
		return nil, errors.New("refresh request failed")
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("refresh response has no id_token")
	}
	idt, err := h.provider.Verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("refreshed ID token rejected: %w", err)
	}
	var c idClaims
	if err = idt.Claims(&c); err != nil {
		return nil, fmt.Errorf("decoding claims: %w", err)
	}
	switch {
	case c.Subject != sess.Subject:
		return nil, errors.New("refreshed ID token is for another subject")
	case idt.Nonce != "" && subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(sess.Nonce)) != 1:
		return nil, errors.New("refreshed ID token nonce mismatch")
	case c.IssuedAt == nil:
		return nil, errors.New("missing iat")
	case time.Unix(*c.IssuedAt, 0).After(h.now().Add(clockSkew)):
		return nil, errors.New("iat in the future")
	}
	clientID := h.oauth.ClientID
	if (len(idt.Audience) > 1 && c.AZP != clientID) || (c.AZP != "" && c.AZP != clientID) {
		return nil, errors.New("azp does not match client")
	}
	groups, err := h.groups(idt)
	if err != nil {
		return nil, err
	}

	out := *sess
	out.Groups = groups
	out.Email = ""
	if verified, ok := c.EmailVerified.(bool); ok && verified {
		out.Email = c.Email
	}
	if c.PreferredUsername != "" {
		out.Username = c.PreferredUsername
	}
	if c.AMR != nil {
		out.AMR = c.AMR
	}
	if c.AuthTime != nil {
		out.AuthTime = time.Unix(*c.AuthTime, 0).UTC()
	}
	if tok.RefreshToken != "" {
		out.RefreshToken = tok.RefreshToken
	}
	out.Refreshed = h.now()
	return &out, nil
}
