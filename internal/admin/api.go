package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

// APIPrefix is where the admin JSON API lives on the auth host.
const APIPrefix = "/.warden/api/"

// CSRFHeader carries the session's CSRF token on mutating requests.
const CSRFHeader = "X-CSRF-Token"

// maxBody bounds a mutating request's JSON body.
const maxBody = 4 << 10

// Sessions is what the API needs from the session store.
type Sessions interface {
	List(ctx context.Context, offset, limit int) ([]session.Session, int, error)
	ListUser(ctx context.Context, sub string) ([]session.Session, error)
	DeleteHash(ctx context.Context, hash string) error
	RevokeUser(ctx context.Context, sub string) (int, error)
}

// Options configures the admin handler.
type Options struct {
	Sessions  Sessions
	Decisions *audit.Recent
	// AuthOrigin is the auth host's public origin; mutating requests must
	// come from it.
	AuthOrigin string
	// Dashboard is the built dashboard (adminui.Files); nil serves none.
	Dashboard fs.FS
	Logger    *slog.Logger
}

// Handler serves the admin API. It must only be reached through the proxy,
// which authenticates the caller and applies the admin policy, then passes
// the session with WithSession (docs/DECISIONS.md D22).
type Handler struct {
	mux       *http.ServeMux
	sessions  Sessions
	recent    *audit.Recent
	origin    string
	dashboard fs.FS
	logger    *slog.Logger
}

// New builds the admin handler.
func New(opts Options) (*Handler, error) {
	if opts.Sessions == nil || opts.Decisions == nil {
		return nil, errors.New("admin: sessions and decisions are required")
	}
	if opts.AuthOrigin == "" {
		return nil, errors.New("admin: auth origin is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	h := &Handler{
		mux:       http.NewServeMux(),
		sessions:  opts.Sessions,
		recent:    opts.Decisions,
		origin:    opts.AuthOrigin,
		dashboard: opts.Dashboard,
		logger:    opts.Logger,
	}
	h.mux.HandleFunc("GET "+APIPrefix+"me", h.me)
	h.mux.HandleFunc("GET "+APIPrefix+"sessions", h.listSessions)
	h.mux.HandleFunc("POST "+APIPrefix+"sessions/revoke", h.mutating(h.revokeSession))
	h.mux.HandleFunc("POST "+APIPrefix+"users/revoke", h.mutating(h.revokeUser))
	h.mux.HandleFunc("GET "+APIPrefix+"decisions", h.decisions)
	h.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return h, nil
}

type sessionKey struct{}

// WithSession attaches the authenticated admin's session to ctx.
func WithSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func sessionFrom(ctx context.Context) *session.Session {
	s, _ := ctx.Value(sessionKey{}).(*session.Session)
	return s
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	if sessionFrom(r.Context()) == nil {
		// Reached without the proxy's checks: serve nothing.
		h.logger.Error("admin request without a session", "request_id", requestID(w))
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if IsDashboard(r.URL.Path) {
		h.serveDashboard(w, r)
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       s.Username,
		"sub":        s.Subject,
		"email":      s.Email,
		"groups":     nonNil(s.Groups),
		"amr":        nonNil(s.AMR),
		"auth_time":  s.AuthTime,
		"session":    audit.SessionPrefix(s.Hash),
		"csrf_token": s.CSRFToken,
	})
}

// sessionView is a session as the API shows it: no refresh or CSRF token.
// ID is the full storage hash, which revocation takes (D21).
type sessionView struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Subject  string    `json:"sub"`
	Email    string    `json:"email"`
	Groups   []string  `json:"groups"`
	AMR      []string  `json:"amr"`
	AuthTime time.Time `json:"auth_time"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Current  bool      `json:"current"`
}

func views(ss []session.Session, current string) []sessionView {
	out := make([]sessionView, 0, len(ss))
	for _, s := range ss {
		out = append(out, sessionView{
			ID: s.Hash, User: s.Username, Subject: s.Subject, Email: s.Email,
			Groups: nonNil(s.Groups), AMR: nonNil(s.AMR), AuthTime: s.AuthTime,
			Created: s.Created, LastSeen: s.LastSeen, Current: s.Hash == current,
		})
	}
	return out
}

func (h *Handler) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	current := sessionFrom(r.Context()).Hash
	if sub := q.Get("sub"); sub != "" {
		ss, err := h.sessions.ListUser(r.Context(), sub)
		if err != nil {
			h.fail(w, "listing user sessions", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": views(ss, current), "total": len(ss)})
		return
	}
	offset, ok1 := intParam(q.Get("offset"), 0)
	limit, ok2 := intParam(q.Get("limit"), session.DefaultListLimit)
	if !ok1 || !ok2 {
		writeError(w, http.StatusBadRequest, "bad offset or limit")
		return
	}
	ss, total, err := h.sessions.List(r.Context(), offset, limit)
	if err != nil {
		h.fail(w, "listing sessions", err)
		return
	}
	resp := map[string]any{"sessions": views(ss, current), "total": total}
	if next := offset + min(limit, session.MaxListLimit); next < total && len(ss) > 0 {
		resp["next_offset"] = next
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) revokeSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	err := h.sessions.DeleteHash(r.Context(), req.ID)
	if errors.Is(err, session.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no such session")
		return
	}
	if err != nil {
		h.fail(w, "revoking session", err)
		return
	}
	h.logger.Info("admin revoked session", "request_id", requestID(w),
		"admin", sessionFrom(r.Context()).Username, "target_session", audit.SessionPrefix(req.ID))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revokeUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subject string `json:"sub"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Subject == "" {
		writeError(w, http.StatusBadRequest, "sub is required")
		return
	}
	n, err := h.sessions.RevokeUser(r.Context(), req.Subject)
	if err != nil {
		h.fail(w, "revoking user sessions", err)
		return
	}
	h.logger.Info("admin revoked user sessions", "request_id", requestID(w),
		"admin", sessionFrom(r.Context()).Username, "target_sub", req.Subject, "count", n)
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

func (h *Handler) decisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := audit.Query{User: q.Get("user"), Host: q.Get("host")}
	switch d := q.Get("decision"); d {
	case "", string(audit.Allow), string(audit.Deny):
		query.Decision = audit.Decision(d)
	default:
		writeError(w, http.StatusBadRequest, "decision must be allow or deny")
		return
	}
	limit, ok := intParam(q.Get("limit"), audit.DefaultQueryLimit)
	if !ok {
		writeError(w, http.StatusBadRequest, "bad limit")
		return
	}
	query.Limit = limit
	if b := q.Get("before"); b != "" {
		before, err := strconv.ParseUint(b, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad before")
			return
		}
		query.Before = before
	}
	entries, next := h.recent.Query(query)
	resp := map[string]any{"decisions": nonNil(entries)}
	if next != 0 {
		resp["next_before"] = next
	}
	writeJSON(w, http.StatusOK, resp)
}

// mutating guards a state-changing endpoint against CSRF: the request must
// come from the auth origin, carry a JSON body, and present this session's
// CSRF token (D22). Each check alone defeats a plain cross-site form.
func (h *Handler) mutating(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.sameOrigin(r) {
			h.logger.Warn("admin mutation refused: cross-origin", "request_id", requestID(w))
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
			return
		}
		want := sessionFrom(r.Context()).CSRFToken
		got := r.Header.Get(CSRFHeader)
		if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			h.logger.Warn("admin mutation refused: bad CSRF token", "request_id", requestID(w))
			writeError(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}

// sameOrigin requires a browser request to be same-origin. Requests without
// Sec-Fetch-Site and Origin (non-browser clients) still need the CSRF token.
func (h *Handler) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != h.origin {
		return false
	}
	return true
}

// readJSON decodes exactly one JSON object with known fields into v.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body")
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "bad request body")
		return false
	}
	return true
}

func (h *Handler) fail(w http.ResponseWriter, what string, err error) {
	h.logger.Error("admin API failed", "request_id", requestID(w), "step", what, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func intParam(s string, def int) (int, bool) {
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a generic JSON error with the request ID; causes go to
// the log only.
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg, "request_id": requestID(w)})
}

// WriteError is writeError for the proxy's authentication and policy
// failures on admin paths.
func WriteError(w http.ResponseWriter, code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	writeError(w, code, fmt.Sprintf("%d %s", code, http.StatusText(code)))
}

func requestID(w http.ResponseWriter) string { return w.Header().Get("X-Request-ID") }
