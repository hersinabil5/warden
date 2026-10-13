package authn

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/hersinabil5/warden/internal/session"
)

var sessionTemplate = template.Must(template.New("session").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Warden</title></head>
<body>
{{if .User}}<h1>Signed in as {{.User}}</h1>
<p>Email: {{if .Email}}{{.Email}}{{else}}(none verified){{end}}</p>
<p>Groups: {{if .Groups}}{{.Groups}}{{else}}(none){{end}}</p>
{{else}}<h1>Not signed in</h1>
<p><a href="{{.LoginPath}}">Sign in</a></p>
{{end}}</body>
</html>
`))

// sessionPage shows who is signed in on the auth host. It is the landing
// page after a login with no return URL.
func (h *Handler) sessionPage(w http.ResponseWriter, r *http.Request) {
	data := struct {
		User, Email, Groups, LoginPath string
	}{LoginPath: LoginPath}
	if c, err := r.Cookie(h.cookieName); err == nil {
		sess, gerr := h.sessions.Get(r.Context(), c.Value)
		switch {
		case gerr == nil:
			data.User, data.Email, data.Groups = sess.Username, sess.Email, strings.Join(sess.Groups, ", ")
		case !errors.Is(gerr, session.ErrNotFound):
			h.fail(w, r, "loading session", gerr)
			return
		}
	}
	writeHTML(w, http.StatusOK, sessionTemplate, data)
}

// writeHTML renders a Warden page with the same hardening as error pages.
func writeHTML(w http.ResponseWriter, code int, t *template.Template, data any) {
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	w.WriteHeader(code)
	_ = t.Execute(w, data)
}
