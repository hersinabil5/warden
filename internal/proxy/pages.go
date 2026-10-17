package proxy

import (
	"html/template"
	"net/http"
)

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{.Code}} {{.Title}}</title></head>
<body>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p>Request ID: <code>{{.RequestID}}</code></p>
</body>
</html>
`))

var pageMessages = map[int]string{
	http.StatusBadRequest:          "The request could not be understood.",
	http.StatusUnauthorized:        "Sign in to continue, then try again.",
	http.StatusForbidden:           "You do not have access to this page.",
	http.StatusNotFound:            "There is nothing here.",
	http.StatusMethodNotAllowed:    "That method is not allowed here.",
	http.StatusMisdirectedRequest:  "This connection cannot serve that host.",
	http.StatusTooManyRequests:     "Too many requests. Wait a moment and try again.",
	http.StatusBadGateway:          "The application is unavailable. Try again shortly.",
	http.StatusInternalServerError: "Something went wrong.",
}

// writePage renders Warden's generic error page. It never includes internal
// error details; the request ID lets an operator find them in the logs.
func writePage(w http.ResponseWriter, code int, requestID string) {
	msg, ok := pageMessages[code]
	if !ok {
		msg = pageMessages[http.StatusInternalServerError]
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	setPageHeaders(h)
	w.WriteHeader(code)
	_ = pageTemplate.Execute(w, struct {
		Code                      int
		Title, Message, RequestID string
	}{code, http.StatusText(code), msg, requestID})
}

// ErrorPage writes the generic error page for r, with the request ID the
// proxy assigned. Handlers mounted by the proxy (Options.Auth) use it.
func ErrorPage(w http.ResponseWriter, r *http.Request, code int) {
	writePage(w, code, RequestID(r.Context()))
}
