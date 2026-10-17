package demo

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Account is a public demo login. OTPKey is the decoded TOTP key, nil for an
// account without OTP.
type Account struct {
	Username, Password, Description string
	OTPKey                          []byte
}

// Link is something to try, with a note on who may open it.
type Link struct {
	Label, URL, Note string
}

// PageOptions configures the landing page.
type PageOptions struct {
	Accounts []Account
	Links    []Link
	// NextReset is when demo state is next wiped; nil shows no countdown.
	NextReset func() time.Time
	Now       func() time.Time
}

// style is the page's only CSS, allowed by its hash: no inline styles or
// scripts anywhere else.
const style = `
body{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}
h1{font-size:1.6rem;margin-bottom:.2rem}
p.lede{margin-top:0;color:#57606a}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #d0d7de;vertical-align:top}
code{font:1.05em ui-monospace,monospace}
.otp{font:700 1.4rem ui-monospace,monospace;letter-spacing:.12em}
.muted{color:#57606a;font-size:.9em}
li{margin:.3rem 0}
@media (prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}th,td{border-color:#30363d}p.lede,.muted{color:#8d96a0}a{color:#58a6ff}}
`

var pageTemplate = template.Must(template.New("demo").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="{{.Refresh}}">
<title>Warden demo</title>
<style>` + style + `</style>
</head>
<body>
<h1>Warden demo</h1>
<p class="lede">An identity-aware proxy: every request to the apps below is authenticated with
OpenID Connect, checked against a per-path policy, audited, and forwarded with a signed identity.
Nothing behind it is reachable any other way.</p>

<h2>Demo accounts</h2>
<table>
<tr><th>Username</th><th>Password</th><th>OTP code</th><th>Who</th></tr>
{{range .Accounts}}<tr><td><code>{{.Username}}</code></td><td><code>{{.Password}}</code></td>
<td>{{if .Code}}<span class="otp">{{.Code}}</span>{{else}}<span class="muted">none</span>{{end}}</td>
<td>{{.Description}}</td></tr>
{{end}}</table>
<p class="muted">Codes change every 30 seconds ({{.Left}} s left); this page reloads itself.</p>

<h2>Try it</h2>
<table>
{{range .Links}}<tr><td><a href="{{.URL}}">{{.Label}}</a></td><td>{{.Note}}</td></tr>
{{end}}</table>
<ol>
<li>Open an app and sign in. A request no rule allows gets a 403 with a request ID, never the app.</li>
<li>Paths marked MFA want a recent second factor: with an older login you are sent back to enter
your code again, then land where you were going.</li>
<li>As an admin, open the dashboard: your sessions and every allow and deny. Sign in as another
account in a private window, then revoke it from the dashboard: its next request goes to login.</li>
</ol>
<p class="muted">You only ever see your own activity.{{if .Reset}} Everything resets in {{.Reset}}.{{end}}</p>
</body>
</html>
`))

// csp allows nothing but the page's own style.
var csp = func() string {
	sum := sha256.Sum256([]byte(style))
	return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) +
		"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

type page struct{ opts PageOptions }

// NewPage returns the demo landing page handler.
func NewPage(opts PageOptions) (http.Handler, error) {
	if len(opts.Accounts) == 0 {
		return nil, errors.New("demo: no accounts")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &page{opts}, nil
}

func (p *page) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	now := p.opts.Now()
	left := int(math.Ceil(Remaining(now).Seconds()))
	type row struct{ Username, Password, Description, Code string }
	data := struct {
		Accounts      []row
		Links         []Link
		Refresh, Left int
		Reset         string
	}{Links: p.opts.Links, Refresh: max(left, 1), Left: left}
	for _, a := range p.opts.Accounts {
		rw := row{Username: a.Username, Password: a.Password, Description: a.Description}
		if a.OTPKey != nil {
			rw.Code = Code(a.OTPKey, now)
		}
		data.Accounts = append(data.Accounts, rw)
	}
	if p.opts.NextReset != nil {
		data.Reset = untilText(p.opts.NextReset().Sub(now))
	}
	var buf bytes.Buffer
	if err := pageTemplate.Execute(&buf, data); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "text/html; charset=utf-8")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Security-Policy", csp)
	hdr.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = buf.WriteTo(w)
	}
}

func untilText(d time.Duration) string {
	switch m := int(d / time.Minute); {
	case m < 1:
		return "less than a minute"
	case m == 1:
		return "1 minute"
	default:
		return strconv.Itoa(m) + " minutes"
	}
}
