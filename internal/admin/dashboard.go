package admin

import (
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// DashboardPrefix is where the admin dashboard lives on the auth host.
const DashboardPrefix = "/.warden/admin/"

const dashboardRoot = "/.warden/admin"

// DashboardCSP allows only same-origin script, style, and API calls, and no
// framing (docs/DECISIONS.md D24). Nothing inline is allowed.
const DashboardCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// IsDashboard reports whether the (normalized) path is a dashboard page or
// asset.
func IsDashboard(p string) bool { return p == dashboardRoot || strings.HasPrefix(p, DashboardPrefix) }

// Owns reports whether the (normalized) path is served by the admin handler.
func Owns(p string) bool { return strings.HasPrefix(p, APIPrefix) || IsDashboard(p) }

// serveDashboard serves the embedded build: regular, non-hidden files only,
// never a directory listing or anything outside the build.
func (h *Handler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Content-Security-Policy", DashboardCSP)
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Cross-Origin-Opener-Policy", "same-origin")
	hdr.Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hdr.Set("Allow", "GET, HEAD")
		textError(w, http.StatusMethodNotAllowed)
		return
	}
	if h.dashboard == nil {
		textError(w, http.StatusNotFound)
		return
	}
	if r.URL.Path == dashboardRoot {
		http.Redirect(w, r, DashboardPrefix, http.StatusMovedPermanently)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, DashboardPrefix)
	if name == "" {
		name = "index.html"
	}
	data, err := readFile(h.dashboard, name)
	if err != nil {
		if name == "index.html" && errors.Is(err, fs.ErrNotExist) {
			hdr.Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("The admin dashboard is not built into this binary. Run `make build`.\n"))
			return
		}
		textError(w, http.StatusNotFound)
		return
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	hdr.Set("Content-Type", ctype)
	if strings.HasPrefix(name, "assets/") {
		// Vite puts a content hash in every asset name.
		hdr.Set("Cache-Control", "private, max-age=31536000, immutable")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data) //nolint:gosec // G705: bytes come from the embedded build; the request only selects which file
	}
}

// readFile returns a regular file from fsys. Invalid names (.., empty or
// dot segments, backslashes) and hidden files are ErrNotExist-like errors.
func readFile(fsys fs.FS, name string) ([]byte, error) {
	if !fs.ValidPath(name) || strings.Contains(name, `\`) {
		return nil, fs.ErrInvalid
	}
	for _, seg := range strings.Split(name, "/") {
		if strings.HasPrefix(seg, ".") {
			return nil, fs.ErrInvalid
		}
	}
	fi, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	return fs.ReadFile(fsys, name)
}

func textError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(http.StatusText(code) + "\n"))
}
