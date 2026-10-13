package authn

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// maxReturnURLLen bounds the return URL carried through login.
const maxReturnURLLen = 2048

var errBadReturnURL = errors.New("return URL is not an allowed destination")

// returnURLs validates post-login destinations (invariant 5): absolute https
// URLs on a configured route host and Warden's public port, nothing else.
type returnURLs struct {
	hosts map[string]bool
	port  string // public HTTPS port; "443" means it is omitted from URLs
}

func newReturnURLs(routeHosts []string, port string) *returnURLs {
	hosts := make(map[string]bool, len(routeHosts))
	for _, h := range routeHosts {
		hosts[h] = true
	}
	return &returnURLs{hosts: hosts, port: port}
}

// validate returns a canonical copy of raw, rebuilt from its parsed parts so
// that what is redirected to is exactly what was checked.
func (v *returnURLs) validate(raw string) (string, error) {
	if raw == "" || len(raw) > maxReturnURLLen {
		return "", errBadReturnURL
	}
	// Browsers treat '\' as '/' and strip tabs and newlines, so a raw
	// string the server parses one way can navigate another. Reject them.
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return "", errBadReturnURL
		}
	}
	// Require the literal "https://" form: rules out https:evil.com,
	// https:/evil.com, protocol-relative //evil.com, and other schemes.
	if len(raw) < len("https://") || !strings.EqualFold(raw[:len("https://")], "https://") {
		return "", errBadReturnURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Host == "" {
		return "", errBadReturnURL
	}
	host, port := u.Host, ""
	if h, p, splitErr := net.SplitHostPort(u.Host); splitErr == nil {
		if p == "" {
			return "", errBadReturnURL // "host:" with an empty port
		}
		host, port = h, p
	} else if strings.Contains(u.Host, ":") {
		return "", errBadReturnURL
	}
	host = strings.ToLower(host)
	if !v.hosts[host] {
		return "", errBadReturnURL
	}
	if port != "" && port != v.port {
		return "", errBadReturnURL
	}
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		return "", errBadReturnURL
	}

	out := url.URL{Scheme: "https", Host: host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	if v.port != "443" {
		out.Host = net.JoinHostPort(host, v.port)
	}
	if out.Path == "" {
		out.Path = "/"
	}
	return out.String(), nil
}
