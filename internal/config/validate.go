package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// maxIdentityTTL caps the signed identity assertion lifetime (PLAN.md M4).
const maxIdentityTTL = 60 * time.Second

// idTokenAlgs is the allowlist for auth.id_token_algs: asymmetric JWS
// algorithms only. "none" and HMAC (HS*) are absent on purpose (invariant 3):
// HMAC with a public key as the secret is the classic alg-confusion forgery.
var idTokenAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// problems collects validation errors so one run reports all of them.
type problems []error

func (p *problems) addf(field, format string, args ...any) {
	*p = append(*p, fmt.Errorf("%s: %s", field, fmt.Sprintf(format, args...)))
}

// validate checks every field and normalizes in place (lowercased hosts,
// canonical header names, parsed upstream URLs, the resolved client secret).
func (c *Config) validate(getenv func(string) string) error {
	var p problems

	c.validateListeners(&p)
	if c.TLS.CertFile == "" {
		p.addf("tls.cert_file", "is required")
	}
	if c.TLS.KeyFile == "" {
		p.addf("tls.key_file", "is required")
	}
	c.validateHSTS(&p)
	c.validateAuth(&p, getenv)
	c.validateSession(&p)
	c.validateIdentity(&p)
	for i, h := range c.StripHeaders {
		if !isToken(h) {
			p.addf(fmt.Sprintf("strip_headers[%d]", i), "%q is not a valid header name", h)
			continue
		}
		c.StripHeaders[i] = http.CanonicalHeaderKey(h)
	}
	c.validateAudit(&p)
	c.validateAdmin(&p)
	c.validateRoutes(&p)

	if len(p) > 0 {
		return fmt.Errorf("invalid config:\n%w", errors.Join(p...))
	}
	return nil
}

func (c *Config) validateListeners(p *problems) {
	mainHost, mainPort, err := parseHostPort(c.Listen)
	if err != nil {
		p.addf("listen", "%v", err)
	}
	if c.HTTPRedirectListen == "" {
		return
	}
	redirHost, redirPort, err := parseHostPort(c.HTTPRedirectListen)
	if err != nil {
		p.addf("http_redirect_listen", "%v", err)
		return
	}
	if mainPort == redirPort && (mainHost == redirHost || isWildcardHost(mainHost) || isWildcardHost(redirHost)) {
		p.addf("http_redirect_listen", "overlaps listen %q", c.Listen)
	}
}

func (c *Config) validateHSTS(p *problems) {
	switch d := c.TLS.HSTSMaxAge; {
	case d == nil:
		v := DefaultHSTSMaxAge
		c.TLS.HSTSMaxAge = &v
	case *d < 0:
		p.addf("tls.hsts_max_age", "must not be negative")
	case *d%time.Second != 0:
		p.addf("tls.hsts_max_age", "must be whole seconds")
	}
}

func (c *Config) validateAuth(p *problems, getenv func(string) string) {
	a := &c.Auth

	a.Domain = strings.ToLower(a.Domain)
	if err := validHostname(a.Domain); err != nil {
		p.addf("auth.domain", "%v", err)
	}

	if err := validIssuer(a.Issuer); err != nil {
		p.addf("auth.issuer", "%v", err)
	}
	if a.ClientID == "" {
		p.addf("auth.client_id", "is required")
	}

	switch {
	case a.ClientSecretEnv == "":
		p.addf("auth.client_secret_env", "is required")
	case !envNameRe.MatchString(a.ClientSecretEnv):
		// Don't echo the value: a common mistake is pasting the secret here.
		p.addf("auth.client_secret_env", "must be an environment variable name (letters, digits, underscore); value not shown")
	default:
		v := getenv(a.ClientSecretEnv)
		if v == "" {
			p.addf("auth.client_secret_env", "environment variable %s is not set or empty", a.ClientSecretEnv)
		}
		a.ClientSecret = NewSecret(v)
	}

	for i, s := range a.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			p.addf(fmt.Sprintf("auth.scopes[%d]", i), "%q is not a valid scope", s)
		}
	}
	if !slices.Contains(a.Scopes, "openid") {
		p.addf("auth.scopes", "must include openid")
	}
	if len(a.IDTokenAlgs) == 0 {
		p.addf("auth.id_token_algs", "is required (for example [RS256])")
	}
	for i, alg := range a.IDTokenAlgs {
		field := fmt.Sprintf("auth.id_token_algs[%d]", i)
		switch {
		case !slices.Contains(idTokenAlgs, alg):
			p.addf(field, "%q is not allowed; use one of %s", alg, strings.Join(idTokenAlgs, ", "))
		case slices.Index(a.IDTokenAlgs, alg) < i:
			p.addf(field, "duplicate %q", alg)
		}
	}
	if a.GroupsClaim == "" {
		p.addf("auth.groups_claim", "is required")
	}
	if a.GroupRefreshInterval <= 0 {
		p.addf("auth.group_refresh_interval", "must be positive")
	}
}

func (c *Config) validateSession(p *problems) {
	s := &c.Session
	if h, _, err := parseHostPort(s.RedisAddr); err != nil {
		p.addf("session.redis_addr", "%v", err)
	} else if h == "" {
		p.addf("session.redis_addr", "host is required")
	}
	if s.CookieName == "" {
		p.addf("session.cookie_name", "is required")
	} else if !isToken(s.CookieName) {
		p.addf("session.cookie_name", "%q is not a valid cookie name", s.CookieName)
	}
	if s.AbsoluteTTL <= 0 {
		p.addf("session.absolute_ttl", "must be positive")
	}
	switch {
	case s.IdleTimeout <= 0:
		p.addf("session.idle_timeout", "must be positive")
	case s.AbsoluteTTL > 0 && s.IdleTimeout > s.AbsoluteTTL:
		p.addf("session.idle_timeout", "%v exceeds absolute_ttl %v", s.IdleTimeout, s.AbsoluteTTL)
	}
}

func (c *Config) validateIdentity(p *problems) {
	id := &c.Identity
	if !isToken(id.Header) {
		p.addf("identity.header", "%q is not a valid header name", id.Header)
	} else {
		id.Header = http.CanonicalHeaderKey(id.Header)
	}
	if id.SigningKeyFile == "" {
		p.addf("identity.signing_key_file", "is required")
	}
	for i, f := range id.PreviousKeyFiles {
		field := fmt.Sprintf("identity.previous_key_files[%d]", i)
		switch {
		case f == "":
			p.addf(field, "is empty")
		case f == id.SigningKeyFile:
			p.addf(field, "is the active signing key")
		case slices.Index(id.PreviousKeyFiles, f) < i:
			p.addf(field, "duplicate %q", f)
		}
	}
	if id.TTL <= 0 || id.TTL > maxIdentityTTL {
		p.addf("identity.ttl", "must be in (0, %v], got %v", maxIdentityTTL, id.TTL)
	}
}

func (c *Config) validateAudit(p *problems) {
	switch c.Audit.Sink {
	case AuditSinkFile:
		if c.Audit.File == "" {
			p.addf("audit.file", "is required when sink is %q", AuditSinkFile)
		}
	case AuditSinkStdout:
		if c.Audit.File != "" {
			p.addf("audit.file", "is only valid when sink is %q", AuditSinkFile)
		}
	default:
		p.addf("audit.sink", "must be %q or %q, got %q", AuditSinkFile, AuditSinkStdout, c.Audit.Sink)
	}
}

func (c *Config) validateAdmin(p *problems) {
	if c.Admin == nil {
		return
	}
	validateRules(p, "admin.allow", c.Admin.Allow)
	for i, r := range c.Admin.Allow {
		rf := fmt.Sprintf("admin.allow[%d]", i)
		if r.Users == nil && r.Groups == nil {
			p.addf(rf, "must name users or groups; admin access is never granted to everyone signed in")
		}
		if r.RequireMFAWithin == nil {
			p.addf(rf+".require_mfa_within", "is required for admin access")
		}
	}
}

func (c *Config) validateRoutes(p *problems) {
	if len(c.Routes) == 0 {
		p.addf("routes", "at least one route is required")
		return
	}
	seen := make(map[string]int, len(c.Routes))
	for i := range c.Routes {
		r := &c.Routes[i]
		field := fmt.Sprintf("routes[%d]", i)

		r.Host = strings.ToLower(r.Host)
		if err := validHostname(r.Host); err != nil {
			p.addf(field+".host", "%v", err)
		} else if j, dup := seen[r.Host]; dup {
			p.addf(field+".host", "duplicate host %q (also routes[%d])", r.Host, j)
		} else {
			seen[r.Host] = i
		}

		u, err := parseUpstream(r.Upstream)
		if err != nil {
			p.addf(field+".upstream", "%v", err)
		}
		r.UpstreamURL = u

		if t := r.UpstreamTLS; t != nil {
			if u != nil && u.Scheme != "https" {
				p.addf(field+".upstream_tls", "is only valid with an https upstream")
			}
			if t.CAFile == "" {
				p.addf(field+".upstream_tls.ca_file", "is required")
			}
			if (t.ClientCertFile == "") != (t.ClientKeyFile == "") {
				p.addf(field+".upstream_tls", "client_cert_file and client_key_file must be set together")
			}
		}

		validatePolicy(p, field+".policy", &r.Policy)
	}
	if j, ok := seen[c.Auth.Domain]; ok {
		p.addf("auth.domain", "%q is also routes[%d].host; the auth host must not be a route", c.Auth.Domain, j)
	}
}

func validatePolicy(p *problems, field string, pol *Policy) {
	validateRules(p, field+".allow", pol.Allow)
	seen := make(map[string]bool, len(pol.Paths))
	for i := range pol.Paths {
		pr := &pol.Paths[i]
		pf := fmt.Sprintf("%s.paths[%d]", field, i)
		// /admin and /admin/ cover the same paths, and so do /Admin and
		// /admin when matching ignores case.
		key := pr.Prefix
		if key != "/" {
			key = strings.TrimSuffix(key, "/")
		}
		if pol.CaseInsensitivePaths {
			key = strings.ToLower(key)
		}
		if err := validPathPrefix(pr.Prefix); err != nil {
			p.addf(pf+".prefix", "%v", err)
		} else if seen[key] {
			p.addf(pf+".prefix", "duplicate prefix %q", pr.Prefix)
		}
		seen[key] = true
		validateRules(p, pf+".allow", pr.Allow)
	}
}

func validateRules(p *problems, field string, rules []Rule) {
	if len(rules) == 0 {
		p.addf(field, "at least one rule is required (with none, every request is denied)")
		return
	}
	for i := range rules {
		r := &rules[i]
		rf := fmt.Sprintf("%s[%d]", field, i)
		if r.Authenticated == nil && r.Users == nil && r.Groups == nil &&
			r.EmailDomains == nil && r.RequireMFAWithin == nil {
			p.addf(rf, "empty rule; state at least one condition (use authenticated: true for any signed-in user)")
			continue
		}
		if r.Authenticated != nil && !*r.Authenticated {
			p.addf(rf+".authenticated", "false is not supported; unauthenticated access is never allowed")
		}
		validateNames(p, rf+".users", r.Users)
		validateNames(p, rf+".groups", r.Groups)
		validateNames(p, rf+".email_domains", r.EmailDomains)
		for j, d := range r.EmailDomains {
			r.EmailDomains[j] = strings.ToLower(d)
			if err := validHostname(r.EmailDomains[j]); err != nil {
				p.addf(fmt.Sprintf("%s.email_domains[%d]", rf, j), "%v", err)
			}
		}
		if r.RequireMFAWithin != nil && *r.RequireMFAWithin <= 0 {
			p.addf(rf+".require_mfa_within", "must be positive")
		}
	}
}

// validateNames rejects a present-but-empty list and blank or padded entries.
func validateNames(p *problems, field string, names []string) {
	if names != nil && len(names) == 0 {
		p.addf(field, "is empty; remove the key instead")
	}
	for i, n := range names {
		if n == "" || strings.TrimSpace(n) != n {
			p.addf(fmt.Sprintf("%s[%d]", field, i), "%q is blank or has surrounding whitespace", n)
		}
	}
}

func parseHostPort(addr string) (host string, port int, err error) {
	if addr == "" {
		return "", 0, errors.New("is required")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not host:port", addr)
	}
	port, err = parsePort(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("%q: %w", addr, err)
	}
	return host, port, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || s == "" || s[0] < '0' || s[0] > '9' || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q must be a number in 1-65535", s)
	}
	return n, nil
}

func isWildcardHost(h string) bool {
	ip := net.ParseIP(h)
	return h == "" || (ip != nil && ip.IsUnspecified())
}

// validHostname accepts lowercase ASCII DNS names (no IPs, ports, wildcards,
// or trailing dot), so each host has exactly one spelling.
func validHostname(h string) error {
	switch {
	case h == "":
		return errors.New("is required")
	case len(h) > 253:
		return errors.New("is longer than 253 characters")
	case net.ParseIP(strings.Trim(h, "[]")) != nil:
		return fmt.Errorf("%q must be a DNS name, not an IP address", h)
	case strings.HasSuffix(h, "."):
		return fmt.Errorf("%q must not end with a dot", h)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return fmt.Errorf("%q has an empty or over-long label", h)
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("%q has a label starting or ending with '-'", h)
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return fmt.Errorf("%q may contain only a-z, 0-9, '-' and '.'", h)
			}
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return fmt.Errorf("%q must not end in a numeric label", h)
	}
	return nil
}

func validIssuer(raw string) error {
	if raw == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("%q must be an https URL", raw)
	case u.Opaque != "" || u.Host == "":
		return fmt.Errorf("%q must be an absolute URL with a host", raw)
	case u.User != nil:
		return errors.New("must not contain credentials")
	case strings.ContainsAny(raw, "?#"):
		return fmt.Errorf("%q must not have a query or fragment", raw)
	case u.Scheme == "http" && !isLocalHost(u.Hostname()):
		return fmt.Errorf("%q must use https (plain http is allowed only for localhost names)", raw)
	}
	return nil
}

// isLocalHost reports whether host can only ever name this machine or a
// local network peer: localhost, a *.localhost name (RFC 6761 reserves them;
// the container stack uses keycloak.localhost, D25), or a loopback IP. Plain
// http is tolerated only for these.
func isLocalHost(host string) bool {
	h := strings.ToLower(host)
	if h == "localhost" || (strings.HasSuffix(h, ".localhost") && len(h) > len(".localhost")) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseUpstream accepts only scheme://host[:port], with an optional bare "/".
// A path prefix is rejected so the upstream receives exactly the normalized
// path that policy evaluated (invariant 6).
func parseUpstream(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", err)
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("%q must use http or https", raw)
	case u.Opaque != "" || u.Hostname() == "":
		return nil, fmt.Errorf("%q must be an absolute URL with a host", raw)
	case u.User != nil:
		return nil, errors.New("must not contain credentials")
	case u.Path != "" && u.Path != "/":
		return nil, fmt.Errorf("%q must not have a path", raw)
	case strings.ContainsAny(raw, "?#"):
		return nil, fmt.Errorf("%q must not have a query or fragment", raw)
	}
	if port := u.Port(); port != "" {
		if _, err := parsePort(port); err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// validPathPrefix requires a prefix already in normalized form. Requests are
// matched on normalized paths, so a prefix like /x/../admin or /%61dmin would
// silently never match and leave the real path unprotected.
func validPathPrefix(prefix string) error {
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("%q must start with /", prefix)
	}
	if !utf8.ValidString(prefix) {
		return errors.New("must be valid UTF-8")
	}
	for _, r := range prefix {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`%\?#;`, r) {
			return fmt.Errorf("%q must be a decoded path (no %%, \\, ?, #, ;, or control characters)", prefix)
		}
	}
	segs := strings.Split(prefix[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || (s == "" && i < len(segs)-1) {
			return fmt.Errorf("%q must be normalized (no //, ., or .. segments)", prefix)
		}
	}
	return nil
}

// isToken reports whether h is a non-empty RFC 9110 token, the grammar for
// both header names and cookie names (RFC 6265).
func isToken(h string) bool {
	if h == "" {
		return false
	}
	for i := 0; i < len(h); i++ {
		ch := h[i]
		isAlnum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isAlnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(ch)) {
			return false
		}
	}
	return true
}
