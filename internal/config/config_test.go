package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const testSecret = "test-client-secret-value"

// baseYAML is a small but complete valid config. Negative tests apply one
// textual edit to it, so each case isolates exactly one problem.
const baseYAML = `listen: ":8443"
http_redirect_listen: ":8080"
tls:
  cert_file: cert.pem
  key_file: key.pem
auth:
  domain: auth.example.test
  issuer: https://idp.example.test/realms/warden
  client_id: warden-proxy
  client_secret_env: TEST_CLIENT_SECRET
  scopes: [openid, email]
  id_token_algs: [RS256]
  groups_claim: groups
  group_refresh_interval: 5m
session:
  redis_addr: localhost:6379
  cookie_name: _warden
  absolute_ttl: 8h
  idle_timeout: 1h
identity:
  header: X-Warden-Identity
  signing_key_file: signing.pem
  ttl: 60s
strip_headers: [X-Remote-User]
audit:
  sink: file
  file: audit.jsonl
admin:
  allow:
    - groups: [admins]
      require_mfa_within: 12h
routes:
  - host: app.example.test
    upstream: http://127.0.0.1:9001
    policy:
      allow:
        - authenticated: true
      paths:
        - prefix: /admin
          allow:
            - groups: [admins]
  - host: other.example.test
    upstream: https://127.0.0.1:9003
    upstream_tls:
      ca_file: ca.pem
    policy:
      allow:
        - groups: [dev]
`

func testGetenv(name string) string {
	if name == "TEST_CLIENT_SECRET" {
		return testSecret
	}
	return ""
}

// edit replaces old with new in baseYAML, failing if old is absent so a typo
// can never turn a negative test into a vacuous pass.
func edit(t *testing.T, old, new string) string {
	t.Helper()
	if strings.Count(baseYAML, old) != 1 {
		t.Fatalf("edit target %q must appear exactly once in baseYAML", old)
	}
	return strings.Replace(baseYAML, old, new, 1)
}

func TestParseValidBase(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML), testGetenv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Auth.ClientSecret.Reveal(); got != testSecret {
		t.Errorf("client secret = %q, want %q", got, testSecret)
	}
	if len(cfg.Routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(cfg.Routes))
	}
	r := cfg.Routes[1]
	if r.UpstreamURL == nil || r.UpstreamURL.String() != "https://127.0.0.1:9003" {
		t.Errorf("upstream URL = %v, want https://127.0.0.1:9003", r.UpstreamURL)
	}
	if cfg.Session.AbsoluteTTL != 8*time.Hour || cfg.Identity.TTL != 60*time.Second {
		t.Errorf("durations not parsed: absolute_ttl=%v identity.ttl=%v", cfg.Session.AbsoluteTTL, cfg.Identity.TTL)
	}
	if got := cfg.Routes[0].Policy.Paths[0].Allow[0].Groups; len(got) != 1 || got[0] != "admins" {
		t.Errorf("path rule groups = %v, want [admins]", got)
	}
}

func TestParseAdmin(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML), testGetenv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin == nil || len(cfg.Admin.Allow) != 1 || *cfg.Admin.Allow[0].RequireMFAWithin != 12*time.Hour {
		t.Errorf("admin = %+v", cfg.Admin)
	}
	// Optional: without it the admin API is off.
	cfg, err = Parse([]byte(edit(t, "admin:\n  allow:\n    - groups: [admins]\n      require_mfa_within: 12h\n", "")), testGetenv)
	if err != nil || cfg.Admin != nil {
		t.Errorf("no admin section: %+v, %v", cfg, err)
	}
}

func TestParseNormalizes(t *testing.T) {
	in := edit(t, "  - host: app.example.test", "  - host: App.Example.TEST")
	in = strings.Replace(in, "upstream: http://127.0.0.1:9001", "upstream: http://127.0.0.1:9001/", 1)
	in = strings.Replace(in, "strip_headers: [X-Remote-User]", "strip_headers: [x-remote-user]", 1)
	in = strings.Replace(in, "  domain: auth.example.test", "  domain: AUTH.example.test", 1)
	cfg, err := Parse([]byte(in), testGetenv)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := cfg.Routes[0].Host; got != "app.example.test" {
		t.Errorf("host = %q, want lowercase", got)
	}
	if got := cfg.Auth.Domain; got != "auth.example.test" {
		t.Errorf("auth.domain = %q, want lowercase", got)
	}
	if got := cfg.Routes[0].UpstreamURL.String(); got != "http://127.0.0.1:9001" {
		t.Errorf("upstream = %q, want trailing slash dropped", got)
	}
	if got := cfg.StripHeaders[0]; got != "X-Remote-User" {
		t.Errorf("strip header = %q, want canonical form", got)
	}
}

func TestParseAllowsLocalHTTPIssuer(t *testing.T) {
	for _, issuer := range []string{
		"http://localhost:8180/realms/warden",
		"http://127.0.0.1:8180/realms/warden",
		"http://[::1]:8180/realms/warden",
		"http://keycloak.localhost:8180/realms/warden", // the container setup (D25)
	} {
		in := edit(t, "issuer: https://idp.example.test/realms/warden", "issuer: "+issuer)
		if _, err := Parse([]byte(in), testGetenv); err != nil {
			t.Errorf("issuer %s: %v", issuer, err)
		}
	}
}

func TestParseHSTSMaxAge(t *testing.T) {
	for _, tt := range []struct {
		name, set string
		want      time.Duration
	}{
		{"default when unset", "", DefaultHSTSMaxAge},
		{"explicit", "\n  hsts_max_age: 720h", 720 * time.Hour},
		{"zero turns it off", "\n  hsts_max_age: 0s", 0},
	} {
		cfg, err := Parse([]byte(edit(t, "  key_file: key.pem", "  key_file: key.pem"+tt.set)), testGetenv)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if cfg.TLS.HSTSMaxAge == nil || *cfg.TLS.HSTSMaxAge != tt.want {
			t.Errorf("%s: hsts_max_age = %v, want %v", tt.name, cfg.TLS.HSTSMaxAge, tt.want)
		}
	}
	if DefaultHSTSMaxAge != 365*24*time.Hour {
		t.Errorf("DefaultHSTSMaxAge = %v, want one year", DefaultHSTSMaxAge)
	}
}

func TestParseLogoutAtIdP(t *testing.T) {
	cfg, err := Parse([]byte(edit(t, "  group_refresh_interval: 5m", "  group_refresh_interval: 5m\n  logout_at_idp: true")), testGetenv)
	if err != nil || !cfg.Auth.LogoutAtIdP {
		t.Fatalf("logout_at_idp: %v, %v", cfg, err)
	}
	if _, err := Parse([]byte(edit(t, "  group_refresh_interval: 5m", "  group_refresh_interval: 5m\n  logout_at_idp: yes please")), testGetenv); err == nil {
		t.Error("non-boolean logout_at_idp accepted")
	}
	base, _ := Parse([]byte(baseYAML), testGetenv)
	if base.Auth.LogoutAtIdP {
		t.Error("logout_at_idp defaults to true")
	}
}

func TestParseIDTokenAlgs(t *testing.T) {
	for _, algs := range []string{"[RS256]", "[ES256]", "[RS256, ES256, PS256]", "[RS512, ES384, ES512, PS384, PS512, RS384]"} {
		in := edit(t, "  id_token_algs: [RS256]", "  id_token_algs: "+algs)
		cfg, err := Parse([]byte(in), testGetenv)
		if err != nil {
			t.Errorf("id_token_algs %s: %v", algs, err)
			continue
		}
		if len(cfg.Auth.IDTokenAlgs) == 0 {
			t.Errorf("id_token_algs %s: parsed empty", algs)
		}
	}
}

func TestLoadExampleConfig(t *testing.T) {
	getenv := func(name string) string {
		if name == "WARDEN_CLIENT_SECRET" {
			return "example-secret"
		}
		return ""
	}
	cfg, err := Load("../../config/warden.example.yaml", getenv)
	if err != nil {
		t.Fatalf("config/warden.example.yaml must stay valid: %v", err)
	}
	if len(cfg.Routes) != 3 {
		t.Errorf("routes = %d, want 3", len(cfg.Routes))
	}
	for _, r := range cfg.Routes {
		if r.UpstreamURL == nil {
			t.Errorf("route %s: upstream URL not parsed", r.Host)
		}
	}
}

// The container config (D25) must stay valid too.
func TestLoadDockerConfig(t *testing.T) {
	cfg, err := Load("../../config/warden.docker.yaml", func(string) string { return "example-secret" })
	if err != nil {
		t.Fatalf("config/warden.docker.yaml must stay valid: %v", err)
	}
	if cfg.Auth.Issuer != "http://keycloak.localhost:8180/realms/warden" || len(cfg.Routes) != 3 || cfg.Admin == nil {
		t.Errorf("unexpected docker config: issuer %q, %d routes", cfg.Auth.Issuer, len(cfg.Routes))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(t.TempDir()+"/nope.yaml", testGetenv)
	if err == nil || !strings.Contains(err.Error(), "nope.yaml") {
		t.Fatalf("err = %v, want error naming the file", err)
	}
}

func TestParseRejectsWholeDocumentProblems(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "empty"},
		{"only comments", "# nothing here\n", "empty"},
		{"two documents", baseYAML + "---\nlisten: \":9443\"\n", "multiple YAML documents"},
		{"no routes", strings.Split(baseYAML, "routes:")[0] + "routes: []\n", "routes"},
		{"routes missing", strings.Split(baseYAML, "routes:")[0], "routes"},
		{"not a mapping", "- a\n- b\n", "cannot unmarshal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.in), testGetenv)
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if cfg != nil {
				t.Error("Parse returned a config alongside an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     string // substring the error must contain
	}{
		// Strict decoding.
		{"unknown top-level field", `listen: ":8443"`, "listen: \":8443\"\nbogus: 1", "bogus"},
		{"unknown route field", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:9001\n    timeout: 5s", "timeout"},
		{"inline client secret", "  client_id: warden-proxy", "  client_id: warden-proxy\n  client_secret: hunter2", "client_secret"},
		{"duplicate key", `listen: ":8443"`, "listen: \":8443\"\nlisten: \":9443\"", "already defined"},
		{"wrong type", `listen: ":8443"`, "listen: [1]", "cannot unmarshal"},
		{"duration as bare integer", "  ttl: 60s", "  ttl: 60", "cannot unmarshal"},
		{"duration in words", "  ttl: 60s", "  ttl: 1 minute", "cannot unmarshal"},

		// Listeners.
		{"listen empty", `listen: ":8443"`, `listen: ""`, "listen"},
		{"listen without port", `listen: ":8443"`, `listen: "8443"`, "listen"},
		{"listen named port", `listen: ":8443"`, `listen: ":https"`, "listen"},
		{"listen port zero", `listen: ":8443"`, `listen: ":0"`, "listen"},
		{"listen port too large", `listen: ":8443"`, `listen: ":70000"`, "listen"},
		{"redirect listener same as main", `http_redirect_listen: ":8080"`, `http_redirect_listen: ":8443"`, "http_redirect_listen"},
		{"redirect listener same port wildcard", `http_redirect_listen: ":8080"`, `http_redirect_listen: "127.0.0.1:8443"`, "http_redirect_listen"},

		// Admin: who may use it is narrow and always needs recent MFA.
		{"admin without rules", "  allow:\n    - groups: [admins]\n      require_mfa_within: 12h", "  allow: []", "admin.allow"},
		{"admin rule without MFA", "      require_mfa_within: 12h", "      users: [alice]", "admin.allow[0].require_mfa_within"},
		{"admin rule for any user", "    - groups: [admins]\n      require_mfa_within: 12h", "    - authenticated: true\n      require_mfa_within: 12h", "admin.allow[0]"},
		{"admin rule by email domain only", "    - groups: [admins]\n      require_mfa_within: 12h", "    - email_domains: [warden.local]\n      require_mfa_within: 12h", "admin.allow[0]"},
		{"admin zero MFA window", "      require_mfa_within: 12h", "      require_mfa_within: 0s", "admin.allow[0].require_mfa_within"},
		{"admin empty groups", "    - groups: [admins]\n      require_mfa_within: 12h", "    - groups: []\n      require_mfa_within: 12h", "admin.allow[0].groups"},
		{"admin unknown field", "admin:\n  allow:", "admin:\n  paths: []\n  allow:", "paths"},

		// TLS.
		{"tls cert missing", "  cert_file: cert.pem", `  cert_file: ""`, "tls.cert_file"},
		{"tls key missing", "  key_file: key.pem", `  key_file: ""`, "tls.key_file"},

		// Auth.
		{"issuer not a URL", "issuer: https://idp.example.test/realms/warden", "issuer: idp.example.test/realms", "auth.issuer"},
		{"issuer plain http on remote host", "issuer: https://idp.example.test/realms/warden", "issuer: http://idp.example.test/realms/warden", "https"},
		{"issuer http on localhost lookalike", "issuer: https://idp.example.test/realms/warden", "issuer: http://localhost.evil.test/realms/warden", "https"},
		{"issuer http on .localhost lookalike", "issuer: https://idp.example.test/realms/warden", "issuer: http://keycloak.localhost.evil.test/realms/warden", "https"},
		{"issuer http on localhost suffix without dot", "issuer: https://idp.example.test/realms/warden", "issuer: http://evillocalhost/realms/warden", "https"},
		{"issuer http on trailing-dot localhost", "issuer: https://idp.example.test/realms/warden", "issuer: http://keycloak.localhost./realms/warden", "https"},
		{"issuer with credentials", "issuer: https://idp.example.test/realms/warden", "issuer: https://u:p@idp.example.test/realms/warden", "auth.issuer"},
		{"issuer with query", "issuer: https://idp.example.test/realms/warden", "issuer: https://idp.example.test/realms/warden?x=1", "auth.issuer"},
		{"issuer with fragment", "issuer: https://idp.example.test/realms/warden", "issuer: https://idp.example.test/realms/warden#x", "auth.issuer"},
		{"issuer other scheme", "issuer: https://idp.example.test/realms/warden", "issuer: ftp://idp.example.test/realms/warden", "auth.issuer"},
		{"client_id empty", "  client_id: warden-proxy", `  client_id: ""`, "auth.client_id"},
		{"secret env unset", "  client_secret_env: TEST_CLIENT_SECRET", "  client_secret_env: UNSET_VAR", "UNSET_VAR"},
		{"secret env empty name", "  client_secret_env: TEST_CLIENT_SECRET", `  client_secret_env: ""`, "auth.client_secret_env"},
		{"scopes without openid", "  scopes: [openid, email]", "  scopes: [email]", "openid"},
		{"scopes with empty entry", "  scopes: [openid, email]", `  scopes: [openid, ""]`, "auth.scopes"},
		// ID token algorithms (invariant 3): asymmetric allowlist only.
		{"id_token_algs missing", "  id_token_algs: [RS256]\n", "", "auth.id_token_algs"},
		{"id_token_algs empty", "  id_token_algs: [RS256]", "  id_token_algs: []", "auth.id_token_algs"},
		{"id_token_algs none", "  id_token_algs: [RS256]", "  id_token_algs: [none]", "none"},
		{"id_token_algs NONE", "  id_token_algs: [RS256]", "  id_token_algs: [NONE]", "NONE"},
		{"id_token_algs none alongside RS256", "  id_token_algs: [RS256]", "  id_token_algs: [RS256, none]", "none"},
		{"id_token_algs HS256", "  id_token_algs: [RS256]", "  id_token_algs: [HS256]", "HS256"},
		{"id_token_algs HS512", "  id_token_algs: [RS256]", "  id_token_algs: [HS512]", "HS512"},
		{"id_token_algs lowercase", "  id_token_algs: [RS256]", "  id_token_algs: [rs256]", "rs256"},
		{"id_token_algs unknown", "  id_token_algs: [RS256]", "  id_token_algs: [RS1024]", "RS1024"},
		{"id_token_algs duplicate", "  id_token_algs: [RS256]", "  id_token_algs: [RS256, RS256]", "duplicate"},
		{"groups claim empty", "  groups_claim: groups", `  groups_claim: ""`, "auth.groups_claim"},
		{"group refresh zero", "  group_refresh_interval: 5m", "  group_refresh_interval: 0s", "auth.group_refresh_interval"},
		{"hsts negative", "  key_file: key.pem", "  key_file: key.pem\n  hsts_max_age: -1s", "tls.hsts_max_age"},
		{"hsts not whole seconds", "  key_file: key.pem", "  key_file: key.pem\n  hsts_max_age: 1500ms", "tls.hsts_max_age"},
		{"auth domain invalid", "  domain: auth.example.test", "  domain: auth.example.test:8443", "auth.domain"},
		{"auth domain is a route host", "  domain: auth.example.test", "  domain: app.example.test", "auth.domain"},

		// Route hosts. These become the redirect allowlist (invariant 5).
		{"duplicate host", "  - host: other.example.test", "  - host: app.example.test", "duplicate"},
		{"duplicate host differing in case", "  - host: other.example.test", "  - host: APP.example.TEST", "duplicate"},
		{"host trailing dot", "  - host: app.example.test", "  - host: app.example.test.", "routes[0].host"},
		{"host with port", "  - host: app.example.test", "  - host: app.example.test:8443", "routes[0].host"},
		{"host wildcard", "  - host: app.example.test", `  - host: "*.example.test"`, "routes[0].host"},
		{"host empty", "  - host: app.example.test", `  - host: ""`, "routes[0].host"},
		{"host underscore", "  - host: app.example.test", "  - host: app_x.example.test", "routes[0].host"},
		{"host leading hyphen", "  - host: app.example.test", "  - host: -app.example.test", "routes[0].host"},
		{"host empty label", "  - host: app.example.test", "  - host: app..example.test", "routes[0].host"},
		{"host label too long", "  - host: app.example.test", "  - host: " + strings.Repeat("a", 64) + ".example.test", "routes[0].host"},
		{"host non-ASCII", "  - host: app.example.test", "  - host: äpp.example.test", "routes[0].host"},
		{"host IPv4 literal", "  - host: app.example.test", "  - host: 127.0.0.1", "routes[0].host"},
		{"host IPv6 literal", "  - host: app.example.test", `  - host: "[::1]"`, "routes[0].host"},
		{"host numeric final label", "  - host: app.example.test", "  - host: 1.2.3.999", "routes[0].host"},
		{"host with path", "  - host: app.example.test", "  - host: app.example.test/x", "routes[0].host"},

		// Upstream URLs.
		{"upstream ftp", "    upstream: http://127.0.0.1:9001", "    upstream: ftp://127.0.0.1:9001", "routes[0].upstream"},
		{"upstream file", "    upstream: http://127.0.0.1:9001", "    upstream: file:///etc/passwd", "routes[0].upstream"},
		{"upstream no scheme", "    upstream: http://127.0.0.1:9001", "    upstream: 127.0.0.1:9001", "routes[0].upstream"},
		{"upstream opaque", "    upstream: http://127.0.0.1:9001", "    upstream: http:127.0.0.1", "routes[0].upstream"},
		{"upstream no host", "    upstream: http://127.0.0.1:9001", "    upstream: http://", "routes[0].upstream"},
		{"upstream empty", "    upstream: http://127.0.0.1:9001", `    upstream: ""`, "routes[0].upstream"},
		{"upstream credentials", "    upstream: http://127.0.0.1:9001", "    upstream: http://user:pass@127.0.0.1:9001", "routes[0].upstream"},
		{"upstream path", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:9001/api", "routes[0].upstream"},
		{"upstream query", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:9001?x=1", "routes[0].upstream"},
		{"upstream empty query", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:9001?", "routes[0].upstream"},
		{"upstream fragment", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:9001#f", "routes[0].upstream"},
		{"upstream bad port", "    upstream: http://127.0.0.1:9001", "    upstream: http://127.0.0.1:99999", "routes[0].upstream"},
		{"upstream_tls on http upstream", "    upstream: https://127.0.0.1:9003", "    upstream: http://127.0.0.1:9003", "routes[1].upstream_tls"},
		{"upstream_tls without ca", "      ca_file: ca.pem", `      ca_file: ""`, "routes[1].upstream_tls.ca_file"},
		{"client cert without key", "      ca_file: ca.pem", "      ca_file: ca.pem\n      client_cert_file: c.pem", "routes[1].upstream_tls"},
		{"client key without cert", "      ca_file: ca.pem", "      ca_file: ca.pem\n      client_key_file: k.pem", "routes[1].upstream_tls"},

		// Policy shape. Ambiguous rules must not become "allow everyone" (invariant 1).
		{"no allow rules", "      allow:\n        - groups: [dev]", "      allow: []", "routes[1].policy.allow"},
		{"allow missing", "    policy:\n      allow:\n        - groups: [dev]", "    policy: {}", "routes[1].policy.allow"},
		{"empty rule", "        - authenticated: true", "        - {}", "routes[0].policy.allow[0]"},
		{"authenticated false", "        - authenticated: true", "        - authenticated: false", "authenticated"},
		{"empty group list", "            - groups: [admins]", "            - groups: []", "routes[0].policy.paths[0].allow[0].groups"},
		{"empty group name", "            - groups: [admins]", `            - groups: [""]`, "routes[0].policy.paths[0].allow[0].groups"},
		{"empty users list", "            - groups: [admins]", "            - users: []", "routes[0].policy.paths[0].allow[0].users"},
		{"empty email domain list", "            - groups: [admins]", "            - email_domains: []", "email_domains"},
		{"email domain with @", "            - groups: [admins]", `            - email_domains: ["@example.test"]`, "email_domains"},
		{"mfa window zero", "            - groups: [admins]", "            - groups: [admins]\n              require_mfa_within: 0s", "require_mfa_within"},
		{"mfa window negative", "            - groups: [admins]", "            - groups: [admins]\n              require_mfa_within: -1m", "require_mfa_within"},
		{"path rule without allow", "          allow:\n            - groups: [admins]", "          allow: []", "routes[0].policy.paths[0].allow"},
		{"prefix without slash", "        - prefix: /admin", "        - prefix: admin", "routes[0].policy.paths[0].prefix"},
		{"prefix empty", "        - prefix: /admin", `        - prefix: ""`, "routes[0].policy.paths[0].prefix"},
		{"prefix dot-dot", "        - prefix: /admin", "        - prefix: /x/../admin", "routes[0].policy.paths[0].prefix"},
		{"prefix dot segment", "        - prefix: /admin", "        - prefix: /./admin", "routes[0].policy.paths[0].prefix"},
		{"prefix trailing dot-dot", "        - prefix: /admin", "        - prefix: /admin/..", "routes[0].policy.paths[0].prefix"},
		{"prefix double slash", "        - prefix: /admin", "        - prefix: //admin", "routes[0].policy.paths[0].prefix"},
		{"prefix percent-encoded", "        - prefix: /admin", "        - prefix: /%61dmin", "routes[0].policy.paths[0].prefix"},
		{"prefix backslash", "        - prefix: /admin", `        - prefix: '/admin\x'`, "routes[0].policy.paths[0].prefix"},
		{"prefix query", "        - prefix: /admin", "        - prefix: /admin?x", "routes[0].policy.paths[0].prefix"},
		{"prefix fragment", "        - prefix: /admin", `        - prefix: "/admin#x"`, "routes[0].policy.paths[0].prefix"},
		{"prefix NUL", "        - prefix: /admin", `        - prefix: "/admin\0"`, "routes[0].policy.paths[0].prefix"},
		{"duplicate prefix", "            - groups: [admins]", "            - groups: [admins]\n        - prefix: /admin\n          allow:\n            - groups: [sre]", "duplicate"},
		{"duplicate prefix with trailing slash", "            - groups: [admins]", "            - groups: [admins]\n        - prefix: /admin/\n          allow:\n            - groups: [sre]", "duplicate"},
		{"duplicate prefix ignoring case", "      paths:\n        - prefix: /admin\n          allow:\n            - groups: [admins]",
			"      case_insensitive_paths: true\n      paths:\n        - prefix: /admin\n          allow:\n            - groups: [admins]\n        - prefix: /ADMIN\n          allow:\n            - groups: [sre]", "duplicate"},
		{"prefix path parameter", "        - prefix: /admin", "        - prefix: /admin;x", "routes[0].policy.paths[0].prefix"},

		// Session.
		{"redis addr without port", "  redis_addr: localhost:6379", "  redis_addr: localhost", "session.redis_addr"},
		{"cookie name empty", "  cookie_name: _warden", `  cookie_name: ""`, "session.cookie_name"},
		{"cookie name invalid", "  cookie_name: _warden", `  cookie_name: "bad;name"`, "session.cookie_name"},
		{"absolute ttl zero", "  absolute_ttl: 8h", "  absolute_ttl: 0s", "session.absolute_ttl"},
		{"idle timeout negative", "  idle_timeout: 1h", "  idle_timeout: -1h", "session.idle_timeout"},
		{"idle exceeds absolute", "  idle_timeout: 1h", "  idle_timeout: 9h", "session.idle_timeout"},

		// Identity assertion.
		{"identity ttl over 60s", "  ttl: 60s", "  ttl: 61s", "identity.ttl"},
		{"identity ttl zero", "  ttl: 60s", "  ttl: 0s", "identity.ttl"},
		{"identity header invalid", "  header: X-Warden-Identity", `  header: "X-Warden Identity"`, "identity.header"},
		{"identity header empty", "  header: X-Warden-Identity", `  header: ""`, "identity.header"},
		{"signing key missing", "  signing_key_file: signing.pem", `  signing_key_file: ""`, "identity.signing_key_file"},
		{"previous key empty", "  signing_key_file: signing.pem", "  signing_key_file: signing.pem\n  previous_key_files: [\"\"]", "identity.previous_key_files[0]"},
		{"previous key is active", "  signing_key_file: signing.pem", "  signing_key_file: signing.pem\n  previous_key_files: [signing.pem]", "identity.previous_key_files[0]"},
		{"previous key duplicate", "  signing_key_file: signing.pem", "  signing_key_file: signing.pem\n  previous_key_files: [old.pem, old.pem]", "identity.previous_key_files[1]"},

		// Header stripping.
		{"strip header invalid", "strip_headers: [X-Remote-User]", `strip_headers: ["X-Remote User"]`, "strip_headers[0]"},
		{"strip header empty", "strip_headers: [X-Remote-User]", `strip_headers: [""]`, "strip_headers[0]"},

		// Audit.
		{"audit unknown sink", "  sink: file", "  sink: syslog", "audit.sink"},
		{"audit file sink without path", "  file: audit.jsonl", `  file: ""`, "audit.file"},
		{"audit stdout with path", "  sink: file", "  sink: stdout", "audit.file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := edit(t, tt.old, tt.new)
			cfg, err := Parse([]byte(in), testGetenv)
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if cfg != nil {
				t.Error("Parse returned a config alongside an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestParseReportsAllProblems(t *testing.T) {
	in := edit(t, "  cert_file: cert.pem", `  cert_file: ""`)
	in = strings.Replace(in, "  sink: file", "  sink: syslog", 1)
	in = strings.Replace(in, "    upstream: http://127.0.0.1:9001", "    upstream: ftp://x", 1)
	_, err := Parse([]byte(in), testGetenv)
	if err == nil {
		t.Fatal("Parse succeeded, want error")
	}
	for _, want := range []string{"tls.cert_file", "audit.sink", "routes[0].upstream"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

// A secret pasted where the env var name belongs must not be echoed back in
// the error, which ends up in logs (invariant 9).
func TestParseDoesNotEchoMisplacedSecret(t *testing.T) {
	const pasted = "s3cr3t-Value!/xyz"
	in := edit(t, "  client_secret_env: TEST_CLIENT_SECRET", "  client_secret_env: "+pasted)
	_, err := Parse([]byte(in), testGetenv)
	if err == nil {
		t.Fatal("Parse succeeded, want error")
	}
	if !strings.Contains(err.Error(), "auth.client_secret_env") {
		t.Errorf("error %q does not name the field", err)
	}
	if strings.Contains(err.Error(), pasted) {
		t.Errorf("error echoes the secret-looking value: %q", err)
	}
}

func TestSecretIsRedacted(t *testing.T) {
	cfg, err := Parse([]byte(baseYAML), testGetenv)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Auth.ClientSecret

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	logger.Info("x", "secret", s, "auth", cfg.Auth, "cfg", cfg)

	jsonCfg, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	outputs := map[string]string{
		"%v":         fmt.Sprintf("%v", s),
		"%s":         fmt.Sprintf("%s", s),
		"%+v":        fmt.Sprintf("%+v", s),
		"%#v":        fmt.Sprintf("%#v", s),
		"%q":         fmt.Sprintf("%q", s),
		"%x":         fmt.Sprintf("%x", s),
		"auth %+v":   fmt.Sprintf("%+v", cfg.Auth),
		"auth %#v":   fmt.Sprintf("%#v", cfg.Auth),
		"config %+v": fmt.Sprintf("%+v", *cfg),
		"slog":       logBuf.String(),
		"json":       string(jsonCfg),
	}
	hexSecret := fmt.Sprintf("%x", testSecret)
	for name, out := range outputs {
		if strings.Contains(out, testSecret) || strings.Contains(out, hexSecret) {
			t.Errorf("%s leaks the secret: %s", name, out)
		}
	}
	if !strings.Contains(outputs["%v"], "REDACTED") {
		t.Errorf("%%v = %q, want a redaction marker", outputs["%v"])
	}
}

func TestIsLocalHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "127.0.0.1": true, "127.8.9.10": true, "::1": true,
		"keycloak.localhost": true, "a.b.localhost": true, "KEYCLOAK.LOCALHOST": true,
		"localhost.evil.test": false, "keycloak.localhost.evil.test": false, "evillocalhost": false,
		"keycloak.localhost.": false, ".localhost": false, "": false, "10.0.0.1": false, "idp.example.test": false,
	} {
		if got := isLocalHost(host); got != want {
			t.Errorf("isLocalHost(%q) = %v, want %v", host, got, want)
		}
	}
}
