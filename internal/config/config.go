package config

import (
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"
)

// Config is the full Warden configuration. Fields tagged yaml:"-" are derived
// during Parse and cannot be set from the file.
type Config struct {
	Listen             string   `yaml:"listen"`
	HTTPRedirectListen string   `yaml:"http_redirect_listen"` // optional; empty disables it
	TLS                TLS      `yaml:"tls"`
	Auth               Auth     `yaml:"auth"`
	Session            Session  `yaml:"session"`
	Identity           Identity `yaml:"identity"`
	StripHeaders       []string `yaml:"strip_headers"` // extra headers to strip; canonicalized
	Audit              Audit    `yaml:"audit"`
	Routes             []Route  `yaml:"routes"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type Auth struct {
	Domain               string        `yaml:"domain"` // central auth host; lowercased
	Issuer               string        `yaml:"issuer"`
	ClientID             string        `yaml:"client_id"`
	ClientSecretEnv      string        `yaml:"client_secret_env"`
	ClientSecret         Secret        `yaml:"-"` // read from ClientSecretEnv
	Scopes               []string      `yaml:"scopes"`
	IDTokenAlgs          []string      `yaml:"id_token_algs"` // pinned JWS algs; asymmetric only
	GroupsClaim          string        `yaml:"groups_claim"`
	GroupRefreshInterval time.Duration `yaml:"group_refresh_interval"`
	// LogoutAtIdP also ends the IdP session on logout (RP-initiated logout).
	// Requires the IdP to advertise end_session_endpoint.
	LogoutAtIdP bool `yaml:"logout_at_idp"`
}

type Session struct {
	RedisAddr   string        `yaml:"redis_addr"`
	CookieName  string        `yaml:"cookie_name"`
	AbsoluteTTL time.Duration `yaml:"absolute_ttl"`
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

type Identity struct {
	Header         string `yaml:"header"` // canonicalized
	SigningKeyFile string `yaml:"signing_key_file"`
	// PreviousKeyFiles are retired signing keys (or their public keys),
	// still published in the JWKS for verification during rotation.
	PreviousKeyFiles []string      `yaml:"previous_key_files"`
	TTL              time.Duration `yaml:"ttl"`
}

type Audit struct {
	Sink string `yaml:"sink"` // "file" or "stdout"
	File string `yaml:"file"` // required for, and only allowed with, sink: file
}

const (
	AuditSinkFile   = "file"
	AuditSinkStdout = "stdout"
)

type Route struct {
	Host        string       `yaml:"host"` // lowercased
	Upstream    string       `yaml:"upstream"`
	UpstreamURL *url.URL     `yaml:"-"` // parsed Upstream: scheme and host only
	UpstreamTLS *UpstreamTLS `yaml:"upstream_tls"`
	Policy      Policy       `yaml:"policy"`
}

type UpstreamTLS struct {
	CAFile         string `yaml:"ca_file"`
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`
}

// Policy is the per-route access policy as written in the config. Parse only
// checks its shape; internal/policy defines what the rules mean.
type Policy struct {
	Allow []Rule     `yaml:"allow"`
	Paths []PathRule `yaml:"paths"`
	// CaseInsensitivePaths matches path prefixes ignoring case, for upstreams
	// that treat /ADMIN as /admin. Off by default.
	CaseInsensitivePaths bool `yaml:"case_insensitive_paths"`
}

type PathRule struct {
	Prefix string `yaml:"prefix"`
	Allow  []Rule `yaml:"allow"`
}

// Rule is one allow rule. A nil field means the condition is absent. An empty
// non-nil slice (groups: []) or a zero MFA window is rejected as ambiguous,
// since either could otherwise read as "no restriction".
type Rule struct {
	Authenticated    *bool          `yaml:"authenticated"`
	Users            []string       `yaml:"users"`
	Groups           []string       `yaml:"groups"`
	EmailDomains     []string       `yaml:"email_domains"` // lowercased
	RequireMFAWithin *time.Duration `yaml:"require_mfa_within"`
}

const redacted = "[REDACTED]"

// Secret holds a sensitive string. Every formatting, logging, and marshaling
// path prints a redaction marker; only Reveal returns the value (invariant 9).
type Secret struct {
	value string
}

func NewSecret(v string) Secret { return Secret{value: v} }

// Reveal returns the secret value. Call it only where the value is used, never
// to log or display it.
func (s Secret) Reveal() string { return s.value }

func (Secret) String() string   { return redacted }
func (Secret) GoString() string { return redacted }

// Format covers every fmt verb (%x, %d, ...), not just the Stringer ones.
func (Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
