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
	Listen             string     `yaml:"listen"`
	HTTPRedirectListen string     `yaml:"http_redirect_listen"` // optional; empty disables it
	TLS                TLS        `yaml:"tls"`
	Auth               Auth       `yaml:"auth"`
	Session            Session    `yaml:"session"`
	Identity           Identity   `yaml:"identity"`
	StripHeaders       []string   `yaml:"strip_headers"` // extra headers to strip; canonicalized
	RateLimits         RateLimits `yaml:"rate_limits"`   // optional; unset limits use the defaults
	Audit              Audit      `yaml:"audit"`
	Admin              *Admin     `yaml:"admin"` // optional; nil turns the admin API off
	Demo               *Demo      `yaml:"demo"`  // optional; public demo mode (D30)
	Routes             []Route    `yaml:"routes"`
}

type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// HSTSMaxAge is the Strict-Transport-Security max-age on every HTTPS
	// response. Unset means DefaultHSTSMaxAge; 0 turns HSTS off.
	HSTSMaxAge *time.Duration `yaml:"hsts_max_age"`
}

// DefaultHSTSMaxAge is one year, the common baseline.
const DefaultHSTSMaxAge = 365 * 24 * time.Hour

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
	// WebSocketRecheck is how often an open WebSocket's session and policy
	// are re-checked, so revocation reaches it. Unset means
	// DefaultWebSocketRecheck.
	WebSocketRecheck time.Duration `yaml:"websocket_recheck"`
}

// DefaultWebSocketRecheck bounds how long a revoked session's WebSocket
// stays open.
const DefaultWebSocketRecheck = 30 * time.Second

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

// RateLimits bound requests per client IP to the login and callback
// endpoints, and per IP and per session to the admin API. They cannot be
// turned off; unset ones are filled in with the defaults during Parse.
type RateLimits struct {
	Login        *RateLimit `yaml:"login"`         // per IP: /.warden/login and /.warden/callback
	AdminIP      *RateLimit `yaml:"admin_ip"`      // per IP: admin API and dashboard, before the session lookup
	AdminSession *RateLimit `yaml:"admin_session"` // per signed-in session: admin API and dashboard
}

// RateLimit is a token bucket: a sustained rate and the burst allowed on top.
type RateLimit struct {
	PerMinute int `yaml:"per_minute"`
	Burst     int `yaml:"burst"`
}

// Defaults for RateLimits. A full login is a login plus a callback request.
var (
	DefaultLoginRate        = RateLimit{PerMinute: 20, Burst: 10}
	DefaultAdminIPRate      = RateLimit{PerMinute: 120, Burst: 30}
	DefaultAdminSessionRate = RateLimit{PerMinute: 60, Burst: 20}
)

// Demo turns on the public demo mode: a landing page on the auth host with
// these accounts and their current OTP codes, admin views scoped to each
// visitor, and a reset of all sessions every ResetInterval. Everything in it
// is shown to anyone, so it holds no real credentials.
type Demo struct {
	Enabled       bool          `yaml:"enabled"`        // must be true: no demo mode by accident
	ResetInterval time.Duration `yaml:"reset_interval"` // default DefaultDemoReset
	Accounts      []DemoAccount `yaml:"accounts"`
}

// DemoAccount is a public demo login, shown on the landing page.
type DemoAccount struct {
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	OTPSecret   string `yaml:"otp_secret"` // optional; base32 TOTP key as the IdP has it
	Description string `yaml:"description"`
	OTPKey      []byte `yaml:"-"` // OTPSecret decoded
}

// DefaultDemoReset is how often demo mode wipes sessions.
const DefaultDemoReset = time.Hour

// Admin is who may use the admin API and dashboard on the auth host. Every
// rule must name users or groups and require recent MFA.
type Admin struct {
	Allow []Rule `yaml:"allow"`
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
