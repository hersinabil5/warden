package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

var (
	alice = &Subject{
		Username: "alice", Email: "alice@warden.local", Groups: []string{"admins", "sre"},
		AMR: []string{"pwd", "otp"}, AuthTime: now.Add(-2 * time.Minute),
	}
	bob = &Subject{
		Username: "bob", Email: "bob@warden.local", Groups: []string{"dev"},
		AMR: []string{"pwd"}, AuthTime: now.Add(-2 * time.Minute),
	}
)

func mustCompile(t testing.TB, p config.Policy) *Policy {
	t.Helper()
	c, err := Compile(p)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

// grafana mirrors the example config: sre/admins for the app, admins with
// recent MFA under /admin.
func grafana(t testing.TB, caseInsensitive bool) *Policy {
	return mustCompile(t, config.Policy{
		Allow: []config.Rule{{Groups: []string{"sre", "admins"}}},
		Paths: []config.PathRule{{
			Prefix: "/admin",
			Allow:  []config.Rule{{Groups: []string{"admins"}, RequireMFAWithin: ptr(10 * time.Minute)}},
		}},
		CaseInsensitivePaths: caseInsensitive,
	})
}

func TestEvaluateConditions(t *testing.T) {
	tests := []struct {
		name  string
		rule  config.Rule
		subj  *Subject
		allow bool
	}{
		{"authenticated", config.Rule{Authenticated: ptr(true)}, bob, true},
		{"authenticated, no subject", config.Rule{Authenticated: ptr(true)}, nil, false},
		{"user listed", config.Rule{Users: []string{"carol", "bob"}}, bob, true},
		{"user not listed", config.Rule{Users: []string{"alice"}}, bob, false},
		{"user match is exact", config.Rule{Users: []string{"Bob"}}, bob, false},
		{"group listed", config.Rule{Groups: []string{"dev"}}, bob, true},
		{"group not listed", config.Rule{Groups: []string{"admins"}}, bob, false},
		{"group match is exact", config.Rule{Groups: []string{"Admins"}}, alice, false},
		{"email domain", config.Rule{EmailDomains: []string{"warden.local"}}, bob, true},
		{"email domain mismatch", config.Rule{EmailDomains: []string{"example.com"}}, bob, false},
		{"email domain is not a suffix match", config.Rule{EmailDomains: []string{"local"}}, bob, false},
		{"email domain case-insensitive", config.Rule{EmailDomains: []string{"warden.local"}},
			&Subject{Username: "x", Email: "x@WARDEN.Local"}, true},
		{"no (unverified) email", config.Rule{EmailDomains: []string{"warden.local"}},
			&Subject{Username: "x"}, false},
		{"email domain via subdomain", config.Rule{EmailDomains: []string{"warden.local"}},
			&Subject{Username: "x", Email: "x@evil.warden.local"}, false},
		{"email with two @", config.Rule{EmailDomains: []string{"warden.local"}},
			&Subject{Username: "x", Email: "x@warden.local@evil.com"}, false},
		{"recent MFA", config.Rule{RequireMFAWithin: ptr(10 * time.Minute)}, alice, true},
		{"password only", config.Rule{RequireMFAWithin: ptr(10 * time.Minute)}, bob, false},
		{"MFA too old", config.Rule{RequireMFAWithin: ptr(time.Minute)}, alice, false},
		{"mfa amr value", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"mfa"}, AuthTime: now}, true},
		{"single strong factor is not MFA", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"hwk"}, AuthTime: now}, false},
		{"repeated factor is not MFA", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"pwd", "pwd"}, AuthTime: now}, false},
		{"unknown amr values do not count", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"pwd", "custom"}, AuthTime: now}, false},
		{"MFA without auth_time", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"pwd", "otp"}}, false},
		{"auth_time in the future", config.Rule{RequireMFAWithin: ptr(time.Hour)},
			&Subject{Username: "x", AMR: []string{"pwd", "otp"}, AuthTime: now.Add(time.Hour)}, false},
		{"all conditions must hold", config.Rule{Groups: []string{"admins"}, RequireMFAWithin: ptr(time.Minute)}, alice, false},
		{"all conditions hold", config.Rule{Groups: []string{"admins"}, EmailDomains: []string{"warden.local"}}, alice, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustCompile(t, config.Policy{Allow: []config.Rule{tt.rule}})
			d := p.Evaluate(Input{Path: "/", Subject: tt.subj, Now: now})
			if d.Allow != tt.allow {
				t.Errorf("Allow = %v, want %v (rule %q, reason %q)", d.Allow, tt.allow, d.Rule, d.Reason)
			}
			if d.Reason == "" || d.Rule == "" {
				t.Errorf("decision without rule or reason: %+v", d)
			}
		})
	}
}

func TestEvaluateRulesAreOred(t *testing.T) {
	p := mustCompile(t, config.Policy{Allow: []config.Rule{
		{Users: []string{"carol"}},
		{Groups: []string{"dev"}},
	}})
	d := p.Evaluate(Input{Path: "/", Subject: bob, Now: now})
	if !d.Allow || d.Rule != "allow[1]" {
		t.Errorf("decision = %+v, want allow by allow[1]", d)
	}
}

// PLAN.md M3 acceptance: bob reaches whoami, not Grafana; alice reaches both.
func TestAcceptanceRoutes(t *testing.T) {
	whoami := mustCompile(t, config.Policy{Allow: []config.Rule{{Authenticated: ptr(true)}}})
	g := grafana(t, false)
	for _, tt := range []struct {
		name   string
		p      *Policy
		subj   *Subject
		allow  bool
		policy string
	}{
		{"bob whoami", whoami, bob, true, "whoami"},
		{"alice whoami", whoami, alice, true, "whoami"},
		{"bob grafana", g, bob, false, "grafana"},
		{"alice grafana", g, alice, true, "grafana"},
	} {
		if d := tt.p.Evaluate(Input{Path: "/", Subject: tt.subj, Now: now}); d.Allow != tt.allow {
			t.Errorf("%s: Allow = %v, want %v (%+v)", tt.name, d.Allow, tt.allow, d)
		}
	}
}

func TestPathRules(t *testing.T) {
	// sre-only user: allowed on the app, denied under /admin.
	sre := &Subject{Username: "sam", Groups: []string{"sre"}, AMR: []string{"pwd", "otp"}, AuthTime: now}
	g := grafana(t, false)
	for _, tt := range []struct {
		path  string
		allow bool
		rule  string
	}{
		{"/", true, "allow[0]"},
		{"/d/abc", true, "allow[0]"},
		{"/admin", false, "paths[/admin]"},
		{"/admin/", false, "paths[/admin]"},
		{"/admin/users", false, "paths[/admin]"},
		{"/administrator", true, "allow[0]"}, // segment match: not under /admin
		{"/x/admin", true, "allow[0]"},
		{"/ADMIN", true, "allow[0]"}, // case-sensitive unless configured
	} {
		d := g.Evaluate(Input{Path: tt.path, Subject: sre, Now: now})
		if d.Allow != tt.allow || !strings.HasPrefix(d.Rule, tt.rule) {
			t.Errorf("%s: %+v, want allow=%v rule %s...", tt.path, d, tt.allow, tt.rule)
		}
	}
	if d := g.Evaluate(Input{Path: "/admin/users", Subject: alice, Now: now}); !d.Allow || d.Rule != "paths[/admin].allow[0]" {
		t.Errorf("alice /admin/users: %+v", d)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	p := mustCompile(t, config.Policy{
		Allow: []config.Rule{{Authenticated: ptr(true)}},
		Paths: []config.PathRule{
			{Prefix: "/api", Allow: []config.Rule{{Groups: []string{"dev"}}}},
			{Prefix: "/api/admin", Allow: []config.Rule{{Groups: []string{"admins"}}}},
			{Prefix: "/api/admin/public", Allow: []config.Rule{{Authenticated: ptr(true)}}},
		},
	})
	for _, tt := range []struct {
		path string
		subj *Subject
		want bool
	}{
		{"/api/x", bob, true},
		{"/api/admin", bob, false},
		{"/api/admin/x", bob, false},
		{"/api/admin/x", alice, true},
		{"/api/x", alice, false}, // a more specific rule replaces, not adds to, the outer one
		{"/api/admin/public/x", &Subject{Username: "z"}, true},
		{"/other", &Subject{Username: "z"}, true},
	} {
		if d := p.Evaluate(Input{Path: tt.path, Subject: tt.subj, Now: now}); d.Allow != tt.want {
			t.Errorf("%s as %s: %+v, want allow=%v", tt.path, tt.subj.Username, d, tt.want)
		}
	}
	// Order in the config does not matter.
	q := mustCompile(t, config.Policy{
		Allow: []config.Rule{{Authenticated: ptr(true)}},
		Paths: []config.PathRule{
			{Prefix: "/api/admin", Allow: []config.Rule{{Groups: []string{"admins"}}}},
			{Prefix: "/api", Allow: []config.Rule{{Groups: []string{"dev"}}}},
		},
	})
	if d := q.Evaluate(Input{Path: "/api/admin/x", Subject: bob, Now: now}); d.Allow {
		t.Errorf("reordered config allowed bob on /api/admin/x: %+v", d)
	}
}

// Decoded paths may contain characters that would need encoding on the wire.
func TestEvaluateDecodedPaths(t *testing.T) {
	p := mustCompile(t, config.Policy{Allow: []config.Rule{{Authenticated: ptr(true)}}})
	for _, path := range []string{"/100%", "/a?b", "/a#b", "/café", "/a b"} {
		if d := p.Evaluate(Input{Path: path, Subject: bob, Now: now}); !d.Allow {
			t.Errorf("%q: %+v, want allow", path, d)
		}
	}
}

func TestTrailingSlashPrefixProtectsBarePath(t *testing.T) {
	p := mustCompile(t, config.Policy{
		Allow: []config.Rule{{Authenticated: ptr(true)}},
		Paths: []config.PathRule{{Prefix: "/admin/", Allow: []config.Rule{{Groups: []string{"admins"}}}}},
	})
	for _, path := range []string{"/admin", "/admin/", "/admin/x"} {
		if d := p.Evaluate(Input{Path: path, Subject: bob, Now: now}); d.Allow {
			t.Errorf("%s: allowed bob: %+v", path, d)
		}
	}
}

func TestCaseInsensitivePaths(t *testing.T) {
	g := grafana(t, true)
	for _, path := range []string{"/admin", "/ADMIN", "/Admin/x", "/aDmIn/"} {
		if d := g.Evaluate(Input{Path: path, Subject: bob, Now: now}); d.Allow || !strings.HasPrefix(d.Rule, "paths[/admin]") {
			t.Errorf("%s: %+v, want deny by paths[/admin]", path, d)
		}
	}
	// Unicode case folding: "K" (KELVIN SIGN) folds to "k".
	p := mustCompile(t, config.Policy{
		Allow:                []config.Rule{{Authenticated: ptr(true)}},
		Paths:                []config.PathRule{{Prefix: "/kube", Allow: []config.Rule{{Groups: []string{"admins"}}}}},
		CaseInsensitivePaths: true,
	})
	if d := p.Evaluate(Input{Path: "/Kube", Subject: bob, Now: now}); d.Allow {
		t.Errorf("Kelvin-sign path bypassed /kube: %+v", d)
	}
}

// Invariant 1: anything unexpected is a deny, never an allow.
func TestEvaluateFailsClosed(t *testing.T) {
	g := grafana(t, false)
	for _, tt := range []struct {
		name string
		p    *Policy
		in   Input
	}{
		{"nil policy", nil, Input{Path: "/", Subject: alice, Now: now}},
		{"zero policy", &Policy{}, Input{Path: "/", Subject: alice, Now: now}},
		{"no subject", g, Input{Path: "/", Now: now}},
		{"relative path", g, Input{Path: "admin", Subject: alice, Now: now}},
		{"empty path", g, Input{Path: "", Subject: alice, Now: now}},
		{"unnormalized path", g, Input{Path: "/x/../admin", Subject: alice, Now: now}},
		{"double slash", g, Input{Path: "//admin", Subject: alice, Now: now}},
		{"encoded path", g, Input{Path: "/%61dmin", Subject: alice, Now: now}},
		{"semicolon", g, Input{Path: "/admin;x", Subject: alice, Now: now}},
		{"zero time", g, Input{Path: "/", Subject: alice}},
	} {
		if d := tt.p.Evaluate(tt.in); d.Allow || d.Reason == "" {
			t.Errorf("%s: %+v, want deny with a reason", tt.name, d)
		}
	}
}

func TestCompileRejects(t *testing.T) {
	for name, p := range map[string]config.Policy{
		"no rules":              {},
		"empty rule":            {Allow: []config.Rule{{}}},
		"authenticated false":   {Allow: []config.Rule{{Authenticated: ptr(false)}}},
		"empty groups":          {Allow: []config.Rule{{Groups: []string{}}}},
		"zero MFA window":       {Allow: []config.Rule{{RequireMFAWithin: ptr(time.Duration(0))}}},
		"path without rules":    {Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "/a"}}},
		"relative prefix":       {Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "a", Allow: []config.Rule{{Authenticated: ptr(true)}}}}},
		"unnormalized prefix":   {Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "/a/../b", Allow: []config.Rule{{Authenticated: ptr(true)}}}}},
		"encoded prefix":        {Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "/%61", Allow: []config.Rule{{Authenticated: ptr(true)}}}}},
		"duplicate after slash": {Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "/a", Allow: []config.Rule{{Authenticated: ptr(true)}}}, {Prefix: "/a/", Allow: []config.Rule{{Groups: []string{"x"}}}}}},
		"case duplicate (ci)":   {CaseInsensitivePaths: true, Allow: []config.Rule{{Authenticated: ptr(true)}}, Paths: []config.PathRule{{Prefix: "/Admin", Allow: []config.Rule{{Authenticated: ptr(true)}}}, {Prefix: "/admin", Allow: []config.Rule{{Groups: []string{"x"}}}}}},
	} {
		if _, err := Compile(p); err == nil {
			t.Errorf("%s: Compile accepted it", name)
		}
	}
}

func FuzzEvaluate(f *testing.F) {
	f.Add("/admin", "bob", "dev", int64(60))
	f.Add("/admin/x", "alice", "admins", int64(0))
	f.Add("/ADMIN", "alice", "sre", int64(-5))
	f.Add("/", "", "", int64(1<<40))
	strict, ci := grafana(f, false), grafana(f, true)
	f.Fuzz(func(t *testing.T, path, user, group string, ageSec int64) {
		s := &Subject{Username: user, Groups: []string{group}, AMR: []string{"pwd", "otp"},
			AuthTime: now.Add(-time.Duration(ageSec) * time.Second)}
		for _, p := range []*Policy{strict, ci} {
			d := p.Evaluate(Input{Path: path, Subject: s, Now: now})
			if d.Reason == "" || d.Rule == "" {
				t.Fatalf("decision without rule or reason: %+v", d)
			}
			if !d.Allow {
				continue
			}
			// Only sre/admins get anything; only admins get /admin.
			if group != "sre" && group != "admins" {
				t.Fatalf("group %q allowed on %q: %+v", group, path, d)
			}
			if strings.HasPrefix(d.Rule, "paths[/admin]") && group != "admins" {
				t.Fatalf("non-admin allowed by /admin rule on %q: %+v", path, d)
			}
			// Anything that is the /admin subtree under the matching mode
			// must be decided by the /admin rule.
			under := path == "/admin" || strings.HasPrefix(path, "/admin/")
			if p == ci {
				under = len(path) >= 6 && strings.EqualFold(path[:6], "/admin") && (len(path) == 6 || path[6] == '/')
			}
			if under && !strings.HasPrefix(d.Rule, "paths[/admin]") {
				t.Fatalf("%q decided by %q, not the /admin rule", path, d.Rule)
			}
		}
	})
}
