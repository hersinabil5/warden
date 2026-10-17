package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/pathnorm"
)

// authTimeSkew tolerates a small clock difference between Warden and the
// IdP when checking auth_time for require_mfa_within.
const authTimeSkew = time.Minute

// Subject is the authenticated user a request is evaluated for.
type Subject struct {
	Username string
	Email    string // verified email only; empty otherwise
	Groups   []string
	AMR      []string // RFC 8176 authentication method references
	AuthTime time.Time
}

// Input is everything a decision depends on. Path must already be normalized
// by pathnorm.Normalize; anything else is denied.
type Input struct {
	Path    string
	Subject *Subject // nil means unauthenticated
	Now     time.Time
}

// Decision is the outcome of Evaluate. Rule and Reason are for logs and
// audit only, never for the client.
type Decision struct {
	Allow  bool
	Rule   string // the rule that allowed, or the rule set that denied
	Reason string
	// StepUp is set on a deny that a fresh multi-factor login would turn
	// into an allow: some rule fails only on require_mfa_within, and the
	// current login is older than StepUpGrace.
	StepUp bool
}

// StepUpGrace is how old a login must be before a step-up is offered. A
// login younger than this may be the step-up itself; if it still falls
// short (no second factor enrolled), prompting again would loop.
const StepUpGrace = 2 * time.Minute

// Policy is a compiled route policy. The zero value denies everything.
type Policy struct {
	base            ruleSet
	paths           []pathSet // most specific (most segments) first
	caseInsensitive bool
}

type ruleSet struct {
	name  string // "allow" or "paths[/prefix]"
	rules []rule
}

type pathSet struct {
	prefix   string
	segments []string // prefix split on "/"; empty for "/"
	ruleSet
}

type rule struct {
	authenticated bool
	users         []string
	groups        []string
	emailDomains  []string
	mfaWithin     time.Duration // 0 means no MFA condition
}

// Compile checks a route policy and prepares it for evaluation. It repeats
// the config package's checks so a policy built any other way cannot slip
// through with an ambiguous rule.
func Compile(p config.Policy) (*Policy, error) {
	base, err := compileRules("allow", p.Allow)
	if err != nil {
		return nil, err
	}
	out := &Policy{base: base, caseInsensitive: p.CaseInsensitivePaths}
	for _, pr := range p.Paths {
		prefix, err := canonicalPrefix(pr.Prefix)
		if err != nil {
			return nil, err
		}
		name := "paths[" + prefix + "]"
		for _, other := range out.paths {
			if other.prefix == prefix || (p.CaseInsensitivePaths && strings.EqualFold(other.prefix, prefix)) {
				return nil, fmt.Errorf("%s: duplicate of paths[%s]", name, other.prefix)
			}
		}
		rs, err := compileRules(name+".allow", pr.Allow)
		if err != nil {
			return nil, err
		}
		rs.name = name
		out.paths = append(out.paths, pathSet{prefix: prefix, segments: splitPath(prefix), ruleSet: rs})
	}
	// Longest prefix wins: try the deepest prefixes first. Equal depths
	// cannot both match one path, since duplicates are rejected above.
	slices.SortStableFunc(out.paths, func(a, b pathSet) int { return len(b.segments) - len(a.segments) })
	return out, nil
}

// canonicalPrefix requires a prefix already in normalized form (a prefix
// such as /%61dmin would never match a normalized path) and drops a trailing
// slash, so /admin/ also protects /admin itself.
func canonicalPrefix(prefix string) (string, error) {
	if !pathnorm.IsNormalized(prefix) || strings.ContainsAny(prefix, "%?#") {
		return "", fmt.Errorf("path prefix %q is not a normalized path", prefix)
	}
	if prefix != "/" {
		prefix = strings.TrimSuffix(prefix, "/")
	}
	return prefix, nil
}

func compileRules(name string, in []config.Rule) (ruleSet, error) {
	if len(in) == 0 {
		return ruleSet{}, fmt.Errorf("%s: at least one rule is required", name)
	}
	rs := ruleSet{name: "allow", rules: make([]rule, 0, len(in))}
	for i, r := range in {
		field := fmt.Sprintf("%s[%d]", name, i)
		if r.Authenticated == nil && r.Users == nil && r.Groups == nil && r.EmailDomains == nil && r.RequireMFAWithin == nil {
			return ruleSet{}, fmt.Errorf("%s: empty rule", field)
		}
		if r.Authenticated != nil && !*r.Authenticated {
			return ruleSet{}, fmt.Errorf("%s: authenticated: false is not supported", field)
		}
		for _, l := range [][]string{r.Users, r.Groups, r.EmailDomains} {
			if l != nil && len(l) == 0 {
				return ruleSet{}, fmt.Errorf("%s: empty list", field)
			}
			if slices.Contains(l, "") {
				return ruleSet{}, fmt.Errorf("%s: empty entry", field)
			}
		}
		c := rule{
			authenticated: r.Authenticated != nil,
			users:         slices.Clone(r.Users),
			groups:        slices.Clone(r.Groups),
		}
		for _, d := range r.EmailDomains {
			c.emailDomains = append(c.emailDomains, strings.ToLower(d))
		}
		if r.RequireMFAWithin != nil {
			if *r.RequireMFAWithin <= 0 {
				return ruleSet{}, fmt.Errorf("%s: require_mfa_within must be positive", field)
			}
			c.mfaWithin = *r.RequireMFAWithin
		}
		rs.rules = append(rs.rules, c)
	}
	return rs, nil
}

// Evaluate decides one request. It is a pure function of the policy and the
// input. Default deny (invariant 1): no matching rule, or anything malformed,
// is a deny.
func (p *Policy) Evaluate(in Input) Decision {
	switch {
	case p == nil || len(p.base.rules) == 0:
		return Decision{Rule: "policy", Reason: "no policy"}
	case in.Now.IsZero():
		return Decision{Rule: "input", Reason: "no evaluation time"}
	case in.Path == "":
		return Decision{Rule: "input", Reason: "empty path"}
	}
	if !pathnorm.IsNormalized(in.Path) {
		return Decision{Rule: "input", Reason: "path is not normalized"}
	}
	if in.Subject == nil {
		return Decision{Rule: "input", Reason: "unauthenticated"}
	}

	rs := p.ruleSetFor(in.Path)
	var failures []string
	mfaOnly := false
	for i, r := range rs.rules {
		ruleName := fmt.Sprintf("%s[%d]", rs.ruleName(), i)
		if why, fixable := r.mismatch(in.Subject, in.Now); why != "" {
			failures = append(failures, ruleName+": "+why)
			mfaOnly = mfaOnly || fixable
			continue
		}
		return Decision{Allow: true, Rule: ruleName, Reason: "matched"}
	}
	stale := in.Subject.AuthTime.IsZero() || in.Now.Sub(in.Subject.AuthTime) > StepUpGrace
	return Decision{Rule: rs.name, Reason: "no allow rule matched (" + strings.Join(failures, "; ") + ")",
		StepUp: mfaOnly && stale}
}

func (rs ruleSet) ruleName() string {
	if rs.name == "allow" {
		return "allow"
	}
	return rs.name + ".allow"
}

// ruleSetFor returns the rule set of the longest path prefix containing
// path, matched segment by segment, or the route's base rules.
func (p *Policy) ruleSetFor(path string) ruleSet {
	segs := splitPath(path)
	eq := func(a, b string) bool { return a == b }
	if p.caseInsensitive {
		eq = strings.EqualFold
	}
	for _, ps := range p.paths {
		if len(segs) < len(ps.segments) {
			continue
		}
		match := true
		for i, s := range ps.segments {
			if !eq(segs[i], s) {
				match = false
				break
			}
		}
		if match {
			return ps.ruleSet
		}
	}
	return p.base
}

// splitPath splits a normalized path into its segments; "/" has none.
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// mismatch returns why s does not satisfy r, or "" if it does. All of a
// rule's conditions must hold. fixable reports that only the MFA condition
// failed, in a way a fresh multi-factor login would fix.
func (r rule) mismatch(s *Subject, now time.Time) (why string, fixable bool) {
	switch {
	case r.users != nil && !slices.Contains(r.users, s.Username):
		return "user not listed", false
	case r.groups != nil && !slices.ContainsFunc(s.Groups, func(g string) bool { return slices.Contains(r.groups, g) }):
		return "not in a listed group", false
	case r.emailDomains != nil && !slices.Contains(r.emailDomains, emailDomain(s.Email)):
		return "email domain not allowed", false
	case r.mfaWithin > 0:
		return mfaMismatch(s, now, r.mfaWithin)
	}
	return "", false
}

func mfaMismatch(s *Subject, now time.Time, within time.Duration) (string, bool) {
	switch {
	case !isMFA(s.AMR):
		return "no multi-factor authentication", !s.AuthTime.After(now.Add(authTimeSkew))
	case s.AuthTime.IsZero():
		return "no auth_time", true
	case s.AuthTime.After(now.Add(authTimeSkew)):
		return "auth_time in the future", false // a clock problem; a login won't fix it
	case now.Sub(s.AuthTime) > within:
		return "authentication too old", true
	}
	return "", false
}

// emailDomain returns the lowercased domain of a single-@ address, or "".
func emailDomain(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return ""
	}
	return strings.ToLower(domain)
}

// amrMethods is the RFC 8176 registry of authentication method values.
var amrMethods = []string{
	"face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin",
	"pop", "pwd", "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia",
}

// isMFA reports whether amr shows more than one factor: the explicit "mfa"
// value, or at least two distinct registered methods (Keycloak sends
// ["pwd", "otp"]). A single strong method alone does not count.
func isMFA(amr []string) bool {
	if slices.Contains(amr, "mfa") {
		return true
	}
	seen := map[string]bool{}
	for _, m := range amr {
		if slices.Contains(amrMethods, m) {
			seen[m] = true
		}
	}
	return len(seen) >= 2
}
