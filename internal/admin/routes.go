package admin

import (
	"net/http"

	"github.com/hersinabil5/warden/internal/config"
)

// routeView is a route as the dashboard shows it: host, upstream, and
// policy. TLS file paths stay out (only whether mTLS is on).
type routeView struct {
	Host        string     `json:"host"`
	Upstream    string     `json:"upstream"`
	UpstreamTLS bool       `json:"upstream_tls"`
	Policy      policyView `json:"policy"`
}

type policyView struct {
	Allow           []ruleView     `json:"allow"`
	Paths           []pathRuleView `json:"paths"`
	CaseInsensitive bool           `json:"case_insensitive_paths"`
}

type pathRuleView struct {
	Prefix string     `json:"prefix"`
	Allow  []ruleView `json:"allow"`
}

// ruleView mirrors config.Rule; absent conditions are omitted.
type ruleView struct {
	Authenticated    *bool    `json:"authenticated,omitempty"`
	Users            []string `json:"users,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	EmailDomains     []string `json:"email_domains,omitempty"`
	RequireMFAWithin string   `json:"require_mfa_within,omitempty"`
}

func ruleViews(rules []config.Rule) []ruleView {
	out := make([]ruleView, 0, len(rules))
	for _, r := range rules {
		v := ruleView{Authenticated: r.Authenticated, Users: r.Users, Groups: r.Groups, EmailDomains: r.EmailDomains}
		if r.RequireMFAWithin != nil {
			v.RequireMFAWithin = r.RequireMFAWithin.String()
		}
		out = append(out, v)
	}
	return out
}

func routeViews(routes []config.Route) []routeView {
	out := make([]routeView, 0, len(routes))
	for _, r := range routes {
		pv := policyView{Allow: ruleViews(r.Policy.Allow), Paths: []pathRuleView{}, CaseInsensitive: r.Policy.CaseInsensitivePaths}
		for _, p := range r.Policy.Paths {
			pv.Paths = append(pv.Paths, pathRuleView{Prefix: p.Prefix, Allow: ruleViews(p.Allow)})
		}
		out = append(out, routeView{Host: r.Host, Upstream: r.Upstream, UpstreamTLS: r.UpstreamTLS != nil, Policy: pv})
	}
	return out
}

func (h *Handler) routes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"routes": h.routeList})
}
