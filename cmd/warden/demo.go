package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hersinabil5/warden/internal/admin"
	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/demo"
	"github.com/hersinabil5/warden/internal/session"
)

// newLanding builds the demo landing page from the config: the demo
// accounts, then every route (and protected path) with who may open it.
// It returns nil without demo mode.
func newLanding(cfg *config.Config, nextReset func() time.Time) (http.Handler, error) {
	if cfg.Demo == nil {
		return nil, nil //nolint:nilnil // no demo section: no landing page
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, err
	}
	origin := func(host string) string {
		if port == "443" {
			return "https://" + host
		}
		return "https://" + net.JoinHostPort(host, port)
	}
	opts := demo.PageOptions{NextReset: nextReset}
	for _, a := range cfg.Demo.Accounts {
		opts.Accounts = append(opts.Accounts, demo.Account{
			Username: a.Username, Password: a.Password, Description: a.Description, OTPKey: a.OTPKey,
		})
	}
	for _, r := range cfg.Routes {
		opts.Links = append(opts.Links, demo.Link{Label: r.Host, URL: origin(r.Host) + "/", Note: whoMay(r.Policy.Allow)})
		for _, p := range r.Policy.Paths {
			opts.Links = append(opts.Links, demo.Link{
				Label: r.Host + p.Prefix, URL: origin(r.Host) + p.Prefix, Note: whoMay(p.Allow),
			})
		}
	}
	if cfg.Admin != nil {
		opts.Links = append(opts.Links, demo.Link{
			Label: "Admin dashboard", URL: origin(cfg.Auth.Domain) + admin.DashboardPrefix, Note: whoMay(cfg.Admin.Allow),
		})
	}
	return demo.NewPage(opts)
}

// demoReset wipes demo state: every session (open WebSockets close at their
// next re-check) and the in-memory decisions the dashboard shows. The audit
// sink keeps its records; they are the operator's, not the visitors'.
func demoReset(sessions *session.Store, recent *audit.Recent, logger *slog.Logger) func(context.Context) error {
	return func(ctx context.Context) error {
		n, err := sessions.RevokeAll(ctx)
		recent.Reset()
		if err != nil {
			return err
		}
		logger.Info("demo reset", "sessions", n)
		return nil
	}
}

// whoMay describes allow rules in a few words, for the landing page.
func whoMay(rules []config.Rule) string {
	var alts []string
	for _, r := range rules {
		var parts []string
		if r.Authenticated != nil && *r.Authenticated {
			parts = append(parts, "any signed-in user")
		}
		if r.Users != nil {
			parts = append(parts, "users "+strings.Join(r.Users, ", "))
		}
		if r.Groups != nil {
			parts = append(parts, "groups "+strings.Join(r.Groups, ", "))
		}
		if r.EmailDomains != nil {
			parts = append(parts, "email @"+strings.Join(r.EmailDomains, ", @"))
		}
		if r.RequireMFAWithin != nil {
			parts = append(parts, "MFA within "+shortDuration(*r.RequireMFAWithin))
		}
		alts = append(alts, strings.Join(parts, " with "))
	}
	if len(alts) == 0 {
		return "nobody"
	}
	return strings.Join(alts, "; or ")
}

// shortDuration drops time.Duration's zero units: 10m, not 10m0s.
func shortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
