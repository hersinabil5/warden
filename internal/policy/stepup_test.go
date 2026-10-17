package policy

import (
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

func subj(groups []string, amr []string, age time.Duration) *Subject {
	s := &Subject{Username: "u", Groups: groups, AMR: amr}
	if age >= 0 {
		s.AuthTime = now.Add(-age)
	}
	return s
}

// StepUp means "a fresh MFA login would satisfy a rule": every other
// condition of that rule already holds.
func TestStepUp(t *testing.T) {
	g := grafana(t, false)
	mfa := []string{"pwd", "otp"}
	pwd := []string{"pwd"}
	for _, tt := range []struct {
		name   string
		path   string
		s      *Subject
		allow  bool
		stepUp bool
	}{
		{"recent MFA is allowed", "/admin", subj([]string{"admins"}, mfa, 3*time.Minute), true, false},
		{"MFA too old", "/admin", subj([]string{"admins"}, mfa, time.Hour), false, true},
		{"password only", "/admin", subj([]string{"admins"}, pwd, time.Hour), false, true},
		{"no auth_time", "/admin", subj([]string{"admins"}, mfa, -1), false, true},
		// Re-authenticating cannot change group membership.
		{"wrong group", "/admin", subj([]string{"sre"}, pwd, time.Hour), false, false},
		{"no groups", "/admin", subj(nil, mfa, time.Hour), false, false},
		// Loop protection: a login this fresh just happened, possibly as a
		// step-up; prompting again would not help.
		{"fresh login without MFA", "/admin", subj([]string{"admins"}, pwd, time.Minute), false, false},
		{"just under the grace", "/admin", subj([]string{"admins"}, pwd, StepUpGrace), false, false},
		{"just over the grace", "/admin", subj([]string{"admins"}, pwd, StepUpGrace+time.Second), false, true},
		{"no MFA rule involved", "/", subj([]string{"dev"}, pwd, time.Hour), false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := g.Evaluate(Input{Path: tt.path, Subject: tt.s, Now: now})
			if d.Allow != tt.allow || d.StepUp != tt.stepUp {
				t.Errorf("allow=%v stepUp=%v, want %v %v (%s: %s)", d.Allow, d.StepUp, tt.allow, tt.stepUp, d.Rule, d.Reason)
			}
		})
	}
}

// A clock problem is not something a login fixes.
func TestStepUpFutureAuthTime(t *testing.T) {
	s := &Subject{Username: "u", Groups: []string{"admins"}, AMR: []string{"pwd", "otp"}, AuthTime: now.Add(time.Hour)}
	if d := grafana(t, false).Evaluate(Input{Path: "/admin", Subject: s, Now: now}); d.Allow || d.StepUp {
		t.Errorf("future auth_time: %+v", d)
	}
}

// Any rule that would match after a step-up is enough; others failing for
// other reasons don't matter.
func TestStepUpAnyRule(t *testing.T) {
	p := mustCompile(t, config.Policy{Allow: []config.Rule{
		{Users: []string{"carol"}},
		{Groups: []string{"admins"}, RequireMFAWithin: ptr(10 * time.Minute)},
	}})
	if d := p.Evaluate(Input{Path: "/", Subject: subj([]string{"admins"}, []string{"pwd"}, time.Hour), Now: now}); d.Allow || !d.StepUp {
		t.Errorf("%+v, want a step-up", d)
	}
}

func TestStepUpFailsClosedOnBadInput(t *testing.T) {
	g := grafana(t, false)
	stale := subj([]string{"admins"}, []string{"pwd"}, time.Hour)
	for _, in := range []Input{
		{Path: "/admin", Subject: nil, Now: now},
		{Path: "/admin", Subject: stale},
		{Path: "", Subject: stale, Now: now},
		{Path: "/x/../admin", Subject: stale, Now: now},
	} {
		if d := g.Evaluate(in); d.Allow || d.StepUp {
			t.Errorf("%+v: %+v", in, d)
		}
	}
	var none *Policy
	if d := none.Evaluate(Input{Path: "/", Subject: stale, Now: now}); d.StepUp {
		t.Errorf("nil policy offered a step-up")
	}
}
