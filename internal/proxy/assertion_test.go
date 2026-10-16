package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/hersinabil5/warden/internal/identity"
	"github.com/hersinabil5/warden/internal/session"
)

func verifierFor(t *testing.T, s *identity.Signer, aud string) *identity.Verifier {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(s.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	return &identity.Verifier{
		Issuer: "https://auth.example.test", Audience: aud,
		Keys: func(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
			for _, k := range set.Key(kid) {
				if pub, ok := k.Key.(*ecdsa.PublicKey); ok {
					return pub, nil
				}
			}
			return nil, identity.ErrUnknownKey
		},
	}
}

// PLAN.md M4 acceptance: a forged X-Warden-Identity or X-Forwarded-Email is
// replaced by the real, signed identity.
func TestUpstreamGetsSignedIdentity(t *testing.T) {
	up := newEcho(t)
	signer := testIdentity(t)
	sess := &session.Session{Subject: "b-1", Username: "bob", Email: "bob@warden.local", Groups: []string{"dev"}}
	h, err := New(policyConfig(t, up.URL, false), Options{Audit: nopAudit{},
		Identity: signer, Authenticator: asUser{sess}, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}

	var jtis []string
	for range 2 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		req.Host = "whoami.example.test"
		req.Header.Set("X-Warden-Identity", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
		req.Header.Set("X-Forwarded-Email", "admin@warden.local")
		seen := decodeSeen(t, serve(h, req))

		if got := seen.Header.Values("X-Warden-Identity"); len(got) != 1 {
			t.Fatalf("upstream got %d identity headers", len(got))
		}
		if seen.Header.Get("X-Forwarded-Email") != "" {
			t.Errorf("forged X-Forwarded-Email reached the upstream")
		}
		raw := seen.Header.Get("X-Warden-Identity")
		id, err := verifierFor(t, signer, "whoami.example.test").Verify(t.Context(), raw)
		if err != nil {
			t.Fatalf("assertion does not verify: %v", err)
		}
		if id.Subject != "b-1" || id.Username != "bob" || id.Email != "bob@warden.local" || strings.Join(id.Groups, ",") != "dev" {
			t.Errorf("identity = %+v", id)
		}
		// Bound to this host: another upstream must reject it.
		if _, err := verifierFor(t, signer, "grafana.example.test").Verify(t.Context(), raw); err == nil {
			t.Error("whoami's assertion verifies for grafana")
		}
		jtis = append(jtis, id.ID)
	}
	if jtis[0] == jtis[1] {
		t.Error("assertion reused across requests")
	}
}

type failingAsserter struct{}

func (failingAsserter) Assert(identity.Claims, string) (string, error) {
	return "", errors.New("hsm on fire")
}

// If signing fails the request fails closed: no upstream call, generic 500.
func TestAssertionFailureFailsClosed(t *testing.T) {
	up := newEcho(t)
	var logs bytes.Buffer
	h, err := New(testConfig(t, up.URL), Options{Audit: nopAudit{},
		Identity: failingAsserter{}, Authenticator: allowAll{}, Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	rec := serve(h, req)
	if rec.Code != http.StatusInternalServerError || up.hits.Load() != 0 {
		t.Errorf("status %d, upstream hits %d; want 500 and none", rec.Code, up.hits.Load())
	}
	if strings.Contains(rec.Body.String(), "hsm") || !strings.Contains(logs.String(), "hsm on fire") {
		t.Errorf("cause should be logged, not shown: body %q", rec.Body.String())
	}
}

// Denied requests carry no assertion anywhere (nothing is signed).
func TestNoAssertionWithoutAllow(t *testing.T) {
	up := newEcho(t)
	var logs bytes.Buffer
	h := policyHandler(t, policyConfig(t, up.URL, false), bobSess, &logs)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "grafana.example.test"
	rec := serve(h, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Warden-Identity") != "" {
		t.Errorf("status %d, identity header %q", rec.Code, rec.Header().Get("X-Warden-Identity"))
	}
}

func TestNewRequiresIdentity(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	if _, err := New(cfg, Options{Audit: nopAudit{}, Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("New accepted no asserter")
	}
	cfg.Identity.Header = ""
	if _, err := New(cfg, Options{Audit: nopAudit{}, Identity: testIdentity(t), Logger: slog.New(slog.DiscardHandler)}); err == nil {
		t.Error("New accepted no identity header")
	}
}

// The JWKS is served on the auth host only, without authentication.
func TestJWKSOnAuthHost(t *testing.T) {
	up := newEcho(t)
	signer := testIdentity(t)
	deny := &denyAll{}
	h, err := New(testConfig(t, up.URL), Options{Audit: nopAudit{},
		Identity: signer, JWKS: signer.JWKSHandler(), Authenticator: deny, Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://auth.example.test/.well-known/jwks.json", nil)
	rec := serve(h, req)
	if rec.Code != http.StatusOK || rec.Body.String() != string(signer.JWKS()) {
		t.Errorf("auth host: %d %q", rec.Code, rec.Body.String())
	}
	// On an app host the path is the app's: it goes through login like any other.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.example.test/.well-known/jwks.json", nil)
	if rec := serve(h, req); rec.Code != http.StatusFound || len(deny.hosts) != 1 {
		t.Errorf("app host: %d, authenticator calls %d; want the login redirect", rec.Code, len(deny.hosts))
	}
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://unknown.example/.well-known/jwks.json", nil)
	if rec := serve(h, req); rec.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d, want 404", rec.Code)
	}
}
