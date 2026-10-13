package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/hersinabil5/warden/internal/identity"
)

const (
	issuer   = "https://auth.example.test"
	audience = "app.example.test"
)

func testSigner(t *testing.T, ttl time.Duration, now func() time.Time) *identity.Signer {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := identity.NewSigner(k, nil, identity.SignerOptions{Issuer: issuer, TTL: ttl, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keysOf(t *testing.T, s *identity.Signer) identity.KeyFunc {
	t.Helper()
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(s.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
		for _, k := range set.Key(kid) {
			if pub, ok := k.Key.(*ecdsa.PublicKey); ok {
				return pub, nil
			}
		}
		return nil, identity.ErrUnknownKey
	}
}

func TestHandler(t *testing.T) {
	s := testSigner(t, time.Minute, nil)
	h := newHandler(&identity.Verifier{Issuer: issuer, Audience: audience, Keys: keysOf(t, s)},
		"X-Warden-Identity", slog.New(slog.DiscardHandler))
	alice := identity.Claims{Subject: "u-1", Username: "alice", Email: "alice@warden.local", Groups: []string{"admins"}}
	good, _ := s.Assert(alice, audience)
	forGrafana, _ := s.Assert(alice, "grafana.example.test")
	expired, _ := testSigner(t, time.Minute, func() time.Time { return time.Now().Add(-time.Hour) }).Assert(alice, audience)
	otherKey, _ := testSigner(t, time.Minute, nil).Assert(alice, audience)

	for name, tt := range map[string]struct {
		headers []string
		want    int
	}{
		"valid":                 {[]string{good}, 200},
		"missing":               {nil, 401},
		"garbage":               {[]string{"forged"}, 401},
		"wrong audience":        {[]string{forGrafana}, 401},
		"expired":               {[]string{expired}, 401},
		"signed by another key": {[]string{otherKey}, 401},
		"two headers":           {[]string{good, good}, 401},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
			for _, v := range tt.headers {
				req.Header.Add("X-Warden-Identity", v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			body := rec.Body.String()
			if tt.want == 200 && (!strings.Contains(body, "Hello, alice.") || !strings.Contains(body, "admins")) {
				t.Errorf("body = %q", body)
			}
			if tt.want != 200 && strings.Contains(body, "alice") {
				t.Errorf("rejected request leaks identity: %q", body)
			}
		})
	}
}

// pki issues test certificates.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{c, k}
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

func (p *pki) issue(t *testing.T, cn string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &k.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// PLAN.md M4 acceptance: connecting without Warden's client certificate fails.
func TestServerRequiresWardenClientCert(t *testing.T) {
	internal, other := newPKI(t), newPKI(t)
	s := testSigner(t, time.Minute, nil)
	srv := httptest.NewUnstartedServer(newHandler(
		&identity.Verifier{Issuer: issuer, Audience: audience, Keys: keysOf(t, s)}, "X-Warden-Identity", slog.New(slog.DiscardHandler)))
	srv.TLS = serverTLS(internal.issue(t, "upstream", x509.ExtKeyUsageServerAuth), internal.pool(), "warden-proxy")
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.StartTLS()
	defer srv.Close()
	tok, _ := s.Assert(identity.Claims{Subject: "u-1", Username: "alice"}, audience)

	call := func(t *testing.T, certs []tls.Certificate) (int, error) {
		t.Helper()
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: internal.pool(), Certificates: certs, MinVersion: tls.VersionTLS13,
		}}}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		req.Header.Set("X-Warden-Identity", tok)
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	if code, err := call(t, []tls.Certificate{internal.issue(t, "warden-proxy", x509.ExtKeyUsageClientAuth)}); err != nil || code != 200 {
		t.Fatalf("Warden's cert: %d, %v", code, err)
	}
	for name, certs := range map[string][]tls.Certificate{
		"no client certificate":       nil,
		"client cert from another CA": {other.issue(t, "warden-proxy", x509.ExtKeyUsageClientAuth)},
		"same CA, wrong name":         {internal.issue(t, "intruder", x509.ExtKeyUsageClientAuth)},
		"same CA, server certificate": {internal.issue(t, "warden-proxy", x509.ExtKeyUsageServerAuth)},
	} {
		if code, err := call(t, certs); err == nil {
			t.Errorf("%s: request succeeded with %d", name, code)
		}
	}
}

func TestParseFlags(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil || o.listen != "127.0.0.1:9003" || o.audience != "app.warden.localhost" {
		t.Errorf("defaults: %+v, %v", o, err)
	}
	if _, err := parseFlags([]string{"extra"}); err == nil {
		t.Error("positional argument accepted")
	}
}
