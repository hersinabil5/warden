package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

// testPKI is a throwaway CA with helpers to issue leaves and write PEM files.
type testPKI struct {
	t    *testing.T
	dir  string
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testPKI{t: t, dir: t.TempDir(), cert: cert, key: key}
}

func (p *testPKI) caFile(name string) string {
	return p.write(name, "CERTIFICATE", p.cert.Raw)
}

func (p *testPKI) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

// leaf issues a certificate; it returns the tls pair and PEM file paths.
func (p *testPKI) leaf(name string, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
	p.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		p.t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPath := p.write(name+".pem", "CERTIFICATE", der)
	keyPath := p.write(name+"-key.pem", "PRIVATE KEY", keyDER)
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		p.t.Fatal(err)
	}
	return pair, certPath, keyPath
}

func (p *testPKI) write(name, typ string, der []byte) string {
	p.t.Helper()
	path := filepath.Join(p.dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		p.t.Fatal(err)
	}
	return path
}

// mtlsUpstream requires a client certificate from clientCA.
func mtlsUpstream(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello "+r.TLS.PeerCertificates[0].Subject.CommonName) //nolint:gosec // G705: test upstream, plain text
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCA,
		MinVersion:   tls.VersionTLS13,
	}
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func mtlsHandler(t *testing.T, upstream string, up *config.UpstreamTLS) (*Handler, error) {
	t.Helper()
	cfg := testConfig(t, upstream)
	u, _ := url.Parse(upstream)
	cfg.Routes[0].UpstreamURL = u
	cfg.Routes[0].UpstreamTLS = up
	return New(cfg, Options{Identity: testIdentity(t), Authenticator: allowAll{}, Logger: slog.New(slog.DiscardHandler),
		TransportTimeouts: fastTimeouts})
}

func get(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Host = "app.example.test"
	return serve(h, req)
}

func TestMTLSToUpstream(t *testing.T) {
	internal := newTestPKI(t)
	serverCert, _, _ := internal.leaf("upstream", x509.ExtKeyUsageServerAuth)
	_, clientCertFile, clientKeyFile := internal.leaf("warden-proxy", x509.ExtKeyUsageClientAuth)
	srv := mtlsUpstream(t, serverCert, internal.pool())

	h, err := mtlsHandler(t, srv.URL, &config.UpstreamTLS{
		CAFile: internal.caFile("ca.pem"), ClientCertFile: clientCertFile, ClientKeyFile: clientKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, h); rec.Code != http.StatusOK || rec.Body.String() != "hello warden-proxy" {
		t.Fatalf("mTLS request: %d %q", rec.Code, rec.Body.String())
	}
}

// Every way the handshake should fail does, and the client sees a 502.
func TestMTLSFailsClosed(t *testing.T) {
	internal, other := newTestPKI(t), newTestPKI(t)
	serverCert, _, _ := internal.leaf("upstream", x509.ExtKeyUsageServerAuth)
	_, clientCertFile, clientKeyFile := internal.leaf("warden-proxy", x509.ExtKeyUsageClientAuth)
	_, otherClientCert, otherClientKey := other.leaf("intruder", x509.ExtKeyUsageClientAuth)
	impostorCert, _, _ := other.leaf("impostor", x509.ExtKeyUsageServerAuth)
	srv := mtlsUpstream(t, serverCert, internal.pool())
	impostor := mtlsUpstream(t, impostorCert, internal.pool())

	for name, tt := range map[string]struct {
		upstream string
		tls      *config.UpstreamTLS
	}{
		"no client certificate": {srv.URL, &config.UpstreamTLS{CAFile: internal.caFile("ca1.pem")}},
		"client cert from another CA": {srv.URL, &config.UpstreamTLS{
			CAFile: internal.caFile("ca2.pem"), ClientCertFile: otherClientCert, ClientKeyFile: otherClientKey}},
		"upstream cert from another CA": {impostor.URL, &config.UpstreamTLS{
			CAFile: internal.caFile("ca3.pem"), ClientCertFile: clientCertFile, ClientKeyFile: clientKeyFile}},
		"trusting the wrong CA": {srv.URL, &config.UpstreamTLS{
			CAFile: other.caFile("ca4.pem"), ClientCertFile: clientCertFile, ClientKeyFile: clientKeyFile}},
	} {
		t.Run(name, func(t *testing.T) {
			h, err := mtlsHandler(t, tt.upstream, tt.tls)
			if err != nil {
				t.Fatal(err)
			}
			if rec := get(t, h); rec.Code != http.StatusBadGateway {
				t.Errorf("status %d, want 502", rec.Code)
			}
		})
	}
}

// Without upstream_tls, a TLS upstream is checked against the system roots,
// which do not include a private CA.
func TestPlainHTTPSDoesNotTrustPrivateCA(t *testing.T) {
	internal := newTestPKI(t)
	serverCert, _, _ := internal.leaf("upstream", x509.ExtKeyUsageServerAuth)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	srv.Config.ErrorLog = slog.NewLogLogger(slog.DiscardHandler, slog.LevelError)
	srv.StartTLS()
	defer srv.Close()
	h, err := mtlsHandler(t, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, h); rec.Code != http.StatusBadGateway {
		t.Errorf("status %d, want 502", rec.Code)
	}
}

func TestMTLSConfigErrorsFailStartup(t *testing.T) {
	internal := newTestPKI(t)
	_, certFile, keyFile := internal.leaf("warden-proxy", x509.ExtKeyUsageClientAuth)
	notPEM := internal.write("junk.pem", "NOTHING", []byte("x"))
	for name, up := range map[string]*config.UpstreamTLS{
		"missing CA file":       {CAFile: filepath.Join(internal.dir, "nope.pem")},
		"CA file without certs": {CAFile: notPEM},
		"missing client key":    {CAFile: internal.caFile("ca.pem"), ClientCertFile: certFile, ClientKeyFile: filepath.Join(internal.dir, "nope")},
		"mismatched pair":       {CAFile: internal.caFile("ca.pem"), ClientCertFile: certFile, ClientKeyFile: internal.caFile("not-a-key.pem")},
	} {
		if _, err := mtlsHandler(t, "https://127.0.0.1:1", up); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	_ = keyFile
}
