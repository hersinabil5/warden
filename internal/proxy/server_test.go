package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testCert returns a self-signed certificate for the given DNS names.
func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func TestNewServerSetsTimeouts(t *testing.T) {
	srv := NewServer(http.NotFoundHandler(), DefaultServerTimeouts, slog.New(slog.DiscardHandler))
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("server timeouts must all be set (invariant 10): %+v", DefaultServerTimeouts)
	}
	if srv.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes not set")
	}
}

func TestTLSConfigRejectsOldVersions(t *testing.T) {
	cert, pool := testCert(t, "app.example.test")
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = NewTLSConfig(cert)
	srv.StartTLS()
	defer srv.Close()

	for _, tt := range []struct {
		name    string
		max     uint16
		wantErr bool
	}{
		{"TLS 1.0", tls.VersionTLS10, true},
		{"TLS 1.1", tls.VersionTLS11, true},
		{"TLS 1.2", tls.VersionTLS12, false},
		{"TLS 1.3", tls.VersionTLS13, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clientCfg := &tls.Config{ //nolint:gosec // G402: deliberately offers old versions to prove the server refuses them
				ServerName: "app.example.test",
				RootCAs:    pool,
				MinVersion: tls.VersionTLS10,
				MaxVersion: tt.max,
			}
			d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: clientCfg}
			conn, err := d.DialContext(t.Context(), "tcp", srv.Listener.Addr().String())
			if err == nil {
				_ = conn.Close()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("handshake err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
