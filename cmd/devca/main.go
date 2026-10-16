// Command devca is the development internal CA. It issues the certificates
// for mTLS between Warden and upstreams: a client certificate for Warden and
// a server certificate for examples/upstream. Development only.
//
// The CA is created once and reused; leaf certificates are reissued on every
// run. The CA is name-constrained to localhost and 127.0.0.1, so even a leaked
// CA key cannot vouch for any other name.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidity   = 365 * 24 * time.Hour
	leafValidity = 90 * 24 * time.Hour

	// ClientName is the CN of Warden's client certificate. Upstreams can
	// require it, so a server certificate from the same CA can't stand in.
	ClientName = "warden-proxy"
)

// Output files, relative to -dir. config/warden.example.yaml and the
// Makefile refer to these names.
const (
	caCert         = "internal-ca.pem"
	caKey          = "internal-ca-key.pem"
	clientCert     = "warden-client.pem"
	clientKey      = "warden-client-key.pem"
	upstreamCert   = "upstream.pem"
	upstreamKeyOut = "upstream-key.pem"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "devca:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, now time.Time) error {
	fsFlags := flag.NewFlagSet("devca", flag.ContinueOnError)
	dir := fsFlags.String("dir", "deploy/certs", "output directory")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}

	ca, caPriv, created, err := loadOrCreateCA(*dir, now)
	if err != nil {
		return err
	}
	if created {
		_, _ = fmt.Fprintln(out, "created internal CA", filepath.Join(*dir, caCert))
	} else {
		_, _ = fmt.Fprintln(out, "reusing internal CA", filepath.Join(*dir, caCert))
	}

	client := &x509.Certificate{
		Subject:     pkix.Name{CommonName: ClientName},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := issue(*dir, clientCert, clientKey, client, ca, caPriv, now); err != nil {
		return err
	}
	server := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "example-upstream"},
		DNSNames:    []string{"localhost", UpstreamDockerName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if err := issue(*dir, upstreamCert, upstreamKeyOut, server, ca, caPriv, now); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "issued %s and %s (valid %v)\n", clientCert, upstreamCert, leafValidity)
	return nil
}

// UpstreamDockerName is the example upstream's name on the compose network
// (D25). It is under localhost, so the CA's name constraint still holds.
const UpstreamDockerName = "example-upstream.localhost"

func loadOrCreateCA(dir string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, bool, error) {
	certPath, keyPath := filepath.Join(dir, caCert), filepath.Join(dir, caKey)
	certPEM, certErr := os.ReadFile(certPath) //nolint:gosec // G304: operator-chosen directory
	keyPEM, keyErr := os.ReadFile(keyPath)    //nolint:gosec // G304: operator-chosen directory
	switch {
	case certErr == nil && keyErr == nil:
		cert, key, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, nil, false, fmt.Errorf("existing CA in %s: %w", dir, err)
		}
		if now.After(cert.NotAfter) {
			return nil, nil, false, fmt.Errorf("CA %s expired; delete it and its key to create a new one", certPath)
		}
		return cert, key, false, nil
	case errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist):
	default:
		return nil, nil, false, fmt.Errorf("found only one of %s and %s; remove it or restore the other", caCert, caKey)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	_, loopback6, _ := net.ParseCIDR("::1/128")
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "Warden dev internal CA", Organization: []string{"Warden (development only)"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(caValidity),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"localhost"},
		PermittedIPRanges:           []*net.IPNet{loopback, loopback6},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, false, err
	}
	if werr := writeKey(keyPath, key); werr != nil {
		return nil, nil, false, werr
	}
	if werr := writeCert(certPath, der); werr != nil {
		return nil, nil, false, werr
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, true, err
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) || !cert.IsCA {
		return nil, nil, errors.New("key does not match a CA certificate")
	}
	return cert, key, nil
}

func issue(dir, certName, keyName string, tmpl, ca *x509.Certificate, caKey *ecdsa.PrivateKey, now time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = now.Add(-time.Hour)
	tmpl.NotAfter = now.Add(leafValidity)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("issuing %s: %w", certName, err)
	}
	if err := writeKey(filepath.Join(dir, keyName), key); err != nil {
		return err
	}
	return writeCert(filepath.Join(dir, certName), der)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return n
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

func writeCert(path string, der []byte) error {
	return writeFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// writeFile replaces path atomically, so a crash never leaves a half-written
// key next to a new certificate.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".devca-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
