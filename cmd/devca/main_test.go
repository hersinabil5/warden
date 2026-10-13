package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: not PEM", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssuesUsableChain(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := run([]string{"-dir", dir}, io.Discard, now); err != nil {
		t.Fatal(err)
	}
	ca := readCert(t, filepath.Join(dir, caCert))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := readCert(t, filepath.Join(dir, clientCert))
	server := readCert(t, filepath.Join(dir, upstreamCert))

	if client.Subject.CommonName != ClientName {
		t.Errorf("client CN = %q", client.Subject.CommonName)
	}
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client cert does not verify for client auth: %v", err)
	}
	for _, name := range []string{"127.0.0.1", "localhost", "::1"} {
		if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err != nil {
			t.Errorf("server cert does not verify for %s: %v", name, err)
		}
	}
	// Each certificate works only for its role.
	if _, err := client.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("client cert verifies as a server cert")
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("server cert verifies as a client cert")
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.example"}); err == nil {
		t.Error("server cert verifies for another name")
	}
	if !ca.IsCA || !ca.MaxPathLenZero || client.IsCA || server.IsCA {
		t.Error("wrong CA flags")
	}
	if got := server.NotAfter.Sub(now); got > leafValidity+time.Minute {
		t.Errorf("leaf validity %v", got)
	}

	for name, want := range map[string]os.FileMode{caKey: 0o600, clientKey: 0o600, upstreamKeyOut: 0o600, caCert: 0o644} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s mode %v, want %v", name, fi.Mode().Perm(), want)
		}
	}
}

// The CA is reused across runs; leaf certificates are reissued.
func TestReusesCA(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"-dir", dir}, io.Discard, time.Now()); err != nil {
		t.Fatal(err)
	}
	ca1, leaf1 := readCert(t, filepath.Join(dir, caCert)), readCert(t, filepath.Join(dir, clientCert))
	if err := run([]string{"-dir", dir}, io.Discard, time.Now()); err != nil {
		t.Fatal(err)
	}
	ca2, leaf2 := readCert(t, filepath.Join(dir, caCert)), readCert(t, filepath.Join(dir, clientCert))
	if !ca1.Equal(ca2) {
		t.Error("CA replaced on second run")
	}
	if leaf1.Equal(leaf2) {
		t.Error("leaf not reissued")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca2)
	if _, err := leaf2.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("reissued leaf does not chain to the kept CA: %v", err)
	}
}

func TestRefusesHalfACA(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caCert), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-dir", dir}, io.Discard, time.Now()); err == nil {
		t.Error("ran with a CA certificate but no key")
	}
}

func TestRefusesExpiredCA(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"-dir", dir}, io.Discard, time.Now().Add(-2*caValidity)); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-dir", dir}, io.Discard, time.Now()); err == nil {
		t.Error("reused an expired CA")
	}
}

// Name constraints: even with the CA key, a certificate for another name does
// not verify.
func TestCANameConstrained(t *testing.T) {
	dir := t.TempDir()
	if err := run([]string{"-dir", dir}, io.Discard, time.Now()); err != nil {
		t.Fatal(err)
	}
	certPEM, _ := os.ReadFile(filepath.Join(dir, caCert)) //nolint:gosec // G304: test temp dir
	keyPEM, _ := os.ReadFile(filepath.Join(dir, caKey))   //nolint:gosec // G304: test temp dir
	ca, caPriv, err := parseCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tmpl := range map[string]*x509.Certificate{
		"public DNS name": {DNSNames: []string{"bank.example"}},
		"public IP":       {IPAddresses: []net.IP{net.IPv4(8, 8, 8, 8)}},
	} {
		tmpl.SerialNumber = big.NewInt(7)
		tmpl.Subject = pkix.Name{CommonName: "x"}
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caPriv)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err == nil {
			t.Errorf("%s: certificate outside the name constraints verifies", name)
		}
	}
}
