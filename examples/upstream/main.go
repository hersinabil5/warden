// Command upstream is an example app that verifies Warden's signed identity
// assertion and prints the caller's identity.
//
// It trusts nothing about the network: it accepts TLS connections only from
// a client certificate issued by the internal CA with the expected name
// (Warden), and it accepts a request only with a valid assertion for its own
// host. Either check alone fails closed.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hersinabil5/warden/internal/identity"
)

type options struct {
	listen     string
	certFile   string
	keyFile    string
	clientCA   string
	clientName string
	header     string
	jwksURL    string
	jwksCA     string
	issuer     string
	audience   string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(ctx, os.Args[1:], logger); err != nil && !errors.Is(err, flag.ErrHelp) {
		logger.Error("upstream exited", "err", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("upstream", flag.ContinueOnError)
	fs.StringVar(&o.listen, "listen", "127.0.0.1:9003", "listen address (keep it on loopback)")
	fs.StringVar(&o.certFile, "cert", "deploy/certs/upstream.pem", "server certificate (from cmd/devca)")
	fs.StringVar(&o.keyFile, "key", "deploy/certs/upstream-key.pem", "server key")
	fs.StringVar(&o.clientCA, "client-ca", "deploy/certs/internal-ca.pem", "CA that issues Warden's client certificate")
	fs.StringVar(&o.clientName, "client-name", "warden-proxy", "required client certificate CN")
	fs.StringVar(&o.header, "header", "X-Warden-Identity", "assertion header")
	fs.StringVar(&o.jwksURL, "jwks", "https://auth.warden.localhost:8443/.well-known/jwks.json", "Warden's JWKS URL")
	fs.StringVar(&o.jwksCA, "jwks-ca", "", "CA file for the JWKS URL's TLS certificate (default: system roots)")
	fs.StringVar(&o.issuer, "issuer", "https://auth.warden.localhost:8443", "expected assertion issuer")
	fs.StringVar(&o.audience, "audience", "app.warden.localhost", "this app's route host (expected aud)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	return o, nil
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(o.certFile, o.keyFile)
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}
	clientCAs, err := loadPool(o.clientCA)
	if err != nil {
		return fmt.Errorf("client CA: %w", err)
	}
	jwksClient, err := newJWKSClient(o.jwksCA)
	if err != nil {
		return err
	}
	keys := identity.NewRemoteKeys(jwksClient, o.jwksURL, identity.RemoteKeysOptions{})
	v := &identity.Verifier{Issuer: o.issuer, Audience: o.audience, Keys: keys.Key}

	srv := &http.Server{
		Handler:           newHandler(v, o.header, logger),
		TLSConfig:         serverTLS(cert, clientCAs, o.clientName),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", o.listen)
	if err != nil {
		return err
	}
	logger.Info("example upstream listening", "addr", ln.Addr().String(), "audience", o.audience, "jwks", o.jwksURL)
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// serverTLS requires a client certificate that chains to clientCAs (for
// client auth) and carries the expected CN, so even another certificate
// from the same CA cannot connect.
func serverTLS(cert tls.Certificate, clientCAs *x509.CertPool, clientName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != clientName {
				return fmt.Errorf("client certificate is not %q", clientName)
			}
			return nil
		},
	}
}

func loadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path from the operator's flags
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificates", path)
	}
	return pool, nil
}

func newJWKSClient(caFile string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("JWKS CA: %w", err)
		}
		tlsCfg.RootCAs = pool
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, localhostAddr(addr))
			},
			TLSClientConfig:     tlsCfg,
			TLSHandshakeTimeout: 5 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// localhostAddr sends *.localhost to the loopback address (RFC 6761,
// section 6.3), as browsers and curl do; Go's resolver on macOS does not.
// TLS still verifies the certificate against the original name.
func localhostAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return addr
}

// newHandler answers every request with the verified identity, or 401.
func newHandler(v *identity.Verifier, header string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		vals := r.Header.Values(header)
		if len(vals) != 1 {
			deny(w, logger, r, fmt.Sprintf("want exactly one %s header, got %d", header, len(vals)))
			return
		}
		id, err := v.Verify(r.Context(), vals[0])
		if err != nil {
			deny(w, logger, r, err.Error())
			return
		}
		logger.Info("request", "user", id.Username, "sub", id.Subject, "jti", id.ID,
			"request_id", r.Header.Get("X-Request-Id"), "path", r.URL.Path)
		_, _ = io.WriteString(w, fmt.Sprintf( //nolint:gosec // G705: text/plain with nosniff, not HTML
			"Hello, %s.\n\nWarden vouched for you:\n  subject:  %s\n  email:    %s\n  groups:   %s\n  assertion %s, expires %s\n\npath: %s\n",
			id.Username, id.Subject, orNone(id.Email), orNone(strings.Join(id.Groups, ", ")),
			id.ID, id.Expiry.UTC().Format(time.RFC3339), r.URL.Path))
	})
}

func deny(w http.ResponseWriter, logger *slog.Logger, r *http.Request, reason string) {
	logger.Warn("rejected request", "reason", reason, "request_id", r.Header.Get("X-Request-Id"))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "missing or invalid identity assertion\n")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
