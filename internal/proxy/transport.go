package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

// TransportTimeouts bound every phase of an upstream request (invariant 10).
type TransportTimeouts struct {
	Dial           time.Duration
	TLSHandshake   time.Duration
	ResponseHeader time.Duration // upstream must start responding within this
	ExpectContinue time.Duration
	IdleConn       time.Duration
}

// DefaultTransportTimeouts; see docs/DECISIONS.md D6.
var DefaultTransportTimeouts = TransportTimeouts{
	Dial:           5 * time.Second,
	TLSHandshake:   5 * time.Second,
	ResponseHeader: 30 * time.Second,
	ExpectContinue: 1 * time.Second,
	IdleConn:       90 * time.Second,
}

// newTransport returns the transport for one route. Proxy is nil on purpose:
// http.DefaultTransport honors HTTP_PROXY, which would let an environment
// variable silently reroute upstream traffic.
//
// With upstream_tls the route uses mTLS (D18): the upstream's certificate
// must chain to ca_file alone (never the system roots), and Warden presents
// its client certificate.
func newTransport(t TransportTimeouts, up *config.UpstreamTLS) (*http.Transport, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if up != nil {
		var err error
		if tlsCfg, err = upstreamTLSConfig(up); err != nil {
			return nil, err
		}
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   t.Dial,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   t.TLSHandshake,
		ResponseHeaderTimeout: t.ResponseHeader,
		ExpectContinueTimeout: t.ExpectContinue,
		IdleConnTimeout:       t.IdleConn,
		MaxIdleConnsPerHost:   32,
	}, nil
}

func upstreamTLSConfig(up *config.UpstreamTLS) (*tls.Config, error) {
	caPEM, err := os.ReadFile(up.CAFile)
	if err != nil {
		return nil, fmt.Errorf("upstream_tls.ca_file: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("upstream_tls.ca_file: no certificates found")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if up.ClientCertFile != "" {
		pair, err := tls.LoadX509KeyPair(up.ClientCertFile, up.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream_tls client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg, nil
}
