package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"
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
// failClosedTLS is for routes configured with upstream_tls before mTLS exists
// (M4): an empty root pool makes every TLS handshake fail rather than fall back
// to the system roots.
func newTransport(t TransportTimeouts, failClosedTLS bool) *http.Transport {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if failClosedTLS {
		tlsCfg.RootCAs = x509.NewCertPool()
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
	}
}
