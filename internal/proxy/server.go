package proxy

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"
)

// ServerTimeouts bound how long a client may hold a connection (invariant 10).
type ServerTimeouts struct {
	ReadHeader time.Duration // slow-loris protection
	Read       time.Duration // whole request, including body
	Write      time.Duration // from end of request headers to end of response
	Idle       time.Duration // keep-alive between requests
}

// DefaultServerTimeouts; see docs/DECISIONS.md D6.
var DefaultServerTimeouts = ServerTimeouts{
	ReadHeader: 10 * time.Second,
	Read:       60 * time.Second,
	Write:      120 * time.Second,
	Idle:       120 * time.Second,
}

const maxHeaderBytes = 64 << 10

// NewServer returns an http.Server with every timeout set. Server-internal
// errors (TLS handshake failures, etc.) are logged at warn level.
func NewServer(h http.Handler, t ServerTimeouts, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

// NewTLSConfig serves cert with TLS 1.2 as the minimum version. Go's default
// cipher suites are used; they exclude known-weak ones.
func NewTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
}
