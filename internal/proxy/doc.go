// Package proxy implements host-based routing to upstreams, the reverse proxy, and
// header hygiene: hop-by-hop and incoming identity headers are stripped before
// Warden injects its own.
package proxy
