package proxy

import (
	"net/http"
	"net/http/httputil"
)

// rewriteHeaders sets the forwarding headers on an outbound request.
//
// With ReverseProxy.Rewrite, incoming Forwarded and X-Forwarded-* headers are
// already removed before this runs, so SetXForwarded writes fresh values
// (the client's real IP, the original Host, and the inbound scheme) instead
// of appending to client-supplied ones. Hop-by-hop headers, including any
// named in Connection, are stripped by ReverseProxy in both directions.
func rewriteHeaders(pr *httputil.ProxyRequest) {
	pr.SetXForwarded()
	// Not covered by ReverseProxy, but trusted by many apps for the client IP.
	pr.Out.Header.Del("X-Real-Ip")
	pr.Out.Header.Set(RequestIDHeader, RequestID(pr.In.Context()))
}

// statusRecorder captures the final status code for the request log. Unwrap
// lets http.ResponseController reach the underlying writer for Flush and
// Hijack, which ReverseProxy relies on.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 && code >= 200 { // ignore 1xx informational responses
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) statusCode() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}
