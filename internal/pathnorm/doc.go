// Package pathnorm normalizes request paths before policy evaluation and forwarding.
// Ambiguous encodings (encoded "/", "\", NUL, invalid UTF-8, double encoding) are
// rejected rather than guessed at.
//
// This package must stay free of I/O so it can be fuzzed heavily.
package pathnorm
