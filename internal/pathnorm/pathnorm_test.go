package pathnorm

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/", "/"},
		{"/admin", "/admin"},
		{"/admin/", "/admin/"},
		{"//admin", "/admin"},
		{"/a//b///c", "/a/b/c"},
		{"/foo/../admin", "/admin"},
		{"/foo/bar/../../admin", "/admin"},
		{"/../admin", "/admin"}, // ".." never climbs above the root
		{"/../../..", "/"},
		{"/./admin", "/admin"},
		{"/admin/.", "/admin/"},
		{"/admin/..", "/"},
		{"/a/b/..", "/a/"},
		{"/%61dmin", "/admin"},      // decoded once
		{"/%2e%2e/admin", "/admin"}, // encoded dots resolve after decoding
		{"/%2E/admin", "/admin"},    //
		{"/a%20b", "/a b"},          // decoded form; the proxy re-encodes it
		{"/caf%C3%A9", "/café"},     // valid UTF-8
		{"/café", "/café"},          // raw UTF-8 as some clients send it
		{"/100%25", "/100%"},        // a literal percent sign is fine
		{"/a%3Fb%23c", "/a?b#c"},    // encoded ? and # stay in the path
		{"/.warden/login", "/.warden/login"},
		{"/...", "/..."}, // three dots is a name, not a dot segment
		{"/a.b/c..d", "/a.b/c..d"},
	}
	for _, tt := range tests {
		got, err := Normalize(tt.in)
		if err != nil {
			t.Errorf("Normalize(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Invariant 6: ambiguous encodings are rejected, not guessed at.
func TestNormalizeRejects(t *testing.T) {
	for _, in := range []string{
		// Not an origin-form path.
		"", "admin", "*", "http://evil.example/admin",

		// Encoded separators: an upstream may treat them as "/" or "\".
		"/admin%2F", "/admin%2f", "/a%2Fb", "/a%5Cb", "/a%5cb",
		`/a\b`, `/admin\`, `\admin`,

		// NUL and other control characters, raw or encoded.
		"/a%00b", "/a\x00b", "/a%0Ab", "/a%0d%0aSet-Cookie:x", "/a\tb", "/a%7Fb", "/a%09b",

		// Invalid percent-encoding.
		"/a%", "/a%2", "/a%zz", "/a%G0", "/%%32%65",

		// Double encoding: whatever decodes a second time is ambiguous.
		"/%252e%252e/admin", "/%252F", "/a%2541", "/%25%32%65",

		// Invalid or overlong UTF-8 (overlong "." is a classic traversal).
		"/a%FFb", "/a\xffb", "/%C0%AE%C0%AE/admin", "/%E0%80%AE", "/%ED%A0%80",

		// Path parameters: Tomcat, Jetty, and others strip ";..." per segment,
		// so /admin;x or /..;/admin can reach a path policy did not see.
		"/admin;x", "/..;/admin", "/a/%3B/b", "/a%3bb",
	} {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want rejection", in, got)
		} else if !errors.Is(err, ErrAmbiguous) && !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%q): error %v is neither ErrAmbiguous nor ErrInvalid", in, err)
		}
	}
}

func TestIsNormalized(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/admin": true, "/admin/": true, "/100%": true, "/a?b#c": true, "/café": true, "/a b": true,
		"": false, "admin": false, "//admin": false, "/a/./b": false, "/a/../b": false, "/..": false,
		"/a\\b": false, "/a;b": false, "/a\x00": false, "/%41": false, "/a\xff": false,
	} {
		if got := IsNormalized(p); got != want {
			t.Errorf("IsNormalized(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestNormalizeLengthLimit(t *testing.T) {
	if _, err := Normalize("/" + strings.Repeat("a", MaxLen)); err == nil {
		t.Error("oversized path accepted")
	}
	if _, err := Normalize("/" + strings.Repeat("a", MaxLen-1)); err != nil {
		t.Errorf("path of MaxLen bytes rejected: %v", err)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{
		"/", "/admin", "//admin", "/foo/../admin", "/%61dmin", "/admin/", "/admin%2F",
		"/%252e%252e/admin", "/%2e%2e/%2e%2e/x", "/a;b", "/caf%C3%A9", "/a%00", `/a\b`, "/100%25",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := Normalize(in)
		if err != nil {
			return
		}
		// The output is canonical: absolute, valid UTF-8, no empty, ".", or
		// ".." segments, and nothing a second decode could change.
		if !IsNormalized(out) {
			t.Fatalf("Normalize(%q) = %q: IsNormalized is false", in, out)
		}
		if !strings.HasPrefix(out, "/") || !utf8.ValidString(out) {
			t.Fatalf("Normalize(%q) = %q: not an absolute UTF-8 path", in, out)
		}
		segs := strings.Split(out[1:], "/")
		for i, s := range segs {
			if s == "." || s == ".." || (s == "" && i < len(segs)-1) {
				t.Fatalf("Normalize(%q) = %q: leftover dot or empty segment", in, out)
			}
		}
		if strings.ContainsAny(out, "\\;\x00") {
			t.Fatalf("Normalize(%q) = %q: contains a rejected character", in, out)
		}
		// Re-encoding what the proxy forwards and normalizing again must be
		// a fixed point: the upstream sees exactly what policy saw.
		// (Re-encoding can triple the length, e.g. "é" becomes "%C3%A9",
		// past MaxLen, which bounds only what clients send.)
		forwarded := (&url.URL{Path: out}).EscapedPath()
		if len(forwarded) > MaxLen {
			return
		}
		again, err := Normalize(forwarded)
		if err != nil || again != out {
			t.Fatalf("Normalize(%q) = %q, forwarded as %q, re-normalizes to %q, %v", in, out, forwarded, again, err)
		}
	})
}
