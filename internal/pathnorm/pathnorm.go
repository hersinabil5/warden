package pathnorm

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// MaxLen bounds the raw (still percent-encoded) path Normalize accepts.
const MaxLen = 4096

var (
	// ErrInvalid means the input is not a well-formed origin-form path.
	ErrInvalid = errors.New("invalid request path")
	// ErrAmbiguous means the path could be read more than one way (encoded
	// separators, double encoding, path parameters, ...). It is refused
	// rather than guessed at (invariant 6).
	ErrAmbiguous = errors.New("ambiguous request path")
)

// Normalize turns a raw, percent-encoded request path into its one canonical
// decoded form: decoded exactly once, then "." and ".." segments resolved
// (never above the root) and repeated slashes collapsed. A trailing slash is
// kept. Policy is evaluated on the result and the upstream receives the
// result re-encoded, so both see the same path.
//
// Rejected: anything not starting with "/", invalid percent-encoding,
// encoded "/" or "\", a raw or encoded "\", NUL or other control characters,
// invalid or overlong UTF-8, ";" (path parameters), and anything that still
// contains a percent-escape after decoding (double encoding).
func Normalize(raw string) (string, error) {
	if raw == "" || raw[0] != '/' {
		return "", fmt.Errorf("%w: must start with /", ErrInvalid)
	}
	if len(raw) > MaxLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrInvalid, MaxLen)
	}

	decoded, err := decodeOnce(raw)
	if err != nil {
		return "", err
	}
	if !utf8.ValidString(decoded) {
		return "", fmt.Errorf("%w: invalid UTF-8", ErrInvalid)
	}
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		switch {
		case c < 0x20 || c == 0x7f:
			return "", fmt.Errorf("%w: control character", ErrAmbiguous)
		case c == '\\':
			return "", fmt.Errorf("%w: backslash", ErrAmbiguous)
		case c == ';':
			return "", fmt.Errorf("%w: path parameter", ErrAmbiguous)
		case c == '%' && i+2 < len(decoded) && isHex(decoded[i+1]) && isHex(decoded[i+2]):
			return "", fmt.Errorf("%w: double encoding", ErrAmbiguous)
		}
	}
	return resolve(decoded), nil
}

// IsNormalized reports whether p (a decoded path) is in the form Normalize
// returns: absolute, valid UTF-8, no empty, ".", or ".." segments, and none
// of the characters Normalize rejects. Normalize itself cannot check this,
// since it takes encoded input.
func IsNormalized(p string) bool {
	if p == "" || p[0] != '/' || !utf8.ValidString(p) {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f || c == '\\' || c == ';' ||
			(c == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2])) {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "." || s == ".." || (s == "" && i < len(segs)-1) {
			return false
		}
	}
	return true
}

// decodeOnce percent-decodes raw a single time. An encoded "/" or "\" is
// refused here, because after decoding it can no longer be told apart from a
// real separator.
func decodeOnce(raw string) (string, error) {
	if !strings.Contains(raw, "%") {
		if strings.ContainsAny(raw, "?#") {
			return "", fmt.Errorf("%w: query or fragment in path", ErrInvalid)
		}
		return raw, nil
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch c {
		case '?', '#':
			return "", fmt.Errorf("%w: query or fragment in path", ErrInvalid)
		case '%':
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", fmt.Errorf("%w: bad percent-encoding", ErrInvalid)
			}
			v := unhex(raw[i+1])<<4 | unhex(raw[i+2])
			if v == '/' || v == '\\' {
				return "", fmt.Errorf("%w: encoded separator", ErrAmbiguous)
			}
			b.WriteByte(v)
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// resolve applies RFC 3986 dot-segment removal to an absolute decoded path
// and drops empty segments.
func resolve(p string) string {
	segs := strings.Split(p[1:], "/")
	out := make([]string, 0, len(segs))
	trailing := false
	for _, s := range segs {
		trailing = false
		switch s {
		case "", ".":
			trailing = true
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			trailing = true
		default:
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	res := "/" + strings.Join(out, "/")
	if trailing {
		res += "/"
	}
	return res
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
