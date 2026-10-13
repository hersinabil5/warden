package authn

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testSealer(t *testing.T, now func() time.Time) *cookieSealer {
	t.Helper()
	key, err := NewCookieKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newCookieSealer(key, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testPreAuth(t *testing.T) preAuth {
	t.Helper()
	pa, err := newPreAuth(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return pa
}

func TestNewCookieKeyIsRandom(t *testing.T) {
	a, err := NewCookieKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewCookieKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || string(a) == string(b) {
		t.Errorf("keys: len %d, equal %v; want 32 random bytes", len(a), string(a) == string(b))
	}
}

func TestNewCookieSealerRejectsBadKeys(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := newCookieSealer(make([]byte, n), time.Now); err == nil {
			t.Errorf("%d-byte key accepted, want 32 only", n)
		}
	}
}

func TestPreAuthRoundTrip(t *testing.T) {
	s := testSealer(t, time.Now)
	pa := testPreAuth(t)
	name := preAuthCookieName(pa.State)
	val, err := s.seal(name, pa)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.open(name, val)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != pa {
		t.Errorf("round trip = %+v, want %+v", got, pa)
	}
}

func TestPreAuthValuesAreRandomAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		pa := testPreAuth(t)
		for _, v := range []string{pa.State, pa.Nonce, pa.Verifier} {
			raw, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil || len(raw) < 32 {
				t.Fatalf("value %q is not >=256 bits of base64url", v)
			}
			if seen[v] {
				t.Fatalf("value repeated: %q", v)
			}
			seen[v] = true
		}
	}
}

func TestPreAuthCookieIsOpaque(t *testing.T) {
	s := testSealer(t, time.Now)
	pa := testPreAuth(t)
	val, err := s.seal(preAuthCookieName(pa.State), pa)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{pa.State, pa.Nonce, pa.Verifier} {
		if strings.Contains(val, secret) || strings.Contains(val, secret[:12]) {
			t.Errorf("cookie value reveals %q", secret)
		}
	}
	// Sealing twice gives different ciphertexts (fresh AEAD nonce).
	val2, _ := s.seal(preAuthCookieName(pa.State), pa)
	if val == val2 {
		t.Error("sealing is deterministic; AEAD nonce reused")
	}
}

func TestPreAuthOpenRejectsTampering(t *testing.T) {
	now := time.Now()
	s := testSealer(t, func() time.Time { return now })
	pa := testPreAuth(t)
	name := preAuthCookieName(pa.State)
	val, err := s.seal(name, pa)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(val)

	other := testPreAuth(t)
	otherName := preAuthCookieName(other.State)
	otherKey := testSealer(t, func() time.Time { return now })
	foreign, _ := otherKey.seal(name, pa)
	expired := pa
	expired.Expires = now.Add(-time.Second).Unix()
	expiredVal, _ := s.seal(name, expired)

	tests := []struct {
		name, cookieName, value string
	}{
		{"empty", name, ""},
		{"not base64", name, "!!!not-base64!!!"},
		{"standard base64 padding", name, base64.StdEncoding.EncodeToString(raw)},
		{"too short for nonce", name, base64.RawURLEncoding.EncodeToString(raw[:8])},
		{"truncated tag", name, base64.RawURLEncoding.EncodeToString(raw[:len(raw)-1])},
		{"sealed with another key", name, foreign},
		{"expired", name, expiredVal},
		{"moved to another login's cookie name", otherName, val},
		{"wrong cookie name", "__Host-other", val},
	}
	for i := range raw {
		flipped := append([]byte(nil), raw...)
		flipped[i] ^= 0x01
		tests = append(tests, struct{ name, cookieName, value string }{
			"flipped byte", name, base64.RawURLEncoding.EncodeToString(flipped),
		})
	}
	for _, tt := range tests {
		if _, err := s.open(tt.cookieName, tt.value); err == nil {
			t.Errorf("%s: open succeeded, want error", tt.name)
		}
	}
}

func TestPreAuthExpiryIsShort(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pa, err := newPreAuth(now)
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(pa.Expires, 0).Sub(now); got <= 0 || got > preAuthTTL || preAuthTTL > 10*time.Minute {
		t.Errorf("expiry %v after issue (ttl %v), want (0, 10m]", got, preAuthTTL)
	}
	s := testSealer(t, func() time.Time { return now.Add(preAuthTTL + time.Second) })
	val, _ := s.seal(preAuthCookieName(pa.State), pa)
	if _, err := s.open(preAuthCookieName(pa.State), val); err == nil {
		t.Error("cookie accepted after its TTL")
	}
}

func TestPreAuthCookieName(t *testing.T) {
	pa := testPreAuth(t)
	name := preAuthCookieName(pa.State)
	if !strings.HasPrefix(name, "__Host-") {
		t.Errorf("cookie name %q lacks the __Host- prefix", name)
	}
	if preAuthCookieName(testPreAuth(t).State) == name {
		t.Error("two logins share a cookie name")
	}
}
