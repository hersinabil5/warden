package demo

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column (8 digits).
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	} {
		if got := totp(secret, time.Unix(unix, 0), 8); got != want {
			t.Errorf("T=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestCodeIsSixDigitsAndChangesEvery30s(t *testing.T) {
	secret := []byte("12345678901234567890")
	at := time.Unix(1111111111, 0)
	start := at.Truncate(Period)
	c := Code(secret, start)
	if len(c) != 6 || c != "050471" {
		t.Errorf("Code = %q, want the last 6 digits of the RFC vector", c)
	}
	if Code(secret, start.Add(Period-time.Nanosecond)) != c {
		t.Error("code changed within its period")
	}
	if Code(secret, start.Add(Period)) == c {
		t.Error("code did not change at the period boundary")
	}
	if got := Remaining(start.Add(10 * time.Second)); got != 20*time.Second {
		t.Errorf("Remaining = %v, want 20s", got)
	}
}
