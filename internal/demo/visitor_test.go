package demo

import (
	"strings"
	"testing"
)

func TestVisitorTags(t *testing.T) {
	v, err := NewVisitors()
	if err != nil {
		t.Fatal(err)
	}
	a := v.Of("192.0.2.10:1000")
	if len(a) != VisitorTagLen || strings.Contains(a, "192") {
		t.Errorf("tag %q: want %d hex chars, nothing of the IP", a, VisitorTagLen)
	}
	same := []string{"192.0.2.10:2000", "[::ffff:192.0.2.10]:1"}
	for _, r := range same {
		if v.Of(r) != a {
			t.Errorf("%s: different visitor from the same IP", r)
		}
	}
	if v.Of("192.0.2.11:1000") == a {
		t.Error("two IPs share a visitor")
	}
	// IPv6 by /64, like the rate limiter.
	if v.Of("[2001:db8:1:2::1]:1") != v.Of("[2001:db8:1:2:ffff::9]:1") || v.Of("[2001:db8:1:2::1]:1") == v.Of("[2001:db8:1:3::1]:1") {
		t.Error("IPv6 not grouped by /64")
	}
	// Keyed per process: another instance's tags don't line up, and a tag
	// can't be recomputed from a guessed IP without the key.
	w, _ := NewVisitors()
	if w.Of("192.0.2.10:1000") == a {
		t.Error("tags are not keyed")
	}
}
