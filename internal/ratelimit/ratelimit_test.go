package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTest(t *testing.T, l Limit, maxKeys int) (*Limiter, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	lim, err := New(l, maxKeys, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return lim, c
}

func TestBurstThenRefill(t *testing.T) {
	lim, c := newTest(t, Limit{PerMinute: 60, Burst: 3}, 10)
	for i := range 3 {
		if ok, _ := lim.Allow("a"); !ok {
			t.Fatalf("request %d within burst denied", i+1)
		}
	}
	ok, retry := lim.Allow("a")
	if ok {
		t.Fatal("request past the burst allowed")
	}
	if retry != time.Second {
		t.Errorf("retry after = %v, want 1s (60/min)", retry)
	}
	// A denied request spends nothing: still exactly one second to wait.
	c.advance(500 * time.Millisecond)
	if ok, retry := lim.Allow("a"); ok || retry != 500*time.Millisecond {
		t.Errorf("half refilled: ok=%v retry=%v, want denied with 500ms", ok, retry)
	}
	c.advance(500 * time.Millisecond)
	if ok, _ := lim.Allow("a"); !ok {
		t.Error("denied after a full token refilled")
	}
	if ok, _ := lim.Allow("a"); ok {
		t.Error("second request allowed with only one token refilled")
	}
	// Refill caps at the burst, however long the key is idle.
	c.advance(time.Hour)
	for i := range 3 {
		if ok, _ := lim.Allow("a"); !ok {
			t.Fatalf("after idle: request %d denied", i+1)
		}
	}
	if ok, _ := lim.Allow("a"); ok {
		t.Error("idle time banked more than the burst")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	lim, _ := newTest(t, Limit{PerMinute: 1, Burst: 1}, 10)
	if ok, _ := lim.Allow("a"); !ok {
		t.Fatal("first request denied")
	}
	if ok, _ := lim.Allow("a"); ok {
		t.Fatal("a not limited")
	}
	if ok, _ := lim.Allow("b"); !ok {
		t.Error("b limited by a's requests")
	}
}

// A clock step backwards (NTP) must not mint tokens or panic.
func TestClockGoingBackwards(t *testing.T) {
	lim, c := newTest(t, Limit{PerMinute: 60, Burst: 1}, 10)
	lim.Allow("a")
	c.advance(-time.Hour)
	if ok, _ := lim.Allow("a"); ok {
		t.Error("clock going backwards refilled the bucket")
	}
}

// Memory is bounded however many keys an attacker presents; the least
// recently used key goes first, so an active attacker keeps their own
// (empty) bucket.
func TestKeyTableIsBounded(t *testing.T) {
	lim, _ := newTest(t, Limit{PerMinute: 1, Burst: 1}, 100)
	lim.Allow("attacker")
	for i := range 10_000 {
		lim.Allow(fmt.Sprintf("k%d", i))
		if i%50 == 0 {
			lim.Allow("attacker") // still active
		}
		if n := lim.Len(); n > 100 {
			t.Fatalf("tracked keys = %d, want at most 100", n)
		}
	}
	if ok, _ := lim.Allow("attacker"); ok {
		t.Error("an active key was evicted and its limit reset")
	}
}

func TestConcurrentUse(t *testing.T) {
	lim, _ := newTest(t, Limit{PerMinute: 1, Burst: 50}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range 200 {
		wg.Go(func() {
			if ok, _ := lim.Allow("a"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if allowed != 50 {
		t.Errorf("allowed = %d, want exactly the burst (50)", allowed)
	}
}

func TestNewValidates(t *testing.T) {
	now := time.Now
	for _, tt := range []struct {
		name string
		l    Limit
		max  int
	}{
		{"zero rate", Limit{PerMinute: 0, Burst: 1}, 10},
		{"negative rate", Limit{PerMinute: -1, Burst: 1}, 10},
		{"zero burst", Limit{PerMinute: 1, Burst: 0}, 10},
		{"zero keys", Limit{PerMinute: 1, Burst: 1}, 0},
	} {
		if _, err := New(tt.l, tt.max, now); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
	if _, err := New(Limit{PerMinute: 1, Burst: 1}, 1, nil); err == nil {
		t.Error("nil clock accepted")
	}
}

func TestClientKey(t *testing.T) {
	for _, tt := range []struct{ remote, want string }{
		{"192.0.2.10:5555", "192.0.2.10"},
		{"192.0.2.10:6666", "192.0.2.10"}, // the port is not part of the client
		{"[::ffff:192.0.2.10]:1", "192.0.2.10"},
		// IPv6 clients are grouped by /64: one subscriber usually holds a
		// whole /64 and could otherwise rotate through 2^64 addresses.
		{"[2001:db8:1:2:aaaa::1]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:ffff:ffff:ffff:ffff]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:3::1]:443", "2001:db8:1:3::/64"},
		{"[fe80::1%en0]:443", "fe80::/64"},
		// Not an address (never from a TCP listener): still a key of its own.
		{"garbage", "garbage"},
		{"", ""},
	} {
		if got := ClientKey(tt.remote); got != tt.want {
			t.Errorf("ClientKey(%q) = %q, want %q", tt.remote, got, tt.want)
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]string{
		time.Second:                      "1",
		1500 * time.Millisecond:          "2", // never tell a client to come back early
		time.Millisecond:                 "1",
		0:                                "1",
		90 * time.Second:                 "90",
		90*time.Second + time.Nanosecond: "91",
	} {
		if got := RetryAfterSeconds(d); got != want {
			t.Errorf("RetryAfterSeconds(%v) = %q, want %q", d, got, want)
		}
	}
}
