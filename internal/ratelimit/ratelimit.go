// Package ratelimit is an in-memory token bucket per key (client IP, session
// hash) with a bounded key table. It does no I/O; the clock is injected.
//
// Limits are per process: several Warden instances would each allow the full
// rate (docs/DECISIONS.md D27).
package ratelimit

import (
	"container/list"
	"errors"
	"math"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// DefaultMaxKeys bounds a limiter's memory: about 1 MiB of buckets.
const DefaultMaxKeys = 10_000

// Limit is a sustained rate and how many requests may arrive at once.
type Limit struct {
	PerMinute int
	Burst     int
}

// Limiter tracks one token bucket per key.
type Limiter struct {
	perSec  float64
	burst   float64
	maxKeys int
	now     func() time.Time

	mu      sync.Mutex
	buckets map[string]*list.Element // of *bucket
	lru     *list.List               // front is most recently used
}

type bucket struct {
	key    string
	tokens float64
	last   time.Time
}

// New returns a limiter that tracks at most maxKeys keys, evicting the least
// recently used one when full.
func New(l Limit, maxKeys int, now func() time.Time) (*Limiter, error) {
	switch {
	case l.PerMinute <= 0:
		return nil, errors.New("ratelimit: rate must be positive")
	case l.Burst <= 0:
		return nil, errors.New("ratelimit: burst must be positive")
	case maxKeys <= 0:
		return nil, errors.New("ratelimit: key table size must be positive")
	case now == nil:
		return nil, errors.New("ratelimit: clock is required")
	}
	return &Limiter{
		perSec:  float64(l.PerMinute) / 60,
		burst:   float64(l.Burst),
		maxKeys: maxKeys,
		now:     now,
		buckets: make(map[string]*list.Element),
		lru:     list.New(),
	}, nil
}

// Allow takes a token from key's bucket. When there is none it returns false
// and how long until one refills; a denied request takes nothing.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucket(key, now)
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(l.burst, b.tokens+elapsed.Seconds()*l.perSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
	return false, wait
}

// bucket finds or creates key's bucket and marks it most recently used. A new
// bucket starts full. Callers hold l.mu.
func (l *Limiter) bucket(key string, now time.Time) *bucket {
	if e, ok := l.buckets[key]; ok {
		l.lru.MoveToFront(e)
		return bucketOf(e)
	}
	if l.lru.Len() >= l.maxKeys {
		// The least recently used key goes. Its bucket has been refilling
		// the longest, so this rarely forgives anyone; an attacker who wants
		// their own bucket evicted must outpace maxKeys other clients.
		oldest := l.lru.Back()
		l.lru.Remove(oldest)
		delete(l.buckets, bucketOf(oldest).key)
	}
	b := &bucket{key: key, tokens: l.burst, last: now}
	l.buckets[key] = l.lru.PushFront(b)
	return b
}

// bucketOf unwraps a list element; the list holds only *bucket.
func bucketOf(e *list.Element) *bucket {
	b, _ := e.Value.(*bucket)
	return b
}

// Len is the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lru.Len()
}

// ClientKey is the rate-limit key for a connection's remote address
// (http.Request.RemoteAddr): the IP without the port, IPv4-mapped addresses
// as IPv4, and IPv6 grouped by /64, the usual allocation to one subscriber.
// Forwarding headers are never consulted: Warden is the edge, and any client
// can write them. Anything unparsable is used as is.
func ClientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return remoteAddr
	}
	addr = addr.WithZone("").Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.Prefix(64)
	if err != nil {
		return remoteAddr
	}
	return p.String()
}

// RetryAfterSeconds formats a wait for the Retry-After header: whole seconds,
// rounded up, at least 1.
func RetryAfterSeconds(d time.Duration) string {
	s := int64(math.Ceil(d.Seconds()))
	return strconv.FormatInt(max(s, 1), 10)
}
