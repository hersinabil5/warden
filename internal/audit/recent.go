package audit

import (
	"context"
	"encoding/json"
	"sync"
)

// Query limits for Recent.Query.
const (
	DefaultQueryLimit = 50
	MaxQueryLimit     = 200
)

// Entry is a recorded event with its sequence number (1, 2, ...), which
// pages through Recent.
type Entry struct {
	Seq uint64 `json:"seq"`
	Event
}

// MarshalJSON flattens the sequence number into the event's schema.
func (e Entry) MarshalJSON() ([]byte, error) {
	type flat struct {
		Seq uint64 `json:"seq"`
		wireEvent
	}
	return json.Marshal(flat{e.Seq, e.wire()})
}

// Recent keeps the last N events in memory for the admin API. The durable
// record is the sink; Recent starts empty on every restart.
type Recent struct {
	mu   sync.Mutex
	buf  []Entry // ring of len cap
	next uint64  // sequence number of the next event
	// floor is the first sequence number still visible: Reset raises it so
	// earlier events (and cursors into them) are gone.
	floor uint64
}

// NewRecent keeps the last n events.
func NewRecent(n int) *Recent {
	return &Recent{buf: make([]Entry, max(n, 1)), next: 1}
}

// Reset forgets every event recorded so far (demo mode). Sequence numbers
// keep counting, so a cursor from before the reset reaches nothing.
func (r *Recent) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.buf)
	r.floor = r.next
}

func (r *Recent) Record(_ context.Context, e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next%uint64(len(r.buf))] = Entry{Seq: r.next, Event: e}
	r.next++
}

// Query selects events. Empty fields match anything; Decision matches the
// recorded (fail-closed) decision.
type Query struct {
	User, Host string
	Decision   Decision
	Before     uint64 // only events with Seq < Before; 0 means from the newest
	Limit      int
	// ScopeVisitor limits results to events whose Visitor equals Visitor
	// (demo mode), including when Visitor is empty.
	ScopeVisitor bool
	Visitor      string
}

// Query returns matching events newest first, and the Before value for the
// next page (0 when there is none).
func (r *Recent) Query(q Query) ([]Entry, uint64) {
	if q.Limit <= 0 {
		q.Limit = DefaultQueryLimit
	}
	q.Limit = min(q.Limit, MaxQueryLimit)
	r.mu.Lock()
	defer r.mu.Unlock()
	newest := r.next - 1
	oldest := uint64(1)
	if n := uint64(len(r.buf)); newest > n {
		oldest = newest - n + 1
	}
	oldest = max(oldest, r.floor)
	start := newest
	if q.Before != 0 && q.Before-1 < start {
		start = q.Before - 1
	}
	var out []Entry
	for seq := start; seq >= oldest && seq > 0; seq-- {
		e := r.buf[seq%uint64(len(r.buf))]
		if !q.matches(e.Event) {
			continue
		}
		if len(out) == q.Limit {
			return out, out[len(out)-1].Seq
		}
		out = append(out, e)
	}
	return out, 0
}

func (q Query) matches(e Event) bool {
	return (q.User == "" || e.User == q.User) &&
		(q.Host == "" || e.Host == q.Host) &&
		(q.Decision == "" || e.Decision.String() == q.Decision.String()) &&
		(!q.ScopeVisitor || e.Visitor == q.Visitor)
}
