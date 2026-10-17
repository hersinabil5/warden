package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Decision is the outcome an event records. Anything other than Allow is
// encoded as Deny, so a missing or mistyped decision never reads as access
// granted (invariant 1).
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

func (d Decision) String() string {
	if d == Allow {
		return string(Allow)
	}
	return string(Deny)
}

func (d Decision) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// SessionPrefixLen is how many hex characters of a session hash an event
// keeps: enough to correlate events, useless for finding the session.
const SessionPrefixLen = 12

// SessionPrefix truncates a session hash (session.HashID) for an event.
func SessionPrefix(hash string) string {
	if len(hash) <= SessionPrefixLen {
		return hash
	}
	return hash[:SessionPrefixLen]
}

// Event is one access decision on a route host (docs/DECISIONS.md D19). It
// holds no secrets: no cookies, tokens, query strings, or full session
// hashes (invariant 9).
type Event struct {
	Time      time.Time
	RequestID string
	User      string // username; empty when unauthenticated
	Session   string // SessionPrefix of the main session hash
	Host      string
	Method    string
	Path      string // normalized; the raw path only when it was rejected
	Decision  Decision
	Rule      string
	Reason    string
	Latency   time.Duration
	Status    int
	// Visitor is the demo-mode visitor tag, for scoping admin views. It is
	// in memory only: never written to a sink or the API.
	Visitor string
}

// wireEvent is the JSON schema of an Event.
type wireEvent struct {
	Time      string   `json:"time"`
	RequestID string   `json:"request_id"`
	User      string   `json:"user"`
	Session   string   `json:"session"`
	Host      string   `json:"host"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Decision  Decision `json:"decision"`
	Rule      string   `json:"rule"`
	Reason    string   `json:"reason"`
	LatencyMS float64  `json:"latency_ms"`
	Status    int      `json:"status"`
}

func (e Event) wire() wireEvent {
	return wireEvent{
		Time:      e.Time.UTC().Format(time.RFC3339Nano),
		RequestID: e.RequestID,
		User:      e.User,
		Session:   e.Session,
		Host:      e.Host,
		Method:    e.Method,
		Path:      e.Path,
		Decision:  e.Decision,
		Rule:      e.Rule,
		Reason:    e.Reason,
		LatencyMS: float64(e.Latency.Microseconds()) / 1000,
		Status:    e.Status,
	}
}

func (e Event) MarshalJSON() ([]byte, error) { return json.Marshal(e.wire()) }

// Recorder receives audit events. Record runs after the response is
// written, so it must be quick and cannot change the response; a recorder
// handles its own failures.
type Recorder interface {
	Record(ctx context.Context, e Event)
}
