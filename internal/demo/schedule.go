package demo

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Schedule runs demo mode's periodic reset and knows when the next one is,
// for the landing page's countdown.
type Schedule struct {
	interval time.Duration
	now      func() time.Time
	mu       sync.Mutex
	next     time.Time
}

// NewSchedule starts counting from now: the first reset is one interval
// away.
func NewSchedule(interval time.Duration, now func() time.Time) *Schedule {
	return &Schedule{interval: interval, now: now, next: now().Add(interval)}
}

// Next is when the next reset runs.
func (s *Schedule) Next() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next
}

// Run calls reset every interval until ctx ends. A failed reset is logged
// and retried at the next interval.
func (s *Schedule) Run(ctx context.Context, reset func(context.Context) error, logger *slog.Logger) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		s.next = s.now().Add(s.interval)
		s.mu.Unlock()
		if err := reset(ctx); err != nil && ctx.Err() == nil {
			logger.Error("demo reset failed", "err", err)
		}
	}
}
