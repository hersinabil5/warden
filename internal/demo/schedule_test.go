package demo

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestScheduleRunsAndStops(t *testing.T) {
	s := NewSchedule(20*time.Millisecond, time.Now)
	before := s.Next()
	if d := time.Until(before); d <= 0 || d > 20*time.Millisecond {
		t.Errorf("first reset in %v", d)
	}
	var runs atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		s.Run(ctx, func(context.Context) error {
			if runs.Add(1) == 1 {
				return errors.New("redis down") // logged, the loop goes on
			}
			return nil
		}, slog.New(slog.DiscardHandler))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runs.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatal("resets did not keep running")
		}
		time.Sleep(5 * time.Millisecond) //nolint:forbidigo // polling in a test
	}
	if !s.Next().After(before) {
		t.Error("Next did not advance")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop on cancel")
	}
}
