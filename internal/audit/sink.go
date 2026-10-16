package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// Sink writes events as JSON lines (docs/DECISIONS.md D20). Each event is
// one Write call under a lock, so concurrent events never interleave.
type Sink struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	logger *slog.Logger
	lost   atomic.Uint64
}

// NewWriterSink writes events to w (stdout for sink: stdout).
func NewWriterSink(w io.Writer, logger *slog.Logger) *Sink {
	return &Sink{w: w, logger: logger}
}

// OpenFileSink appends events to the file at path, creating it (0600) and
// its directory (0700) if needed. Existing events are never truncated.
func OpenFileSink(path string, logger *slog.Logger) (*Sink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: creating directory for %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) //nolint:gosec // G304: path comes from the operator's config
	if err != nil {
		return nil, fmt.Errorf("audit: opening %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("audit: %s is not a regular file", path)
	}
	return &Sink{w: f, closer: f, logger: logger}, nil
}

// Record writes e. A failed write cannot undo the response, so it is logged
// at error level with the request ID and a running count, every time.
func (s *Sink) Record(ctx context.Context, e Event) {
	line, err := json.Marshal(e)
	if err == nil {
		line = append(line, '\n')
		s.mu.Lock()
		var n int
		n, err = s.w.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
		s.mu.Unlock()
	}
	if err != nil {
		lost := s.lost.Add(1)
		s.logger.LogAttrs(ctx, slog.LevelError, "AUDIT EVENT LOST",
			slog.String("request_id", e.RequestID), slog.Uint64("lost_total", lost), slog.Any("err", err))
	}
}

// Close closes the file, if the sink owns one.
func (s *Sink) Close() error {
	if s.closer == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.closer.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("audit: closing: %w", err)
	}
	return nil
}

type multi []Recorder

// Multi records every event to each recorder in order.
func Multi(rs ...Recorder) Recorder { return multi(rs) }

func (m multi) Record(ctx context.Context, e Event) {
	for _, r := range m {
		r.Record(ctx, e)
	}
}
