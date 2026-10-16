package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEvent(id string) Event {
	return Event{
		Time: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), RequestID: id, User: "bob",
		Host: "whoami.example.test", Method: "GET", Path: "/", Decision: Allow, Rule: "allow[0]",
		Reason: "matched", Status: 200,
	}
}

func decodeLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q is not JSON: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestWriterSinkWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	s := NewWriterSink(&buf, slog.New(slog.DiscardHandler))
	s.Record(t.Context(), testEvent("r1"))
	s.Record(t.Context(), testEvent("r2"))
	lines := decodeLines(t, buf.Bytes())
	if len(lines) != 2 || lines[0]["request_id"] != "r1" || lines[1]["request_id"] != "r2" {
		t.Fatalf("lines = %v", lines)
	}
	if lines[0]["decision"] != "allow" || lines[0]["user"] != "bob" {
		t.Errorf("line = %v", lines[0])
	}
}

func TestFileSinkCreatesPrivateAppendOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	s, err := OpenFileSink(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.Record(t.Context(), testEvent("r1"))
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// A restart appends; it never truncates earlier events.
	s, err = OpenFileSink(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	s.Record(t.Context(), testEvent("r2"))
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	if lines := decodeLines(t, b); len(lines) != 2 || lines[0]["request_id"] != "r1" || lines[1]["request_id"] != "r2" {
		t.Errorf("file holds %v", lines)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, want 0600", fi.Mode().Perm())
	}
}

func TestFileSinkRefusesNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenFileSink(dir, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("opened a directory as the audit file")
	}
}

// Audit failures are logged at error level with the request ID, every time.
func TestSinkFailureIsLoud(t *testing.T) {
	var logs bytes.Buffer
	s := NewWriterSink(failingWriter{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	s.Record(t.Context(), testEvent("r1"))
	s.Record(t.Context(), testEvent("r2"))
	out := logs.String()
	for _, want := range []string{`"level":"ERROR"`, `"msg":"AUDIT EVENT LOST"`, `"request_id":"r1"`, `"request_id":"r2"`, `"lost_total":2`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %s:\n%s", want, out)
		}
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// Concurrent requests never interleave within a line.
func TestSinkConcurrentWritesStayWhole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenFileSink(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { s.Record(context.Background(), testEvent(strings.Repeat("x", 500))) })
	}
	wg.Wait()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: test temp file
	if err != nil {
		t.Fatal(err)
	}
	if n := len(decodeLines(t, b)); n != 50 {
		t.Errorf("%d whole lines, want 50", n)
	}
}

func TestMultiRecordsToAll(t *testing.T) {
	var a, b bytes.Buffer
	m := Multi(NewWriterSink(&a, slog.New(slog.DiscardHandler)), NewWriterSink(&b, slog.New(slog.DiscardHandler)))
	m.Record(t.Context(), testEvent("r1"))
	if len(decodeLines(t, a.Bytes())) != 1 || len(decodeLines(t, b.Bytes())) != 1 {
		t.Errorf("a=%q b=%q", a.String(), b.String())
	}
}
