package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for concurrent writes and reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func writeConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, []byte("listen: \":8443\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// logLines parses JSON log output and fails the test on any non-JSON line.
func logLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", l, err)
		}
		lines = append(lines, m)
	}
	return lines
}

func hasMsg(lines []map[string]any, msg string) bool {
	for _, l := range lines {
		if l["msg"] == msg {
			return true
		}
	}
	return false
}

func TestRunRejectsBadInvocation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	unreadable := filepath.Join(t.TempDir(), "unreadable.yaml")
	if err := os.WriteFile(unreadable, []byte("x: 1\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"no config flag", nil, "-config is required"},
		{"empty config flag", []string{"-config", ""}, "-config is required"},
		{"nonexistent config", []string{"-config", missing}, missing},
		{"config is a directory", []string{"-config", t.TempDir()}, "config"},
		{"unknown flag", []string{"-config", writeConfig(t), "-bogus"}, "bogus"},
		{"invalid log level", []string{"-config", writeConfig(t), "-log-level", "loud"}, "log-level"},
		{"positional args", []string{"-config", writeConfig(t), "extra"}, "unexpected argument"},
	}
	if os.Getuid() != 0 { // root can read mode-000 files
		tests = append(tests, struct {
			name    string
			args    []string
			wantErr string
		}{"unreadable config", []string{"-config", unreadable}, unreadable})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out syncBuffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := run(ctx, tt.args, &out, nil)
			if err == nil {
				t.Fatal("run succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
			if strings.Contains(out.String(), "warden starting") {
				t.Error("logged startup despite invalid invocation")
			}
		})
	}
}

func TestRunHelpIsNotAFailure(t *testing.T) {
	var out syncBuffer
	err := run(context.Background(), []string{"-h"}, &out, nil)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err = %v, want flag.ErrHelp", err)
	}
}

func TestRunStartsAndStopsOnCancel(t *testing.T) {
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())

	var installed bool
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-config", writeConfig(t)}, &out, func(l *slog.Logger) {
			installed = l != nil
		})
	}()

	waitFor(t, func() bool { return strings.Contains(out.String(), "warden starting") })
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context cancellation")
	}

	if !installed {
		t.Error("logger hook was not called with a logger")
	}
	lines := logLines(t, out.String())
	for _, want := range []string{"warden starting", "shutting down", "warden stopped"} {
		if !hasMsg(lines, want) {
			t.Errorf("missing log message %q in:\n%s", want, out.String())
		}
	}
	for _, l := range lines {
		if _, ok := l["level"]; !ok {
			t.Errorf("log line without level: %v", l)
		}
	}
}

func TestRunLogLevelFiltersDebug(t *testing.T) {
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // return right after startup

	if err := run(ctx, []string{"-config", writeConfig(t), "-log-level", "warn"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"level":"INFO"`) {
		t.Errorf("info lines logged at warn level:\n%s", out.String())
	}
}

func TestRunDoesNotLogConfigContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden.yaml")
	const secret = "super-secret-value-do-not-log"
	if err := os.WriteFile(path, []byte("client_secret: "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := run(ctx, []string{"-config", path, "-log-level", "debug"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), secret) {
		t.Errorf("config contents leaked into logs:\n%s", out.String())
	}
}

func TestShutdownRunsHooksInReverseOrder(t *testing.T) {
	var order []int
	hooks := []shutdownFunc{
		func(context.Context) error { order = append(order, 1); return nil },
		func(context.Context) error { order = append(order, 2); return nil },
		func(context.Context) error { order = append(order, 3); return nil },
	}
	if err := shutdown(time.Second, hooks); err != nil {
		t.Fatal(err)
	}
	if got := order; len(got) != 3 || got[0] != 3 || got[1] != 2 || got[2] != 1 {
		t.Errorf("hook order = %v, want [3 2 1]", got)
	}
}

func TestShutdownCollectsHookErrors(t *testing.T) {
	errA := errors.New("a failed")
	errB := errors.New("b failed")
	var ranLast bool
	hooks := []shutdownFunc{
		func(context.Context) error { ranLast = true; return nil },
		func(context.Context) error { return errA },
		func(context.Context) error { return errB },
	}
	err := shutdown(time.Second, hooks)
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Errorf("err = %v, want both hook errors", err)
	}
	if !ranLast {
		t.Error("a failing hook stopped later hooks from running")
	}
}

func TestShutdownTimesOutOnHungHook(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	hooks := []shutdownFunc{
		// Ignores its context entirely: shutdown must still return.
		func(context.Context) error { <-release; return nil },
	}

	start := time.Now()
	err := shutdown(50*time.Millisecond, hooks)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("shutdown took %v with a 50ms timeout", elapsed)
	}
}

// TestBinaryGracefulShutdownOnSignal builds the real binary and sends it signals.
func TestBinaryGracefulShutdownOnSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "warden")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".") //nolint:gosec // G204: bin is a path under t.TempDir()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), bin, "-config", writeConfig(t)) //nolint:gosec // G204: test-built binary in t.TempDir()
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}

			var out syncBuffer
			started := make(chan struct{})
			copied := make(chan struct{})
			go func() {
				defer close(copied)
				sc := bufio.NewScanner(stderr)
				once := sync.Once{}
				for sc.Scan() {
					_, _ = out.Write(append(sc.Bytes(), '\n'))
					if strings.Contains(sc.Text(), "warden starting") {
						once.Do(func() { close(started) })
					}
				}
				if err := sc.Err(); err != nil {
					_, _ = out.Write([]byte("scan error: " + err.Error() + "\n"))
				}
			}()

			select {
			case <-started:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("binary never logged startup:\n%s", out.String())
			}

			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			<-copied
			if err := cmd.Wait(); err != nil {
				t.Fatalf("exit after %v: %v\n%s", sig, err, out.String())
			}
			if !hasMsg(logLines(t, out.String()), "warden stopped") {
				t.Errorf("no graceful stop logged:\n%s", out.String())
			}
		})
	}
}

func TestBinaryExitsNonZeroOnBadConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := filepath.Join(t.TempDir(), "warden")
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput(); err != nil { //nolint:gosec // G204: bin is a path under t.TempDir()
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	cmd := exec.CommandContext(t.Context(), bin, "-config", filepath.Join(t.TempDir(), "nope.yaml")) //nolint:gosec // G204: test-built binary in t.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
		t.Fatalf("err = %v, want non-zero exit", err)
	}
	logLines(t, stderr.String()) // the fatal error is still JSON
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var _ io.Writer = (*syncBuffer)(nil)
