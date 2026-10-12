// Command warden is an identity-aware access proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/hersinabil5/warden/internal/config"
)

// shutdownTimeout bounds how long graceful shutdown may take before giving up.
const shutdownTimeout = 15 * time.Second

// shutdownFunc releases one resource during graceful shutdown (for example
// http.Server.Shutdown). It should return promptly once ctx is done.
type shutdownFunc func(ctx context.Context) error

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	go func() {
		// After the first signal, restore default handling so a second
		// signal terminates immediately instead of waiting for shutdown.
		<-ctx.Done()
		stop()
	}()

	err := run(ctx, os.Args[1:], os.Stderr, os.Getenv, slog.SetDefault)
	stop()
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return
	default:
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("warden exited", "err", err)
		os.Exit(1)
	}
}

// run parses flags, loads the config, sets up logging, and blocks until ctx is
// cancelled, then shuts down gracefully. Logs go to logOut as JSON. getenv
// resolves secrets named in the config. If onLogger is non-nil it receives the
// configured logger (main uses it to install the process default).
func run(ctx context.Context, args []string, logOut io.Writer, getenv func(string) string, onLogger func(*slog.Logger)) error {
	fs := flag.NewFlagSet("warden", flag.ContinueOnError)
	fs.SetOutput(logOut)
	configPath := fs.String("config", "", "path to the YAML config file (required)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if *configPath == "" {
		return errors.New("-config is required")
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid -log-level %q: %w", *logLevel, err)
	}

	cfg, err := config.Load(*configPath, getenv)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: level}))
	if onLogger != nil {
		onLogger(logger)
	}

	var hooks []shutdownFunc

	logger.Info("warden starting", "config", *configPath, "routes", len(cfg.Routes))
	<-ctx.Done()
	logger.Info("shutting down", "timeout", shutdownTimeout.String())

	if err := shutdown(shutdownTimeout, hooks); err != nil {
		logger.Error("shutdown incomplete", "err", err)
		return err
	}
	logger.Info("warden stopped")
	return nil
}

// shutdown runs hooks in reverse registration order, sharing one deadline.
// A hook that ignores its context cannot stall shutdown past the timeout.
// Errors from every hook are joined; a failing hook does not skip later ones.
func shutdown(timeout time.Duration, hooks []shutdownFunc) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var errs []error
	for _, h := range slices.Backward(hooks) {
		done := make(chan error, 1)
		go func() { done <- h(ctx) }()
		select {
		case err := <-done:
			if err != nil {
				errs = append(errs, err)
			}
		case <-ctx.Done():
			errs = append(errs, fmt.Errorf("shutdown timed out after %v: %w", timeout, ctx.Err()))
			return errors.Join(errs...)
		}
	}
	return errors.Join(errs...)
}
