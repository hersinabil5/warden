// Command warden is an identity-aware access proxy.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hersinabil5/warden/internal/authn"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/proxy"
	"github.com/hersinabil5/warden/internal/session"
)

// shutdownTimeout bounds how long graceful shutdown may take before giving up.
const shutdownTimeout = 15 * time.Second

// redisPingTimeout bounds the startup connectivity check.
const redisPingTimeout = 5 * time.Second

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

	err := run(ctx, os.Args[1:], os.Stderr, os.Getenv, installLogger)
	stop()
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return
	default:
		slog.New(slog.NewJSONHandler(os.Stderr, nil)).Error("warden exited", "err", err)
		os.Exit(1)
	}
}

// installLogger makes l the process-wide logger for code Warden does not
// own: the slog default and go-redis's package logger (D3). Only main calls
// it, once.
func installLogger(l *slog.Logger) {
	slog.SetDefault(l)
	redis.SetLogger(session.RedisLogger{Logger: l})
}

// run parses flags, loads the config, sets up logging, discovers the OIDC
// provider, starts the HTTPS
// listener (and the optional HTTP redirect listener), and blocks until ctx is
// cancelled or a server fails, then shuts down gracefully. Logs go to logOut as JSON. getenv
// resolves secrets named in the config. If onLogger is non-nil it receives the
// configured logger (main uses it to install the process default).
func run(ctx context.Context, args []string, logOut io.Writer, getenv func(string) string, onLogger func(*slog.Logger)) error {
	fs := flag.NewFlagSet("warden", flag.ContinueOnError)
	fs.SetOutput(logOut)
	configPath := fs.String("config", "", "path to the YAML config file (required)")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	devSkipPolicy := fs.Bool("dev-skip-policy", false,
		"DEV ONLY (removed in M3): proxy any authenticated request without policy checks; requires loopback listeners")
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

	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("loading TLS certificate: %w", err)
	}
	// Fail fast, before binding any listener, if the IdP is unreachable or
	// misconfigured.
	provider, err := authn.Discover(ctx, cfg.Auth, authn.DiscoverOptions{Logger: logger})
	if err != nil {
		if ctx.Err() != nil {
			// A shutdown signal while waiting for the IdP is a clean stop.
			logger.Info("shutdown requested during startup; warden stopped")
			return nil
		}
		return err
	}
	// Sessions live in Redis (D2); refuse to start without it.
	rdb := session.NewClient(cfg.Session.RedisAddr)
	defer func() { _ = rdb.Close() }()
	sessions := session.NewStore(rdb, session.Options{
		AbsoluteTTL: cfg.Session.AbsoluteTTL,
		IdleTimeout: cfg.Session.IdleTimeout,
	})
	pingCtx, cancelPing := context.WithTimeout(ctx, redisPingTimeout)
	err = sessions.Ping(pingCtx)
	cancelPing()
	if err != nil {
		return fmt.Errorf("connecting to Redis at %s: %w", cfg.Session.RedisAddr, err)
	}

	// Per-process key for pre-auth cookies; a restart only cancels logins in
	// progress (docs/DECISIONS.md D9).
	cookieKey, err := authn.NewCookieKey()
	if err != nil {
		return err
	}
	authHandler, err := authn.NewHandler(cfg, provider, authn.HandlerOptions{
		CookieKey: cookieKey,
		Sessions:  sessions,
		Logger:    logger,
		ErrorPage: proxy.ErrorPage,
	})
	if err != nil {
		return err
	}

	handler, err := proxy.New(cfg, proxy.Options{
		SkipPolicy:    *devSkipPolicy,
		Logger:        logger,
		Auth:          authHandler,
		Authenticator: authHandler,
		CookieNames:   authn.CookieNames(cfg.Session.CookieName),
	})
	if err != nil {
		return err
	}
	if *devSkipPolicy {
		logger.Warn("DEV MODE: any signed-in user can reach every route (no policy); loopback listeners only")
	}

	var hooks []shutdownFunc
	serveErr := make(chan error, 2)
	serve := func(name string, srv *http.Server, fn func() error) {
		hooks = append(hooks, srv.Shutdown)
		go func() {
			if srvErr := fn(); !errors.Is(srvErr, http.ErrServerClosed) {
				serveErr <- fmt.Errorf("%s server: %w", name, srvErr)
			}
		}()
	}
	var lc net.ListenConfig

	httpsLn, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Listen, err)
	}
	httpsSrv := proxy.NewServer(handler, proxy.DefaultServerTimeouts, logger)
	httpsSrv.TLSConfig = proxy.NewTLSConfig(cert)
	serve("https", httpsSrv, func() error { return httpsSrv.ServeTLS(httpsLn, "", "") })
	startAttrs := []any{"config", *configPath, "routes", len(cfg.Routes), "https", httpsLn.Addr().String()}

	if cfg.HTTPRedirectListen != "" {
		redirLn, listenErr := lc.Listen(ctx, "tcp", cfg.HTTPRedirectListen)
		if listenErr != nil {
			_ = shutdown(shutdownTimeout, hooks)
			return fmt.Errorf("listening on %s: %w", cfg.HTTPRedirectListen, listenErr)
		}
		_, portStr, _ := net.SplitHostPort(cfg.Listen) // validated by config
		httpsPort, _ := strconv.Atoi(portStr)
		hosts := []string{cfg.Auth.Domain}
		for _, r := range cfg.Routes {
			hosts = append(hosts, r.Host)
		}
		redirSrv := proxy.NewServer(proxy.NewRedirectHandler(hosts, httpsPort, logger), proxy.DefaultServerTimeouts, logger)
		serve("http redirect", redirSrv, func() error { return redirSrv.Serve(redirLn) })
		startAttrs = append(startAttrs, "http_redirect", redirLn.Addr().String())
	}

	logger.Info("warden starting", startAttrs...)
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-serveErr:
		logger.Error("server failed", "err", runErr)
	}
	logger.Info("shutting down", "timeout", shutdownTimeout.String())

	if err := shutdown(shutdownTimeout, hooks); err != nil {
		logger.Error("shutdown incomplete", "err", err)
		return errors.Join(runErr, err)
	}
	if runErr != nil {
		return runErr
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
