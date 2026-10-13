package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hersinabil5/warden/internal/authn/testidp"
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

const (
	testSecretEnv = "WARDEN_TEST_CLIENT_SECRET"
	testSecret    = "super-secret-value-do-not-log"
)

// minimalConfig is a small valid config; internal/config tests cover validation.
const minimalConfig = `listen: ":8443"
tls: {cert_file: cert.pem, key_file: key.pem}
auth:
  domain: auth.example.test
  issuer: https://idp.example.test/realms/warden
  client_id: warden-proxy
  client_secret_env: ` + testSecretEnv + `
  scopes: [openid]
  id_token_algs: [RS256]
  groups_claim: groups
  group_refresh_interval: 5m
session: {redis_addr: "localhost:6379", cookie_name: _warden, absolute_ttl: 8h, idle_timeout: 1h}
identity: {header: X-Warden-Identity, signing_key_file: signing.pem, ttl: 60s}
audit: {sink: stdout}
routes:
  - host: app.example.test
    upstream: http://127.0.0.1:9001
    policy:
      allow:
        - authenticated: true
`

func testGetenv(name string) string {
	if name == testSecretEnv {
		return testSecret
	}
	return ""
}

// testEnv is a runnable config: free loopback ports and a real certificate.
type testEnv struct {
	path, httpsAddr, redirectAddr string
	pool                          *x509.CertPool
}

// writeConfig writes minimalConfig with free ports and a generated cert.
func writeConfig(t *testing.T) string {
	t.Helper()
	return newTestEnv(t, minimalConfig).path
}

// newTestEnv makes content runnable: it swaps in free loopback ports (adding a
// redirect listener), a freshly generated certificate, and a fake IdP.
func newTestEnv(t *testing.T, content string) testEnv {
	t.Helper()
	return newTestEnvWithIdP(t, content, testidp.New(t))
}

func newTestEnvWithIdP(t *testing.T, content string, idp *testidp.IdP) testEnv {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath, pool := writeTestCert(t, dir)
	env := testEnv{httpsAddr: freeAddr(t), redirectAddr: freeAddr(t), pool: pool}
	content = strings.NewReplacer(
		`listen: ":8443"`, `listen: "`+env.httpsAddr+`"`+"\nhttp_redirect_listen: \""+env.redirectAddr+`"`,
		"cert_file: cert.pem", "cert_file: "+certPath,
		"key_file: key.pem", "key_file: "+keyPath,
		"issuer: https://idp.example.test/realms/warden", "issuer: "+idp.Issuer,
	).Replace(content)
	env.path = writeConfigContent(t, content)
	return env
}

func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

func writeTestCert(t *testing.T, dir string) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "app.example.test"},
		DNSNames:     []string{"app.example.test", "auth.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(leaf)
	return certPath, keyPath, pool
}

func writeConfigContent(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
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
		{"invalid YAML", []string{"-config", writeConfigContent(t, "listen: [\n")}, "parsing YAML"},
		{"unknown field", []string{"-config", writeConfigContent(t, minimalConfig+"bogus: 1\n")}, "bogus"},
		{"fails validation", []string{"-config", writeConfigContent(t, strings.Replace(minimalConfig, "upstream: http://", "upstream: ftp://", 1))}, "routes[0].upstream"},
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

			err := run(ctx, tt.args, &out, testGetenv, nil)
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
	err := run(context.Background(), []string{"-h"}, &out, testGetenv, nil)
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
		done <- run(ctx, []string{"-config", writeConfig(t)}, &out, testGetenv, func(l *slog.Logger) {
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

// runUntilStarted runs warden with a fresh test env, cancels once the HTTPS
// listener accepts connections (startup, including discovery, is complete),
// and returns all output. Polling the port works at any log level.
func runUntilStarted(t *testing.T, extraArgs ...string) string {
	t.Helper()
	env := newTestEnv(t, minimalConfig)
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, append([]string{"-config", env.path}, extraArgs...), &out, testGetenv, nil) }()
	waitFor(t, func() bool {
		var d net.Dialer
		c, err := d.DialContext(t.Context(), "tcp", env.httpsAddr)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}
	return out.String()
}

func TestRunLogLevelFiltersDebug(t *testing.T) {
	out := runUntilStarted(t, "-log-level", "warn")
	if strings.Contains(out, `"level":"INFO"`) {
		t.Errorf("info lines logged at warn level:\n%s", out)
	}
}

func TestRunDoesNotLogSecrets(t *testing.T) {
	out := runUntilStarted(t, "-log-level", "debug")
	if !strings.Contains(out, "OIDC provider discovered") {
		t.Fatalf("startup did not get past discovery:\n%s", out)
	}
	if strings.Contains(out, testSecret) {
		t.Errorf("client secret leaked into logs:\n%s", out)
	}
}

func TestRunCancelDuringDiscoveryIsCleanStop(t *testing.T) {
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, []string{"-config", writeConfig(t)}, &out, testGetenv, nil); err != nil {
		t.Fatalf("run = %v, want clean stop", err)
	}
	if hasMsg(logLines(t, out.String()), "warden starting") {
		t.Error("started serving despite cancellation")
	}
}

// A secret pasted into the config by mistake must not be echoed in the error,
// which main logs on exit.
func TestRunDoesNotEchoSecretFromBadConfig(t *testing.T) {
	path := writeConfigContent(t, strings.Replace(minimalConfig,
		"client_secret_env: "+testSecretEnv, "client_secret_env: "+testSecret+"!", 1))
	var out syncBuffer
	err := run(context.Background(), []string{"-config", path}, &out, testGetenv, nil)
	if err == nil {
		t.Fatal("run succeeded, want error")
	}
	if strings.Contains(err.Error(), testSecret) || strings.Contains(out.String(), testSecret) {
		t.Errorf("secret echoed: err=%q out=%q", err, out.String())
	}
}

func TestRunFailsWhenSecretEnvUnset(t *testing.T) {
	var out syncBuffer
	err := run(context.Background(), []string{"-config", writeConfig(t)}, &out,
		func(string) string { return "" }, nil)
	if err == nil || !strings.Contains(err.Error(), testSecretEnv) {
		t.Fatalf("err = %v, want error naming %s", err, testSecretEnv)
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
			cmd.Env = append(os.Environ(), testSecretEnv+"="+testSecret)
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

// startRun runs warden in the background until the test ends and waits for
// it to log startup.
func startRun(t *testing.T, args ...string) *syncBuffer {
	t.Helper()
	var out syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, args, &out, testGetenv, nil) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v\n%s", err, out.String())
		}
	})
	waitFor(t, func() bool { return strings.Contains(out.String(), "warden starting") })
	return &out
}

// clientFor returns an HTTP client that resolves every host to addr, trusts
// pool, and does not follow redirects.
func clientFor(addr string, pool *x509.CertPool) *http.Client {
	var d net.Dialer
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// get performs a GET and returns the response with its body fully read.
func get(t *testing.T, c *http.Client, url string) response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{resp.StatusCode, resp.Header, string(body)}
}

func TestRunServesHTTPSAndRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	defer upstream.Close()
	env := newTestEnv(t, strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1))
	startRun(t, "-config", env.path, "-dev-allow-unauthenticated")

	https := clientFor(env.httpsAddr, env.pool)
	_, httpsPort, _ := net.SplitHostPort(env.httpsAddr)

	resp := get(t, https, "https://app.example.test/")
	if resp.StatusCode != http.StatusOK || resp.Body != "hello from upstream" {
		t.Errorf("proxied response = %d %q", resp.StatusCode, resp.Body)
	}

	resp = get(t, https, "https://auth.example.test/")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("auth host (no upstream yet) = %d, want 404", resp.StatusCode)
	}

	plain := clientFor(env.redirectAddr, nil)
	resp = get(t, plain, "http://app.example.test/x?y=1")
	want := "https://app.example.test:" + httpsPort + "/x?y=1"
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
		t.Errorf("redirect = %d %q, want 308 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	resp = get(t, plain, "http://evil.example/")
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Errorf("unknown host redirect = %d %q, want 400 and no Location", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRunDeniesByDefault(t *testing.T) {
	env := newTestEnv(t, minimalConfig)
	startRun(t, "-config", env.path)
	resp := get(t, clientFor(env.httpsAddr, env.pool), "https://app.example.test/")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 without the dev flag", resp.StatusCode)
	}
}

func TestRunStartupFailures(t *testing.T) {
	missingCert := newTestEnv(t, strings.Replace(minimalConfig, "cert_file: cert.pem", "cert_file: /nonexistent/cert.pem", 1))
	// The loopback check runs before anything is bound, so 0.0.0.0 is never opened.
	publicListen := newTestEnv(t, strings.Replace(minimalConfig, `listen: ":8443"`, `listen: "0.0.0.0:8443"`, 1)).path

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing certificate", []string{"-config", missingCert.path}, "loading TLS certificate"},
		{"dev flag on public listener", []string{"-config", publicListen, "-dev-allow-unauthenticated"}, "loopback"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out syncBuffer
			err := run(t.Context(), tt.args, &out, testGetenv, nil)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// A misconfigured IdP must stop startup before any listener is bound, and the
// error must not carry the client secret.
func TestRunFailsFastOnBadIdP(t *testing.T) {
	idp := testidp.New(t)
	idp.EditDiscovery(func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} })
	env := newTestEnvWithIdP(t, minimalConfig, idp)

	var out syncBuffer
	err := run(t.Context(), []string{"-config", env.path}, &out, testGetenv, nil)
	if err == nil || !strings.Contains(err.Error(), "S256") {
		t.Fatalf("err = %v, want PKCE S256 error", err)
	}
	if strings.Contains(err.Error()+out.String(), testSecret) {
		t.Error("client secret appears in error or logs")
	}
	for _, addr := range []string{env.httpsAddr, env.redirectAddr} {
		var lc net.ListenConfig
		ln, lerr := lc.Listen(t.Context(), "tcp", addr)
		if lerr != nil {
			t.Errorf("%s still bound after failed startup: %v", addr, lerr)
			continue
		}
		_ = ln.Close()
	}
	if hasMsg(logLines(t, out.String()), "warden starting") {
		t.Error("logged startup despite failed discovery")
	}
}

func TestRunFailsWhenPortTaken(t *testing.T) {
	env := newTestEnv(t, minimalConfig)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", env.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	var out syncBuffer
	err = run(t.Context(), []string{"-config", env.path}, &out, testGetenv, nil)
	if err == nil || !strings.Contains(err.Error(), "listening on") {
		t.Fatalf("err = %v, want listen error", err)
	}
}
