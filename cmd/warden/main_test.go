package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6455 handshake in a test upstream
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/hersinabil5/warden/internal/admin"
	"github.com/hersinabil5/warden/internal/authn/testidp"
	"github.com/hersinabil5/warden/internal/config"
	"github.com/hersinabil5/warden/internal/demo"
	"github.com/hersinabil5/warden/internal/identity"
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
		"signing_key_file: signing.pem", "signing_key_file: "+keyPath, // the test TLS key is P-256 too
		"issuer: https://idp.example.test/realms/warden", "issuer: "+idp.Issuer,
		`redis_addr: "localhost:6379"`, `redis_addr: "`+miniredis.RunT(t).Addr()+`"`,
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
		{"removed dev flag", []string{"-config", writeConfig(t), "-dev-skip-policy"}, "dev-skip-policy"},
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

			err := run(ctx, tt.args, &out, io.Discard, testGetenv, nil)
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
	err := run(context.Background(), []string{"-h"}, &out, io.Discard, testGetenv, nil)
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
		done <- run(ctx, []string{"-config", writeConfig(t)}, &out, io.Discard, testGetenv, func(l *slog.Logger) {
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
	go func() {
		done <- run(ctx, append([]string{"-config", env.path}, extraArgs...), &out, io.Discard, testGetenv, nil)
	}()
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
	if err := run(ctx, []string{"-config", writeConfig(t)}, &out, io.Discard, testGetenv, nil); err != nil {
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
	err := run(context.Background(), []string{"-config", path}, &out, io.Discard, testGetenv, nil)
	if err == nil {
		t.Fatal("run succeeded, want error")
	}
	if strings.Contains(err.Error(), testSecret) || strings.Contains(out.String(), testSecret) {
		t.Errorf("secret echoed: err=%q out=%q", err, out.String())
	}
}

func TestRunFailsWhenSecretEnvUnset(t *testing.T) {
	var out syncBuffer
	err := run(context.Background(), []string{"-config", writeConfig(t)}, &out, io.Discard,
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
	go func() { done <- run(ctx, args, &out, io.Discard, testGetenv, nil) }()
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
	startRun(t, "-config", env.path)

	https := clientFor(env.httpsAddr, env.pool)
	_, httpsPort, _ := net.SplitHostPort(env.httpsAddr)

	// Unauthenticated: sent to login, never to the upstream.
	resp := get(t, https, "https://app.example.test/")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "https://auth.example.test:"+httpsPort+"/.warden/login?") {
		t.Errorf("unauthenticated response = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if strings.Contains(resp.Body, "hello from upstream") {
		t.Error("upstream reached without a session")
	}

	resp = get(t, https, "https://auth.example.test/")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("auth host (no upstream yet) = %d, want 404", resp.StatusCode)
	}
	// HTTPS responses carry HSTS (default one year); plain HTTP never does.
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HTTPS Strict-Transport-Security = %q, want the one-year default", got)
	}

	plain := clientFor(env.redirectAddr, nil)
	resp = get(t, plain, "http://app.example.test/x?y=1")
	want := "https://app.example.test:" + httpsPort + "/x?y=1"
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
		t.Errorf("redirect = %d %q, want 308 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got != "" {
		t.Errorf("plain HTTP Strict-Transport-Security = %q, want none", got)
	}
	resp = get(t, plain, "http://evil.example/")
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Errorf("unknown host redirect = %d %q, want 400 and no Location", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRunServesLogin(t *testing.T) {
	idp := testidp.New(t)
	env := newTestEnvWithIdP(t, minimalConfig, idp)
	startRun(t, "-config", env.path)

	resp := get(t, clientFor(env.httpsAddr, env.pool), "https://auth.example.test/.warden/login")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, idp.Server.URL+"/auth?") {
		t.Errorf("Location = %q, want the IdP authorize endpoint", loc)
	}
	_, port, _ := net.SplitHostPort(env.httpsAddr)
	if !strings.Contains(loc, "redirect_uri=https%3A%2F%2Fauth.example.test%3A"+port+"%2F.warden%2Fcallback") {
		t.Errorf("Location %q lacks the configured redirect_uri", loc)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), "__Host-warden_login_") {
		t.Errorf("no pre-auth cookie: %q", resp.Header.Get("Set-Cookie"))
	}

	// App hosts do not serve login.
	resp = get(t, clientFor(env.httpsAddr, env.pool), "https://app.example.test/.warden/login")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("login on app host = %d, want 404", resp.StatusCode)
	}
}

// browserFor is a cookie-keeping client that sends *.example.test to Warden
// and everything else (the fake IdP) to its real address, and does not follow
// redirects, so tests can inspect each hop.
func browserFor(t *testing.T, env testEnv) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var d net.Dialer
	return &http.Client{
		Timeout: 5 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.Contains(addr, ".example.test:") {
					addr = env.httpsAddr
				}
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: env.pool, MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// TestRunLoginEndToEnd is the M2 acceptance flow through real listeners: a
// logged-out request to a route goes to the IdP, and after login the browser
// lands on the original URL with a host-only app cookie.
func TestRunLoginEndToEnd(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream saw "+r.URL.RequestURI()+" cookies="+r.Header.Get("Cookie")) //nolint:gosec // G705: test upstream echoing the request as text/plain
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	env := newTestEnvWithIdP(t, strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1), idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)

	b := browserFor(t, env)
	final, hops := browse(t, b, "https://app.example.test:"+port+"/dash?x=1")
	if final.StatusCode != http.StatusOK || final.Body != "upstream saw /dash?x=1 cookies=" {
		t.Fatalf("final = %d %q\nhops:\n%s", final.StatusCode, final.Body, strings.Join(hops, "\n"))
	}
	if !strings.HasPrefix(hops[len(hops)-1], "200 https://app.example.test:"+port+"/dash?x=1") {
		t.Fatalf("did not land on the original URL:\n%s", strings.Join(hops, "\n"))
	}
	if idp.TokenHits() != 1 {
		t.Errorf("token endpoint hits = %d, want 1", idp.TokenHits())
	}

	// Host-only cookies: the app cookie is not sent to another route or the
	// auth host, and the main cookie never reaches the app.
	appURL, _ := url.Parse("https://app.example.test:" + port + "/")
	authURL, _ := url.Parse("https://auth.example.test:" + port + "/")
	if len(b.Jar.Cookies(appURL)) == 0 || len(b.Jar.Cookies(authURL)) == 0 {
		t.Fatal("expected cookies on both hosts")
	}
	for _, c := range b.Jar.Cookies(appURL) {
		for _, a := range b.Jar.Cookies(authURL) {
			if c.Name == a.Name && c.Value == a.Value {
				t.Errorf("cookie %s shared between hosts", c.Name)
			}
		}
	}

	// Logout on the auth host revokes the app session on its next request.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://auth.example.test:"+port+"/.warden/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://auth.example.test:"+port)
	out, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = out.Body.Close()
	if out.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d, want 303", out.StatusCode)
	}
	after := get(t, b, "https://app.example.test:"+port+"/dash?x=1")
	if after.StatusCode != http.StatusFound || !strings.Contains(after.Header.Get("Location"), "/.warden/login?") {
		t.Errorf("after logout = %d %q, want a login redirect", after.StatusCode, after.Header.Get("Location"))
	}
}

// browse follows redirects from target with b until a non-redirect response,
// returning it and each hop ("status url").
func browse(t *testing.T, b *http.Client, target string) (response, []string) {
	t.Helper()
	var hops []string
	for range 10 {
		resp := get(t, b, target)
		hops = append(hops, strconv.Itoa(resp.StatusCode)+" "+target)
		if resp.StatusCode != http.StatusFound {
			return resp, hops
		}
		base, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		next, err := base.Parse(resp.Header.Get("Location")) // relative, as a browser resolves it
		if err != nil {
			t.Fatal(err)
		}
		target = next.String()
	}
	t.Fatalf("redirect loop:\n%s", strings.Join(hops, "\n"))
	return response{}, nil
}

func splitPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}

// A signed-in user that no rule allows gets 403 after login (invariant 1).
func TestRunDeniesByPolicy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1)
	cfg = strings.Replace(cfg, "        - authenticated: true", "        - groups: [nobody-has-this]", 1)
	env := newTestEnvWithIdP(t, cfg, idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)

	final, hops := browse(t, browserFor(t, env), "https://app.example.test:"+port+"/")
	if final.StatusCode != http.StatusForbidden || idp.TokenHits() != 1 {
		t.Errorf("signed-in request = %d (token hits %d), want 403 after login\n%s",
			final.StatusCode, idp.TokenHits(), strings.Join(hops, "\n"))
	}
}

// PLAN.md M5: every allow and deny lands in the configured audit file with a
// reason.
func TestRunAuditsDecisionsToFile(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	auditPath := filepath.Join(t.TempDir(), "audit", "audit.jsonl")
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1)
	cfg = strings.Replace(cfg, "audit: {sink: stdout}", "audit: {sink: file, file: "+auditPath+"}", 1)
	env := newTestEnvWithIdP(t, cfg, idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)

	if final, hops := browse(t, browserFor(t, env), "https://app.example.test:"+port+"/x"); final.StatusCode != http.StatusOK {
		t.Fatalf("signed-in request = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	var events []map[string]any
	waitFor(t, func() bool {
		b, err := os.ReadFile(auditPath) //nolint:gosec // G304: test temp file
		if err != nil {
			return false
		}
		events = logLines(t, string(b))
		return len(events) >= 2
	})
	first, last := events[0], events[len(events)-1]
	if first["decision"] != "deny" || first["reason"] != "unauthenticated" || first["path"] != "/x" {
		t.Errorf("first event = %v, want the unauthenticated deny", first)
	}
	if sess, _ := last["session"].(string); last["decision"] != "allow" || last["rule"] != "allow[0]" ||
		last["status"] != float64(200) || last["user"] == "" || len(sess) != 12 {
		t.Errorf("last event = %v, want the allow", last)
	}
}

const adminSection = `admin:
  allow:
    - groups: [admins]
      require_mfa_within: 1h
routes:`

// PLAN.md M5 acceptance: revoking bob's sessions via the admin API makes his
// next request redirect to login. Bob himself cannot use the API.
func TestRunAdminRevokesUser(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1)
	cfg = strings.Replace(cfg, "routes:", adminSection, 1)
	env := newTestEnvWithIdP(t, cfg, idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	app := "https://app.example.test:" + port + "/"
	api := "https://auth.example.test:" + port + "/.warden/api/"

	idp.SetUser(func() map[string]any {
		return map[string]any{"sub": "sub-bob", "preferred_username": "bob", "groups": []string{"dev"}}
	})
	bob := browserFor(t, env)
	if final, hops := browse(t, bob, app); final.StatusCode != http.StatusOK {
		t.Fatalf("bob login = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	if r := get(t, bob, api+"sessions"); r.StatusCode != http.StatusForbidden {
		t.Errorf("bob on the admin API = %d, want 403", r.StatusCode)
	}
	// PLAN.md M6 acceptance: a non-admin gets 403 on the dashboard.
	dash := "https://auth.example.test:" + port + "/.warden/admin/"
	if r := get(t, bob, dash); r.StatusCode != http.StatusForbidden || strings.Contains(r.Body, "<script") {
		t.Errorf("bob on the dashboard = %d", r.StatusCode)
	}
	if r := get(t, browserFor(t, env), dash); r.StatusCode != http.StatusFound || !strings.Contains(r.Header.Get("Location"), "/.warden/login") {
		t.Errorf("logged out on the dashboard = %d %q", r.StatusCode, r.Header.Get("Location"))
	}

	idp.SetUser(func() map[string]any {
		return map[string]any{"sub": "sub-alice", "preferred_username": "alice", "groups": []string{"admins"},
			"amr": []string{"pwd", "otp"}, "auth_time": time.Now().Unix()}
	})
	alice := browserFor(t, env)
	if final, hops := browse(t, alice, "https://auth.example.test:"+port+"/.warden/login"); final.StatusCode != http.StatusOK {
		t.Fatalf("alice login = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	me := get(t, alice, api+"me")
	var meBody struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal([]byte(me.Body), &meBody); err != nil || me.StatusCode != http.StatusOK || meBody.CSRF == "" {
		t.Fatalf("me = %d %s", me.StatusCode, me.Body)
	}
	// The dashboard is served (or reports that it isn't built) under the CSP.
	if r := get(t, alice, dash); (r.StatusCode != http.StatusOK && r.StatusCode != http.StatusServiceUnavailable) ||
		r.Header.Get("Content-Security-Policy") != admin.DashboardCSP {
		t.Errorf("alice on the dashboard = %d, CSP %q", r.StatusCode, r.Header.Get("Content-Security-Policy"))
	}

	revoke := func(token string) response {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, api+"users/revoke", strings.NewReader(`{"sub":"sub-bob"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://auth.example.test:"+port)
		req.Header.Set("X-CSRF-Token", token)
		resp, err := alice.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return response{resp.StatusCode, resp.Header, string(body)}
	}
	if r := revoke("wrong"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke without the CSRF token = %d", r.StatusCode)
	}
	if r := get(t, bob, app); r.StatusCode != http.StatusOK {
		t.Fatalf("bob was revoked by a refused request: %d", r.StatusCode)
	}
	if r := revoke(meBody.CSRF); r.StatusCode != http.StatusOK || !strings.Contains(r.Body, `"revoked":1`) {
		t.Fatalf("revoke = %d %s", r.StatusCode, r.Body)
	}
	after := get(t, bob, app)
	if after.StatusCode != http.StatusFound || !strings.Contains(after.Header.Get("Location"), "/.warden/login?") {
		t.Errorf("bob after revocation = %d %q, want a login redirect", after.StatusCode, after.Header.Get("Location"))
	}
	if r := get(t, alice, api+"me"); r.StatusCode != http.StatusOK {
		t.Errorf("alice's session was revoked too: %d", r.StatusCode)
	}
}

// PLAN.md M5 acceptance: removing alice from sre at the IdP blocks her from
// an sre-only route within the refresh interval; disabling her ends the
// session.
func TestRunGroupRefreshRevokesAccess(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "grafana")
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1)
	cfg = strings.Replace(cfg, "        - authenticated: true", "        - groups: [sre]", 1)
	cfg = strings.Replace(cfg, "group_refresh_interval: 5m", "group_refresh_interval: 1s", 1)
	env := newTestEnvWithIdP(t, cfg, idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	app := "https://app.example.test:" + port + "/"

	idp.SetUser(func() map[string]any { return map[string]any{"groups": []string{"sre"}} })
	b := browserFor(t, env)
	if final, hops := browse(t, b, app); final.StatusCode != http.StatusOK {
		t.Fatalf("login = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	idp.SetUser(func() map[string]any { return map[string]any{"groups": []string{"dev"}} })
	time.Sleep(1100 * time.Millisecond)
	if r := get(t, b, app); r.StatusCode != http.StatusForbidden {
		t.Fatalf("after removal from sre = %d, want 403", r.StatusCode)
	}
	idp.RevokeRefreshTokens() // user disabled
	time.Sleep(1100 * time.Millisecond)
	r := get(t, b, app)
	if r.StatusCode != http.StatusFound || !strings.Contains(r.Header.Get("Location"), "/.warden/login?") {
		t.Errorf("after disabling = %d %q, want a login redirect", r.StatusCode, r.Header.Get("Location"))
	}
}

// Warden refuses to run unaudited.
func TestRunFailsOnUnwritableAuditFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(minimalConfig, "audit: {sink: stdout}", "audit: {sink: file, file: "+blocker+"/audit.jsonl}", 1)
	env := newTestEnv(t, cfg)
	var out syncBuffer
	err := run(t.Context(), []string{"-config", env.path}, &out, io.Discard, testGetenv, nil)
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("err = %v, want an audit error", err)
	}
	if hasMsg(logLines(t, out.String()), "warden starting") {
		t.Error("started serving without an audit sink")
	}
}

func TestRunStartupFailures(t *testing.T) {
	missingCert := newTestEnv(t, strings.Replace(minimalConfig, "cert_file: cert.pem", "cert_file: /nonexistent/cert.pem", 1))

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing certificate", []string{"-config", missingCert.path}, "loading TLS certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out syncBuffer
			err := run(t.Context(), tt.args, &out, io.Discard, testGetenv, nil)
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
	err := run(t.Context(), []string{"-config", env.path}, &out, io.Discard, testGetenv, nil)
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

func TestRunFailsFastWithoutRedis(t *testing.T) {
	env := newTestEnv(t, strings.Replace(minimalConfig, `redis_addr: "localhost:6379"`, `redis_addr: "`+freeAddr(t)+`"`, 1))
	var out syncBuffer
	err := run(t.Context(), []string{"-config", env.path}, &out, io.Discard, testGetenv, nil)
	if err == nil || !strings.Contains(err.Error(), "Redis") {
		t.Fatalf("err = %v, want Redis connection error", err)
	}
	if hasMsg(logLines(t, out.String()), "warden starting") {
		t.Error("started without Redis")
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
	err = run(t.Context(), []string{"-config", env.path}, &out, io.Discard, testGetenv, nil)
	if err == nil || !strings.Contains(err.Error(), "listening on") {
		t.Fatalf("err = %v, want listen error", err)
	}
}

// M4: the upstream gets a signed assertion that verifies against Warden's
// published JWKS, and a forged header from the client never survives.
func TestRunAssertsIdentityEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Values("X-Warden-Identity")...)
		mu.Unlock()
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	env := newTestEnvWithIdP(t, strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream.URL, 1), idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)

	b := browserFor(t, env)
	if final, hops := browse(t, b, "https://app.example.test:"+port+"/"); final.StatusCode != http.StatusOK {
		t.Fatalf("login: %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.example.test:"+port+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Warden-Identity", "forged")
	req.Header.Set("X-Forwarded-Email", "admin@example.test")
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("upstream saw %d identity headers over 2 requests, want 2: %q", len(got), got)
	}
	keys := identity.NewRemoteKeys(b, "https://auth.example.test:"+port+"/.well-known/jwks.json", identity.RemoteKeysOptions{})
	v := &identity.Verifier{Issuer: "https://auth.example.test:" + port, Audience: "app.example.test", Keys: keys.Key}
	for _, raw := range got {
		id, err := v.Verify(t.Context(), raw)
		if err != nil {
			t.Fatalf("assertion %q: %v", raw, err)
		}
		if id.Username != "alice" || id.Subject != "user-1" {
			t.Errorf("identity = %+v", id)
		}
	}
}

// Login is rate limited per client by default (burst 10), through the real
// listener and the client's real address.
func TestRunRateLimitsLogin(t *testing.T) {
	env := newTestEnv(t, minimalConfig)
	startRun(t, "-config", env.path)
	c := clientFor(env.httpsAddr, env.pool)
	for i := range config.DefaultLoginRate.Burst {
		if resp := get(t, c, "https://auth.example.test/.warden/login"); resp.StatusCode != http.StatusFound {
			t.Fatalf("login %d: status %d, want 302", i+1, resp.StatusCode)
		}
	}
	resp := get(t, c, "https://auth.example.test/.warden/login")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("login past the burst: status %d, Retry-After %q; want 429 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if resp.Header.Get("Strict-Transport-Security") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("429 page lacks the security headers")
	}
}

// stepUpConfig protects /admin with groups admins + MFA within 10 minutes.
func stepUpConfig(upstream string) string {
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", upstream, 1)
	return strings.Replace(cfg, "        - authenticated: true", `        - authenticated: true
      paths:
        - prefix: /admin
          allow:
            - groups: [admins]
              require_mfa_within: 10m`, 1)
}

// PLAN.md M7 acceptance: an MFA-protected path with a stale login sends the
// user back to the IdP, then succeeds on the original URL.
func TestRunStepUpMFA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream saw "+r.URL.Path) //nolint:gosec // G705: test upstream echoing its path
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	env := newTestEnvWithIdP(t, stepUpConfig(upstream.URL), idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	b := browserFor(t, env)

	// Signed in an hour ago with password and OTP: fine for the app, too
	// old for /admin.
	idp.SetUser(func() map[string]any {
		return map[string]any{"amr": []string{"pwd", "otp"}, "auth_time": time.Now().Add(-time.Hour).Unix()}
	})
	if final, hops := browse(t, b, "https://app.example.test:"+port+"/"); final.StatusCode != http.StatusOK {
		t.Fatalf("app = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	// The IdP authenticates again (fresh auth_time) when asked to.
	idp.SetUser(func() map[string]any { return map[string]any{"amr": []string{"pwd", "otp"}} })
	final, hops := browse(t, b, "https://app.example.test:"+port+"/admin/x")
	if final.StatusCode != http.StatusOK || final.Body != "upstream saw /admin/x" {
		t.Fatalf("/admin after step-up = %d %q\n%s", final.StatusCode, final.Body, strings.Join(hops, "\n"))
	}
	if q := idp.LastAuthorize(); q.Get("prompt") != "login" || q.Get("max_age") != "0" {
		t.Errorf("step-up authorize query %v, want prompt=login and max_age=0", q)
	}
	if !strings.Contains(strings.Join(hops, "\n"), "step_up=1") {
		t.Errorf("no step-up in the hops:\n%s", strings.Join(hops, "\n"))
	}
}

// A user with no second factor re-authenticates once, then gets a 403: no
// redirect loop.
func TestRunStepUpWithoutOTPDoesNotLoop(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	env := newTestEnvWithIdP(t, stepUpConfig(upstream.URL), idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	b := browserFor(t, env)

	idp.SetUser(func() map[string]any {
		return map[string]any{"amr": []string{"pwd"}, "auth_time": time.Now().Add(-time.Hour).Unix()}
	})
	browse(t, b, "https://app.example.test:"+port+"/")
	idp.SetUser(func() map[string]any { return map[string]any{"amr": []string{"pwd"}} }) // fresh, still no OTP
	before := idp.TokenHits()
	final, hops := browse(t, b, "https://app.example.test:"+port+"/admin")
	if final.StatusCode != http.StatusForbidden || strings.Contains(final.Body, "upstream") {
		t.Fatalf("/admin = %d\n%s", final.StatusCode, strings.Join(hops, "\n"))
	}
	if n := idp.TokenHits() - before; n != 1 {
		t.Errorf("logins during the step-up = %d, want exactly 1\n%s", n, strings.Join(hops, "\n"))
	}
	// Asking again right away doesn't bounce to the IdP either.
	if again := get(t, b, "https://app.example.test:"+port+"/admin"); again.StatusCode != http.StatusForbidden {
		t.Errorf("second /admin = %d, want 403", again.StatusCode)
	}
}

// wsEcho is an upstream that accepts any WebSocket handshake and echoes
// bytes; done gets a value when a connection ends.
func wsEcho(t *testing.T, done chan<- struct{}) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-Websocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")) //nolint:gosec // G401: RFC 6455 handshake
		w.Header().Set("Sec-WebSocket-Accept", base64.StdEncoding.EncodeToString(sum[:]))
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close(); done <- struct{}{} }()
		_ = brw.Flush()
		_, _ = io.Copy(conn, brw)
	}))
	t.Cleanup(s.Close)
	return s
}

// PLAN.md M7: WebSockets get the same checks, and revocation reaches an open
// socket at the next re-check.
func TestRunWebSocketClosedOnLogout(t *testing.T) {
	done := make(chan struct{}, 4)
	up := wsEcho(t, done)
	idp := testidp.New(t)
	idp.SetClientSecret(testSecret)
	cfg := strings.Replace(minimalConfig, "http://127.0.0.1:9001", up.URL, 1)
	cfg = strings.Replace(cfg, "idle_timeout: 1h}", "idle_timeout: 1h, websocket_recheck: 1s}", 1)
	env := newTestEnvWithIdP(t, cfg, idp)
	startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	b := browserFor(t, env)
	browse(t, b, "https://app.example.test:"+port+"/") // log in

	appURL, _ := url.Parse("https://app.example.test:" + port + "/")
	var cookies []string
	for _, c := range b.Jar.Cookies(appURL) {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	dialer := tls.Dialer{Config: &tls.Config{ServerName: "app.example.test", RootCAs: env.pool, MinVersion: tls.VersionTLS12}}
	conn, err := dialer.DialContext(t.Context(), "tcp", env.httpsAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, "GET /live HTTP/1.1\r\nHost: app.example.test:"+port+"\r\n"+
		"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: https://app.example.test:"+port+"\r\n"+
		"Cookie: "+strings.Join(cookies, "; ")+"\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d, want 101", resp.StatusCode)
	}
	_, _ = io.WriteString(conn, "ping")
	buf := make([]byte, 4)
	if _, rerr := io.ReadFull(br, buf); rerr != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, rerr)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://auth.example.test:"+port+"/.warden/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://auth.example.test:"+port)
	out, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = out.Body.Close()
	loggedOut := time.Now()
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("socket still open after logout: %v", err)
	}
	if d := time.Since(loggedOut); d > 3*time.Second {
		t.Errorf("socket closed after %v, want within the 1s re-check", d)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("upstream side of the socket still open")
	}
}

const demoSection = `demo:
  enabled: true
  accounts:
    - {username: alice, password: alice, otp_secret: K5QXEZDFNZCGK5SPORYEC3DJMNSTAMBR, description: "admins, sre; has OTP"}
    - {username: bob, password: bob, description: "dev; no OTP"}
audit:`

func TestRunDemoLandingPage(t *testing.T) {
	cfg := strings.Replace(stepUpConfig("http://127.0.0.1:9001"), "audit:", demoSection, 1)
	env := newTestEnv(t, cfg)
	logs := startRun(t, "-config", env.path)
	_, port := splitPort(t, env.httpsAddr)
	resp := get(t, clientFor(env.httpsAddr, env.pool), "https://auth.example.test:"+port+"/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("landing = %d", resp.StatusCode)
	}
	key := []byte("WardenDevOtpAlice001")
	now := time.Now()
	codes := []string{demo.Code(key, now.Add(-demo.Period)), demo.Code(key, now), demo.Code(key, now.Add(demo.Period))}
	if !strings.Contains(resp.Body, codes[0]) && !strings.Contains(resp.Body, codes[1]) && !strings.Contains(resp.Body, codes[2]) {
		t.Errorf("landing page shows no current code for alice (%v)", codes)
	}
	for _, want := range []string{"https://app.example.test:" + port + "/admin", "groups admins with MFA within 10m", "any signed-in user"} {
		if !strings.Contains(resp.Body, want) {
			t.Errorf("landing page lacks %q", want)
		}
	}
	if strings.Contains(resp.Body, testSecret) {
		t.Error("landing page shows the client secret")
	}
	if !strings.Contains(logs.String(), "DEMO MODE") {
		t.Error("no demo mode warning at startup")
	}
	// Not on app hosts, and not without demo mode (TestRunServesHTTPSAndRedirects).
	if r := get(t, clientFor(env.httpsAddr, env.pool), "https://auth.example.test:"+port+"/demo"); r.StatusCode != http.StatusNotFound {
		t.Errorf("/demo = %d, want 404", r.StatusCode)
	}
}
