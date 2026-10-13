package session

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

const (
	absTTL  = 8 * time.Hour
	idleTTL = time.Hour
)

// clock is a settable time source shared by the store and miniredis.
type clock struct {
	mu sync.Mutex
	t  time.Time
	mr *miniredis.Miniredis
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	c.mr.FastForward(d)
}

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis, *clock) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := &clock{t: time.Unix(1_800_000_000, 0), mr: mr}
	rdb := NewClient(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	return NewStore(rdb, Options{AbsoluteTTL: absTTL, IdleTimeout: idleTTL, Now: c.now}), mr, c
}

func testSession() Session {
	return Session{
		Subject:      "sub-alice",
		Username:     "alice",
		Email:        "alice@warden.local",
		Groups:       []string{"admins", "sre"},
		AuthTime:     time.Unix(1_799_999_990, 0).UTC(),
		AMR:          []string{"pwd"},
		RefreshToken: "refresh-token-secret",
	}
}

func TestCreateAndGet(t *testing.T) {
	s, _, c := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(t.Context(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := testSession()
	if got.Subject != want.Subject || got.Username != want.Username || got.Email != want.Email ||
		strings.Join(got.Groups, ",") != "admins,sre" || !got.AuthTime.Equal(want.AuthTime) ||
		strings.Join(got.AMR, ",") != "pwd" || got.RefreshToken != want.RefreshToken {
		t.Errorf("Get = %+v", got)
	}
	if !got.Created.Equal(c.now()) || !got.LastSeen.Equal(c.now()) {
		t.Errorf("created/last seen = %v/%v, want %v", got.Created, got.LastSeen, c.now())
	}
}

func TestIDsAreRandom256Bit(t *testing.T) {
	s, _, _ := newTestStore(t)
	seen := map[string]bool{}
	for range 50 {
		id, err := s.Create(t.Context(), testSession())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(raw) != 32 {
			t.Fatalf("id %q is not 32 bytes of base64url", id)
		}
		if seen[id] {
			t.Fatal("repeated session ID")
		}
		seen[id] = true
	}
}

// Redis must hold only hashes of session IDs (invariant 7): a read of the
// store yields no usable cookie.
func TestRedisNeverHoldsRawIDs(t *testing.T) {
	s, mr, _ := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	appID, err := s.CreateApp(t.Context(), HashID(id), "whoami.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutOnce(t.Context(), "handshake", "one-time-code", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, k := range mr.Keys() {
		v, _ := mr.Get(k)
		members, _ := mr.Members(k)
		all := k + v + strings.Join(members, "")
		for _, secret := range []string{id, appID, "one-time-code"} {
			if strings.Contains(all, secret) {
				t.Errorf("redis key %q holds a raw secret", k)
			}
		}
	}
	if !mr.Exists(keyPrefix + "s:" + HashID(id)) {
		t.Error("session not stored under the SHA-256 of its ID")
	}
}

func TestGetRejectsUnknownIDs(t *testing.T) {
	s, _, _ := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "x", id + "x", id[:len(id)-1], strings.ToUpper(id), HashID(id)} {
		if _, err := s.Get(t.Context(), bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) err = %v, want ErrNotFound", bad, err)
		}
	}
}

func TestIdleTimeout(t *testing.T) {
	s, _, c := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	// Activity just inside the idle window keeps the session alive.
	for range 3 {
		c.advance(idleTTL - time.Minute)
		if _, err := s.Get(t.Context(), id); err != nil {
			t.Fatalf("active session expired: %v", err)
		}
	}
	c.advance(idleTTL)
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idle session err = %v, want ErrNotFound", err)
	}
}

// The idle check must not rely on Redis expiry alone.
func TestIdleTimeoutCheckedInRecord(t *testing.T) {
	s, mr, c := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	mr.SetTTL(keyPrefix+"s:"+HashID(id), 0) // as if the Redis TTL were lost
	c.mu.Lock()
	c.t = c.t.Add(idleTTL + time.Second)
	c.mu.Unlock()
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound from the record's own timestamps", err)
	}
}

func TestAbsoluteTTLDespiteActivity(t *testing.T) {
	s, _, c := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	var lived time.Duration
	for lived+30*time.Minute < absTTL {
		c.advance(30 * time.Minute)
		lived += 30 * time.Minute
		if _, err := s.Get(t.Context(), id); err != nil {
			t.Fatalf("session died early after %v: %v", lived, err)
		}
	}
	c.advance(absTTL - lived)
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v after absolute TTL, want ErrNotFound", err)
	}
}

func TestRedisTTLNeverExceedsLimits(t *testing.T) {
	s, mr, c := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	key := keyPrefix + "s:" + HashID(id)
	if ttl := mr.TTL(key); ttl <= 0 || ttl > idleTTL {
		t.Errorf("TTL after create = %v, want (0, %v]", ttl, idleTTL)
	}
	// Near the absolute limit, the TTL shrinks to what remains.
	for i := 0; i < 15; i++ {
		c.advance(30 * time.Minute)
		if _, err := s.Get(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	remaining := absTTL - 15*30*time.Minute
	if ttl := mr.TTL(key); ttl <= 0 || ttl > remaining {
		t.Errorf("TTL = %v, want (0, %v]", ttl, remaining)
	}
}

func TestDeleteRevokesImmediately(t *testing.T) {
	s, _, _ := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v after delete, want ErrNotFound", err)
	}
	if err := s.Delete(t.Context(), id); err != nil {
		t.Errorf("second delete: %v", err)
	}
}

// A touch racing a revocation must not resurrect the session.
func TestTouchDoesNotResurrect(t *testing.T) {
	s, mr, _ := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.load(t.Context(), HashID(id))
	if err != nil {
		t.Fatal(err)
	}
	mr.Del(keyPrefix + "s:" + HashID(id)) // revoked between load and touch
	if err := s.touch(t.Context(), HashID(id), rec); err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if mr.Exists(keyPrefix + "s:" + HashID(id)) {
		t.Fatal("touch recreated a revoked session")
	}
}

func TestAppSessions(t *testing.T) {
	s, _, c := newTestStore(t)
	mainID, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	const host = "whoami.example.test"
	appID, err := s.CreateApp(t.Context(), HashID(mainID), host)
	if err != nil {
		t.Fatal(err)
	}
	if appID == mainID {
		t.Fatal("app session reuses the main ID")
	}
	got, err := s.GetApp(t.Context(), appID, host)
	if err != nil || got.Username != "alice" {
		t.Fatalf("GetApp = %+v, %v", got, err)
	}

	// Bound to its host: the cookie is useless elsewhere.
	if _, err := s.GetApp(t.Context(), appID, "grafana.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app session on another host: err = %v, want ErrNotFound", err)
	}
	// An app ID is not a main session, and a main ID is not an app session.
	if _, err := s.Get(t.Context(), appID); !errors.Is(err, ErrNotFound) {
		t.Errorf("app ID accepted as main session: %v", err)
	}
	if _, err := s.GetApp(t.Context(), mainID, host); !errors.Is(err, ErrNotFound) {
		t.Errorf("main ID accepted as app session: %v", err)
	}

	// App activity keeps the main session from idling out.
	for range 3 {
		c.advance(idleTTL - time.Minute)
		if _, err := s.GetApp(t.Context(), appID, host); err != nil {
			t.Fatalf("app activity did not keep session alive: %v", err)
		}
	}

	// Revoking the main session revokes every app session on the next request.
	if err := s.Delete(t.Context(), mainID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApp(t.Context(), appID, host); !errors.Is(err, ErrNotFound) {
		t.Errorf("app session survived main revocation: %v", err)
	}
}

func TestCreateAppRequiresLiveParent(t *testing.T) {
	s, _, c := newTestStore(t)
	if _, err := s.CreateApp(t.Context(), HashID("no-such-session"), "whoami.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	mainID, _ := s.Create(t.Context(), testSession())
	c.advance(idleTTL + time.Second)
	if _, err := s.CreateApp(t.Context(), HashID(mainID), "whoami.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app session created for an idle-expired parent: %v", err)
	}
}

func TestOnce(t *testing.T) {
	s, _, c := newTestStore(t)
	if err := s.PutOnce(t.Context(), "code", "abc", []byte("payload"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeOnce(t.Context(), "other-ns", "abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("namespaces not separated: %v", err)
	}
	v, err := s.TakeOnce(t.Context(), "code", "abc")
	if err != nil || string(v) != "payload" {
		t.Fatalf("TakeOnce = %q, %v", v, err)
	}
	if _, err := s.TakeOnce(t.Context(), "code", "abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second take err = %v, want ErrNotFound", err)
	}

	if err := s.PutOnce(t.Context(), "code", "late", []byte("x"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.advance(31 * time.Second)
	if _, err := s.TakeOnce(t.Context(), "code", "late"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired code err = %v, want ErrNotFound", err)
	}
}

func TestMarkUsed(t *testing.T) {
	s, _, _ := newTestStore(t)
	first, err := s.MarkUsed(t.Context(), "state", "s1", time.Minute)
	if err != nil || !first {
		t.Fatalf("first MarkUsed = %v, %v", first, err)
	}
	again, err := s.MarkUsed(t.Context(), "state", "s1", time.Minute)
	if err != nil || again {
		t.Fatalf("second MarkUsed = %v, %v; want false", again, err)
	}
}

func TestRedisFailureIsNotNotFound(t *testing.T) {
	s, mr, _ := newTestStore(t)
	id, err := s.Create(t.Context(), testSession())
	if err != nil {
		t.Fatal(err)
	}
	mr.Close()
	if _, err := s.Get(t.Context(), id); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want a store error distinct from ErrNotFound", err)
	}
	if _, err := s.MarkUsed(t.Context(), "state", "s", time.Minute); err == nil {
		t.Error("MarkUsed succeeded with Redis down")
	}
}

func TestSessionDoesNotLeakRefreshToken(t *testing.T) {
	sess := testSession()
	var b strings.Builder
	slog.New(slog.NewJSONHandler(&b, nil)).Info("s", "session", sess)
	for _, out := range []string{b.String(), fmt.Sprintf("%v %+v %#v %s", sess, sess, sess, sess)} {
		if strings.Contains(out, "refresh-token-secret") {
			t.Errorf("refresh token in output: %s", out)
		}
	}
}

func TestNewClientHasTimeouts(t *testing.T) {
	o := NewClient("localhost:6379").Options()
	if o.DialTimeout <= 0 || o.ReadTimeout <= 0 || o.WriteTimeout <= 0 || o.PoolTimeout <= 0 {
		t.Errorf("missing timeouts: dial %v read %v write %v pool %v", o.DialTimeout, o.ReadTimeout, o.WriteTimeout, o.PoolTimeout)
	}
}

func TestDeleteAppOnlyDeletesAppSessions(t *testing.T) {
	s, _, _ := newTestStore(t)
	mainID, _ := s.Create(t.Context(), testSession())
	appID, err := s.CreateApp(t.Context(), HashID(mainID), "whoami.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp(t.Context(), mainID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(t.Context(), mainID); err != nil {
		t.Errorf("DeleteApp removed a main session: %v", err)
	}
	if err := s.DeleteApp(t.Context(), appID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApp(t.Context(), appID, "whoami.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app session survived DeleteApp: %v", err)
	}
	if err := s.DeleteApp(t.Context(), "unknown"); err != nil {
		t.Errorf("unknown ID: %v", err)
	}
}
