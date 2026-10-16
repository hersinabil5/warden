package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// keyPrefix namespaces every Warden key in Redis.
const keyPrefix = "warden:"

// Redis client timeouts (invariant 10). Redis is local; slow means broken.
const (
	redisDialTimeout  = 2 * time.Second
	redisReadTimeout  = time.Second
	redisWriteTimeout = time.Second
	redisPoolTimeout  = 2 * time.Second
)

// ErrNotFound means the session or one-time value does not exist, expired,
// or does not apply here. Callers treat it as "not authenticated". Any other
// error is a store failure, which callers must also treat as a deny.
var ErrNotFound = errors.New("session: not found")

// Session is the identity Warden holds for a signed-in user.
type Session struct {
	Subject      string    `json:"sub"`
	Username     string    `json:"username"`
	Email        string    `json:"email"` // set only when the IdP marked it verified
	Groups       []string  `json:"groups"`
	AuthTime     time.Time `json:"auth_time"`
	AMR          []string  `json:"amr"`
	RefreshToken string    `json:"refresh_token"` // secret; never logged
	// CSRFToken guards the admin API's mutating endpoints for this session
	// (docs/DECISIONS.md D22). Random per session; never logged or listed.
	CSRFToken string    `json:"csrf_token"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"last_seen"`
	// Hash is the main session's HashID, set on lookup for audit
	// correlation. It is the storage key, so it is never stored itself.
	Hash string `json:"-"`
}

// Format prints only non-secret identity fields, for every fmt verb, so a
// stray %v cannot leak the refresh token (invariant 9).
func (s Session) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "session{user="+s.Username+" sub="+s.Subject+"}")
}

func (s Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", s.Username), slog.String("sub", s.Subject))
}

// record is what Redis stores under a session key. A main session holds the
// identity. An app session (one per app host, docs/DECISIONS.md D1) holds
// only a pointer to its main session, so revoking the main session revokes
// every app session on its next request.
type record struct {
	Kind    string   `json:"kind"`
	Session *Session `json:"session,omitempty"`
	Parent  string   `json:"parent,omitempty"` // main session hash
	Host    string   `json:"host,omitempty"`
}

const (
	kindMain = "main"
	kindApp  = "app"
)

// Options configures a Store.
type Options struct {
	AbsoluteTTL time.Duration
	IdleTimeout time.Duration
	Now         func() time.Time
}

// Store keeps server-side sessions in Redis, keyed by SHA-256 of the session
// ID (docs/DECISIONS.md D2). Raw IDs exist only in cookies.
type Store struct {
	rdb  redis.UniversalClient
	abs  time.Duration
	idle time.Duration
	now  func() time.Time
}

// NewClient returns a Redis client with bounded timeouts.
func NewClient(addr string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  redisDialTimeout,
		ReadTimeout:  redisReadTimeout,
		WriteTimeout: redisWriteTimeout,
		PoolTimeout:  redisPoolTimeout,
	})
}

func NewStore(rdb redis.UniversalClient, opts Options) *Store {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{rdb: rdb, abs: opts.AbsoluteTTL, idle: opts.IdleTimeout, now: opts.Now}
}

// Ping checks that Redis is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	return nil
}

// AbsoluteTTL is the maximum session lifetime, for cookie Max-Age.
func (s *Store) AbsoluteTTL() time.Duration { return s.abs }

// HashID returns the storage key for a session ID: hex SHA-256. It is also a
// safe correlation value for logs once truncated.
func HashID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// NewID returns a 256-bit random value, base64url-encoded (invariant 7, 11).
func NewID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating session ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sessionKey(hash string) string  { return keyPrefix + "s:" + hash }
func childrenKey(hash string) string { return keyPrefix + "children:" + hash }

// Create stores a new main session and returns its ID. A fresh ID is always
// generated, so a session can never be fixed by a client (T2).
func (s *Store) Create(ctx context.Context, sess Session) (string, error) {
	if sess.Subject == "" {
		return "", errors.New("session store: subject is required")
	}
	now := s.now()
	sess.Created, sess.LastSeen = now, now
	id, err := NewID()
	if err != nil {
		return "", err
	}
	if sess.CSRFToken, err = NewID(); err != nil {
		return "", err
	}
	hash := HashID(id)
	rec := record{Kind: kindMain, Session: &sess}
	if err := s.write(ctx, hash, rec, s.ttl(&sess, now), false); err != nil {
		return "", err
	}
	if err := s.index(ctx, hash, &sess); err != nil {
		// An unindexed session could not be revoked per user; drop it.
		_ = s.rdb.Del(ctx, sessionKey(hash)).Err()
		return "", err
	}
	return id, nil
}

// Get returns the live main session for id and records activity.
func (s *Store) Get(ctx context.Context, id string) (*Session, error) {
	return s.getMain(ctx, HashID(id))
}

// CreateApp creates an app-host session pointing at a live main session.
func (s *Store) CreateApp(ctx context.Context, mainHash, host string) (string, error) {
	parent, err := s.getMain(ctx, mainHash)
	if err != nil {
		return "", err
	}
	id, err := NewID()
	if err != nil {
		return "", err
	}
	hash := HashID(id)
	ttl := parent.Created.Add(s.abs).Sub(s.now())
	if err := s.write(ctx, hash, record{Kind: kindApp, Parent: mainHash, Host: host}, ttl, false); err != nil {
		return "", err
	}
	// Index children so Delete can clean them up; correctness does not
	// depend on it, since an app session is useless once its parent is gone.
	pipe := s.rdb.TxPipeline()
	pipe.SAdd(ctx, childrenKey(mainHash), hash)
	pipe.Expire(ctx, childrenKey(mainHash), ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", fmt.Errorf("session store: indexing app session: %w", err)
	}
	return id, nil
}

// GetApp returns the main session behind an app session, provided the app
// session was issued for host. Activity refreshes the main session's idle
// timer.
func (s *Store) GetApp(ctx context.Context, id, host string) (*Session, error) {
	rec, err := s.load(ctx, HashID(id))
	if err != nil {
		return nil, err
	}
	if rec.Kind != kindApp || rec.Host != host || rec.Parent == "" {
		return nil, ErrNotFound
	}
	return s.getMain(ctx, rec.Parent)
}

// Delete removes a main session, its app sessions, and its index entries.
// Deleting an unknown ID is not an error.
func (s *Store) Delete(ctx context.Context, id string) error {
	hash := HashID(id)
	sub := ""
	rec, err := s.load(ctx, hash)
	switch {
	case err == nil && rec.Kind == kindMain && rec.Session != nil:
		sub = rec.Session.Subject
	case err != nil && !errors.Is(err, ErrNotFound):
		return err
	}
	return s.revoke(ctx, hash, sub)
}

func (s *Store) getMain(ctx context.Context, hash string) (*Session, error) {
	rec, err := s.load(ctx, hash)
	if err != nil {
		return nil, err
	}
	if rec.Kind != kindMain || rec.Session == nil {
		return nil, ErrNotFound
	}
	sess := rec.Session
	now := s.now()
	// Check the record's own timestamps, not only Redis expiry.
	if !now.Before(sess.Created.Add(s.abs)) || !now.Before(sess.LastSeen.Add(s.idle)) {
		_ = s.rdb.Del(ctx, sessionKey(hash)).Err()
		return nil, ErrNotFound
	}
	sess.LastSeen = now
	if err := s.touch(ctx, hash, rec); err != nil {
		return nil, err
	}
	sess.Hash = hash
	return sess, nil
}

// touch rewrites a session with its new LastSeen, only if it still exists
// (SET XX), so a touch racing a revocation cannot resurrect it (invariant 8).
func (s *Store) touch(ctx context.Context, hash string, rec *record) error {
	return s.write(ctx, hash, *rec, s.ttl(rec.Session, s.now()), true)
}

// ttl is the Redis expiry for a main session: the idle timeout, capped by
// what remains of the absolute lifetime.
func (s *Store) ttl(sess *Session, now time.Time) time.Duration {
	return min(s.idle, sess.Created.Add(s.abs).Sub(now))
}

func (s *Store) write(ctx context.Context, hash string, rec record, ttl time.Duration, mustExist bool) error {
	if ttl <= 0 {
		return ErrNotFound
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("session store: encoding: %w", err)
	}
	args := redis.SetArgs{TTL: ttl, Mode: "NX"}
	if mustExist {
		args.Mode = "XX"
	}
	err = s.rdb.SetArgs(ctx, sessionKey(hash), data, args).Err()
	switch {
	case errors.Is(err, redis.Nil):
		if mustExist {
			return ErrNotFound
		}
		return errors.New("session store: ID collision")
	case err != nil:
		return fmt.Errorf("session store: %w", err)
	}
	return nil
}

func (s *Store) load(ctx context.Context, hash string) (*record, error) {
	data, err := s.rdb.Get(ctx, sessionKey(hash)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("session store: decoding: %w", err)
	}
	return &rec, nil
}

func onceKey(ns, token string) string { return keyPrefix + "once:" + ns + ":" + HashID(token) }
func usedKey(ns, token string) string { return keyPrefix + "used:" + ns + ":" + HashID(token) }

// PutOnce stores value under a one-time token for ttl. Only the token's hash
// is stored.
func (s *Store) PutOnce(ctx context.Context, ns, token string, value []byte, ttl time.Duration) error {
	ok, err := s.rdb.SetNX(ctx, onceKey(ns, token), value, ttl).Result()
	if err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	if !ok {
		return errors.New("session store: one-time token collision")
	}
	return nil
}

// TakeOnce atomically returns and deletes the value for token (GETDEL), so
// it can be redeemed at most once.
func (s *Store) TakeOnce(ctx context.Context, ns, token string) ([]byte, error) {
	v, err := s.rdb.GetDel(ctx, onceKey(ns, token)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	return v, nil
}

// MarkUsed records token as used for ttl and reports whether this was the
// first use. It makes OAuth state single-use (invariant 4).
func (s *Store) MarkUsed(ctx context.Context, ns, token string, ttl time.Duration) (bool, error) {
	first, err := s.rdb.SetNX(ctx, usedKey(ns, token), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("session store: %w", err)
	}
	return first, nil
}

// DeleteApp removes one app session. Unknown IDs, and IDs that are not app
// sessions (a main session ID presented as an app cookie), are left alone.
func (s *Store) DeleteApp(ctx context.Context, id string) error {
	hash := HashID(id)
	rec, err := s.load(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rec.Kind != kindApp {
		return nil
	}
	if err := s.rdb.Del(ctx, sessionKey(hash)).Err(); err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	return nil
}
