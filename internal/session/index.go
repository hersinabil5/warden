package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// Session indexes (docs/DECISIONS.md D21). Both are sorted sets of main
// session hashes scored by creation time, so entries past the absolute
// lifetime are pruned by score; sessions that idled out or were deleted
// without their subject known are pruned when a listing finds them gone.
const allSessionsKey = keyPrefix + "sessions"

func userKey(sub string) string { return keyPrefix + "user:" + sub }

// Listing limits.
const (
	DefaultListLimit = 50
	MaxListLimit     = 200
)

// index records a new main session in both indexes.
func (s *Store) index(ctx context.Context, hash string, sess *Session) error {
	z := redis.Z{Score: float64(sess.Created.Unix()), Member: hash}
	pipe := s.rdb.TxPipeline()
	pipe.ZAdd(ctx, allSessionsKey, z)
	pipe.ZAdd(ctx, userKey(sess.Subject), z)
	// The user index outlives each of its sessions by at most the absolute
	// lifetime of the newest one.
	pipe.Expire(ctx, userKey(sess.Subject), s.abs)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("session store: indexing session: %w", err)
	}
	return nil
}

// revoke deletes a session, its app sessions, and its index entries.
func (s *Store) revoke(ctx context.Context, hash, sub string) error {
	children, err := s.rdb.SMembers(ctx, childrenKey(hash)).Result()
	if err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	keys := []string{sessionKey(hash), childrenKey(hash)}
	for _, c := range children {
		keys = append(keys, sessionKey(c))
	}
	pipe := s.rdb.TxPipeline()
	pipe.Del(ctx, keys...)
	pipe.ZRem(ctx, allSessionsKey, hash)
	if sub != "" {
		pipe.ZRem(ctx, userKey(sub), hash)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	return nil
}

// DeleteHash revokes the main session with storage key hash (as listed by
// List), with its app sessions. Anything that is not a live main session's
// hash is ErrNotFound.
func (s *Store) DeleteHash(ctx context.Context, hash string) error {
	if !validHash(hash) {
		return ErrNotFound
	}
	rec, err := s.load(ctx, hash)
	if err != nil {
		return err
	}
	if rec.Kind != kindMain || rec.Session == nil {
		return ErrNotFound
	}
	return s.revoke(ctx, hash, rec.Session.Subject)
}

// RevokeUser revokes every session of the subject and returns how many were
// live. It reads only that subject's index.
func (s *Store) RevokeUser(ctx context.Context, sub string) (int, error) {
	if sub == "" {
		return 0, errors.New("session store: subject is required")
	}
	hashes, err := s.rdb.ZRange(ctx, userKey(sub), 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("session store: %w", err)
	}
	n := 0
	for _, h := range hashes {
		rec, lerr := s.load(ctx, h)
		switch {
		case lerr == nil && rec.Kind == kindMain && rec.Session != nil:
			n++
		case lerr != nil && !errors.Is(lerr, ErrNotFound):
			return n, lerr
		}
		if err := s.revoke(ctx, h, sub); err != nil {
			return n, err
		}
	}
	if err := s.rdb.Del(ctx, userKey(sub)).Err(); err != nil {
		return n, fmt.Errorf("session store: %w", err)
	}
	return n, nil
}

// List returns live main sessions, newest first, starting at offset, and
// the number of indexed sessions. It does not count as activity.
func (s *Store) List(ctx context.Context, offset, limit int) ([]Session, int, error) {
	offset = max(offset, 0)
	if limit <= 0 {
		limit = DefaultListLimit
	}
	limit = min(limit, MaxListLimit)
	if err := s.prune(ctx, allSessionsKey); err != nil {
		return nil, 0, err
	}
	hashes, err := s.rdb.ZRevRange(ctx, allSessionsKey, int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("session store: %w", err)
	}
	out, err := s.peekAll(ctx, hashes, "")
	if err != nil {
		return nil, 0, err
	}
	total, err := s.rdb.ZCard(ctx, allSessionsKey).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("session store: %w", err)
	}
	return out, int(total), nil
}

// ListUser returns the subject's live main sessions, newest first. It does
// not count as activity.
func (s *Store) ListUser(ctx context.Context, sub string) ([]Session, error) {
	if sub == "" {
		return nil, nil
	}
	if err := s.prune(ctx, userKey(sub)); err != nil {
		return nil, err
	}
	hashes, err := s.rdb.ZRevRange(ctx, userKey(sub), 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}
	return s.peekAll(ctx, hashes, sub)
}

// prune drops index entries created more than the absolute lifetime ago.
func (s *Store) prune(ctx context.Context, key string) error {
	cutoff := s.now().Add(-s.abs).Unix()
	if err := s.rdb.ZRemRangeByScore(ctx, key, "-inf", "("+strconv.FormatInt(cutoff, 10)).Err(); err != nil {
		return fmt.Errorf("session store: %w", err)
	}
	return nil
}

// peekAll loads the live sessions among hashes and drops dead ones from the
// indexes: the global one, and the subject's when it is known (sub, or the
// dead session's record if it still exists).
func (s *Store) peekAll(ctx context.Context, hashes []string, sub string) ([]Session, error) {
	out := make([]Session, 0, len(hashes))
	for _, h := range hashes {
		sess, err := s.peek(ctx, h)
		switch {
		case err == nil:
			out = append(out, *sess)
		case errors.Is(err, ErrNotFound):
			pipe := s.rdb.Pipeline()
			pipe.ZRem(ctx, allSessionsKey, h)
			owner := sub
			if owner == "" && sess != nil {
				owner = sess.Subject
			}
			if owner != "" {
				pipe.ZRem(ctx, userKey(owner), h)
			}
			if _, perr := pipe.Exec(ctx); perr != nil {
				return nil, fmt.Errorf("session store: %w", perr)
			}
		default:
			return nil, err
		}
	}
	return out, nil
}

// peek reads a main session without recording activity. The copy it
// returns has no refresh or CSRF token. A dead session is ErrNotFound, with the
// session still returned when its record exists, for index cleanup.
func (s *Store) peek(ctx context.Context, hash string) (*Session, error) {
	rec, err := s.load(ctx, hash)
	if err != nil {
		return nil, err
	}
	if rec.Kind != kindMain || rec.Session == nil {
		return nil, ErrNotFound
	}
	sess := *rec.Session
	sess.Hash, sess.RefreshToken, sess.CSRFToken = hash, "", ""
	now := s.now()
	if !now.Before(sess.Created.Add(s.abs)) || !now.Before(sess.LastSeen.Add(s.idle)) {
		return &sess, ErrNotFound
	}
	return &sess, nil
}

// validHash reports whether h looks like a HashID: 64 lowercase hex digits.
func validHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
