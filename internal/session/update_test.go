package session

import (
	"errors"
	"testing"
	"time"
)

func TestCreateStampsRefreshed(t *testing.T) {
	s, _, c := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	got, err := s.Get(t.Context(), id)
	if err != nil || !got.Refreshed.Equal(c.now()) {
		t.Errorf("refreshed = %v, %v; want %v", got.Refreshed, err, c.now())
	}
}

func TestUpdateReplacesIdentityOnly(t *testing.T) {
	s, _, c := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	orig, _ := s.Get(t.Context(), id)
	c.advance(time.Minute)

	upd := *orig
	upd.Groups = []string{"sre"}
	upd.RefreshToken = "rotated"
	upd.Refreshed = c.now()
	upd.Created = time.Unix(0, 0)     // ignored: server-owned
	upd.CSRFToken = "attacker-chosen" // ignored
	if err := s.Update(t.Context(), upd); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "sre" || got.RefreshToken != "rotated" || !got.Refreshed.Equal(c.now()) {
		t.Errorf("update not applied: %+v groups=%v", got, got.Groups)
	}
	if !got.Created.Equal(orig.Created) || got.CSRFToken != orig.CSRFToken {
		t.Errorf("server-owned fields changed: created %v csrf changed=%v", got.Created, got.CSRFToken != orig.CSRFToken)
	}
}

func TestUpdateRefusesOtherSubjectAndDeadSessions(t *testing.T) {
	s, _, _ := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	orig, _ := s.Get(t.Context(), id)

	other := *orig
	other.Subject = "sub-mallory"
	if err := s.Update(t.Context(), other); err == nil {
		t.Error("Update changed the subject")
	}
	if err := s.Update(t.Context(), Session{Subject: orig.Subject, Hash: "nothex"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("bad hash: %v", err)
	}
	// A refresh racing a revocation must not resurrect the session.
	if err := s.Delete(t.Context(), id); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(t.Context(), *orig); !errors.Is(err, ErrNotFound) {
		t.Errorf("update after revoke = %v, want ErrNotFound", err)
	}
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Error("update resurrected a revoked session")
	}
}

func TestTryLock(t *testing.T) {
	s, _, c := newTestStore(t)
	ok, err := s.TryLock(t.Context(), "refresh:x", 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("first lock = %v, %v", ok, err)
	}
	if ok, _ := s.TryLock(t.Context(), "refresh:x", 10*time.Second); ok {
		t.Error("lock taken twice")
	}
	if ok, _ := s.TryLock(t.Context(), "refresh:y", 10*time.Second); !ok {
		t.Error("locks are not independent")
	}
	s.Unlock(t.Context(), "refresh:x")
	if ok, _ := s.TryLock(t.Context(), "refresh:x", 10*time.Second); !ok {
		t.Error("unlock did not release")
	}
	// A crashed holder's lock expires.
	c.advance(11 * time.Second)
	if ok, _ := s.TryLock(t.Context(), "refresh:y", 10*time.Second); !ok {
		t.Error("lock did not expire")
	}
}
