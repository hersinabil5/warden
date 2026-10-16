package session

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sessionFor(sub, user string) Session {
	s := testSession()
	s.Subject, s.Username = sub, user
	return s
}

func hashes(ss []Session) string {
	var out []string
	for _, s := range ss {
		out = append(out, s.Hash)
	}
	return strings.Join(out, ",")
}

// PLAN.md M5: "revoke all" touches only that user's sessions, via the
// per-user index.
func TestRevokeUser(t *testing.T) {
	s, mr, c := newTestStore(t)
	a1, _ := s.Create(t.Context(), sessionFor("sub-alice", "alice"))
	c.advance(time.Second)
	a2, _ := s.Create(t.Context(), sessionFor("sub-alice", "alice"))
	b1, _ := s.Create(t.Context(), sessionFor("sub-bob", "bob"))
	app, err := s.CreateApp(t.Context(), HashID(a1), "whoami.example.test")
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.RevokeUser(t.Context(), "sub-alice")
	if err != nil || n != 2 {
		t.Fatalf("RevokeUser = %d, %v; want 2", n, err)
	}
	for _, id := range []string{a1, a2} {
		if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
			t.Errorf("alice session survived: %v", err)
		}
	}
	if _, err := s.GetApp(t.Context(), app, "whoami.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("alice app session survived: %v", err)
	}
	if _, err := s.Get(t.Context(), b1); err != nil {
		t.Errorf("bob's session was revoked: %v", err)
	}
	if mr.Exists(userKey("sub-alice")) {
		t.Error("alice's index survived")
	}
	if got, _ := s.ListUser(t.Context(), "sub-bob"); hashes(got) != HashID(b1) {
		t.Errorf("bob's index = %s", hashes(got))
	}
}

func TestRevokeUserRejectsEmptyAndUnknown(t *testing.T) {
	s, _, _ := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	if _, err := s.RevokeUser(t.Context(), ""); err == nil {
		t.Error("RevokeUser accepted an empty subject")
	}
	if n, err := s.RevokeUser(t.Context(), "sub-nobody"); err != nil || n != 0 {
		t.Errorf("unknown subject = %d, %v", n, err)
	}
	if _, err := s.Get(t.Context(), id); err != nil {
		t.Errorf("unrelated session revoked: %v", err)
	}
}

func TestCreateRequiresSubject(t *testing.T) {
	s, _, _ := newTestStore(t)
	if _, err := s.Create(t.Context(), sessionFor("", "anon")); err == nil {
		t.Error("created a session with no subject")
	}
}

func TestListNewestFirstAndPaginated(t *testing.T) {
	s, _, c := newTestStore(t)
	var ids []string
	for i := range 5 {
		id, err := s.Create(t.Context(), sessionFor("sub-"+string(rune('a'+i)), "u"))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		c.advance(time.Second)
	}
	page, total, err := s.List(t.Context(), 0, 2)
	if err != nil || total != 5 || hashes(page) != HashID(ids[4])+","+HashID(ids[3]) {
		t.Fatalf("page 1 = %s, total %d, %v", hashes(page), total, err)
	}
	page, _, _ = s.List(t.Context(), 4, 2)
	if hashes(page) != HashID(ids[0]) {
		t.Errorf("last page = %s", hashes(page))
	}
	if page, _, err = s.List(t.Context(), -1, 0); err != nil || len(page) == 0 {
		t.Errorf("bad offset/limit not clamped: %d, %v", len(page), err)
	}
}

// Listing is read-only: it must not extend the idle timer, and it never
// returns the refresh token.
func TestListDoesNotTouchOrLeak(t *testing.T) {
	s, _, c := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	created := c.now()
	c.advance(time.Minute)
	got, err := s.ListUser(t.Context(), "sub-alice")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListUser = %v, %v", got, err)
	}
	if !got[0].LastSeen.Equal(created) || got[0].RefreshToken != "" || got[0].Hash != HashID(id) {
		t.Errorf("listed session = last seen %v, refresh %q, hash %q", got[0].LastSeen, got[0].RefreshToken, got[0].Hash)
	}
	all, _, _ := s.List(t.Context(), 0, 10)
	if len(all) != 1 || all[0].RefreshToken != "" {
		t.Errorf("List leaked or missed: %+v", all)
	}
	// Still idle since creation: listing did not keep it alive.
	c.advance(idleTTL)
	if _, err := s.Get(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Errorf("listing extended the idle timer: %v", err)
	}
}

// Expired and deleted sessions drop out of both indexes.
func TestIndexPrunesDeadSessions(t *testing.T) {
	s, mr, c := newTestStore(t)
	gone, _ := s.Create(t.Context(), testSession())
	_, _ = s.Create(t.Context(), testSession()) // will idle out
	live, _ := s.Create(t.Context(), testSession())
	if err := s.Delete(t.Context(), gone); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		c.advance(idleTTL - time.Minute)
		if _, err := s.Get(t.Context(), live); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListUser(t.Context(), "sub-alice")
	if err != nil || hashes(got) != HashID(live) {
		t.Fatalf("ListUser = %s, %v; want only the live session", hashes(got), err)
	}
	all, total, _ := s.List(t.Context(), 0, 10)
	if hashes(all) != HashID(live) || total != 1 {
		t.Errorf("List = %s (total %d)", hashes(all), total)
	}
	for _, key := range []string{userKey("sub-alice"), allSessionsKey} {
		members, _ := mr.ZMembers(key)
		if strings.Join(members, ",") != HashID(live) {
			t.Errorf("%s still lists %v", key, members)
		}
	}
}

func TestDeleteHash(t *testing.T) {
	s, _, _ := newTestStore(t)
	id, _ := s.Create(t.Context(), testSession())
	app, _ := s.CreateApp(t.Context(), HashID(id), "whoami.example.test")
	for _, bad := range []string{"", "nothex", strings.Repeat("z", 64), id} {
		if err := s.DeleteHash(t.Context(), bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("DeleteHash(%q) = %v, want ErrNotFound", bad, err)
		}
	}
	// An app session's hash is not a main session: refused, nothing deleted.
	if err := s.DeleteHash(t.Context(), HashID(app)); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteHash(app) = %v", err)
	}
	if _, err := s.Get(t.Context(), id); err != nil {
		t.Fatalf("session gone after refused deletes: %v", err)
	}
	if err := s.DeleteHash(t.Context(), HashID(id)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetApp(t.Context(), app, "whoami.example.test"); !errors.Is(err, ErrNotFound) {
		t.Errorf("app session survived: %v", err)
	}
	if got, _ := s.ListUser(t.Context(), "sub-alice"); len(got) != 0 {
		t.Errorf("index still lists %s", hashes(got))
	}
	if err := s.DeleteHash(t.Context(), HashID(id)); !errors.Is(err, ErrNotFound) {
		t.Errorf("second DeleteHash = %v, want ErrNotFound", err)
	}
}
