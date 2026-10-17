package admin

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

// demoFixture has two visitors, each signed in as alice (admin) and bob.
// Requests are made as visitor 1's alice.
type demoFixture struct {
	*fixture
	bob1, bob2 string // session hashes
}

func newDemoFixture(t *testing.T) *demoFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := session.NewClient(mr.Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb, session.Options{AbsoluteTTL: 8 * time.Hour, IdleTimeout: time.Hour})
	f := &demoFixture{fixture: &fixture{store: store, recent: audit.NewRecent(100)}}
	create := func(sub, user, visitor string) string {
		id, err := store.Create(t.Context(), session.Session{Subject: sub, Username: user, Visitor: visitor,
			Groups: []string{"admins"}, AMR: []string{"pwd", "otp"}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	f.adminID = create("sub-alice", "alice", "v1")
	f.bob1 = session.HashID(create("sub-bob", "bob", "v1"))
	create("sub-alice", "alice", "v2")
	f.bob2 = session.HashID(create("sub-bob", "bob", "v2"))
	var err error
	if f.admin, err = store.Get(t.Context(), f.adminID); err != nil {
		t.Fatal(err)
	}
	h, err := New(Options{Sessions: store, Decisions: f.recent, AuthOrigin: authOrigin, Demo: true, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

type sessionList struct {
	Sessions []sessionView `json:"sessions"`
	Total    int           `json:"total"`
}

func TestDemoListsOnlyOwnSessions(t *testing.T) {
	f := newDemoFixture(t)
	for _, target := range []string{"sessions", "sessions?offset=0&limit=200", "sessions?sub=sub-alice", "sessions?sub=sub-bob"} {
		got := decode[sessionList](t, f.do(t, http.MethodGet, APIPrefix+target, "", nil))
		for _, s := range got.Sessions {
			if s.ID == f.bob2 || (s.ID != f.admin.Hash && s.ID != f.bob1) {
				t.Errorf("%s: listed another visitor's session %s (%s)", target, s.ID, s.User)
			}
		}
		if got.Total != len(got.Sessions) {
			t.Errorf("%s: total %d but %d listed: totals must not count other visitors", target, got.Total, len(got.Sessions))
		}
	}
	if got := decode[sessionList](t, f.do(t, http.MethodGet, APIPrefix+"sessions", "", nil)); got.Total != 2 {
		t.Errorf("own sessions = %d, want 2", got.Total)
	}
}

func TestDemoCannotRevokeOtherVisitors(t *testing.T) {
	f := newDemoFixture(t)
	rec := f.do(t, http.MethodPost, APIPrefix+"sessions/revoke", `{"id":"`+f.bob2+`"}`, f.mutation())
	if rec.Code != http.StatusNotFound {
		t.Errorf("revoking visitor 2's session: %d, want 404", rec.Code)
	}
	if _, err := f.store.GetByHash(t.Context(), f.bob2); err != nil {
		t.Errorf("visitor 2's session was revoked: %v", err)
	}
	if rec := f.do(t, http.MethodPost, APIPrefix+"sessions/revoke", `{"id":"`+f.bob1+`"}`, f.mutation()); rec.Code != http.StatusNoContent {
		t.Errorf("revoking own bob: %d", rec.Code)
	}
}

func TestDemoRevokeUserOnlyOwnSessions(t *testing.T) {
	f := newDemoFixture(t)
	rec := f.do(t, http.MethodPost, APIPrefix+"users/revoke", `{"sub":"sub-bob"}`, f.mutation())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revoked":1`) {
		t.Fatalf("revoke bob: %d %s, want 1 revoked", rec.Code, rec.Body.String())
	}
	if _, err := f.store.GetByHash(t.Context(), f.bob1); err == nil {
		t.Error("own bob survived")
	}
	if _, err := f.store.GetByHash(t.Context(), f.bob2); err != nil {
		t.Errorf("visitor 2's bob was revoked: %v", err)
	}
	// Revoking "alice" logs out only this visitor's alice: the caller.
	f.do(t, http.MethodPost, APIPrefix+"users/revoke", `{"sub":"sub-alice"}`, f.mutation())
	others, _ := f.store.ListVisitor(t.Context(), "v2")
	if len(others) != 2 {
		t.Errorf("visitor 2 has %d sessions left, want 2", len(others))
	}
}

func TestDemoDecisionsOnlyOwn(t *testing.T) {
	f := newDemoFixture(t)
	for _, v := range []string{"v1", "v2", "v2", ""} {
		f.recent.Record(t.Context(), audit.Event{Time: time.Now(), User: "alice", Host: "app.example.test", Visitor: v, Decision: audit.Allow})
	}
	got := decode[struct {
		Decisions []map[string]any `json:"decisions"`
	}](t, f.do(t, http.MethodGet, APIPrefix+"decisions?limit=200", "", nil))
	if len(got.Decisions) != 1 {
		t.Errorf("decisions = %d, want only this visitor's 1", len(got.Decisions))
	}
}

// A session without a visitor tag (from before demo mode) sees nothing.
func TestDemoUntaggedAdminSeesNothing(t *testing.T) {
	f := newDemoFixture(t)
	f.admin.Visitor = ""
	f.recent.Record(t.Context(), audit.Event{Time: time.Now(), User: "x", Decision: audit.Allow})
	if got := decode[sessionList](t, f.do(t, http.MethodGet, APIPrefix+"sessions", "", nil)); len(got.Sessions) != 0 {
		t.Errorf("untagged admin listed %d sessions", len(got.Sessions))
	}
	if body := f.do(t, http.MethodGet, APIPrefix+"decisions", "", nil).Body.String(); !strings.Contains(body, `"decisions":[]`) {
		t.Errorf("untagged admin saw decisions: %s", body)
	}
	if rec := f.do(t, http.MethodPost, APIPrefix+"users/revoke", `{"sub":"sub-bob"}`, f.mutation()); !strings.Contains(rec.Body.String(), `"revoked":0`) {
		t.Errorf("untagged admin revoked: %s", rec.Body.String())
	}
}
