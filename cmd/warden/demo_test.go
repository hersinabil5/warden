package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/hersinabil5/warden/internal/audit"
	"github.com/hersinabil5/warden/internal/session"
)

func TestDemoResetClearsSessionsAndDashboardAudit(t *testing.T) {
	rdb := session.NewClient(miniredis.RunT(t).Addr())
	t.Cleanup(func() { _ = rdb.Close() })
	store := session.NewStore(rdb, session.Options{AbsoluteTTL: time.Hour, IdleTimeout: time.Hour})
	id, err := store.Create(t.Context(), session.Session{Subject: "sub-alice", Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	recent := audit.NewRecent(10)
	var file bytes.Buffer
	sink := audit.NewWriterSink(&file, slog.New(slog.DiscardHandler))
	rec := audit.Multi(sink, recent)
	rec.Record(t.Context(), audit.Event{Time: time.Now(), User: "alice", Decision: audit.Allow})

	var logs bytes.Buffer
	if err := demoReset(store, recent, slog.New(slog.NewJSONHandler(&logs, nil)))(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(t.Context(), id); err == nil {
		t.Error("session survived the reset")
	}
	if got, _ := recent.Query(audit.Query{}); len(got) != 0 {
		t.Errorf("dashboard audit view kept %d events", len(got))
	}
	if !strings.Contains(file.String(), `"user":"alice"`) {
		t.Error("the audit file lost its events")
	}
	if !strings.Contains(logs.String(), `"msg":"demo reset"`) || !strings.Contains(logs.String(), `"sessions":1`) {
		t.Errorf("reset not logged: %s", logs.String())
	}
}
