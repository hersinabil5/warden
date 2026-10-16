package audit

import (
	"fmt"
	"strings"
	"testing"
)

func seqs(es []Entry) string {
	var out []string
	for _, e := range es {
		out = append(out, fmt.Sprint(e.Seq))
	}
	return strings.Join(out, ",")
}

func TestRecentNewestFirstAndBounded(t *testing.T) {
	r := NewRecent(3)
	for i := range 5 {
		r.Record(t.Context(), testEvent(fmt.Sprint(i)))
	}
	got, next := r.Query(Query{Limit: 10})
	if seqs(got) != "5,4,3" || next != 0 {
		t.Errorf("got %s (next %d), want the 3 newest and no next page", seqs(got), next)
	}
	if got[0].RequestID != "4" {
		t.Errorf("newest = %q", got[0].RequestID)
	}
}

func TestRecentPaginates(t *testing.T) {
	r := NewRecent(100)
	for i := range 7 {
		r.Record(t.Context(), testEvent(fmt.Sprint(i)))
	}
	page, next := r.Query(Query{Limit: 3})
	if seqs(page) != "7,6,5" || next != 5 {
		t.Fatalf("page 1 = %s next %d", seqs(page), next)
	}
	page, next = r.Query(Query{Limit: 3, Before: next})
	if seqs(page) != "4,3,2" || next != 2 {
		t.Fatalf("page 2 = %s next %d", seqs(page), next)
	}
	page, next = r.Query(Query{Limit: 3, Before: next})
	if seqs(page) != "1" || next != 0 {
		t.Fatalf("page 3 = %s next %d", seqs(page), next)
	}
}

func TestRecentFilters(t *testing.T) {
	r := NewRecent(100)
	add := func(user, host string, d Decision) {
		e := testEvent("x")
		e.User, e.Host, e.Decision = user, host, d
		r.Record(t.Context(), e)
	}
	add("alice", "grafana.example.test", Allow) // 1
	add("bob", "grafana.example.test", Deny)    // 2
	add("bob", "whoami.example.test", Allow)    // 3
	add("", "whoami.example.test", Deny)        // 4: unauthenticated
	add("bob", "grafana.example.test", "weird") // 5: recorded as deny
	for _, tt := range []struct {
		q    Query
		want string
	}{
		{Query{User: "bob"}, "5,3,2"},
		{Query{Host: "grafana.example.test"}, "5,2,1"},
		{Query{Decision: Deny}, "5,4,2"},
		{Query{Decision: Allow}, "3,1"},
		{Query{User: "bob", Host: "grafana.example.test", Decision: Deny}, "5,2"},
		{Query{User: "nobody"}, ""},
	} {
		if got, _ := r.Query(tt.q); seqs(got) != tt.want {
			t.Errorf("%+v = %s, want %s", tt.q, seqs(got), tt.want)
		}
	}
	// A filtered page's cursor continues the filtered listing.
	page, next := r.Query(Query{User: "bob", Limit: 1})
	if seqs(page) != "5" || next != 5 {
		t.Fatalf("filtered page = %s next %d", seqs(page), next)
	}
	page, _ = r.Query(Query{User: "bob", Limit: 5, Before: next})
	if seqs(page) != "3,2" {
		t.Errorf("filtered page 2 = %s", seqs(page))
	}
}

func TestRecentClampsLimit(t *testing.T) {
	r := NewRecent(1000)
	for range 300 {
		r.Record(t.Context(), testEvent("x"))
	}
	if got, _ := r.Query(Query{Limit: 0}); len(got) != DefaultQueryLimit {
		t.Errorf("default limit gave %d", len(got))
	}
	if got, _ := r.Query(Query{Limit: 1 << 30}); len(got) != MaxQueryLimit {
		t.Errorf("huge limit gave %d", len(got))
	}
}
