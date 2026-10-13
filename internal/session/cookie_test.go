package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCookieAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	SetCookie(rec, "_warden", "v", time.Hour)
	ClearCookie(rec, "_old")
	cs := rec.Result().Cookies()
	if len(cs) != 2 {
		t.Fatalf("%d cookies", len(cs))
	}
	for _, c := range cs {
		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
			t.Errorf("%s: attributes %+v", c.Name, c)
		}
	}
	if cs[0].MaxAge != 3600 || cs[1].MaxAge >= 0 {
		t.Errorf("Max-Age = %d / %d", cs[0].MaxAge, cs[1].MaxAge)
	}
}
