package adminui

import (
	"errors"
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

var (
	scriptTag   = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	styleTag    = regexp.MustCompile(`(?i)<style\b`)
	inlineAttr  = regexp.MustCompile(`(?i)\s(on[a-z]+|style)\s*=`)
	jsURL       = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["']?\s*javascript:`)
	externalRef = regexp.MustCompile(`(?i)(src|href)\s*=\s*["']?(https?:)?//`)
)

// The dashboard's CSP forbids inline script and style (docs/DECISIONS.md
// D24). This checks the build itself, so a Vite or code change that starts
// inlining fails here, not silently in the browser. Skipped when the
// frontend hasn't been built (make build).
func TestBuildHasNoInlineCode(t *testing.T) {
	files := Files()
	if _, err := fs.Stat(files, "index.html"); errors.Is(err, fs.ErrNotExist) {
		t.Skip("dashboard not built; run make build")
	}
	checked := 0
	err := fs.WalkDir(files, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(name, ".html") {
			return err
		}
		b, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		html := string(b)
		checked++
		for _, m := range scriptTag.FindAllStringSubmatch(html, -1) {
			if !strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) != "" {
				t.Errorf("%s: inline script: %.80s", name, m[0])
			}
		}
		for _, re := range []*regexp.Regexp{styleTag, inlineAttr, jsURL, externalRef} {
			if loc := re.FindStringIndex(html); loc != nil {
				t.Errorf("%s: forbidden %q", name, html[loc[0]:min(loc[1]+40, len(html))])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no HTML in the build")
	}
}

// The checker itself must catch what it is for.
func TestInlineCheckerCatchesViolations(t *testing.T) {
	for _, bad := range []string{
		`<script>alert(1)</script>`,
		`<script type="module">import "x"</script>`,
		`<script src="/a.js">alert(1)</script>`,
		`<div onclick="x()">`,
		`<div style="color:red">`,
		`<style>body{}</style>`,
		`<a href="javascript:alert(1)">`,
		`<script src="https://cdn.example/x.js"></script>`,
		`<link href="//evil.example/x.css">`,
	} {
		caught := false
		for _, m := range scriptTag.FindAllStringSubmatch(bad, -1) {
			if !strings.Contains(strings.ToLower(m[1]), "src=") || strings.TrimSpace(m[2]) != "" {
				caught = true
			}
		}
		for _, re := range []*regexp.Regexp{styleTag, inlineAttr, jsURL, externalRef} {
			caught = caught || re.MatchString(bad)
		}
		if !caught {
			t.Errorf("not caught: %s", bad)
		}
	}
	ok := `<script type="module" crossorigin src="/.warden/admin/assets/index-x.js"></script>` +
		`<link rel="stylesheet" crossorigin href="/.warden/admin/assets/index-x.css">`
	for _, re := range []*regexp.Regexp{styleTag, inlineAttr, jsURL, externalRef} {
		if re.MatchString(ok) {
			t.Errorf("false positive %v on the real build shape", re)
		}
	}
}
