// Package adminui embeds the built admin dashboard (web/admin/dist). Build
// it with `make build`; without a build, dist holds only .gitkeep and the
// dashboard serves a "not built" page.
package adminui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Files returns the built dashboard, rooted at dist/.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // "dist" is a valid literal path; Sub cannot fail
	}
	return sub
}
