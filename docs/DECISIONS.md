# Decision log

Short entries. Newest at the bottom. Format: context, decision, consequences.

## D1: Host-only cookies with a central auth domain

**Context:** One cookie on `.warden.localhost` would be sent to every upstream host, so any
upstream (or XSS in one) could read or replay it.

**Decision:** The main session cookie lives only on `auth.warden.localhost`. When a user
visits an app host without a cookie, Warden redirects to the auth host, which (if logged in)
redirects back to `https://<app-host>/.warden/handshake?code=<one-time code>`. The app host
exchanges the code server-side for an app-scoped session cookie (host-only). Codes are
single-use and expire in 30 seconds.

**Consequences:** One extra redirect per app per session. Revoking the main session must also
revoke its app-scoped sessions (track them together in Redis).

## D2: Server-side sessions in Redis, hashed IDs

**Context:** JWT-in-cookie sessions can't be revoked before expiry.

**Decision:** Opaque 256-bit session ID in the cookie; Redis key is SHA-256 of the ID.

**Consequences:** Redis is a hard dependency. A Redis read leak doesn't yield usable cookies.

## D3: `slog.SetDefault` only in `main`

**Context:** "No global mutable state" means loggers are passed explicitly. Third-party
libraries (and the standard library) still log through the process-wide default logger,
which would otherwise emit plain text.

**Decision:** `cmd/warden/main.go` installs the configured JSON logger as the slog default,
exactly once at startup. Internal packages never read or write the default; they take a
`*slog.Logger` as a dependency. `run()` receives the install step as a callback, so tests
don't touch the global.

**Consequences:** All process output is JSON. Tests can run in parallel without racing on
the default logger.

## D4: Lint policy: no global exclusions, justified suppressions only

**Context:** `gosec` catches several invariant violations mechanically (`math/rand`, missing
`ReadHeaderTimeout`, `InsecureSkipVerify`, weak crypto). A global exclusion, or a bare
`//nolint`, would silence those warnings everywhere without anyone noticing.

**Decision:** `.golangci.yml` has no global exclusions or presets, and `gosec` runs on tests
too. Exceptions are line-level only, and `nolintlint` requires each one to name the linter
and give a reason: `//nolint:gosec // <why this is safe>`.

**Consequences:** Some test code needs explicit, explained suppressions. Every silenced
security warning is visible in review and greppable (`grep -rn nolint`).
