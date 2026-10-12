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

## D5: Strict config: reject ambiguity instead of guessing

**Context:** The config is the security policy. A typo that loads "successfully" can silently
weaken it: an empty rule `{}` reads as "no conditions", `groups: []` or `require_mfa_within: 0s`
can read as "no restriction", a misspelled key is ignored, and an upstream with a path prefix
means the upstream sees a different path from the one policy evaluated.

**Decision:** `internal/config` decodes strictly (unknown fields, duplicate keys, wrong types,
and extra YAML documents are errors) and rejects anything ambiguous: empty rules, empty
condition lists, `authenticated: false` (no public routes until there is an explicit `public:
true`), non-positive durations, path prefixes not already in normalized form, upstream URLs
with a path/query/fragment/credentials, and hosts that are not a single lowercase DNS spelling
(no ports, IPs, wildcards, or trailing dot). Every problem is reported at once with its field
path. The client secret comes only from the environment variable named in the config, is held
in a `config.Secret` that redacts itself in fmt/slog/JSON, and a missing secret fails at
startup.

**Consequences:** Some valid-looking configs are refused and must be rewritten explicitly.
Public routes and upstream path prefixes need a deliberate design change, not a config tweak.

## D6: Temporary unauthenticated dev mode; timeout values

**Context:** M1 builds the proxy before login (M2) and policy (M3) exist, but its acceptance
test is reaching whoami through Warden. Proxying without authentication contradicts invariant 1
(default deny).

**Decision:** Default deny holds: without a flag, every proxied request gets 403. The flag
`-dev-allow-unauthenticated` proxies without authentication, but Warden refuses to start with
it unless every listener is a loopback address, and logs a warning at startup. `make run`
passes it. It is removed in M3 (tracked as a task in `PLAN.md`).

Timeouts (invariant 10), as named constants in `internal/proxy`:

| Where | Setting | Value | Why |
|---|---|---|---|
| Server | ReadHeaderTimeout | 10s | Slow-loris: headers must arrive quickly |
| Server | ReadTimeout | 60s | Whole request including body |
| Server | WriteTimeout | 120s | Bounds a response; long streams will need a rethink in M7 (WebSockets) |
| Server | IdleTimeout | 120s | Keep-alive connections |
| Upstream | Dial / TLS handshake | 5s / 5s | Upstreams are local; slow connects mean trouble |
| Upstream | ResponseHeaderTimeout | 30s | Upstream must start answering |
| Upstream | ExpectContinueTimeout | 1s | Standard |

The upstream transport never reads `HTTP_PROXY`/`HTTPS_PROXY` (unlike
`http.DefaultTransport`), so an environment variable cannot reroute upstream traffic.

**Consequences:** No browser demo without the flag until M3. The timeouts are not configurable
yet; they become config fields if a real upstream needs different values.

## D7: Warden-owned request plumbing

**Context:** Warden sits on every host, so its own endpoints and request metadata share space
with upstream apps and with attacker-controlled input.

**Decision:**
- `/.warden/` is reserved on every host: Warden serves it (healthz now; login callback and
  handshake later) and never proxies it, so an upstream cannot shadow a Warden endpoint.
- The TLS SNI name must match the `Host` header (421 otherwise), so a connection negotiated
  for one host cannot be used to reach another.
- The HTTP→HTTPS redirect only targets configured hosts (400 otherwise), never the raw Host
  header, so it cannot become an open redirect.
- Request IDs are always generated by Warden (`crypto/rand`, ≥128 bits). A client-supplied
  `X-Request-ID` is discarded, so clients cannot forge or collide IDs in logs and audit events.

**Consequences:** An upstream app that itself serves `/.warden/...` paths cannot be proxied
unchanged. Upstreams see Warden's request ID, which is what correlation needs.
