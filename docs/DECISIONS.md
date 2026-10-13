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
the default logger. The same callback also installs go-redis's package-level logger (added in M2),
which otherwise prints plain text.

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

## D8: OIDC discovery: pinned algorithms, strict metadata, bounded retries

**Context:** Everything about token validation flows from the discovery document and JWKS. Taking
them on trust would let a misconfigured or hostile IdP endpoint (or anything spoofing it)
weaken validation: advertise `none` or `HS256`, point `jwks_uri` at plain HTTP, drop PKCE, or name
a different issuer. Startup also has to cope with Keycloak still booting.

**Decision:**
- `auth.id_token_algs` is required and limited to asymmetric algorithms (`RS*`, `PS*`, `ES*`).
  `none` and `HS*` cannot be configured. The verifier accepts only the pinned algorithms the IdP
  also advertises, and startup fails if that set is empty.
- Warden fetches the discovery document itself and rejects it unless: `issuer` matches the config
  exactly; `authorization_endpoint`, `token_endpoint` and `jwks_uri` (plus `userinfo_endpoint` and
  `end_session_endpoint` when present) are absolute https URLs without credentials (plain http only
  on loopback, the same rule as the issuer); `response_types_supported` includes `code`; and
  `code_challenge_methods_supported` includes `S256`.
- Warden fetches the JWKS once at startup and requires at least one public signing key that fits a
  pinned algorithm. Unknown key types are skipped. Private or symmetric key material is a hard error.
- Network errors, 5xx, 408 and 429 are retried with exponential backoff (500ms doubling to a 10s
  cap, with jitter in [d/2, d]) for up to 60s. Everything else fails at once, so a typo'd issuer
  doesn't stall startup. Discovery runs before any listener is bound. A shutdown signal during
  discovery is a clean stop.
- The IdP HTTP client has a 10s overall timeout (5s dial, 5s TLS handshake, 10s response header),
  ignores `HTTP_PROXY`/`HTTPS_PROXY`, requires TLS 1.2+, caps response bodies at 1 MiB, and never
  follows redirects. go-oidc gets it via `oidc.ClientContext`, so JWKS refreshes during key
  rotation use it too.

**Consequences:** An IdP that only signs with HMAC, or doesn't advertise S256, can't be used. An
issuer URL that redirects (e.g. a missing trailing path) fails with a message to configure the
exact URL. A deployment that needs an egress proxy to reach the IdP would need an explicit config
option (none today).

## D9: Pre-auth login cookie: sealed, per-login, per-process key

**Context:** Between `/.warden/login` and the callback, Warden must remember `state`, `nonce` and the
PKCE verifier and bind them to the browser (invariant 4) before Redis sessions exist. The plan asks
for a signed cookie. The verifier and nonce shouldn't be readable by anything that can see cookies.

**Decision:**
- The cookie is sealed with AES-256-GCM (standard library), which both authenticates and encrypts
  it. The cookie name is the associated data, and `open` also checks that the name matches the
  sealed `state`, so a value only opens under the name it was issued for. The sealed expiry (10
  minutes) is checked on open, independent of the browser's `Max-Age`.
- The name is `__Host-warden_login_<first 16 chars of state>`. The `__Host-` prefix makes browsers
  enforce `Secure`, `Path=/` and no `Domain` (invariant 7). One cookie per login means concurrent
  logins in two tabs don't overwrite each other. Attributes: `HttpOnly; Secure; SameSite=Lax;
  Max-Age=600`. Lax is enough because the IdP returns with a top-level GET.
- The key is 32 random bytes generated at startup. It is never configured, stored or logged.
- `state` and `nonce` are 256-bit `crypto/rand` values. The verifier comes from
  `oauth2.GenerateVerifier`. Nothing from the login request (query, Host) feeds the authorize URL.
  `redirect_uri` is built from `auth.domain` and the `listen` port (left out when it's 443).
- A sealed cookie can be replayed until it expires, so single-use `state` is enforced server-side
  by the callback, not by the cookie.

**Consequences:** A restart cancels logins in progress (users click login again). Multiple Warden
instances (M8) would need a shared, rotatable key, which becomes a config secret then. Login
doesn't accept a return URL yet; that arrives with return-URL validation (invariant 5).

## D10: Session store layout and revocation semantics

**Context:** D1 gives each app host its own cookie, and D2 keeps sessions in Redis under a hash
of the ID. Revocation must take effect on the next request (invariant 8), including for every app
host the user visited.

**Decision:**
- **Keys:** `warden:s:<sha256(id)>`. The raw ID exists only in the cookie. One-time values
  (handshake codes) and used-`state` markers are also stored under hashes of their tokens.
- **Main vs. app sessions:** a main session (auth host) holds the identity. An app session (one per
  app host) holds only a pointer to its main session and the host it was issued for. Looking up an
  app session resolves the main session every time, so deleting the main session revokes every app
  session at once, with no fan-out needed. A children index exists only for cleanup. App activity
  refreshes the main session's idle timer.
- **Timeouts:** absolute TTL and idle timeout are checked from the record's own timestamps on every
  read, not just through Redis expiry. The Redis TTL is `min(idle, absolute remaining)`.
- **Touches** use `SET XX`, so a touch racing a revocation cannot recreate the session. One-time
  codes are redeemed with `GETDEL`, and `state` is marked used with `SET NX`.
- **Failures:** a Redis error is distinct from "not found", and callers deny on both. Warden pings
  Redis at startup and refuses to start without it. Client timeouts: 2s dial, 1s read/write, 2s
  pool wait.
- **Refresh token:** stored in the session record (needed for M5 group refresh). `Session` redacts
  it from every fmt verb and from slog.

**Consequences:** Every authenticated request costs a Redis read and write for the main session
(plus a read for the app pointer). Anyone who can read Redis gets refresh tokens but no usable
cookies. Encrypting refresh tokens at rest is a possible later hardening.

## D11: Return URLs are absolute, canonicalized, and route-host only

**Context:** After login, Warden redirects to the URL the user originally asked for (`rd`). Browsers
and Go's URL parser disagree on edge cases: `\` treated as `/`, stripped tabs and newlines,
`https:evil.com`, userinfo (`a@evil.com`). Any disagreement can become an open redirect.

**Decision:** `rd` must be a single parameter, at most 2048 bytes, contain no whitespace, control
characters or `\`, start with the literal `https://`, have no userinfo, and name a configured route
host (not the auth host) on Warden's public port, with the port optional. Relative URLs are
rejected rather than resolved. Warden redirects to a URL rebuilt from the parsed parts
(`https://<lowercase host>[:port]<path>?<query>`, fragment dropped), never the raw input, so what
it redirects to is exactly what it checked. Anything else gets a 400. A fuzz test checks that every
accepted URL lands on an allowed origin and re-validates to itself.

**Consequences:** Warden builds absolute return URLs itself when it sends an app request to login,
so legitimate flows always pass. Hand-written relative `rd` values don't work.

## D12: Callback checks and ordering

**Context:** The callback is where untrusted input (query parameters, cookies, the IdP's token
response) turns into a session. Every check must run before anything is created, and a failure at
any step must deny.

**Decision:** In order:
1. Exactly one non-empty `state` is required. The pre-auth cookie for that state must exist (no
   cookie means a login started in another browser: login CSRF). The cookie is cleared from this
   point on, whatever the outcome.
2. The cookie must open (D9), and its sealed `state` must equal the query `state` (constant-time).
3. `state` is marked used in Redis (`SET NX`) before the code is exchanged, so a replay never
   reaches the IdP.
4. An IdP `error` parameter, or anything other than exactly one `code`, is rejected.
5. Code exchange with the PKCE verifier and `client_secret_basic` (one fixed auth method), over the
   bounded IdP client. Only the OAuth error code is logged from a refusal, never the body.
6. ID token: go-oidc checks signature (pinned algorithms), `iss`, `aud` and `exp`. Warden then
   requires a `nonce` equal to the sealed one (constant-time), an `iat` no earlier than the login
   start and no later than now (1 minute skew both ways), `azp` equal to the client ID when there
   are several audiences or `azp` is present, and a non-empty `sub`. The groups claim must be a
   list of non-empty strings if present. Email is kept only when `email_verified` is the boolean
   `true`.
7. Any session cookie the browser already had is revoked, and a new session ID is issued (T2).

Client-caused failures return 400, IdP outages 502, and Redis failures 500. Details go only to
the log, keyed by request ID with hashed `state` and session prefixes.

**Consequences:** Users whose IdP account has no verified email get no email in their session, so
`email_domains` rules won't match them. Groups are used exactly as the IdP sends them. Keycloak's
mapper uses flat names (`full.path: false`).

## D13: Handshake binding, cookie isolation, and `-dev-skip-policy`

**Context:** D1's one-time code arrives in a URL. If the code were the only proof, an attacker could
start a login as themselves and send the victim their handshake link, signing the victim into the
app as the attacker (login CSRF / session swap). Separately, upstreams sit on the same host as
Warden's app cookie: they receive it in `Cookie` and could overwrite it with `Set-Cookie`. And now
that login exists, D6's "proxy without authentication" flag is no longer needed.

**Decision:**
- **Binding.** An unauthenticated GET on an app host sets (or reuses) a `__Host-warden_hs` cookie
  holding 256 random bits, valid for 10 minutes, and redirects to
  `https://<auth>/.warden/login?rd=<url>&hs=<base64url(sha256(cookie))>`. The hash is sealed into
  the pre-auth cookie and stored in the handshake code's record. Redeeming a code requires the
  binding cookie whose hash matches, on the host the code was issued for, within 30 seconds, once
  (`GETDEL`; any attempt spends the code). Without `hs` (a hand-made `login?rd=` link), Warden
  never issues a code: after login it returns the browser to the app URL, which starts a bound
  handshake.
- **Single sign-on.** A login request with a live main session skips the IdP and goes straight to
  the handshake.
- **Host scoping.** The auth handler serves login, callback and the session page only on the auth
  host, and the handshake only on route hosts. Everything else under `/.warden/` is 404.
- **Unauthenticated requests:** GET/HEAD get a login redirect; other methods get 401 (no redirect
  dance for API calls). A dead app cookie is cleared. A Redis error is a 500 and a deny.
- **Cookie isolation.** The proxy removes Warden's cookies (`<session cookie>` and
  `__Host-warden_*`) from requests to upstreams, and drops upstream `Set-Cookie` headers for those
  names.
- **Dev flag.** `-dev-allow-unauthenticated` is replaced by `-dev-skip-policy`. Authentication is
  always enforced. The flag only lets any signed-in user through until the policy engine exists
  (M3), keeps D6's loopback-only restriction, and is removed in M3. Without it, signed-in users get
  403 (default deny).

**Consequences:** Every app needs one extra redirect per session (D1). The binding cookie is shared
by the tabs of one browser on a host, so parallel logins work. An app that relies on reading a
cookie named like Warden's won't see it.
