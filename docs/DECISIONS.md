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
  403 (default deny). (Removed in M3 as planned; see D15.)

**Consequences:** Every app needs one extra redirect per session (D1). The binding cookie is shared
by the tabs of one browser on a host, so parallel logins work. An app that relies on reading a
cookie named like Warden's won't see it.

## D14: Logout

**Context:** Logout must end access everywhere at once (invariant 8). It's also a state-changing
endpoint, so a cross-site page must not be able to trigger it (logout CSRF).

**Decision:** `POST /.warden/logout` on the auth host only. `GET` and other methods get 405, so an
`<img>` or link can't log anyone out. Requests a browser marks as cross-origin (`Sec-Fetch-Site`
other than `same-origin`/`none`, or an `Origin` that isn't the auth origin, including `null`) get
403. This sits on top of the `SameSite=Lax` cookie, which cross-site POSTs don't carry anyway.
Logout clears the cookie first, then deletes the main session; app sessions die with it (D10). If
Redis fails, the cookie is still cleared and the user sees a 500, so they know revocation didn't
happen. With `auth.logout_at_idp: true`, Warden then redirects (303) to the IdP's
`end_session_endpoint` with `client_id` and a fixed `post_logout_redirect_uri` (the session page).
It sends no ID token, so Keycloak asks the user to confirm. Startup fails if the option is on but
the IdP has no end-session endpoint. The session page's CSP `form-action` includes the IdP origin,
because Chrome applies it to the redirect after the form POST.

**Consequences:** Without `logout_at_idp`, the IdP session survives, and the next login is silent
SSO. App-host cookies stay in the browser but are dead; the next request clears them and starts a
new login.

## D15: Policy semantics and path normalization

**Context:** Policy is only as good as the path it's evaluated on. Upstreams decode and clean paths
in different ways (`%2F` as `/`, `\` as `/`, `;params` stripped, case folded), so any gap between
what Warden checks and what the upstream serves is a bypass (invariant 6). The rule language also
needs exact meanings for prefixes, multiple rules, and MFA.

**Decision:**
- **One normalization, up front.** Warden normalizes the raw request target (`RequestURI`, so
  `%2F` is still visible; absolute-form is accepted per RFC 9112) before routing, before
  `/.warden/` dispatch, and before authentication. `pathnorm.Normalize` decodes once, resolves `.`
  and `..` (never above the root), collapses `//`, and keeps a trailing slash. Everything
  downstream (Warden's endpoints, policy, the upstream) sees only the result, and the upstream gets
  it re-encoded. The query string is passed through untouched.
- **Rejected with 400, never guessed:** encoded `/` or `\`, raw `\`, NUL and control characters,
  invalid or overlong UTF-8, bad percent-encoding, anything still percent-encoded after one decode
  (double encoding), and `;` anywhere in the path. `;` is legal in URLs, but Tomcat, Jetty and
  others strip `;...` from segments (`/admin;x`, `/..;/admin`), which is a known bypass; refusing it
  costs little. Paths over 4 KiB are refused.
- **Rules.** Rules in one `allow` list are ORed; the conditions inside a rule are ANDed. `users`
  matches the username (`preferred_username`, falling back to `sub`) exactly; `groups` matches any
  listed group exactly; `email_domains` matches the domain of a *verified* email exactly (no
  subdomains). `authenticated: true` matches any session.
- **Paths.** The route's `allow` applies unless a `paths` prefix contains the request path, in
  which case that prefix's rules apply *instead* (the longest prefix wins; rules don't stack).
  Prefixes match whole segments: `/admin` covers `/admin`, `/admin/` and `/admin/x`, not
  `/administrator`. A trailing slash on a prefix is dropped, so `/admin/` also protects `/admin`.
  Matching is case-sensitive unless the route sets `case_insensitive_paths: true` (for upstreams
  that fold case); that uses Unicode case folding, so `/\u212Aube` matches a `/kube` prefix.
- **MFA.** `require_mfa_within: D` holds when the ID token's `amr` shows more than one factor (the
  value `mfa`, or two distinct RFC 8176 methods, e.g. Keycloak's `["pwd","otp"]`) and `auth_time`
  is no older than `D` (and not more than a minute in the future). A single strong method such as
  `hwk` alone doesn't count. Until step-up (M7), a stale or missing MFA is a plain 403.
- **Failing closed.** `Evaluate` is pure and denies on anything unexpected: no policy, no session,
  no time, or a path that isn't normalized. `policy.Compile` repeats the config checks, so a
  policy built another way can't smuggle in an empty rule.
- **Denials.** 403 with the generic page and request ID. The rule and reason go to the log only.
- `-dev-skip-policy` is gone. `make run` now enforces the configured policy.

**Consequences:** Apps that need `;` or encoded slashes in paths can't sit behind Warden as-is. A
path rule replaces the route rule, so a prefix meant to be *looser* (for example `/public`) is
looser only for that subtree. Case-insensitive matching is opt-in per route, because folding
everything would let `/Admin` rules capture unrelated paths on case-sensitive apps.

## D16: Dev MFA: Keycloak OTP with `amr`

**Context:** `require_mfa_within` (D15) reads the ID token's `amr`, but Keycloak sends none by
default, and with no MFA user nothing could pass an MFA rule. M7's step-up needs this too.

**Decision:** The realm import (`deploy/keycloak/realm-warden.json`) now:
- binds a custom browser flow, `browser-amr`: cookie SSO, or password then OTP when the user has
  an OTP credential. The password and OTP steps carry "Authentication Reference" configs (`pwd`,
  `otp`, max age 10 h); Keycloak leaves `amr` empty without them, and treats a missing max age as
  expired.
- adds the `oidc-amr-mapper` to the `warden-proxy` client (ID token only).
- gives `alice` a TOTP credential with a fixed secret (`WardenDevOtpAlice001`, base32
  `K5QXEZDFNZCGK5SPORYEC3DJMNSTAMBR`), so the setup is reproducible and testable without a phone.
  Like the realm's passwords and client secret, it is for the local dev realm only.

**Consequences:** alice's MFA login yields `amr: ["pwd","otp"]` and passes Grafana's `/admin`
rule; bob's yields `["pwd"]`. A real deployment enrolls OTP per user and must configure the same
references and mapper. Realm changes apply only when the Keycloak container is recreated.

## D17: Signed identity assertion and JWKS

**Context:** Upstreams need to know who the user is, and must be able to tell Warden's word apart
from a header a client typed (invariant 2) or a token minted for another app.

**Decision:**
- **Strip, then inject.** Before proxying, Warden deletes every identity header a client sent: a
  built-in list (`X-Forwarded-User`/`-Email`/`-Groups`/..., `Remote-User`, Grafana's
  `X-Webauth-*`), the `X-Warden-*` and `X-Auth-Request-*` families, and `strip_headers`. Names are
  matched case-insensitively with `_` folded to `-`, because WSGI, CGI and some proxies read
  `X_Forwarded_Email` as `X-Forwarded-Email`. `Authorization` is the app's own and is kept.
- **Assertion.** After the policy allows a request, Warden signs a JWT for it and sends it in
  `identity.header` (`X-Warden-Identity`): ES256 (P-256), header `typ: warden-identity+jwt`
  (explicit typing, RFC 8725, so no ID or access token can pass as one) and `kid`. Claims: `iss` =
  the auth origin (`https://auth.warden.localhost:8443`), `aud` = the route host (one value),
  `sub`, `preferred_username`, `email` (verified only, omitted otherwise), `groups` (always a
  list), `iat` = `nbf`, `exp` = `iat` + `identity.ttl` (at most 60 s), and a 128-bit random `jti`.
  A new assertion per request; if signing fails the request gets a 500 and is not proxied.
- **Keys and rotation.** The `kid` is the key's RFC 7638 thumbprint, so it needs no config and
  changes with the key. `identity.previous_key_files` lists retired keys (old private key files or
  public keys) that stay in the JWKS for verification. Rotate by generating a new key, moving the
  old file to `previous_key_files`, and restarting; drop it later. Startup fails on a non-P-256
  key or a duplicate.
- **JWKS** at `https://<auth>/.well-known/jwks.json`, public, `Cache-Control: max-age=300`, public
  keys only. On app hosts that path belongs to the app.
- **Verifying** (`identity.Verifier`, used by `examples/upstream`): ES256 only, the `typ`, a known
  `kid`, the signature, `iss`, exactly one `aud` equal to the app's host, `exp`/`nbf`/`iat` with
  5 s leeway, lifetime ≤ 60 s, `sub` and `jti` present. `identity.RemoteKeys` caches the JWKS and
  refetches on an unknown `kid` at most every 30 s, keeps only ES256 P-256 signing keys, and
  caps the response at 1 MiB.

**Consequences:** An assertion leaked from one app can't be replayed at another (`aud`), and
expires within a minute. Within that minute it could be replayed at the same app; `jti` lets an
app reject repeats if that matters, but Warden doesn't require it. Upstreams still have to refuse
traffic that bypasses Warden; that's mTLS (D18).

## D18: mTLS to upstreams and the dev internal CA

**Context:** A signed assertion (D17) proves who the user is, but an upstream reachable on the
network could still be called directly. Upstreams should accept connections only from Warden, and
Warden should talk only to the real upstream.

**Decision:**
- **Warden side.** A route with `upstream_tls` uses TLS 1.3, trusts only `ca_file` (never the
  system roots), and presents `client_cert_file`/`client_key_file`. Missing or unreadable files fail
  startup; a failed handshake is a 502. Plain `https://` upstreams without `upstream_tls` use the
  system roots.
- **Upstream side** (`examples/upstream`): `RequireAndVerifyClientCert` against the internal CA,
  plus the client certificate's CN must be `warden-proxy`, so another certificate from the same CA
  (an upstream's server certificate) can't connect. Then every request also needs exactly one valid
  assertion for its own host. Listens on 127.0.0.1 only.
- **Dev CA** (`cmd/devca`, run by `make certs` / `make internal-ca`): an ECDSA P-256 CA, path
  length 0, **name-constrained** to `localhost`, `127.0.0.0/8` and `::1`, valid one year, created
  once and reused. Each run reissues 90-day leaves: Warden's client certificate (client-auth EKU
  only) and the upstream's server certificate (server-auth EKU only, `localhost`/`127.0.0.1`/`::1`).
  Keys are written 0600, atomically. A Go program rather than an openssl script, so it's portable
  and tested.

**Consequences:** Even a leaked dev CA key can't mint a certificate for a real site. Upstreams
other than the example (whoami, Grafana) still run plain HTTP on loopback; putting them behind
mTLS or on a private network is M7. Certificate rotation is "run `make internal-ca` and restart";
there's no revocation for the dev CA.

## D19: Audit event schema and what gets audited

**Context:** M5 needs every allow and deny recorded with a reason, in a form an admin API and
dashboard can read, without turning the audit log into a second place secrets can leak.

**Decision:**
- **One event per request to a route host**, emitted after the response with its final status and
  latency. Warden's own endpoints (`/.warden/*`, healthz, JWKS) and unknown hosts produce no
  event: they aren't access decisions on a protected app. Login and session events come with the
  admin API and refresh tasks.
- **Fields:** `time` (UTC, RFC 3339 nanoseconds), `request_id` (Warden's own, D7), `user`,
  `session`, `host`, `method`, `path`, `decision`, `rule`, `reason`, `latency_ms`, `status`.
- **Fail closed in the log too.** Each request starts as `deny`/`no decision`; only reaching the
  upstream makes it `allow`. Any other `Decision` value encodes as `deny`. Outcomes before policy
  get fixed reasons: `invalid path`, `misdirected request`, `no authenticator`, `unauthenticated`
  (which also covers a session-store error; the 500 status tells them apart). A policy allow
  followed by a signing failure is a `deny` with reason `identity assertion failed`. An upstream
  error after an allow stays `allow` with status 502: the policy did grant access.
- **Path:** the normalized path policy saw. A rejected path has no normalized form, so the event
  records the raw request target's path (still percent-encoded), without the query.
- **Session:** the first 12 hex characters (48 bits) of the *main* session's SHA-256 hash, so the
  events from one login line up across app hosts and match what "revoke session" targets. That's
  enough to correlate events, and useless for finding or forging a session.
- **Never recorded:** the query string, cookies, `Authorization`, tokens, or full hashes
  (invariant 9).
- `audit.Recorder.Record` returns nothing: it must not change the response. Sinks handle their own
  failures (next task). Until then, `main` uses `audit.LogRecorder` (events in the process log).

**Consequences:** Requests that never reach a decision on a route (e.g. 404 on an unknown host)
leave no audit trail, only a request log line. Repeated events with no `user` are the place to
look for scanning.

## D20: Audit sinks

**Context:** Audit events (D19) need to land somewhere durable, and a lost event must not go
unnoticed.

**Decision:**
- Two sinks, chosen by `audit.sink`: `file` appends JSON lines to `audit.file`, and `stdout`
  writes them to standard output (logs stay on stderr, so the two streams never mix). The file is
  created `0600` in a `0700` directory and opened `O_APPEND`, never truncated; a path that isn't a
  regular file is refused.
- **Startup fails** if the audit file can't be opened: Warden doesn't serve unaudited.
- **Writes are synchronous**, one `Write` per event under a lock, so concurrent events never
  interleave and the line is on disk (in the page cache) when the handler returns. A local append
  costs microseconds; an asynchronous queue would add a way to drop events silently.
- **Failures are loud:** every failed write logs `AUDIT EVENT LOST` at error level with the request
  ID and a running count. The response already went out, so the request itself can't fail closed;
  the operator alert is the log line.

**Consequences:** A full disk shows up as error logs, not as an outage. With `stdout`, a reader
that stops draining the pipe eventually blocks requests; use `file` in production. No rotation:
use an external tool (`logrotate` with `copytruncate`, or rotate by renaming and restarting).

## D21: Session indexes

**Context:** The admin API lists sessions and revokes all of a user's sessions. Scanning every
Redis key for a user's sessions is O(all sessions) and racy.

**Decision:**
- Two Redis sorted sets of main session hashes, scored by creation time: `warden:sessions` (all)
  and `warden:user:<sub>` (per OIDC subject, which is stable where usernames can change). Both are
  written in the same transaction right after the session record; if indexing fails, the new
  session is deleted, so no session exists that "revoke all" can't find.
- **Revoke all** reads only the user's set and revokes each session with its app sessions, then
  deletes the set: O(sessions for that user). Revoking one session removes it from both sets.
- **Stale entries** (a session that idled out or expired in Redis) are pruned two ways: by score
  once they're past the absolute lifetime, and lazily when a listing finds the record gone. A
  stale entry is harmless: it points at nothing.
- Listings are read-only (they don't extend the idle timer) and never return the refresh token.
- Admin operations address a session by its full SHA-256 hash. The hash isn't a credential (the
  cookie is its preimage, and nothing accepts a hash from a client except these admin calls), so
  admins can see it; logs and audit events still get only the 12-character prefix (invariant 9).
- A session needs a subject; `Create` refuses an empty one.

## D22: Admin API and its protection

**Context:** Admins need to see sessions and recent decisions and revoke sessions. The API is the
most powerful thing Warden serves, so it must be at least as well guarded as any route.

**Decision:**
- **Where:** `https://<auth domain>/.warden/api/` only. Requests to it go through the same steps
  as a route request, in the proxy: normalized path, the *main* session (auth-host cookie), the
  admin policy (default deny), and an audit event. The admin handler serves nothing unless the
  proxy attached a session (fail closed on a wiring mistake). Without an `admin:` config section
  the API doesn't exist.
- **Who:** `admin.allow` rules. Config validation requires every rule to name `users` or `groups`
  (never "anyone signed in") and to set `require_mfa_within`, so admin access always means a named
  admin with recent MFA (`amr` + `auth_time`, D15/D16). Step-up re-authentication for a stale MFA
  comes in M7; until then the admin gets 403 and signs in again.
- **Unauthenticated / denied:** JSON `401` / `403` with the request ID, no redirect: the API is for
  scripts and the dashboard, not navigation.
- **Endpoints:** `GET me` (identity and CSRF token), `GET sessions` (paginated, or `?sub=` for one
  user), `POST sessions/revoke {"id"}`, `POST users/revoke {"sub"}` (uses the per-user index, D21),
  `GET decisions` (filter by `user`, `host`, `decision`; page with `before`), from an in-memory
  buffer of the last 10,000 events (`Recent`). The durable record is the audit file.
- **No secrets in responses:** listings omit refresh and CSRF tokens. Sessions are addressed by
  their full hash in request *bodies*, not paths, so the hash never lands in audit paths or access
  logs (D19, D21).
- **CSRF on mutations (POST only):** all of
  1. `Sec-Fetch-Site`, when sent, must be `same-origin`, and `Origin`, when sent, must be the auth
     origin;
  2. `Content-Type: application/json` (a cross-site form can't send it without a CORS preflight,
     which Warden never answers);
  3. `X-CSRF-Token` equal (constant time) to a random 256-bit token stored in the session at
     login. A session without one is refused.
  Bodies are capped at 4 KiB, decoded strictly (unknown fields and trailing data are errors).
- Admin revocations are also logged with the admin's username and the target (hash prefix or
  subject).

**Consequences:** Every admin API call is itself an audit event, including the dashboard's reads.
A restart empties the recent-decisions buffer. Sessions created before this change have no CSRF
token and can't mutate until the admin signs in again.

## D23: Group refresh and revocation on refresh failure

**Context:** Groups come from the ID token at login. Without a refresh, removing a user from a
group (or disabling them) at the IdP wouldn't take effect until their session expired, up to 8h.

**Decision:**
- **On request, not in the background.** When a session's groups are older than
  `auth.group_refresh_interval`, the next request that uses it (app host or admin API) redeems the
  refresh token before policy runs. An idle session isn't refreshed, but it can't access anything
  until it is, so the guarantee is the same: no access on groups older than the interval (plus
  the one-refresh window below).
- **Validated like a login:** an `id_token` is required in the refresh response and goes through
  the same verifier (signature with pinned algorithms, `iss`, `aud`, `exp`), plus `iat` not in the
  future, `azp`, and the same `sub` as the session. OIDC Core 12.2 says a refreshed ID token
  shouldn't carry a nonce, so one isn't required, but if present it must equal the login's nonce
  (stored in the session). Groups, verified email, username, `amr`, and `auth_time` are replaced; a
  rotated refresh token is stored.
- **Any failure revokes the session:** `invalid_grant` (user disabled, IdP session ended), IdP
  errors, network errors, or an invalid token. The request becomes unauthenticated (login
  redirect or 401). This is deliberately strict: an IdP outage logs users out at their next
  refresh rather than letting stale groups through.
- **One refresh at a time per session:** a Redis lock (30s, longer than the IdP client timeout).
  The holder re-reads the session under the lock, so a request that waited never spends a refresh
  token that another request already rotated (which the IdP would refuse, wrongly revoking a
  healthy session). Requests that don't get the lock proceed on the current groups.
- The session update uses `SET XX`, so a refresh racing a revocation can't bring the session back.

**Consequences:** Every `group_refresh_interval` an active session costs one IdP round trip on
one request. Sessions created before this change have no stored nonce; a refreshed token that
carries a nonce then fails the check and the user signs in again.

## D24: Admin dashboard: embedding and serving

**Context:** M6 adds a React dashboard for the admin API. It has to ship inside the single Warden
binary, and it must not open a weaker path to admin data than the API itself.

**Decision:**
- **Build and embed:** Vite + React + TypeScript in `web/admin`, built to `web/admin/dist` and
  embedded with `go:embed all:dist` (package `adminui`). `make build` runs `npm ci` (exactly the
  lockfile), type-checks, builds, then builds `bin/warden`; `make web` does only the frontend. The build output is gitignored except
  `dist/.gitkeep`, so `go build` and `go test` work without Node; such a binary answers the
  dashboard with a "not built, run `make build`" page (503). Dependencies are pinned exactly and
  locked: `react`, `react-dom`, and, for building only, `vite`, `typescript`, `@vitejs/plugin-react`,
  `@types/react`, `@types/react-dom`. No router (hash navigation), UI kit, or state library.
- **Same gate as the API:** `/.warden/admin/` on the auth host goes through the proxy's admin
  checks (main session, admin policy, audit, D22). Because it's a page, a logged-out GET is
  redirected to login and a denial is the generic HTML 403 page.
- **After login** the browser lands on the session page, which links to the dashboard. A return
  URL to the auth host would need invariant 5 relaxed; one extra click doesn't justify that.
- **Static serving:** only regular files in the embedded build, with names that pass
  `fs.ValidPath` and have no hidden (`.`) segments or backslashes; never a directory listing or
  the filesystem. Unknown paths are 404 (hash navigation needs no fallback to `index.html`).
  GET/HEAD only. `index.html` is `no-store`; hashed `assets/*` are `private, immutable`.
- **Headers on every dashboard response:** the CSP `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, and same-origin COOP/CORP. The Vite build is configured to emit
  no inline script (no module-preload polyfill, no inlined assets).
- **Pages:** live sessions (find by name, revoke), audit log (filter by user, host, decision; page
  back with "load older"), routes (read-only, from a new `GET /api/routes` that shows host,
  upstream, whether mTLS is on, and the policy, but never TLS file paths), and a user page (their
  sessions, recent access, "revoke all"). Every revoke asks for confirmation first.
- **Enforcing "no inline code":** a Go test walks the embedded build and fails on any inline
  `<script>` body, `<style>` element, `style=` or `on*=` attribute, `javascript:` URL, or
  cross-origin script/stylesheet reference (skipped only when the frontend isn't built). API
  responses carry `default-src 'none'; frame-ancestors 'none'` too, in case one is opened as a
  page. The dashboard sends the session's CSRF token (from `GET /api/me`) on every mutation; the
  API enforces it (D22).

## D25: Container stack and the issuer URL

**Context:** M7 runs Warden in Docker next to Keycloak, Redis, and the apps, with the apps
reachable only through Warden. Warden checks that tokens come from exactly one issuer URL, but
the browser and a container see "localhost" differently: in the browser it's your machine; in
Warden's container it's that container.

**Decision:**
- **One URL for both: `http://keycloak.localhost:8180`.** Browsers send `*.localhost` to the
  machine (RFC 6761), where Keycloak's port is published; inside Docker, `keycloak.localhost` is a
  network alias for the Keycloak container, which listens on 8180 too (`KC_HTTP_PORT`). Keycloak
  derives the issuer from the request URL, so both see the same issuer.
- To allow that, plain `http` for the issuer and IdP endpoints is now accepted for any
  `*.localhost` name, not just `localhost` and loopback IPs. Those names are reserved and can never
  be public, so this doesn't open http to real hosts; lookalikes (`keycloak.localhost.evil.test`,
  `evillocalhost`, a trailing dot) are rejected. Public deployments use https.
- Rejected alternative: sharing Keycloak's network namespace so `localhost` matches. No rule
  change, but it couples the containers (restarting Keycloak breaks Warden's networking).
- **Networks:** `edge` (Warden, Keycloak; the only published ports, on 127.0.0.1) and `apps`
  (`internal: true`: no published ports, no route out) for the apps and Redis. Warden is on both.
  `make dev-check` verifies this on the running stack.
- **Images:** one multi-stage `Dockerfile` (Node builds the dashboard, Go builds static binaries)
  with `warden` and `example-upstream` targets on `distroless/static:nonroot`, all bases pinned by
  version and digest, built natively for amd64 and arm64. `.dockerignore` keeps keys, `.env`, and
  local state out of every layer; certificates are bind-mounted read-only at runtime.
- **Containers** run as the host user (the Makefile passes `id -u`/`id -g`) so mounted keys keep
  their `0600` mode, with a read-only root filesystem, all capabilities dropped,
  `no-new-privileges`, and `restart: unless-stopped`. The audit log is `./var/audit.jsonl`.
- The example upstream's certificate adds `example-upstream.localhost` (still inside the dev CA's
  `localhost` name constraint), and its `-loopback-localhost=false` flag lets Docker's DNS resolve
  `auth.warden.localhost` to Warden for the JWKS.
- `make run` still works for fast iteration via `make dev-up-host`, an opt-in override that
  re-publishes the apps on 127.0.0.1, deliberately undoing the isolation.

**Consequences:** Keycloak sets its login cookies `Secure` even over http; browsers accept that on
`*.localhost` (a secure context), curl does not, so scripted logins need a real browser. Recreating
the Keycloak container resets its dev database (OTP enrollments included).

## D26: Security headers

**Context:** Warden writes its own pages (errors, login redirects, the session page, the admin
dashboard and API, JWKS, healthz) and proxies everything else. Each page set its own headers, and
the generic error page could be framed (`default-src` does not cover `frame-ancestors`).

**Decision:**
- **One set for every Warden response,** applied by the proxy before any handler runs:
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` (login and handshake URLs
  carry state and codes), `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` (clickjacking),
  `Cross-Origin-Opener-Policy: same-origin`, and a default CSP of `default-src 'none';
  frame-ancestors 'none'`. Pages that render more (session page, dashboard) replace the CSP with
  their own, which keeps `frame-ancestors 'none'`. New endpoints get the set without opting in.
- **Proxied responses are the app's.** The set is removed just before a request goes upstream, so
  Grafana and friends keep their own framing and CSP rules. Warden doesn't invent headers for them.
- **HSTS on every HTTPS response, proxied or not.** Warden terminates TLS for all its hosts, so
  it alone decides their HSTS policy: an upstream's `Strict-Transport-Security` is dropped, so an
  app can neither turn it off (`max-age=0`) nor widen it (`includeSubDomains; preload` could lock
  out unrelated sibling hosts). Default `max-age` one year (`tls.hsts_max_age`, `0s` turns it
  off); Warden never adds `includeSubDomains` or `preload`. Never sent on the plain-HTTP redirect
  listener, where it is meaningless and forbidden (RFC 6797 section 7.2).

**Consequences:** A browser that has seen a Warden host keeps using HTTPS for it for a year. If a
deployment ever has to serve plain HTTP on that name, it must first ship `hsts_max_age: 0s` and
wait out the old max-age.

## D27: Rate limiting

**Context:** Login and callback each cost the IdP a round trip (the callback a code exchange), and
the admin API reads Redis on every request. Without limits, one client can flood both.

**Decision:**
- **Token buckets, in memory, per process** (`internal/ratelimit`): a sustained rate per minute
  plus a burst. A small hand-written limiter instead of `golang.org/x/time/rate`, which has no
  keyed table or eviction (the part that matters here) and would be a new dependency. The bucket
  math is a few lines; no cryptography is involved.
- **What is limited, and by what:**
  - `/.warden/login` and `/.warden/callback`, per client IP, one shared bucket (a full login uses
    one of each). Default 20/min, burst 10. Checked before any other work, so a limited callback
    never reaches the token endpoint or the session store.
  - Admin API and dashboard, per client IP before the session lookup (default 120/min, burst 30),
    so a flood never reaches Redis; then per signed-in session (default 60/min, burst 20), so a
    stolen admin cookie can't be used at full speed from many addresses.
  - Not limited: the app routes (apps have their own capacity concerns; Warden's job there is
    access control), the handshake (single-use 256-bit codes, nothing to guess), healthz, JWKS.
- **Client identity is `RemoteAddr` only.** Warden is the edge; `X-Forwarded-For` and friends are
  written by the client and never consulted. IPv6 clients are grouped by /64, the usual
  allocation to one subscriber, so rotating addresses within it doesn't help.
- **Bounded memory:** at most 10,000 keys per limiter, least recently used evicted first. An
  attacker who wants their own empty bucket evicted must outpace 10,000 other clients, at which
  point they have that many addresses anyway.
- **Response:** `429` with `Retry-After` (whole seconds, rounded up): the generic page for login
  and the dashboard, the JSON error for the API. Admin 429s are audited as a deny with reason
  `rate limited`; every 429 is logged with the client key (an IP is not a secret).
- **Always on.** `rate_limits` in the config tunes the three limits (validated, 1 to 1,000,000);
  there is no off switch. Unset limits get the defaults.

**Consequences:** Limits are per Warden process; several instances behind a load balancer would
each allow the full rate (M8 would move the buckets to Redis). Many users behind one NAT share a
login bucket; burst 10 covers a few people signing in at once. In the local Docker stack, Docker's
port proxy can make every local client appear as the bridge gateway address, so they share one
bucket; that's harmless in dev, and published ports on a public host keep real client addresses.
