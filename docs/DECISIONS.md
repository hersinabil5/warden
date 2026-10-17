# Decision log

Why Warden works the way it does. Each entry is a design choice: the **problem**, what I
**decided**, and the **trade-off**. Newest at the bottom. The code refers to these by number
(for example `// docs/DECISIONS.md D22`), and [THREAT_MODEL.md](THREAT_MODEL.md) links to them.

## D1: Host-only cookies with a central auth domain

**Problem:** One cookie for `*.warden.localhost` would be sent to every app, so any app (or an
XSS bug in one) could steal it.

**Decision:** The main login cookie lives only on the auth host. When you visit an app, Warden
bounces you through the auth host, which hands the app a one-time code (single use, 30 seconds)
that the app trades for its own cookie.

**Trade-off:** One extra redirect per app. Logging out has to end every app's session too.

## D2: Server-side sessions in Redis, hashed IDs

**Problem:** Sessions stored as JWTs in cookies can't be revoked before they expire.

**Decision:** The cookie holds a random 256-bit ID. Redis stores the session under the SHA-256
hash of that ID, never the ID itself.

**Trade-off:** Warden needs Redis to work. But someone who reads Redis still can't build a
working cookie.

## D3: `slog.SetDefault` only in `main`

**Problem:** Loggers are passed around explicitly (no global state), but libraries still log
through Go's global default logger, which prints plain text.

**Decision:** `main` sets the global logger to the JSON logger once at startup, and nothing else
touches it. Tests don't use the global at all.

**Trade-off:** None really; all output is JSON and tests can run in parallel.

## D4: Lint rules: no global exceptions

**Problem:** `gosec` catches real security mistakes (weak randomness, missing timeouts, skipped
TLS checks). Turning it off globally, or with a bare `//nolint`, would hide them.

**Decision:** No global exclusions. Every exception is on one line and has to name the linter
and say why: `//nolint:gosec // <reason>`.

**Trade-off:** Some test code needs explained exceptions, but every silenced warning is visible.

## D5: Strict config: reject anything ambiguous

**Problem:** The config *is* the security policy. A typo that loads fine can quietly weaken it:
an empty rule `{}` could mean "no conditions", and a misspelled key would just be ignored.

**Decision:** The config is decoded strictly (unknown keys, duplicates, and wrong types are
errors) and anything ambiguous is rejected: empty rules, empty lists, zero durations,
non-normalized path prefixes, upstream URLs with a path. All problems are reported at once.
The client secret comes only from an environment variable and hides itself when printed.

**Trade-off:** Some reasonable-looking configs are refused and have to be written explicitly.

## D6: Temporary dev mode, and timeout values

**Problem:** In the first milestone the proxy existed before login and policies did, but it
still had to be testable without breaking "default deny".

**Decision:** A temporary `-dev-allow-unauthenticated` flag, which only worked on localhost and
logged a warning. It was removed once policies existed (M3). Timeouts were set everywhere:

| Where | Timeout | Value |
|---|---|---|
| Server | Read headers / whole request / write / idle | 10s / 60s / 120s / 120s |
| App connections | Connect / TLS / response headers | 5s / 5s / 30s |

App traffic also ignores `HTTP_PROXY`, so an environment variable can't reroute it.

**Trade-off:** The timeouts aren't configurable yet.

## D7: Warden's own paths, hosts, and request IDs

**Problem:** Warden shares every host with the apps behind it and with attacker input.

**Decision:**
- `/.warden/` is reserved on every host and never passed to apps.
- The TLS name must match the `Host` header (otherwise 421).
- The HTTP→HTTPS redirect only goes to configured hosts, so it can't be an open redirect.
- Warden always makes its own random request IDs and ignores the client's.

**Trade-off:** An app that uses `/.warden/` paths itself can't sit behind Warden unchanged.

## D8: Trusting the identity provider carefully

**Problem:** All token checks depend on the identity provider's discovery document and keys. A
misconfigured or fake one could weaken them, for example by allowing `alg: none` or dropping
PKCE.

**Decision:**
- Only asymmetric signing algorithms (RS, PS, ES) can be configured; `none` and HMAC can't.
- The discovery document must match the configured issuer exactly, use HTTPS (plain HTTP only on
  localhost), and support PKCE (S256).
- The key set must contain a usable public key and no private or secret keys.
- Startup retries for up to 60 seconds while Keycloak boots, but fails at once on a typo.
- Calls to the identity provider have timeouts, a 1 MiB size limit, and never follow redirects.

**Trade-off:** Identity providers that only sign with HMAC or don't support PKCE can't be used.

## D9: The login cookie

**Problem:** Between "start login" and "login finished", Warden has to remember `state`,
`nonce`, and the PKCE verifier, tied to this browser, before any session exists.

**Decision:** They go in a cookie encrypted and signed with AES-256-GCM, with a key that's random
per process. The cookie is named `__Host-warden_login_<part of state>`, so two tabs logging in
at once don't clash, and the `__Host-` prefix makes the browser enforce safe settings. It expires
after 10 minutes, and `state` is also marked as used on the server so the cookie can't be
replayed.

**Trade-off:** Restarting Warden cancels logins in progress.

## D10: How sessions are stored and revoked

**Problem:** Each app has its own cookie (D1), but revoking a user has to take effect on every
app at once, on the very next request.

**Decision:**
- An app session only points to the main session. Every lookup goes through the main session,
  so deleting it instantly kills every app session.
- Idle and absolute timeouts are checked on every read, not just left to Redis expiry.
- Updates can't bring a revoked session back (`SET XX`), and one-time codes are read and deleted
  in one step (`GETDEL`).
- A Redis error is treated as "no access", never as "allowed".
- The refresh token is stored in the session and hidden from logs.

**Trade-off:** Every request costs a Redis read and write.

## D11: Return URLs after login

**Problem:** After login, Warden sends you back to the page you wanted. Browsers and Go parse
weird URLs differently (`\` as `/`, `https:evil.com`, `a@evil.com`), and any difference can
become an open redirect.

**Decision:** The return URL must start with `https://`, have no spaces, control characters,
backslashes, or user info, and point at one of Warden's app hosts. Warden then redirects to a
URL it rebuilt itself from the parsed parts, never the raw input. A fuzz test checks that every
accepted URL lands on an allowed host.

**Trade-off:** Hand-written relative return URLs don't work (Warden's own redirects always pass).

## D12: Checks in the login callback

**Problem:** The callback is where untrusted input turns into a session, so every check has to
pass before anything is created.

**Decision:** In order:
1. The `state` must match the login cookie from this browser (otherwise it's login CSRF).
2. `state` is marked as used before the code is exchanged, so a replay never reaches Keycloak.
3. The code is exchanged with the PKCE verifier.
4. The ID token is fully checked: signature, issuer, audience, expiry, nonce, issue time, `azp`,
   and `sub`. Email is kept only if it's verified.
5. Any old session in the browser is revoked and a new session ID is issued.

**Trade-off:** Users without a verified email can't match `email_domains` rules.

## D13: Handshake binding and cookie isolation

**Problem:** If the one-time code from D1 were enough by itself, an attacker could log in as
themselves and send the victim the link, signing the victim in as the attacker. Also, apps share
a host with Warden's cookies and could read or overwrite them.

**Decision:**
- Before login, the app host sets a random cookie in the browser. The code only works in the
  browser that has that cookie, on that host, once, within 30 seconds.
- If you're already logged in, login skips Keycloak (single sign-on).
- Logged-out page loads get redirected to login; other requests get a 401.
- Warden removes its cookies from requests to apps and blocks apps from setting them.

**Trade-off:** An app that relies on a cookie with the same name as Warden's won't see it.

## D14: Logout

**Problem:** Logout has to end access everywhere, and another site must not be able to log you
out.

**Decision:** Logout is a POST on the auth host only, and cross-site requests are refused. It
clears the cookie, deletes the main session (which kills every app session), and can optionally
log you out of Keycloak too.

**Trade-off:** Without the Keycloak option, your next login is silent single sign-on.

## D15: Policy rules and path normalization

**Problem:** A rule is only as good as the path it checks. Apps decode paths differently (`%2F`
as `/`, `\` as `/`, `;x` stripped), so any gap between what Warden checks and what the app
serves is a bypass.

**Decision:**
- **Normalize once, first.** Warden decodes the path once, resolves `.` and `..`, and collapses
  `//`, before doing anything else. The policy and the app both see that exact path.
- **Reject instead of guessing:** encoded `/` or `\`, raw `\`, NUL and control characters, bad
  UTF-8, double encoding, and `;` all get a 400.
- **Rules:** rules in a list are ORed; conditions inside a rule are ANDed. A path rule replaces
  the route's rule for that path (longest prefix wins). Prefixes match whole segments, so
  `/admin` covers `/admin/x` but not `/administrator`.
- **MFA:** `require_mfa_within` needs two factors in `amr` (like Keycloak's `["pwd","otp"]`) and
  a recent enough `auth_time`.
- **Fail closed:** anything unexpected is a deny.

**Trade-off:** Apps that need `;` or encoded slashes in paths can't sit behind Warden as is.

## D16: Dev MFA with Keycloak OTP

**Problem:** MFA rules read `amr` from the ID token, but Keycloak doesn't send it by default.

**Decision:** The dev realm has a login flow that records `pwd` and `otp`, a mapper that puts
them in the token, and gives alice a fixed OTP key so the setup works the same every time (dev
only).

**Trade-off:** A real deployment has to set up the same flow and mapper.

## D17: Signed identity tokens for apps

**Problem:** Apps need to know who the user is, and must be able to tell Warden's word apart
from a header the client made up or a token for another app.

**Decision:**
- **Strip, then add.** Warden deletes every identity header the client sent (including tricky
  spellings like `X_Forwarded_Email`), then adds its own signed token.
- **The token** is an ES256 JWT with a special type, made for one app only (`aud` = the app's
  host), valid for at most 60 seconds, with a unique ID.
- **Keys** are published at `/.well-known/jwks.json`, and old keys can stay listed during a key
  rotation.

**Trade-off:** A leaked token could be replayed at the same app for up to a minute.

## D18: mTLS to apps and the dev CA

**Problem:** A signed token says who the user is, but an app reachable on the network could
still be called directly.

**Decision:** For mTLS routes, Warden presents a client certificate from an internal CA and
trusts only that CA. The example app accepts only Warden's certificate. The dev CA is
**name-constrained** to localhost, so even if its key leaked, it couldn't sign a certificate for
a real website.

**Trade-off:** Certificate rotation is manual ("run `make internal-ca` and restart").

## D19: What goes in the audit log

**Problem:** Every allow and deny should be recorded with a reason, without the log becoming a
place where secrets leak.

**Decision:**
- One event per request to an app: time, request ID, user, session, host, method, path,
  decision, rule, reason, latency, status.
- Every request starts as "deny" and only becomes "allow" when it actually reaches the app.
- Only the first 12 characters of the session hash are logged.
- Never logged: query strings, cookies, `Authorization`, tokens.

**Trade-off:** Requests that never reach a decision (like an unknown host) only show up in the
normal request log.

## D20: Where audit events go

**Problem:** Audit events need to be saved somewhere durable, and a lost event must be noticed.

**Decision:** Events go to a JSON-lines file (private, append-only) or to stdout. Warden won't
start if it can't open the file. A failed write logs `AUDIT EVENT LOST` loudly.

**Trade-off:** No built-in log rotation; use an external tool.

## D21: Session indexes

**Problem:** The admin API needs to list sessions and revoke all of one user's sessions, without
scanning all of Redis.

**Decision:** Two Redis sorted sets: all sessions, and sessions per user. Every new session is
added to both, or it's deleted. Stale entries are cleaned up as they're found.

**Trade-off:** A little extra Redis work on each login.

## D22: Admin API and its protection

**Problem:** The admin API is the most powerful thing Warden serves, so it needs at least the
same protection as any app.

**Decision:**
- It lives only on the auth host, and every request goes through the same session, policy, and
  audit checks as app requests.
- Admin rules must name users or groups and require recent MFA.
- Changes (revoking) need a same-origin request, a JSON body, and a per-session CSRF token.
- Session listings never include refresh tokens or CSRF tokens.

**Trade-off:** Every dashboard click is also an audit event.

## D23: Re-checking groups with Keycloak

**Problem:** Groups come from the login token. If someone is removed from a group or disabled in
Keycloak, they'd keep access until their session expired (up to 8 hours).

**Decision:** When a session's groups are older than `group_refresh_interval`, the next request
uses the refresh token to get fresh ones, and checks the new token as carefully as a login. **Any
failure logs the user out.** Only one refresh per session runs at a time.

**Trade-off:** If Keycloak is down, users get logged out at their next refresh instead of keeping
possibly-stale access. That's on purpose.

## D24: Admin dashboard

**Problem:** The React dashboard has to ship inside the Warden binary and must not be an easier
way into admin data than the API.

**Decision:**
- Built with Vite and embedded with `go:embed`. Pinned dependencies, no extra libraries.
- Same checks as the API: logged-out users go to login, non-admins get a 403.
- Only real files from the build are served, never directory listings.
- A strict CSP with no inline code, and a test that fails if the build ever contains inline code.

**Trade-off:** After login you land on the session page and click through to the dashboard.

## D25: Running everything in Docker, and the issuer URL problem

**Problem:** Warden checks that tokens come from one exact issuer URL. But `localhost` means my
laptop to the browser and the Warden container itself inside Docker, so the URLs never matched.

**Decision:**
- **Use `keycloak.localhost:8180` for both.** Browsers send `*.localhost` to my machine, and in
  Docker it's a name for the Keycloak container. Plain HTTP is allowed only for `*.localhost`
  names, which can never be public.
- **Two networks:** `edge` (Warden and Keycloak, the only open ports, on 127.0.0.1) and an
  internal `apps` network with no open ports. `make dev-check` verifies this.
- **Containers** are distroless, non-root, read-only, with all capabilities dropped and pinned
  image versions. Keys and `.env` are never copied into images.

**Trade-off:** Scripted logins need a real browser, because Keycloak's cookies are marked
`Secure` even over HTTP.

## D26: Security headers

**Problem:** Each Warden page set its own headers, and the error page could be framed.

**Decision:**
- Every page Warden serves gets the same set: no framing, `nosniff`, `no-referrer`, and a strict
  CSP. New pages get them automatically.
- Apps keep their own headers; Warden doesn't add page headers to app responses.
- HSTS (one year) on every HTTPS response, including apps. Apps can't turn it off or widen it.
  Never sent over plain HTTP.

**Trade-off:** A browser that visited once keeps using HTTPS for a year.

## D27: Rate limiting

**Problem:** One client could flood login (each one costs a trip to Keycloak) or the admin API
(each one costs a Redis read).

**Decision:**
- Token-bucket limits, kept in memory, written by hand (`golang.org/x/time/rate` doesn't handle
  per-client limits or memory bounds, and would be a new dependency).
- Login and callback: 20 per minute per IP. Admin API: per IP before the session lookup, then per
  session.
- The IP comes only from the connection, never from `X-Forwarded-For`. IPv6 is grouped by /64.
- At most 10,000 tracked clients, so memory stays bounded.
- Over the limit: `429` with `Retry-After`. Always on.

**Trade-off:** Limits are per Warden process, and people sharing one IP share a limit.

## D28: Step-up re-authentication

**Problem:** A stale MFA login on an MFA page got a 403, and the only fix was logging out and in
again.

**Decision:**
- If re-logging in would fix the problem (everything else about the user already matches), Warden
  sends them to Keycloak with `prompt=login` and `max_age=0`, which forces a full login with OTP.
- The new token must show a login time **after** the step-up started, or it's refused.
- **No loops:** step-up is only offered if the current login is over 2 minutes old. A user with no
  second factor gets one try, then a plain 403.
- Only page loads step up; a POST can't survive the round trip, so it gets a 403.

**Trade-off:** A step-up costs a full login.

## D29: WebSockets

**Problem:** Go's reverse proxy forwards any `Upgrade` request, an open socket never makes a
"next request" for revocation to act on, browsers don't apply CORS to WebSockets, and a socket
can't follow a login redirect.

**Decision:**
- **Only `Upgrade: websocket`.** Anything else (like `h2c`) gets a 400, because h2c would turn
  the connection into raw HTTP/2 to the app and skip per-path rules (h2c smuggling).
- **Same origin only:** a socket opened from another site gets a 403.
- Logged-out sockets get a 401, not a redirect.
- **Open sockets are re-checked every 30 seconds** (session, groups, and policy). Any failure,
  even Redis being down, closes the socket.

**Trade-off:** A revoked user can keep a socket for up to 30 seconds.

## D30: Demo mode

**Problem:** Strangers using the live demo need logins and OTP codes without an authenticator
app, they all share the same accounts, and they shouldn't see or break each other's demo.

**Decision:**
- Turned on with an explicit `demo: enabled: true`, with a loud warning at startup.
- A landing page shows the demo accounts and **live OTP codes**, with no JavaScript.
- The OTP codes are computed with the standard library's HMAC, following RFC 6238, and tested
  against the RFC's examples. Warden only shows codes; Keycloak still checks them.
- **Visitors only see themselves:** each one is tagged with a keyed hash of their IP, and the
  dashboard only shows and revokes their own sessions.
- Everything resets every hour (the audit file keeps everything).

**Trade-off:** People behind the same public IP see each other's demo. Keycloak itself also needs
locking down for a public demo (no password or OTP changes for demo users).

## D31: Dashboard showcase build

**Problem:** The portfolio needs a link that always works, even if the live demo server is down.

**Decision:** The same dashboard, built a second way: `vite build --mode showcase` swaps the API
client for sample data at build time, and the result is a static site on Vercel. None of the
sample code ends up in the real binary, and a test checks that. The showcase has the same strict
headers as the real dashboard.

**Trade-off:** Two builds to keep working.
