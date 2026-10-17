# Threat model

What Warden defends against, and how. Each threat has a number (T1, T2, ...) and points to the
design decision that explains it (D1, D2, ... in [DECISIONS.md](DECISIONS.md)). Update this
whenever a change adds, removes, or weakens a defense.

## What we're protecting

- The internal apps behind Warden and their data
- User sessions and session cookies
- Secrets: the OIDC client secret, the key that signs identity tokens, the mTLS client key
- The audit log

## Who trusts whom

1. **Browser → Warden:** the internet. Everything from the browser is untrusted.
2. **Warden → Keycloak:** trusted to say who a user is.
3. **Warden → Redis:** trusted, on a private network.
4. **Warden → apps:** the apps trust only Warden (mTLS plus a signed identity token).

## Threats and defenses

### Getting in without permission

| # | Attack | Defense |
|---|---|---|
| T1 | Reaching an app without logging in | Every request needs a valid session and a policy rule that allows it. No rule means deny, and any error means deny (D13, D15) |
| T10 | Using a weak or old login on a sensitive page | Rules can require MFA within N minutes. If the login is too old, Warden sends the user back to log in again with their OTP, and checks that the login really is fresh (D15, D16, D28) |
| T14 | A config typo quietly weakening a rule | The config is checked strictly at startup: unknown keys, empty rules, and anything ambiguous stop Warden from starting (D5) |
| T33 | Getting into the admin API | Admin rules must name users or groups and require recent MFA. Admin requests get the same checks and audit as app requests (D22) |

### Login attacks

| # | Attack | Defense |
|---|---|---|
| T2 | Login CSRF: tricking a browser into finishing someone else's login | Random `state`, `nonce`, and PKCE, sealed in a cookie only this browser has; `state` can be used once; a fresh session ID after login (D9, D12) |
| T3 | Forged or swapped login tokens | Every ID token is fully checked: signature, issuer, audience, expiry, issue time, nonce, `azp`, `sub` (D8, D12) |
| T23 | A fake or misconfigured identity provider | Its discovery document must match the configured issuer exactly, use HTTPS, and support PKCE (D8) |
| T24 | Algorithm tricks (`alg: none`, HS256 with the public key) | Only the configured asymmetric algorithms are accepted (D8) |
| T25 | Hanging or redirecting Warden's calls to the identity provider | Timeouts, a size limit, no proxy settings, no redirects, limited retries (D8) |
| T26 | Tampering with the login request | The login URL is built only from config, never from the request (D9) |
| T27 | Swapping sessions by forwarding someone a handshake link | Handshake codes only work in the browser that started the login, once, within 30 seconds (D13) |
| T29 | Forcing a logout from another site | Logout is POST only and refuses cross-site requests (D14) |
| T11 | Brute force and floods on login and the admin API | Rate limits per IP (and per session for the admin API), using the real connection IP (D27) |

### Stolen or stale sessions

| # | Attack | Defense |
|---|---|---|
| T9 | A stolen session cookie | Random 256-bit IDs, only hashes stored, idle and absolute timeouts, host-only cookies, revocable from the dashboard (D2, D10, D21, D22) |
| T8 | Keeping access after being removed at the identity provider | Groups are re-checked with the identity provider regularly, and any failure logs the user out (D23) |
| T38 | An open WebSocket outliving a logout or revocation | Open sockets are re-checked every 30 seconds and closed if the session or policy says no (D29) |

### Request tricks

| # | Attack | Defense |
|---|---|---|
| T5 | Path tricks to get around a rule (`%2F`, `..`, `\`, `;`) | The path is normalized once, ambiguous paths are rejected, and the app gets exactly the path the policy checked. Fuzz tested (D15) |
| T4 | Open redirect through the "return to" URL after login | Only HTTPS URLs on Warden's own app hosts are allowed, and Warden redirects to a URL it rebuilt itself. Fuzz tested (D11) |
| T15 | Open redirect through the HTTP→HTTPS redirect | Only configured hosts are redirected (D7) |
| T16 | Using a TLS connection for one host to reach another | Warden refuses requests whose host doesn't match the TLS name (D7) |
| T19 | Faking the client IP or host with `X-Forwarded-*` headers | Warden overwrites them with what it actually saw, and strips hop-by-hop headers |
| T20 | Faking request IDs in logs | Warden always makes its own request IDs (D7) |
| T36 | Request smuggling through an `Upgrade: h2c` request | Only `Upgrade: websocket` is allowed (D29) |
| T37 | Another site opening a WebSocket with the user's cookies | WebSockets must come from the app's own origin (D29) |
| T18 | An app shadowing Warden's own pages | `/.warden/` is reserved on every host and never passed to apps (D7) |

### Protecting the apps

| # | Attack | Defense |
|---|---|---|
| T6 | Sending a fake identity header to an app | Warden deletes all identity headers from the client, then adds its own signed token (D17) |
| T30 | Reusing an identity token at another app | Each token is for one app only and expires within 60 seconds (D17) |
| T7 | Skipping Warden and talking to an app directly | The apps sit on an internal network with no open ports, and the example app also requires Warden's mTLS certificate (D18, D25) |
| T28 | An app stealing or overwriting Warden's cookies | Warden's cookies are removed before requests reach apps, and apps can't set them (D13) |
| T17 | Rerouting app traffic with a proxy environment variable | Warden ignores `HTTP_PROXY` for app traffic (D6) |

### Browser attacks on Warden's own pages

| # | Attack | Defense |
|---|---|---|
| T13 | CSRF or XSS on the admin dashboard | Admin changes need a same-origin request, JSON, and a per-session CSRF token. The dashboard has a strict CSP and a test that it contains no inline code (D22, D24) |
| T34 | Clickjacking, MIME sniffing, leaking URLs through the referrer | Every Warden page gets anti-framing, `nosniff`, `no-referrer`, and a strict CSP (D26) |
| T35 | Downgrading to plain HTTP (SSL stripping) | HSTS on every HTTPS response (D26) |

### Leaks and availability

| # | Attack | Defense |
|---|---|---|
| T12 | Secrets showing up in logs | Tokens, cookies, and codes are never logged; only short hashes are. The client secret hides itself when printed. **Status: partly done** (config secrets are covered) |
| T32 | Secrets showing up in the audit log | Audit events leave out query strings, cookies, and tokens. Tested with planted secrets (D19) |
| T22 | Internal details in error pages | Users only see a generic page with a request ID; details go to the logs |
| T21 | Slow clients or hung apps tying up Warden | Timeouts on every connection, in both directions (D6) |
| T31 | Access with no record of who did what | Every request to an app is logged with the user, path, decision, and reason. Warden won't start without a working audit log (D19, D20) |

### Public demo

| # | Attack | Defense |
|---|---|---|
| T39 | Demo visitors seeing or kicking out each other | Each visitor only sees and revokes their own sessions; everything resets hourly (D30) |
| T40 | Demo mode or demo passwords ending up in a real deployment | Demo mode needs an explicit `enabled: true`, logs a loud warning, and only shows the demo section of the config (D30) |

## Not defended (out of scope)

- **A hacked identity provider.** Whoever controls Keycloak can log in as anyone.
- **A hacked user device** with a valid session. Short timeouts and revocation limit the damage.
- **A hacked Warden server.** It holds the signing key and access to the session store, so it's
  a high-value target and a single point of failure.
- **Bugs inside the apps** once a user is allowed in.
