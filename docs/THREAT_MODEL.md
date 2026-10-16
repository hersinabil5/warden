# Threat model

Update this whenever a change adds, removes, or weakens a mitigation.

## Assets

- Access to internal apps and the data behind them
- User sessions and session cookies
- OIDC client secret; identity-assertion signing key; mTLS client key
- Audit log integrity

## Trust boundaries

1. Browser ↔ Warden (internet-facing, untrusted input)
2. Warden ↔ IdP (Keycloak): trusted for identity, reached over TLS in production
3. Warden ↔ Redis: trusted, private network
4. Warden ↔ upstream apps: upstreams trust only Warden (mTLS + signed assertion)

## Threats and mitigations

| # | Threat | Mitigation | Milestone | Status |
|---|--------|-----------|-----------|--------|
| T1 | Unauthenticated access to internal apps | Every route request needs a valid app session (login redirect for GET/HEAD, 401 otherwise), then a matching allow rule; default deny, any evaluation problem is a deny, 403 page shows only the request ID (D13, D15) | M1–M3 | done |
| T2 | Login CSRF / session fixation | Random 256-bit `state`/`nonce` + PKCE S256 in a sealed, host-only, per-login cookie (D9); callback requires the cookie for that state, single-use state in Redis before code exchange, and a fresh session ID with any prior session revoked (D12) | M2 | done |
| T3 | Token forgery or substitution | Signature via JWKS with pinned asymmetric algs (no `none`/`HS*`, D8); `iss`, `aud`, `exp`; `nonce` bound to the pre-auth cookie; `iat` within the login window; `azp`; `sub` required; groups claim type-checked; unverified email dropped (D12) | M2 | done |
| T4 | Open redirect via return URL | Return URL must be a literal `https://` URL on a configured route host and Warden's public port; `\`, whitespace, control chars, userinfo and other schemes rejected; redirect goes to a canonical URL rebuilt from the parsed parts; fuzzed (D11) | M2 | done |
| T5 | Policy bypass via path tricks | Raw request target normalized once before routing, `/.warden/` dispatch, auth and policy; `.`/`..`/`//` resolved; encoded `/` and `\`, `\`, NUL/control characters, bad or overlong UTF-8, double encoding and `;` rejected with 400; the upstream gets exactly the normalized path; prefixes match whole segments; optional case-insensitive matching (D15). Fuzzed | M3 | done |
| T6 | Identity header spoofing | Every identity header stripped before proxying (built-in list, `X-Warden-*`, `X-Auth-Request-*`, `strip_headers`), matched case-insensitively with `_` folded to `-`; then a signed ES256 assertion per request (`typ`-pinned, `aud` = route host, ≤ 60 s, `jti`), verifiable via the public JWKS (D17) | M4 | done |
| T7 | Bypassing Warden to reach upstreams directly | mTLS to upstreams: they require Warden's client certificate (internal CA + CN) and Warden trusts only the internal CA for them; every request also needs a valid assertion; dev CA name-constrained to loopback (D18). Private network for the other upstreams in M7 | M4, M7 | partial |
| T8 | Access persists after user removal | Server-side sessions; admin revocation (D22); groups re-confirmed with the IdP every `group_refresh_interval` via the refresh token, fully validated, and any refresh failure (disabled user, ended IdP session, error) revokes the session (D23) | M5 | done |
| T9 | Stolen session cookie | Opaque 256-bit IDs, only hashes in Redis; idle + absolute TTL checked on every read; app sessions bound to their host and revoked with the main session (D10). HttpOnly/Secure/SameSite host-only cookies; per-user session index so every session of a user can be found and revoked (D21); admin API revokes one session or all of a user's, effective on the next request (D22) | M2, M5 | done |
| T10 | Weak authentication on sensitive paths | `require_mfa_within` checks `amr` (two factors or `mfa`) and `auth_time` recency; Keycloak OTP + `amr` mapper in the dev realm (D16); denied with 403 until step-up re-authentication (D15) | M3, M7 | partial |
| T11 | Brute force / abuse of auth endpoints | Rate limiting | M7 | planned |
| T12 | Secrets leaking via logs | Never log tokens/cookies/codes; hashed identifiers only; client secret held in a self-redacting `config.Secret` and never echoed in config errors | all | partial (config: done) |
| T13 | Admin dashboard CSRF / XSS | API mutations need same-origin `Sec-Fetch-Site`/`Origin`, a JSON content type, and the session's random CSRF token; strict JSON decoding (D22). Dashboard behind the admin policy with a strict CSP (`script-src`/`style-src 'self'`, no framing); the build is tested to contain no inline code; API responses locked down by CSP too (D24) | M5, M6 | done |
| T14 | Misconfiguration silently weakens policy | Strict config decoding and validation at startup; ambiguous rules, non-normalized path prefixes, and pathful upstreams rejected (D5) | M1 | done |
| T15 | Open redirect via HTTP→HTTPS redirect (attacker-set Host) | Redirect only to configured hosts, configured HTTPS port; else 400 (D7) | M1 | done |
| T16 | Host confusion / domain fronting (SNI ≠ Host) | 421 when TLS ServerName and Host differ (D7) | M1 | done |
| T17 | Upstream traffic rerouted via `HTTP_PROXY` env | Upstream transport ignores proxy env vars (D6) | M1 | done |
| T18 | Upstream path shadowing Warden endpoints | `/.warden/` reserved on every host, never proxied (D7) | M1 | done |
| T19 | Spoofed client IP / host / scheme via `X-Forwarded-*`, `Forwarded`, `X-Real-IP` | Overwritten with values Warden observed (never appended); `Forwarded` and `X-Real-IP` removed; hop-by-hop headers stripped both ways | M1 | done |
| T20 | Forged or colliding request IDs in logs/audit | Warden always generates the ID; client and upstream values discarded (D7) | M1 | done |
| T21 | Resource exhaustion (slow-loris clients, hung upstreams) | Server read-header/read/write/idle timeouts; upstream dial/TLS/response-header timeouts (D6) | M1 | done |
| T22 | Internal details leaked in error responses | Generic error pages with request ID only; causes go to logs | M1 | done |
| T23 | IdP mix-up or malicious discovery metadata (wrong issuer, http endpoints, no PKCE) | Discovery `issuer` must match exactly; endpoints https-only (loopback excepted), no credentials; S256 and `code` required; JWKS must hold a usable public key and no private/symmetric keys (D8) | M2 | done |
| T24 | Algorithm downgrade / confusion (`alg: none`, HS256 keyed with the RSA public key) | `auth.id_token_algs` allows asymmetric algs only; verifier pinned to their intersection with the IdP's list (D8) | M2 | done |
| T25 | Startup hang or traffic redirection on IdP calls | Bounded retry budget; IdP client timeouts, 1 MiB body cap, no proxy env, no redirects (D8) | M2 | done |
| T26 | Authorize-request tampering via login parameters or Host header (redirect_uri, client_id, scope, response_type, PKCE method) | Authorize URL built only from config and discovery; request query and Host ignored (D9) | M2 | done |
| T27 | Login CSRF / session swap on app hosts via a forwarded handshake code | Code bound to an app-host `__Host-` cookie (only its hash travels), redeemable once within 30s on the issuing host only; no code issued without a binding (D13) | M2 | done |
| T28 | Upstream stealing or planting Warden cookies | Warden cookies stripped from requests to upstreams; upstream `Set-Cookie` for Warden names dropped (D13) | M2 | done |
| T29 | Logout CSRF / forced logout | POST-only logout on the auth host; cross-origin `Origin`/`Sec-Fetch-Site` refused; SameSite=Lax cookie (D14) | M2 | done |
| T30 | Assertion replay or confusion (token for app A used at app B; ID token passed as an assertion) | `aud` = one route host; explicit `typ` checked by verifiers; 60 s lifetime; ES256 only; `kid` from a published set (D17) | M4 | done |
| T31 | Undetected or repudiated access (no record of who reached what) | One audit event per request to a route host: user, main session hash prefix, normalized path, allow/deny with rule and reason, status, Warden request ID; pre-policy failures recorded as deny (D19); appended to a 0600 JSONL file or stdout, startup fails without a writable sink, lost events logged at error level (D20) | M5 | done |
| T33 | Privilege escalation to the admin API | Auth host only, main session, admin policy that config validation forces to name users/groups and require recent MFA; default deny; audited; handler refuses requests without the proxy's session (D22) | M5 | done |
| T32 | Secrets leaking via the audit log | Events omit query strings, cookies, `Authorization`, tokens; session only as a 12-hex prefix of its hash; tested with planted secrets (D19) | M5 | done |

## Out of scope (explicitly not defended)

- Compromised IdP: an attacker controlling Keycloak can mint any identity.
- Compromised user device with a valid session (partially mitigated by short TTLs and revocation; device posture is a stretch goal).
- Compromised Warden host: it holds the signing key and session store access. Warden is a high-value target and a single point of failure.
- Vulnerabilities inside upstream apps once a user is legitimately authorized.
