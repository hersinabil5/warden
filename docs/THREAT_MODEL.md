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
| T1 | Unauthenticated access to internal apps | Every route request needs a valid app session (login redirect for GET/HEAD, 401 otherwise); authenticated requests still denied until policy exists (M3), except in loopback-only `-dev-skip-policy` mode (D13) | M1–M3 | partial |
| T2 | Login CSRF / session fixation | Random 256-bit `state`/`nonce` + PKCE S256 in a sealed, host-only, per-login cookie (D9); callback requires the cookie for that state, single-use state in Redis before code exchange, and a fresh session ID with any prior session revoked (D12) | M2 | done |
| T3 | Token forgery or substitution | Signature via JWKS with pinned asymmetric algs (no `none`/`HS*`, D8); `iss`, `aud`, `exp`; `nonce` bound to the pre-auth cookie; `iat` within the login window; `azp`; `sub` required; groups claim type-checked; unverified email dropped (D12) | M2 | done |
| T4 | Open redirect via return URL | Return URL must be a literal `https://` URL on a configured route host and Warden's public port; `\`, whitespace, control chars, userinfo and other schemes rejected; redirect goes to a canonical URL rebuilt from the parsed parts; fuzzed (D11) | M2 | done |
| T5 | Policy bypass via path tricks | Normalize path; forward the normalized path; reject ambiguous encodings | M3 | planned |
| T6 | Identity header spoofing | Strip all identity headers; signed short-lived assertion | M4 | planned |
| T7 | Bypassing Warden to reach upstreams directly | mTLS to upstreams; upstreams on private network | M4, M7 | planned |
| T8 | Access persists after user removal | Server-side sessions, revocation, periodic group refresh | M5 | planned |
| T9 | Stolen session cookie | Opaque 256-bit IDs, only hashes in Redis; idle + absolute TTL checked on every read; app sessions bound to their host and revoked with the main session (D10). HttpOnly/Secure/SameSite host-only cookies; revocation API in M5 | M2, M5 | partial |
| T10 | Weak authentication on sensitive paths | Step-up MFA with recency check | M7 | planned |
| T11 | Brute force / abuse of auth endpoints | Rate limiting | M7 | planned |
| T12 | Secrets leaking via logs | Never log tokens/cookies/codes; hashed identifiers only; client secret held in a self-redacting `config.Secret` and never echoed in config errors | all | partial (config: done) |
| T13 | Admin dashboard CSRF / XSS | CSRF tokens, strict CSP, no inline scripts | M5, M6 | planned |
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

## Out of scope (explicitly not defended)

- Compromised IdP: an attacker controlling Keycloak can mint any identity.
- Compromised user device with a valid session (partially mitigated by short TTLs and revocation; device posture is a stretch goal).
- Compromised Warden host: it holds the signing key and session store access. Warden is a high-value target and a single point of failure.
- Vulnerabilities inside upstream apps once a user is legitimately authorized.
