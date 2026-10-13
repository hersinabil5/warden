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
| T1 | Unauthenticated access to internal apps | Default-deny routing (unknown host 404, routed host 403 until login exists); login required. Temporary loopback-only dev bypass (D6) | M1–M3 | partial |
| T2 | Login CSRF / session fixation | Random 256-bit `state`/`nonce` + PKCE S256 verifier in a sealed, host-only, per-login pre-auth cookie (D9); single-use check at callback and new session ID on login pending | M2 | partial |
| T3 | Token forgery or substitution | Full ID token validation: signature via JWKS with pinned asymmetric algs (no `none`/`HS*`, D8), `iss`, `aud`, `exp` done; `nonce`/`iat` at callback | M2 | partial |
| T4 | Open redirect via return URL | Return URL must match a configured route host | M2 | planned |
| T5 | Policy bypass via path tricks | Normalize path; forward the normalized path; reject ambiguous encodings | M3 | planned |
| T6 | Identity header spoofing | Strip all identity headers; signed short-lived assertion | M4 | planned |
| T7 | Bypassing Warden to reach upstreams directly | mTLS to upstreams; upstreams on private network | M4, M7 | planned |
| T8 | Access persists after user removal | Server-side sessions, revocation, periodic group refresh | M5 | planned |
| T9 | Stolen session cookie | HttpOnly/Secure/SameSite, host-only cookies, idle + absolute TTL, revocation | M2, M5 | planned |
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

## Out of scope (explicitly not defended)

- Compromised IdP: an attacker controlling Keycloak can mint any identity.
- Compromised user device with a valid session (partially mitigated by short TTLs and revocation; device posture is a stretch goal).
- Compromised Warden host: it holds the signing key and session store access. Warden is a high-value target and a single point of failure.
- Vulnerabilities inside upstream apps once a user is legitimately authorized.
