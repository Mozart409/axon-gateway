# Axon Gateway threat model

This document says what axon-gateway protects, who might attack it, and what
stops them. It describes database mode (multi-user, RBAC). Standalone mode with
a TOML file has one shared token and no users, so most of this does not apply.

## 1. Scope and assets

The gateway gives MCP clients access to backend tools. What needs protecting:

- **Access to backends.** Who may call which tool, as which identity.
- **Backend and provider secrets.** API keys and upstream OAuth tokens. They are
  sealed in Postgres.
- **PATs, service tokens and sessions.** They grant the access of their owner.
- **The audit trail.** It must stay complete and unaltered.
- **The KEK.** The key that wraps every secret. Whoever has it and the database
  has every secret.

## 2. Trust boundaries

| Boundary | Trust |
| --- | --- |
| Browser to gateway (UI session) | Authenticated by a session cookie. Cross-site requests are not trusted. |
| MCP client to gateway | Authenticated by PAT, service token, OIDC JWT or OAuth access token. The client is untrusted until it proves one. |
| Gateway to admin-configured backends | Trusted. An admin chose them. |
| Gateway to personal backends and their upstream OAuth servers | Untrusted. Users choose them. |
| IdP claims to RBAC | Groups from the IdP and SCIM drive roles. The IdP is trusted. |
| Operator to env and KEK | Trusted. The operator holds the KEK and the database URL. |

## 3. Actors, threats and mitigations

Section 4 describes each mitigation in detail.

### Unauthenticated network attacker

- Guesses or brute-forces tokens: tokens are 32 random bytes, stored as hashes,
  and token endpoints are rate limited.
- Floods login, callback, OAuth or break-glass endpoints: DB-backed rate limits.
- Reads operational data: in database mode the status pages need
  `gateway.admin`. `/metrics`, `/healthz`, `/readyz` and `/build` stay open and
  belong on an internal network.

### Malicious user

- Reaches tools they have no role for: RBAC is checked on every call.
- Uses another user's browser session (CSRF, clickjacking, XSS): CSRF tokens,
  Sec-Fetch-Site/Origin checks, strict CSP, `frame-ancestors 'none'`.
- Makes the gateway fetch internal URLs through a personal backend (SSRF):
  egress policy.
- Runs a local process through a stdio backend: stdio is admin only and off by
  default.
- Reads other users' personal backends or tokens: rows are scoped by owner, and
  sealed values are bound to their row.

### Compromised PAT

- The attacker has the access of the PAT owner, no more. PATs are scoped.
- Only the hash is stored, so a database leak does not reveal PATs.
- The owner or an admin revokes it. Use is rate limited per token and audited.

### Hostile personal backend (and its OAuth server)

- Probes the internal network via redirects or DNS tricks: no redirects, no
  proxy, DNS resolved once and pinned, private and metadata ranges denied.
- Returns hostile tool output or metadata: the gateway treats it as data. The
  backend only gets the credentials the user gave it.
- Cannot reach other users' secrets: they are never sent to it.

### Compromised IdP claim

- Users are keyed by (issuer, subject). Email is never used to link or take
  over an account.
- A forged `groups` claim would grant roles, so the JWT signature, `iss`, `aud`,
  `azp`, time claims and `nonce` are all checked.
- Remaining risk: a fully compromised IdP is out of scope (section 5).

### Insider admin

- An admin can change backends, roles and config, and can point backends at any
  address.
- Their changes are written to the audit log in the same transaction, and the
  log is append-only.
- Reading tool arguments needs `audit.read_sensitive`, and that read is audited.
- Remaining risk: section 5.

## 4. Mitigations

### Sessions

- Cookies use the `__Host-` prefix, `Secure`, `HttpOnly` and `SameSite=Lax`.
- Session tokens are stored hashed.
- A new login deletes the previous session. Logout deletes the row. Disabling a
  user ends their sessions.
- The OIDC `id_token` kept for logout is sealed with the KEK.

### CSRF

- Every state-changing UI route and cookie-authenticated API route checks a
  per-session CSRF token in constant time.
- Requests with a cross-site `Sec-Fetch-Site` or a foreign `Origin` are rejected.
- There is no CORS layer.

### Headers

- Strict CSP on HTML: `script-src 'self'`, no inline script, no style
  attributes, `frame-ancestors 'none'`, `base-uri 'none'`. htmx is served by the
  gateway itself.
- `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store` on HTML.
- HSTS when the base URL is https.
- `form-action` is deliberately not set. Logout and OAuth consent redirect to
  other origins, and a `form-action` rule would block them.

### Rate limits

- Limits are DB-backed, so replicas share them. They fail open on database
  errors.
- Covered: OAuth register, authorize, token and revoke; OIDC login and callback;
  break-glass; the OAuth consent decision; upstream OAuth connect; PAT and
  service-token creation; SCIM; MCP requests per token and user.
- Client IP is the rightmost `X-Forwarded-For` entry, and only when the peer is
  loopback or private. One trusted proxy is assumed.

### Logs

- Request spans record the path only, never the query string.
- Tool and prompt arguments are never logged. Only names are, and keys at debug
  level.
- URLs in logs lose userinfo and query.
- Config types that hold secrets have a redacting `Debug`.

### Audit

- Admin and SCIM mutations, OAuth grant revocation, catalog changes and config
  import write `audit_log` rows in the same transaction as the change. SCIM
  actions use the actor `scim:<provider>`.
- `audit_log` is append-only by a trigger. DELETE always raises. The one
  allowed UPDATE sets `actor_user_id` to null, which the foreign key's
  `on delete set null` does when a user is deleted. All other columns must stay
  unchanged. When the app does not own its tables, the operator can also
  `REVOKE UPDATE, DELETE` from the app role.
- Tool-call arguments: none are captured for read-only tools. For other tools
  they are redacted with a key denylist and value patterns (bearer and basic
  credentials, JWTs, common token prefixes, PEM keys).
- Reading arguments needs `audit.read_sensitive`, and the read is audited.
- Enabling `full` capture is an organisational decision. It touches GDPR purpose
  limitation, and in Germany works council co-determination under section 87(1)
  no. 6 BetrVG. The software does not enforce this.

### SSRF

- Personal backends and their OAuth endpoints go through an egress policy.
- Default deny: loopback, private, CGNAT, link-local and metadata, ULA,
  multicast and reserved ranges.
- IPv4-mapped, NAT64, 6to4 and Teredo addresses are checked by their embedded
  IPv4 address.
- Host allow rules never open loopback, unspecified or link-local addresses.
- DNS is resolved once and pinned for the connection. No redirects, no proxy.
- Admin-configured backends, catalog entries and OIDC providers are trusted and
  not checked. An admin can point them anywhere.

### stdio backends

- Only admins can create them, and only when `AXON_ALLOW_STDIO=true`.
- Personal backends are HTTP only.

### Secrets at rest

- AES-256-GCM with one DEK per secret. The KEK wraps the DEKs. The AAD binds a
  sealed value to its row.
- The KEK comes from the environment or a file. It never enters the database.
- `admin rewrap-secrets` covers every sealed column, so the KEK can be rotated.

### Tokens

- PATs, session tokens, OAuth codes, refresh tokens and SCIM tokens are 32
  random bytes. Only their SHA-256 hash is stored.
- Comparisons run in constant time.

### OIDC

- `iss`, `aud`, `azp`, `exp`, `iat` and `nbf` are validated (60 s leeway), and
  so is `nonce`, in constant time.
- Algorithms are pinned to an asymmetric allowlist. `none` and HS* are refused.
- The JWKS is refetched on an unknown `kid`, at most once per 60 s.
- Users are keyed by (issuer, subject). Email is never used for linking.
- PKCE is used, and the state is stored hashed.

### Status endpoints

- In database mode `/status`, `/status/detailed` and `/status/toolsets` need
  `gateway.admin`.
- `/metrics`, `/healthz`, `/readyz` and `/build` stay open. Keep them on an
  internal network.

### Supply chain

- `deny.toml` sets a licence allowlist, crates.io as the only source, no unknown
  git or registries, no wildcard versions, yanked crates denied and unmaintained
  advisories flagged.
- `cargo deny` and `cargo audit` run in `just axon-ci` and in CI.
- htmx is vendored at a pinned version.

## 5. Residual risks and out of scope

- **Insider admin.** An admin can read the audit log, enable `full` capture and
  point backends anywhere. Only the append-only audit log and the auditing of
  break-glass use limit this.
- **Rate limits fail open.** A database error lets requests through.
- **One trusted proxy.** The client IP logic assumes exactly one proxy in front.
  Other setups can let a client pick its own IP.
- **Compromised IdP.** Groups drive RBAC, so an IdP that lies can grant any
  role.
- **KEK compromise.** The KEK plus a database copy reveals every secret.
- **NAT64 of public addresses.** `64:ff9b::/96` is allowed, because it maps
  public addresses. An embedded private IPv4 address is still denied.
- **Plaintext short-lived values.** CSRF and PKCE values sit in plaintext in
  short-lived rows.
- **Host and network security.** Container, database, TLS termination and
  network segmentation are the operator's job.
