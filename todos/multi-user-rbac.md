# Multi-user, RBAC and Production Readiness Plan

Design and implementation plan for evolving axon-gateway from a single-tenant
homelab MCP gateway into a multi-user, production-grade gateway that can run in
a team or company setting as well as in a homelab. Phases are shippable
increments; each ends green (`cargo clippy --all-targets --locked -- -D warnings`,
`cargo test`) with an exit criterion.

## 1. Summary, goals, non-goals

Today one shared secret (plus a few named `[[tokens]]`) decides who may use the
gateway, the dashboard is open to anyone who can reach it, and nothing records
who did what. The target is a gateway where:

- people sign in with their organisation's OIDC provider (any provider, several
  at once),
- what a person (or an agent acting for them) may do is decided by roles, groups
  and tool grants, and is explainable,
- people can add their own MCP servers and bring their own credentials to shared
  ones, without being able to harm the gateway host or the network behind it,
- every action is attributable (audit log, traces, metrics),
- it still starts from one TOML file with no database for basic use.

Goals:

- Generic OIDC login for the dashboard; no provider-specific code paths.
- Per-principal tool visibility and enforcement (users, service accounts, PATs).
- Declarative config stays authoritative; the database layers user-created
  objects on top.
- Spec-compliant MCP transport (notifications, progress, cancellation).
- OpenTelemetry, Prometheus, audit log, health endpoints suitable for operations.
- Safe by default: SSRF guard, stdio admin-only, encrypted secrets, hashed tokens.

Non-goals:

- Multi-org tenancy. One deployment is one tenant; groups are the unit of
  separation. Run a second deployment for a second tenant.
- Building an identity provider. Axon consumes OIDC; it does not store passwords
  or manage MFA.

## 2. Current state and gaps

- `src/auth.rs` `AuthManager`: one shared `gateway.auth_token` plus config
  `[[tokens]]` (`TokenConfig`: `allowed_tools` globs, `allowed_backends`,
  `rate_limit_per_minute`), constant-time compare, in-memory rate limit map.
  Tokens are not tied to a person.
- The `/ui` dashboard is unauthenticated (homelab LAN assumption). Only
  `POST /ui/actions/*` is guarded, by `reject_cross_site_middleware`
  (Sec-Fetch-Site / Origin).
- `/mcp` (`src/server.rs`, `handle_mcp_request`) is a hand-rolled stateless
  JSON-RPC handler: no server-initiated notifications, no progress, no
  cancellation, no sessions. `/mcp/sse` (`handle_mcp_sse`) is a stub that only
  emits an `endpoint` event.
- Tool groups (`[[groups]]`, `ToolGroupConfig`, routed at `/mcp/group/{name}`)
  are path-based filters, not an access control concept.
- No per-user state at all: no users, no personal backends, no per-user
  credentials. Backends are global and share one credential.
- Metrics (`/metrics`) have no principal dimension; there are no traces; there
  is no audit log; `/health` is the only health endpoint.
- Size: `server.rs` ~1300 lines, `gateway.rs` ~1370, `backend.rs` ~1360. The
  server module needs splitting before auth work lands on it.

## 3. Decisions

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | Hybrid agent auth: OIDC login, personal access tokens (PATs) carrying the user's RBAC (optionally narrowed), admin-managed service accounts for headless agents, MCP OAuth for interactive clients later | Works with every MCP client today (static bearer) while converging on the spec |
| 2 | Any OIDC provider, several at once (Keycloak, Authentik, Entra ID, Okta, Google, Dex, PocketID) | No vendor lock-in; deployments differ |
| 3 | Postgres via sqlx with migrations | Needed for sessions, audit, grants; multi-replica friendly; already run in the fleet |
| 4 | `config.toml` stays authoritative; config-declared objects are read-only in the UI, DB holds user/admin-created objects | GitOps-friendly, safe recovery, no surprise drift |
| 5 | Production-grade at work: no homelab-only shortcuts | Same binary, same guarantees |
| 6 | Without `[database]` axon behaves exactly as today | GOALS.md: no database required for basic usage |
| 7 | Allow-only grants, union semantics, no deny rules in v1 | Easy to reason about and explain; revisit if needed |
| 8 | `openidconnect` crate, not bare `oauth2` | Discovery, JWKS caching and ID-token validation included (see 5) |
| 9 | PATs stored as SHA-256 of a high-entropy secret | No slow hash needed for 256-bit random secrets |
| 10 | stdio backends admin-only | stdio is code execution on the gateway host |
| 11 | Envelope encryption for stored secrets | KEK rotation without re-encrypting everything |
| 12 | Admin JSON API is the single write path | UI, CLI and tests share one service layer |
| 13 | Keep existing `axon_*` metric names | No breaking rename for existing dashboards |
| 14 | Postgres LISTEN/NOTIFY for replica fan-out | No extra infrastructure |

## 4. Domain model

### Principals

`Principal = User | ServiceAccount`.

- **User**: key is `(issuer, sub)`. Email and display name are informational and
  refreshed at login, never used as identity.
- **ServiceAccount**: created by admins, no login, authenticates only with
  tokens (or, in Phase 7, IdP-issued JWTs). Bound to groups and roles exactly
  like a user.

### Groups

Group `source` is one of:

- `config`: declared in `config.toml`, read-only.
- `idp`: membership derived from a claim value at login. The IdP mapping is
  `(provider, claim value) -> group`, because Entra emits group object IDs, not
  names. Mapping rows live in config or the DB.
- `local`: created in the UI, members added by admins.

Built-in group `authenticated`: every user is a member, so admin-assigned shared
backends reach all users without per-user work.

Membership from IdP claims is refreshed at every login. The claim path is
configurable (`groups`, `roles`, or nested such as `realm_access.roles`).
Entra groups-overage (more than ~200 groups: no groups claim, a link instead):
v1 documents using app roles instead; a Graph lookup is a later item (verify the
exact limit per provider docs).

### Roles and permissions

A role is a named set of permissions. Built-ins:

| Role | Permissions |
| --- | --- |
| `admin` | all |
| `backend-admin` | `backends.view`, `backends.manage`, `catalog.manage` |
| `auditor` | `audit.read`, `backends.view` (read-only views) |
| `member` | `personal_backends.create`, use granted tools, manage own MCPs and tokens |

Custom roles come in Phase 7.

| Permission | Allows |
| --- | --- |
| `gateway.admin` | gateway settings, reload, break-glass operations |
| `backends.view` | see shared backends and their status |
| `backends.manage` | create/edit/disable shared backends |
| `catalog.manage` | publish/edit catalog templates |
| `personal_backends.create` | add personal MCP servers |
| `users.manage` | disable users, assign roles, see users |
| `groups.manage` | groups, IdP mappings, memberships, grants |
| `roles.manage` | custom roles |
| `service_accounts.manage` | service accounts and their tokens |
| `tokens.manage_all` | list/revoke any user's tokens |
| `audit.read` | audit log and usage views |

Role bindings: `role -> group | principal`. The bootstrap admin comes from an
`admin_groups` mapping in config (Phase 1).

### Tool grants

`grant = (group | principal) -> backend` with:

- `include` / `exclude` tool globs (same glob semantics as today's
  `allowed_tools`),
- optional `read_only = true`: only tools whose MCP annotations carry
  `readOnlyHint: true` pass. Tools without the annotation are treated as not
  read-only.

### Evaluation

- Effective policy = union of grants over the principal's groups plus direct
  grants. Allow-only: no deny rules in v1, so adding a grant can never remove
  access and the explain view stays a simple list. Revisit if workplaces need
  carve-outs.
- A PAT intersects the owner's effective policy with its own scope (backends,
  tool globs). A PAT can never exceed its owner; if the owner loses access, the
  token loses it at once (policy is evaluated per request, not baked into the
  token).
- Multi-user mode is deny-by-default: no grant, no tool.
- Tool groups (`/mcp/group/{name}`) are a further filter applied after policy.

## 5. Authentication

### Dashboard (OIDC)

- Authorization Code + PKCE + `state` + `nonce` using the `openidconnect` crate
  (discovery, JWKS caching, ID-token validation). Note: lanternd and countdown-rs
  in this monorepo use bare `oauth2`; axon differs on purpose, because it needs
  ID-token validation across arbitrary providers.
- Config, a list so several providers work together:

```toml
[database]
url_env = "AXON_DATABASE_URL"

[[auth.oidc]]
id = "corp"                       # stable id, part of the user key
display_name = "Company SSO"
issuer = "https://idp.example.com/realms/main"
client_id = "axon"
client_secret_env = "AXON_OIDC_CORP_SECRET"
scopes = ["openid", "profile", "email", "groups"]
groups_claim = "groups"           # or "roles", "realm_access.roles"
allowed_email_domains = []        # optional
admin_groups = ["axon-admins"]    # bootstrap admin mapping

[[auth.oidc.group_map]]           # claim value -> group
claim_value = "a1b2c3d4-..."
group = "engineering"
```

- Server-side sessions in Postgres. Cookie `__Host-axon_session`, `Secure`,
  `HttpOnly`, `SameSite=Lax`, rotated on login, idle and absolute timeouts,
  RP-initiated logout.
- CSRF token on all forms, in addition to the existing Sec-Fetch-Site/Origin
  middleware.

### Agents, phase A: PATs and service accounts

- Format `axon_pat_<public id>_<secret>`. The prefix enables secret scanning.
  Store SHA-256 of the secret; look up by public id, then constant-time compare.
- Expiry is required; admin-configurable maximum lifetime. Track `last_used_at`
  and last IP. Optional scope narrowing (backends, tool globs). Revoke anytime.
- Service accounts are owned by admins and bound to groups/roles like users.

Deprovisioning: a PAT outlives the IdP session, so:

- maximum lifetime,
- PATs are suspended when the owner has not logged in for N days (configurable)
  or was disabled by an admin,
- SCIM 2.0 provisioning in a later phase (Phase 7).

### Agents, phase B (optional, enterprise): resource-server mode

Accept IdP-issued JWT access tokens (validate issuer, audience, `exp` via JWKS)
so client-credentials service principals from Entra, Keycloak etc. work without
PATs. Maps the token's subject/claims to a service account.

### Agents, phase C: MCP authorization

- Serve `/.well-known/oauth-protected-resource` (RFC 9728) and send
  `WWW-Authenticate` with `resource_metadata` on 401.
- Axon acts as an OAuth 2.1 authorization server for MCP clients: Dynamic Client
  Registration (RFC 7591), PKCE, short-lived access tokens plus refresh. The
  actual login is delegated to the configured IdP, because many IdPs do not
  offer DCR (PocketID: verify).

### Legacy and break-glass

- `gateway.auth_token` and `[[tokens]]` keep working. In multi-user mode they
  map to config-declared service accounts. The shared token becomes opt-in
  break-glass and logs a deprecation warning.
- IdP down: CLI subcommand `axon-gateway admin ...` talks to the database
  directly and creates a short-lived admin token.

### Standalone mode

Without `[database]` axon behaves exactly as today. Multi-user features require
Postgres and at least one configured OIDC provider. The unauthenticated UI is
allowed only in standalone mode and logs a warning at startup.

## 6. Backends and personal MCPs

### Scopes

- **shared**: declared in config or created by an admin.
- **personal**: owned by a user, visible only to them. Sharing a personal backend
  with groups the owner belongs to is a possible later feature (open question).

### Credential modes (per backend)

| Mode | Meaning |
| --- | --- |
| `shared` | One credential for everyone (today's behaviour) |
| `per_user` | Each user stores their own credential; one connection per user |
| `passthrough` | Forward the user's identity via RFC 8693 token exchange (Phase 7) |

Catalog: admins publish templates (URL, transport, required credential fields)
that users instantiate with their own credentials. This is the main workplace
use case, for example a SaaS MCP server where every employee has their own
account.

Upstream OAuth (Phase 7): many remote MCP servers require OAuth 2.1. Axon acts
as OAuth client per user, stores refresh tokens encrypted, and the UI shows a
"Connect" button.

### Personal backend policy (admin-configurable, secure defaults)

- Transports for non-admins: streamable HTTP/SSE only. stdio is admin-only
  because it executes code on the gateway host.
- Egress policy: allow/deny lists of host patterns and CIDRs. Default deny:
  loopback, link-local, RFC1918 and ULA ranges, cloud metadata
  (`169.254.169.254`). This matters in the homelab deployment too, where shared
  backends are bound to `127.0.0.1` on the gateway host: a personal backend must
  not be able to reach them.
- Resolve DNS, check the resolved IP against the policy, and pin that IP for the
  connection (DNS rebinding). No redirects, or re-check every hop.
- Per-user quotas: maximum backends, maximum tool-call rate.

### Secrets at rest

Envelope encryption: per-row data key, AES-256-GCM via a vetted crate (verify
choice), wrapped by a key-encryption key (KEK) read from `AXON_KEK_FILE`
(or env). The KEK id is stored with each row so the KEK can rotate. KMS/Vault
KEK providers later.

### Namespacing

Shared tools keep `<backend>_<tool>`. Personal backends get a user-chosen prefix
that must not collide with any shared backend name or the user's other prefixes;
a reserved-name list applies.

## 7. Architecture changes

Module layout:

```
src/server/{mcp.rs, api.rs, auth.rs, ui/...}   # split of server.rs
src/store/        # sqlx Postgres repositories
migrations/       # sqlx migrations
src/authz/        # policy engine: pure, unit-testable
src/oidc/         # providers, discovery, login flow, claim mapping
src/crypto/       # envelope encryption, token hashing
```

- **Policy engine** replaces AuthManager's ad-hoc checks:
  `Authorizer::effective_policy(principal) -> Policy`, cached (moka) by
  principal and policy version; invalidated on grant/group/role changes.
- **Registry becomes multi-scope**: instances keyed by
  `(backend id, credential owner)`. Shared instances as today; per-user
  instances spawn lazily on first use and stop after an idle timeout; caps on
  concurrent per-user actors.
- **tools/list per principal**: shared registry view plus personal backends,
  filtered by policy. Tool groups are a further filter, never a bypass.
- **MCP transport**: replace the hand-rolled JSON-RPC handler and the SSE stub
  with spec-compliant Streamable HTTP (rmcp server side), so
  `notifications/tools/list_changed` (on grant or backend change), progress and
  cancellation reach clients.
- **Horizontal scaling**: sessions are stateless or sticky; durable state lives
  in Postgres; config/grant changes fan out across replicas via LISTEN/NOTIFY.
  Rate limits stay per-instance in v1 (documented), shared later.
- **Admin JSON API** `/api/v1/...` is the single write path. The HTMX UI and a
  future CLI call the same service layer. Writes to config-managed objects
  return 409.
- **UI pages**: Login (provider picker); My tools (effective tools and why:
  which group/grant), My MCP servers, My tokens, Catalog. Admin: Shared
  backends, Catalog, Users, Groups and IdP mappings, Roles, Service accounts,
  Audit log, Gateway settings. A "why can/can't I use this tool" explain view is
  valuable for support.

## 8. Observability

- **OpenTelemetry** over OTLP: traces, plus metrics and logs as optional
  exports, via tracing-opentelemetry. hofvarpnir in this monorepo pins
  opentelemetry 0.33 and tracing-opentelemetry 0.34; keep versions aligned.
  Config: standard `OTEL_*` env vars plus a `[telemetry]` table.
- **Spans**: HTTP request -> MCP method -> authz decision -> backend call.
  Attributes: principal type, principal id (hashing optional), auth method
  (`pat`/`session`/`jwt`/`oauth`), backend, tool, outcome. Propagate W3C
  `traceparent` to HTTP backends and into MCP `_meta` (`traceparent`) per the
  MCP trace-context proposal (verify status).
- **Metrics**: keep existing `axon_*` names. Add `axon_authn_total{method,result}`,
  `axon_authz_denied_total{reason}`, `axon_active_sessions`,
  `axon_user_backends{state}`, `axon_tokens_active`, principal-type labels,
  database pool metrics, OIDC provider latency/errors. No user id on Prometheus
  labels by default (cardinality); opt-in, and prefer trace exemplars.
- **Audit log**: append-only Postgres table: who, principal, auth method, token
  id, action, target, tool, outcome, duration, trace id, client IP, user agent.
  Covers admin actions and tool calls. Tool arguments are not stored by default;
  configurable `none | hash | redacted` (key denylist) `| full`. Retention job.
  Also emitted as a structured log event (`target = "axon::audit"`) for
  Loki/any SIEM. UI: audit view with filters and a per-user usage page.
- **Health**: `/livez`; `/readyz` (DB reachable, migrations applied, config
  backends evaluated); `/health` stays as alias.
- **Ship in repo** under `example/observability/`: Grafana dashboard JSON and
  Prometheus alert rules (backend down, error rate, auth failure spike, DB down,
  OIDC provider unreachable).

## 9. Security checklist

- [ ] Threat model written down (malicious user, compromised PAT, hostile
      personal backend, compromised IdP claim, insider admin).
- [ ] Rate-limit login, callback and token-mint endpoints.
- [ ] No secrets, tokens or tool arguments in logs or spans.
- [ ] CSP header on the UI (no inline script beyond what is hashed/nonced).
- [ ] Cookie flags (`__Host-`, Secure, HttpOnly, SameSite=Lax); session rotation.
- [ ] CSRF tokens plus Sec-Fetch-Site/Origin check.
- [ ] SSRF guard for personal backends and upstream OAuth endpoints.
- [ ] stdio backends admin-only; arguments of stdio backends not user-editable.
- [ ] Secrets encrypted at rest; KEK never in the database.
- [ ] PATs hashed; constant-time comparisons everywhere tokens are checked.
- [ ] Admin actions audited; audit table append-only (no UPDATE/DELETE grant to
      the app role where practical).
- [ ] OIDC: validate `iss`, `aud`, `exp`, `nonce`; pin allowed algorithms.
- [ ] Dependency policy via `deny.toml`; new crates reviewed against it.

## 10. Testing

- Hermetic mock OIDC issuer in `tests/support/`: axum app with a test RSA key
  serving discovery, JWKS and token endpoint.
- Postgres test database via new monorepo recipes `axon-db-up`, `axon-db-down`
  and `axon-with-db <recipes>` on host port 5437 (follows the "Test databases"
  convention in the root AGENTS.md; taken: lanternd 5433, internal-dashboard
  5434, hofvarpnir 5435, countdown 5436). `axon-ci` runs the DB tests through
  `axon-with-db`.
- Policy engine: table and property tests (union, PAT intersection, glob edge
  cases, `read_only`, deny-by-default).
- End to end: login -> mint PAT -> `tools/list` filtered -> call allowed and
  denied.
- SSRF guard tests: loopback, RFC1918, link-local, metadata IP, DNS rebinding
  (resolver stub), redirects.
- `example/` compose with Keycloak or Dex for manual testing.

## 11. Phased plan

### Phase 0 - Groundwork (no behaviour change)

- [ ] Split `server.rs` into `server/mcp.rs`, `server/ui/`, `server/api.rs`,
      `server/auth.rs`.
- [ ] Add sqlx, `migrations/`, `[database]` config, `store/` layer.
- [ ] Add `axon-db-up`, `axon-db-down`, `axon-with-db` recipes (port 5437) and
      wire `axon-ci`.
- [ ] Extract `authz/` policy engine from `AuthManager` with current semantics
      and tests.
- [ ] OTel tracing foundation (`[telemetry]`, OTLP exporter, request spans).
- [ ] `/livez`, `/readyz`; keep `/health`.
- Exit: all existing tests pass unchanged; no `[database]` means identical
  behaviour; traces visible in a local collector.

### Phase 1 - OIDC login for the dashboard

- [ ] `oidc/` with generic multi-provider discovery, PKCE, state, nonce.
- [ ] `users` and `sessions` tables; cookie handling; timeouts; logout.
- [ ] Protect `/ui` and `/ui/actions/*` in multi-user mode; login page with
      provider picker.
- [ ] Bootstrap admin via `admin_groups` mapping in config.
- [ ] CSRF tokens on forms.
- Exit: login works against the mock issuer and one real IdP; UI inaccessible
  without a session; standalone mode unchanged.

### Phase 2 - RBAC

- [ ] Tables: groups, memberships, roles, role bindings, grants.
- [ ] Config layer merged read-only (`source = config`); 409 on write.
- [ ] IdP group mapping with configurable claim path.
- [ ] Per-principal `tools/list` and `tools/call` enforcement.
- [ ] Explain view ("why can/can't I use this tool").
- [ ] Admin UI for groups and grants; `/api/v1` write path.
- [ ] Audit log for admin actions.
- Exit: two users with different groups see and can call different tools.

### Phase 3 - Agent tokens

- [ ] PATs (`axon_pat_...`), expiry, max lifetime, scope narrowing, revoke,
      last-used tracking.
- [ ] Service accounts (admin-managed).
- [ ] Legacy `auth_token` / `[[tokens]]` mapped to config service accounts;
      deprecation warning.
- [ ] Deprovisioning rules (inactivity, disabled user).
- [ ] Tool-call audit.
- [ ] Break-glass CLI `axon-gateway admin ...`.
- Exit: an agent authenticates with a PAT and is limited to its owner's policy
  intersected with its scope.

### Phase 4 - Spec-compliant MCP transport

- [ ] Streamable HTTP server side via rmcp.
- [ ] `notifications/tools/list_changed` on grant/backend changes.
- [ ] Progress and cancellation passthrough.
- [ ] LISTEN/NOTIFY fan-out; multi-replica notes in the docs.
- [ ] Remove the SSE stub.
- Exit: a spec-conformant client receives list_changed after a grant change;
  two replicas stay consistent.

### Phase 5 - Personal MCP servers and catalog

- [ ] Personal backends with namespacing rules.
- [ ] Egress policy and SSRF guard; stdio admin-only.
- [ ] `crypto/` envelope encryption, `AXON_KEK_FILE`, KEK rotation.
- [ ] Per-user backend actors with idle stop and caps.
- [ ] Catalog and `per_user` credentials.
- [ ] Per-user quotas.
- Exit: a user adds a personal HTTP MCP and a catalog backend with their own
  credential; loopback and metadata targets are refused.

### Phase 6 - Observability completion

- [ ] New metrics (section 8), pool and OIDC metrics.
- [ ] Audit UI, retention job, per-user usage page.
- [ ] Grafana dashboard and alert rules in `example/observability/`.
- [ ] `traceparent` propagation to backends and MCP `_meta`.
- Exit: dashboards and alerts load against a running instance.

### Phase 7 - Enterprise auth

- [ ] Resource-server JWT mode.
- [ ] MCP OAuth authorization server (RFC 9728, RFC 7591, PKCE, refresh).
- [ ] Upstream OAuth for backends ("Connect" button).
- [ ] Token-exchange passthrough (RFC 8693).
- [ ] SCIM 2.0.
- [ ] Custom roles.
- [ ] Entra groups-overage lookup (if the work IdP needs it).

### Homelab rollout (the user does all deploys)

- [ ] Create a PocketID OIDC client for axon (redirect URI under the
      gateway's `base_url`, `https://axon.homelab.internal`).
- [ ] agenix secrets: OIDC client secret and KEK.
- [ ] Postgres database and role on the database host.
- [ ] Update the NixOS module in `infra/hosts/mcp_vm/axon-gateway/default.nix`
      (`[database]`, `[[auth.oidc]]`, env files).
- [ ] Migrate current agents' bearer token to service-account PATs; then turn
      the shared token into break-glass.

### Versioning and docs

- Phase 0-1 -> 0.5; Phase 2-3 -> 0.6; 1.0 after Phase 5 with a documented
  upgrade path.
- [ ] Update GOALS.md, README and AGENTS.md as each phase lands.

## 12. Open questions

- Work deployment target: Kubernetes/Helm chart or VM/container, and replica
  count (drives the rate-limit and session design).
- Which IdP at work; if Entra, groups-overage work moves up.
- May personal backends be shared with groups?
- Tool-argument audit default for compliance (`none`, `hash`, `redacted`, `full`).
- Per-user Prometheus labels: allow at all?
- Do `/mcp/group/{name}` tool groups stay, or fold into grants?
- Minimum supported MCP protocol version.
