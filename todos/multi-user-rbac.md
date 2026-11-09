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
- Good defaults over config options: a knob is added only when a real
  deployment needs it.

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
  are path-based filters, not an access control concept. They become toolsets
  (`[[toolsets]]`, `/mcp/toolset/{name}`, section 4) because "groups" now means
  RBAC groups.
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
| 8 | `oauth2` + `jsonwebtoken` (aws-lc), the rust/lanternd stack, not `openidconnect` | `openidconnect` pulls the `rsa` crate (RUSTSEC-2023-0071); discovery, JWKS caching and ID-token checks are ported from lanternd (see 5) |
| 9 | PATs stored as SHA-256 of a high-entropy secret | No slow hash needed for 256-bit random secrets |
| 10 | stdio backends admin-only | stdio is code execution on the gateway host |
| 11 | Envelope encryption for stored secrets | KEK rotation without re-encrypting everything |
| 12 | Admin JSON API is the single write path | UI, CLI and tests share one service layer |
| 13 | Keep existing `axon_*` metric names | No breaking rename for existing dashboards |
| 14 | Postgres LISTEN/NOTIFY for replica fan-out | No extra infrastructure |
| 15 | Two layers: grants (security, admin-only) and views (convenience, can only narrow) | A user can tidy their tool list without ever touching what they are allowed to do |
| 16 | Users are opted in to every backend granted to their groups and may opt out per backend or tool; an opt-out is not a deny. Grants carry a `mandatory` flag (default false) that blocks opt-out | Less noise for users, compliance tools stay on |
| 17 | Personal MCP servers are never shared with groups; only admins create shared backends and grant them to IdP-mapped groups | Sharing is an admin decision with an audit trail |
| 18 | `[[groups]]` becomes `[[toolsets]]`, `/mcp/group/{name}` becomes `/mcp/toolset/{name}`; old names stay as deprecated aliases for one minor release | "groups" now means RBAC groups; toolsets are view layer, applied after grants |
| 19 | Audit metadata is always recorded; arguments go to a separate `audit_arguments` table with shorter retention (default 30 days, metadata 1 year) | Arguments are the sensitive part and need their own lifetime |
| 20 | Reading arguments needs `audit.read_sensitive` (not part of `auditor`); every read is audited | Separation of duties |
| 21 | Default argument capture follows MCP tool annotations: `readOnlyHint: true` none, otherwise redacted; admins override per backend and tool glob | Safe default, evidence where it matters |
| 22 | Work deployment is Kubernetes with 3 replicas: the 2026-07-28 path is stateless, ingress hashes on `Mcp-Session-Id` only for older clients, rate limits live in Postgres, singleton jobs run under an advisory lock | Pod-local sessions for old clients only, shared limits (see 7) |
| 23 | The work IdP is Entra ID through the generic OIDC path; app roles carry the groups | No provider-specific code, no groups-overage (see 5) |
| 24 | Good defaults over config options; a knob is added only when a real deployment needs it | Fewer settings to document, test and get wrong |
| 25 | stdio backends only when enabled in config: `[gateway] allow_stdio = true` (default `false`); axon detects nothing about its environment. On Kubernetes the Helm chart leaves it off; stdio-only servers run as their own Deployment behind a stdio-to-HTTP bridge and are added as HTTP backends | stdio is code execution on the host or pod; explicit config, no magic. Breaking for standalone users with stdio backends: document in the upgrade notes |
| 26 | Prometheus gets one per-user counter, `axon_user_tool_calls_total{user, backend, outcome}`, with the internal user UUID and no option; no `tool` label on it, no user label on histograms; per-user latency comes from traces | Cardinality: 300 users x 200 tools x ~12 buckets is about 720k series |
| 27 | MCP versions: clients 2025-06-18, 2025-11-25, 2026-07-28; backends every version rmcp knows; stateless-first around 2026-07-28 | See "Protocol versions" in 7 |
| 28 | Rate limits stay in Postgres as shared counters for now | No extra infrastructure; revisit if they show up in database load (see 12) |
| 29 | One shared instance per backend with a shared credential; per-user instances only for `per_user` and personal backends. Every instance (shared, per-user, personal) disconnects after 5 minutes idle by default; `[gateway] idle_timeout_secs` changes the default and a backend's `idle_timeout_secs` overrides it (`0` = always connected) | Scale to zero when nobody uses a backend; per-user connections would only multiply connections (see "Backend instances" in 7) |

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
  names (unless app roles are used, see the Entra recipe in section 5). Mapping
  rows live in config or the DB.
- `local`: created in the UI, members added by admins.

Built-in group `authenticated`: every user is a member, so admin-assigned shared
backends reach all users without per-user work.

Membership from IdP claims is refreshed at every login. The claim path is
configurable (`groups`, `roles`, or nested such as `realm_access.roles`).
Entra groups-overage (more than ~200 groups: no groups claim, a link instead):
the answer is app roles, see the Entra recipe in section 5; a Graph lookup stays
a later fallback (verify the exact limit per provider docs).

### Roles and permissions

A role is a named set of permissions. Built-ins:

| Role | Permissions |
| --- | --- |
| `admin` | all |
| `backend-admin` | `backends.view`, `backends.manage`, `catalog.manage` |
| `auditor` | `audit.read`, `backends.view` (read-only views; not `audit.read_sensitive`) |
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
| `audit.read` | audit log and usage views (metadata only) |
| `audit.read_sensitive` | read recorded tool arguments; `admin` has it, `auditor` does not by default; every read is itself audited |

Role bindings: `role -> group | principal`. The bootstrap admin comes from an
`admin_groups` mapping in config (Phase 1).

### Tool grants

`grant = (group | principal) -> backend` with:

- `include` / `exclude` tool globs (same glob semantics as today's
  `allowed_tools`),
- optional `read_only = true`: only tools whose MCP annotations carry
  `readOnlyHint: true` pass. Tools without the annotation are treated as not
  read-only.
- optional `mandatory = true` (default `false`): users cannot opt out of it
  (example: Hindsight memory, a compliance tool).

### Grants vs views

Two layers with different jobs:

- **Grants layer = security.** What a principal is allowed to call. Only admins
  change it.
- **View layer = convenience.** What appears in a principal's `tools/list`. It
  can only narrow, never widen. It consists of per-user opt-outs and toolsets.

Rules:

- Users are opted in automatically to every backend granted to their groups and
  can opt out per backend and per tool.
- An opt-out is not a deny: the user can opt back in at any time. Opt-outs never
  show up in the explain view as denials; they appear as "hidden by you".
- Grants marked `mandatory` cannot be opted out of.
- A toolset is a named subset of tools (view layer, filters after grants).
  Admins define shared toolsets ("coding", "ops"); users define their own; a PAT
  may pin one. Config `[[toolsets]]` (`ToolGroupConfig` renamed) routes at
  `/mcp/toolset/{name}`; `[[groups]]` and `/mcp/group/{name}` stay as deprecated
  aliases for one minor release. The name changed because "groups" now means RBAC
  groups. The user's opt-outs are their default view.
- Hidden tools are absent from `tools/list`, so a harness never sees them.
- Opt-out, opt-in and toolset changes trigger `notifications/tools/list_changed`.

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
- Final `tools/list` = policy (grants intersected with the PAT scope), minus the
  user's opt-outs (except `mandatory` grants), filtered by the selected toolset.
- `tools/call` enforcement uses the grants layer, and a tool hidden by the view
  is also rejected. The rejection is the standard unknown-tool error, exactly as
  for a tool that does not exist: hidden must look like absent, with no special
  case. It only catches clients that use a stale cached list. Re-enabling a
  hidden tool needs no admin.

## 5. Authentication

### Dashboard (OIDC)

- Authorization Code + PKCE + `state` + `nonce` with `oauth2` and
  `jsonwebtoken` on aws-lc, ported from rust/lanternd: lazy discovery, JWKS
  refetch at most once a minute on an unknown `kid`, asymmetric algorithms
  only, `iss`/`aud`/`azp`/`nonce`/`exp`/`iat`/`nbf` checked with 60 s leeway.
  Not `openidconnect`: it pulls the `rsa` crate (RUSTSEC-2023-0071).
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

### Provider recipes

The mechanism stays generic OIDC; recipes only say what to configure at the IdP.

**Entra ID (work IdP).**

- Define app roles (for example `axon.admin`, `axon.it`, `axon.sales`) on the
  app registration and assign Entra groups to them. Set `groups_claim = "roles"`:
  the values are readable names, so no GUID mapping and no groups-overage.
- Alternative: `groupMembershipClaims = ApplicationGroup` limits the `groups`
  claim to groups assigned to the app (GUIDs, so `group_map` is needed).
- Use the single-tenant v2 issuer `https://login.microsoftonline.com/{tenant-id}/v2.0`;
  the multi-tenant `common` endpoint fails strict issuer validation.
- Phase 7 resource-server mode needs "Expose an API" (the app ID URI is the
  audience) and v2 access tokens in the manifest (`api.requestedAccessTokenVersion: 2`
  in the Microsoft Graph manifest, `accessTokenAcceptedVersion: 2` in the
  legacy one).

**Keycloak:** `groups_claim = "realm_access.roles"`, or add a groups mapper and use
`groups`. **PocketID:** the `groups` claim.

### Agents, phase A: PATs and service accounts

- Format `axon_pat_<public id>_<secret>`. The prefix enables secret scanning.
  Store SHA-256 of the secret; look up by public id, then constant-time compare.
- Expiry is required; fixed maximum lifetime (90 days for users, 365 for
  service accounts; no config knob until a deployment needs one). Track `last_used_at`
  and last IP. Optional scope narrowing (backends, tool globs). Revoke anytime.
- Service accounts are owned by admins and bound to groups/roles like users.

Deprovisioning: a PAT outlives the IdP session, so:

- maximum lifetime,
- PATs are suspended when the owner has not logged in for 90 days
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

- **shared**: declared in config or created by an admin. Only admins create
  shared backends, and they grant them to IdP-mapped groups.
- **personal**: owned by a user, visible only to them. Personal backends cannot be
  shared with groups.

Example grants: IT gets `forgejo`, `prom`, `loki`; Sales gets `crm`; everyone
(via `authenticated`) gets `hindsight`. A user in several groups gets the union.

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
- **tools/list per principal**: shared registry view plus personal backends,
  filtered by policy. Opt-outs and toolsets are a further view filter, never a
  bypass.
- **MCP transport**: replace the hand-rolled JSON-RPC handler and the SSE stub
  with spec-compliant Streamable HTTP (rmcp server side), so
  `notifications/tools/list_changed` (on grant or backend change), progress and
  cancellation reach clients. Versions and statelessness: see "Protocol
  versions" below.
- **Horizontal scaling**: sessions are stateless or sticky; durable state lives
  in Postgres; config/grant changes fan out across replicas via LISTEN/NOTIFY.
  Rate limits are shared; see "Kubernetes / multi-replica" below.
- **Admin JSON API** `/api/v1/...` is the single write path. The HTMX UI and a
  future CLI call the same service layer. Writes to config-managed objects
  return 409.
- **UI pages**: Login (provider picker); My tools (effective tools and why:
  which group/grant), My MCP servers, My tokens, Catalog. Admin: Shared
  backends, Catalog, Users, Groups and IdP mappings, Roles, Service accounts,
  Audit log, Gateway settings. My tools also holds the opt-outs and toolsets. A
  "why can/can't I use this tool" explain view is valuable for support.

### Protocol versions

- **Client-facing:** accept 2025-06-18, 2025-11-25 and 2026-07-28. The minimum
  is 2025-06-18, the first revision with the OAuth resource-server model
  (RFC 9728) that Phase 7 builds on.
- **Backend-facing:** every version rmcp knows, including 2024-11-05, because
  axon does not control backends. rmcp 3.9 knows exactly five versions
  (`ProtocolVersion::KNOWN_VERSIONS`): 2024-11-05, 2025-03-26, 2025-06-18,
  2025-11-25, 2026-07-28.
- **Stateless-first:** build the new transport around 2026-07-28, which drops
  the `initialize` handshake (SEP-2567; lifecycle data goes in each request's
  `_meta`). With no session state, any pod serves any request. `Mcp-Session-Id`
  ingress affinity is needed only for pre-2026-07-28 clients.
- **Standard headers:** SEP-2243 (`Mcp-Method`, `Mcp-Name`, from 2026-07-28) lets
  the ingress, the rate limiter and metrics see the method and tool without
  parsing the body. Axon emits and consumes them.

### Backend instances

- A backend with a shared credential (for example Prometheus with one service
  token) has ONE instance per pod, shared by all users. Identity and permissions
  are enforced in axon before the call, so per-user connections would only
  multiply connections and health checks.
- Per-user instances exist only for `per_user`-credential backends and personal
  backends; caps on concurrent per-user instances apply.
- Idle timeout: every instance (shared, per-user and personal) starts on first
  use and disconnects after 5 minutes without calls. `[gateway]
  idle_timeout_secs` (default 300) sets the default; a backend's own
  `idle_timeout_secs` overrides it, and `0` keeps it always connected. Tool
  definitions stay cached, so `tools/list` needs no live connection; the first
  call after idle pays the connect cost. The UI shows state `idle`, which is not
  down.
- Health is split by backend kind, decoupled from the idle session:
  - **Shared backends: active probes, also while idle.** A short probe runs on
    the existing `health_check_interval_secs` (default 30 s, `0` disables): a
    stateless `ping` for 2026-07-28 backends, open-session/`ping`/close for
    older ones. Each pod probes on its own (3 probes per interval on
    Kubernetes; negligible, and it catches pod-local network faults).
  - **Per-user and personal backends: passive health only.** No background
    probes: with hundreds of users they would be constant traffic against each
    user's own SaaS account and its rate limits. Health comes from real calls:
    failures feed the circuit breaker, and the user's UI shows "last call
    ok/failed at ...".
  - New metric `axon_backend_up{backend}` (1/0) from probe results, shared
    backends only. Alerts use it and the real-call error rate, never the
    connection state, because `idle` is not down.
- **Existing bug (Phase 0):** `BackendActor`'s `CallTool` handler awaits
  `call_tool` inside the message handler (`src/backend.rs` around line 838).
  kameo processes one message at a time, so all calls to a backend are
  serialized and one slow call (for example a long `prom_query_range`) blocks
  every other user. Fix: the actor owns only the connection lifecycle (connect,
  reconnect, health, circuit breaker). Calls run concurrently on a cloned rmcp
  peer handle (`rmcp::Peer` is `Clone`: an mpsc sender plus `Arc`s), capped by a per-backend
  semaphore (fixed default, for example 32 in flight). Circuit-breaker
  accounting still updates from call outcomes.

### Kubernetes / multi-replica

The work deployment is Kubernetes with 3 replicas.

- **Sessions.** The 2026-07-28 path is stateless, so any pod serves any
  request. Sessions for older clients are pod-local: the ingress hashes on the
  `Mcp-Session-Id` header (nginx-ingress `upstream-hash-by`) for them only.
- **Backend connections.** Every pod holds its own backend connections and runs
  its own health probes for shared backends: up to 3x connections and pings to
  backends (idle timeout applies per pod). Fine for HTTP. The Helm chart leaves
  `allow_stdio` off; a stdio-only MCP server runs as its own Deployment behind a
  stdio-to-HTTP bridge and is added as an HTTP backend.
- **Rate limits** must be shared: Postgres-backed counters, replacing the
  per-instance limiter.
- **Singleton jobs** (audit and argument retention, token expiry,
  inactive-user suspension) run under a Postgres advisory lock. sqlx migrations
  already take a lock.
- **ConfigMap hot reload.** The kubelet swaps a `..data` symlink, so the watcher
  must watch the config directory, not the file. `src/watcher.rs` already
  watches the parent directory, but its callback keeps only events whose path
  file name equals the config file name, which drops the `..data` swap events;
  extend the filter to accept `..data` (to do, verify in a test with a
  kubelet-style layout).
- **Helm chart** (`deploy/helm/axon-gateway/`): Deployment, PodDisruptionBudget,
  liveness and readiness on `/livez` and `/readyz`, ServiceMonitor, secrets
  (OIDC client secret, KEK, DB URL) from a k8s Secret or external-secrets.
  Graceful shutdown drains SSE streams.

## 8. Observability

- **OpenTelemetry** over OTLP: traces, plus metrics and logs as optional
  exports, via tracing-opentelemetry. hofvarpnir in this monorepo pins
  opentelemetry 0.33 and tracing-opentelemetry 0.34; keep versions aligned.
  Config: the standard `OTEL_*` env vars only, no `[telemetry]` table (export
  is on when `OTEL_EXPORTER_OTLP_ENDPOINT` is set).
- **Spans**: HTTP request -> MCP method -> authz decision -> backend call.
  Attributes: principal type, principal id (hashing optional), auth method
  (`pat`/`session`/`jwt`/`oauth`), backend, tool, outcome. Propagate W3C
  `traceparent` to HTTP backends and into MCP `_meta` (`traceparent`) per the
  MCP trace-context proposal (verify status).
- **Metrics**: keep existing `axon_*` names. Add `axon_authn_total{method,result}`,
  `axon_authz_denied_total{reason}`, `axon_active_sessions`,
  `axon_user_backends{state}`, `axon_tokens_active`, principal-type labels,
  database pool metrics, OIDC provider latency/errors,
  `axon_backend_inflight_calls{backend}`, `axon_backend_up{backend}` (probe
  result, shared backends).
- **Per-user metric:** one counter, `axon_user_tool_calls_total{user, backend,
  outcome}`, where `user` is the stable internal axon user id (UUID); there is no
  option for it. No `tool` label on it and no user label on histograms, for
  cardinality (300 users x 200 tools x ~12 buckets is about 720k series).
  Per-user latency comes from traces.
- **Audit log**: append-only Postgres table: who, principal, auth method, token
  id, action, target, tool, outcome, duration, trace id, client IP, user agent.
  Covers admin actions and tool calls. Arguments are handled separately (see
  Audit arguments). Retention job.
  Also emitted as a structured log event (`target = "axon::audit"`) for
  Loki/any SIEM. UI: audit view with filters and a per-user usage page.
- **Health**: `/livez`; `/readyz` (DB reachable, migrations applied, config
  backends evaluated); `/health` stays as alias.
- **Ship in repo** under `example/observability/`: Grafana dashboard JSON and
  Prometheus alert rules (shared backend down via `axon_backend_up`, tool-call
  error rate per backend, auth failure spike, DB down, OIDC provider
  unreachable).

### Audit arguments

- Metadata is always recorded: who, principal, auth method, token id, tool,
  outcome, duration, trace id, client IP, user agent.
- Arguments go to a separate table `audit_arguments` with its own, shorter
  retention: default 30 days for arguments, 1 year for metadata, both
  configurable.
- Reading arguments requires `audit.read_sensitive` (`admin` has it, `auditor`
  does not by default). Every read of arguments is itself audited.
- Default capture follows MCP tool annotations: `destructiveHint: true` ->
  redacted; `readOnlyHint: true` -> none; no annotation -> redacted. (Verify: the
  MCP spec defaults `destructiveHint` to true when `readOnlyHint` is false, so
  unannotated tools count as potentially destructive.)
- Redaction masks values whose keys match a denylist (password, secret, token,
  authorization, api_key, cookie, ...) and truncates long values (configurable,
  for example 2 KiB). Tool results are never stored by default.
- Admin overrides per backend and per tool glob: `none | redacted | full`, plus
  per-key drop lists. Examples: `pg*_run_query` = `full` (the query is the
  evidence); `forgejo_create_file` = `redacted` with `content` dropped.
  Config-declared overrides are read-only like other config objects.
- Compliance: GDPR applies (purpose limitation, retention, data-subject
  requests). In Germany with a works council, per-employee activity logging is a
  technical system suited to monitoring behaviour, so co-determination under
  section 87(1) no. 6 BetrVG applies; involve the council before enabling `full`
  capture.

## 9. Security checklist

- [ ] Threat model written down (malicious user, compromised PAT, hostile
      personal backend, compromised IdP claim, insider admin).
- [ ] Rate-limit login, callback and token-mint endpoints.
- [ ] No secrets, tokens or tool arguments in logs or spans.
- [ ] Audit arguments: redaction denylist, `audit.read_sensitive` gate, works
      council and GDPR review before enabling `full`.
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
  and `axon-with-db <recipes>` on a unix-socket tmpfs cluster, no host port (follows the "Test databases"
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

Status (2026-11-09): Phases 0, 1, 2a, 2b and 3a are done and committed. Resume
at Phase 3b. Open caveats: OIDC login is untested against a real IdP, and a
plain-text 403 from the CSRF check can replace an admin page section (the
htmx config swaps 4xx responses).

### Phase 0 - Groundwork (no behaviour change)

- [x] Split `server.rs` into `server/mcp.rs`, `server/ui/`, `server/api.rs`,
      `server/auth.rs`.
- [x] Add sqlx, `migrations/`, `[database]` config, `store/` layer.
- [x] Add `axon-db-up`, `axon-db-down`, `axon-with-db` recipes (tmpfs, unix socket) and
      wire `axon-ci`.
- [x] Extract `authz/` policy engine from `AuthManager` with current semantics
      and tests.
- [x] Fix `BackendActor` call serialization (`src/backend.rs` ~838): the actor
      owns only the connection lifecycle; calls run concurrently on a cloned
      rmcp peer, capped by a per-backend semaphore (fixed, ~32 in flight);
      circuit-breaker accounting still updates from outcomes. Test: two slow
      calls to one backend run in parallel.
- [x] OTel tracing foundation (`OTEL_*` env, OTLP exporter, request spans).
- [x] `/livez`, `/readyz`; keep `/health`.
- Exit: all existing tests pass unchanged; no `[database]` means identical
  behaviour; traces visible in a local collector.

### Phase 1 - OIDC login for the dashboard

- [x] `oidc.rs` with generic multi-provider discovery, PKCE, state, nonce
      (lanternd's `oauth2` + `jsonwebtoken` stack, see decision 8).
- [x] `users` and `sessions` tables; cookie handling; timeouts; logout
      (RP-initiated via `end_session_endpoint`).
- [x] Protect `/ui` and `/ui/actions/*` in multi-user mode; login page with
      provider picker.
- [x] Bootstrap admin via `admin_groups` mapping in config.
- [x] CSRF tokens on forms (`X-CSRF-Token` via `hx-headers`, form field on
      logout).
- [x] `allowed_email_domains` only trusts verified addresses (`email_verified`,
      or Entra's optional `xms_edov` claim).
- Open: `/status/detailed` and `/metrics` stay unauthenticated, as today;
  RBAC (phase 2) decides who may read them. Not yet tried against a real IdP.
- Exit: login works against the mock issuer and one real IdP; UI inaccessible
  without a session; standalone mode unchanged.

### Phase 2a - RBAC config layer, policy and "My tools"

- [x] Rename `[[groups]]`/`ToolGroupConfig` to `[[toolsets]]`, route
      `/mcp/toolset/{name}` and `/status/toolsets`; `[[groups]]`,
      `/mcp/group/{name}` and `/status/groups` stay as deprecated aliases for
      one minor release (the alias returns the list under `"toolsets"`).
- [x] `[rbac]` config layer: `[[rbac.groups]]` with IdP mappings
      (`provider` + claim `value`), `[[rbac.grants]]` with include/exclude
      globs on original tool names, `read_only` and `mandatory`; validated at
      load, not hot-reloadable. Built-in `authenticated` group.
- [x] Pure policy engine (`src/policy.rs`): allow-only union, deny by default,
      explain with reasons, view layer (`visible`).
- [x] Tool annotations passed through; `readOnlyHint` feeds `read_only` grants.
- [x] Per-user opt-outs (`tool_opt_outs`, whole backend or single tool);
      mandatory tools cannot be hidden.
- [x] "My tools" page (`/ui/tools`): the user's groups, every tool's state
      (on / mandatory / hidden by you / not granted + why), htmx toggles
      behind CSRF.
- Groups are computed per request from the stored IdP claim values, so a
  changed mapping applies on the next request after a restart.

### Phase 2b - Managed RBAC

- [x] Tables: groups, IdP mappings, memberships, role bindings, grants,
      audit log (built-in roles only; custom roles stay Phase 7, grants to a
      single principal come with service accounts in Phase 3).
- [x] Config layer merged read-only (`source = config`); 409 on write;
      replicas reload the merged policy every 30 s.
- [x] Admin UI for groups and grants (`/ui/admin`); `/api/v1` write path
      (session + CSRF until PATs exist).
- [x] Audit log for admin actions, written in the same transaction
      (`/ui/admin/audit`, `GET /api/v1/audit`).

### Phase 3a - Agent tokens and enforcement

- [x] Per-principal `tools/list` and `tools/call` enforcement (moved from
      Phase 2: it needs PATs to know the principal); hidden tools answer
      `tools/call` with the unknown-tool error (-32601, hidden looks like
      absent); resources and prompts filtered by permitted backends.
- [x] PATs (`axon_pat_...`), expiry, max lifetime, scope narrowing, revoke,
      last-used tracking (`/ui/tokens`, `/api/v1/tokens`). Lifetimes are fixed
      defaults, no config knob: 30 days default, 90 days max for users, 365
      for service accounts.
- [x] Service accounts (admin-managed, `/ui/admin/service-accounts`,
      `/api/v1/service-accounts`), members of database groups.
- [x] Multi-user mode is deny-by-default on `/mcp` (401 with
      `WWW-Authenticate: Bearer`); legacy tokens still work and log a
      deprecation warning.
- [x] Deprovisioning: a user's tokens are suspended after 90 days without a
      login; a disabled service account's tokens stop working.
- Exit (met, `tests/tokens.rs`): two users with different groups see and can
  call different tools; an agent authenticates with a PAT and is limited to
  its owner's policy intersected with its scope.

### Phase 3b - Agent tokens, rest

- [ ] Legacy `auth_token` / `[[tokens]]` mapped to config service accounts.
- [ ] Service accounts in config groups (today only database groups take
      them as members).
- [ ] Admin disable of a human user (suspends their tokens).
- [ ] Record the client IP on token use (`last_used_ip` is written as null).
- [ ] User-defined toolsets and PAT toolset pinning.
- [ ] Tool-call audit, with argument capture policy (annotation defaults,
      overrides), `audit_arguments` table and `audit.read_sensitive`.
- [ ] Break-glass CLI `axon-gateway admin ...`.

### Phase 4 - Spec-compliant MCP transport

- [ ] Streamable HTTP server side via rmcp: stateless 2026-07-28 path first
      (no `initialize`, lifecycle data in `_meta`), session path for older
      clients; accept 2025-06-18, 2025-11-25, 2026-07-28 from clients.
- [ ] Emit and consume SEP-2243 headers (`Mcp-Method`, `Mcp-Name`); rate limiter
      and metrics read them instead of parsing the body.
- [ ] `[gateway] allow_stdio` (default `false`): config load fails on a stdio
      backend unless it is set; upgrade note for standalone users; document the
      stdio-to-HTTP bridge Deployment pattern for Kubernetes.
- [ ] `notifications/tools/list_changed` on grant/backend changes and on opt-out
      or toolset changes.
- [ ] Progress and cancellation passthrough.
- [ ] LISTEN/NOTIFY fan-out; multi-replica notes in the docs.
- [ ] Shared rate limits (Postgres counters).
- [ ] Singleton jobs under a Postgres advisory lock (retention, token expiry,
      inactive-user suspension).
- [ ] Config watcher accepts the kubelet `..data` symlink swap (directory watch,
      adjust the file-name filter).
- [ ] Remove the SSE stub.
- Exit: a spec-conformant client receives list_changed after a grant change;
  two replicas stay consistent.

### Phase 5 - Personal MCP servers and catalog

- [ ] Personal backends with namespacing rules.
- [ ] Egress policy and SSRF guard; stdio admin-only.
- [ ] `crypto/` envelope encryption, `AXON_KEK_FILE`, KEK rotation.
- [ ] Per-user backend instances (`per_user` and personal only) with caps.
- [ ] Idle timeout for all instances: `[gateway] idle_timeout_secs` (default
      300) with per-backend override (`0` = always connected); cached tool
      definitions, connect on first call, state `idle` in UI and metrics.
- [ ] Health split: probes for shared backends keep running while idle
      (stateless `ping` or open/`ping`/close); per-user and personal backends
      get passive health from call outcomes, with no probes.
- [ ] Catalog and `per_user` credentials.
- [ ] Per-user quotas.
- Exit: a user adds a personal HTTP MCP and a catalog backend with their own
  credential; loopback and metadata targets are refused.

### Phase 6 - Observability completion

- [ ] New metrics (section 8), including `axon_user_tool_calls_total{user,
      backend, outcome}`, `axon_backend_inflight_calls{backend}` and
      `axon_backend_up{backend}`; pool and
      OIDC metrics.
- [ ] Audit UI, retention job (metadata 1 year, arguments 30 days, both
      configurable), per-user usage page.
- [ ] Helm chart under `deploy/helm/axon-gateway/` (section 7).
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
- [ ] Entra groups-overage Graph lookup (fallback only; app roles are the default, section 5).

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

## 12. Revisit later

- Move rate-limit counters to Valkey/Redis (GCRA in an atomic Lua script) if
  they show up in database load.
