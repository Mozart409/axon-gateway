# Axon Gateway

A lightweight, self-hosted MCP (Model Context Protocol) gateway that aggregates multiple MCP servers into a single endpoint.

## Features

- **Aggregation**: Combine tools from multiple MCP servers into one endpoint
- **Namespacing**: Tools are automatically prefixed with backend name (e.g., `homeassistant_turn_on`)
- **Multiple transports**: SSE, HTTP, and stdio backends supported (stdio is opt-in, see [Gateway settings](#gateway-settings))
- **Streamable HTTP**: Clients connect per the MCP spec and hear `notifications/tools/list_changed` when their tools change
- **Multi-token auth**: Named API tokens with fine-grained permissions (allowed tools/backends)
- **Toolsets**: Expose subsets of tools via different path prefixes
- **Hot reload**: Config file watching with automatic backend updates; Kubernetes ConfigMap updates (the `..data` symlink swap) are picked up too
- **Prometheus metrics**: Built-in metrics endpoint for monitoring
- **Resource/Prompt proxying**: Forward MCP resources and prompts from backends
- **Auto-reconnect**: Exponential backoff reconnection with circuit breaker
- **Health checks**: Periodic backend health monitoring
- **Actor-based**: Built on kameo for robust concurrency

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   MCP Gateway                       │
│                                                     │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │ HTTP Server  │  │   Gateway   │  │  Registry  │  │
│  │ (axum)       │──│   Actor     │──│   Actor    │  │
│  │ /mcp         │  │             │  │            │  │
│  └──────────────┘  └─────────────┘  └────────────┘  │
│                           │                         │
│         ┌─────────────────┼─────────────────┐       │
│         │                 │                 │       │
│  ┌──────▼─────┐  ┌────────▼─────┐  ┌────────▼────┐  │
│  │ Backend    │  │ Backend      │  │ Backend     │  │
│  │ Actor      │  │ Actor        │  │ Actor       │  │
│  │ (HA)       │  │ (Jellyfin)   │  │ (Proxmox)   │  │
│  └──────┬─────┘  └───────┬──────┘  └───────┬─────┘  │
└─────────┼────────────────┼─────────────────┼────────┘
          │                │                 │
          ▼                ▼                 ▼
    MCP Server 1     MCP Server 2      MCP Server 3
```

## Quick Start

1. **Configure your backends** in `config.toml`:

```toml
[gateway]
bind = "0.0.0.0:8080"

[[backends]]
name = "homeassistant"
url = "http://localhost:3001/mcp/sse"
transport = "sse"
enabled = true

[[backends]]
name = "jellyfin"
url = "http://localhost:3002/mcp"
transport = "http"
enabled = true
```

2. **Run the gateway**:

```bash
cargo run -- config.toml
# or
MCP_GATEWAY_CONFIG=config.toml cargo run
```

3. **Connect your agent** to the gateway:

```json
{
  "mcpServers": {
    "homelab": {
      "url": "http://localhost:8080/mcp",
      "transport": "http"
    }
  }
}
```

## Container Deployment

Prebuilt images are published to `ghcr.io/mozart409/axon-gateway`. Example
Compose files live in [`example/`](example/):

- `compose.yml` — runs the published image (`ghcr.io/mozart409/axon-gateway:latest`)
- `compose.local.yml` — builds the image from this repo

```bash
# from example/, with a config.toml alongside it
podman compose -f compose.yml up -d   # or: docker compose
```

Mount your config read-only at `/app/config.toml` and pass it as the command
argument (both example files already do this).

> **Healthcheck note:** the runtime image is the minimal Chainguard
> `wolfi-base`, which ships **no HTTP client** — no `curl`, no `wget`, and its
> busybox has no `wget` applet. The Compose healthchecks probe `/health` with
> `wget`, so the Dockerfile installs the tiny Wolfi `wget` package
> (`apk add --no-cache wget`) specifically to make that check pass. Drop that
> line only if you also remove the `healthcheck:` blocks from the Compose files.

> **DNS note:** the container's `/etc/resolv.conf` is fixed when it starts:
> Podman and Docker copy the host's resolver settings at that moment. If a
> backend is reached by hostname and the host's DNS setup changes later (a VPN
> client such as Tailscale added or removed, a new DHCP lease), the container
> keeps the old nameservers, and lookups fail with `Temporary failure in name
> resolution`. The gateway keeps reconnecting with backoff, so the backend
> comes back on its own as soon as resolution works again. To keep it working,
> pin the container to a resolver that does not move: `dns:` in Compose (see
> the commented line in the example files), or `--dns=<ip>`. With host
> networking and a caching resolver on the host, that is `--dns=127.0.0.1`.
> Without a pin, restart the container after changing the host's DNS.

## Kubernetes (Helm)

The chart is in [`deploy/helm/axon-gateway`](deploy/helm/axon-gateway). The
gateway config is raw TOML in the `config` value; secrets are not part of it.
`existingSecret` names a Secret whose keys all become environment variables
(`AXON_DATABASE_URL`, client secrets, backend tokens), `env` and `envFrom` add
more, and `kek.existingSecret` mounts the key-encryption key as a file for
`AXON_KEK_FILE`. Roll the pods after changing a Secret. Exposure is a Gateway
API `HTTPRoute` (there is no Ingress). A `ServiceMonitor`, a `PrometheusRule`
and a Grafana dashboard ConfigMap are optional, and all off by default:

```yaml
config: |
  [gateway]
  base_url = "https://axon.example.com"
  [database]
  url_env = "AXON_DATABASE_URL"
existingSecret: axon-gateway-env
httpRoute:
  enabled: true
  parentRefs: [{name: public-gateway}]
  hostnames: [axon.example.com]
serviceMonitor: {enabled: true}
prometheusRule: {enabled: true}
grafanaDashboard: {enabled: true}
```

```bash
helm install axon deploy/helm/axon-gateway -f my-values.yaml

# check a change to the chart or the rules
helm lint deploy/helm/axon-gateway
helm template axon deploy/helm/axon-gateway -f deploy/helm/axon-gateway/ci/all-on-values.yaml \
  | kubeconform -strict -summary -ignore-missing-schemas
promtool check rules example/observability/prometheus-rules.yaml
```

Outside Kubernetes, [`example/observability/`](example/observability/)
has the same dashboard JSON and Prometheus rules.

## API Endpoints

| Endpoint                                | Method | Description                                         |
| --------------------------------------- | ------ | --------------------------------------------------- |
| `/mcp`                                  | any    | MCP endpoint (Streamable HTTP, see MCP Endpoint)    |
| `/mcp/toolset/{toolset_name}`           | any    | MCP endpoint filtered by toolset                    |
| `/mcp/group/{toolset_name}`             | any    | Deprecated alias of `/mcp/toolset/{toolset_name}`   |
| `/`                                     | GET    | Landing page                                        |
| `/ui`                                   | GET    | SSR dashboard page                                  |
| `/ui/backends/{name}`                   | GET    | Backend detail page                                 |
| `/ui/events`                            | GET    | Dashboard SSE stream (`text/event-stream`)          |
| `/ui/partials/backends`                 | GET    | SSR backend panel fragment                          |
| `/ui/actions/backends/{name}/reconnect` | POST   | HTMX action: reconnect backend                      |
| `/ui/actions/backends/{name}/disable`   | POST   | HTMX action: disable backend                        |
| `/ui/actions/backends/{name}/enable`    | POST   | HTMX action: enable backend                         |
| `/ui/actions/reload`                    | POST   | HTMX action: reload config                          |
| `/ui/tools`                             | GET    | "My tools" page (multi-user mode)                   |
| `/ui/tokens`                            | GET    | Personal access tokens page (multi-user mode)       |
| `/api/v1/...`                           | any    | JSON admin API for RBAC (multi-user mode, see RBAC) |
| `/api/v1/me/backends`, `/api/v1/catalog`, ... | any | Personal MCP servers and catalog (see Personal MCP servers and the catalog) |
| `/build`                                | GET    | Build/runtime metadata (version, pid, startup time) |
| `/health`                               | GET    | Health check                                        |
| `/livez`                                | GET    | Liveness probe (200 while the process is up)        |
| `/readyz`                               | GET    | Readiness probe (503 if the gateway actor stopped)  |
| `/status`                               | GET    | Gateway status (backend list, counts)               |
| `/status/detailed`                      | GET    | Detailed status with tool/resource/prompt lists     |
| `/status/toolsets`                      | GET    | List configured toolsets                            |
| `/status/groups`                        | GET    | Deprecated alias of `/status/toolsets`              |
| `/metrics`                              | GET    | Prometheus metrics endpoint                         |

## MCP Endpoint

`/mcp` and the toolset endpoints speak Streamable HTTP as the MCP spec defines
it: clients `POST` JSON-RPC messages and may open a `GET` stream for messages
from the gateway. Three protocol versions are served:

- `2025-06-18` and `2025-11-25` use sessions: `initialize` returns an
  `Mcp-Session-Id` header that the client sends on every later request.
- `2026-07-28` is stateless: there is no session, and a client that wants to
  hear changes opens a `subscriptions/listen` stream.

With a database, sessions for the two older versions are stored there, so any
replica can serve them, and each is bound to the principal that opened it:
another principal sending its `Mcp-Session-Id` gets HTTP 404. See
[Multiple replicas](#multiple-replicas).

`/mcp/sse`, the old SSE endpoint, is removed; point clients at `/mcp` with the
Streamable HTTP transport.

The gateway sends `notifications/tools/list_changed` to the callers a change
concerns, after a short debounce so a burst becomes one notification:

- a backend connects, disconnects or changes its tools (every caller)
- a grant, group or role changes, in config or the database (every caller)
- a user changes their opt-outs or toolsets (that user's callers)

Progress notifications and cancellation pass through to the backend that runs
the call, so a long tool call reports progress and stops when the client
cancels it.

The endpoints check the `Host` header against an allowlist (DNS rebinding
protection): loopback, the host of `[gateway] base_url` and everything in
`[gateway] allowed_hosts`. A request with any other `Host` is refused, so behind
a reverse proxy set `base_url` to the public URL, and list every other name the
proxy answers to in `allowed_hosts`.

## Frontend Architecture

The web UI is SSR-first and keeps all rendering server-side:

- **Server framework**: `axum`
- **Templating**: `maud`
- **Live updates**: `htmx` + SSE extension (`/ui/events`)
- **Styling**: Tailwind CSS v4 (compiled `styles/output.css` served by axum)

Runtime update flow:

1. Client loads `/ui` (fully rendered HTML works without JavaScript).
2. If JS is available, HTMX opens SSE connection to `/ui/events`.
3. Backend status updates and admin actions publish typed UI events.
4. SSE events carry HTML fragments (`backend_status_changed`, `flash`) swapped into the DOM.

## UI Authentication

UI routes use the same bearer auth logic as MCP/admin routes:

- If no auth is configured, `/ui` and `/ui/events` are open.
- If auth is configured, callers must send `Authorization: Bearer <token>`.
- HTMX action routes under `/ui/actions/*` require auth and return HTML fragments.

## Local UI Development

From the repository root:

```bash
# terminal 1: run gateway
bacon run-long

# terminal 2: rebuild Tailwind on change
bacon css-watch
```

Useful checks:

```bash
curl http://127.0.0.1:8080/build
curl -I http://127.0.0.1:8080/styles/output.css
```

`/build` helps detect stale processes (pid/start time/fingerprint mismatch).

## UI Follow-Up Backlog

- Backend filtering/search and grouped backend views
- Action audit log / live event feed panel
- Pagination and virtualized rows for large backend/tool lists
- More granular SSE topics per widget
- Integration snapshots for rendered fragments

## How Tool Namespacing Works

When backend `homeassistant` provides tools `turn_on` and `turn_off`, the gateway exposes them as:

- `homeassistant_turn_on`
- `homeassistant_turn_off`

When your agent calls `homeassistant_turn_on`, the gateway:

1. Looks up which backend owns the tool
2. Strips the prefix to get `turn_on`
3. Forwards the call to the Home Assistant MCP server
4. Returns the result

## Authentication

### Simple Token Auth

Enable auth by setting `auth_token` in config:

```toml
[gateway]
bind = "0.0.0.0:8080"
auth_token = "your-secret-token"
```

Clients must include `Authorization: Bearer your-secret-token` header.

### Multi-Token Auth with Permissions

For fine-grained access control, configure named tokens:

```toml
[gateway]
bind = "0.0.0.0:8080"

[[tokens]]
name = "admin"
token = "${ADMIN_TOKEN}"
allowed_backends = ["*"]  # All backends

[[tokens]]
name = "readonly"
token = "${READONLY_TOKEN}"
allowed_tools = ["*_read", "*_list"]  # Only read/list tools
```

Token permissions:

- `allowed_backends`: List of backend names (supports `*` wildcard)
- `allowed_tools`: List of tool name patterns (supports `*` wildcard)

## Rate Limiting

Requests are rate-limited **per token** using a fixed 1-minute window. There is
a single setting, `rate_limit_per_minute`, configurable at two levels:

```toml
[gateway]
bind = "0.0.0.0:8080"
rate_limit_per_minute = 100   # global default applied to every token

[[tokens]]
name = "admin"
token = "${ADMIN_TOKEN}"
rate_limit_per_minute = 1000  # per-token override

[[tokens]]
name = "readonly"
token = "${READONLY_TOKEN}"
# no value → falls back to the global default (100)
```

Semantics:

- **Default: `0`** — both the global and per-token values default to `0`, which
  means **unlimited**. Rate limiting is **off** until you set a non-zero value.
- **Resolution**: a per-token `rate_limit_per_minute > 0` overrides the global
  value; a per-token `0` (or omitted) falls back to the global default.
- **Window**: fixed 1-minute window per token (not a sliding window or token
  bucket). In standalone mode the counter lives in memory, per replica, and
  resets once a full minute has elapsed.
- **Multi-user mode**: the counter lives in Postgres (table `rate_limit_windows`,
  one row per token and minute, aligned to the wall-clock minute), so the limit
  holds across all replicas.
- **Personal access tokens and service-account tokens** are limited by the
  global `[gateway] rate_limit_per_minute` too.
- **Fail-open**: if the counter cannot be updated, the request is let through
  and a warning is logged. The limit protects the backends; it is not an access
  check.
- **Simple shared-token auth** (`auth_token`, no named `[[tokens]]`) is not
  rate-limited. Use named tokens to enforce limits.
- Exceeding the limit returns an auth error (HTTP 429).

## Toolsets

Expose subsets of tools via different path prefixes:

```toml
[[toolsets]]
name = "coding"
backends = ["vscode", "git"]
description = "Development tools only"

[[toolsets]]
name = "readonly"
tools = ["*_read", "*_list", "*_get"]
description = "Read-only operations"
```

Access a toolset at `/mcp/toolset/{toolset_name}` instead of `/mcp`.

`[[groups]]`, `/mcp/group/{name}` and `/status/groups` are deprecated aliases
(`groups` now means RBAC groups) and will be removed after one minor release.

## Database

An optional Postgres store; without a `[database]` section the gateway runs
standalone. The connection URL is read from an environment variable, never from
the config file, and migrations run at startup. The section is not
hot-reloadable: changes need a restart.

```toml
[database]
url_env = "AXON_DATABASE_URL" # default
```

When configured, `/readyz` also pings the database and returns 503
(`database unreachable`) when it does not answer within 2 s.

## Multiple replicas

Several gateways can share one database and serve the same clients. Sessions
need no sticky routing.

Changes fan out through Postgres. Triggers run `NOTIFY axon_changes` when
groups, IdP mappings, memberships, grants or role bindings change (payload kind
`policy`), when a user's opt-outs, toolsets or personal servers change (kind `user`), and when the catalog changes (kind `catalog`). Every
replica LISTENs on the channel: a policy notice reloads its policy, and a user
notice sends `notifications/tools/list_changed` to that user's MCP clients.
Changes made with `axon-gateway admin` or straight in SQL propagate the same way.
Payloads name the schema and replicas ignore other schemas, so gateways in
different schemas can share one database.

If the listen connection drops, the replica reloads its policy and tells all
clients their tool list may have changed. The 30-second policy poll stays as a
backstop.

With a database, MCP session state for `2025-06-18` and `2025-11-25` is stored
in the `mcp_sessions` table, keyed by the SHA-256 of the session id. Any replica
can serve such a session, and one that does not know it restores it from the
database. Each session is bound to the principal that opened it (user, config
service account, legacy token or open), and another principal gets HTTP 404.
Sessions unused for 24 hours are purged. Without a database, sessions and their
binding live in the process only. `2026-07-28` requests are stateless and need
nothing shared.

Rate limits are shared in multi-user mode; see [Rate Limiting](#rate-limiting).

Background jobs (expired login sessions, audit retention, rate-limit windows
and idle MCP sessions) run hourly. Every replica ticks, but a lease row in
`job_runs` makes each job run about once an hour across all replicas. Token
expiry and inactive-user suspension need no job: they are checked when a token
is used.

Some state stays per replica. Each replica connects to the backends itself, so
backend tool changes are not shared. Progress and cancellation for an in-flight
call travel on the connection that made the call.

## Dashboard login (OIDC)

Multi-user mode turns on with a `[database]` section plus at least one
`[[auth.oidc]]` provider; any OIDC provider works (Entra ID, Pocket ID,
Keycloak, ...). Register `{base_url}/auth/callback` as the redirect URI and
`{base_url}/` as the post-logout redirect.

```toml
[[auth.oidc]]
id = "pocket"                      # used in URLs
display_name = "Pocket ID"         # login button label
issuer = "https://id.example.com"
client_id = "axon"
client_secret_env = "AXON_OIDC_POCKET_SECRET"
scopes = ["openid", "profile", "email"] # default
groups_claim = "groups"            # default, dotted paths allowed
allowed_email_domains = ["example.com"]
admin_groups = ["axon-admins"]
```

Sessions use the `__Host-axon_session` cookie, which needs HTTPS. They expire
after 12 h idle or 7 days absolute. For Entra ID, add a "groups" claim in the
token configuration and emit groups as object IDs; users in more than ~200
groups get no groups (overage) for now.

`allowed_email_domains` only trusts a verified address: the ID token must carry
`email_verified: true`, or for Entra ID the optional `xms_edov` claim (add it
in the token configuration). A single-tenant Entra issuer already limits logins
to the tenant, so the list is usually not needed there.

Without OIDC the dashboard stays open as before, so keep it on a trusted
network.

## RBAC

In multi-user mode, access is described by groups, tool grants and roles. A
user belongs to the built-in `authenticated` group (everyone logged in), to
every group with an IdP mapping that matches one of their claim values at the
login provider, and to every group they were added to by hand. A grant lets a
group use a backend's tools (globs over the tool's original name); the union of
a user's grants is what the "My tools" page shows as allowed.

On `/mcp` (and the toolset endpoints) a personal access token
(`axon_pat_...`, or a service account's) gets exactly what its owner's policy
allows, narrowed by the token's scope (backends and tool globs) and minus the
owner's opt-outs, in both `tools/list` and `tools/call`. A tool the token may
not use is hidden like one that does not exist: `tools/call` answers it with
the same `Unknown tool` error (-32601) as for a name no backend has (with
HTTP 404 on the stateless 2026-07-28 path, as rmcp maps that code), and a
backend outside the policy is listed nowhere. Without a valid token in
multi-user mode the endpoints answer 401 with `WWW-Authenticate: Bearer`. In
multi-user mode the shared `gateway.auth_token` is refused (401) and the
gateway warns at startup that it is ignored. Use service accounts instead, and
`axon-gateway admin login-link` for emergencies. A `[[tokens]]` entry becomes a
service account declared in config, under RBAC like any other principal. It
gets the tools of the config groups that list its `name` in
`service_accounts`, narrowed by its `allowed_tools` and `allowed_backends`. A
token in no group can call nothing, and the gateway warns about it at startup.
Its rate limit still applies. Logs name it `config:<name>`. Standalone (no
`[database]`), `auth_token` and `[[tokens]]` behave as before.

```toml
[[rbac.groups]]
name = "it"                        # [a-z0-9_-]+, 1 to 64 characters
description = "IT staff"
idp = [{ provider = "pocket", value = "it-staff" }]

[[rbac.grants]]
group = "it"                       # a declared group or "authenticated"
backend = "files"
include = ["*"]                    # default
exclude = ["delete_*"]
read_only = false                  # only tools with readOnlyHint pass
mandatory = false                  # users cannot hide these tools

[[rbac.role_bindings]]
role = "auditor"
group = "it"
```

Roles are built in. Everyone is a `member` (add personal backends); users the
provider marks in `admin_groups` are `admin` (everything). Bindings add more:

| Role            | Allows                                                    |
| --------------- | --------------------------------------------------------- |
| `admin`         | everything, including managing groups, grants and roles   |
| `backend-admin` | view and manage backends, manage the catalog              |
| `auditor`       | read the audit log, view backends                         |
| `member`        | add personal backends                                     |

Besides `config.toml`, admins manage the same things at runtime (the API below
and the dashboard's admin pages). Those entries live in the database and are listed
next to the config ones. Entries from `config.toml` are read-only: a write to
them answers 409, and a config group wins over a database group of the same
name. Every change is written to the audit log in the same transaction. A
change applies at once on the replica that took it; other replicas reload the
database rows every 30 s.

All `/api/v1` routes need a dashboard session (the session cookie); without one
they answer 401 `{"error": "not signed in"}`. Writes also need the session's
CSRF token in `X-CSRF-Token`. Outside multi-user mode they answer 404. Errors
are `{"error": "..."}` with 400 (invalid input, bad JSON), 403, 404, 409 or 503
(database unavailable); creates answer 201, deletes 204.

| Endpoint                                      | Method        | Needs                       |
| --------------------------------------------- | ------------- | --------------------------- |
| `/api/v1/me`                                  | GET           | a session                   |
| `/api/v1/groups`                              | GET, POST     | reads `groups.manage` or `audit.read`; writes `groups.manage` |
| `/api/v1/groups/{name}`                       | GET, PATCH, DELETE | reads as above; writes `groups.manage` |
| `/api/v1/groups/{name}/idp-mappings`          | POST, DELETE  | `groups.manage`             |
| `/api/v1/groups/{name}/members/{user_id}`     | PUT, DELETE   | `groups.manage`             |
| `/api/v1/grants`                              | GET, POST     | reads `groups.manage` or `audit.read`; writes `groups.manage` |
| `/api/v1/grants/{id}`                         | DELETE        | `groups.manage`             |
| `/api/v1/role-bindings`                       | GET, POST     | reads `groups.manage` or `audit.read`; writes `roles.manage` |
| `/api/v1/role-bindings/{id}`                  | DELETE        | `roles.manage`              |
| `/api/v1/users?limit=`                        | GET           | `users.manage` or `groups.manage` (default 100, max 500) |
| `/api/v1/audit?limit=&before=`                | GET           | `audit.read` (default 50, max 200; `before` is an entry id) |

Bodies: group `{"name", "description"}` (PATCH: `{"description"}`, null clears),
IdP mapping `{"provider", "value"}` (provider is a configured `[[auth.oidc]]`
id), grant like `[[rbac.grants]]` (`group`, `backend`, optional `include`,
`exclude`, `read_only`, `mandatory`), role binding `{"role", "group"}` or
`{"role", "user_id"}`. Lists answer `{"groups": [...]}`, `{"grants": [...]}`,
`{"role_bindings": [...]}`, `{"users": [...]}` and `{"entries": [...]}`.

The dashboard has the same under `/ui/admin` (an "Admin" link in the user bar,
shown to users with `groups.manage` or `audit.read`): groups with their IdP
mappings and members at `/ui/admin/groups/{name}`, grants, role bindings and
the audit log at `/ui/admin/audit`. It goes through the same service as the
API, so permissions, validation, audit entries and the read-only config rows
behave the same; users without a write permission see the tables only.

### Personal access tokens and service accounts

A client that cannot log in through a browser, such as an agent, calls `/mcp`
with a personal access token (PAT):

```text
Authorization: Bearer axon_pat_<public id>_<secret>
```

The public id is 16 hex characters and names the token in lists and the audit
log; the secret is 64. Only a SHA-256 of the secret is stored, so the
plaintext is shown once, in the response (or dashboard box) that creates the
token, and cannot be recovered: revoke a lost token and make a new one.

A PAT acts as its owner. It gets what the owner's groups grant, minus the
tools the owner hid on "My tools", narrowed by the token's own scope:

- `scope_backends` limits it to those backends (exact names),
- `scope_tools` limits it to tools matching one of the globs, written over the
  namespaced name (`files_read_*`),
- an empty or missing list does not narrow, and when both are set a tool must
  pass both.

A scope can only narrow, never widen: a tool the owner may not use stays
hidden whatever the scope says. A token also follows its owner's later
changes (a group left, a grant removed) at once.

Lifetimes: a token expires after `expires_in_days` (default 30). A user may ask
for at most 90 days, a service account's token for at most 365. A token stops
working when it expires, is revoked, or its owner is disabled. A user's tokens
are also suspended while the user has not logged in to the dashboard for 90
days, and work again after the next login. Each token shows its state
(active, expired, revoked) and when it was last used (updated about once a
minute).

Every signed-in user manages their own tokens, on `/ui/tokens` (a "Tokens" link
in the user bar) or through the API: create with a name, an expiry and an
optional scope, then copy the plaintext from the box that shows it once, and
revoke when done. Backends to narrow to are offered from the ones the user is
granted. A token's secret is never shown again, to anyone, so an admin
cannot read a user's token either.

A service account is a principal owned by admins (`service_accounts.manage`,
held by the `admin` role) for agents and scripts that belong to no person. It
has a name (`[a-z0-9_-]+`, like a group), an optional description, and no
login. Because it is a user row of its own kind, it joins groups like a user:
add it on a group's page (the member list marks it as a service account) or
with `PUT /api/v1/groups/{name}/members/{id}`, and give that group grants. A group
declared in `config.toml` cannot take database members (the write answers 409),
but lists service accounts by name in `service_accounts`, which applies to
database accounts and `[[tokens]]` entries of that name alike. A database
account cannot take the name of a `[[tokens]]` entry (409), so it cannot
inherit that entry's config groups. Listing a database account by name trusts
whoever holds `service_accounts.manage` to create it. Its groups are
exactly its memberships, without the built-in `authenticated` group. Disabling
the account stops all its tokens at once (enabling it restores them), and
deleting it removes its tokens and memberships. Each token records when it was
last used and from which address: the peer, or, when the peer is a loopback or
private address (a reverse proxy), the rightmost `X-Forwarded-For` entry. Admins
manage accounts on `/ui/admin/service-accounts` (linked from `/ui/admin`).

```toml
[[rbac.groups]]
name = "agents"
service_accounts = ["ci-bot", "hermes"]
```

| Endpoint                                                 | Method           | Needs                      |
| -------------------------------------------------------- | ---------------- | -------------------------- |
| `/api/v1/tokens`                                         | GET, POST        | a session                  |
| `/api/v1/tokens/{id}`                                    | DELETE           | a session (own tokens)     |
| `/api/v1/service-accounts`                               | GET, POST        | `service_accounts.manage`  |
| `/api/v1/service-accounts/{id}`                          | PATCH, DELETE    | `service_accounts.manage`  |
| `/api/v1/service-accounts/{id}/tokens`                   | GET, POST        | `service_accounts.manage`  |
| `/api/v1/service-accounts/{id}/tokens/{token_id}`        | DELETE           | `service_accounts.manage`  |

Bodies: a token `{"name", "expires_in_days", "scope_backends", "scope_tools"}`
(only `name` is required), a service account `{"name", "description"}`, a PATCH
`{"disabled": true}` or `{"disabled": false}`. `POST` of a token answers 201
with its metadata (`id`, `public_id`, `name`, `prefix`, `scope_backends`,
`scope_tools`, `created_at`, `expires_at`, `last_used_at`, `state`) and, only
there, `plaintext`. Lists answer `{"tokens": [...]}` and
`{"service_accounts": [...]}`. A bad name, expiry (0 or beyond the maximum) or
scope answers 400. Revoking a token that is not yours, or not live, answers 404.
Token and service account changes are written to the audit log
(`token.create`, `token.revoke`, `service_account.*`) without any secret.

```sh
# a token for an agent, 30 days, only the Prometheus tools
curl -X POST https://axon.homelab.internal/api/v1/tokens \
  -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"name": "agent", "scope_tools": ["prom_*"]}'
```

**Disabling users.** Admins with `users.manage` (the `admin` role) list human
users on `/ui/admin/users` and disable or re-enable them. A disabled user's
sessions end at once, the login is refused, and their personal access tokens
stop working until re-enabled. An admin cannot disable themselves. API:
`GET /api/v1/users` (each user has `disabled`), and
`PATCH /api/v1/users/{id}` with `{"disabled": true|false}`, which needs
`users.manage`. Audit actions are `user.disable` and `user.enable`.

**Break-glass login.** When the identity provider is down, run on a host that
reaches the database:

```sh
axon-gateway admin login-link --config /path/to/config.toml
```

It prints `<base_url>/auth/break-glass?code=...`. The link works once and
expires after 15 minutes. Opening it shows a confirmation button; confirming
starts a one-hour admin session as the built-in user "Break-glass admin".
Creating the link (`break_glass.link_created`) and using it
(`break_glass.login`) are audited. To switch break-glass off, disable that user
on `/ui/admin/users`. `--config` defaults to `AXON_GATEWAY_CONFIG`, then
`config.toml`.

### Resource-server mode (IdP access tokens)

An agent that already holds a JWT access token from the identity provider (a
client-credentials token, or a user's token from another app) can call `/mcp`
with it as a bearer token, so it needs no PAT. Turn it on per provider:

```toml
[[auth.oidc]]
id = "pocket"
issuer = "https://id.example.com"
client_id = "axon"
accept_access_tokens = true          # default false
# access_token_audience = "api://axon"   # default: client_id
```

The gateway verifies the signature against the provider's JWKS (asymmetric
algorithms the provider advertises only, keys fetched again on an unknown
`kid`), then `iss` (exactly the configured issuer), `aud` (a string or an array
that holds the audience), `exp` (required) and `nbf`/`iat`, with 60 seconds of
clock leeway. A token with a `nonce` claim or the type `ID` is an ID token and
is refused, so the token of a dashboard login cannot be replayed as a bearer
token. Any failure answers 401. The `[database]` every provider needs also
stores the users and bindings below.

The default audience is the provider's `client_id`. Entra ID v2 access tokens
carry the application id of the API as `aud`, so use the same app registration
as the dashboard login, and under "Expose an API" give it an application ID URI
and a scope; clients then request that scope. Other providers need a client
or resource whose tokens name `client_id` (or whatever
`access_token_audience` says) in `aud`.

Who the token acts as is decided by its `iss` and `sub`:

1. a **service account** bound to that issuer and subject, with the policy of
   the account (its group memberships); else
2. the **user** with that issuer and subject, who must have logged in to the
   dashboard once, with the policy of that user. The groups claim of the token
   (`groups_claim`) replaces the groups stored at the last login when the token
   has one; without it the stored groups apply.

Nothing else matches: an unknown subject, a disabled user or service account,
or a user who has not logged in for 90 days answers 401. The token is not
narrowed by a scope; the principal gets everything its groups grant, minus a
user's hidden tools.

A service account is bound on `/ui/admin/service-accounts` (the "JWT bindings"
list under each account: pick one of the issuers that accept access tokens,
enter the `sub` of the client and press "Bind subject"), or through the API
with `service_accounts.manage`:

```sh
# the client-credentials app "ci-bot-app" has sub = its client id at most IdPs
curl -X POST https://axon.homelab.internal/api/v1/service-accounts/$ID/jwt-bindings \
  -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"issuer": "https://id.example.com", "subject": "ci-bot-app"}'
```

`GET` on the same path lists the bindings and `DELETE
/api/v1/service-accounts/{id}/jwt-bindings/{binding_id}` removes one. The
issuer must be a configured provider with `accept_access_tokens` (else 400), and
a subject can be bound once per issuer (else 409). Creating and deleting a
binding is audited (`service_account.jwt_binding.create` and `.delete`).
Metrics count these requests as `axon_authn_total{method="jwt"}`.

### MCP OAuth (for MCP clients)

With multi-user mode on, the gateway is also an OAuth 2.1 authorization server
for MCP clients (Claude Code, Claude Desktop, editors), so a user signs in
through the browser instead of pasting a PAT. An unauthenticated `/mcp` request
gets a 401 whose `WWW-Authenticate` names `resource_metadata`; the client
discovers the rest from there. `base_url` must be the gateway's public URL,
since it is the issuer and the resource.

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource[/<path>]` | RFC 9728 resource metadata |
| `/.well-known/oauth-authorization-server` | RFC 8414 AS metadata |
| `/oauth/register` | RFC 7591 dynamic client registration |
| `/oauth/authorize` | consent page after the dashboard login (PKCE S256; `resource` defaults to `<base_url>/mcp`) |
| `/oauth/token` | code and refresh-token grants |
| `/oauth/revoke` | RFC 7009 revocation |

- Access tokens (`axon_oat_`) last 1 hour; refresh tokens (`axon_ort_`) last
  30 days and rotate on every use, and a reused refresh token ends the grant.
  Codes last 60 seconds and are single use. Tokens are stored hashed.
- Clients are public (no secret). They register by DCR, or use an `https://`
  client-id metadata document (CIMD). Redirect URIs must be `https`, or `http`
  to `127.0.0.1`, `[::1]` or `localhost`. Registrations unused for 30 days
  expire.
- A token is bound to the resource it was issued for and acts as the user who
  approved it, with that user's roles. It is accepted on `/mcp` only, not on
  `/api/v1`.
- Users see and end their grants on **Connected apps** (`/ui/me/apps`) or via
  `GET`/`DELETE /api/v1/me/oauth-grants[/{id}]`; admins use
  `/api/v1/admin/oauth-grants[/{id}]`.

### Upstream OAuth and identity passthrough

Besides the header values of `credential_mode = "per_user"`, a backend can
authenticate each user in two more ways. Both need multi-user mode and a
database, make the backend a catalog entry (a user needs a grant on it, like
any other), give every user their own connection, and keep every token sealed
with the gateway KEK (see [Encryption](#personal-mcp-servers-and-the-catalog)).

**OAuth (`credential_mode = "oauth"`).** Each user connects their own account
at the backend's authorization server, for a backend that speaks MCP's
authorization spec (OAuth 2.1 with PKCE and protected resource metadata). The
gateway finds the authorization server from the backend's URL and picks a
client in this order:

1. the static client of `[backends.oauth]`;
2. the gateway's client ID metadata document, `<base_url>/oauth/upstream/client.json`,
   when the authorization server supports those;
3. dynamic client registration, once per backend, shared by all users (a
   registered secret is sealed too).

```toml
[[backends]]
name = "tracker"
url = "https://mcp.tracker.example.com/mcp"
transport = "http"
credential_mode = "oauth"

# optional: a client registered by hand; leave the table out to use the
# metadata document or registration
[backends.oauth]
client_id = "axon-gateway"
client_secret_env = "TRACKER_CLIENT_SECRET"   # leave out for a public client
scopes = ["read", "write"]                    # empty: what the backend advertises
```

A user presses **Connect** on `/ui/catalog` (or calls `POST
/api/v1/me/connections/{backend}`, below), signs in at the backend and is sent
back to `<base_url>/oauth/upstream/callback`, which needs their dashboard
session. Register that URL as a redirect URI of a static client. The request
lasts 10 minutes and is single use; an authorization server that returns `iss`
is checked against the one the gateway started with. The tokens are refreshed
shortly before they expire; if a refresh fails the catalog shows "Reconnect
needed" with the reason, and **Disconnect** removes them. Connecting again
replaces the old connection on every replica. `base_url` must be the gateway's
public URL, since the redirect URI and the metadata document are built from it.

**Identity passthrough (`credential_mode = "passthrough"`).** The user signs in
once, and the gateway trades the identity provider's token for one the backend
accepts, with no extra step for the user. The catalog shows "Uses your sign-in".

```toml
[[auth.oidc]]
id = "entra"
issuer = "https://login.microsoftonline.com/<tenant>/v2.0"
client_id = "axon"
client_secret_env = "AXON_OIDC_SECRET"
accept_access_tokens = true
# offline_access keeps a refresh token from the dashboard login, and the
# gateway's own API scope makes the token's audience the gateway (Entra OBO)
scopes = ["openid", "profile", "email", "offline_access", "api://axon/access"]

[[backends]]
name = "reports"
url = "https://reports.example.com/mcp"
transport = "http"
credential_mode = "passthrough"

[backends.passthrough]
grant = "entra_obo"                  # or "token_exchange" (RFC 8693)
provider = "entra"                   # id of the [[auth.oidc]] provider
scope = "api://reports/.default"     # required for entra_obo
# audience = "reports"               # token exchange `audience`
# resource = "https://reports.example.com"   # token exchange `resource`
```

`entra_obo` runs Entra's on-behalf-of flow and needs `scope` and a
`client_secret_env` on the provider; `token_exchange` posts an RFC 8693 request
to the provider's token endpoint with `audience`, `scope` and `resource` when
set. The subject token it starts from is the user's identity provider token:

- the access token of a request that came in as a resource-server JWT (see
  above; the provider needs `accept_access_tokens = true`), or else
- the refresh token the provider gave at the dashboard login, which the
  gateway keeps sealed. The provider's `scopes` must include `offline_access`
  for it to give one, and for Entra OBO a scope of the gateway's own API, so
  that the token's audience is the gateway. Users who signed in before the
  change sign in again once.

A user with neither (no recent request with a JWT, no stored refresh token)
gets no tools of that backend until they sign in again.

**In the catalog.** An admin can also create OAuth entries in the dashboard or
with `POST /api/v1/catalog`: `auth` is `"fields"` (the default) or `"oauth"`,
and an OAuth entry takes no `credential_fields`. Its optional settings are
`oauth_client_id`, `oauth_scopes` (an array in the API, space or comma
separated in the form) and `oauth_client_secret`. The secret is write-only and
never returned (`oauth_client_secret_set` says whether one is stored): on
`PATCH`, leaving it out or `null` keeps the stored one and `""` clears it; the
edit form keeps it when the field is empty and has a "clear" box. Passthrough
entries are config-only.

```sh
curl -X POST https://axon.example.com/api/v1/catalog \
  -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"name": "tracker", "url": "https://mcp.tracker.example.com/mcp",
       "auth": "oauth", "oauth_scopes": ["read", "write"]}'
```

**For users.** `/api/v1/catalog` lists each entry with `"auth": "fields" |
"oauth" | "passthrough"`. The connection endpoints are session-only like the
other `/api/v1/me/*` routes, and writes need `X-CSRF-Token`:

| Endpoint | Method | Does |
| --- | --- | --- |
| `/api/v1/me/connections` | GET | `{"connections": [{backend, issuer, expires_at, last_error, last_error_at, created_at}]}`, never a token |
| `/api/v1/me/connections/{backend}` | POST | optional body `{"return_to": "/ui/catalog"}` (a local path); answers `{"authorize_url": "..."}` to send the browser to |
| `/api/v1/me/connections/{backend}` | DELETE | 204, or 404 when there was no connection |

A backend that cannot be connected this way answers 404, a client secret the
gateway cannot read or an authorization server that cannot be used 502.

## Tool-call audit

In multi-user mode every `tools/call` made by a user or service account
principal is recorded. Legacy `[[tokens]]` callers outside multi-user mode and
the `auth_token` are not.

**What is recorded.** One row per call: the time, the user, the principal
label, the token id and its kind (`pat`, or `config_token` for a config
`[[tokens]]` principal), the backend, the original tool name, the outcome, the
JSON-RPC error code and message, the duration, the trace id, the client IP and
the `User-Agent` (cut at 200 characters). The outcome is `ok`, `error` (a
JSON-RPC error, which includes a tool the principal may not call: it is
recorded under its real backend and name with code `-32601`) or `tool_error`
(the tool answered with `isError`). Tool results are never stored, and neither
are arguments in the log output.

**Arguments** are kept apart from the row and expire sooner. What is stored
depends on the capture mode:

- the default follows the tool's MCP annotations: `readOnlyHint: true` stores
  no arguments, anything else (an unannotated tool counts as potentially
  destructive) stores them redacted,
- `redacted` masks the value of every key containing `password`, `passwd`,
  `secret`, `token`, `authorization`, `api_key`, `apikey`, `cookie`,
  `credential` or `private_key` (case-insensitive, at any depth) with
  `[redacted]`,
- `full` keeps every value, `none` keeps nothing,
- in every mode a string longer than 2 KiB is truncated with a
  `[truncated]` marker.

**Capture rules** override the default per backend (or `*` for all) and tool
glob. A rule has a mode (`none` | `redacted` | `full`) and optional drop keys
that are removed at any depth in `redacted` and `full` mode. The most specific
matching rule wins: an exact backend over `*`, then an exact tool name over a
glob, then the longer pattern, then the newer rule. A rule change applies to
the next call of the process that made it; another replica picks it up within
30 seconds.

**Retention** defaults to 30 days for arguments and 365 days for the call
rows. Admins change both on `/ui/admin/audit-settings` (1 to 3650 days); the
purge runs hourly.

**Permissions.** `audit.read` (role `auditor`) lists calls, rules and settings.
Reading stored arguments needs `audit.read_sensitive`, and every read is itself
audited as `audit.arguments_read`. Changing rules and settings needs
`gateway.admin`. The `admin` role has all three.

| Endpoint                                  | Method       | Needs                  |
| ----------------------------------------- | ------------ | ---------------------- |
| `/api/v1/tool-calls`                      | GET          | `audit.read`           |
| `/api/v1/tool-calls/{id}`                 | GET          | `audit.read`           |
| `/api/v1/tool-calls/{id}/arguments`       | POST         | `audit.read_sensitive` |
| `/api/v1/audit/settings`                  | GET, PUT     | `audit.read`, `gateway.admin` to change |
| `/api/v1/audit/capture-rules`             | GET, POST    | `audit.read`, `gateway.admin` to create |
| `/api/v1/audit/capture-rules/{id}`        | DELETE       | `gateway.admin`        |

`GET /api/v1/tool-calls` takes the filters `user`, `backend`, `tool` and
`outcome`, plus `before` and `limit` (up to 200) to page; `next_before` in the
answer is the `before` of the next page. A rule is
`{"backend": "files", "tool_pattern": "read_*", "mode": "redacted", "drop_keys": ["body"]}`;
settings are
`{"arguments_retention_days": 30, "metadata_retention_days": 365}`. Like the
other write routes they need the session's `X-CSRF-Token`. The pages are
`/ui/admin/tool-calls` and `/ui/admin/audit-settings`.

Two metrics watch the writer, which batches events and never blocks a call:
`axon_audit_dropped_total` counts events dropped because the queue was full,
and `axon_audit_write_errors_total` counts batches the database refused.

**Data protection.** A call log ties a person to what they did, so it is
personal data (GDPR) and, where staff use the gateway, a means to monitor
their behaviour or performance: in Germany that needs the works council's
agreement (BetrVG section 87(1) no. 6). The defaults store metadata and
redacted arguments for a short time. Settle purpose, access and retention
with the data protection officer and the works council before enabling `full`,
and keep the retention as short as the purpose allows.

## Usage

The usage pages show tool-call activity from the [tool-call audit](#tool-call-audit):
totals with p50 and p95 latency, calls per day, calls per backend and the ten
most called tools. The window is `days`, 1 to 90 (default 30), in whole UTC
days; any other value is refused with 400.

| UI page                      | JSON                                |
| ---------------------------- | ----------------------------------- |
| `GET /ui/me/usage`           | `GET /api/v1/me/usage?days=`        |
| `GET /ui/admin/usage`        | `GET /api/v1/admin/usage?days=`     |
| `GET /ui/admin/usage/{user_id}` | `GET /api/v1/admin/usage/{user_id}?days=` |

The first row is the signed-in user's own usage; the admin rows list users by
calls and show one user. The admin views need the `audit.read` permission. The
numbers come from the audit, so they are empty when the audit is off.

## User toolsets

A user keeps their own named toolsets, apart from the config ones above, on
`/ui/toolsets` or through the API (a dashboard session, and the `X-CSRF-Token`
for writes). A toolset is a name, a description and two narrowings: `tools`
(globs over the namespaced tool name) and `backends` (exact names); an empty
list does not narrow.

| Endpoint                | Method | Description                                    |
| ----------------------- | ------ | ---------------------------------------------- |
| `/api/v1/toolsets`      | GET    | List your toolsets                             |
| `/api/v1/toolsets`      | POST   | Create one: `{"name", "description", "tools", "backends"}` |
| `/api/v1/toolsets/{id}` | GET    | One toolset                                    |
| `/api/v1/toolsets/{id}` | PATCH  | Change the fields present in the body          |
| `/api/v1/toolsets/{id}` | DELETE | Delete it; 409 while a valid token is pinned to it |

Only your own toolsets exist for you: someone else's id is a 404.

- **Pinning.** Create a token with `"toolset_id"` (`POST /api/v1/tokens`) to pin
  it. The pin is a live link, not a copy: the token may use what the owner's
  policy allows, inside the toolset, inside the token's own scope
  (policy ∩ toolset ∩ scope), and an edit to the toolset applies to the token
  at once. A service account token cannot be pinned.
- **Endpoint.** `/mcp/toolset/{name}` resolves a toolset of the caller's own
  with that name first and treats it like a pinned one: it narrows both the
  tool list and the calls. Without such a toolset it serves the config toolset
  of that name, which only filters the list.
- **Deleting** a toolset that a still-valid token is pinned to answers 409.
  Revoke or re-pin the token first.

## Personal MCP servers and the catalog

Users bring their own MCP servers, and admins publish backends that each user
connects with their own credential. Both need a database and multi-user mode,
and are on by default (`[personal_backends] enabled = true`). Their
connections are per user and per replica; nothing here touches the shared
backends.

```toml
[personal_backends]
enabled = true
max_per_user = 10          # personal servers + catalog credentials
max_calls_per_minute = 0   # 0 = off
max_instances = 500        # live per-user connections, all users
egress_allow = []          # see Egress guard
egress_deny = []

[[backends]]
name = "notes"
url = "https://notes.example.com/mcp"
transport = "http"
credential_mode = "per_user"

[[backends.credential_fields]]
name = "api_token"
label = "API token"
header = "Authorization"
prefix = "Bearer "
```

**Personal servers.** Any human user (the built-in Member role has
`personal_backends.create`) adds a Streamable HTTP MCP server with a prefix and
optional headers. stdio stays admin-only: config plus `allow_stdio`. Its tools
appear as `<prefix>_<tool>` for that user only. No RBAC grant is needed, but
the user's opt-outs, a token's scope and a pinned toolset still apply, so the
user's personal access tokens see the tools within their scope. A shared tool
wins a name collision. The prefix matches `^[a-z][a-z0-9-]{1,30}$`, is not one
of `axon`, `mcp`, `admin`, `api`, `system`, `gateway`, `internal` or
`catalog`, and must neither equal a shared or catalog name nor clash with one
(`<prefix>_` is a prefix of a shared tool name, or the other way round). On
save the egress guard is a hard reject; then the gateway connects, lists the
tools and returns the result, and the server is saved either way. Header
values are write-only: they are sealed and never returned or rendered. Admins
(`users.manage`) list, disable and delete anyone's personal servers and never
see header values.

**Catalog.** A catalog entry is a backend whose users bring their own
credential. Define it in the config as a `[[backends]]` entry with
`credential_mode = "per_user"` and one `[[backends.credential_fields]]` per
value (`name`, `label`, `header`, `prefix`): the gateway sends the header with
`prefix` plus what the user entered. Config entries are read-only in the UI
and API (409). Or create entries with `catalog.manage` through the API or the
UI. A user sees an entry only if their RBAC grants cover that backend (admins
see all). Entering a credential gives them their own connection; its tools
`<entry>_<tool>` need a normal grant. Catalog entries get no egress check.
`credential_mode` says whose credentials a backend uses: `shared` (the default,
one connection with the backend's own `auth_token` and `headers`), `per_user`
(the values above), `oauth` or `passthrough` (see
[Upstream OAuth and identity passthrough](#upstream-oauth-and-identity-passthrough)).

| Endpoint                                         | Method        | Needs                    |
| ------------------------------------------------ | ------------- | ------------------------ |
| `/api/v1/me/backends`                            | GET, POST     | `personal_backends.create` to add |
| `/api/v1/me/backends/{prefix}`                   | PATCH, DELETE | own server               |
| `/api/v1/me/credentials`                         | GET           | your credentials and the entries you may use |
| `/api/v1/me/credentials/{entry}`                 | PUT, DELETE   | a grant on the entry     |
| `/api/v1/me/connections`                         | GET           | your OAuth connections   |
| `/api/v1/me/connections/{backend}`               | POST, DELETE  | a grant on the entry     |
| `/api/v1/catalog`                                | GET, POST     | `catalog.manage` to create |
| `/api/v1/catalog/{name}`                         | PATCH, DELETE | `catalog.manage`         |
| `/api/v1/admin/personal-backends`                | GET           | `users.manage`           |
| `/api/v1/admin/personal-backends/{owner_id}/{prefix}` | PATCH, DELETE | `users.manage`      |

A personal server is `{"prefix", "url", "headers": {"name": "value"}}` (PATCH:
`url`, `enabled`, `headers`) and the answer carries the connection `test`. A
credential is `{"values": {"<field name>": "value"}}`. A catalog entry is
`{"name", "description", "url", "credential_fields": [...]}`. Like the other
write routes they need the session's `X-CSRF-Token`; without the personal hub
(no database, or `enabled = false`) they answer 404.

**Encryption.** Header and credential values are sealed per secret with a
random data key (AES-256-GCM); the data key is wrapped by a key-encryption key
(KEK), derived with HKDF-SHA256 from `AXON_KEK_FILE` (a path) or `AXON_KEK` (the
text). It has one line per KEK, `[id:]secret`, a secret of at least 32
characters, and the first line is the active key. With `[database]` and
`[personal_backends] enabled = true` the gateway refuses to start without one.
Generate a secret with `pwgen -s 48 1`.

To rotate, put the new key first and keep the old line, restart, run
`axon-gateway admin rewrap-secrets --config <path>` (it rewraps the data keys
only and prints how many it moved), then drop the old line.

**Egress guard.** A personal server URL is typed in by a user, so the gateway
checks it: `http` or `https` only, no userinfo, every resolved address is
checked and the first one is pinned for the connection (no second lookup), no
redirects and no proxy. The order is `egress_deny`, then `egress_allow`, then
the built-in default deny, then allow. The default deny covers `0.0.0.0/8`,
`10.0.0.0/8`, `100.64.0.0/10` (CGNAT), `127.0.0.0/8`, `169.254.0.0/16`
(link-local and cloud metadata), `172.16.0.0/12`, `192.0.0.0/24`,
`192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`, `::/128`,
`::1/128`, `fc00::/7`, `fe80::/10` and `ff00::/8`. A rule is a CIDR, an IP, a
host or `*.host` (subdomains only, not the apex). To reach a LAN:
`egress_allow = ["10.0.0.0/8"]`.

**Quotas.** `max_per_user` caps personal servers plus catalog credentials per
user. `max_calls_per_minute` limits a user's calls to personal and catalog
backends; shared calls never count. `max_instances` caps the live per-user
connections of all users on a replica; the least recently used users are
evicted and reconnect on their next call.

**Audit.** A personal tool call is recorded with the user, tool, prefix,
outcome and latency, never its arguments or result. Catalog calls are audited
like shared ones.

**Replicas.** Changes travel on the existing `NOTIFY` fan-out (kinds `user`
and `catalog`), see [Multiple replicas](#multiple-replicas).

**Limits.** Toolset endpoints, resources and prompts serve shared backends
only.

## Tracing

Logs go to stdout (`AXON_LOG_JSON=1` for JSON, `RUST_LOG` to filter). Set
`OTEL_EXPORTER_OTLP_ENDPOINT` to also export traces over OTLP; the standard
`OTEL_*` variables apply (`OTEL_EXPORTER_OTLP_PROTOCOL` = `grpc` or
`http/protobuf`, `OTEL_SERVICE_NAME`, default `axon-gateway`,
`OTEL_TRACES_SAMPLER`). Every HTTP request gets a server span, and an incoming
W3C `traceparent` header becomes its parent.

The gateway forwards the current trace context to backends in the `_meta` of
the MCP request (`traceparent`, and `tracestate` when there is one) for
`tools/call`, `resources/read` and `prompts/get`, so a backend's spans join the
caller's trace. It does not set an HTTP `traceparent` header on backend
requests.

## Metrics

Prometheus metrics are exposed at `/metrics`:

- `axon_tool_calls_total` - Tool call counter by backend/tool
- `axon_tool_call_duration_seconds` - Tool call latency histogram
- `axon_tool_call_errors_total` - Tool call error counter
- `axon_backend_connections{backend,state}` - Backend connection state gauge (1 for the current state)
- `axon_requests_total` - HTTP request counter
- `axon_health_checks_total` - Health check counter
- `axon_resource_reads_total` - Resource read counter
- `axon_prompt_gets_total` - Prompt get counter
- `axon_backend_up` - Gauge per backend, 1 when the last connect or health probe succeeded
- `axon_audit_dropped_total` - Tool-call audit events dropped on a full queue
- `axon_audit_write_errors_total` - Tool-call audit batches the database refused
- `axon_mcp_requests_total{method,principal_type}` - MCP requests by `Mcp-Method`; `principal_type` is `open`, `legacy_token`, `service` (config `[[tokens]]` accounts and service-account tokens) or `pat`
- `axon_user_tool_calls_total{user,backend,outcome}` - Tool calls per user; `outcome` is `ok`, `error` or `denied`, `backend` is `personal` for personal backends; only callers with an owner user are counted
- `axon_authn_total{method,result}` - Authentication attempts; `method` is `pat`, `service_token`, `legacy_token`, `session`, `break_glass` or `open`; `result` is `ok`, `invalid`, `expired`, `disabled` or `rate_limited`
- `axon_authz_denied_total{reason}` - Denied calls; `reason` is `tool`, `backend`, `quota` or `rate_limit`
- `axon_backend_inflight_calls{backend}` - Tool calls in flight per backend
- `axon_oidc_requests_total{provider,op,result}` and `axon_oidc_request_duration_seconds{provider,op}` - Requests to the identity provider; `op` is `discovery`, `jwks` or `token`, `result` is `ok` or `error`
- `axon_oidc_provider_up{provider}` - 1 when the last request to the provider succeeded

Sampled every 30 s, per replica:

- `axon_active_sessions{kind}` - Sessions, `kind` is `mcp` or `ui`
- `axon_tokens_active{kind}` - Tokens neither revoked nor expired, `kind` is `pat` or `service`
- `axon_db_pool_connections{state}` and `axon_db_pool_max` - Database pool, `state` is `idle` or `used`
- `axon_db_up` - 1 when the database answers
- `axon_user_backends{state}` - Per-user backends by state (`connected`, `idle`, `failed`, `other`)

The `user` label of `axon_user_tool_calls_total` is the user's UUID, so its
cardinality is bounded by the number of users.

The `idle` value of the backend state gauge counts backends closed by the idle
timeout. Personal and catalog connections are not labelled in metrics.

## Gateway Settings

These `[gateway]` settings control what the gateway runs and answers to:

```toml
[gateway]
bind = "0.0.0.0:8080"
base_url = "https://axon.example.com"
allow_stdio = false # default
allowed_hosts = ["axon.internal.example.com", "axon.internal.example.com:8443"]
idle_timeout_secs = 300 # default
```

- `allow_stdio` (default `false`): stdio backends spawn processes inside the
  gateway, so they are off unless you turn them on. A config with a
  `transport = "stdio"` backend and `allow_stdio = false` fails to load, and
  the error names the backends.
- `allowed_hosts` (default empty): extra `Host` names, or `host:port` pairs,
  that `/mcp` and the toolset endpoints accept. `localhost`, `127.0.0.1`, `::1`
  and the host of `base_url` (with its port, when it has one) are always
  accepted.
- `idle_timeout_secs` (default `300`): a backend connection with no call for
  this long is closed; `0` keeps it always connected. A backend's own
  `idle_timeout_secs` wins, and stdio backends default to `0`. An idle backend
  keeps its cached tools, shows state `idle` in the UI and metrics, and
  reconnects on the next call. Shared backends keep their health probes while
  idle (on a short-lived connection). Personal and catalog connections are
  passive: no probes, health comes from call outcomes, and the UI shows
  `last_ok_at` and `last_error`.

> **Upgrading:** standalone setups that run stdio backends must now set
> `allow_stdio = true` in `[gateway]`; without it the config no longer loads.
> Setups behind a reverse proxy should check that `base_url` is the public URL
> and add any other name the proxy answers to (an alias, a second vhost) to
> `allowed_hosts`.

### stdio backends on Kubernetes

Leave `allow_stdio` off in a cluster: a process spawned inside the gateway pod
shares its container, its secrets and its resource limits. Run the stdio
server in its own Deployment instead, behind a stdio-to-Streamable-HTTP bridge,
and point axon at the Service over HTTP:

```toml
[[backends]]
name = "local-tool"
url = "http://local-tool.tools.svc:8000/mcp"
transport = "http"
```

## Environment Variable References in Config

You can reference environment variables in `config.toml` using `${VAR_NAME}` placeholders.

Example:

```toml
[gateway]
bind = "0.0.0.0:8080"
auth_token = "${AXON_GATEWAY_TOKEN}"
allow_stdio = true # needed for the stdio backend below

[[tokens]]
name = "claude-agent"
token = "${CLAUDE_AGENT_TOKEN}"

[[backends]]
name = "secure-api"
url = "https://example.com/mcp"
transport = "http"
auth_token = "${SECURE_API_TOKEN}"

[[backends]]
name = "local-tool"
command = "/usr/local/bin/mcp-tool"
transport = "stdio"
env = { API_KEY = "${OPENAI_API_KEY}" }
```

Resolution rules:

- Placeholders are resolved at config load time
- Missing variables are a hard error (startup/reload fails)
- Process environment variables take precedence over `.env`
- A `.env` file in the same directory as `config.toml` is loaded automatically

## Current Status

Phase 1 (MVP) is complete:

- [x] **Real rmcp integration**: Backend actors connect to real MCP servers
- [x] **Multiple transports**: SSE, HTTP (via streamable HTTP), and stdio supported
- [x] **Tool aggregation**: Tools fetched from backends and namespaced
- [x] **Tool forwarding**: `tools/call` forwarded to correct backend with real results

## TODO / Next Steps

Completed:

- [x] **Reconnection logic**: Automatic reconnect with exponential backoff (1s base, 5min max)
- [x] **Health checks**: Periodic pings to detect dead backends
- [x] **Hot reload**: Watch config file and update backends without restart
- [x] **Metrics**: Prometheus metrics for tool calls, latency, errors
- [x] **Tool filtering**: Support `allowed_tools` config per token/group
- [x] **Resource/Prompt proxying**: Forward MCP resources and prompts
- [x] **Multi-token auth**: Named tokens with fine-grained permissions
- [x] **Streamable HTTP**: MCP Streamable HTTP server (`/mcp`) with `notifications/tools/list_changed`

To make it production-ready:

- [ ] **OpenID/OAuth**: More auth options beyond simple tokens

## Project Structure

```
src/
├── main.rs      # Entry point
├── config.rs    # Config parsing
├── types.rs     # Core types (Tool, JsonRpc, etc.)
├── error.rs     # Error types (thiserror)
├── registry.rs  # Registry actor (tool aggregation)
├── backend.rs   # Backend actor (per-server connection via rmcp)
├── gateway.rs   # Gateway actor (orchestration)
├── crypto.rs    # Envelope encryption, KEK keyring and rotation
├── egress.rs    # Egress policy and SSRF guard for personal backend URLs
├── personal.rs  # Personal and catalog backends (per-user instances, quotas)
├── store/
│   └── personal.rs  # Personal backend, catalog and credential storage
├── server.rs    # HTTP server (axum), MCP Streamable HTTP
└── server/
    ├── personal_api.rs    # /api/v1 routes for personal servers and catalog
    ├── personal_ui.rs     # Dashboard pages for them
    └── personal_views.rs  # Their templates
migrations/
└── 0010_personal_backends.sql
```

## License

MIT
