# Axon Gateway

A lightweight, self-hosted MCP (Model Context Protocol) gateway that aggregates multiple MCP servers into a single endpoint.

## Features

- **Aggregation**: Combine tools from multiple MCP servers into one endpoint
- **Namespacing**: Tools are automatically prefixed with backend name (e.g., `homeassistant_turn_on`)
- **Multiple transports**: SSE, HTTP, and stdio backends supported
- **Multi-token auth**: Named API tokens with fine-grained permissions (allowed tools/backends)
- **Toolsets**: Expose subsets of tools via different path prefixes
- **Hot reload**: Config file watching with automatic backend updates
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

## API Endpoints

| Endpoint                                | Method | Description                                         |
| --------------------------------------- | ------ | --------------------------------------------------- |
| `/mcp`                                  | POST   | JSON-RPC endpoint (Streamable HTTP transport)       |
| `/mcp/sse`                              | GET    | SSE endpoint for streaming transport                |
| `/mcp/toolset/{toolset_name}`           | POST   | JSON-RPC endpoint filtered by toolset               |
| `/mcp/group/{toolset_name}`             | POST   | Deprecated alias of `/mcp/toolset/{toolset_name}`   |
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
| `/build`                                | GET    | Build/runtime metadata (version, pid, startup time) |
| `/health`                               | GET    | Health check                                        |
| `/livez`                                | GET    | Liveness probe (200 while the process is up)        |
| `/readyz`                               | GET    | Readiness probe (503 if the gateway actor stopped)  |
| `/status`                               | GET    | Gateway status (backend list, counts)               |
| `/status/detailed`                      | GET    | Detailed status with tool/resource/prompt lists     |
| `/status/toolsets`                      | GET    | List configured toolsets                            |
| `/status/groups`                        | GET    | Deprecated alias of `/status/toolsets`              |
| `/metrics`                              | GET    | Prometheus metrics endpoint                         |

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
- **Window**: fixed 1-minute window per token; the counter resets once a full
  minute has elapsed (not a sliding window or token bucket).
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

On `/mcp` (and `/mcp/sse` and the toolset endpoints) a personal access token
(`axon_pat_...`, or a service account's) gets exactly what its owner's policy
allows, narrowed by the token's scope (backends and tool globs) and minus the
owner's opt-outs, in both `tools/list` and `tools/call`. A tool the token may
not use is hidden like one that does not exist: `tools/call` answers it with
the same `Unknown tool` error (-32601) as for a name no backend has, and a
backend outside the policy is listed nowhere. Without a valid token in
multi-user mode the endpoints answer 401 with `WWW-Authenticate: Bearer`. The
legacy `gateway.auth_token` and `[[tokens]]` still work, but they bypass RBAC
(they keep their own ACL) and are deprecated in favour of personal access
tokens and service accounts; the gateway logs a warning at startup when they
are set in multi-user mode.

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
with `PUT /api/v1/groups/{name}/members/{id}`, and give that group grants. It
is a member of database groups only: a group declared in `config.toml` takes
members from its IdP mappings alone, so a service account cannot join one
(the write answers 409). Its groups are exactly its memberships, without the
built-in `authenticated` group. Disabling the account stops all its tokens at
once (enabling it restores them), and deleting it removes its tokens and
memberships. Admins manage accounts on `/ui/admin/service-accounts` (linked
from `/ui/admin`).

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

## Tracing

Logs go to stdout (`AXON_LOG_JSON=1` for JSON, `RUST_LOG` to filter). Set
`OTEL_EXPORTER_OTLP_ENDPOINT` to also export traces over OTLP; the standard
`OTEL_*` variables apply (`OTEL_EXPORTER_OTLP_PROTOCOL` = `grpc` or
`http/protobuf`, `OTEL_SERVICE_NAME`, default `axon-gateway`,
`OTEL_TRACES_SAMPLER`). Every HTTP request gets a server span, and an incoming
W3C `traceparent` header becomes its parent.

## Metrics

Prometheus metrics are exposed at `/metrics`:

- `axon_tool_calls_total` - Tool call counter by backend/tool
- `axon_tool_call_duration_seconds` - Tool call latency histogram
- `axon_tool_call_errors_total` - Tool call error counter
- `axon_backend_state` - Backend connection state gauge
- `axon_http_requests_total` - HTTP request counter
- `axon_health_checks_total` - Health check counter
- `axon_resource_reads_total` - Resource read counter
- `axon_prompt_gets_total` - Prompt get counter

## Environment Variable References in Config

You can reference environment variables in `config.toml` using `${VAR_NAME}` placeholders.

Example:

```toml
[gateway]
bind = "0.0.0.0:8080"
auth_token = "${AXON_GATEWAY_TOKEN}"

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
- [x] **SSE streaming**: MCP SSE transport support (`/mcp/sse`)

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
└── server.rs    # HTTP/SSE server (axum)
```

## License

MIT
