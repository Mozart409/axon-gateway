# Axon Gateway

A lightweight, self-hosted MCP (Model Context Protocol) gateway that aggregates multiple MCP servers into a single endpoint.

## Features

- **Aggregation**: Combine tools from multiple MCP servers into one endpoint
- **Namespacing**: Tools are automatically prefixed with backend name (e.g., `homeassistant_turn_on`)
- **Multiple transports**: SSE, HTTP, and stdio backends supported
- **Multi-token auth**: Named API tokens with fine-grained permissions (allowed tools/backends)
- **Tool groups**: Expose subsets of tools via different path prefixes
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
| `/mcp/group/{group_name}`               | POST   | JSON-RPC endpoint filtered by tool group            |
| `/`                                     | GET    | Landing page                                        |
| `/ui`                                   | GET    | SSR dashboard page                                  |
| `/ui/backends/{name}`                   | GET    | Backend detail page                                 |
| `/ui/events`                            | GET    | Dashboard SSE stream (`text/event-stream`)          |
| `/ui/partials/backends`                 | GET    | SSR backend panel fragment                          |
| `/ui/actions/backends/{name}/reconnect` | POST   | HTMX action: reconnect backend                      |
| `/ui/actions/backends/{name}/disable`   | POST   | HTMX action: disable backend                        |
| `/ui/actions/backends/{name}/enable`    | POST   | HTMX action: enable backend                         |
| `/ui/actions/reload`                    | POST   | HTMX action: reload config                          |
| `/build`                                | GET    | Build/runtime metadata (version, pid, startup time) |
| `/health`                               | GET    | Health check                                        |
| `/status`                               | GET    | Gateway status (backend list, counts)               |
| `/status/detailed`                      | GET    | Detailed status with tool/resource/prompt lists     |
| `/status/groups`                        | GET    | List configured tool groups                         |
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

## Tool Groups

Expose subsets of tools via different path prefixes:

```toml
[[groups]]
name = "coding"
backends = ["vscode", "git"]
description = "Development tools only"

[[groups]]
name = "readonly"
tools = ["*_read", "*_list", "*_get"]
description = "Read-only operations"
```

Access grouped tools at `/mcp/group/{group_name}` instead of `/mcp`.

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
