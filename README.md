# Axon Gateway

A lightweight, self-hosted MCP (Model Context Protocol) gateway that aggregates multiple MCP servers into a single endpoint.

## Features

- **Aggregation**: Combine tools from multiple MCP servers into one endpoint
- **Namespacing**: Tools are automatically prefixed with backend name (e.g., `homeassistant_turn_on`)
- **Multiple transports**: SSE, HTTP, and stdio backends supported
- **Auth**: Optional Bearer token authentication
- **Actor-based**: Built on kameo for robust concurrency

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   MCP Gateway                        │
│                                                      │
│  ┌──────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │ HTTP Server  │  │   Gateway   │  │  Registry  │  │
│  │ (axum)       │──│   Actor     │──│   Actor    │  │
│  │ /mcp         │  │             │  │            │  │
│  └──────────────┘  └─────────────┘  └────────────┘  │
│                           │                          │
│         ┌─────────────────┼─────────────────┐       │
│         │                 │                 │       │
│  ┌──────▼─────┐  ┌───────▼──────┐  ┌───────▼─────┐ │
│  │ Backend    │  │ Backend      │  │ Backend     │ │
│  │ Actor      │  │ Actor        │  │ Actor       │ │
│  │ (HA)       │  │ (Jellyfin)   │  │ (Proxmox)   │ │
│  └──────┬─────┘  └───────┬──────┘  └───────┬─────┘ │
└─────────┼────────────────┼─────────────────┼───────┘
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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST | JSON-RPC endpoint (Streamable HTTP transport) |
| `/mcp/sse` | GET | SSE endpoint for streaming transport |
| `/health` | GET | Health check |
| `/status` | GET | Gateway status (backend list, counts) |

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

Enable auth by setting `auth_token` in config:

```toml
[gateway]
bind = "0.0.0.0:8080"
auth_token = "your-secret-token"
```

Clients must include `Authorization: Bearer your-secret-token` header.

## Current Status

Phase 1 (MVP) is complete:

- [x] **Real rmcp integration**: Backend actors connect to real MCP servers
- [x] **Multiple transports**: SSE, HTTP (via streamable HTTP), and stdio supported
- [x] **Tool aggregation**: Tools fetched from backends and namespaced
- [x] **Tool forwarding**: `tools/call` forwarded to correct backend with real results

## TODO / Next Steps

To make it production-ready:

- [ ] **Reconnection logic**: Automatic reconnect with exponential backoff
- [ ] **Health checks**: Periodic pings to detect dead backends
- [ ] **Hot reload**: Watch config file and update backends without restart
- [ ] **Metrics**: Prometheus metrics for tool calls, latency, errors
- [ ] **Tool filtering**: Support `allowed_tools` config per backend
- [ ] **Resource/Prompt proxying**: Forward MCP resources and prompts too
- [ ] **SSE streaming**: Full bidirectional SSE session support
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

MIT / Apache-2.0
