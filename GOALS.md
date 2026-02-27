# MCP Gateway - Project Goals

## Overview

A self-hosted MCP (Model Context Protocol) gateway written in Rust that aggregates multiple MCP servers into a single endpoint. This allows AI agents to connect to one gateway instead of configuring dozens of individual MCP servers.

## Core Goals

1. **Single endpoint for all MCP servers** — Agents connect to one URL and get access to all homelab tools
2. **Automatic namespacing** — Tools are prefixed with backend name to avoid collisions (e.g., `homeassistant_turn_on`)
3. **Transport agnostic** — Support SSE, Streamable HTTP, and stdio backends
4. **Minimal configuration** — Simple TOML config, no database required for basic usage
5. **Resilient** — Backend failures don't crash the gateway; automatic reconnection

## Architecture Decisions

### Actor-based design (kameo)

- One `BackendActor` per MCP server — isolates failures, manages connection lifecycle
- One `RegistryActor` — central registry of all tools, handles routing lookups
- One `GatewayActor` — orchestrates backends, handles MCP protocol

### Why not just proxy raw requests?

MCP tools/list must return an aggregated list from ALL backends. We need to:

1. Connect to each backend on startup
2. Fetch their tool lists
3. Namespace and merge them
4. Route incoming tool calls to the correct backend

### Transport choice

Expose the gateway via Streamable HTTP (`POST /mcp`) as primary transport. SSE (`GET /mcp/sse`) as secondary for clients that prefer it.

## Implementation Tasks

### Phase 1: Core Functionality (MVP)

- [x] Project structure with kameo actors
- [x] Config parsing (TOML)
- [x] Registry actor with tool aggregation
- [x] Backend actor skeleton
- [x] Gateway actor with MCP protocol handling
- [x] HTTP server with `/mcp` endpoint
- [ ] **Wire up rmcp client** — Replace mock connections with real rmcp transports
  - [ ] SSE client transport
  - [ ] HTTP client transport
  - [ ] Stdio client transport (spawn subprocess)
- [ ] **Real tool forwarding** — Forward `tools/call` to backend, return actual result
- [ ] **Error handling** — Graceful handling when backends fail mid-request

### Phase 2: Reliability

- [ ] **Reconnection logic** — Exponential backoff reconnect on connection loss
- [ ] **Health checks** — Periodic pings to detect dead backends
- [ ] **Connection pooling** — Reuse connections for HTTP backends
- [ ] **Timeouts** — Configurable per-backend timeouts for tool calls
- [ ] **Circuit breaker** — Stop routing to consistently failing backends

### Phase 3: Features

- [ ] **Hot reload** — Watch config file, add/remove backends without restart
- [ ] **Tool filtering** — `allowed_tools` config to expose subset of backend tools
- [ ] **Resource proxying** — Forward MCP `resources/list` and `resources/read`
- [ ] **Prompt proxying** — Forward MCP `prompts/list` and `prompts/get`
- [ ] **Logging/tracing** — Structured logging with request IDs, OpenTelemetry support

### Phase 4: Auth & Security

- [ ] **Bearer token auth** — Simple token auth (already scaffolded)
- [ ] **Per-backend auth** — Pass auth headers to backends that need them
- [ ] **OIDC integration** — Integrate with PocketID for SSO
- [ ] **Tool-level permissions** — ACLs for which tools different tokens can access
- [ ] **Rate limiting** — Per-token rate limits

### Phase 5: Observability & Operations

- [ ] **Prometheus metrics** — Tool call counts, latencies, error rates per backend
- [ ] **Status API** — Detailed backend health, last error, tool counts
- [ ] **Admin API** — Endpoints to reload config, force reconnect, disable backends
- [ ] **Systemd unit** — Service file for running as daemon
- [ ] **NixOS module** — Declarative config for your NixOS setup
- [ ] **Docker image** — Multi-stage build, minimal image

### Phase 6: Advanced

- [ ] **Tool groups** — Expose subsets of tools via different endpoints (like MCPJungle)
- [ ] **Caching** — Cache tool lists, invalidate on backend reconnect
- [ ] **Streaming responses** — Properly proxy streaming tool results
- [ ] **Multi-tenant** — Different configs/permissions per API key
- [ ] **Web UI** — Simple dashboard showing backends, tools, recent calls

## Technical Notes

### rmcp Integration Points

The main integration points with rmcp are in `backend.rs`:

```rust
// In BackendActor::connect()
// Replace mock connection with:
match self.config.transport {
    TransportType::Sse => {
        let transport = SseClientTransport::new(url);
        let client = McpClient::new(transport).await?;
        self.client = Some(client);
    }
    // ... similar for HTTP and stdio
}

// In BackendActor::fetch_tools()
// Replace mock with:
let response = self.client.request("tools/list", json!({})).await?;
let tools: Vec<ToolDefinition> = serde_json::from_value(response["tools"])?;

// In BackendActor::call_tool()
// Replace mock with:
let response = self.client.request("tools/call", json!({
    "name": tool_name,
    "arguments": arguments
})).await?;
```

### Config Schema

```toml
[gateway]
bind = "0.0.0.0:8080"      # Required: listen address
auth_token = "secret"       # Optional: enable bearer auth

[[backends]]
name = "unique-name"        # Required: used as namespace prefix
url = "http://..."          # Required for sse/http transport
command = "/path/to/bin"    # Required for stdio transport
args = ["--flag", "value"]  # Optional: args for stdio
transport = "sse"           # Required: sse | http | stdio
enabled = true              # Optional: default true
allowed_tools = ["tool1"]   # Optional: filter tools (empty = all)
timeout_secs = 30           # Optional: per-backend timeout
```

### MCP Protocol Methods to Handle

| Method                      | Gateway Behavior                                      |
| --------------------------- | ----------------------------------------------------- |
| `initialize`                | Return gateway capabilities                           |
| `notifications/initialized` | Acknowledge                                           |
| `tools/list`                | Return aggregated, namespaced tools from all backends |
| `tools/call`                | Route to correct backend, strip namespace, forward    |
| `resources/list`            | (Future) Aggregate from all backends                  |
| `resources/read`            | (Future) Route to correct backend                     |
| `prompts/list`              | (Future) Aggregate from all backends                  |
| `prompts/get`               | (Future) Route to correct backend                     |

### Testing Strategy

1. **Unit tests** — Registry logic, namespacing, routing
2. **Integration tests** — Spawn mock MCP servers, verify aggregation
3. **E2E tests** — Full gateway with real backends (homeassistant-mcp, etc.)

### Performance Considerations

- Tool list is cached in registry; only refreshed on backend reconnect
- Use `DashMap` for concurrent access to registry without locks
- Connection per backend is long-lived (SSE) or pooled (HTTP)
- Consider lazy connection — don't connect until first request to that backend

## File Structure

```
mcp-gateway/
├── Cargo.toml
├── config.toml          # Example config
├── GOALS.md             # This file
├── README.md
└── src/
    ├── main.rs          # Entry point, arg parsing
    ├── lib.rs           # Library exports
    ├── config.rs        # Config types and parsing
    ├── types.rs         # Core types (Tool, JsonRpc, etc.)
    ├── registry.rs      # Registry actor
    ├── backend.rs       # Backend actor (per-server)
    ├── gateway.rs       # Gateway actor (orchestrator)
    └── server.rs        # HTTP/SSE server
```

## References

- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [rmcp crate](https://github.com/anthropics/rmcp)
- [kameo actor framework](https://github.com/tqwewe/kameo)
- [MCPJungle](https://github.com/mcpjungle/MCPJungle) — Similar project in Go
- [MetaMCP](https://github.com/metatool-ai/metamcp) — Docker-based aggregator
