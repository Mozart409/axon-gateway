# Bug Report: `notifications/initialized` fails with `422 Unprocessable Entity`

## Summary

The `axon-gateway` rejects the MCP `notifications/initialized` notification with `422 Unprocessable Entity` because the `JsonRpcRequest` type requires the `id` field, but JSON-RPC notifications **must not** include an `id` field.

## Reproduction

Send a POST request to `/mcp` without an `id` field:

```bash
curl -X POST https://axon.homelab.local/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {}
  }'
# Response: 422 Unprocessable Entity
```

With `id: null`, it parses successfully (fails later at auth, which is expected):

```bash
curl -X POST https://axon.homelab.local/mcp \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": null,
    "method": "notifications/initialized",
    "params": {}
  }'
# Response: 401 Unauthorized (parses correctly!)
```

## Root Cause

In `src/types.rs`, the `JsonRpcRequest` struct requires `id`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,  // <— REQUIRED, but notifications omit `id`
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}
```

Per the [JSON-RPC 2.0 spec](https://www.jsonrpc.org/specification#notification):

> A Notification is a Request object without an `id` member.

Per the MCP spec (streamable HTTP transport), the client must send a `notifications/initialized` message after the `initialize` handshake completes. This message is a **notification**, not a request, so it has no `id`.

## Impact

Any MCP client that strictly follows the spec (e.g., `hermes-agent` via `mcp.client.streamable_http`) cannot connect to the gateway. The client retries 3 times, then aborts, causing a systemd restart loop.

MCP Inspector may work because it may skip the `notifications/initialized` step, always include an `id`, or use a different transport (SSE).

## Fix

Make `id` optional in `JsonRpcRequest`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,  // <— Optional
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}
```

Then update the `handle_mcp_request` handler in `src/server.rs` to differentiate between:

- **Request**: has `id` → send a `JsonRpcResponse` back to the client
- **Notification**: no `id` → process the method, return `200 OK` with no body (or an empty JSON-RPC response)

For `notifications/initialized`, the handler can simply return `200 OK` with no body, or a success response.

## Additional Note: Protocol Version Mismatch

The gateway hardcodes `protocolVersion: "2024-11-05"` in the `initialize` response:

```rust
// src/gateway.rs
"initialize" => JsonRpcResponse::success(
    request.id,
    serde_json::json!({
        "protocolVersion": "2024-11-05",  // <— hardcoded
        ...
    }),
),
```

If the backend uses `2025-11-25` (the newer streamable HTTP transport), this version mismatch may cause issues. Consider:

- Matching the backend's protocol version in the response
- Or configuring the gateway's protocol version explicitly

## Environment

- **axon-gateway version**: `v0.1.8` (commit `e6f74f1`)
- **Image**: `ghcr.io/mozart409/axon-gateway:v0.1.8`
- **Backend**: `hamcp` (streamable HTTP, `2025-11-25`)
- **Client**: `hermes-agent` using `mcp.client.streamable_http`

## Logs

### hermes-agent (crash loop)
```
httpx.HTTPStatusError: Client error '422 Unprocessable Entity'
for url 'https://axon.homelab.local/mcp'
```

### axon-gateway logs
```
2026-06-20T21:30:11.289920Z  INFO http_request: finished processing request latency=0 ms status=200
2026-06-20T21:30:11.301547Z  INFO http_request: finished processing request latency=0 ms status=422
2026-06-20T21:30:12.354183Z  INFO http_request: finished processing request latency=0 ms status=200
2026-06-20T21:30:12.358045Z  INFO http_request: finished processing request latency=0 ms status=422
```

Pattern: `POST initialize` → `200`, then `POST notifications/initialized` → `422`, repeated 3 times.

## Files to Modify

1. `src/types.rs` — Make `id` optional in `JsonRpcRequest`
2. `src/gateway.rs` — Update all `request.id` references to handle `Option`
3. `src/server.rs` — Handle notifications (no response body) vs requests (JSON-RPC response)

