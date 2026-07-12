# Agent Guidelines for Axon Gateway

## Project Overview

A self-hosted MCP (Model Context Protocol) gateway written in Rust that aggregates multiple MCP servers into a single endpoint. Uses actor-based architecture with kameo.

## Build/Test Commands

```bash
# Build the project
cargo build

# Run all tests
cargo test

# Run a single test
cargo test <test_name>

# Run clippy (standard)
cargo clippy

# Run clippy with pedantic warnings (as configured in lefthook.yml)
cargo clippy -- -W clippy::pedantic

# Always run pedantic clippy and fix all reported issues
cargo clippy -- -W clippy::pedantic

# Format code
cargo fmt

# Check all targets with clippy
cargo clippy --all-targets -- -D warnings

# Run bacon (background code checker)
bacon
# or with specific job:
bacon clippy-all
bacon pedantic
```

## Code Style Guidelines

### Imports
- Group imports: std library, external crates, internal modules
- Use `use crate::` for internal modules
- Prefer explicit imports over `use super::*` or glob imports
- Order: std → external crates → internal (separated by blank lines)

### Formatting
- Use `cargo fmt` for automatic formatting
- 4 spaces for indentation
- Line length: standard Rust (100 chars recommended)
- Trailing commas in multi-line structs/arrays
- Comments: `//` for single line, `//!` for module docs, `///` for item docs

### Naming Conventions
- **Types**: PascalCase (`GatewayActor`, `BackendConfig`)
- **Functions/Methods**: snake_case (`handle_request`, `fetch_tools`)
- **Variables**: snake_case (`tool_name`, `backend_config`)
- **Constants**: UPPER_SNAKE_CASE (if any)
- **Actors**: Suffix with `Actor` (`GatewayActor`, `BackendActor`, `RegistryActor`)
- **Messages**: PascalCase verb/noun (`HandleRequest`, `RegisterBackend`, `CallTool`)

### Types & Error Handling
- Use `color_eyre::eyre::Result` for main application errors
- Use `thiserror` for structured internal error types
- Return `Result<T, String>` for actor message replies that may fail
- Use `BoxError` (from kameo) for actor lifecycle errors
- Format strings: inline variables (`format!("{tool_name}")` not `format!("{}", tool_name)`)
- Clone with `clone_from()` instead of assignment when applicable

### Actor Pattern (kameo)
- Each actor implements `Actor` trait with `Mailbox` type
- Messages implement `Message<M>` trait with associated `Reply` type
- Use `ask()` for requests needing reply, `tell()` for fire-and-forget
- Actor handlers: `async fn handle(&mut self, msg: M, _ctx: Context) -> Self::Reply`
- Implement `on_start()` for initialization logic
- Allow clippy exceptions where needed: `#[allow(clippy::too_many_lines)]`

### Architecture
- **main.rs**: Entry point, CLI parsing, actor spawning
- **gateway.rs**: GatewayActor - orchestrates MCP protocol handling
- **backend.rs**: BackendActor - per-MCP-server connection management
- **registry.rs**: RegistryActor - tool aggregation and routing
- **server.rs**: HTTP server (axum) - endpoints and request handling
- **config.rs**: Config types and TOML parsing
- **types.rs**: Core domain types (ToolDefinition, JsonRpc, etc.)
- **error.rs**: Error types using thiserror
- **auth.rs**: Authentication middleware and token validation
- **metrics.rs**: Prometheus metrics recording functions
- **watcher.rs**: Config file watcher for hot reload

### UI Stack (Dashboard)
- **Rendering**: Server-side HTML rendering with **maud** in `server.rs`
- **Styling**: **Tailwind CSS** via `styles/input.css` compiled to `styles/output.css`
- **Interactions**: **HTMX** for action endpoints and partial swaps (no SPA framework)
- **Realtime updates**: **Server-Sent Events (SSE)** from `/ui/events` consumed by HTMX SSE extension
- **Pattern**: SSR-first pages + HTMX/SSE progressive enhancement for live backend state updates

### Code Patterns
- Use `#[serde(rename_all = "lowercase")]` for enums in configs
- Use `#[serde(default)]` for optional config fields with defaults
- Implement `Default` for config structs with sensible defaults
- Use `DashMap` for concurrent access in registry
- Use `tracing` for structured logging
- Comments for modules use `//!`, items use `///`
- Backticks around code identifiers in docs: `` `BackendInfo` ``

### Testing
- Unit tests: inline in source files with `#[cfg(test)]`
- Integration tests: in `tests/` directory
- Run single test: `cargo test test_name`

### Pre-commit Checks
Lefthook runs automatically on commit:
- `cargo fmt` - format code
- `cargo clippy --all-targets -- -D warnings` - lint check
- `typos` - spell check

Pre-push:
- `cargo test` - run all tests
- `cargo clippy -- -W clippy::pedantic` - pedantic lint check

### Dependencies
- **Async**: tokio (full features)
- **Actors**: kameo (0.20)
- **MCP Protocol**: rmcp (1.5) with features:
  - `client` - Client service types
  - `server` - Server service types
  - `transport-child-process` - Stdio transport via child process
  - `transport-streamable-http-client-reqwest` - HTTP/SSE client transport
  - `transport-streamable-http-server` - HTTP server transport
- **Web**: axum (0.8), tower-http (0.6)
- **UI**: maud, tailwindcss, htmx (+ htmx-ext-sse)
- **Metrics**: metrics, metrics-exporter-prometheus
- **Config watching**: notify (8)
- **Caching**: moka
- **Serialization**: serde, serde_json, toml
- **Errors**: thiserror, color-eyre
- **Logging**: tracing, tracing-subscriber
- **Utils**: dashmap, futures, chrono, uuid

## Important Notes
- Edition 2024 is used
- No lib.rs - this is a binary-only crate
- Backend actors use real rmcp client connections (not mocks)
- Config file is TOML format with sections `[gateway]` and `[[backends]]`
- SSE and HTTP transports both use rmcp's `StreamableHttpClientTransport`
- Stdio transport uses rmcp's `TokioChildProcess` to spawn MCP servers
- `auth_token` in `[gateway]` config only protects the MCP endpoint (`/mcp`), not the `/ui` dashboard routes
- Runtime image is Chainguard `wolfi-base` (minimal): it ships **no** `curl`/`wget` and busybox has no `wget` applet. The Compose healthchecks probe `/health` with `wget`, so the Dockerfile must `apk add --no-cache wget` for them to pass — keep that line in sync with the `healthcheck:` blocks in `example/compose.yml` and `example/compose.local.yml`

## Version Synchronization
When updating the Rust version, ensure consistency across:
1. **flake.nix**: `rust-bin.stable."X.Y.Z"` (line 22)
2. **Dockerfile**: `FROM rust:X.Y-bookworm AS builder` (line 2)

Both must use the same Rust version to avoid build discrepancies.
