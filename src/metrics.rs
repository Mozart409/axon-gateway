//! Prometheus metrics for the MCP Gateway
//!
//! Exposes metrics at `GET /metrics` in Prometheus text format:
//! - `axon_tool_calls_total` — Counter of tool call requests per backend/tool
//! - `axon_tool_call_duration_seconds` — Histogram of tool call latencies
//! - `axon_tool_call_errors_total` — Counter of failed tool calls
//! - `axon_backend_connections` — Gauge of backend connection states
//! - `axon_backend_inflight_calls` — Gauge of requests in flight per backend
//! - `axon_requests_total` — Counter of HTTP requests by method/path
//! - `axon_mcp_requests_total` — Counter of MCP requests by `Mcp-Method` header value
//! - `axon_health_checks_total` — Counter of health check results
//! - `axon_audit_dropped_total` — Counter of tool call audit events dropped (queue full)
//! - `axon_audit_write_errors_total` — Counter of failed tool call audit batch writes

use metrics::{counter, describe_counter, gauge, histogram};

/// Record a tool call request
pub fn record_tool_call(backend: &str, tool: &str) {
    counter!("axon_tool_calls_total", "backend" => backend.to_string(), "tool" => tool.to_string())
        .increment(1);
}

/// Record tool call duration in seconds
pub fn record_tool_call_duration(backend: &str, tool: &str, duration_secs: f64) {
    histogram!(
        "axon_tool_call_duration_seconds",
        "backend" => backend.to_string(),
        "tool" => tool.to_string()
    )
    .record(duration_secs);
}

/// Record a tool call error
pub fn record_tool_call_error(backend: &str, tool: &str) {
    counter!(
        "axon_tool_call_errors_total",
        "backend" => backend.to_string(),
        "tool" => tool.to_string()
    )
    .increment(1);
}

/// Record backend connection state change
pub fn record_backend_state(backend: &str, state: &str) {
    // Reset all state gauges for this backend, then set the current one
    for s in &[
        "disconnected",
        "connecting",
        "connected",
        "failed",
        "circuit_open",
        "reconnecting",
    ] {
        gauge!(
            "axon_backend_connections",
            "backend" => backend.to_string(),
            "state" => (*s).to_string()
        )
        .set(0.0);
    }
    gauge!(
        "axon_backend_connections",
        "backend" => backend.to_string(),
        "state" => state.to_string()
    )
    .set(1.0);
}

/// Counts a request as in flight for its backend until dropped.
pub struct InflightCallGuard {
    backend: String,
}

impl InflightCallGuard {
    pub fn new(backend: &str) -> Self {
        gauge!("axon_backend_inflight_calls", "backend" => backend.to_string()).increment(1.0);
        Self {
            backend: backend.to_string(),
        }
    }
}

impl Drop for InflightCallGuard {
    fn drop(&mut self) {
        gauge!("axon_backend_inflight_calls", "backend" => self.backend.clone()).decrement(1.0);
    }
}

/// Record an HTTP request
pub fn record_http_request(method: &str, path: &str, status: u16) {
    counter!(
        "axon_requests_total",
        "method" => method.to_string(),
        "path" => path.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

/// The MCP methods `axon_mcp_requests_total` tells apart; any other value of the
/// client-controlled `Mcp-Method` header is counted as `other`.
const MCP_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "server/discover",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "subscriptions/listen",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/roots/list_changed",
];

/// Describe the MCP request metrics, so they show up with help text.
pub fn describe_mcp_metrics() {
    describe_counter!(
        "axon_mcp_requests_total",
        "MCP requests by the method in their Mcp-Method header (none: no header, other: not a known method)"
    );
}

/// Record an MCP request by its `Mcp-Method` header; an empty `method` is a
/// request without the header. The label is bounded: a value outside
/// [`MCP_METHODS`] counts as `other`.
pub fn record_mcp_request(method: &str) {
    let label = if method.is_empty() {
        "none"
    } else if MCP_METHODS.contains(&method) {
        method
    } else {
        "other"
    };
    counter!("axon_mcp_requests_total", "method" => label.to_string()).increment(1);
}

/// Record a health check result
pub fn record_health_check(backend: &str, success: bool) {
    let result = if success { "success" } else { "failure" };
    counter!(
        "axon_health_checks_total",
        "backend" => backend.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

/// Record resource read request
pub fn record_resource_read(backend: &str) {
    counter!(
        "axon_resource_reads_total",
        "backend" => backend.to_string()
    )
    .increment(1);
}

/// Record prompt get request
pub fn record_prompt_get(backend: &str) {
    counter!(
        "axon_prompt_gets_total",
        "backend" => backend.to_string()
    )
    .increment(1);
}

/// Record an SSE client count update.
#[allow(clippy::cast_precision_loss)]
pub fn record_ui_sse_clients(active_clients: u64) {
    gauge!("axon_ui_sse_clients").set(active_clients as f64);
}

/// Record an SSE stream lifecycle event.
pub fn record_ui_sse_lifecycle(event: &str) {
    counter!("axon_ui_sse_lifecycle_total", "event" => event.to_string()).increment(1);
}

/// Record an SSE event fanout.
pub fn record_ui_sse_event(event: &str) {
    counter!("axon_ui_sse_events_total", "event" => event.to_string()).increment(1);
}

/// Record dropped SSE events.
pub fn record_ui_sse_dropped(count: u64) {
    counter!("axon_ui_sse_dropped_total").increment(count);
}

/// Describe the audit metrics, so they show up with help text.
pub fn describe_audit_metrics() {
    describe_counter!(
        "axon_audit_dropped_total",
        "Tool call audit events dropped because the writer queue was full"
    );
    describe_counter!(
        "axon_audit_write_errors_total",
        "Tool call audit batches that could not be written to the database"
    );
}

/// Record a tool call audit event dropped because the writer queue was full.
pub fn record_audit_dropped() {
    counter!("axon_audit_dropped_total").increment(1);
}

/// Record a tool call audit batch that failed to write.
pub fn record_audit_write_error() {
    counter!("axon_audit_write_errors_total").increment(1);
}
