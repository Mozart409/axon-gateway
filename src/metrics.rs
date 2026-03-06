//! Prometheus metrics for the MCP Gateway
//!
//! Exposes metrics at `GET /metrics` in Prometheus text format:
//! - `axon_tool_calls_total` — Counter of tool call requests per backend/tool
//! - `axon_tool_call_duration_seconds` — Histogram of tool call latencies
//! - `axon_tool_call_errors_total` — Counter of failed tool calls
//! - `axon_backend_connections` — Gauge of backend connection states
//! - `axon_requests_total` — Counter of HTTP requests by method/path
//! - `axon_health_checks_total` — Counter of health check results

use metrics::{counter, gauge, histogram};

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
