//! Prometheus metrics for the MCP Gateway
//!
//! Exposes metrics at `GET /metrics` in Prometheus text format:
//! - `axon_tool_calls_total` — Counter of tool call requests per backend/tool
//! - `axon_tool_call_duration_seconds` — Histogram of tool call latencies
//! - `axon_tool_call_errors_total` — Counter of failed tool calls
//! - `axon_backend_connections` — Gauge of backend connection states
//! - `axon_backend_up` — Gauge, 1 when the last connect or health probe succeeded
//! - `axon_backend_inflight_calls` — Gauge of requests in flight per backend
//! - `axon_requests_total` — Counter of HTTP requests by method/path
//! - `axon_mcp_requests_total` — Counter of MCP requests by `Mcp-Method` header value and principal type
//! - `axon_health_checks_total` — Counter of health check results
//! - `axon_audit_dropped_total` — Counter of tool call audit events dropped (queue full)
//! - `axon_audit_write_errors_total` — Counter of failed tool call audit batch writes
//! - `axon_user_tool_calls_total` — Counter of tool calls per user, backend and outcome
//! - `axon_authn_total` — Counter of authentication attempts by method and result
//! - `axon_authz_denied_total` — Counter of calls denied, by reason
//! - `axon_active_sessions`, `axon_tokens_active`, `axon_db_pool_connections`,
//!   `axon_db_pool_max`, `axon_db_up`, `axon_user_backends` — Gauges the sampler refreshes
//! - `axon_oidc_requests_total`, `axon_oidc_request_duration_seconds`,
//!   `axon_oidc_provider_up` — Requests to the OIDC identity providers

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use uuid::Uuid;

use crate::gateway::Caller;
use crate::types::BackendState;

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

/// The states `axon_backend_connections` tells apart
pub const BACKEND_STATES: &[&str] = &[
    "disconnected",
    "connecting",
    "connected",
    "failed",
    "circuit_open",
    "reconnecting",
    "idle",
];

/// Record backend connection state change
pub fn record_backend_state(backend: &str, state: &str) {
    // Reset all state gauges for this backend, then set the current one
    for s in BACKEND_STATES {
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

/// Record whether the last connect attempt or health probe of a backend succeeded
pub fn record_backend_up(backend: &str, up: bool) {
    gauge!("axon_backend_up", "backend" => backend.to_string()).set(if up { 1.0 } else { 0.0 });
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

/// The `principal_type` label of a caller: `service` for a config `[[tokens]]`
/// account or a service account's token, `pat` for a person's own token.
pub fn principal_type(caller: &Caller) -> &'static str {
    match caller {
        Caller::Open => "open",
        Caller::Token(_) => "legacy_token",
        Caller::Principal(principal) => {
            if principal.is_service_account() {
                "service"
            } else {
                "pat"
            }
        }
    }
}

/// Record an MCP request by its `Mcp-Method` header; an empty `method` is a
/// request without the header. The label is bounded: a value outside
/// [`MCP_METHODS`] counts as `other`.
pub fn record_mcp_request(method: &str, principal_type: &str) {
    let label = if method.is_empty() {
        "none"
    } else if MCP_METHODS.contains(&method) {
        method
    } else {
        "other"
    };
    counter!(
        "axon_mcp_requests_total",
        "method" => label.to_string(),
        "principal_type" => principal_type.to_string()
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

/// Record a tool call of a user. `backend` is a shared or catalog backend name,
/// or `personal` for a personal backend; `outcome` is `ok`, `error` or `denied`.
pub fn record_user_tool_call(user: Uuid, backend: &str, outcome: &str) {
    counter!(
        "axon_user_tool_calls_total",
        "user" => user.to_string(),
        "backend" => backend.to_string(),
        "outcome" => outcome.to_string()
    )
    .increment(1);
}

/// Record an authentication attempt: `method` is `pat`, `service_token`,
/// `legacy_token`, `session`, `break_glass` or `open`; `result` is `ok`,
/// `invalid`, `expired`, `disabled` or `rate_limited`.
pub fn record_authn(method: &str, result: &str) {
    counter!(
        "axon_authn_total",
        "method" => method.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
}

/// Record a call or request denied: `reason` is `backend`, `tool`, `quota` or
/// `rate_limit`.
pub fn record_authz_denied(reason: &str) {
    counter!("axon_authz_denied_total", "reason" => reason.to_string()).increment(1);
}

/// Record the live sessions: `kind` is `mcp` or `ui`.
#[allow(clippy::cast_precision_loss)]
pub fn record_active_sessions(kind: &str, count: u64) {
    gauge!("axon_active_sessions", "kind" => kind.to_string()).set(count as f64);
}

/// Record the usable API tokens: `kind` is `pat` or `service`.
#[allow(clippy::cast_precision_loss)]
pub fn record_tokens_active(kind: &str, count: u64) {
    gauge!("axon_tokens_active", "kind" => kind.to_string()).set(count as f64);
}

/// Record the database pool: connections idle and in use, and the maximum.
pub fn record_db_pool(idle: u32, used: u32, max: u32) {
    gauge!("axon_db_pool_connections", "state" => "idle").set(f64::from(idle));
    gauge!("axon_db_pool_connections", "state" => "used").set(f64::from(used));
    gauge!("axon_db_pool_max").set(f64::from(max));
}

/// Record whether the database answered the sampler's probe.
pub fn record_db_up(up: bool) {
    gauge!("axon_db_up").set(if up { 1.0 } else { 0.0 });
}

/// The `state` label of a per-user backend: anything but connected, idle and
/// failed counts as `other`.
fn user_backend_state(state: BackendState) -> &'static str {
    match state {
        BackendState::Connected => "connected",
        BackendState::Idle => "idle",
        BackendState::Failed => "failed",
        _ => "other",
    }
}

/// Record the per-user backends of this replica by state; a state without
/// backends is set to 0.
#[allow(clippy::cast_precision_loss)]
pub fn record_user_backend_states(states: &[BackendState]) {
    for label in ["connected", "idle", "failed", "other"] {
        let count = states
            .iter()
            .filter(|state| user_backend_state(**state) == label)
            .count();
        gauge!("axon_user_backends", "state" => label).set(count as f64);
    }
}

/// Record a request to an OIDC provider: `op` is `discovery`, `token`,
/// `userinfo` or `jwks`. The provider is up when its last request succeeded.
pub fn record_oidc_request(provider: &str, op: &str, ok: bool, duration_secs: f64) {
    let result = if ok { "ok" } else { "error" };
    counter!(
        "axon_oidc_requests_total",
        "provider" => provider.to_string(),
        "op" => op.to_string(),
        "result" => result.to_string()
    )
    .increment(1);
    histogram!(
        "axon_oidc_request_duration_seconds",
        "provider" => provider.to_string(),
        "op" => op.to_string()
    )
    .record(duration_secs);
    gauge!("axon_oidc_provider_up", "provider" => provider.to_string()).set(if ok {
        1.0
    } else {
        0.0
    });
}

/// Describe the user, authentication, sampler and OIDC metrics, so they show up
/// with help text.
pub fn describe_user_metrics() {
    describe_counter!(
        "axon_user_tool_calls_total",
        "Tool calls by users, per backend (personal for personal backends) and outcome (ok, error, denied)"
    );
    describe_counter!(
        "axon_authn_total",
        "Authentication attempts by method and result (ok, invalid, expired, disabled, rate_limited)"
    );
    describe_counter!(
        "axon_authz_denied_total",
        "Calls denied by reason (backend, tool, quota, rate_limit)"
    );
    describe_gauge!(
        "axon_active_sessions",
        "Live sessions by kind: mcp (seen within the session TTL) and ui (dashboard)"
    );
    describe_gauge!(
        "axon_tokens_active",
        "API tokens neither revoked nor expired, by kind (pat, service)"
    );
    describe_gauge!(
        "axon_db_pool_connections",
        "Database pool connections of this replica by state (idle, used)"
    );
    describe_gauge!(
        "axon_db_pool_max",
        "Maximum connections of the database pool of this replica"
    );
    describe_gauge!(
        "axon_db_up",
        "1 when the last database probe succeeded, else 0"
    );
    describe_gauge!(
        "axon_user_backends",
        "Per-user backends held by this replica by state (connected, idle, failed, other)"
    );
    describe_counter!(
        "axon_oidc_requests_total",
        "Requests to OIDC providers by provider, operation (discovery, token, userinfo, jwks) and result (ok, error)"
    );
    describe_histogram!(
        "axon_oidc_request_duration_seconds",
        "Duration of requests to OIDC providers by provider and operation"
    );
    describe_gauge!(
        "axon_oidc_provider_up",
        "1 when the last request to the OIDC provider succeeded, else 0"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenIdentity;
    use crate::policy::{OptOuts, Policy, RbacConfig};
    use crate::principal::{PrincipalPolicy, TokenScope};

    fn principal(label: &str, owner: Option<Uuid>, service: bool) -> Caller {
        let effective = Policy::from_config(&RbacConfig::default()).effective(&[]);
        let policy = PrincipalPolicy::new(
            label.to_owned(),
            effective,
            OptOuts::default(),
            TokenScope::default(),
        )
        .with_identity(owner, None);
        Caller::Principal(if service {
            policy.with_service_account()
        } else {
            policy
        })
    }

    #[test]
    fn principal_types_tell_the_callers_apart() {
        assert_eq!(principal_type(&Caller::Open), "open");
        let token = Caller::Token(TokenIdentity {
            name: "ci".to_owned(),
            allowed_tools: Vec::new(),
            allowed_backends: Vec::new(),
            rate_limit_per_minute: 0,
        });
        assert_eq!(principal_type(&token), "legacy_token");
        let user = Some(Uuid::from_u128(1));
        assert_eq!(
            principal_type(&principal("a@b.c / laptop", user, false)),
            "pat"
        );
        // A principal without an owner and without the service flag is not a service
        assert_eq!(principal_type(&principal("config:ci", None, false)), "pat");
        assert_eq!(
            principal_type(&principal("config:ci", None, true)),
            "service"
        );
        assert_eq!(
            principal_type(&principal("ci / deploy", user, true)),
            "service"
        );
    }

    #[test]
    fn user_backend_states_are_bounded() {
        assert_eq!(user_backend_state(BackendState::Connected), "connected");
        assert_eq!(user_backend_state(BackendState::Idle), "idle");
        assert_eq!(user_backend_state(BackendState::Failed), "failed");
        assert_eq!(user_backend_state(BackendState::CircuitOpen), "other");
        assert_eq!(user_backend_state(BackendState::Connecting), "other");
    }
}
