//! MCP JSON-RPC endpoints (`/mcp`, `/mcp/sse`, `/mcp/toolset/{name}`, plus the
//! deprecated alias `/mcp/group/{name}`) and the toolset listing.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
};
use futures::stream;
use serde_json::{Value, json};

use super::AppState;
use super::auth::{ClientIp, authenticate};
use crate::audit::{CallOutcome, ToolCallEvent};
use crate::auth::AuthManager;
use crate::gateway::{Caller, DescribeTool, HandleRequest, HandleToolsetRequest};
use crate::principal::{PrincipalPolicy, TokenScope};
use crate::types::{JsonRpcRequest, JsonRpcResponse};

/// Longest `User-Agent` kept in the audit.
const MAX_USER_AGENT_CHARS: usize = 200;

/// JSON-RPC code of a gateway that failed to answer.
const INTERNAL_ERROR: i32 = -32603;

/// What the tool-call audit needs from a `tools/call` made by a principal,
/// taken before the call so the time can be measured around it.
struct CallAudit {
    principal: PrincipalPolicy,
    name: String,
    arguments: Value,
    client_ip: Option<String>,
    user_agent: Option<String>,
    trace_id: Option<String>,
    started: Instant,
}

impl CallAudit {
    /// `Some` for a `tools/call` of a principal while the audit is on. Legacy
    /// token and open callers (standalone mode) are not recorded.
    fn start(
        state: &AppState,
        caller: &Caller,
        request: &JsonRpcRequest,
        client_ip: Option<&str>,
        headers: &HeaderMap,
    ) -> Option<Self> {
        let Caller::Principal(principal) = caller else {
            return None;
        };
        if request.method != "tools/call" || state.audit.is_none() {
            return None;
        }
        Some(Self {
            principal: principal.clone(),
            name: request
                .params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            arguments: request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Null),
            client_ip: client_ip.map(str::to_owned),
            user_agent: headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok())
                .map(|agent| agent.chars().take(MAX_USER_AGENT_CHARS).collect()),
            trace_id: crate::telemetry::current_trace_id(),
            started: Instant::now(),
        })
    }

    /// Queues the event. The tool lookup and the queueing run in a task, so
    /// the response is not delayed; the arguments are never logged here.
    fn finish(self, state: &AppState, response: Option<&JsonRpcResponse>) {
        let Some(sink) = state.audit.clone() else {
            return;
        };
        let duration = self.started.elapsed();
        let (outcome, error_code, error_message) = outcome_of(response);
        let gateway = state.gateway.clone();
        tokio::spawn(async move {
            let described = gateway
                .ask(DescribeTool {
                    namespaced_name: self.name.clone(),
                })
                .await
                .ok()
                .flatten();
            let (backend, tool, annotations) = match described {
                Some(tool) => (tool.backend_name, tool.original_tool_name, tool.annotations),
                None => (String::new(), self.name, None),
            };
            sink.record(ToolCallEvent {
                user_id: self.principal.owner_id(),
                principal_label: self.principal.label().to_owned(),
                token_id: self.principal.token_id(),
                auth_method: if self.principal.token_id().is_some() {
                    "pat"
                } else {
                    "config_token"
                }
                .to_owned(),
                backend,
                tool,
                outcome,
                error_code,
                error_message,
                duration,
                trace_id: self.trace_id,
                client_ip: self.client_ip,
                user_agent: self.user_agent,
                arguments: self.arguments,
                annotations,
            });
        });
    }
}

/// The audit outcome of a gateway answer: a JSON-RPC error, a tool result with
/// `isError` (message from its first text content), or success. No answer at
/// all counts as an internal error.
fn outcome_of(response: Option<&JsonRpcResponse>) -> (CallOutcome, Option<i32>, Option<String>) {
    let Some(response) = response else {
        return (
            CallOutcome::Error,
            Some(INTERNAL_ERROR),
            Some("gateway error".to_owned()),
        );
    };
    if let Some(error) = &response.error {
        return (
            CallOutcome::Error,
            Some(error.code),
            Some(error.message.clone()),
        );
    }
    let result = response.result.as_ref();
    if result
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let message = result
            .and_then(|result| result.get("content"))
            .and_then(Value::as_array)
            .and_then(|content| {
                content
                    .iter()
                    .find_map(|item| item.get("text").and_then(Value::as_str).map(str::to_owned))
            });
        return (CallOutcome::ToolError, None, message);
    }
    (CallOutcome::Ok, None, None)
}

/// Records the call when it is audited and turns the gateway's answer into the
/// HTTP response.
fn reply<E: std::fmt::Debug>(
    state: &AppState,
    audit: Option<CallAudit>,
    result: Result<JsonRpcResponse, E>,
) -> Response {
    if let Some(audit) = audit {
        audit.finish(state, result.as_ref().ok());
    }
    match result {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Answer a JSON-RPC notification (a message without an `id`).
///
/// Notifications get no JSON-RPC response; the Streamable HTTP transport
/// acknowledges them with `202 Accepted` and an empty body. The gateway has
/// nothing to do for any of them (`initialized`, `cancelled`, ...), so they are
/// not forwarded.
fn accept_notification(request: &JsonRpcRequest) -> Option<Response> {
    if request.id.is_some() {
        return None;
    }
    tracing::debug!(method = %request.method, "Accepted JSON-RPC notification");
    Some(StatusCode::ACCEPTED.into_response())
}

/// Log which principal (user or service account and token) sent a request.
fn log_principal(caller: &Caller, request: &JsonRpcRequest, client_ip: Option<&str>) {
    if let Caller::Principal(principal) = caller {
        tracing::debug!(
            principal = principal.label(),
            method = %request.method,
            ip = client_ip,
            "MCP request"
        );
    }
}

/// Handle POST /mcp - JSON-RPC over HTTP
pub(super) async fn handle_mcp_request(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let caller = match authenticate(&headers, &state, client_ip.as_deref()).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    if let Some(accepted) = accept_notification(&request) {
        return accepted;
    }
    log_principal(&caller, &request, client_ip.as_deref());

    // For tool calls, check tool-level permissions of a legacy token. A
    // principal's are checked in the gateway, which answers a tool it may not
    // call like an unknown one.
    if request.method == "tools/call"
        && let Caller::Token(identity) = &caller
        && let Some(tool_name) = request.params.get("name").and_then(|v| v.as_str())
        && let Err(e) = AuthManager::check_tool_permission(Some(identity), tool_name)
    {
        tracing::warn!("Tool permission denied: {e}");
        return StatusCode::FORBIDDEN.into_response();
    }

    let audit = CallAudit::start(&state, &caller, &request, client_ip.as_deref(), &headers);
    let result = state
        .gateway
        .ask(HandleRequest {
            request,
            caller: Arc::new(caller),
        })
        .await;
    reply(&state, audit, result)
}

/// Handle GET /mcp/sse - Server-Sent Events endpoint
///
/// For MCP SSE transport, the flow is:
/// 1. Client connects to SSE endpoint
/// 2. Server sends `endpoint` event with POST URL
/// 3. Client sends JSON-RPC requests to that POST URL
/// 4. Server streams responses via SSE
pub(super) async fn handle_mcp_sse(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = authenticate(&headers, &state, client_ip.as_deref()).await {
        return *response;
    }

    // For SSE transport, we send an initial "endpoint" message
    // Real implementation would maintain a session and stream responses
    let stream = stream::once(async {
        Ok::<_, Infallible>(Event::default().event("endpoint").data("/mcp"))
    });

    Sse::new(stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(Duration::from_secs(30))
                .text("ping"),
        )
        .into_response()
}

/// Handle toolset endpoint - JSON-RPC scoped to a toolset
///
/// Same as `/mcp` but only lists tools in the specified toolset. Tool calls are
/// forwarded normally (no restriction to toolset tools at call time), except for a
/// principal that owns a toolset of that name: the toolset then narrows the principal
/// like a pinned one, and the request is handled as on `/mcp`, listing and calls both.
pub(super) async fn handle_toolset_request(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(toolset_name): Path<String>,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let caller = match authenticate(&headers, &state, client_ip.as_deref()).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    if let Some(accepted) = accept_notification(&request) {
        return accepted;
    }
    log_principal(&caller, &request, client_ip.as_deref());

    // For tool calls, check tool-level permissions of a legacy token. A
    // principal's are checked in the gateway, which answers a tool it may not
    // call like an unknown one.
    if request.method == "tools/call"
        && let Caller::Token(identity) = &caller
        && let Some(tool_name) = request.params.get("name").and_then(|v| v.as_str())
        && let Err(e) = AuthManager::check_tool_permission(Some(identity), tool_name)
    {
        tracing::warn!("Tool permission denied: {e}");
        return StatusCode::FORBIDDEN.into_response();
    }

    let audit = CallAudit::start(&state, &caller, &request, client_ip.as_deref(), &headers);
    let caller = match own_toolset(&state, caller, &toolset_name).await {
        Ok(Ok(principal)) => {
            let result = state
                .gateway
                .ask(HandleRequest {
                    request,
                    caller: Arc::new(Caller::Principal(principal)),
                })
                .await;
            return reply(&state, audit, result);
        }
        Ok(Err(caller)) => caller,
        Err(response) => return *response,
    };

    let result = state
        .gateway
        .ask(HandleToolsetRequest {
            request,
            caller: Arc::new(caller),
            toolset_name,
        })
        .await;
    reply(&state, audit, result)
}

/// Narrows a principal with its own toolset called `name`. `Ok(Ok(narrowed))` when it
/// has one, `Ok(Err(caller))` hands the caller back for the config toolset path (no
/// owner, no multi-user store, or no such toolset), `Err` is a store failure.
async fn own_toolset(
    state: &AppState,
    caller: Caller,
    name: &str,
) -> Result<Result<PrincipalPolicy, Caller>, Box<Response>> {
    let (Caller::Principal(principal), Some((store, _))) = (&caller, state.multi_user()) else {
        return Ok(Err(caller));
    };
    let Some(owner_id) = principal.owner_id() else {
        return Ok(Err(caller));
    };
    match store.toolset_by_name(owner_id, name).await {
        Ok(Some(toolset)) => {
            let scope = TokenScope {
                backends: toolset.backends,
                tools: toolset.tools,
            };
            match caller {
                Caller::Principal(principal) => Ok(Ok(principal.with_toolset(scope))),
                other => Ok(Err(other)),
            }
        }
        Ok(None) => Ok(Err(caller)),
        Err(error) => {
            tracing::error!("Failed to look up a user toolset: {error}");
            Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))
        }
    }
}

/// List available toolsets
pub(super) async fn list_toolsets(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let toolsets = state
        .gateway
        .ask(crate::gateway::GetToolsets)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list toolsets: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({ "toolsets": toolsets })))
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::server::create_router;
    use crate::server::tests::test_state;

    async fn post_mcp(uri: &str, body: serde_json::Value) -> (StatusCode, Vec<u8>) {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .method(http::Method::POST)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        (status, body.to_vec())
    }

    #[rstest::rstest]
    #[case("/mcp", "notifications/initialized")]
    #[case("/mcp", "notifications/cancelled")]
    #[case("/mcp/toolset/any", "notifications/initialized")]
    #[tokio::test]
    async fn notifications_get_202_with_empty_body(#[case] uri: &str, #[case] method: &str) {
        let (status, body) = post_mcp(
            uri,
            json!({ "jsonrpc": "2.0", "method": method, "params": {} }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(body.is_empty(), "notification body must be empty");
    }

    #[tokio::test]
    async fn requests_with_id_still_get_a_json_response() {
        let (status, body) = post_mcp(
            "/mcp",
            json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let payload: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(payload["id"], 7);
    }
}
