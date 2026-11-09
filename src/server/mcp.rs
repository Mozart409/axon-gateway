//! MCP JSON-RPC endpoints (`/mcp`, `/mcp/sse`, `/mcp/toolset/{name}`, plus the
//! deprecated alias `/mcp/group/{name}`) and the toolset listing.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
};
use futures::stream;
use serde_json::json;

use super::AppState;
use super::auth::authenticate;
use crate::auth::AuthManager;
use crate::gateway::{Caller, HandleRequest, HandleToolsetRequest};
use crate::types::JsonRpcRequest;

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
fn log_principal(caller: &Caller, request: &JsonRpcRequest) {
    if let Caller::Principal(principal) = caller {
        tracing::debug!(principal = principal.label(), method = %request.method, "MCP request");
    }
}

/// Handle POST /mcp - JSON-RPC over HTTP
pub(super) async fn handle_mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let caller = match authenticate(&headers, &state).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    if let Some(accepted) = accept_notification(&request) {
        return accepted;
    }
    log_principal(&caller, &request);

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

    match state
        .gateway
        .ask(HandleRequest {
            request,
            caller: Arc::new(caller),
        })
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Handle GET /mcp/sse - Server-Sent Events endpoint
///
/// For MCP SSE transport, the flow is:
/// 1. Client connects to SSE endpoint
/// 2. Server sends `endpoint` event with POST URL
/// 3. Client sends JSON-RPC requests to that POST URL
/// 4. Server streams responses via SSE
pub(super) async fn handle_mcp_sse(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = authenticate(&headers, &state).await {
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
/// Same as `/mcp` but only lists tools in the specified toolset.
/// Tool calls are forwarded normally (no restriction to toolset tools at call time).
pub(super) async fn handle_toolset_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(toolset_name): Path<String>,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let caller = match authenticate(&headers, &state).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    if let Some(accepted) = accept_notification(&request) {
        return accepted;
    }
    log_principal(&caller, &request);

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

    match state
        .gateway
        .ask(HandleToolsetRequest {
            request,
            caller: Arc::new(caller),
            toolset_name,
        })
        .await
    {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
