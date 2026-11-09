//! MCP JSON-RPC endpoints (`/mcp`, `/mcp/sse`, `/mcp/group/{name}`) and the
//! tool group listing.

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
use futures::stream::{self, Stream};
use serde_json::json;

use super::AppState;
use super::auth::verify_auth;
use crate::auth::AuthManager;
use crate::gateway::{HandleGroupRequest, HandleRequest};
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

/// Handle POST /mcp - JSON-RPC over HTTP
pub(super) async fn handle_mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Result<Response, StatusCode> {
    let identity = verify_auth(&headers, &state.auth_manager.load())?;
    if let Some(accepted) = accept_notification(&request) {
        return Ok(accepted);
    }

    // For tool calls, check tool-level permissions
    if request.method == "tools/call"
        && let Some(tool_name) = request.params.get("name").and_then(|v| v.as_str())
        && let Err(e) = AuthManager::check_tool_permission(identity.as_ref(), tool_name)
    {
        tracing::warn!("Tool permission denied: {e}");
        return Err(StatusCode::FORBIDDEN);
    }

    let response = state
        .gateway
        .ask(HandleRequest {
            request,
            identity: identity.map(Arc::new),
        })
        .await
        .map_err(|e| {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(response).into_response())
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
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager.load())?;

    // For SSE transport, we send an initial "endpoint" message
    // Real implementation would maintain a session and stream responses
    let stream = stream::once(async { Ok(Event::default().event("endpoint").data("/mcp")) });

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("ping"),
    ))
}

/// Handle tool group endpoint - JSON-RPC scoped to a tool group
///
/// Same as `/mcp` but only lists tools in the specified group.
/// Tool calls are forwarded normally (no restriction to group tools at call time).
pub(super) async fn handle_group_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_name): Path<String>,
    Json(request): Json<JsonRpcRequest>,
) -> Result<Response, StatusCode> {
    let identity = verify_auth(&headers, &state.auth_manager.load())?;
    if let Some(accepted) = accept_notification(&request) {
        return Ok(accepted);
    }

    // For tool calls, check tool-level permissions
    if request.method == "tools/call"
        && let Some(tool_name) = request.params.get("name").and_then(|v| v.as_str())
        && let Err(e) = AuthManager::check_tool_permission(identity.as_ref(), tool_name)
    {
        tracing::warn!("Tool permission denied: {e}");
        return Err(StatusCode::FORBIDDEN);
    }

    let response = state
        .gateway
        .ask(HandleGroupRequest {
            request,
            identity: identity.map(Arc::new),
            group_name,
        })
        .await
        .map_err(|e| {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(response).into_response())
}

/// List available tool groups
pub(super) async fn list_tool_groups(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let groups = state
        .gateway
        .ask(crate::gateway::GetToolGroups)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list tool groups: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({ "groups": groups })))
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
    #[case("/mcp/group/any", "notifications/initialized")]
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
