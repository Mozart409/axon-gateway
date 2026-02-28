//! HTTP Server - Exposes the MCP gateway via SSE/HTTP
//!
//! Provides:
//! - POST /mcp - JSON-RPC endpoint (Streamable HTTP)
//! - GET /mcp/sse - SSE endpoint for streaming
//! - GET /health - Health check
//! - GET /status - Gateway status

use crate::error::ServerError;
use crate::gateway::{GatewayActor, GetStatus, HandleRequest};
use crate::types::JsonRpcRequest;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Json,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures::stream::{self, Stream};
use kameo::actor::ActorRef;
use serde_json::json;
use std::{convert::Infallible, time::Duration};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct AppState {
    pub gateway: ActorRef<GatewayActor>,
    pub auth_token: Option<String>,
}

/// Create the Axum router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // MCP endpoints
        .route("/mcp", post(handle_mcp_request))
        .route("/mcp/sse", get(handle_mcp_sse))
        // Status endpoints
        .route("/health", get(health_check))
        .route("/status", get(get_status))
        // Middleware
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Verify auth token if configured
fn verify_auth(headers: &HeaderMap, expected: Option<&String>) -> Result<(), StatusCode> {
    if let Some(token) = expected {
        let auth_header = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let provided_token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

        if provided_token != token {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(())
}

/// Handle POST /mcp - JSON-RPC over HTTP
async fn handle_mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_auth(&headers, state.auth_token.as_ref())?;

    let response = state
        .gateway
        .ask(HandleRequest { request })
        .await
        .map_err(|e| {
            tracing::error!("Gateway error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(response))
}

/// Handle GET /mcp/sse - Server-Sent Events endpoint
///
/// For MCP SSE transport, the flow is:
/// 1. Client connects to SSE endpoint
/// 2. Server sends `endpoint` event with POST URL
/// 3. Client sends JSON-RPC requests to that POST URL
/// 4. Server streams responses via SSE
async fn handle_mcp_sse(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    verify_auth(&headers, state.auth_token.as_ref())?;

    // For SSE transport, we send an initial "endpoint" message
    // Real implementation would maintain a session and stream responses
    let stream = stream::once(async { Ok(Event::default().event("endpoint").data("/mcp")) });

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("ping"),
    ))
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Gateway status endpoint
async fn get_status(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let status = state.gateway.ask(GetStatus).await.map_err(|e| {
        tracing::error!("Failed to get status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(status))
}

/// Start the HTTP server
pub async fn serve(state: AppState, bind: &str) -> Result<(), ServerError> {
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|source| ServerError::BindFailed {
            address: bind.to_string(),
            source,
        })?;
    tracing::info!("MCP Gateway listening on {}", bind);

    axum::serve(listener, router).await?;

    Ok(())
}
