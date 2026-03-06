//! HTTP Server - Exposes the MCP gateway via SSE/HTTP
//!
//! Provides:
//! - POST /mcp - JSON-RPC endpoint (Streamable HTTP)
//! - GET /mcp/sse - SSE endpoint for streaming
//! - GET /health - Health check
//! - GET /status - Gateway status
//! - GET /status/detailed - Detailed backend status
//! - GET /metrics - Prometheus metrics
//! - POST /admin/backends/{name}/reconnect - Force reconnect a backend
//! - POST /admin/backends/{name}/disable - Disable a backend
//! - POST /admin/backends/{name}/enable - Enable a backend
//! - POST /admin/reload - Reload configuration

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{
        IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use futures::stream::{self, Stream};
use kameo::actor::ActorRef;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::auth::{AuthError, AuthManager, TokenIdentity};
use crate::config::Config;
use crate::error::ServerError;
use crate::gateway::{
    DisableBackendMsg, EnableBackendMsg, ForceBackendReconnect, GatewayActor, GetDetailedStatus,
    GetStatus, HandleRequest, ReloadConfig,
};
use crate::types::JsonRpcRequest;

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct AppState {
    pub gateway: ActorRef<GatewayActor>,
    pub auth_manager: Arc<AuthManager>,
    pub config_path: Option<String>,
    /// Prometheus metrics handle for rendering
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
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
        .route("/status/detailed", get(get_detailed_status))
        // Metrics endpoint
        .route("/metrics", get(prometheus_metrics))
        // Admin endpoints
        .route(
            "/admin/backends/{name}/reconnect",
            post(force_backend_reconnect),
        )
        .route("/admin/backends/{name}/disable", post(disable_backend))
        .route("/admin/backends/{name}/enable", post(enable_backend))
        .route("/admin/reload", post(reload_config))
        // Middleware
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .map(|id| id.0.clone())
                    .unwrap_or_default();

                tracing::info_span!(
                    "http_request",
                    request_id = %request_id,
                    method = %request.method(),
                    uri = %request.uri(),
                )
            }),
        )
        .with_state(state)
}

/// Request ID for tracing
#[derive(Clone)]
struct RequestId(String);

/// Middleware to add request ID and record HTTP metrics
async fn request_id_middleware(mut request: Request<axum::body::Body>, next: Next) -> Response {
    // Check for existing request ID in header, or generate a new one
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| Uuid::new_v4().to_string(), String::from);

    let method = request.method().to_string();
    let path = request.uri().path().to_string();

    // Store in request extensions for later use
    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));

    // Add request ID to response headers
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());

    // Record HTTP request metrics
    crate::metrics::record_http_request(&method, &path, response.status().as_u16());

    response
}

/// Extract and validate auth token from request headers.
///
/// Returns `Ok(Some(identity))` for named tokens, `Ok(None)` for shared
/// token or no auth configured, or `Err(StatusCode)` on auth failure.
fn verify_auth(
    headers: &HeaderMap,
    auth_manager: &AuthManager,
) -> Result<Option<TokenIdentity>, StatusCode> {
    if !auth_manager.auth_required() {
        return Ok(None);
    }

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let provided_token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    if provided_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match auth_manager.validate_token(provided_token) {
        Ok(identity) => Ok(identity),
        Err(AuthError::RateLimited { .. }) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Handle POST /mcp - JSON-RPC over HTTP
async fn handle_mcp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let identity = verify_auth(&headers, &state.auth_manager)?;

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
    let _identity = verify_auth(&headers, &state.auth_manager)?;

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

/// Detailed gateway status endpoint
async fn get_detailed_status(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get detailed status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(status))
}

/// Force reconnect a backend
async fn force_backend_reconnect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    // Admin endpoints require auth
    let _identity = verify_auth(&headers, &state.auth_manager)?;

    // When Reply = Result<T, E>, ask().await returns Result<T, SendError<M, E>>
    let result = state
        .gateway
        .ask(ForceBackendReconnect {
            backend_name: name.clone(),
        })
        .await;

    match result {
        Ok(()) => Ok(Json(json!({
            "status": "ok",
            "message": format!("Backend '{}' reconnect initiated", name)
        }))),
        Err(e) => {
            tracing::warn!("Force reconnect failed for '{}': {:?}", name, e);
            Ok(Json(json!({
                "status": "error",
                "message": format!("{:?}", e)
            })))
        }
    }
}

/// Reload configuration from file
async fn reload_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // Admin endpoints require auth
    let _identity = verify_auth(&headers, &state.auth_manager)?;

    let config_path = state.config_path.as_ref().ok_or_else(|| {
        tracing::error!("Config path not set, cannot reload");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Load the new config
    let new_config = Config::load(config_path).map_err(|e| {
        tracing::error!("Failed to load config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Send reload message to gateway
    match state.gateway.ask(ReloadConfig { config: new_config }).await {
        Ok(result) => Ok(Json(json!({
            "status": "ok",
            "added": result.added,
            "removed": result.removed,
            "errors": result.errors
        }))),
        Err(e) => {
            tracing::error!("Config reload failed: {:?}", e);
            Ok(Json(json!({
                "status": "error",
                "message": format!("{:?}", e)
            })))
        }
    }
}

/// Prometheus metrics endpoint
async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics_handle.render()
}

/// Disable a backend (stop routing traffic to it)
async fn disable_backend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager)?;

    match state
        .gateway
        .ask(DisableBackendMsg {
            backend_name: name.clone(),
        })
        .await
    {
        Ok(()) => Ok(Json(json!({
            "status": "ok",
            "message": format!("Backend '{name}' disabled")
        }))),
        Err(e) => {
            tracing::warn!("Failed to disable backend '{}': {:?}", name, e);
            Ok(Json(json!({
                "status": "error",
                "message": format!("{e:?}")
            })))
        }
    }
}

/// Enable a previously disabled backend
async fn enable_backend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager)?;

    match state
        .gateway
        .ask(EnableBackendMsg {
            backend_name: name.clone(),
        })
        .await
    {
        Ok(()) => Ok(Json(json!({
            "status": "ok",
            "message": format!("Backend '{name}' enabled")
        }))),
        Err(e) => {
            tracing::warn!("Failed to enable backend '{}': {:?}", name, e);
            Ok(Json(json!({
                "status": "error",
                "message": format!("{e:?}")
            })))
        }
    }
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
