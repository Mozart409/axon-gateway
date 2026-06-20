//! HTTP Server - Exposes the MCP gateway via SSE/HTTP
//!
//! Provides:
//! - POST /mcp - JSON-RPC endpoint (Streamable HTTP)
//! - GET /mcp/sse - SSE endpoint for streaming
//! - POST /mcp/group/{name} - JSON-RPC scoped to a tool group
//! - GET /health - Health check
//! - GET /build - Build and process metadata
//! - GET /status - Gateway status
//! - GET /status/detailed - Detailed backend status
//! - GET /ui - Dashboard
//! - GET /ui/backends/{name} - Backend detail page
//! - GET /status/groups - List tool groups
//! - GET /metrics - Prometheus metrics
//!
//! HTML rendering lives in the [`views`] submodule; this module owns routing,
//! request handling, middleware, and server lifecycle.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Json, Response,
        sse::{Event, Sse},
    },
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use futures::stream::{self, Stream};
use kameo::actor::ActorRef;
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::auth::{AuthError, AuthManager, TokenIdentity};
use crate::config::Config;
use crate::error::ServerError;
use crate::gateway::{
    DetailedGatewayStatus, DisableBackendMsg, EnableBackendMsg, ForceBackendReconnect,
    GatewayActor, GetDetailedStatus, GetStatus, HandleGroupRequest, HandleRequest, ReloadConfig,
};
use crate::types::{JsonRpcRequest, PromptDefinition, ResourceDefinition};

mod views;

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct AppState {
    pub gateway: ActorRef<GatewayActor>,
    pub auth_manager: Arc<AuthManager>,
    pub config_path: Option<String>,
    pub base_url: String,
    pub ui_events: broadcast::Sender<UiEvent>,
    pub sse_clients: Arc<AtomicU64>,
    pub started_at: SystemTime,
    pub process_id: u32,
    /// Prometheus metrics handle for rendering
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

#[derive(Clone, Debug)]
pub enum UiEvent {
    BackendStatusChanged(DetailedGatewayStatus),
    ConfigReloaded {
        added: Vec<String>,
        removed: Vec<String>,
        errors: Vec<String>,
    },
    Flash(FlashMessage),
}

#[derive(Clone, Debug, Serialize)]
pub enum FlashLevel {
    Success,
    Error,
    Info,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlashMessage {
    pub level: FlashLevel,
    pub message: String,
}

/// Create the Axum router
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Landing page
        .route("/", get(handle_landing))
        // MCP endpoints
        .route("/mcp", post(handle_mcp_request))
        .route("/mcp/sse", get(handle_mcp_sse))
        .route_service("/styles/output.css", ServeFile::new("styles/output.css"))
        .route_service("/favicon.svg", ServeFile::new("static/favicon.svg"))
        // UI endpoints
        .route("/ui", get(handle_ui))
        .route("/ui/backends/{name}", get(handle_ui_backend_detail))
        .route("/ui/events", get(handle_ui_events))
        .route("/ui/partials/backends", get(handle_ui_backends_partial))
        .route(
            "/ui/actions/backends/{name}/reconnect",
            post(handle_ui_reconnect_backend),
        )
        .route(
            "/ui/actions/backends/{name}/disable",
            post(handle_ui_disable_backend),
        )
        .route(
            "/ui/actions/backends/{name}/enable",
            post(handle_ui_enable_backend),
        )
        .route("/ui/actions/reload", post(handle_ui_reload_config))
        // Status endpoints
        .route("/health", get(health_check))
        .route("/build", get(get_build_info))
        .route("/status", get(get_status))
        .route("/status/detailed", get(get_detailed_status))
        // Tool group endpoints (subset of tools via named groups)
        .route("/mcp/group/{group_name}", post(handle_group_request))
        .route("/status/groups", get(list_tool_groups))
        // Metrics endpoint
        .route("/metrics", get(prometheus_metrics))
        // Middleware
        .layer(middleware::from_fn(request_id_middleware))
        .layer(CorsLayer::permissive())
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
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
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .fallback(handle_not_found)
        .with_state(state)
}

/// Handle GET / - simple landing page
async fn handle_landing(State(state): State<AppState>) -> Html<String> {
    Html(views::render_landing_page(&state).into_string())
}

/// Global 404 page for unmatched routes
async fn handle_not_found(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Html(views::render_not_found_page(&state).into_string()),
    )
}

/// Handle GET /ui - SSR dashboard
async fn handle_ui(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get UI backend status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let page = views::render_ui_page(&status, &state);
    Ok(Html(page.into_string()))
}

/// Handle GET /ui/backends/{name} - backend detail page
async fn handle_ui_backend_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!(backend = %name, "Failed to get UI backend detail status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(backend) = status
        .backends
        .into_iter()
        .find(|backend| backend.name == name)
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let prompts = fetch_backend_prompts(&state, &backend.name).await;
    let resources = fetch_backend_resources(&state, &backend.name).await;

    let page = views::render_ui_backend_detail_page(&backend, &prompts, &resources, &state);
    Ok(Html(page.into_string()))
}

/// Handle GET /ui/partials/backends - HTML fragment for backend list
async fn handle_ui_backends_partial(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get backend partial status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(views::render_backend_panel(&status).into_string()))
}

/// Handle GET /ui/events - SSE stream for HTMX updates
async fn handle_ui_events(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let initial_status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to load initial UI status for SSE: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let active = state.sse_clients.fetch_add(1, Ordering::SeqCst) + 1;
    crate::metrics::record_ui_sse_lifecycle("connect");
    crate::metrics::record_ui_sse_clients(active);
    tracing::info!(active_clients = active, "UI SSE client connected");

    let guard = SseClientGuard {
        clients: Arc::clone(&state.sse_clients),
    };
    let stream = stream::unfold(
        (
            Some(UiEvent::BackendStatusChanged(initial_status)),
            state.ui_events.subscribe(),
            guard,
        ),
        |(initial, mut rx, guard)| async move {
            let event = if let Some(event) = initial {
                event
            } else {
                match rx.recv().await {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::metrics::record_ui_sse_dropped(skipped);
                        tracing::warn!(skipped, "UI SSE client lagged behind event stream");
                        UiEvent::Flash(FlashMessage {
                            level: FlashLevel::Error,
                            message: format!(
                                "Live updates dropped ({skipped}). Dashboard will continue with latest state."
                            ),
                        })
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            };

            let event_name = ui_event_name(&event);
            crate::metrics::record_ui_sse_event(event_name);
            Some((Ok(ui_event_to_sse(event)), (None, rx, guard)))
        },
    );

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("ping"),
    ))
}

async fn handle_ui_reconnect_backend(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let flash = match state
        .gateway
        .ask(ForceBackendReconnect {
            backend_name: name.clone(),
        })
        .await
    {
        Ok(()) => FlashMessage {
            level: FlashLevel::Success,
            message: format!("Reconnect started for backend '{name}'"),
        },
        Err(e) => FlashMessage {
            level: FlashLevel::Error,
            message: format!("Reconnect failed for '{name}': {e:?}"),
        },
    };

    publish_ui_event(&state.ui_events, UiEvent::Flash(flash.clone()));
    refresh_ui_backend_snapshot(&state).await;
    Ok(Html(views::render_flash(&flash).into_string()))
}

async fn handle_ui_disable_backend(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let flash = match state
        .gateway
        .ask(DisableBackendMsg {
            backend_name: name.clone(),
        })
        .await
    {
        Ok(()) => FlashMessage {
            level: FlashLevel::Success,
            message: format!("Backend '{name}' disabled"),
        },
        Err(e) => FlashMessage {
            level: FlashLevel::Error,
            message: format!("Disable failed for '{name}': {e:?}"),
        },
    };

    publish_ui_event(&state.ui_events, UiEvent::Flash(flash.clone()));
    refresh_ui_backend_snapshot(&state).await;
    Ok(Html(views::render_flash(&flash).into_string()))
}

async fn handle_ui_enable_backend(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Html<String>, StatusCode> {
    let flash = match state
        .gateway
        .ask(EnableBackendMsg {
            backend_name: name.clone(),
        })
        .await
    {
        Ok(()) => FlashMessage {
            level: FlashLevel::Success,
            message: format!("Backend '{name}' enabled"),
        },
        Err(e) => FlashMessage {
            level: FlashLevel::Error,
            message: format!("Enable failed for '{name}': {e:?}"),
        },
    };

    publish_ui_event(&state.ui_events, UiEvent::Flash(flash.clone()));
    refresh_ui_backend_snapshot(&state).await;
    Ok(Html(views::render_flash(&flash).into_string()))
}

async fn handle_ui_reload_config(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let config_path = state.config_path.as_ref().ok_or_else(|| {
        tracing::error!("Config path not set, cannot reload from UI action");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let flash = match Config::load(config_path) {
        Ok(new_config) => match state.gateway.ask(ReloadConfig { config: new_config }).await {
            Ok(result) => {
                publish_ui_event(
                    &state.ui_events,
                    UiEvent::ConfigReloaded {
                        added: result.added.clone(),
                        removed: result.removed.clone(),
                        errors: result.errors.clone(),
                    },
                );
                let message = format!(
                    "Config reloaded (added: {}, removed: {}, errors: {})",
                    result.added.len(),
                    result.removed.len(),
                    result.errors.len()
                );
                FlashMessage {
                    level: if result.errors.is_empty() {
                        FlashLevel::Success
                    } else {
                        FlashLevel::Info
                    },
                    message,
                }
            }
            Err(e) => FlashMessage {
                level: FlashLevel::Error,
                message: format!("Config reload failed: {e:?}"),
            },
        },
        Err(e) => FlashMessage {
            level: FlashLevel::Error,
            message: format!("Failed to read config: {e}"),
        },
    };

    publish_ui_event(&state.ui_events, UiEvent::Flash(flash.clone()));
    refresh_ui_backend_snapshot(&state).await;
    Ok(Html(views::render_flash(&flash).into_string()))
}

fn publish_ui_event(sender: &broadcast::Sender<UiEvent>, event: UiEvent) {
    if let Err(e) = sender.send(event) {
        tracing::debug!("No UI subscribers for event broadcast: {e}");
    }
}

async fn refresh_ui_backend_snapshot(state: &AppState) {
    match state.gateway.ask(GetDetailedStatus).await {
        Ok(status) => publish_ui_event(&state.ui_events, UiEvent::BackendStatusChanged(status)),
        Err(e) => {
            tracing::warn!(
                "Failed to refresh UI backend snapshot after action: {:?}",
                e
            );
        }
    }
}

fn ui_event_name(event: &UiEvent) -> &'static str {
    match event {
        UiEvent::BackendStatusChanged(_) => "backend_status_changed",
        UiEvent::ConfigReloaded { .. } => "config_reloaded",
        UiEvent::Flash(_) => "flash",
    }
}

fn ui_event_to_sse(event: UiEvent) -> Event {
    match event {
        UiEvent::BackendStatusChanged(status) => Event::default()
            .event("backend_status_changed")
            .data(views::render_backend_panel(&status).into_string()),
        UiEvent::ConfigReloaded {
            added,
            removed,
            errors,
        } => Event::default().event("config_reloaded").data(
            views::render_flash(&FlashMessage {
                level: if errors.is_empty() {
                    FlashLevel::Success
                } else {
                    FlashLevel::Info
                },
                message: format!(
                    "Config reloaded (added: {}, removed: {}, errors: {})",
                    added.len(),
                    removed.len(),
                    errors.len()
                ),
            })
            .into_string(),
        ),
        UiEvent::Flash(flash) => Event::default()
            .event("flash")
            .data(views::render_flash(&flash).into_string()),
    }
}

async fn fetch_backend_prompts(state: &AppState, backend_name: &str) -> Vec<PromptDefinition> {
    let response = match state
        .gateway
        .ask(HandleRequest {
            request: JsonRpcRequest {
                jsonrpc: String::from("2.0"),
                id: Some(json!("ui-backend-prompts")),
                method: String::from("prompts/list"),
                params: json!({}),
            },
            identity: None,
        })
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(backend = %backend_name, "Failed to fetch prompts for UI detail: {:?}", e);
            return Vec::new();
        }
    };

    let Some(result) = response.result else {
        return Vec::new();
    };

    let Some(prompts_value) = result.get("prompts") else {
        return Vec::new();
    };

    let Ok(prompts) = serde_json::from_value::<Vec<PromptDefinition>>(prompts_value.clone()) else {
        return Vec::new();
    };

    let prefix = format!("{backend_name}_");
    prompts
        .into_iter()
        .filter_map(|mut prompt| {
            let original_name = prompt.name.strip_prefix(&prefix)?;
            prompt.name = original_name.to_string();
            Some(prompt)
        })
        .collect()
}

async fn fetch_backend_resources(state: &AppState, backend_name: &str) -> Vec<ResourceDefinition> {
    let response = match state
        .gateway
        .ask(HandleRequest {
            request: JsonRpcRequest {
                jsonrpc: String::from("2.0"),
                id: Some(json!("ui-backend-resources")),
                method: String::from("resources/list"),
                params: json!({}),
            },
            identity: None,
        })
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!(backend = %backend_name, "Failed to fetch resources for UI detail: {:?}", e);
            return Vec::new();
        }
    };

    let Some(result) = response.result else {
        return Vec::new();
    };

    let Some(resources_value) = result.get("resources") else {
        return Vec::new();
    };

    let Ok(resources) = serde_json::from_value::<Vec<ResourceDefinition>>(resources_value.clone())
    else {
        return Vec::new();
    };

    resources
        .into_iter()
        .filter_map(|mut resource| {
            let (resource_backend, original_uri) = resource.uri.split_once("://")?;
            if resource_backend != backend_name {
                return None;
            }

            resource.uri = original_uri.to_string();
            Some(resource)
        })
        .collect()
}

struct SseClientGuard {
    clients: Arc<AtomicU64>,
}

impl Drop for SseClientGuard {
    fn drop(&mut self) {
        let active = self
            .clients
            .fetch_sub(1, Ordering::SeqCst)
            .saturating_sub(1);
        crate::metrics::record_ui_sse_lifecycle("disconnect");
        crate::metrics::record_ui_sse_clients(active);
        tracing::info!(active_clients = active, "UI SSE client disconnected");
    }
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

/// Handle tool group endpoint - JSON-RPC scoped to a tool group
///
/// Same as `/mcp` but only lists tools in the specified group.
/// Tool calls are forwarded normally (no restriction to group tools at call time).
async fn handle_group_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_name): Path<String>,
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

    Ok(Json(response))
}

/// List available tool groups
async fn list_tool_groups(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
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

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Build and process metadata endpoint
async fn get_build_info(State(state): State<AppState>) -> impl IntoResponse {
    let started_utc: DateTime<Utc> = state.started_at.into();
    let started_unix = state
        .started_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("AXON_GIT_SHA").unwrap_or("dev"),
        "pid": state.process_id,
        "sse_clients": state.sse_clients.load(Ordering::SeqCst),
        "started_utc": started_utc.to_rfc3339(),
        "started_unix": started_unix,
    }))
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

/// Prometheus metrics endpoint
async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics_handle.render()
}

fn start_ui_event_poller(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        let mut previous_snapshot = String::new();

        loop {
            interval.tick().await;

            let status = match state.gateway.ask(GetDetailedStatus).await {
                Ok(status) => status,
                Err(e) => {
                    tracing::warn!("UI event poller failed to fetch backend status: {:?}", e);
                    continue;
                }
            };

            let snapshot = serde_json::to_string(&status).unwrap_or_default();
            if snapshot != previous_snapshot {
                previous_snapshot.clone_from(&snapshot);
                publish_ui_event(&state.ui_events, UiEvent::BackendStatusChanged(status));
            }
        }
    });
}

/// Start the HTTP server
pub async fn serve(
    state: AppState,
    bind: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    start_ui_event_poller(state.clone());
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|source| ServerError::BindFailed {
            address: bind.to_string(),
            source,
        })?;
    tracing::info!("MCP Gateway listening on {}", bind);

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::time::SystemTime;

    use axum::body::{Body, to_bytes};
    use http::Request;
    use kameo::actor::Spawn;
    use kameo::mailbox;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{Config, GatewayConfig};
    use crate::gateway::GatewayActor;
    use crate::registry::RegistryActor;
    use crate::types::{BackendInfo, BackendState};

    fn test_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        static METRICS_HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> =
            OnceLock::new();

        METRICS_HANDLE
            .get_or_init(|| {
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .install_recorder()
                    .expect("metrics recorder should install once in tests")
            })
            .clone()
    }

    fn test_state() -> AppState {
        let config = Config {
            gateway: GatewayConfig {
                bind: String::from("127.0.0.1:0"),
                base_url: String::from("http://127.0.0.1:8080"),
                auth_token: None,
                rate_limit_per_minute: 0,
            },
            backends: Vec::new(),
            tokens: Vec::new(),
            groups: Vec::new(),
        };

        let registry =
            RegistryActor::spawn_with_mailbox(RegistryActor::new(), mailbox::unbounded());
        let gateway = GatewayActor::spawn_with_mailbox(
            GatewayActor::new(config, registry),
            mailbox::unbounded(),
        );

        AppState {
            gateway,
            auth_manager: Arc::new(AuthManager::new(
                &GatewayConfig {
                    bind: String::from("127.0.0.1:0"),
                    base_url: String::from("http://127.0.0.1:8080"),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                &[],
            )),
            config_path: None,
            base_url: String::from("http://127.0.0.1:8080"),
            ui_events: broadcast::channel(64).0,
            sse_clients: Arc::new(AtomicU64::new(0)),
            started_at: SystemTime::now(),
            process_id: std::process::id(),
            metrics_handle: test_metrics_handle(),
        }
    }

    #[test]
    fn ui_event_names_are_stable() {
        let flash = UiEvent::Flash(FlashMessage {
            level: FlashLevel::Info,
            message: String::from("test"),
        });

        assert_eq!(ui_event_name(&flash), "flash");
    }

    #[test]
    fn render_flash_contains_message() {
        let flash = FlashMessage {
            level: FlashLevel::Success,
            message: String::from("done"),
        };

        let markup = views::render_flash(&flash).into_string();
        assert!(markup.contains("done"));
    }

    #[test]
    fn backend_row_links_name_to_detail_page() {
        let backend = BackendInfo::new(
            String::from("filesystem"),
            BackendState::Connected,
            Vec::new(),
            None,
        );

        let markup = views::render_backend_row(&backend).into_string();
        assert!(markup.contains("href=\"/ui/backends/filesystem\""));
    }

    #[tokio::test]
    async fn landing_page_renders() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8(body.to_vec()).expect("html should be utf-8");
        assert!(html.contains("Open Dashboard"));
        assert!(html.contains("Copy MCP URL"));
        assert!(html.contains("http://127.0.0.1:8080/mcp"));
        assert!(html.contains("started:"));
    }

    #[tokio::test]
    async fn ui_page_renders_with_backend_panel() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ui")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8(body.to_vec()).expect("html should be utf-8");
        assert!(html.contains("Axon Gateway Dashboard"));
        assert!(html.contains("backend-panel"));
    }

    #[tokio::test]
    async fn backend_detail_returns_not_found_for_unknown_backend() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ui/backends/missing")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn build_endpoint_returns_metadata() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/build")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("build payload should be json");

        assert!(payload.get("version").is_some());
        assert!(payload.get("pid").is_some());
        assert!(payload.get("started_utc").is_some());
        assert!(payload.get("sse_clients").is_some());
    }

    #[tokio::test]
    async fn htmx_reconnect_action_returns_flash_fragment() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ui/actions/backends/missing/reconnect")
                    .method(http::Method::POST)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8(body.to_vec()).expect("html should be utf-8");
        assert!(html.contains("Reconnect failed"));
    }
}
