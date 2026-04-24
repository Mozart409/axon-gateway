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
//! - GET /status/groups - List tool groups
//! - GET /metrics - Prometheus metrics
//! - POST /admin/backends/{name}/reconnect - Force reconnect a backend
//! - POST /admin/backends/{name}/disable - Disable a backend
//! - POST /admin/backends/{name}/enable - Enable a backend
//! - POST /admin/reload - Reload configuration

use std::convert::Infallible;
use std::sync::Arc;
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
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::auth::{AuthError, AuthManager, TokenIdentity};
use crate::config::Config;
use crate::error::ServerError;
use crate::gateway::{
    DetailedGatewayStatus, DisableBackendMsg, EnableBackendMsg, ForceBackendReconnect,
    GatewayActor, GetDetailedStatus, GetStatus, HandleGroupRequest, HandleRequest, ReloadConfig,
};
use crate::types::JsonRpcRequest;
use crate::types::{BackendInfo, BackendState};

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct AppState {
    pub gateway: ActorRef<GatewayActor>,
    pub auth_manager: Arc<AuthManager>,
    pub config_path: Option<String>,
    pub started_at: SystemTime,
    pub process_id: u32,
    /// Prometheus metrics handle for rendering
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
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
        // UI endpoints
        .route("/ui", get(handle_ui))
        .route("/ui/events", get(handle_ui_events))
        .route("/ui/partials/backends", get(handle_ui_backends_partial))
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
        .fallback(handle_not_found)
        .with_state(state)
}

/// Handle GET / - simple landing page
async fn handle_landing(State(state): State<AppState>) -> Html<String> {
    let page = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway" }
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-4xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                            "Axon Gateway"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" {
                            "One endpoint for your MCP backends"
                        }
                        p class="mt-3 text-slate-600 dark:text-slate-300" {
                            "Use the dashboard for live backend health, and the MCP endpoint for agent calls."
                        }
                        div class="mt-6 flex flex-wrap gap-3" {
                            a
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                href="/ui"
                            {
                                "Open Dashboard"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/status"
                            {
                                "Gateway Status"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/health"
                            {
                                "Health"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                            (build_fingerprint(&state))
                        }
                    }
                }
            }
        }
    };

    Html(page.into_string())
}

/// Global 404 page for unmatched routes
async fn handle_not_found(State(state): State<AppState>) -> impl IntoResponse {
    let page = html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Page Not Found" }
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" { "404" }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" { "Route not found" }
                        p class="mt-3 text-slate-600 dark:text-slate-300" {
                            "The page you requested does not exist on this gateway instance."
                        }
                        div class="mt-6 flex justify-center gap-3" {
                            a
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                href="/"
                            {
                                "Go Home"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/ui"
                            {
                                "Open Dashboard"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                            (build_fingerprint(&state))
                        }
                    }
                }
            }
        }
    };

    (StatusCode::NOT_FOUND, Html(page.into_string()))
}

/// Handle GET /ui - SSR dashboard
async fn handle_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager)?;
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get UI backend status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let page = render_ui_page(&status, &state);
    Ok(Html(page.into_string()))
}

/// Handle GET /ui/partials/backends - HTML fragment for backend list
async fn handle_ui_backends_partial(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager)?;
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get backend partial status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(render_backend_panel(&status).into_string()))
}

/// Handle GET /ui/events - SSE stream for HTMX updates
async fn handle_ui_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let _identity = verify_auth(&headers, &state.auth_manager)?;

    let stream = stream::unfold(
        (tokio::time::interval(Duration::from_secs(5)), state),
        |(mut interval, state)| async move {
            interval.tick().await;

            let event = match state.gateway.ask(GetDetailedStatus).await {
                Ok(status) => {
                    let html = render_backend_panel(&status).into_string();
                    Ok(Event::default().event("backends").data(html))
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh dashboard from SSE: {:?}", e);
                    let html = html! {
                        div class="rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" {
                            "Unable to refresh backend status."
                        }
                    }
                    .into_string();
                    Ok(Event::default().event("flash").data(html))
                }
            };

            Some((event, (interval, state)))
        },
    );

    Ok(Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("ping"),
    ))
}

fn render_ui_page(status: &DetailedGatewayStatus, state: &AppState) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway Dashboard" }
                script src="https://unpkg.com/htmx.org@2.0.4" defer {};
                script src="https://unpkg.com/htmx-ext-sse@2.2.2" defer {};
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto max-w-6xl p-6" {
                    section class="mb-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h1 class="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                            "Axon Gateway"
                        }
                        p class="mt-2 text-sm text-slate-600 dark:text-slate-300" {
                            "Server-rendered dashboard with SSE updates."
                        }
                    }
                    div
                        hx-ext="sse"
                        sse-connect="/ui/events"
                    {
                        div id="flash" sse-swap="flash" {}
                        div id="backend-panel" sse-swap="backends" {
                            (render_backend_panel(status))
                        }
                    }
                    footer class="mt-6 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                        (build_fingerprint(state))
                    }
                }
            }
        }
    }
}

fn build_fingerprint(state: &AppState) -> String {
    let started_utc: DateTime<Utc> = state.started_at.into();
    let started = started_utc.format("%Y-%m-%d %H:%M:%S UTC");
    let git_sha = option_env!("AXON_GIT_SHA").unwrap_or("dev");

    format!(
        "v{} | {git_sha} | pid:{} | started:{started}",
        env!("CARGO_PKG_VERSION"),
        state.process_id
    )
}

fn render_backend_panel(status: &DetailedGatewayStatus) -> Markup {
    html! {
        section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
            h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" { "Backends" }
            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" { (status.backend_count) " active backend actors" }
            @if status.backends.is_empty() {
                p class="mt-4 text-sm text-slate-500 dark:text-slate-400" { "No backends currently connected." }
            } @else {
                div class="mt-4 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800" {
                    table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800" {
                        thead class="bg-slate-50 dark:bg-slate-800/80" {
                        tr {
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Name" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "State" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Tools" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Last Error" }
                            }
                        }
                        tbody class="divide-y divide-slate-100 bg-white dark:divide-slate-800 dark:bg-slate-900" {
                            @for backend in &status.backends {
                                (render_backend_row(backend))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_backend_row(backend: &BackendInfo) -> Markup {
    let state_text = match backend.state {
        BackendState::Disconnected => "Disconnected",
        BackendState::Connecting => "Connecting",
        BackendState::Connected => "Connected",
        BackendState::Failed => "Failed",
        BackendState::CircuitOpen => "Circuit Open",
        BackendState::Reconnecting => "Reconnecting",
    };

    let state_class = match backend.state {
        BackendState::Connected => "text-emerald-700 dark:text-emerald-400",
        BackendState::Connecting | BackendState::Reconnecting => {
            "text-amber-700 dark:text-amber-400"
        }
        BackendState::Failed | BackendState::CircuitOpen | BackendState::Disconnected => {
            "text-red-700 dark:text-red-400"
        }
    };

    html! {
        tr class="align-top" {
            td class="px-4 py-3" { code { (backend.name) } }
            td class="px-4 py-3" { span class=(state_class) { (state_text) } }
            td class="px-4 py-3 text-slate-700 dark:text-slate-200" { (backend.tool_count) }
            td class="px-4 py-3" {
                @if let Some(error) = &backend.last_error {
                    code class="text-xs text-red-700 dark:text-red-400" { (error) }
                } @else {
                    (PreEscaped("&mdash;"))
                }
            }
        }
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
