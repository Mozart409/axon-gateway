//! HTTP Server - Exposes the MCP gateway via SSE/HTTP
//!
//! Provides:
//! - POST /mcp - JSON-RPC endpoint (Streamable HTTP)
//! - GET /mcp/sse - SSE endpoint for streaming
//! - POST /mcp/toolset/{name} - JSON-RPC scoped to a toolset (`/mcp/group/{name}` is a
//!   deprecated alias)
//! - GET /health - Health check
//! - GET /livez - Liveness probe
//! - GET /readyz - Readiness probe
//! - GET /build - Build and process metadata
//! - GET /status - Gateway status
//! - GET /status/detailed - Detailed backend status
//! - GET /ui - Dashboard
//! - GET /ui/backends/{name} - Backend detail page
//! - GET /ui/tools - "My tools" page (multi-user mode only)
//! - GET /ui/admin, /ui/admin/groups/{name}, /ui/admin/audit - RBAC admin pages
//!   (multi-user mode only)
//! - GET /ui/tokens - personal access tokens; GET /ui/admin/service-accounts - service
//!   accounts and their tokens (multi-user mode only)
//! - GET /auth/login, /auth/login/{id}, /auth/callback, POST /auth/logout - OIDC
//!   dashboard login (only with `[auth.oidc]` and `[database]`)
//! - /api/v1/... - JSON admin API for RBAC, personal access tokens and service accounts
//!   (session login; multi-user mode only)
//! - GET /status/toolsets - List toolsets (`/status/groups` is a deprecated alias)
//! - GET /metrics - Prometheus metrics
//!
//! HTML rendering lives in the [`views`] submodule (`admin_views` for the admin
//! pages). Handlers live in `ui`, `mcp` and `api`, the admin JSON API in
//! `admin_api` (token routes in `tokens_api`), the admin pages in `admin_ui` (token pages in
//! `tokens_ui` and `tokens_views`), token checks in `auth`, the
//! dashboard login in `session`; this module owns the shared state, routing, middleware, and server lifecycle.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use kameo::actor::ActorRef;
use serde::Serialize;
use tokio::sync::broadcast;
use tower_http::services::ServeFile;
use tower_http::trace::{DefaultOnResponse, OnResponse, TraceLayer};
use tracing::Level;
use uuid::Uuid;

use crate::auth::SharedAuth;
use crate::error::ServerError;
use crate::gateway::{DetailedGatewayStatus, GatewayActor};

mod admin_api;
mod admin_ui;
mod admin_views;
mod api;
mod auth;
mod mcp;
mod session;
mod tokens_api;
mod tokens_ui;
mod tokens_views;
mod ui;
mod views;

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct AppState {
    pub gateway: ActorRef<GatewayActor>,
    pub auth_manager: SharedAuth,
    pub config_path: Option<String>,
    pub base_url: String,
    pub ui_events: broadcast::Sender<UiEvent>,
    pub sse_clients: Arc<AtomicU64>,
    pub started_at: SystemTime,
    pub process_id: u32,
    /// Prometheus metrics handle for rendering
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    /// Postgres store; `None` in standalone mode
    pub store: Option<crate::store::Store>,
    /// OIDC providers for the dashboard login; `None` without `[auth.oidc]`
    pub oidc: Option<Arc<crate::oidc::OidcProviders>>,
    /// RBAC groups and grants from `[rbac]` and the database
    pub policy: Arc<crate::rbac::PolicyHandle>,
}

impl AppState {
    /// The store and providers when the dashboard has a login (an
    /// `[auth.oidc]` provider and a `[database]`); `None` in standalone mode.
    pub(crate) fn multi_user(&self) -> Option<(&crate::store::Store, &crate::oidc::OidcProviders)> {
        Some((self.store.as_ref()?, self.oidc.as_deref()?))
    }
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
    // State-changing dashboard actions. Refuse requests a browser marks as
    // cross-site: otherwise any web page could drive them with a plain form
    // POST. In multi-user mode they also need the session's CSRF token
    // (`session::require_csrf`, behind the session guard below).
    let ui_actions = Router::new()
        .route(
            "/ui/actions/backends/{name}/reconnect",
            post(ui::handle_ui_reconnect_backend),
        )
        .route(
            "/ui/actions/backends/{name}/disable",
            post(ui::handle_ui_disable_backend),
        )
        .route(
            "/ui/actions/backends/{name}/enable",
            post(ui::handle_ui_enable_backend),
        )
        .route("/ui/actions/reload", post(ui::handle_ui_reload_config))
        .route(
            "/ui/actions/tools/opt-out",
            post(ui::handle_ui_tool_opt_out),
        )
        .merge(admin_ui::action_routes())
        .merge(tokens_ui::action_routes())
        .route_layer(middleware::from_fn(session::require_csrf))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_cross_site_middleware,
        ));

    // Every dashboard route sits behind the session guard, which does nothing
    // outside multi-user mode.
    let ui_routes = Router::new()
        .route("/ui", get(ui::handle_ui))
        .route("/ui/backends/{name}", get(ui::handle_ui_backend_detail))
        .route("/ui/tools", get(ui::handle_ui_tools))
        .route("/ui/events", get(ui::handle_ui_events))
        .route("/ui/partials/backends", get(ui::handle_ui_backends_partial))
        .merge(admin_ui::page_routes())
        .merge(tokens_ui::page_routes())
        .merge(ui_actions)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require_session,
        ));

    // The login routes answer 404 outside multi-user mode.
    let auth_routes = Router::new()
        .route("/auth/login", get(session::login_index))
        .route("/auth/login/{id}", get(session::login_provider))
        .route("/auth/callback", get(session::callback))
        .merge(
            Router::new()
                .route("/auth/logout", post(session::logout))
                .route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    reject_cross_site_middleware,
                )),
        );

    // No CORS layer: nothing here is meant to be called from another origin's
    // page, and without `Access-Control-Allow-*` headers browsers keep other
    // sites from reading `/status/detailed`, `/mcp` and friends.
    Router::new()
        // Landing page
        .route("/", get(ui::handle_landing))
        // MCP endpoints
        .route("/mcp", post(mcp::handle_mcp_request))
        .route("/mcp/sse", get(mcp::handle_mcp_sse))
        .route_service("/styles/output.css", ServeFile::new("styles/output.css"))
        .route_service("/favicon.svg", ServeFile::new("static/favicon.svg"))
        // UI endpoints
        .merge(ui_routes)
        // Dashboard login
        .merge(auth_routes)
        // JSON admin API
        .merge(admin_api::router(state.clone()))
        // Status endpoints
        .route("/health", get(api::health_check))
        .route("/livez", get(api::livez))
        .route("/readyz", get(api::readyz))
        .route("/build", get(api::get_build_info))
        .route("/status", get(api::get_status))
        .route("/status/detailed", get(api::get_detailed_status))
        // Toolset endpoints (subset of tools via named toolsets)
        .route(
            "/mcp/toolset/{toolset_name}",
            post(mcp::handle_toolset_request),
        )
        .route("/status/toolsets", get(mcp::list_toolsets))
        // Deprecated aliases for the toolset endpoints, removed after one minor release
        .route(
            "/mcp/group/{toolset_name}",
            post(mcp::handle_toolset_request),
        )
        .route("/status/groups", get(mcp::list_toolsets))
        // Metrics endpoint
        .route("/metrics", get(api::prometheus_metrics))
        // Middleware
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let request_id = request
                        .extensions()
                        .get::<RequestId>()
                        .map(|id| id.0.as_str())
                        .unwrap_or_default();
                    crate::telemetry::http_request_span(request, request_id)
                })
                .on_response(
                    |response: &Response, latency: std::time::Duration, span: &tracing::Span| {
                        crate::telemetry::record_response_status(span, response.status());
                        DefaultOnResponse::new()
                            .level(Level::INFO)
                            .on_response(response, latency, span);
                    },
                ),
        )
        // Outermost, so the request id exists before TraceLayer opens its span
        .layer(middleware::from_fn(request_id_middleware))
        .fallback(ui::handle_not_found)
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
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    // Record HTTP request metrics
    crate::metrics::record_http_request(&method, &path, response.status().as_u16());

    response
}

/// Reject requests that a browser reports as coming from another site.
async fn reject_cross_site_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if is_cross_site(request.headers(), &state.base_url) {
        tracing::warn!(
            path = %request.uri().path(),
            origin = ?request.headers().get(http::header::ORIGIN),
            "Rejected cross-site UI action"
        );
        return (StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
    }
    next.run(request).await
}

/// Whether a request was sent by a page on another origin.
///
/// Browsers send `Sec-Fetch-Site` (trusted when present: only `same-origin`
/// and `none`, i.e. user-initiated, pass) and `Origin` on POSTs. The `Origin`
/// must match the request's `Host` or the configured `base_url`. Requests with
/// neither header come from non-browser clients (curl, scripts) and are not a
/// CSRF vector, so they pass.
fn is_cross_site(headers: &HeaderMap, base_url: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return !matches!(site.to_str(), Ok("same-origin" | "none"));
    }

    let Some(origin) = headers.get(http::header::ORIGIN) else {
        return false;
    };
    let Ok(origin) = origin.to_str() else {
        return true;
    };
    let Some(origin_authority) = authority_of(origin) else {
        return true; // includes the opaque `null` origin
    };

    let host_matches = headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|host| host.eq_ignore_ascii_case(origin_authority));
    let base_matches = origin_of(base_url)
        .is_some_and(|base| base.eq_ignore_ascii_case(origin.trim_end_matches('/')));

    !(host_matches || base_matches)
}

/// The `host[:port]` part of an `http(s)://host[:port][/path]` URL.
fn authority_of(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty()).then_some(authority)
}

/// The `scheme://host[:port]` origin of an `http(s)` URL.
fn origin_of(url: &str) -> Option<&str> {
    let authority = authority_of(url)?;
    let scheme_len = url.find("://")? + 3;
    url.get(..scheme_len + authority.len())
}

/// Start the HTTP server
pub async fn serve(
    state: AppState,
    bind: &str,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), ServerError> {
    ui::start_ui_event_poller(state.clone());
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

    use axum::body::Body;
    use http::Request;
    use kameo::actor::Spawn;
    use kameo::mailbox;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::AuthManager;
    use crate::config::{Config, GatewayConfig};
    use crate::registry::RegistryActor;

    pub(super) fn test_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
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

    pub(super) fn test_state() -> AppState {
        let config = Config {
            gateway: GatewayConfig {
                bind: String::from("127.0.0.1:0"),
                base_url: String::from("http://127.0.0.1:8080"),
                auth_token: None,
                rate_limit_per_minute: 0,
            },
            backends: Vec::new(),
            tokens: Vec::new(),
            toolsets: Vec::new(),
            groups: Vec::new(),
            database: None,
            auth: crate::config::AuthConfig::default(),
            rbac: crate::policy::RbacConfig::default(),
        };

        let registry =
            RegistryActor::spawn_with_mailbox(RegistryActor::new(), mailbox::unbounded());
        let gateway = GatewayActor::spawn_with_mailbox(
            GatewayActor::new(config, registry),
            mailbox::unbounded(),
        );

        AppState {
            gateway,
            auth_manager: SharedAuth::new(AuthManager::new(
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
            store: None,
            oidc: None,
            policy: Arc::new(crate::rbac::PolicyHandle::new(
                crate::policy::RbacConfig::default(),
            )),
        }
    }

    async fn post_ui_action(headers: &[(&str, &str)]) -> StatusCode {
        let app = create_router(test_state());
        let mut builder = Request::builder()
            .uri("/ui/actions/backends/missing/reconnect")
            .method(http::Method::POST);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        app.oneshot(builder.body(Body::empty()).expect("request should build"))
            .await
            .expect("router should respond")
            .status()
    }

    #[tokio::test]
    async fn ui_action_rejects_cross_site_origin() {
        let status = post_ui_action(&[
            ("host", "axon.homelab.internal"),
            ("origin", "https://evil.example"),
        ])
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ui_action_rejects_null_origin() {
        let status = post_ui_action(&[("host", "axon.homelab.internal"), ("origin", "null")]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[rstest::rstest]
    #[case("cross-site")]
    #[case("same-site")]
    #[tokio::test]
    async fn ui_action_rejects_cross_site_fetch_metadata(#[case] site: &str) {
        // Sec-Fetch-Site wins even when the Origin looks right.
        let status = post_ui_action(&[
            ("host", "axon.homelab.internal"),
            ("origin", "https://axon.homelab.internal"),
            ("sec-fetch-site", site),
        ])
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ui_action_accepts_same_origin_browser_request() {
        let status = post_ui_action(&[
            ("host", "axon.homelab.internal"),
            ("origin", "https://axon.homelab.internal"),
            ("sec-fetch-site", "same-origin"),
        ])
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn ui_action_accepts_origin_matching_host_without_fetch_metadata() {
        let status = post_ui_action(&[
            ("host", "axon.homelab.internal:8080"),
            ("origin", "http://axon.homelab.internal:8080"),
        ])
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn ui_action_accepts_origin_matching_base_url() {
        // Behind a proxy that rewrites Host, the configured base_url still matches.
        let status = post_ui_action(&[
            ("host", "10.0.0.5:8080"),
            ("origin", "http://127.0.0.1:8080"),
        ])
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn responses_carry_no_cors_headers() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/status/detailed")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }

    #[test]
    fn origin_helpers_parse_urls() {
        assert_eq!(authority_of("https://a.lan:9/x"), Some("a.lan:9"));
        assert_eq!(authority_of("null"), None);
        assert_eq!(origin_of("http://a.lan:8080/ui"), Some("http://a.lan:8080"));
    }
}
