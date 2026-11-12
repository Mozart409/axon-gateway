//! HTTP Server - Exposes the MCP gateway via SSE/HTTP
//!
//! Provides:
//! - /mcp - MCP Streamable HTTP endpoint (POST for requests and notifications, GET for the
//!   event stream of a pre-2026-07-28 session, DELETE to end one), served by rmcp
//! - /mcp/toolset/{name} - the same endpoint scoped to a toolset (`/mcp/group/{name}` is a
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
//! - /.well-known/oauth-protected-resource, /.well-known/oauth-authorization-server and
//!   /oauth/{register,authorize,token,revoke} - the OAuth authorization server for MCP
//!   clients; GET /ui/me/apps lists a user's connected apps (multi-user mode only)
//! - /api/v1/... - JSON admin API for RBAC, personal access tokens and service accounts
//!   (session login; multi-user mode only)
//! - GET /status/toolsets - List toolsets (`/status/groups` is a deprecated alias)
//! - GET /metrics - Prometheus metrics
//!
//! HTML rendering lives in the [`views`] submodule (`admin_views` for the admin
//! pages). Handlers live in `ui`, `mcp` (the MCP handler behind rmcp's transport) and `api`, the admin
//! JSON API in
//! `admin_api` (token routes in `tokens_api`, grant routes in `oauth_api`), the OAuth server in
//! `oauth` (consent pages in `oauth_ui` and `oauth_views`), the admin pages in `admin_ui` (token pages in
//! `tokens_ui` and `tokens_views`), token checks in `auth`, the
//! dashboard login in `session`; this module owns the shared state, routing, middleware, and server lifecycle.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get, post},
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
mod audit_api;
mod audit_ui;
mod audit_views;
mod auth;
mod break_glass;
mod config_api;
mod config_ui;
mod config_views;
mod mcp;
mod mcp_sessions;
mod oauth;
mod oauth_api;
mod oauth_ui;
mod oauth_views;
mod personal_api;
mod personal_ui;
mod personal_views;
mod scim_admin;
mod scim_api;
mod session;
mod tokens_api;
mod tokens_ui;
mod tokens_views;
mod toolsets_api;
mod toolsets_ui;
mod toolsets_views;
mod ui;
mod upstream_oauth_ui;
mod usage_api;
mod usage_ui;
mod usage_views;
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
    /// Tool-call audit writer; `None` in standalone mode
    pub audit: Option<crate::audit::AuditSink>,
    /// Where tool-list changes are published; MCP clients listening for
    /// `notifications/tools/list_changed` wait on it
    pub changes: crate::changes::ChangeBus,
    /// `Host` values the MCP endpoints accept (DNS rebinding protection of the
    /// rmcp transport), read per request and swapped on a reload; empty accepts any
    pub mcp_allowed_hosts: Arc<std::sync::RwLock<Vec<String>>>,
    /// Users' own and catalog backends; `None` without a database or with
    /// `[personal_backends] enabled = false`
    pub personal: Option<Arc<crate::personal::PersonalHub>>,
    /// What the configuration admin API needs to write the stored configuration;
    /// `None` in standalone mode
    pub db_config: Option<crate::dbconfig::DbConfigContext>,
}

impl AppState {
    /// The store and providers when the dashboard has a login (database mode,
    /// where the provider list may be empty); `None` in standalone mode.
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
        changed: Vec<String>,
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

/// The state-changing dashboard actions.
fn ui_action_routes(state: &AppState) -> Router<AppState> {
    // State-changing dashboard actions. Refuse requests a browser marks as
    // cross-site: otherwise any web page could drive them with a plain form
    // POST. In multi-user mode they also need the session's CSRF token
    // (`session::require_csrf`, behind the session guard below).
    Router::new()
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
        .merge(config_ui::action_routes())
        .merge(tokens_ui::action_routes())
        .merge(oauth_ui::action_routes())
        .merge(audit_ui::action_routes())
        .merge(scim_admin::action_routes())
        .route_layer(middleware::from_fn(session::require_csrf))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_cross_site_middleware,
        ))
}

/// The MCP endpoints: one rmcp Streamable HTTP service at `/mcp` and the toolset paths.
///
/// The middleware authenticates every request before the transport sees it (a 401 stays
/// an HTTP 401) and hands the caller to the MCP handler in a request extension.
fn mcp_routes(state: &AppState) -> Router<AppState> {
    let service = mcp::mcp_service(state);
    let owners = mcp_sessions::SessionOwners::new(state.store.as_ref());
    let handler = move || {
        let service = service.clone();
        any(move |request: axum::extract::Request| async move { service.handle(request).await })
    };
    Router::new()
        .route("/mcp", handler())
        .route("/mcp/toolset/{toolset_name}", handler())
        // Deprecated alias for the toolset endpoint, removed after one minor release
        .route("/mcp/group/{toolset_name}", handler())
        .route_layer(middleware::from_fn_with_state(
            (state.clone(), owners),
            mcp::authenticate_mcp,
        ))
}

/// Create the Axum router
pub fn create_router(state: AppState) -> Router {
    let ui_actions = ui_action_routes(&state);

    // Every dashboard route sits behind the session guard, which does nothing
    // outside multi-user mode.
    let ui_routes = Router::new()
        .route("/ui", get(ui::handle_ui))
        .route("/ui/backends/{name}", get(ui::handle_ui_backend_detail))
        .route("/ui/tools", get(ui::handle_ui_tools))
        .route("/ui/events", get(ui::handle_ui_events))
        .route("/ui/partials/backends", get(ui::handle_ui_backends_partial))
        .merge(admin_ui::page_routes())
        .merge(config_ui::page_routes())
        .merge(tokens_ui::page_routes())
        .merge(oauth_ui::page_routes())
        .merge(audit_ui::page_routes())
        .merge(scim_admin::page_routes())
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
        // MCP endpoints (toolset paths included)
        .merge(mcp_routes(&state))
        .route_service("/styles/output.css", ServeFile::new("styles/output.css"))
        .route_service("/favicon.svg", ServeFile::new("static/favicon.svg"))
        // Scripts are served from the binary, so the pages need no third-party origin
        .route(
            "/static/htmx-2.0.4.min.js",
            get(|| async { script(HTMX_JS, CACHE_IMMUTABLE) }),
        )
        .route(
            "/static/htmx-ext-sse-2.2.2.js",
            get(|| async { script(HTMX_SSE_JS, CACHE_IMMUTABLE) }),
        )
        .route(
            "/static/copy-url.js",
            get(|| async { script(COPY_URL_JS, CACHE_ONE_HOUR) }),
        )
        // UI endpoints
        .merge(ui_routes)
        // Dashboard login
        .merge(auth_routes)
        // MCP OAuth authorization server (multi-user mode only)
        .merge(oauth::routes(&state))
        .merge(oauth_ui::consent_routes(&state))
        // Connecting a catalog entry to the user's own account (multi-user mode only)
        .merge(upstream_oauth_ui::routes(&state))
        .merge(break_glass::routes())
        // JSON admin API
        .merge(admin_api::router(state.clone()))
        .merge(config_api::router(state.clone()))
        .merge(audit_api::router(state.clone()))
        .merge(scim_admin::api_router(state.clone()))
        // SCIM provisioning by an identity provider (multi-user mode only)
        .merge(scim_api::router(state.clone()))
        // Status endpoints
        .route("/health", get(api::health_check))
        .route("/livez", get(api::livez))
        .route("/readyz", get(api::readyz))
        .route("/build", get(api::get_build_info))
        .route("/status", get(api::get_status))
        .route("/status/detailed", get(api::get_detailed_status))
        // Toolset listing (the toolset MCP endpoints are in `mcp_routes`)
        .route("/status/toolsets", get(mcp::list_toolsets))
        // Deprecated alias, removed after one minor release
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
        // After the fallback, so the 404 page gets the headers too
        .layer(middleware::map_response_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        .with_state(state)
}

const HTMX_JS: &str = include_str!("../static/htmx-2.0.4.min.js");
const HTMX_SSE_JS: &str = include_str!("../static/htmx-ext-sse-2.2.2.js");
const COPY_URL_JS: &str = include_str!("../static/copy-url.js");
/// The htmx files carry their version in the path, so they never change.
const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
const CACHE_ONE_HOUR: &str = "public, max-age=3600";

/// Every script the pages load comes from `'self'`: no inline script, no `eval`, no
/// inline style, no other origin. No `form-action`: the logout and OAuth consent
/// POSTs redirect to other origins.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; \
    frame-ancestors 'none'";

/// A JavaScript file served from memory.
fn script(body: &'static str, cache_control: &'static str) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, cache_control),
        ],
        body,
    )
}

/// Add the security headers a handler did not set itself (the OAuth consent page
/// sets its own CSP).
async fn security_headers_middleware(
    State(state): State<AppState>,
    response: Response,
) -> Response {
    let https = state
        .base_url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
    with_security_headers(response, https)
}

fn with_security_headers(mut response: Response, https: bool) -> Response {
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));
    let headers = response.headers_mut();
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("same-origin"));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    if https {
        headers
            .entry(header::STRICT_TRANSPORT_SECURITY)
            .or_insert(HeaderValue::from_static(
                "max-age=63072000; includeSubDomains",
            ));
    }
    if is_html {
        headers
            .entry(header::CONTENT_SECURITY_POLICY)
            .or_insert(HeaderValue::from_static(CONTENT_SECURITY_POLICY));
        headers
            .entry(header::CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
    }
    response
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

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
                allow_stdio: false,
                allowed_hosts: vec![],
                idle_timeout_secs: 300,
            },
            backends: Vec::new(),
            tokens: Vec::new(),
            toolsets: Vec::new(),
            groups: Vec::new(),
            database: None,
            auth: crate::config::AuthConfig::default(),
            rbac: crate::policy::RbacConfig::default(),
            personal_backends: crate::config::PersonalBackendsConfig::default(),
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
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
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
            policy: Arc::new(crate::rbac::PolicyHandle::new()),
            audit: None,
            changes: crate::changes::ChangeBus::new(),
            mcp_allowed_hosts: Arc::new(std::sync::RwLock::new(Vec::new())),
            personal: None,
            db_config: None,
        }
    }

    async fn get_path(path: &str) -> (Response, String) {
        let response = create_router(test_state())
            .oneshot(
                Request::builder()
                    .uri(path)
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("body should be readable");
        let html = String::from_utf8_lossy(&body).into_owned();
        (Response::from_parts(parts, Body::empty()), html)
    }

    /// A response from a one-route router wrapped in the security headers layer.
    async fn through_layer(
        response: impl IntoResponse + Clone + Send + Sync + 'static,
    ) -> Response {
        Router::new()
            .route("/", get(move || async move { response.clone() }))
            .layer(middleware::map_response_with_state(
                test_state(),
                security_headers_middleware,
            ))
            .oneshot(Request::new(Body::empty()))
            .await
            .expect("router should respond")
    }

    fn header_of<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
        response.headers().get(name).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn html_response_gets_csp_and_nosniff() {
        let response = through_layer(axum::response::Html("<p>hi</p>")).await;
        let csp = header_of(&response, "content-security-policy").expect("csp should be set");
        assert!(csp.starts_with("default-src 'none'; script-src 'self'"));
        assert!(!csp.contains("form-action"));
        assert_eq!(
            header_of(&response, "x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(header_of(&response, "x-frame-options"), Some("DENY"));
        assert_eq!(header_of(&response, "referrer-policy"), Some("same-origin"));
        assert_eq!(header_of(&response, "cache-control"), Some("no-store"));
        // test_state() has an http base URL
        assert_eq!(header_of(&response, "strict-transport-security"), None);
    }

    #[tokio::test]
    async fn handler_set_csp_is_preserved() {
        let response = through_layer((
            [(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'")],
            axum::response::Html("<p>consent</p>"),
        ))
        .await;
        assert_eq!(
            header_of(&response, "content-security-policy"),
            Some("frame-ancestors 'none'")
        );
        assert_eq!(
            header_of(&response, "x-content-type-options"),
            Some("nosniff")
        );
    }

    #[tokio::test]
    async fn json_response_gets_nosniff_but_no_csp() {
        let response = through_layer(axum::Json(serde_json::json!({"ok": true}))).await;
        assert_eq!(
            header_of(&response, "x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(header_of(&response, "content-security-policy"), None);
        assert_eq!(header_of(&response, "cache-control"), None);
    }

    #[test]
    fn hsts_is_set_only_for_https() {
        let plain = with_security_headers(Response::new(Body::empty()), false);
        assert!(plain.headers().get("strict-transport-security").is_none());
        let secure = with_security_headers(Response::new(Body::empty()), true);
        assert_eq!(
            header_of(&secure, "strict-transport-security"),
            Some("max-age=63072000; includeSubDomains")
        );
    }

    #[tokio::test]
    async fn vendored_scripts_are_served_from_memory() {
        let (response, body) = get_path("/static/htmx-2.0.4.min.js").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            header_of(&response, "content-type"),
            Some("text/javascript; charset=utf-8")
        );
        assert!(header_of(&response, "cache-control").is_some_and(|v| v.contains("immutable")));
        assert_eq!(
            body.len(),
            include_str!("../static/htmx-2.0.4.min.js").len()
        );
    }

    #[tokio::test]
    async fn rendered_pages_load_no_inline_or_third_party_script() {
        for path in ["/", "/ui", "/no-such-page"] {
            let (response, html) = get_path(path).await;
            assert!(
                header_of(&response, "content-security-policy").is_some(),
                "{path} should carry a CSP"
            );
            assert!(!html.contains("unpkg.com"), "{path} loads from unpkg");
            for (index, _) in html.match_indices("<script") {
                let rest = &html[index..];
                let tag = &rest[..rest.find('>').unwrap_or(rest.len())];
                assert!(
                    tag.contains(" src=\"/static/"),
                    "{path} has an inline script: {tag}"
                );
            }
            assert!(!html.contains(" style="), "{path} has a style attribute");
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
