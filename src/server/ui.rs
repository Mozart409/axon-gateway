//! Dashboard UI handlers, SSE event stream and the backend status poller.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Form,
    extract::{Path, State, rejection::FormRejection},
    http::StatusCode,
    response::{
        Html, IntoResponse, Response,
        sse::{Event, Sse},
    },
};
use futures::stream::{self, Stream};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::broadcast;

use super::{AppState, FlashLevel, FlashMessage, UiEvent, views};
use crate::config::Config;
use crate::gateway::{
    Caller, DisableBackendMsg, EnableBackendMsg, ForceBackendReconnect, GetDetailedStatus,
    HandleRequest, ReloadConfig,
};
use crate::policy::{OptOuts, ToolRef};
use crate::store::{SessionUser, Store};
use crate::types::{JsonRpcRequest, PromptDefinition, ResourceDefinition};

/// Handle GET / - simple landing page
pub(super) async fn handle_landing(State(state): State<AppState>) -> Html<String> {
    Html(views::render_landing_page(&state).into_string())
}

/// Global 404 page for unmatched routes
pub(super) async fn handle_not_found(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Html(views::render_not_found_page(&state).into_string()),
    )
}

/// Handle GET /ui - SSR dashboard
pub(super) async fn handle_ui(
    State(state): State<AppState>,
    user: Option<axum::Extension<crate::store::SessionUser>>,
) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get UI backend status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let page = views::render_ui_page(&status, &state, user.as_ref().map(|axum::Extension(u)| u));
    Ok(Html(page.into_string()))
}

/// Handle GET /ui/backends/{name} - backend detail page
pub(super) async fn handle_ui_backend_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
    user: Option<axum::Extension<crate::store::SessionUser>>,
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

    let page = views::render_ui_backend_detail_page(
        &backend,
        &prompts,
        &resources,
        &state,
        user.as_ref().map(|axum::Extension(u)| u),
    );
    Ok(Html(page.into_string()))
}

/// The user's opt-outs as the policy's view layer wants them.
async fn load_opt_outs(store: &Store, user_id: uuid::Uuid) -> Result<OptOuts, Box<Response>> {
    match store.opt_outs(user_id).await {
        Ok(rows) => Ok(OptOuts::new(
            rows.into_iter().map(|row| (row.backend, row.tool)),
        )),
        Err(error) => {
            tracing::warn!(%error, "could not load tool opt-outs");
            Err(Box::new(store_unavailable()))
        }
    }
}

fn store_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "tool preferences unavailable\n",
    )
        .into_response()
}

/// Handle GET /ui/tools - "My tools" page (multi-user mode only)
pub(super) async fn handle_ui_tools(
    State(state): State<AppState>,
    user: Option<axum::Extension<SessionUser>>,
) -> Response {
    let (Some((store, _)), Some(axum::Extension(session))) = (state.multi_user(), user) else {
        return handle_not_found(State(state.clone())).await.into_response();
    };

    let status = match state.gateway.ask(GetDetailedStatus).await {
        Ok(status) => status,
        Err(e) => {
            tracing::error!("Failed to get status for the tools page: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let opt_outs = match load_opt_outs(store, session.user.id).await {
        Ok(opt_outs) => opt_outs,
        Err(response) => return *response,
    };

    let policy = state.policy.current();
    let groups = policy.groups_for(session.user.id, &session.provider_id, &session.user.groups);
    let effective = policy.effective(&groups);
    let page = views::render_my_tools_page(
        &state,
        &session,
        &groups,
        &status.backends,
        &effective,
        &opt_outs,
    );
    Html(page.into_string()).into_response()
}

/// `POST /ui/actions/tools/opt-out` form
#[derive(Debug, Deserialize)]
pub(super) struct OptOutForm {
    backend: String,
    /// Original tool name; absent or empty means the whole backend
    tool: Option<String>,
    hidden: bool,
}

/// Handle POST /ui/actions/tools/opt-out - hide or show a tool or a backend
pub(super) async fn handle_ui_tool_opt_out(
    State(state): State<AppState>,
    user: Option<axum::Extension<SessionUser>>,
    form: Result<Form<OptOutForm>, FormRejection>,
) -> Response {
    let (Some((store, _)), Some(axum::Extension(session))) = (state.multi_user(), user) else {
        return handle_not_found(State(state.clone())).await.into_response();
    };
    let Ok(Form(form)) = form else {
        return (StatusCode::BAD_REQUEST, "invalid form\n").into_response();
    };
    let tool_name = form.tool.as_deref().filter(|tool| !tool.is_empty());

    let status = match state.gateway.ask(GetDetailedStatus).await {
        Ok(status) => status,
        Err(e) => {
            tracing::error!("Failed to get status for a tool opt-out: {:?}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let policy = state.policy.current();
    let groups = policy.groups_for(session.user.id, &session.provider_id, &session.user.groups);
    let effective = policy.effective(&groups);

    let Some(backend) = status
        .backends
        .iter()
        .find(|backend| backend.name == form.backend && !backend.tools.is_empty())
    else {
        return (StatusCode::BAD_REQUEST, "unknown backend\n").into_response();
    };
    if !effective.backends().contains(&backend.name) {
        return (StatusCode::BAD_REQUEST, "no grant for this backend\n").into_response();
    }
    if let Some(tool_name) = tool_name {
        let Some(tool) = backend
            .tools
            .iter()
            .find(|tool| tool.original_name == tool_name)
        else {
            return (StatusCode::BAD_REQUEST, "unknown tool\n").into_response();
        };
        let tool_ref = ToolRef {
            backend: &tool.backend_name,
            name: &tool.original_name,
            read_only_hint: tool.definition.read_only_hint(),
        };
        if !effective.allows(tool_ref) {
            return (StatusCode::BAD_REQUEST, "tool not granted\n").into_response();
        }
        if effective.is_mandatory(tool_ref) {
            return (StatusCode::BAD_REQUEST, "tool is mandatory\n").into_response();
        }
    }

    if let Err(error) = store
        .set_opt_out(session.user.id, &backend.name, tool_name, form.hidden)
        .await
    {
        tracing::warn!(%error, "could not save a tool opt-out");
        return store_unavailable();
    }
    state
        .changes
        .publish(crate::changes::ChangeScope::User(session.user.id));

    let opt_outs = match load_opt_outs(store, session.user.id).await {
        Ok(opt_outs) => opt_outs,
        Err(response) => return *response,
    };
    Html(views::render_tool_backend_section(backend, &effective, &opt_outs).into_string())
        .into_response()
}

/// Handle GET /ui/partials/backends - HTML fragment for backend list
pub(super) async fn handle_ui_backends_partial(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get backend partial status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Html(views::render_backend_panel(&status).into_string()))
}

/// Handle GET /ui/events - SSE stream for HTMX updates
pub(super) async fn handle_ui_events(
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

pub(super) async fn handle_ui_reconnect_backend(
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

pub(super) async fn handle_ui_disable_backend(
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

pub(super) async fn handle_ui_enable_backend(
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

pub(super) async fn handle_ui_reload_config(
    State(state): State<AppState>,
) -> Result<Html<String>, StatusCode> {
    let config_path = state.config_path.as_ref().ok_or_else(|| {
        tracing::error!("Config path not set, cannot reload from UI action");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let flash = match Config::load_async(config_path).await {
        Ok(new_config) => {
            state
                .auth_manager
                .reload(&new_config.gateway, &new_config.tokens);
            reload_flash(
                state.gateway.ask(ReloadConfig { config: new_config }).await,
                &state,
            )
        }
        Err(e) => FlashMessage {
            level: FlashLevel::Error,
            message: format!("Failed to read config: {e}"),
        },
    };

    publish_ui_event(&state.ui_events, UiEvent::Flash(flash.clone()));
    refresh_ui_backend_snapshot(&state).await;
    Ok(Html(views::render_flash(&flash).into_string()))
}

/// Turn the gateway's reload reply into a flash message (and announce it).
fn reload_flash<E: std::fmt::Debug>(
    reply: Result<crate::gateway::ReloadResult, E>,
    state: &AppState,
) -> FlashMessage {
    match reply {
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
    }
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
            caller: Arc::new(Caller::Open),
            relay: None,
            personal: None,
            hub: None,
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
            caller: Arc::new(Caller::Open),
            relay: None,
            personal: None,
            hub: None,
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

pub(super) fn start_ui_event_poller(state: AppState) {
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

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::policy::{GrantConfig, IdpMapping, Policy, RbacConfig, RbacGroupConfig};
    use crate::server::create_router;
    use crate::server::tests::test_state;
    use crate::types::{BackendInfo, BackendState, NamespacedTool, ToolDefinition};

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

    fn test_session_user(is_admin: bool) -> crate::store::SessionUser {
        crate::store::SessionUser {
            user: crate::store::User {
                id: uuid::Uuid::nil(),
                issuer: String::from("https://idp.example"),
                subject: String::from("sub-1"),
                email: Some(String::from("ada@example.com")),
                display_name: Some(String::from("Ada Lovelace")),
                groups: Vec::new(),
                is_admin,
            },
            provider_id: String::from("pocket"),
            csrf_token: String::from("tok-123"),
            id_token: None,
        }
    }

    fn detail_backend() -> BackendInfo {
        BackendInfo::new(
            String::from("filesystem"),
            BackendState::Connected,
            Vec::new(),
            None,
        )
    }

    #[tokio::test]
    async fn login_page_lists_options_and_escapes_labels() {
        let options = vec![
            views::LoginOption {
                display_name: String::from("Pocket ID"),
                href: String::from("/auth/login/pocket?next=%2Fui"),
            },
            views::LoginOption {
                display_name: String::from("<b>Evil</b>"),
                href: String::from("/auth/login/evil"),
            },
        ];

        let html = views::render_login_page(&test_state(), &options).into_string();
        assert!(html.contains("Sign in to Axon Gateway"));
        assert!(html.contains("Pocket ID"));
        assert!(html.contains("href=\"/auth/login/pocket?next=%2Fui\""));
        assert!(html.contains("href=\"/auth/login/evil\""));
        assert!(html.contains("&lt;b&gt;Evil&lt;/b&gt;"));
        assert!(!html.contains("<b>Evil</b>"));

        let empty = views::render_login_page(&test_state(), &[]).into_string();
        assert!(empty.contains("No login providers are configured"));
    }

    #[tokio::test]
    async fn auth_error_page_links_back() {
        let html = views::render_auth_error_page(&test_state(), "Login failed", "Please retry.")
            .into_string();
        assert!(html.contains("Login failed"));
        assert!(html.contains("Please retry."));
        assert!(html.contains("href=\"/auth/login\""));
        assert!(html.contains("Try again"));
        assert!(html.contains("href=\"/\""));
    }

    #[tokio::test]
    async fn signed_in_header_shows_user_logout_and_csrf() {
        let user = test_session_user(true);
        let html = views::render_ui_backend_detail_page(
            &detail_backend(),
            &[],
            &[],
            &test_state(),
            Some(&user),
        )
        .into_string();

        assert!(html.contains("Ada Lovelace"));
        assert!(html.contains(">admin<"));
        assert!(html.contains("action=\"/auth/logout\""));
        assert!(html.contains("name=\"csrf_token\" value=\"tok-123\""));
        assert!(html.contains("name=\"csrf-token\" content=\"tok-123\""));
        assert!(html.contains("hx-headers=\"{&quot;X-CSRF-Token&quot;:&quot;tok-123&quot;}\""));
    }

    #[tokio::test]
    async fn admin_badge_only_for_admins() {
        let user = test_session_user(false);
        let html = views::render_ui_backend_detail_page(
            &detail_backend(),
            &[],
            &[],
            &test_state(),
            Some(&user),
        )
        .into_string();

        assert!(html.contains("Ada Lovelace"));
        assert!(!html.contains(">admin<"));
    }

    #[tokio::test]
    async fn pages_without_user_have_no_logout_or_hx_headers() {
        let html =
            views::render_ui_backend_detail_page(&detail_backend(), &[], &[], &test_state(), None)
                .into_string();

        assert!(!html.contains("/auth/logout"));
        assert!(!html.contains("hx-headers"));
        assert!(!html.contains("csrf-token"));
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

    fn tool(backend: &str, name: &str, read_only: bool) -> NamespacedTool {
        NamespacedTool::new(
            backend,
            ToolDefinition {
                name: name.to_string(),
                description: Some(format!("does {name}")),
                input_schema: json!({}),
                annotations: read_only.then(|| json!({"readOnlyHint": true})),
            },
        )
    }

    fn backend_with(name: &str, tools: Vec<NamespacedTool>) -> BackendInfo {
        BackendInfo::new(name.to_string(), BackendState::Connected, tools, None)
    }

    fn grant(group: &str, backend: &str, include: &[&str], exclude: &[&str]) -> GrantConfig {
        GrantConfig {
            group: group.to_string(),
            backend: backend.to_string(),
            include: include.iter().map(|s| (*s).to_string()).collect(),
            exclude: exclude.iter().map(|s| (*s).to_string()).collect(),
            read_only: false,
            mandatory: false,
        }
    }

    /// Group `it` (claim `it-claim` from `pocket`); `files` is granted in pieces,
    /// `wiki` read-only, `mail` not at all.
    fn tools_config() -> RbacConfig {
        let mut wiki = grant("authenticated", "wiki", &["*"], &[]);
        wiki.read_only = true;
        let mut audit = grant("authenticated", "files", &["audit_log"], &[]);
        audit.mandatory = true;
        RbacConfig {
            groups: vec![RbacGroupConfig {
                name: String::from("it"),
                description: Some(String::from("<b>IT</b> staff")),
                idp: vec![IdpMapping {
                    provider: String::from("pocket"),
                    value: String::from("it-claim"),
                }],
                service_accounts: Vec::new(),
            }],
            grants: vec![
                grant("authenticated", "files", &["read_*"], &[]),
                audit,
                grant("it", "files", &["*"], &["delete_*"]),
                wiki,
            ],
            role_bindings: Vec::new(),
        }
    }

    fn tools_policy() -> Policy {
        Policy::from_config(&tools_config())
    }

    fn files_backend() -> BackendInfo {
        backend_with(
            "files",
            vec![
                tool("files", "read_file", true),
                tool("files", "write_file", false),
                tool("files", "delete_file", false),
                tool("files", "audit_log", false),
            ],
        )
    }

    fn wiki_backend() -> BackendInfo {
        backend_with(
            "wiki",
            vec![tool("wiki", "search", true), tool("wiki", "edit", false)],
        )
    }

    fn render_section(backend: &BackendInfo, opt_outs: &OptOuts) -> String {
        let policy = tools_policy();
        let groups = policy.groups_for(uuid::Uuid::nil(), "pocket", &[String::from("it-claim")]);
        views::render_tool_backend_section(backend, &policy.effective(&groups), opt_outs)
            .into_string()
    }

    #[test]
    fn tool_states_and_reasons_render() {
        let html = render_section(&files_backend(), &OptOuts::default());
        assert!(html.contains("files_read_file"));
        assert!(html.contains("read-only"));
        assert!(html.contains(">on<"));
        assert!(html.contains(">mandatory<"));
        assert!(html.contains("required by your admin"));

        // The `it` user is allowed everything but `delete_*`.
        assert!(html.contains(">not granted<"));
        assert!(html.contains("not included by the grant of group authenticated"));
        assert!(html.contains("excluded by the grant of group it"));

        let html = render_section(&wiki_backend(), &OptOuts::default());
        assert!(html.contains(
            "the grant of group authenticated is read-only and this tool is not marked read-only"
        ));

        // For a user outside `it`, the same tool is simply not covered.
        let policy = tools_policy();
        let effective = policy.effective(&policy.groups_for(uuid::Uuid::nil(), "pocket", &[]));
        let html =
            views::render_tool_backend_section(&files_backend(), &effective, &OptOuts::default())
                .into_string();
        assert!(html.contains("not included by the grant of group authenticated"));
        assert!(!html.contains("group it"));
    }

    #[test]
    fn mandatory_tool_has_no_toggle() {
        let backend = backend_with("files", vec![tool("files", "audit_log", false)]);
        let html = render_section(&backend, &OptOuts::default());
        assert!(html.contains(">mandatory<"));
        assert!(!html.contains("name=\"tool\""));

        // Hiding the backend leaves it mandatory.
        let hidden = OptOuts::new([(String::from("files"), None)]);
        let html = render_section(&backend, &hidden);
        assert!(html.contains(">mandatory<"));
        assert!(html.contains("Its mandatory tools stay visible"));
    }

    #[test]
    fn toggles_carry_backend_tool_and_target_state() {
        let html = render_section(&wiki_backend(), &OptOuts::default());
        assert!(html.contains("hx-post=\"/ui/actions/tools/opt-out\""));
        assert!(html.contains("hx-target=\"closest section\""));
        assert!(html.contains("hx-swap=\"outerHTML\""));
        assert!(html.contains("name=\"backend\" value=\"wiki\""));
        assert!(html.contains("name=\"tool\" value=\"search\""));
        assert!(html.contains("name=\"hidden\" value=\"true\""));
        assert!(html.contains("Hide backend"));
        // `edit` is not granted: no toggle for it.
        assert!(!html.contains("name=\"tool\" value=\"edit\""));

        let hidden = OptOuts::new([(String::from("wiki"), Some(String::from("search")))]);
        let html = render_section(&wiki_backend(), &hidden);
        assert!(html.contains(">hidden by you<"));
        assert!(html.contains("name=\"tool\" value=\"search\""));
        assert!(html.contains("name=\"hidden\" value=\"false\""));
        assert!(html.contains("Hide backend"));
    }

    #[test]
    fn hidden_backend_offers_show_for_the_backend_only() {
        let hidden = OptOuts::new([(String::from("wiki"), None)]);
        let html = render_section(&wiki_backend(), &hidden);
        assert!(html.contains("Show backend"));
        assert!(html.contains(">hidden by you<"));
        assert!(html.contains("name=\"hidden\" value=\"false\""));
        assert!(!html.contains("name=\"tool\""));
    }

    #[test]
    fn backend_without_a_grant_shows_no_access() {
        let backend = backend_with("mail", vec![tool("mail", "send", false)]);
        let html = render_section(&backend, &OptOuts::default());
        assert!(html.contains("No access"));
        assert!(html.contains("ask an admin"));
        assert!(!html.contains("<table"));
        assert!(!html.contains("name=\"backend\""));
    }

    #[tokio::test]
    async fn my_tools_page_lists_groups_and_escapes_descriptions() {
        let mut state = test_state();
        state.policy = Arc::new(crate::rbac::PolicyHandle::new(tools_config()));
        let user = test_session_user(false);
        let policy = state.policy.current();
        let groups = policy.groups_for(user.user.id, "pocket", &[String::from("it-claim")]);
        let backends = vec![
            wiki_backend(),
            files_backend(),
            backend_with("empty", Vec::new()),
        ];

        let html = views::render_my_tools_page(
            &state,
            &user,
            &groups,
            &backends,
            &policy.effective(&groups),
            &OptOuts::default(),
        )
        .into_string();
        assert!(html.contains("My tools"));
        assert!(html.contains("built in"));
        assert!(html.contains("&lt;b&gt;IT&lt;/b&gt; staff"));
        assert!(!html.contains("<b>IT</b>"));
        assert!(html.contains("name=\"csrf-token\" content=\"tok-123\""));
        assert!(html.contains("hx-headers="));
        // Sections are sorted by backend and skip backends without tools.
        let files = html.find("files_read_file").expect("files section");
        let wiki = html.find("wiki_search").expect("wiki section");
        assert!(files < wiki);
        assert!(!html.contains("<code>empty</code>"));
    }

    #[tokio::test]
    async fn user_bar_links_to_my_tools() {
        let user = test_session_user(false);
        let html = views::render_ui_backend_detail_page(
            &detail_backend(),
            &[],
            &[],
            &test_state(),
            Some(&user),
        )
        .into_string();
        assert!(html.contains("href=\"/ui/tools\""));

        let html =
            views::render_ui_backend_detail_page(&detail_backend(), &[], &[], &test_state(), None)
                .into_string();
        assert!(!html.contains("/ui/tools"));
    }

    #[tokio::test]
    async fn my_tools_is_not_found_outside_multi_user_mode() {
        let app = create_router(test_state());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ui/tools")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ui/actions/tools/opt-out")
                    .method(http::Method::POST)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("backend=files&hidden=true"))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
