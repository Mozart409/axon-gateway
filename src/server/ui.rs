//! Dashboard UI handlers, SSE event stream and the backend status poller.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        Html, IntoResponse,
        sse::{Event, Sse},
    },
};
use futures::stream::{self, Stream};
use serde_json::json;
use tokio::sync::broadcast;

use super::{AppState, FlashLevel, FlashMessage, UiEvent, views};
use crate::config::Config;
use crate::gateway::{
    DisableBackendMsg, EnableBackendMsg, ForceBackendReconnect, GetDetailedStatus, HandleRequest,
    ReloadConfig,
};
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
pub(super) async fn handle_ui(State(state): State<AppState>) -> Result<Html<String>, StatusCode> {
    let status = state.gateway.ask(GetDetailedStatus).await.map_err(|e| {
        tracing::error!("Failed to get UI backend status: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let page = views::render_ui_page(&status, &state);
    Ok(Html(page.into_string()))
}

/// Handle GET /ui/backends/{name} - backend detail page
pub(super) async fn handle_ui_backend_detail(
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
    use crate::server::create_router;
    use crate::server::tests::test_state;
    use crate::types::{BackendInfo, BackendState};

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
