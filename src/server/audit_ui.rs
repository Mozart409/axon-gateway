//! The tool-call audit pages under `/ui/admin` and their htmx actions under
//! `/ui/actions/admin`: the call list and details, the capture rules and the
//! retention settings.
//!
//! Mounted like `admin_ui`: the routes sit behind the session guard (actions
//! also the CSRF and same-site checks) and are 404s outside multi-user mode.
//! What a user may do is decided by [`AuditAdmin`]; this module maps HTTP to it
//! and its errors back with the helpers of `admin_ui`. Showing the arguments of
//! a call is a POST, because the read is audited.

use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::header::CACHE_CONTROL;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;

use super::AppState;
use super::admin_ui::{AdminForm, backend_names, error_response, fragment, not_found, page_error};
use super::audit_api::call_filter;
use super::audit_views::{
    self, CallDetail, CallsPage, SettingsPage, render_arguments_block, render_retention_section,
    render_rules_section,
};
use crate::audit_admin::{AuditAdmin, split_keys};
use crate::rbac::AdminError;
use crate::store::SessionUser;

/// Calls per page
const CALLS_PAGE: usize = 50;
/// One more than a page, to know whether an older page exists
const CALLS_FETCH: i64 = 51;

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/admin/tool-calls", get(handle_calls))
        .route("/ui/admin/tool-calls/{id}", get(handle_call))
        .route("/ui/admin/audit-settings", get(handle_settings))
        .merge(super::usage_ui::page_routes())
}

/// The POST actions, to merge into the routes behind the CSRF and same-site
/// checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/ui/actions/admin/tool-calls/{id}/arguments",
            post(handle_arguments),
        )
        .route(
            "/ui/actions/admin/audit-settings",
            post(handle_settings_update),
        )
        .route("/ui/actions/admin/audit-rules", post(handle_rule_create))
        .route(
            "/ui/actions/admin/audit-rules/{id}/delete",
            post(handle_rule_delete),
        )
}

/// The session and the audit service, or the 404 outside multi-user mode
/// (boxed: a `Response` is large for an error type).
fn audit_for(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
) -> Result<(SessionUser, AuditAdmin<'_>), Box<Response>> {
    let Some(Extension(session)) = user else {
        return Err(Box::new(not_found(state)));
    };
    match AuditAdmin::from_state(state, &session) {
        Some(audit) => Ok((session, audit)),
        None => Err(Box::new(not_found(state))),
    }
}

/// `GET /ui/admin/tool-calls` query: the filter fields as a form sends them
/// (empty when left blank) and `before`, a call id, for paging
#[derive(Debug, Deserialize)]
pub(super) struct CallsQuery {
    user: Option<String>,
    backend: Option<String>,
    tool: Option<String>,
    outcome: Option<String>,
    before: Option<i64>,
}

/// Handle GET /ui/admin/tool-calls - the calls, newest first
pub(super) async fn handle_calls(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<CallsQuery>,
) -> Response {
    let (session, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let filter = match call_filter(
        query.user.as_deref(),
        query.backend.as_deref(),
        query.tool.as_deref(),
        query.outcome.as_deref(),
    ) {
        Ok(filter) => filter,
        Err(error) => return page_error(&state, &session, &error),
    };
    let mut calls = match audit.calls(&filter, query.before, CALLS_FETCH).await {
        Ok(calls) => calls,
        Err(error) => return page_error(&state, &session, &error),
    };
    let older = if calls.len() > CALLS_PAGE {
        calls.truncate(CALLS_PAGE);
        calls.last().map(|call| call.id)
    } else {
        None
    };
    let typed = |value: Option<String>| {
        value
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    };
    let page = CallsPage {
        calls,
        user: typed(query.user),
        backend: typed(query.backend),
        tool: typed(query.tool),
        outcome: typed(query.outcome),
        before: query.before,
        older,
    };
    Html(audit_views::render_calls_page(&state, &session, &page).into_string()).into_response()
}

/// Handle GET /ui/admin/tool-calls/{id} - one call
pub(super) async fn handle_call(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<i64>,
) -> Response {
    let (session, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match audit.call(id).await {
        Ok(call) => {
            let detail = CallDetail {
                call,
                can_read_arguments: audit.can_read_arguments(),
            };
            Html(audit_views::render_call_page(&state, &session, &detail).into_string())
                .into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

async fn load_settings_page(
    state: &AppState,
    audit: &AuditAdmin<'_>,
) -> Result<SettingsPage, AdminError> {
    Ok(SettingsPage {
        settings: audit.settings().await?,
        rules: audit.capture_rules().await?,
        backends: backend_names(state).await,
        manage: audit.can_manage(),
    })
}

/// Handle GET /ui/admin/audit-settings - retention and capture rules
pub(super) async fn handle_settings(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match load_settings_page(&state, &audit).await {
        Ok(page) => Html(audit_views::render_settings_page(&state, &session, &page).into_string())
            .into_response(),
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/tool-calls/{id}/arguments - show the stored
/// arguments of a call (audited)
pub(super) async fn handle_arguments(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<i64>,
) -> Response {
    let (_, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match audit.arguments(id).await {
        Ok(stored) => {
            let mut response = fragment(&render_arguments_block(&stored));
            response
                .headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error_response(&error),
    }
}

/// `POST /ui/actions/admin/audit-settings` form
#[derive(Debug, Deserialize)]
pub(super) struct SettingsForm {
    arguments_retention_days: i32,
    metadata_retention_days: i32,
}

/// Handle POST /ui/actions/admin/audit-settings - change the retention
pub(super) async fn handle_settings_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<SettingsForm>,
) -> Response {
    let (_, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = audit
        .update_settings(form.arguments_retention_days, form.metadata_retention_days)
        .await
    {
        return error_response(&error);
    }
    match load_settings_page(&state, &audit).await {
        Ok(page) => fragment(&render_retention_section(&page, false)),
        Err(error) => error_response(&error),
    }
}

/// `POST /ui/actions/admin/audit-rules` form; the keys are comma separated
#[derive(Debug, Deserialize)]
pub(super) struct RuleForm {
    backend: String,
    tool_pattern: String,
    mode: String,
    drop_keys: Option<String>,
}

/// Handle POST /ui/actions/admin/audit-rules - add a capture rule
pub(super) async fn handle_rule_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<RuleForm>,
) -> Response {
    let (_, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let drop_keys = split_keys(form.drop_keys.as_deref().unwrap_or_default());
    if let Err(error) = audit
        .create_capture_rule(&form.backend, &form.tool_pattern, &form.mode, &drop_keys)
        .await
    {
        return error_response(&error);
    }
    rules_fragment(&state, &audit).await
}

/// Handle POST /ui/actions/admin/audit-rules/{id}/delete
pub(super) async fn handle_rule_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<i64>,
) -> Response {
    let (_, audit) = match audit_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = audit.delete_capture_rule(id).await {
        return error_response(&error);
    }
    rules_fragment(&state, &audit).await
}

/// The answer to a rule action: the re-rendered rules section, or the error.
async fn rules_fragment(state: &AppState, audit: &AuditAdmin<'_>) -> Response {
    match load_settings_page(state, audit).await {
        Ok(page) => fragment(&render_rules_section(&page, false)),
        Err(error) => error_response(&error),
    }
}
