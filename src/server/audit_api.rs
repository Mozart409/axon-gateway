//! The tool-call audit routes of the JSON API under `/api/v1`: calls, their
//! stored arguments, capture rules and retention settings.
//!
//! Like `admin_api`, every route needs a dashboard session, writes (and the
//! argument read, which is audited and so is an action) also the session's
//! `X-CSRF-Token` and a same-site request, and outside multi-user mode every
//! route is a JSON 404. What a caller may do is decided by [`AuditAdmin`];
//! errors answer as in `admin_api`.

use axum::extract::{FromRequestParts, Query, Request, State};
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use super::admin_api::{ApiError, ApiJson, ApiPath, ApiResult};
use super::{AppState, reject_cross_site_middleware, session};
use crate::audit::{AuditSettings, CallOutcome, CaptureRule, ToolCallFilter, ToolCallRecord};
use crate::audit_admin::AuditAdmin;
use crate::rbac::AdminError;
use crate::store::SessionUser;

const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// The audit routes with their guards: multi-user check, session, same-site
/// check, CSRF token (writes only).
pub(super) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/tool-calls", get(handle_list_calls))
        .route("/api/v1/tool-calls/{id}", get(handle_get_call))
        .route("/api/v1/tool-calls/{id}/arguments", post(handle_arguments))
        .route(
            "/api/v1/audit/settings",
            get(handle_get_settings).put(handle_put_settings),
        )
        .route(
            "/api/v1/audit/capture-rules",
            get(handle_list_rules).post(handle_create_rule),
        )
        .route(
            "/api/v1/audit/capture-rules/{id}",
            delete(handle_delete_rule),
        )
        .route_layer(middleware::from_fn(session::require_csrf))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_cross_site_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require_session,
        ))
        .route_layer(middleware::from_fn_with_state(state, require_multi_user))
}

/// The API does not exist outside multi-user mode.
async fn require_multi_user(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if state.multi_user().is_none() {
        return ApiError::from(AdminError::NotFound).into_response();
    }
    next.run(request).await
}

/// `Query<T>` whose rejection is a 400 JSON error
struct ApiQuery<T>(T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(AdminError::Invalid(rejection.body_text()).into()),
        }
    }
}

pub(super) fn audit_admin<'a>(
    state: &'a AppState,
    session: &SessionUser,
) -> ApiResult<AuditAdmin<'a>> {
    AuditAdmin::from_state(state, session).ok_or_else(|| AdminError::NotFound.into())
}

/// The listing filter from query or form values; blank values match everything.
///
/// # Errors
/// [`AdminError::Invalid`] for a user that is not a UUID or an unknown outcome.
pub(super) fn call_filter(
    user: Option<&str>,
    backend: Option<&str>,
    tool: Option<&str>,
    outcome: Option<&str>,
) -> Result<ToolCallFilter, AdminError> {
    fn clean(value: Option<&str>) -> Option<&str> {
        value.map(str::trim).filter(|value| !value.is_empty())
    }
    let user_id = clean(user)
        .map(|user| {
            Uuid::parse_str(user)
                .map_err(|_| AdminError::Invalid("user must be a user id (a UUID)".to_owned()))
        })
        .transpose()?;
    let outcome = clean(outcome)
        .map(|outcome| {
            CallOutcome::parse(outcome)
                .map(|outcome| outcome.as_str().to_owned())
                .ok_or_else(|| {
                    AdminError::Invalid("outcome must be ok, error or tool_error".to_owned())
                })
        })
        .transpose()?;
    Ok(ToolCallFilter {
        user_id,
        backend: clean(backend).map(str::to_owned),
        tool: clean(tool).map(str::to_owned),
        outcome,
    })
}

fn call_json(call: &ToolCallRecord) -> Value {
    json!({
        "id": call.id,
        "at": call.at.to_rfc3339(),
        "user_id": call.user_id,
        "principal": call.principal_label,
        "token_id": call.token_id,
        "auth_method": call.auth_method,
        "backend": call.backend,
        "tool": call.tool,
        "outcome": call.outcome,
        "error_code": call.error_code,
        "error_message": call.error_message,
        "duration_ms": call.duration_ms,
        "trace_id": call.trace_id,
        "client_ip": call.client_ip,
        "user_agent": call.user_agent,
        "arguments_capture": call.arguments_capture,
    })
}

fn rule_json(rule: &CaptureRule) -> Value {
    json!({
        "id": rule.id,
        "backend": rule.backend,
        "tool_pattern": rule.tool_pattern,
        "mode": rule.mode.as_str(),
        "drop_keys": rule.drop_keys,
    })
}

fn settings_json(settings: AuditSettings) -> Value {
    json!({
        "arguments_retention_days": settings.arguments_retention_days,
        "metadata_retention_days": settings.metadata_retention_days,
    })
}

/// `GET /api/v1/tool-calls` query
#[derive(Debug, Deserialize)]
struct CallsQuery {
    /// A user id
    user: Option<String>,
    backend: Option<String>,
    /// The backend's own tool name
    tool: Option<String>,
    outcome: Option<String>,
    /// A call id: only older calls
    before: Option<i64>,
    limit: Option<i64>,
}

/// `GET /api/v1/tool-calls`: newest first; `next_before` is the `before` of the
/// next page, `null` on the last one
async fn handle_list_calls(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiQuery(query): ApiQuery<CallsQuery>,
) -> ApiResult<Json<Value>> {
    let filter = call_filter(
        query.user.as_deref(),
        query.backend.as_deref(),
        query.tool.as_deref(),
        query.outcome.as_deref(),
    )?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let mut calls = audit_admin(&state, &session)?
        .calls(&filter, query.before, limit + 1)
        .await?;
    let page = usize::try_from(limit).unwrap_or(usize::MAX);
    let next_before = if calls.len() > page {
        calls.truncate(page);
        calls.last().map(|call| call.id)
    } else {
        None
    };
    let calls: Vec<Value> = calls.iter().map(call_json).collect();
    Ok(Json(json!({ "calls": calls, "next_before": next_before })))
}

/// `GET /api/v1/tool-calls/{id}`: the metadata of one call
async fn handle_get_call(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<Json<Value>> {
    let call = audit_admin(&state, &session)?.call(id).await?;
    Ok(Json(call_json(&call)))
}

/// `POST /api/v1/tool-calls/{id}/arguments`: the stored arguments. A POST
/// because the read is itself audited. 404 when none are stored.
async fn handle_arguments(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<Response> {
    let stored = audit_admin(&state, &session)?.arguments(id).await?;
    let body = Json(json!({
        "call_id": stored.call_id,
        "at": stored.at.to_rfc3339(),
        "capture": stored.capture,
        "arguments": stored.arguments,
    }));
    Ok(([(CACHE_CONTROL, "no-store")], body).into_response())
}

/// `GET /api/v1/audit/settings`
async fn handle_get_settings(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let settings = audit_admin(&state, &session)?.settings().await?;
    Ok(Json(settings_json(settings)))
}

/// `PUT /api/v1/audit/settings` body: both retentions, in days
#[derive(Debug, Deserialize)]
struct SettingsBody {
    arguments_retention_days: i32,
    metadata_retention_days: i32,
}

/// `PUT /api/v1/audit/settings`
async fn handle_put_settings(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<SettingsBody>,
) -> ApiResult<Json<Value>> {
    let settings = audit_admin(&state, &session)?
        .update_settings(body.arguments_retention_days, body.metadata_retention_days)
        .await?;
    Ok(Json(settings_json(settings)))
}

/// `GET /api/v1/audit/capture-rules`
async fn handle_list_rules(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let rules = audit_admin(&state, &session)?.capture_rules().await?;
    let rules: Vec<Value> = rules.iter().map(rule_json).collect();
    Ok(Json(json!({ "rules": rules })))
}

/// `POST /api/v1/audit/capture-rules` body
#[derive(Debug, Deserialize)]
struct RuleBody {
    /// A backend name or `*`
    backend: String,
    /// A tool name or a prefix ending in `*`
    tool_pattern: String,
    /// `none`, `redacted` or `full`
    mode: String,
    #[serde(default)]
    drop_keys: Vec<String>,
}

/// `POST /api/v1/audit/capture-rules`
async fn handle_create_rule(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<RuleBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let rule = audit_admin(&state, &session)?
        .create_capture_rule(
            &body.backend,
            &body.tool_pattern,
            &body.mode,
            &body.drop_keys,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(rule_json(&rule))))
}

/// `DELETE /api/v1/audit/capture-rules/{id}`
async fn handle_delete_rule(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    audit_admin(&state, &session)?
        .delete_capture_rule(id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_filters_match_everything() {
        let filter = call_filter(Some(" "), Some(""), None, Some("  ")).unwrap();
        assert_eq!(filter, ToolCallFilter::default());
    }

    #[test]
    fn filters_are_parsed_and_trimmed() {
        let id = Uuid::new_v4();
        let filter = call_filter(
            Some(&format!(" {id} ")),
            Some(" files "),
            Some("read_file"),
            Some("tool_error"),
        )
        .unwrap();
        assert_eq!(
            filter,
            ToolCallFilter {
                user_id: Some(id),
                backend: Some("files".to_owned()),
                tool: Some("read_file".to_owned()),
                outcome: Some("tool_error".to_owned()),
            }
        );
    }

    #[test]
    fn a_bad_user_or_outcome_is_invalid() {
        assert!(matches!(
            call_filter(Some("alice"), None, None, None),
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            call_filter(None, None, None, Some("denied")),
            Err(AdminError::Invalid(_))
        ));
    }
}
