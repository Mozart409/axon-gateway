//! The usage routes of the JSON API under `/api/v1`: a user's own tool-call
//! usage, and for `audit.read` holders the users by calls and any user's usage.
//!
//! The routes are merged into the audit API router (`audit_api::router`), so
//! they sit behind its guards: multi-user mode, session, same-site check. The
//! loaders are shared with the usage pages in `usage_ui`.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::AppState;
use super::admin_api::{ApiPath, ApiResult};
use crate::policy::Permission;
use crate::rbac::{AdminError, resolve};
use crate::store::{
    DEFAULT_USAGE_DAYS, MAX_USAGE_DAYS, SessionUser, Store, UsageReport, UsageUser, UserUsageRow,
};

/// Rows of the users-by-calls table
pub(super) const USERS_LIMIT: i64 = 100;

/// The audit API's guards apply: the routes are merged into its router.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/me/usage", get(handle_my_usage))
        .route("/api/v1/admin/usage", get(handle_users_usage))
        .route("/api/v1/admin/usage/{user_id}", get(handle_user_usage))
}

/// The `days` query of every usage route, as typed
#[derive(Debug, Deserialize)]
pub(super) struct DaysQuery {
    pub days: Option<String>,
}

/// The window of a request: 1 to 90 days, 30 when absent or blank.
///
/// # Errors
/// [`AdminError::Invalid`] for anything else.
pub(super) fn parse_days(days: Option<&str>) -> Result<i32, AdminError> {
    let Some(days) = days.map(str::trim).filter(|days| !days.is_empty()) else {
        return Ok(DEFAULT_USAGE_DAYS);
    };
    match days.parse::<i32>() {
        Ok(days) if (1..=MAX_USAGE_DAYS).contains(&days) => Ok(days),
        _ => Err(AdminError::Invalid(format!(
            "days must be a whole number between 1 and {MAX_USAGE_DAYS}"
        ))),
    }
}

fn store(state: &AppState) -> Result<&Store, AdminError> {
    state
        .multi_user()
        .map(|(store, _)| store)
        .ok_or(AdminError::NotFound)
}

fn require_audit_read(state: &AppState, session: &SessionUser) -> Result<(), AdminError> {
    let (_, permissions) = resolve(&state.policy.current(), session);
    if permissions.has(Permission::AuditRead) {
        Ok(())
    } else {
        Err(AdminError::Forbidden)
    }
}

/// The caller's own usage; anyone signed in may.
///
/// # Errors
/// Not found outside multi-user mode; a store error.
pub(super) async fn load_own(
    state: &AppState,
    session: &SessionUser,
    days: i32,
) -> Result<UsageReport, AdminError> {
    Ok(store(state)?.user_usage(session.user.id, days).await?)
}

/// The users with calls in the window, most calls first.
///
/// # Errors
/// Forbidden without `audit.read`; a store error.
pub(super) async fn load_users(
    state: &AppState,
    session: &SessionUser,
    days: i32,
) -> Result<Vec<UserUsageRow>, AdminError> {
    require_audit_read(state, session)?;
    Ok(store(state)?.usage_by_user(days, USERS_LIMIT).await?)
}

/// One user's usage and name.
///
/// # Errors
/// Forbidden without `audit.read`; not found for an unknown user.
pub(super) async fn load_user(
    state: &AppState,
    session: &SessionUser,
    user_id: Uuid,
    days: i32,
) -> Result<(UsageUser, UsageReport), AdminError> {
    require_audit_read(state, session)?;
    let store = store(state)?;
    let user = store
        .usage_user(user_id)
        .await?
        .ok_or(AdminError::NotFound)?;
    let report = store.user_usage(user_id, days).await?;
    Ok((user, report))
}

fn report_json(report: &UsageReport) -> Value {
    let totals = &report.totals;
    let daily: Vec<Value> = report
        .daily
        .iter()
        .map(|day| json!({"date": day.day.to_string(), "calls": day.calls, "errors": day.errors}))
        .collect();
    let backends: Vec<Value> = report
        .backends
        .iter()
        .map(|backend| {
            json!({
                "backend": backend.backend,
                "calls": backend.calls,
                "errors": backend.errors,
                "error_rate": backend.error_rate,
                "p95_ms": backend.p95_ms,
            })
        })
        .collect();
    let tools: Vec<Value> = report
        .tools
        .iter()
        .map(|tool| {
            json!({
                "backend": tool.backend,
                "tool": tool.tool,
                "calls": tool.calls,
                "errors": tool.errors,
            })
        })
        .collect();
    json!({
        "days": report.days,
        "since": report.since.to_rfc3339(),
        "totals": {
            "calls": totals.calls,
            "errors": totals.errors,
            "error_rate": totals.error_rate,
            "tools": totals.tools,
            "backends": totals.backends,
            "p50_ms": totals.p50_ms,
            "p95_ms": totals.p95_ms,
        },
        "daily": daily,
        "backends": backends,
        "tools": tools,
    })
}

/// `GET /api/v1/me/usage?days=`: the caller's usage
async fn handle_my_usage(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    Query(query): Query<DaysQuery>,
) -> ApiResult<Json<Value>> {
    let days = parse_days(query.days.as_deref())?;
    let report = load_own(&state, &session, days).await?;
    Ok(Json(report_json(&report)))
}

/// `GET /api/v1/admin/usage?days=`: the users by calls (`audit.read`)
async fn handle_users_usage(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    Query(query): Query<DaysQuery>,
) -> ApiResult<Json<Value>> {
    let days = parse_days(query.days.as_deref())?;
    let rows = load_users(&state, &session, days).await?;
    let users: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "user_id": row.user_id,
                "name": row.user.label(),
                "display_name": row.user.display_name,
                "email": row.user.email,
                "calls": row.calls,
                "errors": row.errors,
                "last_call": row.last_call.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(json!({ "days": days, "users": users })))
}

/// `GET /api/v1/admin/usage/{user_id}?days=`: one user's usage (`audit.read`)
async fn handle_user_usage(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(user_id): ApiPath<Uuid>,
    Query(query): Query<DaysQuery>,
) -> ApiResult<Json<Value>> {
    let days = parse_days(query.days.as_deref())?;
    let (user, report) = load_user(&state, &session, user_id, days).await?;
    let mut body = report_json(&report);
    if let Value::Object(map) = &mut body {
        map.insert(
            "user".to_owned(),
            json!({
                "id": user_id,
                "name": user.label(),
                "display_name": user.display_name,
                "email": user.email,
            }),
        );
    }
    Ok(Json(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_defaults_to_30_days() {
        assert_eq!(parse_days(None).unwrap(), 30);
        assert_eq!(parse_days(Some("")).unwrap(), 30);
        assert_eq!(parse_days(Some("  ")).unwrap(), 30);
    }

    #[test]
    fn the_window_is_one_to_ninety_days() {
        assert_eq!(parse_days(Some("1")).unwrap(), 1);
        assert_eq!(parse_days(Some(" 90 ")).unwrap(), 90);
        for bad in ["0", "91", "-3", "week", "7.5"] {
            assert!(
                matches!(parse_days(Some(bad)), Err(AdminError::Invalid(_))),
                "{bad}"
            );
        }
    }
}
