//! The usage pages: `/ui/me/usage` for a user's own tool-call usage,
//! `/ui/admin/usage` (users by calls) and `/ui/admin/usage/{user_id}` for
//! holders of `audit.read`.
//!
//! Merged into the routes behind the session guard (see `audit_ui`); outside
//! multi-user mode every route is a 404. The loaders and their permission
//! checks are those of `usage_api`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use uuid::Uuid;

use super::AppState;
use super::admin_ui::{not_found, page_error};
use super::usage_api::{DaysQuery, load_own, load_user, load_users, parse_days};
use super::usage_views::{
    my_usage_region, render_my_usage_page, render_user_usage_page, render_users_usage_page,
    user_usage_region, users_usage_region,
};
use crate::rbac::AdminError;
use crate::store::SessionUser;

fn admin_error_status(error: &AdminError) -> StatusCode {
    match error {
        AdminError::Forbidden => StatusCode::FORBIDDEN,
        AdminError::NotFound => StatusCode::NOT_FOUND,
        AdminError::Conflict(_) => StatusCode::CONFLICT,
        AdminError::Invalid(_) => StatusCode::BAD_REQUEST,
        AdminError::Store(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/me/usage", get(handle_my_usage))
        .route("/ui/admin/usage", get(handle_users_usage))
        .route("/ui/admin/usage/{user_id}", get(handle_user_usage))
        .route("/ui/partials/usage", get(handle_my_usage_fragment))
        .route("/ui/partials/admin/usage", get(handle_users_usage_fragment))
        .route(
            "/ui/partials/admin/usage/{user_id}",
            get(handle_user_usage_fragment),
        )
}

/// Handle GET /ui/me/usage - the signed-in user's own usage
async fn handle_my_usage(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<DaysQuery>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return page_error(&state, &session, &error),
    };
    match load_own(&state, &session, days).await {
        Ok(report) => {
            Html(render_my_usage_page(&state, &session, &report).into_string()).into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle GET /ui/partials/usage - the my-usage region fragment
async fn handle_my_usage_fragment(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<DaysQuery>,
) -> Result<Html<String>, StatusCode> {
    let Some(Extension(session)) = user else {
        return Err(StatusCode::NOT_FOUND);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return Err(admin_error_status(&error)),
    };
    match load_own(&state, &session, days).await {
        Ok(report) => Ok(Html(my_usage_region(days, &report).into_string())),
        Err(error) => Err(admin_error_status(&error)),
    }
}

/// Handle GET /ui/admin/usage - the users by calls
async fn handle_users_usage(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<DaysQuery>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return page_error(&state, &session, &error),
    };
    match load_users(&state, &session, days).await {
        Ok(rows) => Html(render_users_usage_page(&state, &session, days, &rows).into_string())
            .into_response(),
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle GET /ui/partials/admin/usage - users-by-calls region fragment
async fn handle_users_usage_fragment(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<DaysQuery>,
) -> Result<Html<String>, StatusCode> {
    let Some(Extension(session)) = user else {
        return Err(StatusCode::NOT_FOUND);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return Err(admin_error_status(&error)),
    };
    match load_users(&state, &session, days).await {
        Ok(rows) => Ok(Html(users_usage_region(days, &rows).into_string())),
        Err(error) => Err(admin_error_status(&error)),
    }
}

/// Handle `GET /ui/admin/usage/{user_id}` - one user's usage
async fn handle_user_usage(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<DaysQuery>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return page_error(&state, &session, &error),
    };
    match load_user(&state, &session, user_id, days).await {
        Ok((subject, report)) => {
            Html(render_user_usage_page(&state, &session, user_id, &subject, &report).into_string())
                .into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle `GET /ui/partials/admin/usage/{user_id}` - one user's usage region fragment
async fn handle_user_usage_fragment(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<DaysQuery>,
) -> Result<Html<String>, StatusCode> {
    let Some(Extension(session)) = user else {
        return Err(StatusCode::NOT_FOUND);
    };
    let days = match parse_days(query.days.as_deref()) {
        Ok(days) => days,
        Err(error) => return Err(admin_error_status(&error)),
    };
    match load_user(&state, &session, user_id, days).await {
        Ok((_subject, report)) => Ok(Html(
            user_usage_region(user_id, days, &report).into_string(),
        )),
        Err(error) => Err(admin_error_status(&error)),
    }
}
