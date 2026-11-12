//! The connected-apps routes of the JSON API under `/api/v1`: a user's own OAuth grants and,
//! for admins with `tokens.manage_all`, everyone's.
//!
//! [`routes`] is merged into the router of `admin_api`, so these routes sit behind the same
//! multi-user check, session guard, same-site check and CSRF token, and answer errors the
//! same way.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Extension, Json, Router};
use serde_json::{Value, json};
use uuid::Uuid;

use super::AppState;
use super::admin_api::{ApiPath, ApiResult};
use super::oauth::cimd_host;
use crate::policy::Permission;
use crate::rbac::{AdminError, resolve};
use crate::store::{Actor, OauthGrant, SessionUser, Store};

/// The grant routes, without guards: `admin_api::router` adds them.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/me/oauth-grants", get(handle_list_mine))
        .route("/api/v1/me/oauth-grants/{id}", delete(handle_revoke_mine))
        .route("/api/v1/admin/oauth-grants", get(handle_list_all))
        .route("/api/v1/admin/oauth-grants/{id}", delete(handle_revoke_any))
}

fn grant_json(grant: &OauthGrant) -> Value {
    json!({
        "id": grant.id,
        "client_id": grant.client_id,
        "client_name": grant.client_name,
        "client_host": cimd_host(&grant.client_id),
        "user_id": grant.user_id,
        "user_email": grant.user_email,
        "scope": grant.scope,
        "resource": grant.resource,
        "created_at": grant.created_at.to_rfc3339(),
        "last_used_at": grant.last_used_at.map(|at| at.to_rfc3339()),
    })
}

fn store(state: &AppState) -> ApiResult<&Store> {
    state
        .multi_user()
        .map(|(store, _)| store)
        .ok_or_else(|| AdminError::NotFound.into())
}

/// The store, when the caller may manage everyone's grants
fn admin_store<'a>(state: &'a AppState, session: &SessionUser) -> ApiResult<&'a Store> {
    let (_, permissions) = resolve(&state.policy.current(), session);
    if !(permissions.has(Permission::TokensManageAll) || permissions.is_admin()) {
        return Err(AdminError::Forbidden.into());
    }
    store(state)
}

/// `GET /api/v1/me/oauth-grants`: the caller's live grants
async fn handle_list_mine(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let grants = store(&state)?
        .list_oauth_grants(Some(session.user.id))
        .await
        .map_err(AdminError::Store)?;
    let grants: Vec<Value> = grants.iter().map(grant_json).collect();
    Ok(Json(json!({ "grants": grants })))
}

/// `DELETE /api/v1/me/oauth-grants/{id}`: revokes one of the caller's grants
async fn handle_revoke_mine(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    let revoked = store(&state)?
        .revoke_oauth_grant(id, Some(session.user.id))
        .await
        .map_err(AdminError::Store)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::NotFound.into())
    }
}

/// `GET /api/v1/admin/oauth-grants`: every user's live grants
async fn handle_list_all(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let grants = admin_store(&state, &session)?
        .list_oauth_grants(None)
        .await
        .map_err(AdminError::Store)?;
    let grants: Vec<Value> = grants.iter().map(grant_json).collect();
    Ok(Json(json!({ "grants": grants })))
}

/// `DELETE /api/v1/admin/oauth-grants/{id}`: revokes anyone's grant
async fn handle_revoke_any(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    let actor = Actor {
        user_id: Some(session.user.id),
        label: [
            session.user.email.as_deref(),
            session.user.display_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&session.user.subject)
        .to_owned(),
    };
    let revoked = admin_store(&state, &session)?
        .admin_revoke_oauth_grant(&actor, id)
        .await
        .map_err(AdminError::Store)?;
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AdminError::NotFound.into())
    }
}
