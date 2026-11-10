//! The toolset routes of the JSON API under `/api/v1`: a user's own toolsets.
//!
//! [`routes`] is merged into the token routes (and so into the router of `admin_api`),
//! so these routes sit behind the same multi-user check, session guard, same-site check
//! and CSRF token, and answer errors the same way. Every route works on the caller's
//! own toolsets: someone else's id is a 404. A delete answers 409 while a token that is
//! still valid is pinned to the toolset.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::AppState;
use super::admin_api::{ApiJson, ApiPath, ApiResult};
use crate::principal::TokenScope;
use crate::rbac::{AdminError, MyTokens};
use crate::store::{SessionUser, Toolset};

/// The toolset routes, without guards: `tokens_api::routes` merges them in.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/toolsets",
            get(handle_list_toolsets).post(handle_create_toolset),
        )
        .route(
            "/api/v1/toolsets/{id}",
            get(handle_get_toolset)
                .patch(handle_update_toolset)
                .delete(handle_delete_toolset),
        )
}

fn toolset_json(toolset: &Toolset) -> Value {
    json!({
        "id": toolset.id,
        "name": toolset.name,
        "description": toolset.description,
        "tools": toolset.tools,
        "backends": toolset.backends,
        "created_at": toolset.created_at.to_rfc3339(),
        "updated_at": toolset.updated_at.to_rfc3339(),
    })
}

/// `POST /api/v1/toolsets` body
#[derive(Debug, Deserialize)]
struct CreateToolsetBody {
    name: String,
    description: Option<String>,
    /// Globs on the namespaced tool name; empty or absent means no narrowing
    #[serde(default)]
    tools: Vec<String>,
    /// Backends matched exactly; empty or absent means no narrowing
    #[serde(default)]
    backends: Vec<String>,
}

/// `PATCH /api/v1/toolsets/{id}` body: only the fields present change; an empty
/// `description` clears it
#[derive(Debug, Deserialize)]
struct UpdateToolsetBody {
    name: Option<String>,
    description: Option<String>,
    tools: Option<Vec<String>>,
    backends: Option<Vec<String>>,
}

fn my_tokens<'a>(state: &'a AppState, session: &SessionUser) -> ApiResult<MyTokens<'a>> {
    MyTokens::from_state(state, session).ok_or_else(|| AdminError::NotFound.into())
}

/// `GET /api/v1/toolsets`: the caller's toolsets
async fn handle_list_toolsets(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let toolsets = my_tokens(&state, &session)?.toolsets().await?;
    let toolsets: Vec<Value> = toolsets.iter().map(toolset_json).collect();
    Ok(Json(json!({ "toolsets": toolsets })))
}

/// `POST /api/v1/toolsets`: creates a toolset for the caller
async fn handle_create_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<CreateToolsetBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let scope = TokenScope {
        backends: body.backends,
        tools: body.tools,
    };
    let toolset = my_tokens(&state, &session)?
        .create_toolset(&body.name, body.description.as_deref(), &scope)
        .await?;
    Ok((StatusCode::CREATED, Json(toolset_json(&toolset))))
}

/// `GET /api/v1/toolsets/{id}`
async fn handle_get_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Value>> {
    let toolset = my_tokens(&state, &session)?.toolset(id).await?;
    Ok(Json(toolset_json(&toolset)))
}

/// `PATCH /api/v1/toolsets/{id}`: tokens pinned to it follow at once
async fn handle_update_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<UpdateToolsetBody>,
) -> ApiResult<Json<Value>> {
    let mine = my_tokens(&state, &session)?;
    let current = mine.toolset(id).await?;
    let scope = TokenScope {
        backends: body.backends.unwrap_or(current.backends),
        tools: body.tools.unwrap_or(current.tools),
    };
    let name = body.name.unwrap_or(current.name);
    let description = body.description.or(current.description);
    let toolset = mine
        .update_toolset(id, &name, description.as_deref(), &scope)
        .await?;
    Ok(Json(toolset_json(&toolset)))
}

/// `DELETE /api/v1/toolsets/{id}`
async fn handle_delete_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    my_tokens(&state, &session)?.delete_toolset(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
