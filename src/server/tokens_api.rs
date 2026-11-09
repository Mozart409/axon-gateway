//! The token routes of the JSON API under `/api/v1`: a user's own personal
//! access tokens and the admin's service accounts with their tokens.
//!
//! [`routes`] is merged into the router of `admin_api`, so these routes sit
//! behind the same multi-user check, session guard, same-site check and CSRF
//! token, and answer errors the same way. The secret of a token is in the
//! response that creates it and nowhere else.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, patch};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::AppState;
use super::admin_api::{ApiJson, ApiPath, ApiResult, admin};
use crate::principal::TokenScope;
use crate::rbac::{AdminError, MyTokens, TokenState};
use crate::store::{ApiToken, IssuedToken, PAT_PREFIX, ServiceAccount, SessionUser};

/// The token routes, without guards: `admin_api::router` adds them.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/tokens",
            get(handle_list_tokens).post(handle_create_token),
        )
        .route("/api/v1/tokens/{id}", delete(handle_revoke_token))
        .route(
            "/api/v1/service-accounts",
            get(handle_list_accounts).post(handle_create_account),
        )
        .route(
            "/api/v1/service-accounts/{id}",
            patch(handle_update_account).delete(handle_delete_account),
        )
        .route(
            "/api/v1/service-accounts/{id}/tokens",
            get(handle_list_account_tokens).post(handle_create_account_token),
        )
        .route(
            "/api/v1/service-accounts/{id}/tokens/{token_id}",
            delete(handle_revoke_account_token),
        )
}

/// What a token looks like with its secret left out
fn token_json(token: &ApiToken) -> Value {
    json!({
        "id": token.id,
        "public_id": token.public_id,
        "name": token.name,
        "prefix": format!("{PAT_PREFIX}{}_", token.public_id),
        "scope_backends": token.scope_backends,
        "scope_tools": token.scope_tools,
        "created_at": token.created_at.to_rfc3339(),
        "expires_at": token.expires_at.to_rfc3339(),
        "last_used_at": token.last_used_at.map(|at| at.to_rfc3339()),
        "state": TokenState::of(token).as_str(),
    })
}

/// The create response: the token and its plaintext, which is never shown again
fn issued_json(issued: &IssuedToken) -> Value {
    let mut value = token_json(&issued.token);
    if let Some(object) = value.as_object_mut() {
        object.insert(String::from("plaintext"), json!(issued.plaintext));
    }
    value
}

fn account_json(account: &ServiceAccount) -> Value {
    json!({
        "id": account.id,
        "name": account.name,
        "description": account.description,
        "disabled": account.disabled,
        "created_at": account.created_at.to_rfc3339(),
    })
}

/// `POST /api/v1/tokens` and `POST /api/v1/service-accounts/{id}/tokens` body
#[derive(Debug, Deserialize)]
struct CreateTokenBody {
    name: String,
    /// Defaults to 30; users may ask for up to 90, service accounts 365
    expires_in_days: Option<u32>,
    /// Backends the token is narrowed to; empty or absent means no narrowing
    #[serde(default)]
    scope_backends: Vec<String>,
    /// Tool globs on the namespaced tool name; empty or absent means no narrowing
    #[serde(default)]
    scope_tools: Vec<String>,
}

impl CreateTokenBody {
    fn scope(&self) -> TokenScope {
        TokenScope {
            backends: self.scope_backends.clone(),
            tools: self.scope_tools.clone(),
        }
    }
}

fn my_tokens<'a>(state: &'a AppState, session: &SessionUser) -> ApiResult<MyTokens<'a>> {
    MyTokens::from_state(state, session).ok_or_else(|| AdminError::NotFound.into())
}

/// `GET /api/v1/tokens`: the caller's tokens
async fn handle_list_tokens(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let tokens = my_tokens(&state, &session)?.list().await?;
    let tokens: Vec<Value> = tokens.iter().map(token_json).collect();
    Ok(Json(json!({ "tokens": tokens })))
}

/// `POST /api/v1/tokens`: issues a token for the caller
async fn handle_create_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<CreateTokenBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let issued = my_tokens(&state, &session)?
        .create(&body.name, body.expires_in_days, &body.scope())
        .await?;
    Ok((StatusCode::CREATED, Json(issued_json(&issued))))
}

/// `DELETE /api/v1/tokens/{id}`: revokes one of the caller's tokens
async fn handle_revoke_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    my_tokens(&state, &session)?.revoke(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/service-accounts`
async fn handle_list_accounts(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let accounts = admin(&state, &session).await?.service_accounts().await?;
    let accounts: Vec<Value> = accounts.iter().map(account_json).collect();
    Ok(Json(json!({ "service_accounts": accounts })))
}

/// `POST /api/v1/service-accounts` body
#[derive(Debug, Deserialize)]
struct CreateAccountBody {
    name: String,
    description: Option<String>,
}

/// `POST /api/v1/service-accounts`
async fn handle_create_account(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<CreateAccountBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let account = admin(&state, &session)
        .await?
        .create_service_account(&body.name, body.description.as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(account_json(&account))))
}

/// `PATCH /api/v1/service-accounts/{id}` body
#[derive(Debug, Deserialize)]
struct UpdateAccountBody {
    disabled: bool,
}

/// `PATCH /api/v1/service-accounts/{id}`: disables or re-enables the account
async fn handle_update_account(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<UpdateAccountBody>,
) -> ApiResult<Json<Value>> {
    let admin = admin(&state, &session).await?;
    admin
        .set_service_account_disabled(id, body.disabled)
        .await?;
    let account = admin.service_account(id).await?;
    Ok(Json(account_json(&account)))
}

/// `DELETE /api/v1/service-accounts/{id}`
async fn handle_delete_account(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .delete_service_account(id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/service-accounts/{id}/tokens`
async fn handle_list_account_tokens(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
) -> ApiResult<Json<Value>> {
    let tokens = admin(&state, &session)
        .await?
        .service_account_tokens(id)
        .await?;
    let tokens: Vec<Value> = tokens.iter().map(token_json).collect();
    Ok(Json(json!({ "tokens": tokens })))
}

/// `POST /api/v1/service-accounts/{id}/tokens`
async fn handle_create_account_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<CreateTokenBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let issued = admin(&state, &session)
        .await?
        .issue_service_account_token(id, &body.name, body.expires_in_days, &body.scope())
        .await?;
    Ok((StatusCode::CREATED, Json(issued_json(&issued))))
}

/// `DELETE /api/v1/service-accounts/{id}/tokens/{token_id}`
async fn handle_revoke_account_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath((id, token_id)): ApiPath<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .revoke_service_account_token(id, token_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
