//! The JSON admin API under `/api/v1`: RBAC groups, grants, role bindings,
//! users and the audit log (and, from `tokens_api`, personal access tokens and
//! service accounts).
//!
//! Every route needs a dashboard session (`session::require_session`, which
//! answers 401 JSON here); writes also need the session's `X-CSRF-Token` and a
//! same-site request. Outside multi-user mode every route is a JSON 404. What
//! a caller may do is decided by [`Admin`]; this module only maps HTTP to it
//! and its errors back: 403 forbidden, 404 not found, 409 conflict, 400
//! invalid input (bad JSON included), 503 database trouble, all as
//! `{"error": "..."}`.

use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Json, Router};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{AppState, reject_cross_site_middleware, session};
use crate::policy::{
    GrantConfig, GrantView, GroupView, Permission, Role, RoleBinding, RoleSubject, Source,
};
use crate::rbac::{Admin, AdminError, ManagedUser, resolve};
use crate::store::{AuditRecord, SessionUser};

const DEFAULT_USERS_LIMIT: i64 = 100;
const MAX_USERS_LIMIT: i64 = 500;
const DEFAULT_AUDIT_LIMIT: i64 = 50;
const MAX_AUDIT_LIMIT: i64 = 200;

pub(super) type ApiResult<T> = Result<T, ApiError>;

/// An [`AdminError`] as a JSON response
pub(super) struct ApiError(AdminError);

impl ApiError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(AdminError::Invalid(message.into()))
    }
}

impl From<AdminError> for ApiError {
    fn from(error: AdminError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self.0 {
            AdminError::Forbidden => (StatusCode::FORBIDDEN, self.0.to_string()),
            AdminError::NotFound => (StatusCode::NOT_FOUND, self.0.to_string()),
            AdminError::Conflict(_) => (StatusCode::CONFLICT, self.0.to_string()),
            AdminError::Invalid(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            AdminError::Store(error) => {
                tracing::warn!(%error, "An admin API request failed in the database");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the database is unavailable".to_owned(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

/// `Json<T>` whose rejection is a 400 JSON error
pub(super) struct ApiJson<T>(pub(super) T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::invalid(rejection.body_text())),
        }
    }
}

/// `Path<T>` whose rejection is a 400 JSON error
pub(super) struct ApiPath<T>(pub(super) T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(ApiError::invalid(rejection.body_text())),
        }
    }
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
            Err(rejection) => Err(ApiError::invalid(rejection.body_text())),
        }
    }
}

/// The `/api/v1` routes with their guards.
///
/// Layers run outermost first: multi-user check, session, same-site check,
/// CSRF token (writes only).
pub(super) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/me", get(handle_me))
        .route(
            "/api/v1/groups",
            get(handle_list_groups).post(handle_create_group),
        )
        .route(
            "/api/v1/groups/{name}",
            get(handle_get_group)
                .patch(handle_update_group)
                .delete(handle_delete_group),
        )
        .route(
            "/api/v1/groups/{name}/idp-mappings",
            post(handle_add_idp_mapping).delete(handle_remove_idp_mapping),
        )
        .route(
            "/api/v1/groups/{name}/members/{user_id}",
            put(handle_add_member).delete(handle_remove_member),
        )
        .route(
            "/api/v1/grants",
            get(handle_list_grants).post(handle_create_grant),
        )
        .route("/api/v1/grants/{id}", delete(handle_delete_grant))
        .route(
            "/api/v1/role-bindings",
            get(handle_list_role_bindings).post(handle_create_role_binding),
        )
        .route(
            "/api/v1/role-bindings/{id}",
            delete(handle_delete_role_binding),
        )
        .route("/api/v1/users", get(handle_list_users))
        .route("/api/v1/users/{id}", patch(handle_update_user))
        .route("/api/v1/audit", get(handle_list_audit))
        .merge(super::tokens_api::routes())
        .merge(super::personal_api::routes())
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
        return ApiError(AdminError::NotFound).into_response();
    }
    next.run(request).await
}

pub(super) async fn admin<'a>(state: &'a AppState, session: &SessionUser) -> ApiResult<Admin<'a>> {
    Admin::from_state(state, session)
        .await
        .ok_or_else(|| AdminError::NotFound.into())
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::Config => "config",
        Source::Local => "local",
    }
}

fn group_json(group: &GroupView) -> Value {
    json!({
        "name": group.name,
        "description": group.description,
        "source": source_name(group.source),
        "idp_mappings": group
            .idp
            .iter()
            .map(|mapping| json!({ "provider": mapping.provider, "value": mapping.value }))
            .collect::<Vec<_>>(),
    })
}

fn grant_json(view: &GrantView) -> Value {
    json!({
        "id": view.id,
        "source": source_name(view.source),
        "group": view.grant.group,
        "backend": view.grant.backend,
        "include": view.grant.include,
        "exclude": view.grant.exclude,
        "read_only": view.grant.read_only,
        "mandatory": view.grant.mandatory,
    })
}

fn binding_json(binding: &RoleBinding) -> Value {
    let (group, user_id) = match &binding.subject {
        RoleSubject::Group(group) => (Some(group.as_str()), None),
        RoleSubject::User(user_id) => (None, Some(*user_id)),
    };
    let source = if binding.id.is_some() {
        Source::Local
    } else {
        Source::Config
    };
    json!({
        "id": binding.id,
        "source": source_name(source),
        "role": binding.role.as_str(),
        "group": group,
        "user_id": user_id,
    })
}

fn user_json(managed: &ManagedUser) -> Value {
    let user = &managed.user;
    json!({
        "id": user.id,
        "issuer": user.issuer,
        "subject": user.subject,
        "email": user.email,
        "display_name": user.display_name,
        "groups": user.groups,
        "is_admin": user.is_admin,
        "last_login_at": managed.last_login_at.map(|at| at.to_rfc3339()),
        "disabled": managed.disabled,
    })
}

fn audit_json(record: &AuditRecord) -> Value {
    json!({
        "id": record.id,
        "at": record.at.to_rfc3339(),
        "actor_user_id": record.actor_user_id,
        "actor": record.actor,
        "action": record.action,
        "target": record.target,
        "details": record.details,
    })
}

/// `GET /api/v1/me`: the caller, their groups, roles and permissions.
async fn handle_me(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Json<Value> {
    let (groups, permissions) = resolve(&state.policy.current(), &session);
    let user = &session.user;
    Json(json!({
        "user": {
            "id": user.id,
            "issuer": user.issuer,
            "subject": user.subject,
            "email": user.email,
            "display_name": user.display_name,
        },
        "groups": groups,
        "roles": permissions.roles().map(Role::as_str).collect::<Vec<_>>(),
        "permissions": Permission::ALL
            .into_iter()
            .filter(|permission| permissions.has(*permission))
            .map(Permission::as_str)
            .collect::<Vec<_>>(),
    }))
}

/// `GET /api/v1/groups`
async fn handle_list_groups(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let groups = admin(&state, &session).await?.groups()?;
    let groups: Vec<Value> = groups.iter().map(group_json).collect();
    Ok(Json(json!({ "groups": groups })))
}

/// `POST /api/v1/groups` body
#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    name: String,
    description: Option<String>,
}

/// `POST /api/v1/groups`
async fn handle_create_group(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<CreateGroupBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let admin = admin(&state, &session).await?;
    admin
        .create_group(&body.name, body.description.as_deref())
        .await?;
    // Built here: the policy may not have reloaded yet if the refresh failed.
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|text| !text.is_empty());
    let group = json!({
        "name": body.name,
        "description": description,
        "source": source_name(Source::Local),
        "idp_mappings": [],
        "members": [],
    });
    Ok((StatusCode::CREATED, Json(group)))
}

/// `GET /api/v1/groups/{name}`: the group with its member ids
async fn handle_get_group(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    let (group, members) = admin(&state, &session).await?.group(&name)?;
    let mut value = group_json(&group);
    if let Some(object) = value.as_object_mut() {
        object.insert(String::from("members"), json!(members));
    }
    Ok(Json(value))
}

/// `PATCH /api/v1/groups/{name}` body; a missing or null description clears it
#[derive(Debug, Deserialize)]
struct UpdateGroupBody {
    description: Option<String>,
}

/// `PATCH /api/v1/groups/{name}`
async fn handle_update_group(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<UpdateGroupBody>,
) -> ApiResult<Json<Value>> {
    let admin = admin(&state, &session).await?;
    admin
        .update_group(&name, body.description.as_deref())
        .await?;
    let (group, members) = admin.group(&name)?;
    let mut value = group_json(&group);
    if let Some(object) = value.as_object_mut() {
        object.insert(String::from("members"), json!(members));
    }
    Ok(Json(value))
}

/// `DELETE /api/v1/groups/{name}`
async fn handle_delete_group(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> ApiResult<StatusCode> {
    admin(&state, &session).await?.delete_group(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Body of the `IdP` mapping routes
#[derive(Debug, Deserialize)]
struct IdpMappingBody {
    provider: String,
    value: String,
}

/// `POST /api/v1/groups/{name}/idp-mappings`
async fn handle_add_idp_mapping(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<IdpMappingBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    admin(&state, &session)
        .await?
        .add_idp_mapping(&name, &body.provider, &body.value)
        .await?;
    let mapping = json!({ "provider": body.provider, "value": body.value });
    Ok((StatusCode::CREATED, Json(mapping)))
}

/// `DELETE /api/v1/groups/{name}/idp-mappings`
async fn handle_remove_idp_mapping(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<IdpMappingBody>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .remove_idp_mapping(&name, &body.provider, &body.value)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /api/v1/groups/{name}/members/{user_id}`
async fn handle_add_member(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath((name, user_id)): ApiPath<(String, Uuid)>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .add_member(&name, user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/groups/{name}/members/{user_id}`
async fn handle_remove_member(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath((name, user_id)): ApiPath<(String, Uuid)>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .remove_member(&name, user_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/grants`
async fn handle_list_grants(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let grants = admin(&state, &session).await?.grants()?;
    let grants: Vec<Value> = grants.iter().map(grant_json).collect();
    Ok(Json(json!({ "grants": grants })))
}

/// `POST /api/v1/grants`: the body is a `[[rbac.grants]]` entry
async fn handle_create_grant(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(grant): ApiJson<GrantConfig>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let id = admin(&state, &session).await?.create_grant(grant).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

/// `DELETE /api/v1/grants/{id}`
async fn handle_delete_grant(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    admin(&state, &session).await?.delete_grant(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/role-bindings`
async fn handle_list_role_bindings(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let bindings = admin(&state, &session).await?.role_bindings()?;
    let bindings: Vec<Value> = bindings.iter().map(binding_json).collect();
    Ok(Json(json!({ "role_bindings": bindings })))
}

/// `POST /api/v1/role-bindings` body: the role and exactly one of `group` and
/// `user_id`
#[derive(Debug, Deserialize)]
struct RoleBindingBody {
    role: Role,
    group: Option<String>,
    user_id: Option<Uuid>,
}

/// `POST /api/v1/role-bindings`
async fn handle_create_role_binding(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<RoleBindingBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let subject = match (body.group, body.user_id) {
        (Some(group), None) => RoleSubject::Group(group),
        (None, Some(user_id)) => RoleSubject::User(user_id),
        _ => {
            return Err(ApiError::invalid(
                "give exactly one of \"group\" and \"user_id\"",
            ));
        }
    };
    let id = admin(&state, &session)
        .await?
        .create_role_binding(body.role, subject)
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

/// `DELETE /api/v1/role-bindings/{id}`
async fn handle_delete_role_binding(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<i64>,
) -> ApiResult<StatusCode> {
    admin(&state, &session)
        .await?
        .delete_role_binding(id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/users?limit=`
#[derive(Debug, Deserialize)]
struct UsersQuery {
    limit: Option<i64>,
}

/// `GET /api/v1/users`
async fn handle_list_users(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiQuery(query): ApiQuery<UsersQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_USERS_LIMIT)
        .clamp(1, MAX_USERS_LIMIT);
    let users = admin(&state, &session).await?.managed_users(limit).await?;
    let users: Vec<Value> = users.iter().map(user_json).collect();
    Ok(Json(json!({ "users": users })))
}

/// `PATCH /api/v1/users/{id}` body
#[derive(Debug, Deserialize)]
struct UpdateUserBody {
    disabled: bool,
}

/// `PATCH /api/v1/users/{id}`: disables or re-enables the user
async fn handle_update_user(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<UpdateUserBody>,
) -> ApiResult<Json<Value>> {
    let user = admin(&state, &session)
        .await?
        .set_user_disabled(id, body.disabled)
        .await?;
    Ok(Json(user_json(&user)))
}

/// `GET /api/v1/audit?limit=&before=`: `before` is an entry id, for paging
#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    before: Option<i64>,
}

/// `GET /api/v1/audit`
async fn handle_list_audit(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiQuery(query): ApiQuery<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_AUDIT_LIMIT)
        .clamp(1, MAX_AUDIT_LIMIT);
    let entries = admin(&state, &session)
        .await?
        .audit(limit, query.before)
        .await?;
    let entries: Vec<Value> = entries.iter().map(audit_json).collect();
    Ok(Json(json!({ "entries": entries })))
}
