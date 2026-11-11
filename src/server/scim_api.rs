//! The SCIM 2.0 endpoints under `/scim/v2/{provider}`, where `provider` is an
//! `[[auth.oidc]]` id: an identity provider such as Entra ID or Okta pushes
//! its users and groups here (see `crate::scim` for the protocol and
//! `store::scim` for what happens to them).
//!
//! Every route needs the provider's SCIM bearer token, created on the admin
//! page; there is no session and no CSRF. Outside multi-user mode, and for a
//! provider that does not exist, every route is a 404. Requests are rate
//! limited per provider, bodies are capped at 1 MiB, and every answer,
//! errors included, is `application/scim+json` in the SCIM error schema.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, RawPathParams, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::AppState;
use crate::gateway::GetConfig;
use crate::scim::{self, ScimError};
use crate::store::scim::{LinkRule, Lookup, LookupKey, ScimStoreError};
use crate::store::{Store, StoreError};

/// Largest request body
const MAX_BODY: usize = 1024 * 1024;
/// Requests per provider and minute; an `IdP` syncing a large directory is busy
const RATE_LIMIT_PER_MINUTE: u32 = 600;

type ScimResult<T> = Result<T, Failure>;

/// A [`ScimError`] as a response
#[derive(Debug)]
struct Failure(ScimError);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = scim_response(status, &self.0.body());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

impl From<ScimError> for Failure {
    fn from(error: ScimError) -> Self {
        Self(error)
    }
}

impl From<StoreError> for Failure {
    fn from(error: StoreError) -> Self {
        tracing::warn!(%error, "A SCIM request failed in the database");
        Self(ScimError::unavailable())
    }
}

impl From<ScimStoreError> for Failure {
    fn from(error: ScimStoreError) -> Self {
        match error {
            ScimStoreError::Conflict(message) => Self(ScimError::uniqueness(message)),
            ScimStoreError::NotFound => Self(not_found()),
            ScimStoreError::Invalid(message) => Self(ScimError::invalid_value(message)),
            ScimStoreError::Patch(error) => Self(error),
            ScimStoreError::Store(error) => error.into(),
        }
    }
}

fn not_found() -> ScimError {
    ScimError::not_found("resource not found")
}

fn scim_response(status: StatusCode, body: &Value) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(scim::CONTENT_TYPE),
        )],
        serde_json::to_vec(body).unwrap_or_default(),
    )
        .into_response()
}

/// Which provider a request is for, set by [`guard`]
#[derive(Clone)]
struct Ctx {
    provider: String,
    /// `<base_url>/scim/v2/<provider>`, what `meta.location` is built from
    base: String,
}

/// The routes, behind the token guard.
pub(super) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/{provider}/ServiceProviderConfig",
            get(handle_service_provider_config),
        )
        .route(
            "/scim/v2/{provider}/ResourceTypes",
            get(handle_resource_types),
        )
        .route("/scim/v2/{provider}/Schemas", get(handle_schemas))
        .route(
            "/scim/v2/{provider}/Users",
            get(handle_list_users).post(handle_create_user),
        )
        .route(
            "/scim/v2/{provider}/Users/{id}",
            get(handle_get_user)
                .put(handle_replace_user)
                .patch(handle_patch_user)
                .delete(handle_delete_user),
        )
        .route(
            "/scim/v2/{provider}/Groups",
            get(handle_list_groups).post(handle_create_group),
        )
        .route(
            "/scim/v2/{provider}/Groups/{id}",
            get(handle_get_group)
                .put(handle_replace_group)
                .patch(handle_patch_group)
                .delete(handle_delete_group),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .route_layer(middleware::from_fn_with_state(state, guard))
}

/// The token in `Authorization: Bearer <token>`
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
}

/// Counts the request against the provider's window: `false` when it is used
/// up. A store error lets the request through, as for the OAuth limits.
async fn within_limit(store: &Store, provider: &str) -> bool {
    let key = format!("scim:{provider}");
    match store.hit_rate_limit(&key, RATE_LIMIT_PER_MINUTE).await {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(%error, key, "Rate limit check failed, letting the request through");
            true
        }
    }
}

/// Checks the provider exists, the rate limit and the bearer token, in that
/// order, and hands the provider to the handler.
async fn guard(
    State(state): State<AppState>,
    params: RawPathParams,
    mut request: Request,
    next: Next,
) -> Response {
    let Some((store, providers)) = state.multi_user() else {
        return Failure(not_found()).into_response();
    };
    let provider = params
        .iter()
        .find(|(name, _)| *name == "provider")
        .map(|(_, value)| value.to_owned());
    let Some(provider) = provider.filter(|provider| providers.get(provider).is_some()) else {
        return Failure(not_found()).into_response();
    };
    if !within_limit(store, &provider).await {
        return Failure(ScimError::too_many_requests()).into_response();
    }
    let allowed = match bearer(request.headers()) {
        Some(token) => match store.check_scim_token(&provider, token).await {
            Ok(allowed) => allowed,
            Err(error) => return Failure::from(error).into_response(),
        },
        None => false,
    };
    if !allowed {
        tracing::info!(%provider, "Rejected a SCIM request without a valid token");
        return Failure(ScimError::unauthorized("missing or invalid bearer token")).into_response();
    }
    let base = format!(
        "{}/scim/v2/{provider}",
        state.base_url.trim_end_matches('/')
    );
    request.extensions_mut().insert(Ctx { provider, base });
    next.run(request).await
}

/// The store; the guard has checked multi-user mode.
fn store(state: &AppState) -> ScimResult<&Store> {
    state
        .multi_user()
        .map(|(store, _)| store)
        .ok_or_else(|| Failure(not_found()))
}

/// The issuer and match claim a SCIM user is linked by. The claim is in the
/// running config; when that cannot be read, the default (`sub`) stands.
async fn link_rule(state: &AppState, provider: &str) -> LinkRule {
    let issuer = state
        .oidc
        .as_deref()
        .and_then(|providers| providers.get(provider))
        .map(|provider| provider.issuer().to_owned())
        .unwrap_or_default();
    let by_subject = match state.gateway.ask(GetConfig).await {
        Ok(config) => config
            .0
            .auth
            .oidc
            .iter()
            .find(|configured| configured.id == provider)
            .is_none_or(|configured| configured.scim_match_claim() == "sub"),
        Err(error) => {
            tracing::warn!(%error, "Could not read the running config for the SCIM match claim");
            true
        }
    };
    LinkRule { issuer, by_subject }
}

fn parse_body(body: &Bytes) -> ScimResult<Value> {
    serde_json::from_slice(body).map_err(|error| {
        Failure(ScimError::invalid_syntax(format!(
            "the body is not valid JSON: {error}"
        )))
    })
}

fn parse_id(raw: &str) -> ScimResult<Uuid> {
    Uuid::parse_str(raw).map_err(|_| Failure(not_found()))
}

/// The one attribute and value of an `eq` filter, when the attribute is one of
/// `allowed`
fn parse_lookup(
    filter: Option<&str>,
    allowed: &[(&str, LookupKey)],
) -> ScimResult<Option<(LookupKey, String)>> {
    let Some(filter) = filter.filter(|filter| !filter.trim().is_empty()) else {
        return Ok(None);
    };
    let parsed = scim::parse_filter(filter)?;
    let key = allowed
        .iter()
        .find(|(name, _)| *name == parsed.attr)
        .map(|(_, key)| *key)
        .ok_or_else(|| ScimError::invalid_filter(format!("cannot filter on {}", parsed.attr)))?;
    Ok(Some((key, parsed.value)))
}

const USER_FILTERS: [(&str, LookupKey); 3] = [
    ("username", LookupKey::Name),
    ("externalid", LookupKey::ExternalId),
    ("id", LookupKey::Id),
];
const GROUP_FILTERS: [(&str, LookupKey); 3] = [
    ("displayname", LookupKey::Name),
    ("externalid", LookupKey::ExternalId),
    ("id", LookupKey::Id),
];

/// The query of a list or get request
#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    filter: Option<String>,
    #[serde(rename = "startIndex")]
    start_index: Option<String>,
    count: Option<String>,
    #[serde(rename = "excludedAttributes")]
    excluded_attributes: Option<String>,
}

impl ListQuery {
    /// Groups come with their members unless `excludedAttributes` names them
    fn wants_members(&self) -> bool {
        !self.excluded_attributes.as_deref().is_some_and(|excluded| {
            excluded
                .split(',')
                .any(|name| name.trim().eq_ignore_ascii_case("members"))
        })
    }
}

fn created(ctx: &Ctx, kind: &str, id: Uuid, body: &Value) -> Response {
    let mut response = scim_response(StatusCode::CREATED, body);
    if let Ok(location) = HeaderValue::from_str(&format!("{}/{kind}/{id}", ctx.base)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

async fn handle_service_provider_config(Extension(ctx): Extension<Ctx>) -> Response {
    scim_response(StatusCode::OK, &scim::service_provider_config(&ctx.base))
}

async fn handle_resource_types(Extension(ctx): Extension<Ctx>) -> Response {
    scim_response(StatusCode::OK, &scim::resource_types(&ctx.base))
}

async fn handle_schemas(Extension(ctx): Extension<Ctx>) -> Response {
    scim_response(StatusCode::OK, &scim::schemas(&ctx.base))
}

/// `GET /Users`: all of them, or those matching an `eq` filter
async fn handle_list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let found = parse_lookup(query.filter.as_deref(), &USER_FILTERS)?;
    let lookup = found.as_ref().map(|(key, value)| Lookup {
        key: *key,
        value: value.as_str(),
    });
    let (start_index, count) = scim::page(query.start_index.as_deref(), query.count.as_deref());
    let (users, total) = store(&state)?
        .list_scim_users(&ctx.provider, lookup, start_index, count)
        .await?;
    let resources = users
        .iter()
        .map(|user| scim::user_resource(&ctx.base, user))
        .collect::<Vec<_>>();
    Ok(scim_response(
        StatusCode::OK,
        &scim::list_response(&resources, total, start_index),
    ))
}

/// `GET /Users/{id}`
async fn handle_get_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
) -> ScimResult<Response> {
    let user = store(&state)?
        .get_scim_user(&ctx.provider, parse_id(&id)?)
        .await?
        .ok_or_else(|| Failure(not_found()))?;
    Ok(scim_response(
        StatusCode::OK,
        &scim::user_resource(&ctx.base, &user),
    ))
}

/// `POST /Users`: 201, or 409 `uniqueness` for a `userName` the provider has
async fn handle_create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    body: Bytes,
) -> ScimResult<Response> {
    let attrs = scim::user_attrs_from_json(&parse_body(&body)?)?;
    let rule = link_rule(&state, &ctx.provider).await;
    let user = store(&state)?
        .create_scim_user(&ctx.provider, &rule, &attrs)
        .await?;
    Ok(created(
        &ctx,
        "Users",
        user.id,
        &scim::user_resource(&ctx.base, &user),
    ))
}

/// `PUT /Users/{id}`: replaces every attribute
async fn handle_replace_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
    body: Bytes,
) -> ScimResult<Response> {
    let id = parse_id(&id)?;
    let attrs = scim::user_attrs_from_json(&parse_body(&body)?)?;
    let rule = link_rule(&state, &ctx.provider).await;
    let user = store(&state)?
        .replace_scim_user(&ctx.provider, &rule, id, &attrs)
        .await?;
    Ok(scim_response(
        StatusCode::OK,
        &scim::user_resource(&ctx.base, &user),
    ))
}

/// `PATCH /Users/{id}`: add, replace and remove operations
async fn handle_patch_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
    body: Bytes,
) -> ScimResult<Response> {
    let id = parse_id(&id)?;
    let operations = scim::parse_patch(&parse_body(&body)?)?;
    let rule = link_rule(&state, &ctx.provider).await;
    let user = store(&state)?
        .patch_scim_user(&ctx.provider, &rule, id, |attrs| {
            scim::apply_user_patch(attrs, &operations)
        })
        .await?;
    Ok(scim_response(
        StatusCode::OK,
        &scim::user_resource(&ctx.base, &user),
    ))
}

/// `DELETE /Users/{id}`: 204; the linked login is disabled
async fn handle_delete_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
) -> ScimResult<Response> {
    if store(&state)?
        .delete_scim_user(&ctx.provider, parse_id(&id)?)
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(Failure(not_found()))
    }
}

/// `GET /Groups`: all of them, or those matching an `eq` filter
async fn handle_list_groups(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let found = parse_lookup(query.filter.as_deref(), &GROUP_FILTERS)?;
    let lookup = found.as_ref().map(|(key, value)| Lookup {
        key: *key,
        value: value.as_str(),
    });
    let (start_index, count) = scim::page(query.start_index.as_deref(), query.count.as_deref());
    let store = store(&state)?;
    let (groups, total) = store
        .list_scim_groups(&ctx.provider, lookup, start_index, count)
        .await?;
    let members = if query.wants_members() {
        let ids: Vec<Uuid> = groups.iter().map(|group| group.id).collect();
        Some(store.scim_group_members(&ids).await?)
    } else {
        None
    };
    let resources = groups
        .iter()
        .map(|group| scim::group_resource(&ctx.base, group, members.as_deref()))
        .collect::<Vec<_>>();
    Ok(scim_response(
        StatusCode::OK,
        &scim::list_response(&resources, total, start_index),
    ))
}

/// The group as a resource, with its members unless `with_members` is off
async fn group_body(
    store: &Store,
    ctx: &Ctx,
    group: &crate::store::scim::ScimGroup,
    with_members: bool,
) -> ScimResult<Value> {
    let members = if with_members {
        Some(store.scim_group_members(&[group.id]).await?)
    } else {
        None
    };
    Ok(scim::group_resource(&ctx.base, group, members.as_deref()))
}

/// `GET /Groups/{id}`; `excludedAttributes=members` leaves the members out
async fn handle_get_group(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
    Query(query): Query<ListQuery>,
) -> ScimResult<Response> {
    let store = store(&state)?;
    let group = store
        .get_scim_group(&ctx.provider, parse_id(&id)?)
        .await?
        .ok_or_else(|| Failure(not_found()))?;
    let body = group_body(store, &ctx, &group, query.wants_members()).await?;
    Ok(scim_response(StatusCode::OK, &body))
}

/// `POST /Groups`: 201, or 409 `uniqueness` for a `displayName` the provider has
async fn handle_create_group(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    body: Bytes,
) -> ScimResult<Response> {
    let attrs = scim::group_attrs_from_json(&parse_body(&body)?)?;
    let store = store(&state)?;
    let group = store
        .create_scim_group(
            &ctx.provider,
            &attrs.display_name,
            attrs.external_id.as_deref(),
            &attrs.members,
        )
        .await?;
    let body = group_body(store, &ctx, &group, true).await?;
    Ok(created(&ctx, "Groups", group.id, &body))
}

/// `PUT /Groups/{id}`: replaces the name, `externalId` and members
async fn handle_replace_group(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
    body: Bytes,
) -> ScimResult<Response> {
    let id = parse_id(&id)?;
    let attrs = scim::group_attrs_from_json(&parse_body(&body)?)?;
    let store = store(&state)?;
    let group = store
        .replace_scim_group(
            &ctx.provider,
            id,
            &attrs.display_name,
            attrs.external_id.as_deref(),
            &attrs.members,
        )
        .await?;
    let body = group_body(store, &ctx, &group, true).await?;
    Ok(scim_response(StatusCode::OK, &body))
}

/// `PATCH /Groups/{id}`: member add, remove and replace, name and `externalId`
async fn handle_patch_group(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
    body: Bytes,
) -> ScimResult<Response> {
    let id = parse_id(&id)?;
    let changes = scim::group_changes(&scim::parse_patch(&parse_body(&body)?)?)?;
    let store = store(&state)?;
    let group = store.patch_scim_group(&ctx.provider, id, &changes).await?;
    let body = group_body(store, &ctx, &group, true).await?;
    Ok(scim_response(StatusCode::OK, &body))
}

/// `DELETE /Groups/{id}`: 204; the members lose what the group gave them
async fn handle_delete_group(
    State(state): State<AppState>,
    Extension(ctx): Extension<Ctx>,
    Path((_, id)): Path<(String, String)>,
) -> ScimResult<Response> {
    if store(&state)?
        .delete_scim_group(&ctx.provider, parse_id(&id)?)
        .await?
    {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Err(Failure(not_found()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bearer_token_is_read_from_the_authorization_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer  abc "),
        );
        assert_eq!(bearer(&headers), Some("abc"));
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert_eq!(bearer(&headers), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn a_filter_may_only_name_the_attributes_of_the_resource() {
        let found = parse_lookup(Some(r#"userName eq "a""#), &USER_FILTERS).unwrap();
        assert_eq!(found, Some((LookupKey::Name, "a".to_owned())));
        assert!(parse_lookup(Some(r#"displayName eq "a""#), &USER_FILTERS).is_err());
        assert!(parse_lookup(Some(r#"userName eq "a""#), &GROUP_FILTERS).is_err());
        assert_eq!(parse_lookup(Some("  "), &USER_FILTERS).unwrap(), None);
        assert_eq!(parse_lookup(None, &USER_FILTERS).unwrap(), None);
    }

    #[test]
    fn members_are_left_out_when_excluded() {
        let query = |excluded: Option<&str>| ListQuery {
            excluded_attributes: excluded.map(str::to_owned),
            ..ListQuery::default()
        };
        assert!(query(None).wants_members());
        assert!(query(Some("meta")).wants_members());
        assert!(!query(Some("members")).wants_members());
        assert!(!query(Some("meta, Members")).wants_members());
    }

    #[test]
    fn an_error_response_is_scim_json_and_a_401_asks_for_a_bearer_token() {
        let response = Failure(ScimError::unauthorized("no")).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/scim+json"
        );
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Bearer"
        );
        let response = Failure(ScimError::uniqueness("taken")).into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(response.headers().get(header::WWW_AUTHENTICATE).is_none());
    }
}
