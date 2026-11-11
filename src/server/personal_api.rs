//! The personal-backend routes of the JSON API under `/api/v1`: a user's own
//! MCP servers, the catalog of backends everyone may bring a credential for,
//! those credentials, and the admin's view of everybody's personal servers.
//!
//! [`routes`] is merged into the router of `admin_api`, so these routes sit
//! behind the same multi-user check, session guard, same-site check and CSRF
//! token, and answer errors the same way; without the personal hub (no
//! database, or `[personal_backends] enabled = false`) they are a JSON 404.
//! Header values and credential values go in and are sealed; no response ever
//! carries one.
//!
//! The logic is in the plain `pub(super) async fn`s below, which take the
//! [`AppState`] and the [`SessionUser`]; the handlers only map HTTP to them,
//! so the dashboard pages can call the same functions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Extension, Json, Router};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use super::AppState;
use super::admin_api::{ApiError, ApiJson, ApiPath};
use crate::config::CredentialField;
use crate::gateway::GetConfig;
use crate::personal::{
    CatalogAuth, CatalogItem, CatalogSource, ConnectError, ConnectionStatus, PersonalHub,
};
use crate::policy::{Permission, Permissions};
use crate::rbac::{AdminError, resolve};
use crate::store::{
    AdminPersonalBackend, CatalogAuthMode, CatalogEntry, CatalogEntryUpdate, NewCatalogEntry,
    NewPersonalBackend, PersonalBackend, PersonalBackendUpdate, PersonalError, SealedColumns,
    SecretUpdate, SessionUser, Store, StoreError, UserCredential,
};

/// Headers rmcp sets itself, which a user must not override
const RESERVED_HEADERS: &[&str] = &[
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];
const MAX_URL_CHARS: usize = 2048;
const MAX_HEADERS: usize = 20;
const MAX_HEADER_VALUE_CHARS: usize = 4096;
const MAX_CREDENTIAL_FIELDS: usize = 10;
const MAX_FIELD_NAME_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_OAUTH_SCOPES: usize = 32;
const MAX_SCOPE_CHARS: usize = 128;
const MAX_CLIENT_ID_CHARS: usize = 512;
const MAX_CLIENT_SECRET_CHARS: usize = 4096;

/// The personal-backend routes, without guards: `admin_api::router` adds them.
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/me/backends",
            get(handle_list_personal).post(handle_create_personal),
        )
        .route(
            "/api/v1/me/backends/{prefix}",
            patch(handle_update_personal).delete(handle_delete_personal),
        )
        .route("/api/v1/me/connections", get(handle_list_connections))
        .route(
            "/api/v1/me/connections/{backend}",
            post(handle_connect).delete(handle_disconnect),
        )
        .route("/api/v1/me/credentials", get(handle_list_credentials))
        .route(
            "/api/v1/me/credentials/{entry}",
            put(handle_set_credential).delete(handle_delete_credential),
        )
        .route(
            "/api/v1/catalog",
            get(handle_list_catalog).post(handle_create_catalog),
        )
        .route(
            "/api/v1/catalog/{name}",
            patch(handle_update_catalog).delete(handle_delete_catalog),
        )
        .route(
            "/api/v1/admin/personal-backends",
            get(handle_list_all_personal),
        )
        .route(
            "/api/v1/admin/personal-backends/{owner_id}/{prefix}",
            patch(handle_set_personal_enabled).delete(handle_delete_personal_of),
        )
}

/// Why a personal-backend operation did not happen
#[derive(Debug, Error)]
pub(super) enum PersonalApiError {
    /// No personal hub: no database, or personal backends are switched off
    #[error("personal backends are disabled")]
    Disabled,

    /// The server could not do its part; the reason is for the log, not the caller
    #[error("{0}")]
    Internal(&'static str),

    #[error(transparent)]
    Admin(#[from] AdminError),

    #[error(transparent)]
    Connect(#[from] ConnectError),
}

impl From<StoreError> for PersonalApiError {
    fn from(error: StoreError) -> Self {
        Self::Admin(error.into())
    }
}

impl IntoResponse for PersonalApiError {
    fn into_response(self) -> Response {
        let message = self.to_string();
        match self {
            Self::Disabled => {
                (StatusCode::NOT_FOUND, Json(json!({ "error": message }))).into_response()
            }
            Self::Internal(message) => {
                tracing::warn!(message, "A personal backend request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "the request could not be completed" })),
                )
                    .into_response()
            }
            Self::Admin(error) => ApiError::from(error).into_response(),
            Self::Connect(error) => {
                let (status, message) = connect_failure(&error);
                (status, Json(json!({ "error": message }))).into_response()
            }
        }
    }
}

/// The status and the message a failed connection answers with: 404 for a
/// service that cannot be connected, 502 when the other side is at fault, 503
/// and 500 when the gateway's own storage is, 400 for the rest
pub(super) fn connect_failure(error: &ConnectError) -> (StatusCode, String) {
    match error {
        ConnectError::NotConnectable => (StatusCode::NOT_FOUND, error.to_string()),
        ConnectError::ClientUnusable | ConnectError::Upstream(_) => {
            (StatusCode::BAD_GATEWAY, error.to_string())
        }
        ConnectError::Store(source) => {
            tracing::warn!(error = %source, "A connection request failed in the database");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the database is unavailable".to_owned(),
            )
        }
        ConnectError::Seal(source) => {
            tracing::warn!(error = %source, "A connection's tokens could not be sealed");
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
        ConnectError::UnknownRequest
        | ConnectError::WrongUser
        | ConnectError::Callback(_)
        | ConnectError::Exchange(_) => (StatusCode::BAD_REQUEST, error.to_string()),
    }
}

pub(super) type Outcome<T> = Result<T, PersonalApiError>;

fn invalid(message: impl Into<String>) -> PersonalApiError {
    AdminError::Invalid(message.into()).into()
}

fn conflict(message: impl Into<String>) -> PersonalApiError {
    AdminError::Conflict(message.into()).into()
}

fn not_found() -> PersonalApiError {
    AdminError::NotFound.into()
}

fn exists(error: PersonalError, message: String) -> PersonalApiError {
    match error {
        PersonalError::Exists => conflict(message),
        PersonalError::Store(error) => error.into(),
    }
}

/// What the caller is and may do, and the pieces of state the operations use
struct Ctx<'a> {
    state: &'a AppState,
    hub: &'a PersonalHub,
    store: &'a Store,
    session: &'a SessionUser,
    groups: Vec<String>,
    permissions: Permissions,
}

impl<'a> Ctx<'a> {
    fn new(state: &'a AppState, session: &'a SessionUser) -> Outcome<Self> {
        let hub = state
            .personal
            .as_deref()
            .ok_or(PersonalApiError::Disabled)?;
        let (store, _) = state.multi_user().ok_or_else(not_found)?;
        let (groups, permissions) = resolve(&state.policy.current(), session);
        Ok(Self {
            state,
            hub,
            store,
            session,
            groups,
            permissions,
        })
    }

    fn user(&self) -> Uuid {
        self.session.user.id
    }

    fn require(&self, permission: Permission) -> Outcome<()> {
        if self.permissions.has(permission) {
            Ok(())
        } else {
            Err(AdminError::Forbidden.into())
        }
    }

    fn can_manage_catalog(&self) -> bool {
        self.permissions.has(Permission::CatalogManage)
    }

    /// Backends the caller's groups have a grant for
    fn granted_backends(&self) -> BTreeSet<String> {
        self.state
            .policy
            .current()
            .effective(&self.groups)
            .backends()
            .into_iter()
            .collect()
    }

    /// An enabled catalog entry the caller may use
    fn usable_item(&self, entry: &str) -> Outcome<CatalogItem> {
        let granted = self.granted_backends();
        self.hub
            .catalog()
            .into_iter()
            .find(|item| item.name == entry && item.enabled)
            .filter(|item| self.can_manage_catalog() || granted.contains(&item.name))
            .ok_or_else(not_found)
    }

    /// Conflict when the caller already has as many backends as allowed
    async fn ensure_room(&self) -> Outcome<()> {
        let max = self.hub.max_per_user();
        let count = self.store.count_user_backends(self.user()).await?;
        if count >= i64::from(max) {
            return Err(conflict(format!("personal backend limit reached ({max})")));
        }
        Ok(())
    }

    fn seal_headers(
        &self,
        id: Uuid,
        headers: &BTreeMap<String, String>,
    ) -> Outcome<Option<SealedColumns>> {
        if headers.is_empty() {
            return Ok(None);
        }
        self.hub
            .seal_personal_headers(id, headers)
            .map(Some)
            .map_err(|_| PersonalApiError::Internal("could not seal the headers"))
    }

    fn seal_oauth_secret(&self, name: &str, secret: &str) -> Outcome<SealedColumns> {
        self.hub
            .seal_catalog_oauth_secret(name, secret)
            .map_err(|_| PersonalApiError::Internal("could not seal the OAuth client secret"))
    }

    /// Probes the server and records how it went
    async fn test(
        &self,
        id: Uuid,
        url: &str,
        headers: &Result<BTreeMap<String, String>, String>,
    ) -> TestResult {
        let result = match headers {
            Ok(headers) => self.hub.probe(url, headers).await,
            Err(error) => Err(error.clone()),
        };
        if let Err(error) = self
            .store
            .record_personal_outcome(id, result.as_ref().err().map(String::as_str))
            .await
        {
            tracing::warn!(%id, %error, "could not record the outcome of a connection test");
        }
        result
    }

    /// Rebuilds the catalog from the running config and the database, then
    /// drops every user's slot so the change takes effect
    async fn reload_catalog(&self) {
        match self.state.gateway.ask(GetConfig).await {
            Ok(config) => {
                if let Err(error) = self.hub.reload_catalog(&config.0).await {
                    tracing::warn!(%error, "Failed to reload the per-user catalog after a change");
                }
            }
            Err(error) => {
                tracing::warn!(%error, "Could not read the running config to reload the per-user catalog");
            }
        }
        self.hub.invalidate_all().await;
    }

    /// A catalog entry an admin may change: not found, or defined in the config
    fn editable_item(&self, name: &str) -> Outcome<CatalogItem> {
        let item = self
            .hub
            .catalog()
            .into_iter()
            .find(|item| item.name == name)
            .ok_or_else(not_found)?;
        if item.source == CatalogSource::Config {
            return Err(conflict("defined in the config file"));
        }
        Ok(item)
    }
}

/// How a connection test went: the number of tools, or the reason it failed
pub(super) type TestResult = Result<usize, String>;

// -- validation ------------------------------------------------------------

/// A header name in canonical (lowercase) form, refusing what rmcp reserves
fn header_name(name: &str) -> Result<String, String> {
    let parsed = http::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| format!("{name:?} is not a valid HTTP header name"))?;
    if RESERVED_HEADERS.contains(&parsed.as_str()) {
        return Err(format!(
            "the header {:?} is set by the gateway",
            parsed.as_str()
        ));
    }
    Ok(parsed.as_str().to_owned())
}

fn header_value(header: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("the header {header:?} has an empty value"));
    }
    if value.chars().count() > MAX_HEADER_VALUE_CHARS {
        return Err(format!(
            "the value of the header {header:?} is longer than {MAX_HEADER_VALUE_CHARS} characters"
        ));
    }
    http::HeaderValue::from_str(value)
        .map(|_| ())
        .map_err(|_| format!("the value of the header {header:?} is not valid in a header"))
}

/// The headers of a personal backend with canonical names
fn clean_headers(headers: BTreeMap<String, String>) -> Result<BTreeMap<String, String>, String> {
    if headers.len() > MAX_HEADERS {
        return Err(format!("at most {MAX_HEADERS} headers are allowed"));
    }
    let mut cleaned = BTreeMap::new();
    for (name, value) in headers {
        let name = header_name(&name)?;
        header_value(&name, &value)?;
        if cleaned.insert(name.clone(), value).is_some() {
            return Err(format!("the header {name:?} is listed twice"));
        }
    }
    Ok(cleaned)
}

/// An `http` or `https` URL
fn clean_url(raw: &str) -> Result<String, String> {
    let url = raw.trim();
    if url.chars().count() > MAX_URL_CHARS {
        return Err(format!("the url is longer than {MAX_URL_CHARS} characters"));
    }
    let parsed = Url::parse(url).map_err(|error| format!("invalid url: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("the url must be an http or https url".to_owned());
    }
    Ok(url.to_owned())
}

/// Trimmed; blank means none
fn clean_description(description: &str) -> Result<Option<String>, String> {
    let description = description.trim();
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(format!(
            "description must be at most {MAX_DESCRIPTION_CHARS} characters"
        ));
    }
    Ok((!description.is_empty()).then(|| description.to_owned()))
}

/// The credential fields of a catalog entry: at least one, unique names,
/// header names that are valid and not reserved
fn clean_fields(fields: Vec<CredentialField>) -> Result<Vec<CredentialField>, String> {
    if fields.is_empty() {
        return Err("at least one credential field is needed".to_owned());
    }
    if fields.len() > MAX_CREDENTIAL_FIELDS {
        return Err(format!(
            "at most {MAX_CREDENTIAL_FIELDS} credential fields are allowed"
        ));
    }
    let mut seen = BTreeSet::new();
    let mut cleaned = Vec::with_capacity(fields.len());
    for field in fields {
        let name = field.name.trim().to_owned();
        if name.is_empty() || name.chars().count() > MAX_FIELD_NAME_CHARS {
            return Err(format!(
                "a credential field name must be 1 to {MAX_FIELD_NAME_CHARS} characters"
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(format!("the credential field {name:?} is listed twice"));
        }
        header_name(&field.header)?;
        let prefix = field.prefix.filter(|prefix| !prefix.is_empty());
        if let Some(prefix) = &prefix {
            http::HeaderValue::from_str(prefix).map_err(|_| {
                format!("the prefix of the field {name:?} is not valid in a header")
            })?;
        }
        let label = field
            .label
            .map(|label| label.trim().to_owned())
            .filter(|label| !label.is_empty());
        cleaned.push(CredentialField {
            name,
            label,
            header: field.header,
            prefix,
        });
    }
    Ok(cleaned)
}

/// The values a user entered for a catalog entry: only known fields, at least
/// one filled, each fitting its header
fn clean_values(
    fields: &[CredentialField],
    values: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut cleaned = BTreeMap::new();
    for (name, value) in values {
        let Some(field) = fields.iter().find(|field| field.name == name) else {
            return Err(format!("unknown credential field {name:?}"));
        };
        if value.is_empty() {
            continue;
        }
        let prefix = field.prefix.as_deref().unwrap_or_default();
        header_value(&field.header, &format!("{prefix}{value}"))?;
        cleaned.insert(name, value);
    }
    if cleaned.is_empty() {
        return Err("at least one value is needed".to_owned());
    }
    Ok(cleaned)
}

/// How an entry authenticates, as the `auth` field spells it; absent means fields
fn parse_auth(raw: Option<&str>) -> Result<CatalogAuthMode, String> {
    match raw.map(str::trim) {
        None | Some("" | "fields") => Ok(CatalogAuthMode::Fields),
        Some("oauth") => Ok(CatalogAuthMode::OAuth),
        Some(other) => Err(format!(
            "auth must be \"fields\" or \"oauth\", not {other:?}"
        )),
    }
}

/// Scopes written in a form: separated by spaces, commas or both
pub(super) fn split_scopes(raw: &str) -> Vec<String> {
    raw.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The OAuth scopes of an entry: each a valid scope token (RFC 6749, 3.3),
/// listed once, in order
fn clean_scopes(scopes: &[String]) -> Result<Vec<String>, String> {
    let mut cleaned: Vec<String> = Vec::new();
    for scope in scopes.iter().flat_map(|scope| split_scopes(scope)) {
        let valid = scope.chars().count() <= MAX_SCOPE_CHARS
            && scope
                .chars()
                .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\');
        if !valid {
            return Err(format!("{scope:?} is not a valid OAuth scope"));
        }
        if !cleaned.contains(&scope) {
            cleaned.push(scope);
        }
    }
    if cleaned.len() > MAX_OAUTH_SCOPES {
        return Err(format!(
            "at most {MAX_OAUTH_SCOPES} OAuth scopes are allowed"
        ));
    }
    Ok(cleaned)
}

/// The static OAuth client's id, trimmed; blank means none
fn clean_client_id(raw: &str) -> Result<Option<String>, String> {
    let id = raw.trim();
    if id.chars().count() > MAX_CLIENT_ID_CHARS || id.chars().any(char::is_control) {
        return Err(format!(
            "the OAuth client id must be at most {MAX_CLIENT_ID_CHARS} characters, without control characters"
        ));
    }
    Ok((!id.is_empty()).then(|| id.to_owned()))
}

/// A static OAuth client secret worth sealing
fn check_client_secret(secret: &str) -> Result<(), String> {
    if secret.chars().count() > MAX_CLIENT_SECRET_CHARS || secret.chars().any(char::is_control) {
        return Err(format!(
            "the OAuth client secret must be at most {MAX_CLIENT_SECRET_CHARS} characters, without control characters"
        ));
    }
    Ok(())
}

/// Where a connection sends the browser back to: a local path, else nothing.
/// The same rule as the login's `return_to`.
pub(super) fn clean_return_to(raw: Option<&str>) -> Option<String> {
    let raw = raw?;
    let safe = super::session::safe_return_to(Some(raw));
    (safe == raw).then_some(safe)
}

// -- the caller's own personal backends --------------------------------------

/// The body of `POST /api/v1/me/backends`
/// No `Debug`: it carries secret values
#[derive(Deserialize)]
pub(super) struct NewPersonal {
    pub prefix: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// The body of `PATCH /api/v1/me/backends/{prefix}`; `headers` replaces all
/// No `Debug`: it carries secret values
#[derive(Default, Deserialize)]
pub(super) struct PersonalPatch {
    pub url: Option<String>,
    pub enabled: Option<bool>,
    pub headers: Option<BTreeMap<String, String>>,
}

/// A saved personal backend and, when it was tested, how that went
pub(super) struct PersonalSaved {
    pub backend: PersonalBackend,
    pub test: Option<TestResult>,
}

/// The caller's personal backends, by prefix
pub(super) async fn list_personal(
    state: &AppState,
    session: &SessionUser,
) -> Outcome<Vec<PersonalBackend>> {
    let ctx = Ctx::new(state, session)?;
    Ok(ctx.store.list_personal_backends(ctx.user()).await?)
}

/// Adds a personal backend for the caller and tests the server. The backend is
/// saved whatever the test finds.
pub(super) async fn create_personal(
    state: &AppState,
    session: &SessionUser,
    input: NewPersonal,
) -> Outcome<PersonalSaved> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::PersonalBackendsCreate)?;
    ctx.hub.validate_prefix(&input.prefix).map_err(invalid)?;
    let url = clean_url(&input.url).map_err(invalid)?;
    let headers = clean_headers(input.headers).map_err(invalid)?;
    ctx.hub.check_egress(&url).await.map_err(invalid)?;
    ctx.ensure_room().await?;

    let id = Uuid::new_v4();
    let secret = ctx.seal_headers(id, &headers)?;
    let new = NewPersonalBackend {
        id,
        owner_id: ctx.user(),
        prefix: input.prefix,
        url,
        header_names: headers.keys().cloned().collect(),
        secret,
    };
    let backend = ctx
        .store
        .create_personal_backend(&new)
        .await
        .map_err(|error| {
            exists(
                error,
                format!("you already have a backend {:?}", new.prefix),
            )
        })?;
    tracing::info!(user = %ctx.user(), prefix = %backend.prefix, "Personal backend created");

    let test = ctx.test(backend.id, &backend.url, &Ok(headers)).await;
    ctx.hub.invalidate(ctx.user()).await;
    Ok(PersonalSaved {
        backend: refreshed(&ctx, backend).await,
        test: Some(test),
    })
}

/// Changes a personal backend of the caller; the server is tested again when
/// the url or the headers changed
pub(super) async fn update_personal(
    state: &AppState,
    session: &SessionUser,
    prefix: &str,
    patch: PersonalPatch,
) -> Outcome<PersonalSaved> {
    let ctx = Ctx::new(state, session)?;
    let user = ctx.user();
    let current = ctx
        .store
        .personal_backend(user, prefix)
        .await?
        .ok_or_else(not_found)?;
    if patch.url.is_none() && patch.enabled.is_none() && patch.headers.is_none() {
        return Err(invalid("nothing to change"));
    }

    let url = patch
        .url
        .as_deref()
        .map(clean_url)
        .transpose()
        .map_err(invalid)?;
    let headers = patch
        .headers
        .map(clean_headers)
        .transpose()
        .map_err(invalid)?;
    if let Some(url) = &url {
        ctx.hub.check_egress(url).await.map_err(invalid)?;
    }
    let sealed_headers = match &headers {
        Some(headers) => Some((
            headers.keys().cloned().collect(),
            ctx.seal_headers(current.id, headers)?,
        )),
        None => None,
    };

    let update = PersonalBackendUpdate {
        url: url.clone(),
        enabled: patch.enabled,
        headers: sealed_headers,
    };
    let backend = ctx
        .store
        .update_personal_backend(user, prefix, &update)
        .await?
        .ok_or_else(not_found)?;

    let test = if url.is_some() || headers.is_some() {
        let headers = match headers {
            Some(headers) => Ok(headers),
            None => ctx.hub.open_personal_headers(&current),
        };
        Some(ctx.test(backend.id, &backend.url, &headers).await)
    } else {
        None
    };
    ctx.hub.invalidate(user).await;
    Ok(PersonalSaved {
        backend: refreshed(&ctx, backend).await,
        test,
    })
}

/// The backend as stored after a test wrote its outcome; the one at hand when
/// it cannot be read again
async fn refreshed(ctx: &Ctx<'_>, backend: PersonalBackend) -> PersonalBackend {
    match ctx
        .store
        .personal_backend(backend.owner_id, &backend.prefix)
        .await
    {
        Ok(Some(stored)) => stored,
        _ => backend,
    }
}

/// Removes a personal backend of the caller
pub(super) async fn delete_personal(
    state: &AppState,
    session: &SessionUser,
    prefix: &str,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    if !ctx
        .store
        .delete_personal_backend(ctx.user(), prefix)
        .await?
    {
        return Err(not_found());
    }
    tracing::info!(user = %ctx.user(), %prefix, "Personal backend deleted");
    ctx.hub.invalidate(ctx.user()).await;
    Ok(())
}

// -- the catalog and the caller's credentials ----------------------------------

/// A catalog entry as one caller sees it
pub(super) struct CatalogView {
    pub item: CatalogItem,
    /// The caller's stored credential for it, if any
    pub credential: Option<UserCredential>,
    /// The caller's OAuth connection to it, if any
    pub connection: Option<ConnectionStatus>,
    /// Whether the caller manages the catalog, who also sees the url
    pub manage: bool,
}

/// The body of `PUT /api/v1/me/credentials/{entry}`
/// No `Debug`: it carries secret values
#[derive(Deserialize)]
pub(super) struct CredentialValues {
    pub values: BTreeMap<String, String>,
}

/// The body of `POST /api/v1/catalog`; `credential_fields` is for `auth` =
/// `"fields"` (the default) and the `oauth_*` fields for `"oauth"`
/// No `Debug`: it carries a secret value
#[derive(Deserialize)]
pub(super) struct NewCatalogItem {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    #[serde(default)]
    pub credential_fields: Vec<CredentialField>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_scopes: Vec<String>,
    /// Write-only
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
}

/// The body of `PATCH /api/v1/catalog/{name}`; a blank description clears it.
/// A blank `oauth_client_id` clears the static client, an empty `oauth_scopes`
/// the scopes; `oauth_client_secret` absent or `null` keeps the stored secret
/// and `""` clears it.
/// No `Debug`: it carries a secret value
#[derive(Default, Deserialize)]
pub(super) struct CatalogPatch {
    pub description: Option<String>,
    pub url: Option<String>,
    pub credential_fields: Option<Vec<CredentialField>>,
    pub enabled: Option<bool>,
    pub auth: Option<String>,
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Option<Vec<String>>,
    pub oauth_client_secret: Option<String>,
}

/// The catalog entries the caller may use, with their credential state: those
/// the caller's groups have a grant for, or all for a catalog manager
pub(super) async fn list_catalog(
    state: &AppState,
    session: &SessionUser,
) -> Outcome<Vec<CatalogView>> {
    let ctx = Ctx::new(state, session)?;
    let manage = ctx.can_manage_catalog();
    let granted = ctx.granted_backends();
    let mut credentials: HashMap<String, UserCredential> = ctx
        .store
        .list_user_credentials(ctx.user())
        .await?
        .into_iter()
        .map(|credential| (credential.backend.clone(), credential))
        .collect();
    let mut connections: HashMap<String, ConnectionStatus> = ctx
        .hub
        .connections(ctx.user())
        .await?
        .into_iter()
        .map(|connection| (connection.backend.clone(), connection))
        .collect();
    Ok(ctx
        .hub
        .catalog()
        .into_iter()
        .filter(|item| manage || granted.contains(&item.name))
        .map(|item| CatalogView {
            credential: credentials.remove(&item.name),
            connection: connections.remove(&item.name),
            item,
            manage,
        })
        .collect())
}

/// The caller's stored credentials, by backend
pub(super) async fn list_credentials(
    state: &AppState,
    session: &SessionUser,
) -> Outcome<Vec<UserCredential>> {
    let ctx = Ctx::new(state, session)?;
    Ok(ctx.store.list_user_credentials(ctx.user()).await?)
}

/// Stores the caller's credential for a catalog entry, replacing an earlier one
pub(super) async fn set_credential(
    state: &AppState,
    session: &SessionUser,
    entry: &str,
    values: BTreeMap<String, String>,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    let item = ctx.usable_item(entry)?;
    let values = clean_values(&item.credential_fields, values).map_err(invalid)?;

    let user = ctx.user();
    let known = ctx
        .store
        .list_user_credentials(user)
        .await?
        .iter()
        .any(|credential| credential.backend == entry);
    if !known {
        ctx.ensure_room().await?;
    }
    let sealed = ctx
        .hub
        .seal_credential(user, entry, &values)
        .map_err(|_| PersonalApiError::Internal("could not seal the credential"))?;
    ctx.store.set_user_credential(user, entry, &sealed).await?;
    ctx.hub.invalidate(user).await;
    Ok(())
}

/// Deletes the caller's credential for a catalog entry
pub(super) async fn delete_credential(
    state: &AppState,
    session: &SessionUser,
    entry: &str,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    if !ctx.store.delete_user_credential(ctx.user(), entry).await? {
        return Err(not_found());
    }
    ctx.hub.invalidate(ctx.user()).await;
    Ok(())
}

/// The caller's OAuth connections, by backend
pub(super) async fn list_connections(
    state: &AppState,
    session: &SessionUser,
) -> Outcome<Vec<ConnectionStatus>> {
    let ctx = Ctx::new(state, session)?;
    Ok(ctx.hub.connections(ctx.user()).await?)
}

/// Starts connecting the caller to the OAuth catalog entry `entry`; returns
/// the URL to send the browser to. The entry must be one the caller may use.
pub(super) async fn begin_connection(
    state: &AppState,
    session: &SessionUser,
    entry: &str,
    return_to: Option<String>,
) -> Outcome<String> {
    let ctx = Ctx::new(state, session)?;
    ctx.usable_item(entry)?;
    let url = ctx
        .hub
        .begin_connect(ctx.user(), entry, super::oauth::base(state), return_to)
        .await?;
    tracing::info!(user = %ctx.user(), %entry, "OAuth connection started");
    Ok(url)
}

/// Finishes the connection the callback's `state` started; returns the entry
/// and where to send the browser
pub(super) async fn finish_connection(
    state: &AppState,
    session: &SessionUser,
    request_state: &str,
    code: &str,
    iss: Option<&str>,
) -> Outcome<(String, Option<String>)> {
    let ctx = Ctx::new(state, session)?;
    let (entry, return_to) = ctx
        .hub
        .finish_connect(ctx.user(), request_state, code, iss)
        .await?;
    tracing::info!(user = %ctx.user(), %entry, "OAuth connection made");
    Ok((entry, return_to))
}

/// Removes the caller's OAuth connection to `entry`
pub(super) async fn delete_connection(
    state: &AppState,
    session: &SessionUser,
    entry: &str,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    if !ctx.hub.disconnect(ctx.user(), entry).await? {
        return Err(not_found());
    }
    tracing::info!(user = %ctx.user(), %entry, "OAuth connection removed");
    Ok(())
}

/// Adds a catalog entry. Needs `catalog.manage`.
pub(super) async fn create_catalog_entry(
    state: &AppState,
    session: &SessionUser,
    input: NewCatalogItem,
) -> Outcome<CatalogEntry> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::CatalogManage)?;
    let taken = ctx.hub.shared_names().contains(&input.name)
        || ctx.hub.catalog().iter().any(|item| item.name == input.name);
    if taken {
        return Err(conflict(format!(
            "a backend named {:?} already exists",
            input.name
        )));
    }
    ctx.hub.validate_prefix(&input.name).map_err(invalid)?;
    let description = match &input.description {
        Some(description) => clean_description(description).map_err(invalid)?,
        None => None,
    };
    let url = clean_url(&input.url).map_err(invalid)?;
    let auth = parse_auth(input.auth.as_deref()).map_err(invalid)?;
    let oauth_client_id = input
        .oauth_client_id
        .as_deref()
        .map(clean_client_id)
        .transpose()
        .map_err(invalid)?
        .flatten();
    let oauth_scopes = clean_scopes(&input.oauth_scopes).map_err(invalid)?;
    let secret = input
        .oauth_client_secret
        .filter(|secret| !secret.is_empty());
    let credential_fields = match auth {
        CatalogAuthMode::Fields => {
            if oauth_client_id.is_some() || !oauth_scopes.is_empty() || secret.is_some() {
                return Err(invalid("the OAuth settings need auth \"oauth\""));
            }
            clean_fields(input.credential_fields).map_err(invalid)?
        }
        CatalogAuthMode::OAuth => {
            if !input.credential_fields.is_empty() {
                return Err(invalid("an OAuth entry takes no credential fields"));
            }
            if secret.is_some() && oauth_client_id.is_none() {
                return Err(invalid("an OAuth client secret needs an OAuth client id"));
            }
            Vec::new()
        }
    };
    let oauth_secret = match &secret {
        Some(secret) => {
            check_client_secret(secret).map_err(invalid)?;
            Some(ctx.seal_oauth_secret(&input.name, secret)?)
        }
        None => None,
    };

    let new = NewCatalogEntry {
        name: input.name,
        description,
        url,
        credential_fields,
        created_by: Some(actor_label(session)),
        auth,
        oauth_client_id,
        oauth_scopes,
        oauth_secret,
    };
    let entry = ctx
        .store
        .create_catalog_entry(&new)
        .await
        .map_err(|error| {
            exists(
                error,
                format!("a backend named {:?} already exists", new.name),
            )
        })?;
    tracing::info!(user = %ctx.user(), name = %entry.name, "Catalog entry created");
    ctx.reload_catalog().await;
    Ok(entry)
}

/// Changes a catalog entry of the database. Needs `catalog.manage`.
pub(super) async fn update_catalog_entry(
    state: &AppState,
    session: &SessionUser,
    name: &str,
    patch: CatalogPatch,
) -> Outcome<CatalogEntry> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::CatalogManage)?;
    let item = ctx.editable_item(name)?;
    if patch.description.is_none()
        && patch.url.is_none()
        && patch.credential_fields.is_none()
        && patch.enabled.is_none()
        && patch.auth.is_none()
        && patch.oauth_client_id.is_none()
        && patch.oauth_scopes.is_none()
        && patch.oauth_client_secret.is_none()
    {
        return Err(invalid("nothing to change"));
    }
    let current = match item.auth {
        CatalogAuth::OAuth { .. } => CatalogAuthMode::OAuth,
        CatalogAuth::Fields | CatalogAuth::Passthrough(_) => CatalogAuthMode::Fields,
    };
    let auth = match patch.auth.as_deref() {
        Some(raw) => parse_auth(Some(raw)).map_err(invalid)?,
        None => current,
    };
    let oauth_client_id = patch
        .oauth_client_id
        .as_deref()
        .map(clean_client_id)
        .transpose()
        .map_err(invalid)?;
    let oauth_scopes = patch
        .oauth_scopes
        .as_deref()
        .map(clean_scopes)
        .transpose()
        .map_err(invalid)?;
    let oauth_secret = match patch.oauth_client_secret.as_deref() {
        None => SecretUpdate::Keep,
        Some("") => SecretUpdate::Clear,
        Some(secret) => {
            check_client_secret(secret).map_err(invalid)?;
            SecretUpdate::Set(ctx.seal_oauth_secret(name, secret)?)
        }
    };
    // The credential fields follow the mode: none for OAuth, at least one for
    // fields (so switching back needs them in the same request)
    let credential_fields = match (auth, patch.credential_fields) {
        (CatalogAuthMode::Fields, Some(fields)) => Some(clean_fields(fields).map_err(invalid)?),
        (CatalogAuthMode::Fields, None) if current != auth => {
            Some(clean_fields(Vec::new()).map_err(invalid)?)
        }
        (CatalogAuthMode::Fields, None) => None,
        (CatalogAuthMode::OAuth, Some(fields)) if !fields.is_empty() => {
            return Err(invalid("an OAuth entry takes no credential fields"));
        }
        (CatalogAuthMode::OAuth, _) => (current != auth).then(Vec::new),
    };
    if auth == CatalogAuthMode::Fields
        && (oauth_client_id.as_ref().is_some_and(Option::is_some)
            || oauth_scopes
                .as_ref()
                .is_some_and(|scopes| !scopes.is_empty())
            || matches!(oauth_secret, SecretUpdate::Set(_)))
    {
        return Err(invalid("the OAuth settings need auth \"oauth\""));
    }

    let description = match &patch.description {
        // Blank clears it, which the store does for an empty string
        Some(description) => Some(
            clean_description(description)
                .map_err(invalid)?
                .unwrap_or_default(),
        ),
        None => None,
    };
    let update = CatalogEntryUpdate {
        description,
        url: patch
            .url
            .as_deref()
            .map(clean_url)
            .transpose()
            .map_err(invalid)?,
        credential_fields,
        enabled: patch.enabled,
        auth: (auth != current).then_some(auth),
        oauth_client_id: oauth_client_id.map(Option::unwrap_or_default),
        oauth_scopes,
        oauth_secret,
    };
    let entry = ctx
        .store
        .update_catalog_entry(name, &update)
        .await?
        .ok_or_else(not_found)?;
    ctx.reload_catalog().await;
    Ok(entry)
}

/// Deletes a catalog entry of the database with every user's credentials for
/// it. Needs `catalog.manage`.
pub(super) async fn delete_catalog_entry(
    state: &AppState,
    session: &SessionUser,
    name: &str,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::CatalogManage)?;
    ctx.editable_item(name)?;
    if !ctx.store.delete_catalog_entry(name).await? {
        return Err(not_found());
    }
    tracing::info!(user = %ctx.user(), %name, "Catalog entry deleted");
    ctx.reload_catalog().await;
    Ok(())
}

/// Email, else display name, else subject: how the catalog names its creator
fn actor_label(session: &SessionUser) -> String {
    let user = &session.user;
    [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
        .to_owned()
}

// -- admin oversight --------------------------------------------------------

/// Every user's personal backends with their owners. Needs `users.manage`.
pub(super) async fn list_all_personal(
    state: &AppState,
    session: &SessionUser,
) -> Outcome<Vec<AdminPersonalBackend>> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::UsersManage)?;
    Ok(ctx.store.list_all_personal_backends().await?)
}

/// Switches a user's personal backend on or off. Needs `users.manage`.
pub(super) async fn set_personal_enabled(
    state: &AppState,
    session: &SessionUser,
    owner: Uuid,
    prefix: &str,
    enabled: bool,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::UsersManage)?;
    let update = PersonalBackendUpdate {
        enabled: Some(enabled),
        ..PersonalBackendUpdate::default()
    };
    ctx.store
        .update_personal_backend(owner, prefix, &update)
        .await?
        .ok_or_else(not_found)?;
    tracing::info!(admin = %ctx.user(), %owner, %prefix, enabled, "Personal backend switched by an admin");
    ctx.hub.invalidate(owner).await;
    Ok(())
}

/// Removes a user's personal backend. Needs `users.manage`.
pub(super) async fn delete_personal_of(
    state: &AppState,
    session: &SessionUser,
    owner: Uuid,
    prefix: &str,
) -> Outcome<()> {
    let ctx = Ctx::new(state, session)?;
    ctx.require(Permission::UsersManage)?;
    if !ctx.store.delete_personal_backend(owner, prefix).await? {
        return Err(not_found());
    }
    tracing::info!(admin = %ctx.user(), %owner, %prefix, "Personal backend deleted by an admin");
    ctx.hub.invalidate(owner).await;
    Ok(())
}

// -- JSON ------------------------------------------------------------------

fn at(time: chrono::DateTime<chrono::Utc>) -> String {
    time.to_rfc3339()
}

/// A personal backend with its header values left out
pub(super) fn personal_json(backend: &PersonalBackend) -> Value {
    json!({
        "id": backend.id,
        "prefix": backend.prefix,
        "url": backend.url,
        "header_names": backend.header_names,
        "enabled": backend.enabled,
        "created_at": at(backend.created_at),
        "updated_at": at(backend.updated_at),
        "last_ok_at": backend.last_ok_at.map(at),
        "last_error_at": backend.last_error_at.map(at),
        "last_error": backend.last_error,
    })
}

/// How a connection test went; `null` when there was none
pub(super) fn test_json(test: Option<&TestResult>) -> Value {
    match test {
        None => Value::Null,
        Some(Ok(tools)) => json!({ "ok": true, "tools": tools }),
        Some(Err(error)) => json!({ "ok": false, "error": error }),
    }
}

pub(super) fn saved_json(saved: &PersonalSaved) -> Value {
    let mut value = personal_json(&saved.backend);
    if let Some(object) = value.as_object_mut() {
        object.insert("test".to_owned(), test_json(saved.test.as_ref()));
    }
    value
}

fn fields_json(fields: &[CredentialField]) -> Vec<Value> {
    fields
        .iter()
        .map(|field| {
            json!({
                "name": field.name,
                "label": field.label.as_deref().unwrap_or(&field.name),
                "header": field.header,
                "prefix": field.prefix,
            })
        })
        .collect()
}

/// A stored credential's state, never its values
fn credential_state_json(credential: Option<&UserCredential>) -> Value {
    match credential {
        Some(credential) => json!({
            "set": true,
            "updated_at": at(credential.updated_at),
            "last_ok_at": credential.last_ok_at.map(at),
            "last_error_at": credential.last_error_at.map(at),
            "last_error": credential.last_error,
        }),
        None => json!({
            "set": false,
            "updated_at": null,
            "last_ok_at": null,
            "last_error_at": null,
            "last_error": null,
        }),
    }
}

/// How an entry authenticates, as the API spells it
pub(super) fn auth_kind(auth: &CatalogAuth) -> &'static str {
    match auth {
        CatalogAuth::Fields => "fields",
        CatalogAuth::OAuth { .. } => "oauth",
        CatalogAuth::Passthrough(_) => "passthrough",
    }
}

/// An OAuth connection's state, never its tokens
pub(super) fn connection_json(connection: &ConnectionStatus) -> Value {
    json!({
        "backend": connection.backend,
        "issuer": connection.issuer,
        "expires_at": at(connection.expires_at),
        "last_error": connection.last_error,
        "last_error_at": connection.last_error_at.map(at),
        "created_at": at(connection.created_at),
    })
}

pub(super) fn catalog_view_json(view: &CatalogView) -> Value {
    let item = &view.item;
    let source = match item.source {
        CatalogSource::Config => "config",
        CatalogSource::Database => "database",
    };
    json!({
        "name": item.name,
        "description": item.description,
        "url": view.manage.then_some(&item.url),
        "credential_fields": fields_json(&item.credential_fields),
        "auth": auth_kind(&item.auth),
        "enabled": item.enabled,
        "source": source,
        "credential": credential_state_json(view.credential.as_ref()),
    })
}

/// A catalog entry of the database, as the admin sees it
pub(super) fn catalog_entry_json(entry: &CatalogEntry) -> Value {
    json!({
        "name": entry.name,
        "description": entry.description,
        "url": entry.url,
        "credential_fields": fields_json(&entry.credential_fields),
        "auth": entry.auth.as_str(),
        "oauth_client_id": entry.oauth_client_id,
        "oauth_scopes": entry.oauth_scopes,
        "oauth_client_secret_set": entry.oauth_secret.is_some(),
        "enabled": entry.enabled,
        "source": "database",
        "created_by": entry.created_by,
        "created_at": at(entry.created_at),
        "updated_at": at(entry.updated_at),
    })
}

pub(super) fn credential_json(credential: &UserCredential) -> Value {
    json!({
        "backend": credential.backend,
        "created_at": at(credential.created_at),
        "updated_at": at(credential.updated_at),
        "last_ok_at": credential.last_ok_at.map(at),
        "last_error_at": credential.last_error_at.map(at),
        "last_error": credential.last_error,
    })
}

pub(super) fn admin_personal_json(backend: &AdminPersonalBackend) -> Value {
    json!({
        "id": backend.id,
        "owner": {
            "id": backend.owner_id,
            "email": backend.owner_email,
            "display_name": backend.owner_name,
            "subject": backend.owner_subject,
        },
        "prefix": backend.prefix,
        "url": backend.url,
        "header_names": backend.header_names,
        "enabled": backend.enabled,
        "created_at": at(backend.created_at),
        "updated_at": at(backend.updated_at),
        "last_ok_at": backend.last_ok_at.map(at),
        "last_error_at": backend.last_error_at.map(at),
        "last_error": backend.last_error,
    })
}

// -- handlers --------------------------------------------------------------

/// `GET /api/v1/me/backends`
async fn handle_list_personal(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Outcome<Json<Value>> {
    let backends = list_personal(&state, &session).await?;
    let backends: Vec<Value> = backends.iter().map(personal_json).collect();
    Ok(Json(json!({ "backends": backends })))
}

/// `POST /api/v1/me/backends`
async fn handle_create_personal(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<NewPersonal>,
) -> Outcome<(StatusCode, Json<Value>)> {
    let saved = create_personal(&state, &session, body).await?;
    Ok((StatusCode::CREATED, Json(saved_json(&saved))))
}

/// `PATCH /api/v1/me/backends/{prefix}`
async fn handle_update_personal(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(prefix): ApiPath<String>,
    ApiJson(body): ApiJson<PersonalPatch>,
) -> Outcome<Json<Value>> {
    let saved = update_personal(&state, &session, &prefix, body).await?;
    Ok(Json(saved_json(&saved)))
}

/// `DELETE /api/v1/me/backends/{prefix}`
async fn handle_delete_personal(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(prefix): ApiPath<String>,
) -> Outcome<StatusCode> {
    delete_personal(&state, &session, &prefix).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/me/connections`
async fn handle_list_connections(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Outcome<Json<Value>> {
    let connections = list_connections(&state, &session).await?;
    let connections: Vec<Value> = connections.iter().map(connection_json).collect();
    Ok(Json(json!({ "connections": connections })))
}

/// The optional body of `POST /api/v1/me/connections/{backend}`
#[derive(Debug, Default, Deserialize)]
struct ConnectBody {
    return_to: Option<String>,
}

/// `POST /api/v1/me/connections/{backend}`: where to send the browser to
/// connect. The body may be left out; a `return_to` that is not a local path
/// is ignored.
async fn handle_connect(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(backend): ApiPath<String>,
    body: Bytes,
) -> Outcome<Json<Value>> {
    let body: ConnectBody = if body.iter().all(u8::is_ascii_whitespace) {
        ConnectBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|error| invalid(format!("invalid body: {error}")))?
    };
    let return_to = clean_return_to(body.return_to.as_deref());
    let url = begin_connection(&state, &session, &backend, return_to).await?;
    Ok(Json(json!({ "authorize_url": url })))
}

/// `DELETE /api/v1/me/connections/{backend}`
async fn handle_disconnect(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(backend): ApiPath<String>,
) -> Outcome<StatusCode> {
    delete_connection(&state, &session, &backend).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/me/credentials`
async fn handle_list_credentials(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Outcome<Json<Value>> {
    let credentials = list_credentials(&state, &session).await?;
    let credentials: Vec<Value> = credentials.iter().map(credential_json).collect();
    Ok(Json(json!({ "credentials": credentials })))
}

/// `PUT /api/v1/me/credentials/{entry}`
async fn handle_set_credential(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(entry): ApiPath<String>,
    ApiJson(body): ApiJson<CredentialValues>,
) -> Outcome<StatusCode> {
    set_credential(&state, &session, &entry, body.values).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/me/credentials/{entry}`
async fn handle_delete_credential(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(entry): ApiPath<String>,
) -> Outcome<StatusCode> {
    delete_credential(&state, &session, &entry).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/catalog`
async fn handle_list_catalog(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Outcome<Json<Value>> {
    let views = list_catalog(&state, &session).await?;
    let items: Vec<Value> = views.iter().map(catalog_view_json).collect();
    Ok(Json(json!({ "catalog": items })))
}

/// `POST /api/v1/catalog`
async fn handle_create_catalog(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<NewCatalogItem>,
) -> Outcome<(StatusCode, Json<Value>)> {
    let entry = create_catalog_entry(&state, &session, body).await?;
    Ok((StatusCode::CREATED, Json(catalog_entry_json(&entry))))
}

/// `PATCH /api/v1/catalog/{name}`
async fn handle_update_catalog(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<CatalogPatch>,
) -> Outcome<Json<Value>> {
    let entry = update_catalog_entry(&state, &session, &name, body).await?;
    Ok(Json(catalog_entry_json(&entry)))
}

/// `DELETE /api/v1/catalog/{name}`
async fn handle_delete_catalog(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> Outcome<StatusCode> {
    delete_catalog_entry(&state, &session, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/admin/personal-backends`
async fn handle_list_all_personal(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Outcome<Json<Value>> {
    let backends = list_all_personal(&state, &session).await?;
    let backends: Vec<Value> = backends.iter().map(admin_personal_json).collect();
    Ok(Json(json!({ "backends": backends })))
}

/// `PATCH /api/v1/admin/personal-backends/{owner_id}/{prefix}` body
#[derive(Debug, Deserialize)]
struct EnabledBody {
    enabled: bool,
}

/// `PATCH /api/v1/admin/personal-backends/{owner_id}/{prefix}`
async fn handle_set_personal_enabled(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath((owner, prefix)): ApiPath<(Uuid, String)>,
    ApiJson(body): ApiJson<EnabledBody>,
) -> Outcome<StatusCode> {
    set_personal_enabled(&state, &session, owner, &prefix, body.enabled).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/v1/admin/personal-backends/{owner_id}/{prefix}`
async fn handle_delete_personal_of(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath((owner, prefix)): ApiPath<(Uuid, String)>,
) -> Outcome<StatusCode> {
    delete_personal_of(&state, &session, owner, &prefix).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn field(name: &str, header: &str, prefix: Option<&str>) -> CredentialField {
        CredentialField {
            name: name.to_owned(),
            label: None,
            header: header.to_owned(),
            prefix: prefix.map(str::to_owned),
        }
    }

    #[test]
    fn header_names_are_lowercased() {
        assert_eq!(header_name("X-Api-Key").unwrap(), "x-api-key");
        assert_eq!(header_name("Authorization").unwrap(), "authorization");
    }

    #[test]
    fn invalid_header_names_are_refused() {
        assert!(header_name("").is_err());
        assert!(header_name("bad header").is_err());
        assert!(header_name("bad:name").is_err());
        assert!(header_name("ünï").is_err());
    }

    #[test]
    fn reserved_header_names_are_refused_in_any_case() {
        for name in [
            "accept",
            "Accept",
            "MCP-Session-Id",
            "mcp-protocol-version",
            "Last-Event-ID",
        ] {
            let error = header_name(name).unwrap_err();
            assert!(error.contains("set by the gateway"), "{name}: {error}");
        }
    }

    #[test]
    fn headers_are_cleaned_and_checked() {
        let cleaned = clean_headers(map(&[("X-Key", "secret"), ("Authorization", "Bearer t")]));
        assert_eq!(
            cleaned.unwrap(),
            map(&[("x-key", "secret"), ("authorization", "Bearer t")])
        );
        assert!(clean_headers(map(&[("X-Key", "")])).is_err());
        assert!(clean_headers(map(&[("X-Key", "line\nbreak")])).is_err());
        assert!(clean_headers(map(&[("Accept", "text/plain")])).is_err());
        // the same header in two spellings
        assert!(clean_headers(map(&[("X-Key", "a"), ("x-key", "b")])).is_err());
        assert!(clean_headers(BTreeMap::new()).unwrap().is_empty());
    }

    #[test]
    fn too_many_headers_are_refused() {
        let many: BTreeMap<String, String> = (0..=MAX_HEADERS)
            .map(|n| (format!("x-h{n}"), "v".to_owned()))
            .collect();
        assert!(clean_headers(many).is_err());
    }

    #[test]
    fn only_http_urls_are_accepted() {
        assert_eq!(
            clean_url(" https://mcp.example/mcp ").unwrap(),
            "https://mcp.example/mcp"
        );
        assert!(clean_url("http://10.0.0.1:8080/mcp").is_ok());
        assert!(clean_url("ftp://mcp.example").is_err());
        assert!(clean_url("file:///etc/passwd").is_err());
        assert!(clean_url("not a url").is_err());
        assert!(clean_url("").is_err());
    }

    #[test]
    fn credential_fields_are_checked() {
        let good = clean_fields(vec![
            field("token", "Authorization", Some("Bearer ")),
            field("key", "X-Key", Some("")),
        ])
        .unwrap();
        assert_eq!(good[0].prefix.as_deref(), Some("Bearer "));
        assert_eq!(good[1].prefix, None);

        assert!(clean_fields(Vec::new()).is_err());
        assert!(clean_fields(vec![field("a", "X-A", None), field("a", "X-B", None)]).is_err());
        assert!(clean_fields(vec![field("", "X-A", None)]).is_err());
        assert!(clean_fields(vec![field("a", "bad header", None)]).is_err());
        assert!(clean_fields(vec![field("a", "Accept", None)]).is_err());
        assert!(clean_fields(vec![field("a", "X-A", Some("bad\nprefix"))]).is_err());
    }

    #[test]
    fn credential_values_must_name_known_fields_and_fill_one() {
        let fields = [field("token", "Authorization", Some("Bearer "))];
        assert_eq!(
            clean_values(&fields, map(&[("token", "abc")])).unwrap(),
            map(&[("token", "abc")])
        );
        assert!(clean_values(&fields, map(&[("other", "abc")])).is_err());
        assert!(clean_values(&fields, map(&[("token", "")])).is_err());
        assert!(clean_values(&fields, BTreeMap::new()).is_err());
        assert!(clean_values(&fields, map(&[("token", "a\nb")])).is_err());
    }

    #[test]
    fn descriptions_are_trimmed_and_blank_means_none() {
        assert_eq!(clean_description("  hi ").unwrap().as_deref(), Some("hi"));
        assert_eq!(clean_description("   ").unwrap(), None);
        assert!(clean_description(&"x".repeat(MAX_DESCRIPTION_CHARS + 1)).is_err());
    }

    #[test]
    fn the_auth_field_is_fields_or_oauth() {
        assert_eq!(parse_auth(None), Ok(CatalogAuthMode::Fields));
        assert_eq!(parse_auth(Some("")), Ok(CatalogAuthMode::Fields));
        assert_eq!(parse_auth(Some("fields")), Ok(CatalogAuthMode::Fields));
        assert_eq!(parse_auth(Some(" oauth ")), Ok(CatalogAuthMode::OAuth));
        assert!(parse_auth(Some("passthrough")).is_err());
        assert!(parse_auth(Some("OAuth")).is_err());
    }

    #[test]
    fn scopes_split_on_spaces_and_commas() {
        assert_eq!(
            split_scopes("read, write  admin,,\n"),
            vec!["read", "write", "admin"]
        );
        assert_eq!(split_scopes(" , "), [] as [String; 0]);
    }

    #[test]
    fn scopes_are_checked_and_listed_once() {
        let scopes = |items: &[&str]| -> Vec<String> {
            items.iter().map(|item| (*item).to_owned()).collect()
        };
        assert_eq!(
            clean_scopes(&scopes(&["read write", "read", "api://x/.default"])).unwrap(),
            vec!["read", "write", "api://x/.default"]
        );
        assert_eq!(clean_scopes(&[]).unwrap(), [] as [String; 0]);
        assert!(clean_scopes(&scopes(&["a\"b"])).is_err());
        assert!(clean_scopes(&scopes(&["a\\b"])).is_err());
        assert!(clean_scopes(&scopes(&["ünï"])).is_err());
        assert!(clean_scopes(&scopes(&[&"x".repeat(MAX_SCOPE_CHARS + 1)])).is_err());
        let many: Vec<String> = (0..=MAX_OAUTH_SCOPES).map(|n| format!("s{n}")).collect();
        assert!(clean_scopes(&many).is_err());
    }

    #[test]
    fn a_client_id_is_trimmed_and_blank_means_none() {
        assert_eq!(clean_client_id(" abc ").unwrap().as_deref(), Some("abc"));
        assert_eq!(clean_client_id("  ").unwrap(), None);
        assert!(clean_client_id("a\nb").is_err());
        assert!(clean_client_id(&"x".repeat(MAX_CLIENT_ID_CHARS + 1)).is_err());
    }

    #[test]
    fn a_return_to_is_a_local_path_or_nothing() {
        assert_eq!(
            clean_return_to(Some("/ui/catalog")).as_deref(),
            Some("/ui/catalog")
        );
        assert_eq!(clean_return_to(Some("/a?b=c")).as_deref(), Some("/a?b=c"));
        assert_eq!(clean_return_to(None), None);
        assert_eq!(clean_return_to(Some("")), None);
        assert_eq!(clean_return_to(Some("//evil.example/")), None);
        assert_eq!(clean_return_to(Some("/\\evil.example")), None);
        assert_eq!(clean_return_to(Some("https://evil.example/")), None);
        assert_eq!(clean_return_to(Some("ui")), None);
        assert_eq!(clean_return_to(Some("/a\r\nSet-Cookie: x")), None);
    }

    #[test]
    fn a_failed_connection_answers_with_the_right_status() {
        let status = |error: ConnectError| connect_failure(&error).0;
        assert_eq!(status(ConnectError::NotConnectable), StatusCode::NOT_FOUND);
        assert_eq!(
            status(ConnectError::ClientUnusable),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status(ConnectError::Upstream(String::from("down"))),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status(ConnectError::UnknownRequest),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status(ConnectError::WrongUser), StatusCode::BAD_REQUEST);
        assert_eq!(
            status(ConnectError::Callback(String::from("iss"))),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(ConnectError::Exchange(String::from("denied"))),
            StatusCode::BAD_REQUEST
        );
    }
}
