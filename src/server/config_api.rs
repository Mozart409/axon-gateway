//! The JSON API under `/api/v1/admin/config` for the gateway's configuration
//! in the database: shared backends, gateway toolsets, OIDC providers and the
//! global settings. The dashboard pages in `config_ui` call the same
//! [`ConfigCtx`] operations.
//!
//! The routes exist only in database mode (`AppState::db_config` and the store
//! are set); otherwise every one of them is a JSON 404. They sit behind the
//! session guard, the same-site check and the CSRF token like `admin_api`.
//! Backends and toolsets need `backends.view` or `backends.manage` to read and
//! `backends.manage` to write; providers and settings need `gateway.admin`.
//!
//! Every write is checked before it is stored: the change is applied to the
//! current configuration (`dbconfig::load`) and the result validated, so a 400
//! carries the text of the first problem. The handler reloads nothing: every
//! replica picks the change up through the database notification. Responses
//! never hold a secret value, only whether one is set.
//!
//! Secrets on `PUT`: a secret field that is absent or null keeps the stored
//! value, `""` clears it and a value sets it. In the `headers` and `env` maps a
//! key with a null value keeps its stored value and a key that is left out is
//! removed. `POST` takes the values as given. A backend's OAuth client secret
//! is the top-level field `oauth_client_secret`, a provider's `client_secret`.

use std::collections::{BTreeMap, HashMap};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::admin_api::{ApiError, ApiJson, ApiPath};
use super::{AppState, reject_cross_site_middleware, session};
use crate::config::{
    BackendConfig, Config, GatewaySettings, OidcProviderConfig, ToolsetConfig, TransportType,
};
use crate::crypto::CryptoError;
use crate::dbconfig::{
    self, BackendSecrets, DbConfigContext, DbConfigError, merge_backend, open_backend_secrets,
    open_provider_secret, seal_backend_secrets, seal_provider_secret, split_backend,
    split_provider,
};
use crate::policy::{Permission, Permissions};
use crate::rbac::{AdminError, resolve};
use crate::store::{
    Actor, GatewayBackendRow, GatewayConfigError, GatewayToolsetRow, OidcProviderRow,
    SealedColumns, SecretUpdate, SessionUser, Store, StoreError,
};

const STDIO_OFF: &str = "stdio backends are off: start the gateway with AXON_ALLOW_STDIO=true";
const SECRETS_NEED_REENTRY: &str =
    "changing where the backend connects needs its secrets entered again (or cleared)";
const PROVIDER_SECRET_NEEDS_REENTRY: &str =
    "changing the issuer needs the client secret entered again (or cleared)";
const ENV_PROVIDER: &str = "this provider is set by the environment";
const OAUTH_SECRET_WITHOUT_OAUTH: &str =
    "oauth_client_secret needs an oauth section with a client_id";

/// Why a configuration operation did not happen
#[derive(Debug)]
pub(super) enum ConfigApiError {
    Admin(AdminError),
    /// Something the caller cannot fix; the text is only logged
    Internal(String),
}

impl From<AdminError> for ConfigApiError {
    fn from(error: AdminError) -> Self {
        Self::Admin(error)
    }
}

impl From<StoreError> for ConfigApiError {
    fn from(error: StoreError) -> Self {
        Self::Admin(AdminError::Store(error))
    }
}

impl From<GatewayConfigError> for ConfigApiError {
    fn from(error: GatewayConfigError) -> Self {
        match error {
            GatewayConfigError::Exists => Self::Admin(already_exists()),
            GatewayConfigError::Store(error) => error.into(),
        }
    }
}

impl From<CryptoError> for ConfigApiError {
    fn from(error: CryptoError) -> Self {
        Self::Internal(error.to_string())
    }
}

impl IntoResponse for ConfigApiError {
    fn into_response(self) -> Response {
        match self {
            Self::Admin(error) => ApiError::from(error).into_response(),
            Self::Internal(message) => {
                tracing::warn!(message, "A configuration API request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "the request could not be completed" })),
                )
                    .into_response()
            }
        }
    }
}

fn already_exists() -> AdminError {
    AdminError::Conflict("already exists".to_owned())
}

/// What a permission check is about: backends and toolsets, or the gateway
/// itself (providers and settings)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Area {
    Backends,
    Gateway,
}

/// A backend as the API shows it: no secret value, only which are set
#[derive(Debug, Clone)]
pub(super) struct BackendView {
    pub config: BackendConfig,
    pub auth_token_set: bool,
    pub oauth_client_secret_set: bool,
    /// Names of the headers that have a value, sorted
    pub header_names: Vec<String>,
    /// Names of the environment variables that have a value, sorted
    pub env_names: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A gateway toolset with its timestamps
#[derive(Debug, Clone)]
pub(super) struct ToolsetView {
    pub config: ToolsetConfig,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Where an OIDC provider is defined
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProviderSource {
    /// The `AXON_OIDC_*` bootstrap environment: read-only
    Env,
    Database,
}

impl ProviderSource {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Database => "database",
        }
    }
}

/// An OIDC provider as the API shows it: no client secret
#[derive(Debug, Clone)]
pub(super) struct ProviderView {
    pub source: ProviderSource,
    pub config: OidcProviderConfig,
    pub client_secret_set: bool,
    /// Sort key of the login buttons; `None` for the environment provider, which is first
    pub position: Option<i32>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// A backend to write: the config with the secrets that were given. `headers`
/// and `env` values are `None` where the body said null (keep the stored value).
/// The config's own `auth_token` is the token as given (`""` clears on update).
#[derive(Debug)]
pub(super) struct BackendInput {
    pub config: BackendConfig,
    pub headers: BTreeMap<String, Option<String>>,
    pub env: BTreeMap<String, Option<String>>,
    pub oauth_client_secret: Option<String>,
}

/// A provider to write; `client_secret` `None` keeps the stored one
#[derive(Debug)]
pub(super) struct ProviderInput {
    pub config: OidcProviderConfig,
    pub position: Option<i32>,
    pub client_secret: Option<String>,
}

fn invalid(message: impl Into<String>) -> AdminError {
    AdminError::Invalid(message.into())
}

/// Puts the name from the URL into the body, or checks the body agrees
fn set_key(
    object: &mut Map<String, Value>,
    key: &str,
    from_path: Option<&str>,
) -> Result<(), AdminError> {
    let Some(wanted) = from_path else {
        return Ok(());
    };
    match object.get(key) {
        None | Some(Value::Null) => {
            object.insert(key.to_owned(), Value::String(wanted.to_owned()));
            Ok(())
        }
        Some(Value::String(given)) if given == wanted => Ok(()),
        Some(_) => Err(invalid(format!("{key} in the body does not match the URL"))),
    }
}

fn into_object(body: Value) -> Result<Map<String, Value>, AdminError> {
    match body {
        Value::Object(object) => Ok(object),
        _ => Err(invalid("the body must be a JSON object")),
    }
}

/// A string field that may be absent or null
fn take_string(object: &mut Map<String, Value>, key: &str) -> Result<Option<String>, AdminError> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(invalid(format!("{key} must be a string"))),
    }
}

/// A map of secret values where null means "keep the stored value"
fn take_secret_map(
    object: &mut Map<String, Value>,
    key: &str,
) -> Result<BTreeMap<String, Option<String>>, AdminError> {
    let map = match object.remove(key) {
        None | Some(Value::Null) => return Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid(format!("{key} must be an object"))),
    };
    let mut values = BTreeMap::new();
    for (name, value) in map {
        let value = match value {
            Value::Null => None,
            Value::String(text) => Some(text),
            _ => return Err(invalid(format!("{key}.{name} must be a string or null"))),
        };
        values.insert(name, value);
    }
    Ok(values)
}

/// Reads a backend body; `path_name` is the name of a `PUT` URL.
pub(super) fn backend_input(
    body: Value,
    path_name: Option<&str>,
) -> Result<BackendInput, AdminError> {
    let mut object = into_object(body)?;
    set_key(&mut object, "name", path_name)?;
    let headers = take_secret_map(&mut object, "headers")?;
    let env = take_secret_map(&mut object, "env")?;
    let oauth_client_secret = take_string(&mut object, "oauth_client_secret")?;
    let config = serde_json::from_value::<BackendConfig>(Value::Object(object))
        .map_err(|error| invalid(error.to_string()))?;
    Ok(BackendInput {
        config,
        headers,
        env,
        oauth_client_secret,
    })
}

/// Reads a toolset body; `path_name` is the name of a `PUT` URL.
pub(super) fn toolset_input(
    body: Value,
    path_name: Option<&str>,
) -> Result<ToolsetConfig, AdminError> {
    let mut object = into_object(body)?;
    set_key(&mut object, "name", path_name)?;
    serde_json::from_value(Value::Object(object)).map_err(|error| invalid(error.to_string()))
}

/// Reads a provider body; `path_id` is the id of a `PUT` URL.
pub(super) fn provider_input(
    body: Value,
    path_id: Option<&str>,
) -> Result<ProviderInput, AdminError> {
    let mut object = into_object(body)?;
    set_key(&mut object, "id", path_id)?;
    let client_secret = take_string(&mut object, "client_secret")?;
    let position = match object.remove("position") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .and_then(|number| i32::try_from(number).ok())
                .ok_or_else(|| invalid("position must be a number"))?,
        ),
    };
    let config = serde_json::from_value::<OidcProviderConfig>(Value::Object(object))
        .map_err(|error| invalid(error.to_string()))?;
    Ok(ProviderInput {
        config,
        position,
        client_secret,
    })
}

/// Reads a settings body.
pub(super) fn settings_input(body: Value) -> Result<GatewaySettings, AdminError> {
    let object = into_object(body)?;
    serde_json::from_value(Value::Object(object)).map_err(|error| invalid(error.to_string()))
}

/// Whether a backend's credentials would go somewhere else: the transport,
/// URL, command or arguments differ, or the passthrough provider does
/// (the OAuth client has no endpoint of its own)
fn destination_changed(stored: &BackendConfig, new: &BackendConfig) -> bool {
    stored.transport != new.transport
        || stored.url != new.url
        || stored.command != new.command
        || stored.args != new.args
        || stored.passthrough.as_ref().map(|p| &p.provider)
            != new.passthrough.as_ref().map(|p| &p.provider)
}

/// A secret on update: absent keeps, `""` clears, a value replaces
fn updated_secret(given: Option<String>, stored: Option<&str>) -> Option<String> {
    match given {
        None => stored.map(str::to_owned),
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
    }
}

/// A secret map on update: a key with a value sets it, one with `None` keeps
/// the stored value (empty when there is none), a key that is missing is gone
fn updated_map(
    given: BTreeMap<String, Option<String>>,
    stored: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    given
        .into_iter()
        .map(|(name, value)| {
            let value = value
                .or_else(|| stored.get(&name).cloned())
                .unwrap_or_default();
            (name, value)
        })
        .collect()
}

/// A secret map on create: the values as given
fn given_map(given: BTreeMap<String, Option<String>>) -> HashMap<String, String> {
    given
        .into_iter()
        .map(|(name, value)| (name, value.unwrap_or_default()))
        .collect()
}

/// Email, else display name, else subject: how the audit log names the caller
fn actor_of(session: &SessionUser) -> Actor {
    let user = &session.user;
    let label = [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
        .to_owned();
    Actor {
        user_id: Some(user.id),
        label,
    }
}

/// The configuration operations of one logged-in user, shared by the JSON API
/// and the dashboard pages.
pub(super) struct ConfigCtx<'a> {
    store: &'a Store,
    db: &'a DbConfigContext,
    actor: Actor,
    permissions: Permissions,
}

impl<'a> ConfigCtx<'a> {
    /// The operations for a session; `None` outside database mode.
    pub(super) fn from_state(state: &'a AppState, session: &SessionUser) -> Option<Self> {
        let store = state.store.as_ref()?;
        let db = state.db_config.as_ref()?;
        let (_, permissions) = resolve(&state.policy.current(), session);
        Some(Self {
            store,
            db,
            actor: actor_of(session),
            permissions,
        })
    }

    /// Whether the user may read the area's configuration
    pub(super) fn can_read(&self, area: Area) -> bool {
        match area {
            Area::Backends => {
                self.permissions.has(Permission::BackendsView)
                    || self.permissions.has(Permission::BackendsManage)
            }
            Area::Gateway => self.permissions.has(Permission::GatewayAdmin),
        }
    }

    /// Whether the user may change the area's configuration
    pub(super) fn can_write(&self, area: Area) -> bool {
        match area {
            Area::Backends => self.permissions.has(Permission::BackendsManage),
            Area::Gateway => self.permissions.has(Permission::GatewayAdmin),
        }
    }

    /// Whether stdio backends may run (`AXON_ALLOW_STDIO`)
    pub(super) fn allow_stdio(&self) -> bool {
        self.db.bootstrap.allow_stdio
    }

    fn require_read(&self, area: Area) -> Result<(), AdminError> {
        if self.can_read(area) {
            Ok(())
        } else {
            Err(AdminError::Forbidden)
        }
    }

    fn require_write(&self, area: Area) -> Result<(), AdminError> {
        if self.can_write(area) {
            Ok(())
        } else {
            Err(AdminError::Forbidden)
        }
    }

    fn check_transport(&self, config: &BackendConfig) -> Result<(), AdminError> {
        if config.transport == TransportType::Stdio && !self.allow_stdio() {
            return Err(invalid(STDIO_OFF));
        }
        Ok(())
    }

    fn refuse_env_provider(&self, id: &str) -> Result<(), AdminError> {
        if self
            .db
            .bootstrap
            .oidc
            .as_ref()
            .is_some_and(|provider| provider.id == id)
        {
            return Err(AdminError::Conflict(ENV_PROVIDER.to_owned()));
        }
        Ok(())
    }

    /// The configuration as the gateway runs it now
    async fn current(&self) -> Result<Config, ConfigApiError> {
        dbconfig::load(self.store, &self.db.keyring, &self.db.bootstrap)
            .await
            .map_err(|error| match error {
                DbConfigError::Store(error) => error.into(),
                invalid @ DbConfigError::Invalid(_) => {
                    AdminError::Invalid(invalid.to_string()).into()
                }
            })
    }

    /// Refuses a change that would make the configuration invalid
    fn check(current: &Config, change: impl FnOnce(&mut Config)) -> Result<(), ConfigApiError> {
        dbconfig::check_candidate(current, change)
            .map_err(|message| AdminError::Invalid(message).into())
    }

    /// Refuses a deletion that breaks a valid configuration. A configuration
    /// that is invalid already (or cannot be loaded) never blocks a deletion.
    async fn check_deletion(&self, change: impl FnOnce(&mut Config)) -> Result<(), ConfigApiError> {
        let current = match self.current().await {
            Ok(current) => current,
            Err(ConfigApiError::Admin(AdminError::Invalid(_))) => return Ok(()),
            Err(error) => return Err(error),
        };
        if let Err(message) = dbconfig::check_candidate(&current, change)
            && dbconfig::check_candidate(&current, |_| {}).is_ok()
        {
            return Err(AdminError::Invalid(message).into());
        }
        Ok(())
    }

    // -- backends -------------------------------------------------------------

    /// The secrets of a stored backend; ones that cannot be unsealed read as
    /// none (the gateway skips such a backend), so it can be fixed by saving it again.
    fn open_backend(&self, name: &str, sealed: Option<&SealedColumns>) -> BackendSecrets {
        let Some(sealed) = sealed else {
            return BackendSecrets::default();
        };
        open_backend_secrets(&self.db.keyring, name, sealed).unwrap_or_else(|error| {
            tracing::warn!(backend = %name, %error, "The secrets of a backend cannot be unsealed");
            BackendSecrets::default()
        })
    }

    fn backend_view(&self, row: GatewayBackendRow) -> Result<BackendView, String> {
        let mut config: BackendConfig = serde_json::from_value(row.spec)
            .map_err(|error| format!("the stored backend {} does not parse: {error}", row.name))?;
        config.name.clone_from(&row.name);
        let secrets = self.open_backend(&row.name, row.secret.as_ref());
        // The spec holds no values; this only makes sure none reaches a view.
        let (config, _) = split_backend(&config);
        let mut header_names: Vec<String> = config.headers.keys().cloned().collect();
        header_names.sort();
        let mut env_names: Vec<String> = config.env.keys().cloned().collect();
        env_names.sort();
        Ok(BackendView {
            config,
            auth_token_set: secrets.auth_token.is_some(),
            oauth_client_secret_set: secrets.oauth_client_secret.is_some(),
            header_names,
            env_names,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// Every backend, by name.
    ///
    /// # Errors
    /// Fails without `backends.view` or `backends.manage`, or when the query fails.
    pub(super) async fn list_backends(&self) -> Result<Vec<BackendView>, ConfigApiError> {
        self.require_read(Area::Backends)?;
        let rows = self.store.list_gateway_backends().await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let name = row.name.clone();
                self.backend_view(row)
                    .inspect_err(|error| {
                        tracing::warn!(backend = %name, %error, "Skipping a backend");
                    })
                    .ok()
            })
            .collect())
    }

    /// One backend.
    ///
    /// # Errors
    /// Fails without `backends.view` or `backends.manage`, when there is no such
    /// backend, or when the query fails.
    pub(super) async fn get_backend(&self, name: &str) -> Result<BackendView, ConfigApiError> {
        self.require_read(Area::Backends)?;
        let row = self
            .store
            .gateway_backend(name)
            .await?
            .ok_or(AdminError::NotFound)?;
        self.backend_view(row).map_err(ConfigApiError::Internal)
    }

    /// Creates a backend.
    ///
    /// # Errors
    /// Fails without `backends.manage`, for a stdio backend while stdio is off
    /// (400), for a name that is taken (409), for a configuration that does not
    /// validate (400), or when the write fails.
    pub(super) async fn create_backend(
        &self,
        input: BackendInput,
    ) -> Result<BackendView, ConfigApiError> {
        self.require_write(Area::Backends)?;
        let BackendInput {
            mut config,
            headers,
            env,
            oauth_client_secret,
        } = input;
        self.check_transport(&config)?;
        config.auth_token = config.auth_token.filter(|token| !token.is_empty());
        config.headers = given_map(headers);
        config.env = given_map(env);
        let oauth_secret = oauth_client_secret.filter(|secret| !secret.is_empty());
        match config.oauth.as_mut() {
            Some(oauth) => oauth.client_secret = oauth_secret,
            None if oauth_secret.is_some() => {
                return Err(invalid(OAUTH_SECRET_WITHOUT_OAUTH).into());
            }
            None => {}
        }

        if self.store.gateway_backend(&config.name).await?.is_some() {
            return Err(already_exists().into());
        }
        let current = self.current().await?;
        Self::check(&current, |candidate| {
            candidate.backends.push(config.clone());
        })?;

        let (spec, secrets) = split_backend(&config);
        let sealed = seal_backend_secrets(&self.db.keyring, &config.name, &secrets)?;
        let row = self
            .store
            .create_gateway_backend(&self.actor, &spec, sealed.as_ref(), &secrets.keys())
            .await?;
        self.backend_view(row).map_err(ConfigApiError::Internal)
    }

    /// Replaces backend `name`, with the secret semantics of the module docs.
    ///
    /// # Errors
    /// Fails without `backends.manage`, for a stdio backend while stdio is off
    /// (400), when there is no such backend (404), for a configuration that does
    /// not validate (400), or when the write fails.
    pub(super) async fn update_backend(
        &self,
        name: &str,
        input: BackendInput,
    ) -> Result<BackendView, ConfigApiError> {
        self.require_write(Area::Backends)?;
        let BackendInput {
            mut config,
            headers,
            env,
            oauth_client_secret,
        } = input;
        name.clone_into(&mut config.name);
        self.check_transport(&config)?;
        let row = self
            .store
            .gateway_backend(name)
            .await?
            .ok_or(AdminError::NotFound)?;
        let stored = self.open_backend(name, row.secret.as_ref());

        // Secrets must not follow a backend to a new destination unseen.
        let moved = serde_json::from_value::<BackendConfig>(row.spec.clone())
            .ok()
            .is_none_or(|spec| destination_changed(&spec, &config));
        if moved {
            let kept = (config.auth_token.is_none() && stored.auth_token.is_some())
                || (config.oauth.is_some()
                    && oauth_client_secret.is_none()
                    && stored.oauth_client_secret.is_some())
                || headers
                    .iter()
                    .any(|(key, value)| value.is_none() && stored.headers.contains_key(key))
                || env
                    .iter()
                    .any(|(key, value)| value.is_none() && stored.env.contains_key(key));
            if kept {
                return Err(invalid(SECRETS_NEED_REENTRY).into());
            }
        }

        let oauth_client_secret = if config.oauth.is_some() {
            updated_secret(oauth_client_secret, stored.oauth_client_secret.as_deref())
        } else if oauth_client_secret.is_some_and(|secret| !secret.is_empty()) {
            return Err(invalid(OAUTH_SECRET_WITHOUT_OAUTH).into());
        } else {
            None
        };
        let secrets = BackendSecrets {
            auth_token: updated_secret(config.auth_token.take(), stored.auth_token.as_deref()),
            headers: updated_map(headers, &stored.headers),
            env: updated_map(env, &stored.env),
            oauth_client_secret,
        };
        config.headers = secrets
            .headers
            .keys()
            .map(|header| (header.clone(), String::new()))
            .collect();
        config.env = secrets
            .env
            .keys()
            .map(|variable| (variable.clone(), String::new()))
            .collect();
        let full = merge_backend(config, &secrets);

        let current = self.current().await?;
        Self::check(&current, |candidate| {
            match candidate
                .backends
                .iter_mut()
                .find(|backend| backend.name == name)
            {
                Some(slot) => slot.clone_from(&full),
                None => candidate.backends.push(full.clone()),
            }
        })?;

        let (spec, secrets) = split_backend(&full);
        let update = seal_backend_secrets(&self.db.keyring, name, &secrets)?
            .map_or(SecretUpdate::Clear, SecretUpdate::Set);
        let row = self
            .store
            .update_gateway_backend(&self.actor, name, &spec, &update, &secrets.keys())
            .await?
            .ok_or(AdminError::NotFound)?;
        self.backend_view(row).map_err(ConfigApiError::Internal)
    }

    /// Deletes backend `name`.
    ///
    /// # Errors
    /// Fails without `backends.manage`, when there is no such backend (404), when
    /// the rest would not validate (400), or when the write fails.
    pub(super) async fn delete_backend(&self, name: &str) -> Result<(), ConfigApiError> {
        self.require_write(Area::Backends)?;
        self.check_deletion(|candidate| {
            candidate.backends.retain(|backend| backend.name != name);
        })
        .await?;
        if self.store.delete_gateway_backend(&self.actor, name).await? {
            Ok(())
        } else {
            Err(AdminError::NotFound.into())
        }
    }

    // -- toolsets -------------------------------------------------------------

    fn toolset_view(row: GatewayToolsetRow) -> Result<ToolsetView, String> {
        let mut config: ToolsetConfig = serde_json::from_value(row.spec)
            .map_err(|error| format!("the stored toolset {} does not parse: {error}", row.name))?;
        config.name = row.name;
        Ok(ToolsetView {
            config,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// Every gateway toolset, by name.
    ///
    /// # Errors
    /// Fails without `backends.view` or `backends.manage`, or when the query fails.
    pub(super) async fn list_toolsets(&self) -> Result<Vec<ToolsetView>, ConfigApiError> {
        self.require_read(Area::Backends)?;
        let rows = self.store.list_gateway_toolsets().await?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                let name = row.name.clone();
                Self::toolset_view(row)
                    .inspect_err(|error| {
                        tracing::warn!(toolset = %name, %error, "Skipping a toolset");
                    })
                    .ok()
            })
            .collect())
    }

    /// One gateway toolset.
    ///
    /// # Errors
    /// Fails without `backends.view` or `backends.manage`, when there is no such
    /// toolset, or when the query fails.
    pub(super) async fn get_toolset(&self, name: &str) -> Result<ToolsetView, ConfigApiError> {
        self.require_read(Area::Backends)?;
        let row = self
            .store
            .gateway_toolset(name)
            .await?
            .ok_or(AdminError::NotFound)?;
        Self::toolset_view(row).map_err(ConfigApiError::Internal)
    }

    /// Creates a gateway toolset.
    ///
    /// # Errors
    /// Fails without `backends.manage`, for a name that is taken (409), for a
    /// configuration that does not validate (400), or when the write fails.
    pub(super) async fn create_toolset(
        &self,
        config: ToolsetConfig,
    ) -> Result<ToolsetView, ConfigApiError> {
        self.require_write(Area::Backends)?;
        if self.store.gateway_toolset(&config.name).await?.is_some() {
            return Err(already_exists().into());
        }
        let current = self.current().await?;
        Self::check(&current, |candidate| {
            candidate.toolsets.push(config.clone());
        })?;
        let row = self
            .store
            .create_gateway_toolset(&self.actor, &config)
            .await?;
        Self::toolset_view(row).map_err(ConfigApiError::Internal)
    }

    /// Replaces gateway toolset `name`.
    ///
    /// # Errors
    /// Fails without `backends.manage`, when there is no such toolset (404), for
    /// a configuration that does not validate (400), or when the write fails.
    pub(super) async fn update_toolset(
        &self,
        name: &str,
        mut config: ToolsetConfig,
    ) -> Result<ToolsetView, ConfigApiError> {
        self.require_write(Area::Backends)?;
        name.clone_into(&mut config.name);
        let current = self.current().await?;
        Self::check(&current, |candidate| {
            match candidate
                .toolsets
                .iter_mut()
                .find(|toolset| toolset.name == name)
            {
                Some(slot) => slot.clone_from(&config),
                None => candidate.toolsets.push(config.clone()),
            }
        })?;
        let row = self
            .store
            .update_gateway_toolset(&self.actor, name, &config)
            .await?
            .ok_or(AdminError::NotFound)?;
        Self::toolset_view(row).map_err(ConfigApiError::Internal)
    }

    /// Deletes gateway toolset `name`.
    ///
    /// # Errors
    /// Fails without `backends.manage`, when there is no such toolset (404), or
    /// when the write fails.
    pub(super) async fn delete_toolset(&self, name: &str) -> Result<(), ConfigApiError> {
        self.require_write(Area::Backends)?;
        self.check_deletion(|candidate| {
            candidate.toolsets.retain(|toolset| toolset.name != name);
        })
        .await?;
        if self.store.delete_gateway_toolset(&self.actor, name).await? {
            Ok(())
        } else {
            Err(AdminError::NotFound.into())
        }
    }

    // -- OIDC providers -------------------------------------------------------

    /// The bootstrap provider as a read-only view
    fn env_provider(provider: &OidcProviderConfig) -> ProviderView {
        ProviderView {
            source: ProviderSource::Env,
            client_secret_set: provider.client_secret.is_some(),
            config: OidcProviderConfig {
                client_secret: None,
                client_secret_env: None,
                ..provider.clone()
            },
            position: None,
            updated_at: None,
        }
    }

    fn provider_view(row: OidcProviderRow) -> Result<ProviderView, String> {
        let mut config: OidcProviderConfig = serde_json::from_value(row.spec)
            .map_err(|error| format!("the stored provider {} does not parse: {error}", row.id))?;
        config.id = row.id;
        config.client_secret = None;
        config.client_secret_env = None;
        Ok(ProviderView {
            source: ProviderSource::Database,
            config,
            client_secret_set: row.secret.is_some(),
            position: Some(row.position),
            updated_at: Some(row.updated_at),
        })
    }

    /// The environment provider, then the database ones by position.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, or when the query fails.
    pub(super) async fn list_providers(&self) -> Result<Vec<ProviderView>, ConfigApiError> {
        self.require_read(Area::Gateway)?;
        let mut views: Vec<ProviderView> = self
            .db
            .bootstrap
            .oidc
            .iter()
            .map(Self::env_provider)
            .collect();
        for row in self.store.list_oidc_providers().await? {
            let id = row.id.clone();
            if views.iter().any(|view| view.config.id == id) {
                continue;
            }
            match Self::provider_view(row) {
                Ok(view) => views.push(view),
                Err(error) => tracing::warn!(provider = %id, %error, "Skipping a provider"),
            }
        }
        Ok(views)
    }

    /// One provider.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, when there is no such provider, or when
    /// the query fails.
    pub(super) async fn get_provider(&self, id: &str) -> Result<ProviderView, ConfigApiError> {
        self.require_read(Area::Gateway)?;
        if let Some(provider) = self
            .db
            .bootstrap
            .oidc
            .as_ref()
            .filter(|provider| provider.id == id)
        {
            return Ok(Self::env_provider(provider));
        }
        let row = self
            .store
            .oidc_provider(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        Self::provider_view(row).map_err(ConfigApiError::Internal)
    }

    /// Creates a provider.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, for the id of the environment provider or
    /// one that is taken (409), for a configuration that does not validate (400),
    /// or when the write fails.
    pub(super) async fn create_provider(
        &self,
        input: ProviderInput,
    ) -> Result<ProviderView, ConfigApiError> {
        self.require_write(Area::Gateway)?;
        let ProviderInput {
            mut config,
            position,
            client_secret,
        } = input;
        self.refuse_env_provider(&config.id)?;
        if self.store.oidc_provider(&config.id).await?.is_some() {
            return Err(already_exists().into());
        }
        config.client_secret = client_secret.filter(|secret| !secret.is_empty());
        config.client_secret_env = None;
        let current = self.current().await?;
        Self::check(&current, |candidate| {
            candidate.auth.oidc.push(config.clone());
        })?;

        let (spec, secret) = split_provider(&config);
        let sealed = secret
            .map(|secret| seal_provider_secret(&self.db.keyring, &config.id, &secret))
            .transpose()?;
        let row = self
            .store
            .create_oidc_provider(&self.actor, &spec, position, sealed.as_ref())
            .await?;
        Self::provider_view(row).map_err(ConfigApiError::Internal)
    }

    /// The client secret of a stored provider; one that cannot be unsealed reads
    /// as none (the gateway skips such a provider), so saving a new one fixes it.
    fn stored_provider_secret(&self, id: &str, row: &OidcProviderRow) -> Option<String> {
        let sealed = row.secret.as_ref()?;
        open_provider_secret(&self.db.keyring, id, sealed)
            .inspect_err(|error| {
                tracing::warn!(provider = %id, %error, "Cannot unseal a client secret");
            })
            .ok()
    }

    /// Replaces provider `id`, with the secret semantics of the module docs.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, for the environment provider (409), when
    /// there is no such provider (404), for a configuration that does not
    /// validate (400), or when the write fails.
    pub(super) async fn update_provider(
        &self,
        id: &str,
        input: ProviderInput,
    ) -> Result<ProviderView, ConfigApiError> {
        self.require_write(Area::Gateway)?;
        self.refuse_env_provider(id)?;
        let ProviderInput {
            mut config,
            position,
            client_secret,
        } = input;
        let row = self
            .store
            .oidc_provider(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        id.clone_into(&mut config.id);
        config.client_secret_env = None;

        let issuer_moved = serde_json::from_value::<OidcProviderConfig>(row.spec.clone())
            .ok()
            .is_none_or(|stored| stored.issuer != config.issuer);
        if issuer_moved && client_secret.is_none() && row.secret.is_some() {
            return Err(invalid(PROVIDER_SECRET_NEEDS_REENTRY).into());
        }

        let (effective, update) = match client_secret {
            None => (self.stored_provider_secret(id, &row), SecretUpdate::Keep),
            Some(secret) if secret.is_empty() => (None, SecretUpdate::Clear),
            Some(secret) => {
                let sealed = seal_provider_secret(&self.db.keyring, id, &secret)?;
                (Some(secret), SecretUpdate::Set(sealed))
            }
        };
        config.client_secret = effective;

        let current = self.current().await?;
        Self::check(&current, |candidate| {
            match candidate
                .auth
                .oidc
                .iter_mut()
                .find(|provider| provider.id == id)
            {
                Some(slot) => slot.clone_from(&config),
                None => candidate.auth.oidc.push(config.clone()),
            }
        })?;

        let (spec, _) = split_provider(&config);
        let row = self
            .store
            .update_oidc_provider(&self.actor, id, &spec, position, &update)
            .await?
            .ok_or(AdminError::NotFound)?;
        Self::provider_view(row).map_err(ConfigApiError::Internal)
    }

    /// Deletes provider `id`.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, for the environment provider (409), when
    /// there is no such provider (404), or when the write fails.
    pub(super) async fn delete_provider(&self, id: &str) -> Result<(), ConfigApiError> {
        self.require_write(Area::Gateway)?;
        self.refuse_env_provider(id)?;
        self.check_deletion(|candidate| {
            candidate.auth.oidc.retain(|provider| provider.id != id);
        })
        .await?;
        if self.store.delete_oidc_provider(&self.actor, id).await? {
            Ok(())
        } else {
            Err(AdminError::NotFound.into())
        }
    }

    // -- settings -------------------------------------------------------------

    /// The global settings; the defaults until they were first saved.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, or when the query fails.
    pub(super) async fn settings(&self) -> Result<GatewaySettings, ConfigApiError> {
        self.require_read(Area::Gateway)?;
        let Some(row) = self.store.gateway_settings().await? else {
            return Ok(GatewaySettings::default());
        };
        serde_json::from_value(row.spec).map_err(|error| {
            ConfigApiError::Internal(format!("the stored settings do not parse: {error}"))
        })
    }

    /// Saves the global settings.
    ///
    /// # Errors
    /// Fails without `gateway.admin`, for settings that do not validate (400), or
    /// when the write fails.
    pub(super) async fn put_settings(
        &self,
        settings: GatewaySettings,
    ) -> Result<GatewaySettings, ConfigApiError> {
        self.require_write(Area::Gateway)?;
        let current = self.current().await?;
        Self::check(&current, |candidate| {
            candidate.gateway.rate_limit_per_minute = settings.rate_limit_per_minute;
            candidate
                .gateway
                .allowed_hosts
                .clone_from(&settings.allowed_hosts);
            candidate.gateway.idle_timeout_secs = settings.idle_timeout_secs;
            candidate
                .personal_backends
                .clone_from(&settings.personal_backends);
        })?;
        self.store
            .put_gateway_settings(&self.actor, &settings)
            .await?;
        Ok(settings)
    }
}

// -- JSON ---------------------------------------------------------------------

/// A name-to-"set" map for the secret values of a headers or env map
fn set_markers(names: &[String]) -> Value {
    Value::Object(
        names
            .iter()
            .map(|name| (name.clone(), Value::String("set".to_owned())))
            .collect(),
    )
}

fn backend_json(view: &BackendView) -> Value {
    let mut value = serde_json::to_value(&view.config).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.remove("auth_token");
        object.insert("auth_token_set".to_owned(), json!(view.auth_token_set));
        object.insert(
            "oauth_client_secret_set".to_owned(),
            json!(view.oauth_client_secret_set),
        );
        object.insert("headers".to_owned(), set_markers(&view.header_names));
        object.insert("env".to_owned(), set_markers(&view.env_names));
        object.insert("created_at".to_owned(), json!(view.created_at.to_rfc3339()));
        object.insert("updated_at".to_owned(), json!(view.updated_at.to_rfc3339()));
    }
    value
}

fn toolset_json(view: &ToolsetView) -> Value {
    let mut value = serde_json::to_value(&view.config).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.insert("created_at".to_owned(), json!(view.created_at.to_rfc3339()));
        object.insert("updated_at".to_owned(), json!(view.updated_at.to_rfc3339()));
    }
    value
}

fn provider_json(view: &ProviderView) -> Value {
    let mut value = serde_json::to_value(&view.config).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.insert("source".to_owned(), json!(view.source.as_str()));
        object.insert(
            "client_secret_set".to_owned(),
            json!(view.client_secret_set),
        );
        object.insert("position".to_owned(), json!(view.position));
        object.insert(
            "updated_at".to_owned(),
            json!(view.updated_at.map(|at| at.to_rfc3339())),
        );
    }
    value
}

fn settings_json(settings: &GatewaySettings) -> Value {
    serde_json::to_value(settings).unwrap_or_default()
}

// -- routes -------------------------------------------------------------------

/// The `/api/v1/admin/config` routes with their guards, like `admin_api::router`.
pub(super) fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/admin/config/backends",
            get(handle_list_backends).post(handle_create_backend),
        )
        .route(
            "/api/v1/admin/config/backends/{name}",
            get(handle_get_backend)
                .put(handle_update_backend)
                .delete(handle_delete_backend),
        )
        .route(
            "/api/v1/admin/config/toolsets",
            get(handle_list_toolsets).post(handle_create_toolset),
        )
        .route(
            "/api/v1/admin/config/toolsets/{name}",
            get(handle_get_toolset)
                .put(handle_update_toolset)
                .delete(handle_delete_toolset),
        )
        .route(
            "/api/v1/admin/config/oidc-providers",
            get(handle_list_providers).post(handle_create_provider),
        )
        .route(
            "/api/v1/admin/config/oidc-providers/{id}",
            get(handle_get_provider)
                .put(handle_update_provider)
                .delete(handle_delete_provider),
        )
        .route(
            "/api/v1/admin/config/settings",
            get(handle_get_settings).put(handle_put_settings),
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
        .route_layer(middleware::from_fn_with_state(state, require_db_config))
}

/// The API does not exist outside database mode.
async fn require_db_config(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if state.db_config.is_none() || state.store.is_none() {
        return ConfigApiError::Admin(AdminError::NotFound).into_response();
    }
    next.run(request).await
}

fn ctx<'a>(state: &'a AppState, session: &SessionUser) -> Result<ConfigCtx<'a>, ConfigApiError> {
    ConfigCtx::from_state(state, session).ok_or_else(|| AdminError::NotFound.into())
}

/// `GET /api/v1/admin/config/backends`
async fn handle_list_backends(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Result<Json<Value>, ConfigApiError> {
    let views = ctx(&state, &session)?.list_backends().await?;
    let backends: Vec<Value> = views.iter().map(backend_json).collect();
    Ok(Json(json!({ "backends": backends })))
}

/// `POST /api/v1/admin/config/backends`
async fn handle_create_backend(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<Value>), ConfigApiError> {
    let input = backend_input(body, None)?;
    let view = ctx(&state, &session)?.create_backend(input).await?;
    Ok((StatusCode::CREATED, Json(backend_json(&view))))
}

/// `GET /api/v1/admin/config/backends/{name}`
async fn handle_get_backend(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> Result<Json<Value>, ConfigApiError> {
    let view = ctx(&state, &session)?.get_backend(&name).await?;
    Ok(Json(backend_json(&view)))
}

/// `PUT /api/v1/admin/config/backends/{name}`
async fn handle_update_backend(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, ConfigApiError> {
    let input = backend_input(body, Some(&name))?;
    let view = ctx(&state, &session)?.update_backend(&name, input).await?;
    Ok(Json(backend_json(&view)))
}

/// `DELETE /api/v1/admin/config/backends/{name}`
async fn handle_delete_backend(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> Result<StatusCode, ConfigApiError> {
    ctx(&state, &session)?.delete_backend(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/admin/config/toolsets`
async fn handle_list_toolsets(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Result<Json<Value>, ConfigApiError> {
    let views = ctx(&state, &session)?.list_toolsets().await?;
    let toolsets: Vec<Value> = views.iter().map(toolset_json).collect();
    Ok(Json(json!({ "toolsets": toolsets })))
}

/// `POST /api/v1/admin/config/toolsets`
async fn handle_create_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<Value>), ConfigApiError> {
    let config = toolset_input(body, None)?;
    let view = ctx(&state, &session)?.create_toolset(config).await?;
    Ok((StatusCode::CREATED, Json(toolset_json(&view))))
}

/// `GET /api/v1/admin/config/toolsets/{name}`
async fn handle_get_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> Result<Json<Value>, ConfigApiError> {
    let view = ctx(&state, &session)?.get_toolset(&name).await?;
    Ok(Json(toolset_json(&view)))
}

/// `PUT /api/v1/admin/config/toolsets/{name}`
async fn handle_update_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, ConfigApiError> {
    let config = toolset_input(body, Some(&name))?;
    let view = ctx(&state, &session)?.update_toolset(&name, config).await?;
    Ok(Json(toolset_json(&view)))
}

/// `DELETE /api/v1/admin/config/toolsets/{name}`
async fn handle_delete_toolset(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(name): ApiPath<String>,
) -> Result<StatusCode, ConfigApiError> {
    ctx(&state, &session)?.delete_toolset(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/admin/config/oidc-providers`: the environment provider first
async fn handle_list_providers(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Result<Json<Value>, ConfigApiError> {
    let views = ctx(&state, &session)?.list_providers().await?;
    let providers: Vec<Value> = views.iter().map(provider_json).collect();
    Ok(Json(json!({ "providers": providers })))
}

/// `POST /api/v1/admin/config/oidc-providers`
async fn handle_create_provider(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<Value>,
) -> Result<(StatusCode, Json<Value>), ConfigApiError> {
    let input = provider_input(body, None)?;
    let view = ctx(&state, &session)?.create_provider(input).await?;
    Ok((StatusCode::CREATED, Json(provider_json(&view))))
}

/// `GET /api/v1/admin/config/oidc-providers/{id}`
async fn handle_get_provider(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<Value>, ConfigApiError> {
    let view = ctx(&state, &session)?.get_provider(&id).await?;
    Ok(Json(provider_json(&view)))
}

/// `PUT /api/v1/admin/config/oidc-providers/{id}`
async fn handle_update_provider(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<String>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, ConfigApiError> {
    let input = provider_input(body, Some(&id))?;
    let view = ctx(&state, &session)?.update_provider(&id, input).await?;
    Ok(Json(provider_json(&view)))
}

/// `DELETE /api/v1/admin/config/oidc-providers/{id}`
async fn handle_delete_provider(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(id): ApiPath<String>,
) -> Result<StatusCode, ConfigApiError> {
    ctx(&state, &session)?.delete_provider(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/admin/config/settings`
async fn handle_get_settings(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> Result<Json<Value>, ConfigApiError> {
    let settings = ctx(&state, &session)?.settings().await?;
    Ok(Json(settings_json(&settings)))
}

/// `PUT /api/v1/admin/config/settings`
async fn handle_put_settings(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiJson(body): ApiJson<Value>,
) -> Result<Json<Value>, ConfigApiError> {
    let settings = settings_input(body)?;
    let saved = ctx(&state, &session)?.put_settings(settings).await?;
    Ok(Json(settings_json(&saved)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_on_update_keeps_clears_or_sets() {
        assert_eq!(updated_secret(None, Some("old")), Some("old".to_owned()));
        assert_eq!(updated_secret(Some(String::new()), Some("old")), None);
        assert_eq!(
            updated_secret(Some("new".to_owned()), Some("old")),
            Some("new".to_owned())
        );
        assert_eq!(updated_secret(None, None), None);
    }

    #[test]
    fn a_secret_map_on_update_keeps_null_and_drops_missing_keys() {
        let stored = BTreeMap::from([
            ("A".to_owned(), "1".to_owned()),
            ("B".to_owned(), "2".to_owned()),
        ]);
        let given = BTreeMap::from([
            ("A".to_owned(), None),
            ("C".to_owned(), Some("3".to_owned())),
            ("D".to_owned(), None),
        ]);
        let merged = updated_map(given, &stored);
        assert_eq!(
            merged,
            BTreeMap::from([
                ("A".to_owned(), "1".to_owned()),
                ("C".to_owned(), "3".to_owned()),
                ("D".to_owned(), String::new()),
            ])
        );
    }

    #[test]
    fn only_a_new_destination_counts_as_a_change() {
        let base = BackendConfig {
            name: "wiki".to_owned(),
            url: Some("http://a/mcp".to_owned()),
            transport: TransportType::Http,
            ..BackendConfig::default()
        };
        let same = BackendConfig {
            enabled: false,
            timeout_secs: 5,
            ..base.clone()
        };
        assert!(!destination_changed(&base, &same));
        let url = BackendConfig {
            url: Some("http://b/mcp".to_owned()),
            ..base.clone()
        };
        assert!(destination_changed(&base, &url));
        let transport = BackendConfig {
            transport: TransportType::Sse,
            ..base.clone()
        };
        assert!(destination_changed(&base, &transport));
        let command = BackendConfig {
            command: Some("run".to_owned()),
            ..base.clone()
        };
        assert!(destination_changed(&base, &command));
        let args = BackendConfig {
            args: Some(vec!["-x".to_owned()]),
            ..base.clone()
        };
        assert!(destination_changed(&base, &args));
    }

    #[test]
    fn a_backend_body_splits_its_secret_fields_off() {
        let body = json!({
            "name": "wiki",
            "transport": "http",
            "url": "http://localhost:9000/mcp",
            "auth_token": "tok",
            "headers": { "X-Key": null, "X-New": "v" },
            "oauth_client_secret": "shh",
        });
        let input = backend_input(body, Some("wiki")).unwrap();
        assert_eq!(input.config.auth_token.as_deref(), Some("tok"));
        assert_eq!(input.oauth_client_secret.as_deref(), Some("shh"));
        assert_eq!(input.headers.get("X-Key"), Some(&None));
        assert_eq!(input.headers.get("X-New"), Some(&Some("v".to_owned())));
        assert!(input.config.headers.is_empty());
    }

    #[test]
    fn a_body_that_names_another_backend_than_the_url_is_refused() {
        let body = json!({ "name": "other", "transport": "http" });
        assert!(backend_input(body, Some("wiki")).is_err());
        let body = json!({ "transport": "http", "url": "http://x/mcp" });
        let input = backend_input(body, Some("wiki")).unwrap();
        assert_eq!(input.config.name, "wiki");
    }

    #[test]
    fn a_backend_response_has_no_secret_value() {
        let view = BackendView {
            config: BackendConfig {
                name: "wiki".to_owned(),
                url: Some("http://localhost:9000/mcp".to_owned()),
                transport: TransportType::Http,
                ..BackendConfig::default()
            },
            auth_token_set: true,
            oauth_client_secret_set: false,
            header_names: vec!["X-Key".to_owned()],
            env_names: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let value = backend_json(&view);
        assert_eq!(value["auth_token_set"], true);
        assert!(value.get("auth_token").is_none());
        assert_eq!(value["headers"]["X-Key"], "set");
    }
}
