//! The gateway's configuration in the database, assembled into the runtime
//! [`Config`]
//!
//! [`load`] reads the configuration tables, unseals the secrets and builds the
//! one `Config` type the rest of the gateway runs on: bind address, base URL and
//! stdio permission from the [`Bootstrap`] environment, everything else from
//! rows. The write side of the API splits a full [`BackendConfig`] into a spec
//! without secrets (what the `spec` column holds) and the [`BackendSecrets`]
//! that get sealed, and merges them again here.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bootstrap::{Bootstrap, ENV_DATABASE_URL};
use crate::config::{
    AuthConfig, BackendConfig, Config, GatewayConfig, GatewaySettings, OidcProviderConfig,
    ToolsetConfig, TransportType,
};
use crate::crypto::{CryptoError, Keyring, Sealed};
use crate::error::ConfigError;
use crate::store::{
    DatabaseConfig, GatewayBackendRow, GatewaySettingsRow, GatewayToolsetRow, OidcProviderRow,
    SealedColumns, Store, StoreError,
};

/// Errors from assembling the configuration
#[derive(Debug, Error)]
pub enum DbConfigError {
    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("the stored configuration is invalid: {0}")]
    Invalid(#[from] ConfigError),
}

/// What a replica needs to reload and to change the stored configuration:
/// the key that seals the secrets and the bootstrap environment
#[derive(Clone, Debug)]
pub struct DbConfigContext {
    pub keyring: Arc<Keyring>,
    pub bootstrap: Arc<Bootstrap>,
}

/// The secret values of one backend, sealed together in one column set
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSecrets {
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Every custom header value, by header name
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Every environment variable value of a stdio backend, by name
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
}

impl BackendSecrets {
    /// Nothing to seal
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.auth_token.is_none()
            && self.headers.is_empty()
            && self.env.is_empty()
            && self.oauth_client_secret.is_none()
    }

    /// The names of the secret values that are set, for the audit log: never
    /// the values. Headers and variables as `header:<name>` and `env:<name>`.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        if self.auth_token.is_some() {
            keys.push("auth_token".to_owned());
        }
        keys.extend(self.headers.keys().map(|name| format!("header:{name}")));
        keys.extend(self.env.keys().map(|name| format!("env:{name}")));
        if self.oauth_client_secret.is_some() {
            keys.push("oauth_client_secret".to_owned());
        }
        keys
    }
}

impl fmt::Debug for BackendSecrets {
    // By hand, so the values can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendSecrets")
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "<redacted>"),
            )
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field(
                "oauth_client_secret",
                &self.oauth_client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

fn backend_aad(name: &str) -> String {
    format!("gateway-backend:{name}")
}

fn provider_aad(id: &str) -> String {
    format!("oidc-provider:{id}")
}

/// Seals the secrets of backend `name`; `None` when there are none.
///
/// # Errors
/// Fails when encryption fails.
pub fn seal_backend_secrets(
    keyring: &Keyring,
    name: &str,
    secrets: &BackendSecrets,
) -> Result<Option<SealedColumns>, CryptoError> {
    if secrets.is_empty() {
        return Ok(None);
    }
    let payload = serde_json::to_vec(secrets).map_err(|_| CryptoError::Encrypt)?;
    keyring
        .seal(&payload, backend_aad(name).as_bytes())
        .map(|sealed| Some(SealedColumns::from(sealed)))
}

/// Opens the sealed secrets of backend `name`; the error is safe to log.
///
/// # Errors
/// Fails when the data does not decrypt (wrong key or backend) or is damaged.
pub fn open_backend_secrets(
    keyring: &Keyring,
    name: &str,
    sealed: &SealedColumns,
) -> Result<BackendSecrets, String> {
    let payload = keyring
        .open(&Sealed::from(sealed), backend_aad(name).as_bytes())
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&payload)
        .map_err(|_| String::from("the stored secrets are not a valid backend secret object"))
}

/// Seals the client secret of OIDC provider `id`.
///
/// # Errors
/// Fails when encryption fails.
pub fn seal_provider_secret(
    keyring: &Keyring,
    id: &str,
    secret: &str,
) -> Result<SealedColumns, CryptoError> {
    keyring
        .seal(secret.as_bytes(), provider_aad(id).as_bytes())
        .map(SealedColumns::from)
}

/// Opens the sealed client secret of OIDC provider `id`; the error is safe to log.
///
/// # Errors
/// Fails when the data does not decrypt (wrong key or provider) or is not text.
pub fn open_provider_secret(
    keyring: &Keyring,
    id: &str,
    sealed: &SealedColumns,
) -> Result<String, String> {
    let payload = keyring
        .open(&Sealed::from(sealed), provider_aad(id).as_bytes())
        .map_err(|error| error.to_string())?;
    String::from_utf8(payload).map_err(|_| String::from("the stored client secret is not text"))
}

/// Splits a backend into the spec the `spec` column holds and its secrets. The
/// spec has no secret value: `auth_token` is `None`, `headers` and `env` keep
/// their names with empty values, the OAuth client has no secret.
#[must_use]
pub fn split_backend(backend: &BackendConfig) -> (BackendConfig, BackendSecrets) {
    let mut spec = backend.clone();
    let secrets = BackendSecrets {
        auth_token: spec.auth_token.take(),
        headers: spec
            .headers
            .iter_mut()
            .map(|(name, value)| (name.clone(), std::mem::take(value)))
            .collect(),
        env: spec
            .env
            .iter_mut()
            .map(|(name, value)| (name.clone(), std::mem::take(value)))
            .collect(),
        oauth_client_secret: spec
            .oauth
            .as_mut()
            .and_then(|oauth| oauth.client_secret.take()),
    };
    if let Some(oauth) = spec.oauth.as_mut() {
        oauth.client_secret_env = None;
    }
    (spec, secrets)
}

/// The inverse of [`split_backend`]: puts the secrets back into the spec. A
/// header or variable the spec names but the secrets lack gets an empty value;
/// one only the secrets hold is dropped.
#[must_use]
pub fn merge_backend(spec: BackendConfig, secrets: &BackendSecrets) -> BackendConfig {
    let mut backend = spec;
    backend.auth_token.clone_from(&secrets.auth_token);
    for (name, value) in &mut backend.headers {
        *value = secrets.headers.get(name).cloned().unwrap_or_default();
    }
    for (name, value) in &mut backend.env {
        *value = secrets.env.get(name).cloned().unwrap_or_default();
    }
    if let Some(oauth) = backend.oauth.as_mut() {
        oauth.client_secret.clone_from(&secrets.oauth_client_secret);
    }
    backend
}

/// Splits a provider into the spec the `spec` column holds and its client
/// secret. The spec has neither the secret nor `client_secret_env`.
#[must_use]
pub fn split_provider(provider: &OidcProviderConfig) -> (OidcProviderConfig, Option<String>) {
    let mut spec = provider.clone();
    spec.client_secret_env = None;
    let secret = spec.client_secret.take();
    (spec, secret)
}

/// The inverse of [`split_provider`]
#[must_use]
pub fn merge_provider(spec: OidcProviderConfig, secret: Option<String>) -> OidcProviderConfig {
    OidcProviderConfig {
        client_secret: secret,
        ..spec
    }
}

/// Checks a whole configuration the way a reload would.
///
/// # Errors
/// The text of the first problem, fit for a 400 response.
pub fn validate(config: &Config) -> Result<(), String> {
    config.validate().map_err(|error| error.to_string())
}

/// Applies `change` to a copy of `current` and validates the result, so a write
/// is refused before it is stored.
///
/// # Errors
/// The text of the first problem, fit for a 400 response.
pub fn check_candidate(current: &Config, change: impl FnOnce(&mut Config)) -> Result<(), String> {
    let mut candidate = current.clone();
    change(&mut candidate);
    validate(&candidate)
}

/// The version of the stored configuration, for the replicas' backstop poll.
///
/// # Errors
/// Fails when the query fails.
pub async fn state_version(store: &Store) -> Result<i64, StoreError> {
    store.config_version().await
}

/// Reads the configuration tables and assembles the runtime [`Config`]. A row
/// that cannot be parsed or unsealed is skipped with a warning; the rest loads.
///
/// # Errors
/// Fails when a query fails or the assembled configuration is invalid.
pub async fn load(
    store: &Store,
    keyring: &Keyring,
    bootstrap: &Bootstrap,
) -> Result<Config, DbConfigError> {
    let rows = ConfigRows {
        settings: store.gateway_settings().await?,
        backends: store.list_gateway_backends().await?,
        toolsets: store.list_gateway_toolsets().await?,
        providers: store.list_oidc_providers().await?,
    };
    assemble(bootstrap, keyring, rows)
}

/// What the configuration tables hold
struct ConfigRows {
    settings: Option<GatewaySettingsRow>,
    backends: Vec<GatewayBackendRow>,
    toolsets: Vec<GatewayToolsetRow>,
    providers: Vec<OidcProviderRow>,
}

fn assemble(
    bootstrap: &Bootstrap,
    keyring: &Keyring,
    rows: ConfigRows,
) -> Result<Config, DbConfigError> {
    let settings = rows
        .settings
        .and_then(settings_from_row)
        .unwrap_or_default();

    let backends = rows
        .backends
        .into_iter()
        .filter_map(|row| backend_from_row(keyring, row))
        .filter(|backend| {
            let off = backend.transport == TransportType::Stdio && !bootstrap.allow_stdio;
            if off {
                tracing::warn!(
                    backend = %backend.name,
                    "skipping a stdio backend: start the gateway with AXON_ALLOW_STDIO=true to run it"
                );
            }
            !off
        })
        .collect();

    let toolsets = rows
        .toolsets
        .into_iter()
        .filter_map(|row| match serde_json::from_value::<ToolsetConfig>(row.spec) {
            Ok(mut toolset) => {
                toolset.name = row.name;
                Some(toolset)
            }
            Err(error) => {
                tracing::warn!(toolset = %row.name, %error, "skipping a toolset that does not parse");
                None
            }
        })
        .collect();

    let mut oidc: Vec<OidcProviderConfig> = bootstrap.oidc.iter().cloned().collect();
    for row in rows.providers {
        if oidc.iter().any(|provider| provider.id == row.id) {
            tracing::warn!(
                provider = %row.id,
                "ignoring a stored OIDC provider: the bootstrap environment defines one with the same id"
            );
            continue;
        }
        if let Some(provider) = provider_from_row(keyring, row) {
            oidc.push(provider);
        }
    }

    let config = Config {
        gateway: GatewayConfig {
            bind: bootstrap.bind.clone(),
            base_url: bootstrap.base_url.clone(),
            auth_token: None,
            rate_limit_per_minute: settings.rate_limit_per_minute,
            allow_stdio: bootstrap.allow_stdio,
            allowed_hosts: settings.allowed_hosts,
            idle_timeout_secs: settings.idle_timeout_secs,
        },
        backends,
        tokens: Vec::new(),
        toolsets,
        groups: Vec::new(),
        database: Some(DatabaseConfig {
            url_env: ENV_DATABASE_URL.to_owned(),
        }),
        auth: AuthConfig { oidc },
        rbac: crate::policy::RbacConfig::default(),
        personal_backends: settings.personal_backends,
    };
    config.validate()?;
    Ok(config)
}

fn settings_from_row(row: GatewaySettingsRow) -> Option<GatewaySettings> {
    match serde_json::from_value(row.spec) {
        Ok(settings) => Some(settings),
        Err(error) => {
            tracing::warn!(%error, "ignoring the stored gateway settings: they do not parse");
            None
        }
    }
}

fn backend_from_row(keyring: &Keyring, row: GatewayBackendRow) -> Option<BackendConfig> {
    let mut spec = match serde_json::from_value::<BackendConfig>(row.spec) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::warn!(backend = %row.name, %error, "skipping a backend that does not parse");
            return None;
        }
    };
    spec.name.clone_from(&row.name);
    let secrets = match &row.secret {
        Some(sealed) => match open_backend_secrets(keyring, &row.name, sealed) {
            Ok(secrets) => secrets,
            Err(error) => {
                tracing::warn!(backend = %row.name, %error, "skipping a backend whose secrets cannot be unsealed");
                return None;
            }
        },
        None => BackendSecrets::default(),
    };
    Some(merge_backend(spec, &secrets))
}

fn provider_from_row(keyring: &Keyring, row: OidcProviderRow) -> Option<OidcProviderConfig> {
    let mut spec = match serde_json::from_value::<OidcProviderConfig>(row.spec) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::warn!(provider = %row.id, %error, "skipping an OIDC provider that does not parse");
            return None;
        }
    };
    spec.id.clone_from(&row.id);
    let secret = match &row.secret {
        Some(sealed) => match open_provider_secret(keyring, &row.id, sealed) {
            Ok(secret) => Some(secret),
            Err(error) => {
                tracing::warn!(provider = %row.id, %error, "skipping an OIDC provider whose client secret cannot be unsealed");
                return None;
            }
        },
        None => None,
    };
    Some(merge_provider(spec, secret))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::config::{CredentialMode, UpstreamOAuthConfig};

    const KEK_A: &str = "a:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEK_B: &str = "b:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn keyring() -> Keyring {
        Keyring::from_text(KEK_A).unwrap()
    }

    fn secret_backend() -> BackendConfig {
        BackendConfig {
            name: "wiki".to_owned(),
            url: Some("http://localhost:9000/mcp".to_owned()),
            auth_token: Some("tok-123".to_owned()),
            headers: HashMap::from([("X-Api-Key".to_owned(), "hdr-456".to_owned())]),
            env: HashMap::from([("API_KEY".to_owned(), "env-789".to_owned())]),
            transport: TransportType::Http,
            credential_mode: CredentialMode::OAuth,
            oauth: Some(UpstreamOAuthConfig {
                client_id: "cid".to_owned(),
                client_secret_env: Some("WIKI_SECRET".to_owned()),
                client_secret: Some("oauth-abc".to_owned()),
                scopes: vec!["read".to_owned()],
            }),
            ..BackendConfig::default()
        }
    }

    fn bootstrap(vars: &[(&str, &str)]) -> Bootstrap {
        let vars = vars
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        Bootstrap::from_vars(&vars).unwrap()
    }

    fn backend_row(keyring: &Keyring, backend: &BackendConfig) -> GatewayBackendRow {
        let (spec, secrets) = split_backend(backend);
        GatewayBackendRow {
            name: backend.name.clone(),
            spec: serde_json::to_value(&spec).unwrap(),
            secret: seal_backend_secrets(keyring, &backend.name, &secrets).unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn provider(id: &str) -> OidcProviderConfig {
        OidcProviderConfig {
            id: id.to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            client_id: "cid".to_owned(),
            client_secret: Some("client-secret".to_owned()),
            ..OidcProviderConfig::default()
        }
    }

    fn provider_row(
        keyring: &Keyring,
        position: i32,
        provider: &OidcProviderConfig,
    ) -> OidcProviderRow {
        let (spec, secret) = split_provider(provider);
        OidcProviderRow {
            id: provider.id.clone(),
            position,
            spec: serde_json::to_value(&spec).unwrap(),
            secret: secret
                .map(|secret| seal_provider_secret(keyring, &provider.id, &secret).unwrap()),
            updated_at: Utc::now(),
        }
    }

    fn rows() -> ConfigRows {
        ConfigRows {
            settings: None,
            backends: Vec::new(),
            toolsets: Vec::new(),
            providers: Vec::new(),
        }
    }

    #[test]
    fn a_backend_splits_and_merges_back() {
        let backend = secret_backend();
        let (spec, secrets) = split_backend(&backend);
        let mut expected = backend.clone();
        // the env var name is a file-load detail that is not stored
        expected.oauth.as_mut().unwrap().client_secret_env = None;
        assert_eq!(merge_backend(spec, &secrets), expected);
    }

    #[test]
    fn a_spec_never_holds_a_secret_value() {
        let (spec, secrets) = split_backend(&secret_backend());
        assert_eq!(spec.auth_token, None);
        assert_eq!(spec.headers.get("X-Api-Key").map(String::as_str), Some(""));
        assert_eq!(spec.env.get("API_KEY").map(String::as_str), Some(""));
        let oauth = spec.oauth.as_ref().unwrap();
        assert_eq!(oauth.client_secret, None);
        assert_eq!(oauth.client_secret_env, None);

        let json = serde_json::to_string(&spec).unwrap();
        for value in ["tok-123", "hdr-456", "env-789", "oauth-abc", "WIKI_SECRET"] {
            assert!(!json.contains(value), "{value} leaked into {json}");
        }
        assert!(json.contains("X-Api-Key"), "header names stay: {json}");

        assert_eq!(secrets.auth_token.as_deref(), Some("tok-123"));
        assert_eq!(secrets.headers["X-Api-Key"], "hdr-456");
        assert_eq!(secrets.env["API_KEY"], "env-789");
        assert_eq!(secrets.oauth_client_secret.as_deref(), Some("oauth-abc"));
        assert_eq!(
            secrets.keys(),
            [
                "auth_token",
                "header:X-Api-Key",
                "env:API_KEY",
                "oauth_client_secret"
            ]
        );
    }

    #[test]
    fn a_backend_without_secrets_has_nothing_to_seal() {
        let backend = BackendConfig {
            name: "plain".to_owned(),
            url: Some("http://localhost:1".to_owned()),
            ..BackendConfig::default()
        };
        let (spec, secrets) = split_backend(&backend);
        assert!(secrets.is_empty());
        assert_eq!(spec, backend);
        assert_eq!(
            seal_backend_secrets(&keyring(), "plain", &secrets).unwrap(),
            None
        );
    }

    #[test]
    fn a_provider_splits_and_merges_back() {
        let mut full = provider("sso");
        full.client_secret_env = Some("SSO_SECRET".to_owned());
        let (spec, secret) = split_provider(&full);
        assert_eq!(spec.client_secret, None);
        assert_eq!(spec.client_secret_env, None);
        assert_eq!(secret.as_deref(), Some("client-secret"));
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            !json.contains("client-secret") && !json.contains("SSO_SECRET"),
            "{json}"
        );

        let merged = merge_provider(spec, secret);
        assert_eq!(merged.client_secret.as_deref(), Some("client-secret"));
    }

    #[test]
    fn secrets_are_bound_to_their_name_and_key() {
        let keyring = keyring();
        let (_, secrets) = split_backend(&secret_backend());
        let sealed = seal_backend_secrets(&keyring, "wiki", &secrets)
            .unwrap()
            .expect("something to seal");
        assert_eq!(
            open_backend_secrets(&keyring, "wiki", &sealed).unwrap(),
            secrets
        );
        assert!(open_backend_secrets(&keyring, "other", &sealed).is_err());
        let other_keys = Keyring::from_text(KEK_B).unwrap();
        assert!(open_backend_secrets(&other_keys, "wiki", &sealed).is_err());

        let sealed = seal_provider_secret(&keyring, "sso", "client-secret").unwrap();
        assert_eq!(
            open_provider_secret(&keyring, "sso", &sealed).unwrap(),
            "client-secret"
        );
        assert!(open_provider_secret(&keyring, "other", &sealed).is_err());
        // a backend's secrets do not open as a provider's, and the other way round
        assert!(open_backend_secrets(&keyring, "sso", &sealed).is_err());
    }

    #[test]
    fn the_secrets_debug_output_is_redacted() {
        let (_, secrets) = split_backend(&secret_backend());
        let debug = format!("{secrets:?}");
        for value in ["tok-123", "hdr-456", "env-789", "oauth-abc"] {
            assert!(!debug.contains(value), "{debug}");
        }
        assert!(debug.contains("X-Api-Key"), "{debug}");
    }

    #[test]
    fn rows_assemble_into_a_config() {
        let keyring = keyring();
        let mut rows = rows();
        rows.backends.push(backend_row(&keyring, &secret_backend()));
        rows.toolsets.push(GatewayToolsetRow {
            name: "coding".to_owned(),
            spec: json!({ "name": "coding", "tools": ["wiki_*"], "backends": [] }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        rows.providers
            .push(provider_row(&keyring, 0, &provider("a")));
        rows.providers
            .push(provider_row(&keyring, 1, &provider("b")));
        rows.settings = Some(GatewaySettingsRow {
            spec: json!({ "rate_limit_per_minute": 60, "allowed_hosts": ["axon.example.com"] }),
        });

        let bootstrap = bootstrap(&[
            ("AXON_BIND", "127.0.0.1:9000"),
            ("AXON_BASE_URL", "https://axon.example.com"),
        ]);
        let config = assemble(&bootstrap, &keyring, rows).unwrap();

        assert_eq!(config.gateway.bind, "127.0.0.1:9000");
        assert_eq!(config.gateway.base_url, "https://axon.example.com");
        assert_eq!(config.gateway.auth_token, None);
        assert_eq!(config.gateway.rate_limit_per_minute, 60);
        assert_eq!(config.gateway.allowed_hosts, ["axon.example.com"]);
        assert_eq!(
            config.gateway.idle_timeout_secs, 300,
            "a missing key defaults"
        );
        assert!(!config.gateway.allow_stdio);
        assert!(config.tokens.is_empty());
        assert_eq!(
            config.database.as_ref().map(|d| d.url_env.as_str()),
            Some("AXON_DATABASE_URL")
        );

        let [backend] = config.backends.as_slice() else {
            panic!("one backend");
        };
        assert_eq!(backend.auth_token.as_deref(), Some("tok-123"));
        assert_eq!(backend.headers["X-Api-Key"], "hdr-456");
        assert_eq!(backend.env["API_KEY"], "env-789");
        assert_eq!(
            backend
                .oauth
                .as_ref()
                .and_then(|o| o.client_secret.as_deref()),
            Some("oauth-abc")
        );
        assert_eq!(config.toolsets[0].tools, ["wiki_*"]);
        // the rows' order (the store sorts by position), with their secrets
        let ids: Vec<&str> = config.auth.oidc.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        assert_eq!(
            config.auth.oidc[0].client_secret.as_deref(),
            Some("client-secret")
        );
    }

    #[test]
    fn the_bootstrap_provider_comes_first_and_wins_a_clash() {
        let keyring = keyring();
        let mut rows = rows();
        rows.providers
            .push(provider_row(&keyring, 0, &provider("sso")));
        rows.providers
            .push(provider_row(&keyring, 1, &provider("other")));

        let bootstrap = bootstrap(&[
            ("AXON_OIDC_ISSUER", "https://boot.example.com"),
            ("AXON_OIDC_CLIENT_ID", "boot"),
        ]);
        let config = assemble(&bootstrap, &keyring, rows).unwrap();

        let ids: Vec<&str> = config.auth.oidc.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["sso", "other"]);
        assert_eq!(config.auth.oidc[0].issuer, "https://boot.example.com");
        assert_eq!(config.auth.oidc[0].client_id, "boot");
    }

    #[test]
    fn bad_rows_are_skipped_and_the_rest_loads() {
        let keyring = keyring();
        let other_keys = Keyring::from_text(KEK_B).unwrap();
        let mut rows = rows();
        rows.backends.push(backend_row(&keyring, &secret_backend()));
        // sealed under a key this keyring does not know
        let mut stranger = secret_backend();
        stranger.name = "stranger".to_owned();
        rows.backends.push(backend_row(&other_keys, &stranger));
        // a spec that does not parse
        rows.backends.push(GatewayBackendRow {
            name: "broken".to_owned(),
            spec: json!({ "name": "broken", "transport": "carrier-pigeon" }),
            secret: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        rows.providers
            .push(provider_row(&other_keys, 0, &provider("lost")));
        rows.providers
            .push(provider_row(&keyring, 1, &provider("kept")));

        let config = assemble(&bootstrap(&[]), &keyring, rows).unwrap();
        let names: Vec<&str> = config.backends.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["wiki"]);
        let ids: Vec<&str> = config.auth.oidc.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["kept"]);
    }

    #[test]
    fn a_stdio_backend_needs_the_environment_switch() {
        let keyring = keyring();
        let stdio = BackendConfig {
            name: "local".to_owned(),
            transport: TransportType::Stdio,
            command: Some("/usr/bin/mcp".to_owned()),
            ..BackendConfig::default()
        };
        let build = |allow: &str| {
            let mut rows = rows();
            rows.backends.push(backend_row(&keyring, &stdio));
            assemble(&bootstrap(&[("AXON_ALLOW_STDIO", allow)]), &keyring, rows).unwrap()
        };
        assert!(
            build("false").backends.is_empty(),
            "{:?}",
            build("false").backends
        );
        assert_eq!(build("true").backends.len(), 1);
    }

    #[test]
    fn an_invalid_assembly_is_an_error() {
        let keyring = keyring();
        let mut rows = rows();
        // an OIDC provider with an issuer that is not a URL
        let mut bad = provider("bad");
        bad.issuer = "not a url".to_owned();
        rows.providers.push(provider_row(&keyring, 0, &bad));
        let error = assemble(&bootstrap(&[]), &keyring, rows).unwrap_err();
        assert!(matches!(error, DbConfigError::Invalid(_)), "{error:?}");
    }

    #[test]
    fn check_candidate_validates_a_change_without_applying_it() {
        let keyring = keyring();
        let config = assemble(&bootstrap(&[]), &keyring, rows()).unwrap();

        check_candidate(&config, |config| {
            config.backends.push(BackendConfig {
                name: "ok".to_owned(),
                url: Some("http://localhost:1".to_owned()),
                ..BackendConfig::default()
            });
        })
        .expect("a valid backend");

        let error = check_candidate(&config, |config| {
            config.backends.push(BackendConfig {
                name: "nourl".to_owned(),
                ..BackendConfig::default()
            });
        })
        .unwrap_err();
        assert!(error.contains("nourl"), "{error}");
        assert!(
            config.backends.is_empty(),
            "the current config is untouched"
        );
    }
}
