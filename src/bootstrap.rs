//! Bootstrap environment: the settings the gateway needs before it can read
//! its configuration from the database
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `AXON_DATABASE_URL` | Postgres URL; set means database mode |
//! | `AXON_BIND` | listen address, default `0.0.0.0:8080` |
//! | `AXON_BASE_URL` | public URL, default `http://localhost:8080` |
//! | `AXON_ALLOW_STDIO` | `true` or `1` lets stdio backends run; nothing else can turn it on |
//! | `AXON_OIDC_ISSUER` | with it, a bootstrap OIDC provider is configured |
//! | `AXON_OIDC_CLIENT_ID` | its client id (required with the issuer) |
//! | `AXON_OIDC_CLIENT_SECRET_FILE` | file holding its client secret (optional) |
//! | `AXON_OIDC_ADMIN_GROUPS` | comma separated groups whose members are admins |
//! | `AXON_OIDC_ID` | its id, default `sso` |
//! | `AXON_OIDC_DISPLAY_NAME` | its button label (optional) |
//!
//! The key-encryption keys (`AXON_KEK_FILE` / `AXON_KEK`) are read by
//! [`crate::crypto::Keyring::from_env`].

use std::collections::HashMap;

use thiserror::Error;

use crate::config::OidcProviderConfig;

/// Environment variable holding the database URL
pub const ENV_DATABASE_URL: &str = "AXON_DATABASE_URL";

const ENV_BIND: &str = "AXON_BIND";
const ENV_BASE_URL: &str = "AXON_BASE_URL";
const ENV_ALLOW_STDIO: &str = "AXON_ALLOW_STDIO";
const ENV_OIDC_ISSUER: &str = "AXON_OIDC_ISSUER";
const ENV_OIDC_CLIENT_ID: &str = "AXON_OIDC_CLIENT_ID";
const ENV_OIDC_CLIENT_SECRET_FILE: &str = "AXON_OIDC_CLIENT_SECRET_FILE";
const ENV_OIDC_ADMIN_GROUPS: &str = "AXON_OIDC_ADMIN_GROUPS";
const ENV_OIDC_ID: &str = "AXON_OIDC_ID";
const ENV_OIDC_DISPLAY_NAME: &str = "AXON_OIDC_DISPLAY_NAME";

const DEFAULT_BIND: &str = "0.0.0.0:8080";
const DEFAULT_BASE_URL: &str = "http://localhost:8080";
const DEFAULT_OIDC_ID: &str = "sso";

/// Errors from reading the bootstrap environment
#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("{ENV_OIDC_ISSUER} is set, so {ENV_OIDC_CLIENT_ID} is required")]
    MissingClientId,

    #[error("cannot read the OIDC client secret file {path}: {source}")]
    ReadSecretFile {
        path: String,
        source: std::io::Error,
    },

    #[error("the OIDC client secret file {path} is empty")]
    EmptySecretFile { path: String },
}

/// What the gateway reads from its environment instead of a config file
#[derive(Debug, Clone)]
pub struct Bootstrap {
    /// `AXON_DATABASE_URL`; set means database mode
    pub database_url: Option<String>,
    pub bind: String,
    pub base_url: String,
    /// `AXON_ALLOW_STDIO`: the only switch for stdio backends
    pub allow_stdio: bool,
    /// The provider of `AXON_OIDC_*`, listed first and read-only in the UI
    pub oidc: Option<OidcProviderConfig>,
    /// `AXON_OIDC_CLIENT_SECRET_FILE`: [`Bootstrap::from_vars`] only records
    /// the path, [`Bootstrap::from_env`] reads it into `oidc.client_secret`
    pub oidc_client_secret_file: Option<String>,
}

impl Bootstrap {
    /// Reads the process environment, and the client secret file if one is named.
    ///
    /// # Errors
    /// Fails when `AXON_OIDC_ISSUER` is set without a client id, or the secret
    /// file cannot be read or is empty.
    pub fn from_env() -> Result<Self, BootstrapError> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        let mut bootstrap = Self::from_vars(&vars)?;
        if let (Some(path), Some(oidc)) = (&bootstrap.oidc_client_secret_file, &mut bootstrap.oidc)
        {
            let text =
                std::fs::read_to_string(path).map_err(|source| BootstrapError::ReadSecretFile {
                    path: path.clone(),
                    source,
                })?;
            let secret = text.trim();
            if secret.is_empty() {
                return Err(BootstrapError::EmptySecretFile { path: path.clone() });
            }
            oidc.client_secret = Some(secret.to_owned());
        }
        Ok(bootstrap)
    }

    /// Builds the bootstrap settings from variables; touches no file.
    ///
    /// # Errors
    /// Fails when `AXON_OIDC_ISSUER` is set without a client id.
    pub fn from_vars(vars: &HashMap<String, String>) -> Result<Self, BootstrapError> {
        let get = |name: &str| {
            vars.get(name)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };

        let oidc = match get(ENV_OIDC_ISSUER) {
            Some(issuer) => {
                let client_id = get(ENV_OIDC_CLIENT_ID).ok_or(BootstrapError::MissingClientId)?;
                Some(OidcProviderConfig {
                    id: get(ENV_OIDC_ID).unwrap_or(DEFAULT_OIDC_ID).to_owned(),
                    display_name: get(ENV_OIDC_DISPLAY_NAME).map(str::to_owned),
                    issuer: issuer.to_owned(),
                    client_id: client_id.to_owned(),
                    admin_groups: get(ENV_OIDC_ADMIN_GROUPS)
                        .map(split_list)
                        .unwrap_or_default(),
                    ..OidcProviderConfig::default()
                })
            }
            None => None,
        };

        Ok(Self {
            database_url: get(ENV_DATABASE_URL).map(str::to_owned),
            bind: get(ENV_BIND).unwrap_or(DEFAULT_BIND).to_owned(),
            base_url: get(ENV_BASE_URL).unwrap_or(DEFAULT_BASE_URL).to_owned(),
            allow_stdio: get(ENV_ALLOW_STDIO).is_some_and(|value| value == "true" || value == "1"),
            oidc,
            oidc_client_secret_file: get(ENV_OIDC_CLIENT_SECRET_FILE).map(str::to_owned),
        })
    }
}

/// A comma separated list: trimmed, without empty entries
fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn an_empty_environment_has_the_defaults() {
        let bootstrap = Bootstrap::from_vars(&HashMap::new()).unwrap();
        assert_eq!(bootstrap.database_url, None);
        assert_eq!(bootstrap.bind, "0.0.0.0:8080");
        assert_eq!(bootstrap.base_url, "http://localhost:8080");
        assert!(!bootstrap.allow_stdio);
        assert!(bootstrap.oidc.is_none());
        assert_eq!(bootstrap.oidc_client_secret_file, None);
    }

    #[test]
    fn the_connection_variables_are_read() {
        let bootstrap = Bootstrap::from_vars(&vars(&[
            ("AXON_DATABASE_URL", "postgres://axon@db/axon"),
            ("AXON_BIND", "127.0.0.1:9000"),
            ("AXON_BASE_URL", "https://axon.example.com"),
        ]))
        .unwrap();
        assert_eq!(
            bootstrap.database_url.as_deref(),
            Some("postgres://axon@db/axon")
        );
        assert_eq!(bootstrap.bind, "127.0.0.1:9000");
        assert_eq!(bootstrap.base_url, "https://axon.example.com");
    }

    #[test]
    fn blank_variables_count_as_unset() {
        let bootstrap = Bootstrap::from_vars(&vars(&[
            ("AXON_DATABASE_URL", "  "),
            ("AXON_BIND", ""),
            ("AXON_OIDC_ISSUER", " "),
        ]))
        .unwrap();
        assert_eq!(bootstrap.database_url, None);
        assert_eq!(bootstrap.bind, "0.0.0.0:8080");
        assert!(bootstrap.oidc.is_none());
    }

    #[test]
    fn only_true_and_one_allow_stdio() {
        for (value, expected) in [
            ("true", true),
            ("1", true),
            (" true ", true),
            ("false", false),
            ("0", false),
            ("yes", false),
            ("on", false),
            ("", false),
        ] {
            let bootstrap = Bootstrap::from_vars(&vars(&[("AXON_ALLOW_STDIO", value)])).unwrap();
            assert_eq!(bootstrap.allow_stdio, expected, "{value:?}");
        }
    }

    #[test]
    fn the_provider_variables_build_a_provider() {
        let bootstrap = Bootstrap::from_vars(&vars(&[
            ("AXON_OIDC_ISSUER", "https://idp.example.com"),
            ("AXON_OIDC_CLIENT_ID", "axon"),
            ("AXON_OIDC_CLIENT_SECRET_FILE", "/run/secrets/oidc"),
            ("AXON_OIDC_ID", "pocket-id"),
            ("AXON_OIDC_DISPLAY_NAME", "Pocket ID"),
        ]))
        .unwrap();
        let oidc = bootstrap.oidc.expect("a provider");
        assert_eq!(oidc.id, "pocket-id");
        assert_eq!(oidc.display_name.as_deref(), Some("Pocket ID"));
        assert_eq!(oidc.issuer, "https://idp.example.com");
        assert_eq!(oidc.client_id, "axon");
        // the file is read by from_env, never by from_vars
        assert_eq!(oidc.client_secret, None);
        assert_eq!(oidc.client_secret_env, None);
        assert_eq!(
            bootstrap.oidc_client_secret_file.as_deref(),
            Some("/run/secrets/oidc")
        );
        // everything else is the struct's default
        let defaults = OidcProviderConfig::default();
        assert_eq!(oidc.scopes, defaults.scopes);
        assert_eq!(oidc.groups_claim, defaults.groups_claim);
        assert!(!oidc.accept_access_tokens);
        assert!(!oidc.graph_overage);
    }

    #[test]
    fn the_provider_id_defaults_to_sso() {
        let bootstrap = Bootstrap::from_vars(&vars(&[
            ("AXON_OIDC_ISSUER", "https://idp.example.com"),
            ("AXON_OIDC_CLIENT_ID", "axon"),
        ]))
        .unwrap();
        let oidc = bootstrap.oidc.expect("a provider");
        assert_eq!(oidc.id, "sso");
        assert_eq!(oidc.display_name, None);
        assert!(oidc.admin_groups.is_empty(), "{:?}", oidc.admin_groups);
    }

    #[test]
    fn an_issuer_without_a_client_id_is_an_error() {
        let error = Bootstrap::from_vars(&vars(&[("AXON_OIDC_ISSUER", "https://idp.example.com")]))
            .unwrap_err();
        assert!(
            matches!(error, BootstrapError::MissingClientId),
            "{error:?}"
        );
        assert!(error.to_string().contains("AXON_OIDC_CLIENT_ID"));
    }

    #[test]
    fn provider_variables_without_an_issuer_are_ignored() {
        let bootstrap = Bootstrap::from_vars(&vars(&[("AXON_OIDC_CLIENT_ID", "axon")])).unwrap();
        assert!(bootstrap.oidc.is_none());
    }

    #[test]
    fn admin_groups_are_split_and_trimmed() {
        let bootstrap = Bootstrap::from_vars(&vars(&[
            ("AXON_OIDC_ISSUER", "https://idp.example.com"),
            ("AXON_OIDC_CLIENT_ID", "axon"),
            ("AXON_OIDC_ADMIN_GROUPS", " ops , admins,, platform ,"),
        ]))
        .unwrap();
        let oidc = bootstrap.oidc.expect("a provider");
        assert_eq!(oidc.admin_groups, ["ops", "admins", "platform"]);
    }
}
