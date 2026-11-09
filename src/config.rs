//! Configuration types for the MCP Gateway
//!
//! Example config.toml:
//! ```toml
//! [gateway]
//! bind = "0.0.0.0:8080"
//! base_url = "http://localhost:8080"
//! auth_token = "your-secret-token"  # optional
//!
//! [[backends]]
//! name = "homeassistant"
//! url = "http://localhost:3001/mcp"
//! transport = "sse"
//!
//! [[backends]]
//! name = "jellyfin"
//! url = "http://localhost:3002/mcp"
//! transport = "http"
//!
//! [[backends]]
//! name = "proxmox"
//! command = "/usr/local/bin/proxmox-mcp"
//! args = ["--config", "/etc/proxmox-mcp.toml"]
//! transport = "stdio"
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub gateway: GatewayConfig,
    pub backends: Vec<BackendConfig>,
    /// Named API tokens with permissions
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
    /// Tool groups: expose subsets of tools via different path prefixes
    #[serde(default)]
    pub groups: Vec<ToolGroupConfig>,
    /// Optional Postgres store; without it the gateway runs standalone.
    /// Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub database: Option<crate::store::DatabaseConfig>,
    /// How people log in to the dashboard (OIDC providers).
    /// Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub auth: AuthConfig,
}

/// `[auth]` section: how people log in to the dashboard.
/// Not hot-reloadable: changes need a restart.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// OIDC providers offered on the login page, in this order
    #[serde(default)]
    pub oidc: Vec<OidcProviderConfig>,
}

/// A generic OIDC provider (Entra, Pocket ID, Keycloak, ...)
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    /// Stable id used in URLs and stored with each session: `[a-z0-9-]+`
    pub id: String,
    /// Button label on the login page; defaults to the id
    #[serde(default)]
    pub display_name: Option<String>,
    /// Issuer URL; discovery is `{issuer}/.well-known/openid-configuration`
    pub issuer: String,
    pub client_id: String,
    /// Env var holding the client secret; unset for a public (PKCE-only) client
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// ID-token claim with the user's groups; a dotted path reaches into
    /// objects (`realm_access.roles`)
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// When non-empty, only these email domains may log in (case-insensitive)
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Members of any of these groups are gateway admins
    #[serde(default)]
    pub admin_groups: Vec<String>,
}

impl OidcProviderConfig {
    /// Button label: `display_name`, or the id when unset
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }
}

fn default_oidc_scopes() -> Vec<String> {
    ["openid", "profile", "email"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_groups_claim() -> String {
    String::from("groups")
}

/// Tool group configuration
///
/// Expose subsets of tools via different endpoints, e.g. `/mcp/coding`
/// only exposes tools matching the configured patterns.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolGroupConfig {
    /// Group name used as path suffix: `/mcp/{name}`
    pub name: String,
    /// Tool name patterns to include (supports `"backend_*"` globs)
    #[serde(default)]
    pub tools: Vec<String>,
    /// Backends to include (empty = all)
    #[serde(default)]
    pub backends: Vec<String>,
    /// Optional description for this group
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub bind: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Simple shared auth token (for backward compat)
    pub auth_token: Option<String>,
    /// Rate limit: max requests per minute per token (0 = unlimited)
    #[serde(default)]
    pub rate_limit_per_minute: u32,
}

fn default_base_url() -> String {
    String::from("http://localhost:8080")
}

/// Per-token configuration with permissions
#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    /// Display name for this token
    pub name: String,
    /// The secret token value
    pub token: String,
    /// Allowed tool patterns (empty = all tools allowed)
    /// Supports glob-like patterns: `"backend_*"` or specific `"backend_tool_name"`
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Allowed backends (empty = all backends allowed)
    #[serde(default)]
    pub allowed_backends: Vec<String>,
    /// Rate limit override for this token (0 = use global default)
    #[serde(default)]
    pub rate_limit_per_minute: u32,
    /// Custom metadata for this token (for future use)
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// Unique name, used as namespace prefix for tools
    pub name: String,

    /// For SSE/HTTP transports
    pub url: Option<String>,

    /// For stdio transport
    pub command: Option<String>,
    pub args: Option<Vec<String>>,

    /// Transport type: "sse", "http", or "stdio"
    pub transport: TransportType,

    /// Optional: only expose specific tools (empty = all)
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Optional: disable this backend without removing from config
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Optional: timeout for tool calls in seconds (default: 30)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Optional: health check interval in seconds (default: 30, 0 = disabled)
    #[serde(default = "default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,

    /// Optional: max consecutive failures before circuit breaker opens (default: 3)
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,

    /// Optional: circuit breaker cooldown in seconds (default: 60)
    #[serde(default = "default_circuit_breaker_cooldown_secs")]
    pub circuit_breaker_cooldown_secs: u64,

    /// Optional: auth token to send to this backend (Bearer token)
    pub auth_token: Option<String>,

    /// Optional: custom headers to send to this backend
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Optional: environment variables to set for stdio backends
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Default value for the `enabled` field when omitted from config
const fn default_enabled() -> bool {
    true
}

/// Default value for the `timeout_secs` field
const fn default_timeout_secs() -> u64 {
    30
}

/// Default value for the `health_check_interval_secs` field
const fn default_health_check_interval_secs() -> u64 {
    30
}

/// Default value for the `max_consecutive_failures` field
const fn default_max_consecutive_failures() -> u32 {
    3
}

/// Default value for the `circuit_breaker_cooldown_secs` field
const fn default_circuit_breaker_cooldown_secs() -> u64 {
    60
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: None,
            command: None,
            args: None,
            transport: TransportType::Sse,
            allowed_tools: Vec::new(),
            enabled: true,
            timeout_secs: default_timeout_secs(),
            health_check_interval_secs: default_health_check_interval_secs(),
            max_consecutive_failures: default_max_consecutive_failures(),
            circuit_breaker_cooldown_secs: default_circuit_breaker_cooldown_secs(),
            auth_token: None,
            headers: HashMap::new(),
            env: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Sse,
    Http,
    Stdio,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        let env_vars = load_env_vars(path)?;
        config.resolve_env_vars(&env_vars)?;

        config.validate()?;
        Ok(config)
    }

    /// [`Config::load`] for async contexts: the file and `.env` reads are
    /// blocking, so run them on the blocking pool instead of a runtime worker.
    pub async fn load_async(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || Self::load(path))
            .await
            .map_err(|e| ConfigError::ReadError(std::io::Error::other(e)))?
    }

    fn resolve_env_vars(&mut self, env_vars: &HashMap<String, String>) -> Result<(), ConfigError> {
        self.gateway.bind = resolve_placeholders(&self.gateway.bind, "gateway.bind", env_vars)?;
        self.gateway.base_url =
            resolve_placeholders(&self.gateway.base_url, "gateway.base_url", env_vars)?;
        self.gateway.auth_token = resolve_option_placeholder(
            self.gateway.auth_token.take(),
            "gateway.auth_token",
            env_vars,
        )?;

        for (index, token) in self.tokens.iter_mut().enumerate() {
            token.name =
                resolve_placeholders(&token.name, &format!("tokens[{index}].name"), env_vars)?;
            token.token =
                resolve_placeholders(&token.token, &format!("tokens[{index}].token"), env_vars)?;
            resolve_vec_placeholders(
                &mut token.allowed_tools,
                &format!("tokens[{index}].allowed_tools"),
                env_vars,
            )?;
            resolve_vec_placeholders(
                &mut token.allowed_backends,
                &format!("tokens[{index}].allowed_backends"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut token.metadata,
                &format!("tokens[{index}].metadata"),
                env_vars,
            )?;
        }

        for (index, backend) in self.backends.iter_mut().enumerate() {
            backend.name =
                resolve_placeholders(&backend.name, &format!("backends[{index}].name"), env_vars)?;
            backend.url = resolve_option_placeholder(
                backend.url.take(),
                &format!("backends[{index}].url"),
                env_vars,
            )?;
            backend.command = resolve_option_placeholder(
                backend.command.take(),
                &format!("backends[{index}].command"),
                env_vars,
            )?;
            if let Some(args) = backend.args.as_mut() {
                resolve_vec_placeholders(args, &format!("backends[{index}].args"), env_vars)?;
            }
            resolve_vec_placeholders(
                &mut backend.allowed_tools,
                &format!("backends[{index}].allowed_tools"),
                env_vars,
            )?;
            backend.auth_token = resolve_option_placeholder(
                backend.auth_token.take(),
                &format!("backends[{index}].auth_token"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut backend.headers,
                &format!("backends[{index}].headers"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut backend.env,
                &format!("backends[{index}].env"),
                env_vars,
            )?;
        }

        for (index, group) in self.groups.iter_mut().enumerate() {
            group.name =
                resolve_placeholders(&group.name, &format!("groups[{index}].name"), env_vars)?;
            resolve_vec_placeholders(
                &mut group.tools,
                &format!("groups[{index}].tools"),
                env_vars,
            )?;
            resolve_vec_placeholders(
                &mut group.backends,
                &format!("groups[{index}].backends"),
                env_vars,
            )?;
            group.description = resolve_option_placeholder(
                group.description.take(),
                &format!("groups[{index}].description"),
                env_vars,
            )?;
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for backend in &self.backends {
            // Reject bad custom headers here instead of silently dropping them
            // when the backend connects.
            for (name, value) in &backend.headers {
                let invalid = |part| ConfigError::InvalidHeader {
                    backend: backend.name.clone(),
                    header: name.clone(),
                    part,
                };
                if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(invalid("name"));
                }
                if http::HeaderValue::from_str(value).is_err() {
                    return Err(invalid("value"));
                }
            }

            match backend.transport {
                TransportType::Sse | TransportType::Http => {
                    if backend.url.is_none() {
                        return Err(ConfigError::MissingUrl {
                            name: backend.name.clone(),
                            transport: backend.transport,
                        });
                    }
                }
                TransportType::Stdio => {
                    if backend.command.is_none() {
                        return Err(ConfigError::MissingCommand {
                            name: backend.name.clone(),
                        });
                    }
                }
            }
        }

        self.validate_auth()
    }

    fn validate_auth(&self) -> Result<(), ConfigError> {
        if self.auth.oidc.is_empty() {
            return Ok(());
        }
        if self.database.is_none() {
            return Err(ConfigError::OidcRequiresDatabase);
        }

        let mut seen = std::collections::HashSet::new();
        for provider in &self.auth.oidc {
            let invalid = |reason: &str| ConfigError::InvalidOidcProvider {
                id: provider.id.clone(),
                reason: reason.to_string(),
            };

            if provider.id.is_empty()
                || !provider
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(invalid("id must be non-empty and match [a-z0-9-]+"));
            }
            if !seen.insert(provider.id.as_str()) {
                return Err(invalid("duplicate id"));
            }
            if !provider.scopes.iter().any(|scope| scope == "openid") {
                return Err(invalid("scopes must include \"openid\""));
            }
            let Ok(issuer) = reqwest::Url::parse(&provider.issuer) else {
                return Err(invalid("issuer is not a valid URL"));
            };
            let loopback = matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if issuer.scheme() != "https" && !(issuer.scheme() == "http" && loopback) {
                return Err(invalid(
                    "issuer must use https (http is only allowed for localhost)",
                ));
            }
            if provider.client_id.is_empty() {
                return Err(invalid("client_id must not be empty"));
            }
        }
        Ok(())
    }
}

fn load_env_vars(config_path: &Path) -> Result<HashMap<String, String>, ConfigError> {
    let mut env_vars: HashMap<String, String> = std::env::vars().collect();
    let env_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env");

    if env_path.exists() {
        let path_display = env_path.display().to_string();
        let iter =
            dotenvy::from_path_iter(&env_path).map_err(|source| ConfigError::EnvFileError {
                path: path_display.clone(),
                source,
            })?;

        for entry in iter {
            let (key, value) = entry.map_err(|source| ConfigError::EnvFileError {
                path: path_display.clone(),
                source,
            })?;
            env_vars.entry(key).or_insert(value);
        }
    }

    Ok(env_vars)
}

fn resolve_option_placeholder(
    value: Option<String>,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<Option<String>, ConfigError> {
    value
        .map(|v| resolve_placeholders(&v, field, env_vars))
        .transpose()
}

fn resolve_vec_placeholders(
    values: &mut [String],
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (index, value) in values.iter_mut().enumerate() {
        let resolved = resolve_placeholders(value, &format!("{field}[{index}]"), env_vars)?;
        value.clone_from(&resolved);
    }
    Ok(())
}

fn resolve_map_value_placeholders(
    values: &mut HashMap<String, String>,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (key, value) in values.iter_mut() {
        let resolved = resolve_placeholders(value, &format!("{field}.{key}"), env_vars)?;
        value.clone_from(&resolved);
    }
    Ok(())
}

fn resolve_placeholders(
    input: &str,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];

        let Some(end) = after_start.find('}') else {
            return Err(ConfigError::InvalidEnvPlaceholder {
                field: field.to_string(),
                value: input.to_string(),
            });
        };

        let var_name = &after_start[..end];
        if var_name.is_empty() {
            return Err(ConfigError::InvalidEnvPlaceholder {
                field: field.to_string(),
                value: input.to_string(),
            });
        }

        let var_value = env_vars
            .get(var_name)
            .ok_or_else(|| ConfigError::MissingEnvVar {
                var: var_name.to_string(),
                field: field.to_string(),
            })?;
        output.push_str(var_value);

        remaining = &after_start[end + 1..];
    }

    output.push_str(remaining);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::error::ConfigError;

    mod resolve_placeholders {
        use super::*;

        #[test]
        fn resolves_single_placeholder() {
            let env_vars = HashMap::from([(String::from("API_TOKEN"), String::from("abc123"))]);
            let resolved = resolve_placeholders("${API_TOKEN}", "gateway.auth_token", &env_vars)
                .expect("placeholder should resolve");
            assert_eq!(resolved, "abc123");
        }

        #[test]
        fn resolves_multiple_placeholders_in_one_value() {
            let env_vars = HashMap::from([
                (String::from("HOST"), String::from("localhost")),
                (String::from("PORT"), String::from("8080")),
            ]);
            let resolved =
                resolve_placeholders("http://${HOST}:${PORT}", "backends[0].url", &env_vars)
                    .expect("placeholders should resolve");
            assert_eq!(resolved, "http://localhost:8080");
        }

        #[test]
        fn errors_when_placeholder_is_missing() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${MISSING_TOKEN}", "tokens[0].token", &env_vars)
                .expect_err("missing placeholder should error");

            match error {
                ConfigError::MissingEnvVar { var, field } => {
                    assert_eq!(var, "MISSING_TOKEN");
                    assert_eq!(field, "tokens[0].token");
                }
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn returns_input_unchanged_without_placeholders() {
            let env_vars = HashMap::new();
            let result = resolve_placeholders("plain text", "field", &env_vars).unwrap();
            assert_eq!(result, "plain text");
        }

        #[test]
        fn errors_on_unclosed_placeholder() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${UNCLOSED", "field", &env_vars)
                .expect_err("unclosed placeholder should error");

            match error {
                ConfigError::InvalidEnvPlaceholder { field, value } => {
                    assert_eq!(field, "field");
                    assert_eq!(value, "${UNCLOSED");
                }
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn errors_on_empty_placeholder() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${}", "field", &env_vars)
                .expect_err("empty placeholder should error");

            match error {
                ConfigError::InvalidEnvPlaceholder { .. } => {}
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn preserves_text_around_placeholder() {
            let env_vars = HashMap::from([("VAR".to_string(), "value".to_string())]);
            let result = resolve_placeholders("prefix_${VAR}_suffix", "field", &env_vars).unwrap();
            assert_eq!(result, "prefix_value_suffix");
        }
    }

    mod config_validation {
        use super::*;

        #[test]
        fn sse_transport_requires_url() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "test".to_string(),
                    transport: TransportType::Sse,
                    url: None,
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            };

            let error = config.validate().expect_err("should require URL");
            match error {
                ConfigError::MissingUrl { name, transport } => {
                    assert_eq!(name, "test");
                    assert_eq!(transport, TransportType::Sse);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn http_transport_requires_url() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "http_backend".to_string(),
                    transport: TransportType::Http,
                    url: None,
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            };

            let error = config.validate().expect_err("should require URL");
            match error {
                ConfigError::MissingUrl { name, .. } => assert_eq!(name, "http_backend"),
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn stdio_transport_requires_command() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "stdio_backend".to_string(),
                    transport: TransportType::Stdio,
                    command: None,
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            };

            let error = config.validate().expect_err("should require command");
            match error {
                ConfigError::MissingCommand { name } => assert_eq!(name, "stdio_backend"),
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn valid_sse_config_passes() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "valid".to_string(),
                    transport: TransportType::Sse,
                    url: Some("http://localhost:3000".to_string()),
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            };

            config.validate().expect("valid config should pass");
        }

        fn config_with_header(name: &str, value: &str) -> Config {
            Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "hdr".to_string(),
                    transport: TransportType::Http,
                    url: Some("http://localhost:3000".to_string()),
                    headers: HashMap::from([(name.to_string(), value.to_string())]),
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            }
        }

        #[test]
        fn valid_custom_header_passes() {
            config_with_header("X-Api-Key", "secret")
                .validate()
                .expect("valid header should pass");
        }

        #[test]
        fn invalid_header_name_is_rejected() {
            let error = config_with_header("Bad Header", "v")
                .validate()
                .expect_err("space in header name");
            match error {
                ConfigError::InvalidHeader {
                    backend,
                    header,
                    part,
                } => {
                    assert_eq!(backend, "hdr");
                    assert_eq!(header, "Bad Header");
                    assert_eq!(part, "name");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn invalid_header_value_is_rejected_without_leaking_it() {
            let error = config_with_header("X-Api-Key", "line\nbreak-secret")
                .validate()
                .expect_err("newline in header value");
            assert!(matches!(
                error,
                ConfigError::InvalidHeader { part: "value", .. }
            ));
            assert!(!error.to_string().contains("secret"), "{error}");
        }

        #[test]
        fn valid_stdio_config_passes() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: vec![BackendConfig {
                    name: "stdio".to_string(),
                    transport: TransportType::Stdio,
                    command: Some("/usr/bin/mcp-server".to_string()),
                    args: Some(vec!["--config".to_string(), "file.toml".to_string()]),
                    ..Default::default()
                }],
                tokens: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
            };

            config.validate().expect("valid config should pass");
        }
    }

    mod config_parsing {
        use super::*;

        #[test]
        fn parses_minimal_config() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"

                [[backends]]
                name = "test"
                url = "http://localhost:3000"
                transport = "sse"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.gateway.bind, "0.0.0.0:8080");
            assert_eq!(config.backends.len(), 1);
            assert_eq!(config.backends[0].name, "test");
            assert_eq!(config.backends[0].transport, TransportType::Sse);
        }

        #[test]
        fn parses_full_backend_config() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"
                auth_token = "secret"
                rate_limit_per_minute = 100

                [[backends]]
                name = "full"
                url = "http://localhost:3000"
                transport = "http"
                enabled = false
                timeout_secs = 60
                health_check_interval_secs = 120
                max_consecutive_failures = 5
                circuit_breaker_cooldown_secs = 300
                auth_token = "backend_token"
                allowed_tools = ["tool1", "tool2"]

                [backends.headers]
                X-Custom = "value"

                [backends.env]
                MY_VAR = "my_value"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            let backend = &config.backends[0];

            assert_eq!(backend.name, "full");
            assert!(!backend.enabled);
            assert_eq!(backend.timeout_secs, 60);
            assert_eq!(backend.health_check_interval_secs, 120);
            assert_eq!(backend.max_consecutive_failures, 5);
            assert_eq!(backend.circuit_breaker_cooldown_secs, 300);
            assert_eq!(backend.auth_token, Some("backend_token".to_string()));
            assert_eq!(backend.allowed_tools, vec!["tool1", "tool2"]);
            assert_eq!(backend.headers.get("X-Custom"), Some(&"value".to_string()));
            assert_eq!(backend.env.get("MY_VAR"), Some(&"my_value".to_string()));
        }

        #[test]
        fn parses_stdio_backend() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"

                [[backends]]
                name = "stdio_server"
                command = "/usr/local/bin/mcp-server"
                args = ["--verbose", "--config", "/etc/mcp.toml"]
                transport = "stdio"

                [backends.env]
                DEBUG = "1"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            let backend = &config.backends[0];

            assert_eq!(backend.transport, TransportType::Stdio);
            assert_eq!(
                backend.command,
                Some("/usr/local/bin/mcp-server".to_string())
            );
            assert_eq!(
                backend.args,
                Some(vec![
                    "--verbose".to_string(),
                    "--config".to_string(),
                    "/etc/mcp.toml".to_string()
                ])
            );
            assert_eq!(backend.env.get("DEBUG"), Some(&"1".to_string()));
        }

        #[test]
        fn parses_tokens() {
            let toml = r#"
[gateway]
bind = "0.0.0.0:8080"

[[backends]]
name = "dummy"
url = "http://localhost"
transport = "http"

[[tokens]]
name = "admin"
token = "admin_secret"
allowed_tools = ["*"]
allowed_backends = ["backend1", "backend2"]
rate_limit_per_minute = 1000

[[tokens]]
name = "readonly"
token = "ro_token"
allowed_tools = ["*_read", "*_list"]
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.tokens.len(), 2);

            assert_eq!(config.tokens[0].name, "admin");
            assert_eq!(
                config.tokens[0].allowed_backends,
                vec!["backend1", "backend2"]
            );

            assert_eq!(config.tokens[1].name, "readonly");
            assert_eq!(config.tokens[1].allowed_tools, vec!["*_read", "*_list"]);
        }

        #[test]
        fn parses_tool_groups() {
            let toml = r#"
[gateway]
bind = "0.0.0.0:8080"

[[backends]]
name = "dummy"
url = "http://localhost"
transport = "http"

[[groups]]
name = "coding"
tools = ["*_read", "*_write"]
backends = ["vscode", "git"]
description = "Coding tools only"

[[groups]]
name = "readonly"
tools = ["*_read", "*_list", "*_get"]
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.groups.len(), 2);

            assert_eq!(config.groups[0].name, "coding");
            assert_eq!(config.groups[0].backends, vec!["vscode", "git"]);
            assert_eq!(
                config.groups[0].description,
                Some("Coding tools only".to_string())
            );

            assert_eq!(config.groups[1].name, "readonly");
            assert_eq!(config.groups[1].backends, Vec::<String>::new());
        }
    }

    mod load_async {
        use super::*;

        #[tokio::test]
        async fn loads_a_config_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            std::fs::write(&path, "backends = []\n[gateway]\nbind = \"127.0.0.1:0\"\n").unwrap();

            let config = Config::load_async(&path).await.unwrap();
            assert_eq!(config.gateway.bind, "127.0.0.1:0");
        }

        #[tokio::test]
        async fn missing_file_is_a_read_error() {
            let dir = tempfile::tempdir().unwrap();
            let error = Config::load_async(dir.path().join("absent.toml"))
                .await
                .expect_err("missing file must fail");
            assert!(matches!(error, ConfigError::ReadError(_)), "{error:?}");
        }
    }

    mod auth_config {
        use super::*;

        const BASE: &str = r#"
            [gateway]
            bind = "0.0.0.0:8080"

            [[backends]]
            name = "b"
            transport = "http"
            url = "http://localhost:9000"
        "#;

        fn parse(extra: &str) -> Config {
            toml::from_str(&format!("{BASE}\n{extra}")).expect("should parse")
        }

        fn with_db(extra: &str) -> Config {
            parse(&format!("[database]\n{extra}"))
        }

        fn provider(id: &str, issuer: &str) -> String {
            format!("[[auth.oidc]]\nid = \"{id}\"\nissuer = \"{issuer}\"\nclient_id = \"cid\"\n")
        }

        fn invalid_reason(config: &Config) -> String {
            match config.validate().expect_err("should be invalid") {
                ConfigError::InvalidOidcProvider { reason, .. } => reason,
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn absent_auth_is_empty() {
            let config = parse("");
            assert!(config.auth.oidc.is_empty());
            config.validate().expect("no providers is valid");
        }

        #[test]
        fn parses_two_providers_with_defaults() {
            let config = parse(
                r#"
                [database]

                [[auth.oidc]]
                id = "entra"
                display_name = "Microsoft"
                issuer = "https://login.microsoftonline.com/t/v2.0"
                client_id = "abc"
                client_secret_env = "AXON_OIDC_ENTRA_SECRET"
                admin_groups = ["g1"]

                [[auth.oidc]]
                id = "pocket-id"
                issuer = "https://id.homelab.internal"
                client_id = "def"
                scopes = ["openid", "groups"]
                groups_claim = "realm_access.roles"
                allowed_email_domains = ["example.com"]
                "#,
            );
            config.validate().expect("valid config should pass");

            let [entra, pocket] = config.auth.oidc.as_slice() else {
                panic!("expected two providers");
            };
            assert_eq!(entra.display_name(), "Microsoft");
            assert_eq!(entra.scopes, ["openid", "profile", "email"]);
            assert_eq!(entra.groups_claim, "groups");
            assert_eq!(
                entra.client_secret_env.as_deref(),
                Some("AXON_OIDC_ENTRA_SECRET")
            );
            assert_eq!(entra.admin_groups, ["g1"]);
            assert_eq!(pocket.display_name(), "pocket-id");
            assert_eq!(pocket.scopes, ["openid", "groups"]);
            assert_eq!(pocket.groups_claim, "realm_access.roles");
            assert!(pocket.client_secret_env.is_none());
            assert_eq!(pocket.allowed_email_domains, ["example.com"]);
        }

        #[test]
        fn oidc_requires_database() {
            let config = parse(&provider("a", "https://idp.example.com"));
            assert!(matches!(
                config.validate(),
                Err(ConfigError::OidcRequiresDatabase)
            ));
        }

        #[test]
        fn rejects_bad_ids() {
            for id in ["", "Upper", "under_score", "sp ace"] {
                let config = with_db(&provider(id, "https://idp.example.com"));
                assert!(invalid_reason(&config).contains("id"), "{id:?}");
            }
        }

        #[test]
        fn rejects_duplicate_ids() {
            let extra = format!(
                "{}{}",
                provider("a", "https://one.example.com"),
                provider("a", "https://two.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("duplicate"));
        }

        #[test]
        fn rejects_scopes_without_openid() {
            let extra = format!(
                "{}scopes = [\"profile\"]\n",
                provider("a", "https://idp.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("openid"));
        }

        #[test]
        fn rejects_bad_issuers() {
            for issuer in ["not a url", "http://idp.example.com", "ftp://localhost"] {
                let config = with_db(&provider("a", issuer));
                assert!(invalid_reason(&config).contains("issuer"), "{issuer:?}");
            }
        }

        #[test]
        fn allows_http_for_loopback_and_trailing_slash() {
            for issuer in [
                "http://localhost:8081/realms/x",
                "http://127.0.0.1:8081",
                "http://[::1]:8081",
                "https://idp.example.com/",
            ] {
                with_db(&provider("a", issuer))
                    .validate()
                    .unwrap_or_else(|e| panic!("{issuer}: {e}"));
            }
        }

        #[test]
        fn rejects_empty_client_id() {
            let extra = "[[auth.oidc]]\nid = \"a\"\nissuer = \"https://idp.example.com\"\nclient_id = \"\"\n";
            assert!(invalid_reason(&with_db(extra)).contains("client_id"));
        }
    }

    mod backend_config_defaults {
        use super::*;

        #[test]
        fn default_values_are_set() {
            let config = BackendConfig::default();

            assert!(config.enabled);
            assert_eq!(config.timeout_secs, 30);
            assert_eq!(config.health_check_interval_secs, 30);
            assert_eq!(config.max_consecutive_failures, 3);
            assert_eq!(config.circuit_breaker_cooldown_secs, 60);
            assert_eq!(config.allowed_tools, Vec::<String>::new());
            assert!(config.headers.is_empty());
            assert!(config.env.is_empty());
        }
    }
}
