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

    use super::resolve_placeholders;
    use crate::error::ConfigError;

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
        let resolved = resolve_placeholders("http://${HOST}:${PORT}", "backends[0].url", &env_vars)
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
}
