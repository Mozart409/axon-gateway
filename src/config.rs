//! Configuration types for the MCP Gateway
//!
//! Example config.toml:
//! ```toml
//! [gateway]
//! bind = "0.0.0.0:8080"
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
    /// Simple shared auth token (for backward compat)
    pub auth_token: Option<String>,
    /// Rate limit: max requests per minute per token (0 = unlimited)
    #[serde(default)]
    pub rate_limit_per_minute: u32,
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
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
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
