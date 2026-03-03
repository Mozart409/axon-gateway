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

use crate::error::ConfigError;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub gateway: GatewayConfig,
    pub backends: Vec<BackendConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub bind: String,
    pub auth_token: Option<String>,
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
    #[allow(dead_code)]
    pub allowed_tools: Vec<String>,

    /// Optional: disable this backend without removing from config
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

/// Default value for the `enabled` field when omitted from config
const fn default_enabled() -> bool {
    true
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
