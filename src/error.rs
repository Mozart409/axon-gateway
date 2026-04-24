//! Error types for the MCP Gateway
//!
//! Uses `thiserror` for structured error types in internal APIs,
//! and `color_eyre` for user-facing error presentation.

use crate::config::TransportType;
use thiserror::Error;

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file")]
    ReadError(#[from] std::io::Error),

    #[error("invalid TOML in config file")]
    ParseError(#[from] toml::de::Error),

    #[error("failed to read .env file at '{path}'")]
    EnvFileError {
        path: String,
        #[source]
        source: dotenvy::Error,
    },

    #[error("missing environment variable '{var}' referenced by '{field}'")]
    MissingEnvVar { var: String, field: String },

    #[error("invalid environment variable placeholder in '{field}': '{value}'")]
    InvalidEnvPlaceholder { field: String, value: String },

    #[error("backend '{name}' uses {transport:?} transport but has no url")]
    MissingUrl {
        name: String,
        transport: TransportType,
    },

    #[error("backend '{name}' uses stdio transport but has no command")]
    MissingCommand { name: String },
}

/// Server errors
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("failed to bind to address '{address}'")]
    BindFailed {
        address: String,
        #[source]
        source: std::io::Error,
    },

    #[error("server error")]
    Serve(#[from] std::io::Error),
}

/// Backend errors
#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum BackendError {
    #[error("backend '{name}' connection failed: {reason}")]
    ConnectionFailed { name: String, reason: String },

    #[error("backend '{name}' tool call timed out after {timeout_secs}s")]
    Timeout { name: String, timeout_secs: u64 },

    #[error("backend '{name}' circuit breaker is open")]
    CircuitBreakerOpen { name: String },

    #[error("backend '{name}' is not connected (state: {state:?})")]
    NotConnected {
        name: String,
        state: crate::types::BackendState,
    },

    #[error("backend '{name}' tool call failed: {reason}")]
    ToolCallFailed { name: String, reason: String },
}
