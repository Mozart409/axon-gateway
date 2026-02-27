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
