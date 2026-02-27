//! MCP Gateway - Aggregate multiple MCP servers into one
//!
//! Usage:
//!   mcp-gateway --config config.toml
//!
//! Or with environment variable:
//!   MCP_GATEWAY_CONFIG=config.toml mcp-gateway

mod backend;
mod config;
mod error;
mod gateway;
mod registry;
mod server;
mod types;

use color_eyre::eyre::{Result, WrapErr};
use config::Config;
use gateway::GatewayActor;
use registry::RegistryActor;
use server::AppState;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Install color_eyre for pretty error reporting
    color_eyre::install()?;

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mcp_gateway=debug".parse()?)
                .add_directive("info".parse()?),
        )
        .init();

    tracing::info!("Starting MCP Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config_path = env::args()
        .nth(1)
        .or_else(|| env::var("MCP_GATEWAY_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    tracing::info!("Loading config from: {}", config_path);
    let config = Config::load(&config_path)
        .wrap_err_with(|| format!("failed to load config from '{}'", config_path))?;

    let bind_addr = config.gateway.bind.clone();
    let auth_token = config.gateway.auth_token.clone();

    // Spawn registry actor
    let registry = kameo::spawn(RegistryActor::new());

    // Spawn gateway actor
    let gateway = kameo::spawn(GatewayActor::new(config, registry));

    // Give actors time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Start HTTP server
    let state = AppState {
        gateway,
        auth_token,
    };

    server::serve(state, &bind_addr)
        .await
        .wrap_err_with(|| format!("failed to start server on '{}'", bind_addr))?;

    Ok(())
}
