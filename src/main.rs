//! MCP Gateway - Aggregate multiple MCP servers into one
//!
//! Usage:
//!   mcp-gateway --config config.toml
//!
//! Or with environment variable:
//!   `MCP_GATEWAY_CONFIG=config.toml` mcp-gateway

mod auth;
mod backend;
mod config;
mod error;
mod gateway;
mod metrics;
mod registry;
mod server;
mod types;
mod watcher;

use std::env;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use tokio::sync::broadcast;

use color_eyre::eyre::{Result, WrapErr};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::auth::AuthManager;
use crate::config::Config;
use crate::gateway::GatewayActor;
use crate::registry::RegistryActor;
use crate::server::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // Install color_eyre for pretty error reporting
    color_eyre::install()?;

    // Check if JSON logging is requested
    let json_logging = env::var("AXON_LOG_JSON").is_ok();

    // Initialize logging
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("axon_gateway=debug".parse()?)
        .add_directive("info".parse()?);

    if json_logging {
        // JSON logging for production/structured log aggregation
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        // Pretty logging for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!("Starting Axon Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config_path = env::args()
        .nth(1)
        .or_else(|| env::var("AXON_GATEWAY_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    tracing::info!("Loading config from: {}", config_path);
    let config = Config::load(&config_path)
        .wrap_err_with(|| format!("failed to load config from '{config_path}'"))?;

    let bind_addr = config.gateway.bind.clone();

    // Initialize Prometheus metrics exporter
    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .wrap_err("failed to install Prometheus metrics recorder")?;
    tracing::info!("Prometheus metrics available at /metrics");

    // Initialize auth manager
    let auth_manager = Arc::new(AuthManager::new(&config.gateway, &config.tokens));
    if auth_manager.auth_required() {
        tracing::info!("Authentication enabled");
    } else {
        tracing::warn!("No authentication configured - gateway is open");
    }

    // Spawn registry actor (with tool groups if configured)
    let registry = if config.groups.is_empty() {
        kameo::spawn(RegistryActor::new())
    } else {
        tracing::info!(
            "Tool groups configured: {:?}",
            config.groups.iter().map(|g| &g.name).collect::<Vec<_>>()
        );
        kameo::spawn(RegistryActor::with_groups(config.groups.clone()))
    };

    // Spawn gateway actor
    let gateway = kameo::spawn(GatewayActor::new(config, registry));

    // Give actors time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Start config file watcher for hot reload
    if let Err(e) = watcher::start_config_watcher(&config_path, gateway.clone()) {
        tracing::warn!(
            "Failed to start config watcher: {}. Hot reload disabled.",
            e
        );
    }

    // Start HTTP server
    let state = AppState {
        gateway,
        auth_manager,
        config_path: Some(config_path),
        ui_events: broadcast::channel(256).0,
        sse_clients: Arc::new(AtomicU64::new(0)),
        started_at: SystemTime::now(),
        process_id: std::process::id(),
        metrics_handle,
    };

    server::serve(state, &bind_addr)
        .await
        .wrap_err_with(|| format!("failed to start server on '{bind_addr}'"))?;

    Ok(())
}
