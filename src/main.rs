//! MCP Gateway - Aggregate multiple MCP servers into one
//!
//! Usage:
//!   mcp-gateway --config config.toml
//!
//! Or with environment variable:
//!   `MCP_GATEWAY_CONFIG=config.toml` mcp-gateway

mod auth;
mod authz;
mod backend;
mod config;
mod error;
mod gateway;
mod metrics;
mod oidc;
mod policy;
mod registry;
mod server;
mod store;
mod telemetry;
mod types;
mod watcher;

use std::env;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use tokio::sync::broadcast;

use color_eyre::eyre::{Result, WrapErr};

use kameo::actor::Spawn;
use kameo::mailbox;

use crate::auth::{AuthManager, SharedAuth};
use crate::config::Config;
use crate::gateway::GatewayActor;
use crate::oidc::OidcProviders;
use crate::registry::RegistryActor;
use crate::server::AppState;

/// How often expired dashboard sessions and login flows are deleted.
const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

#[tokio::main]
async fn main() -> Result<()> {
    // Install color_eyre for pretty error reporting
    color_eyre::install()?;

    // Logging, plus OTLP trace export when OTEL_EXPORTER_OTLP_*ENDPOINT is set
    let telemetry = telemetry::init(env::var("AXON_LOG_JSON").is_ok());

    tracing::info!("Starting Axon Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load config
    let config_path = env::args()
        .nth(1)
        .or_else(|| env::var("AXON_GATEWAY_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".to_string());

    tracing::info!("Loading config from: {}", config_path);
    let config = Config::load(&config_path)
        .wrap_err_with(|| format!("failed to load config from '{config_path}'"))?;

    let store = match &config.database {
        Some(database) => {
            let store = store::Store::connect(database)
                .await
                .wrap_err("failed to connect to the database")?;
            tracing::info!("Database connected, migrations applied");
            Some(store)
        }
        None => None,
    };

    let bind_addr = config.gateway.bind.clone();
    let base_url = config.gateway.base_url.clone();

    // Dashboard login. Built before `config` moves into the gateway actor.
    let oidc = setup_oidc(&config, &base_url)?;
    let policy = Arc::new(policy::Policy::from_config(&config.rbac));

    if let Some(store) = store.clone() {
        spawn_session_purge(store);
    }

    // Initialize Prometheus metrics exporter
    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .wrap_err("failed to install Prometheus metrics recorder")?;
    tracing::info!("Prometheus metrics available at /metrics");

    // Initialize auth manager
    let auth_manager = SharedAuth::new(AuthManager::new(&config.gateway, &config.tokens));
    if auth_manager.load().auth_required() {
        tracing::info!("Authentication enabled");
    } else {
        tracing::warn!("No authentication configured - gateway is open");
    }

    // Spawn registry actor (with toolsets if configured)
    let registry = if config.toolsets.is_empty() {
        RegistryActor::spawn_with_mailbox(RegistryActor::new(), mailbox::unbounded())
    } else {
        tracing::info!(
            "Toolsets configured: {:?}",
            config.toolsets.iter().map(|g| &g.name).collect::<Vec<_>>()
        );
        RegistryActor::spawn_with_mailbox(
            RegistryActor::with_toolsets(config.toolsets.clone()),
            mailbox::unbounded(),
        )
    };

    let gateway =
        GatewayActor::spawn_with_mailbox(GatewayActor::new(config, registry), mailbox::unbounded());

    // Wait until the gateway actor has finished initializing. kameo runs
    // `on_start` (which spawns every backend) to completion before the actor
    // starts processing its mailbox, so this `ask` only resolves once the
    // gateway is ready — a deterministic replacement for a fixed-duration sleep.
    match gateway.ask(crate::gateway::GetStatus).await {
        Ok(status) => {
            tracing::info!(
                "Gateway initialized with {} backend(s)",
                status.backend_count
            );
        }
        Err(e) => tracing::warn!("Gateway readiness check failed: {e:?}"),
    }

    // Start config file watcher for hot reload
    if let Err(e) =
        watcher::start_config_watcher(&config_path, gateway.clone(), auth_manager.clone())
    {
        tracing::warn!(
            "Failed to start config watcher: {}. Hot reload disabled.",
            e
        );
    }

    // Start HTTP server
    let state = AppState {
        gateway: gateway.clone(),
        auth_manager,
        config_path: Some(config_path),
        base_url,
        ui_events: broadcast::channel(256).0,
        sse_clients: Arc::new(AtomicU64::new(0)),
        started_at: SystemTime::now(),
        process_id: std::process::id(),
        metrics_handle,
        store,
        oidc,
        policy,
    };

    // Run server with graceful shutdown
    server::serve(state, &bind_addr, shutdown_signal())
        .await
        .wrap_err_with(|| format!("failed to start server on '{bind_addr}'"))?;

    // Gracefully stop the gateway actor
    tracing::info!("Stopping gateway actor...");
    if let Err(e) = gateway.stop_gracefully().await {
        tracing::warn!("Failed to stop gateway gracefully: {:?}", e);
    }

    tracing::info!("Shutdown complete");
    telemetry.shutdown();
    Ok(())
}

/// The OIDC providers for the dashboard login, or `None` without any.
fn setup_oidc(config: &Config, base_url: &str) -> Result<Option<Arc<OidcProviders>>> {
    if config.auth.oidc.is_empty() {
        tracing::warn!("No [auth.oidc] provider configured - the dashboard has no login");
        return Ok(None);
    }
    let redirect_url = format!("{}/auth/callback", base_url.trim_end_matches('/'));
    let providers = OidcProviders::new(&config.auth.oidc, &redirect_url)
        .wrap_err("failed to set up OIDC login")?;
    let ids = providers
        .iter()
        .map(oidc::Provider::id)
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!("Dashboard login via OIDC: {ids}");
    Ok(Some(Arc::new(providers)))
}

/// Deletes expired sessions and unfinished logins every hour. They are
/// rejected on lookup anyway; this only keeps the tables small.
fn spawn_session_purge(store: store::Store) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PURGE_INTERVAL);
        loop {
            interval.tick().await;
            match store.purge_expired().await {
                Ok(purged) => tracing::debug!(purged, "Purged expired sessions and logins"),
                Err(error) => tracing::warn!(%error, "Failed to purge expired sessions"),
            }
        }
    });
}

#[expect(
    clippy::expect_used,
    reason = "without signal handlers the gateway cannot shut down cleanly, so fail loudly"
)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => tracing::info!("Received SIGTERM"),
        _ = sigint.recv() => tracing::info!("Received SIGINT"),
    }
}
