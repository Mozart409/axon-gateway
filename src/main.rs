//! MCP Gateway - Aggregate multiple MCP servers into one
//!
//! Usage:
//!   mcp-gateway --config config.toml
//!
//! Or with environment variable:
//!   `MCP_GATEWAY_CONFIG=config.toml` mcp-gateway

mod admin_cli;
mod audit;
mod audit_admin;
mod auth;
mod authz;
mod backend;
mod changes;
mod config;
mod crypto;
mod egress;
mod error;
mod fanout;
mod gateway;
mod jobs;
mod metrics;
mod oidc;
mod personal;
mod policy;
mod principal;
mod rbac;
mod registry;
mod relay;
mod server;
mod store;
mod telemetry;
mod types;
mod upstream_oauth;
mod watcher;

use std::env;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::SystemTime;

use tokio::sync::broadcast;

use color_eyre::eyre::{Result, WrapErr};

use kameo::actor::ActorRef;
use kameo::actor::Spawn;
use kameo::mailbox;

use crate::auth::{AuthManager, SharedAuth};
use crate::changes::ChangeBus;
use crate::config::Config;
use crate::gateway::GatewayActor;
use crate::oidc::OidcProviders;
use crate::personal::PersonalHub;
use crate::registry::RegistryActor;
use crate::server::AppState;

/// How often expired dashboard sessions and login flows are deleted.
const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);
/// How often the sampler refreshes the gauges that are read from the database and the pool
const METRICS_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The legacy token auth. In multi-user mode `[[tokens]]` are config service accounts
/// under RBAC and the shared token is refused.
fn setup_auth(config: &Config, multi_user: bool) -> SharedAuth {
    let auth_manager = SharedAuth::new(AuthManager::new(&config.gateway, &config.tokens));
    if auth_manager.load().auth_required() {
        tracing::info!("Authentication enabled");
    } else if !multi_user {
        tracing::warn!("No authentication configured - gateway is open");
    }
    if multi_user {
        if config.gateway.auth_token.is_some() {
            tracing::warn!(
                "gateway.auth_token is ignored in multi-user mode (requests with it get 401): use a service account token, or `axon-gateway admin login-link` to sign in"
            );
        }
        if !config.tokens.is_empty() {
            tracing::info!(
                "[[tokens]] are config service accounts in multi-user mode: their tools come from [[rbac.groups]] service_accounts"
            );
        }
        for token in &config.tokens {
            let listed = config
                .rbac
                .groups
                .iter()
                .any(|group| group.service_accounts.contains(&token.name));
            if !listed {
                tracing::warn!(
                    token = %token.name,
                    "[[tokens]] entry is in no [[rbac.groups]] service_accounts list and can call no tools"
                );
            }
        }
    }
    auth_manager
}

/// Spawns the background tasks that need the database: the purges, the audit
/// writer (returned) and the RBAC policy refresh.
async fn start_store_tasks(
    store: Option<&store::Store>,
    has_oidc: bool,
    policy: &Arc<rbac::PolicyHandle>,
) -> Option<audit::AuditSink> {
    if let Some(store) = store {
        spawn_purges(store);
    }
    let audit = store.map(|store| {
        audit::spawn_audit_purge(store.clone());
        audit::AuditSink::spawn(store.clone())
    });
    if let (Some(store), true) = (store, has_oidc) {
        // Config-only policy until the database answers; the refresh task
        // retries, and picks up changes made through other replicas.
        if let Err(error) = policy.refresh(store).await {
            tracing::warn!(%error, "Could not load RBAC rows from the database, using [rbac] from the config only");
        }
        rbac::spawn_policy_refresh(Arc::clone(policy), store.clone());
    }
    audit
}

/// The shared registry actor, with toolsets if configured
fn spawn_registry(config: &Config, changes: &ChangeBus) -> ActorRef<RegistryActor> {
    if config.toolsets.is_empty() {
        RegistryActor::spawn_with_mailbox(
            RegistryActor::new().with_change_bus(changes.clone()),
            mailbox::unbounded(),
        )
    } else {
        tracing::info!(
            "Toolsets configured: {:?}",
            config.toolsets.iter().map(|g| &g.name).collect::<Vec<_>>()
        );
        RegistryActor::spawn_with_mailbox(
            RegistryActor::with_toolsets(config.toolsets.clone()).with_change_bus(changes.clone()),
            mailbox::unbounded(),
        )
    }
}

/// Wait until the gateway actor has finished initializing. kameo runs
/// `on_start` (which spawns every backend) to completion before the actor
/// starts processing its mailbox, so this `ask` only resolves once the
/// gateway is ready — a deterministic replacement for a fixed-duration sleep.
async fn await_gateway_ready(gateway: &ActorRef<GatewayActor>) {
    match gateway.ask(crate::gateway::GetStatus).await {
        Ok(status) => {
            tracing::info!(
                "Gateway initialized with {} backend(s)",
                status.backend_count
            );
        }
        Err(e) => tracing::warn!("Gateway readiness check failed: {e:?}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install color_eyre for pretty error reporting
    color_eyre::install()?;

    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "admin") {
        return admin_cli::run(&args).await;
    }

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
    // Tool-list changes (backends, RBAC, toolsets) reach open MCP connections here
    let changes = ChangeBus::new();
    let policy =
        Arc::new(rbac::PolicyHandle::new(config.rbac.clone()).with_change_bus(changes.clone()));

    let audit = start_store_tasks(store.as_ref(), oidc.is_some(), &policy).await;
    let personal = setup_personal(&config, store.as_ref(), &changes, oidc.clone()).await?;

    // Initialize Prometheus metrics exporter
    let prometheus_builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let metrics_handle = prometheus_builder
        .install_recorder()
        .wrap_err("failed to install Prometheus metrics recorder")?;
    crate::metrics::describe_user_metrics();
    tracing::info!("Prometheus metrics available at /metrics");
    if let Some(store) = &store {
        spawn_metrics_sampler(store.clone(), personal.clone());
    }

    let auth_manager = setup_auth(&config, store.is_some() && oidc.is_some());

    // `Host` values the MCP endpoints accept. Built before `config` moves into
    // the gateway actor.
    let mcp_allowed_hosts = config::mcp_allowed_hosts(&config.gateway);

    let registry = spawn_registry(&config, &changes);

    let mut gateway_actor = GatewayActor::new(config, registry);
    if let Some(hub) = &personal {
        gateway_actor = gateway_actor.with_personal(Arc::clone(hub));
    }
    let gateway = GatewayActor::spawn_with_mailbox(gateway_actor, mailbox::unbounded());

    await_gateway_ready(&gateway).await;

    // Database changes (policy, users, the catalog) reach this replica here
    if let (Some(store), true) = (&store, oidc.is_some()) {
        fanout::spawn_change_listener(
            store.clone(),
            Arc::clone(&policy),
            changes.clone(),
            fanout::Handles {
                gateway: gateway.clone(),
                personal: personal.clone(),
            },
        );
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
        audit,
        changes,
        mcp_allowed_hosts,
        personal,
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

/// The hub of the users' own and catalog backends, or `None` without a
/// database or with `[personal_backends] enabled = false`. It needs a key to
/// seal the users' secrets, so a missing one stops the start.
async fn setup_personal(
    config: &Config,
    store: Option<&store::Store>,
    changes: &ChangeBus,
    oidc: Option<Arc<OidcProviders>>,
) -> Result<Option<Arc<PersonalHub>>> {
    let Some(store) = store.filter(|_| config.personal_backends.enabled) else {
        return Ok(None);
    };
    let keyring = crypto::Keyring::from_env()
        .wrap_err("failed to read the personal backends key")?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "personal backends need a key: set AXON_KEK_FILE or AXON_KEK (or [personal_backends] enabled = false)"
            )
        })?;
    let egress = egress::EgressPolicy::new(
        &config.personal_backends.egress_allow,
        &config.personal_backends.egress_deny,
    )
    .wrap_err("invalid [personal_backends] egress rule")?;
    let hub = PersonalHub::new(
        store.clone(),
        Arc::new(keyring),
        Arc::new(egress),
        config,
        changes.clone(),
        oidc,
    );
    if let Err(error) = hub.reload_catalog(config).await {
        tracing::warn!(%error, "Could not load the per-user catalog from the database");
    }
    tracing::info!("Personal backends enabled");
    Ok(Some(Arc::new(hub)))
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

/// Spawns the hourly purges that only keep tables small, each running on one
/// replica at a time. Expired sessions, unfinished logins, rate limit windows
/// and idle MCP sessions are rejected or ignored on lookup anyway.
fn spawn_purges(store: &store::Store) {
    jobs::spawn_singleton(
        store.clone(),
        "sessions",
        PURGE_INTERVAL,
        |store| async move {
            match store.purge_expired().await {
                Ok(purged) => tracing::debug!(purged, "Purged expired sessions and logins"),
                Err(error) => tracing::warn!(%error, "Failed to purge expired sessions"),
            }
        },
    );
    jobs::spawn_singleton(
        store.clone(),
        "rate_limits",
        PURGE_INTERVAL,
        |store| async move {
            match store.purge_rate_limits().await {
                Ok(purged) => tracing::debug!(purged, "Purged expired rate limit windows"),
                Err(error) => tracing::warn!(%error, "Failed to purge rate limit windows"),
            }
        },
    );
    jobs::spawn_singleton(
        store.clone(),
        "mcp_sessions",
        PURGE_INTERVAL,
        |store| async move {
            match store.purge_mcp_sessions().await {
                Ok(purged) => tracing::debug!(purged, "Purged idle MCP sessions"),
                Err(error) => tracing::warn!(%error, "Failed to purge idle MCP sessions"),
            }
        },
    );
    jobs::spawn_singleton(store.clone(), "oauth", PURGE_INTERVAL, |store| async move {
        match store.purge_oauth().await {
            Ok(purged) => tracing::debug!(purged, "Purged expired OAuth state"),
            Err(error) => tracing::warn!(%error, "Failed to purge expired OAuth state"),
        }
    });
    jobs::spawn_singleton(
        store.clone(),
        "upstream_oauth",
        PURGE_INTERVAL,
        |store| async move {
            match store.purge_upstream_oauth().await {
                Ok(purged) => tracing::debug!(purged, "Purged expired upstream OAuth requests"),
                Err(error) => {
                    tracing::warn!(%error, "Failed to purge expired upstream OAuth requests");
                }
            }
        },
    );
}

/// Spawns the task that refreshes this replica's sampled gauges: sessions,
/// tokens, the database pool, the database probe and the per-user backends.
fn spawn_metrics_sampler(store: store::Store, personal: Option<Arc<PersonalHub>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(METRICS_SAMPLE_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            sample_metrics(&store, personal.as_deref()).await;
        }
    });
}

/// One tick of the sampler.
async fn sample_metrics(store: &store::Store, personal: Option<&PersonalHub>) {
    let up = store.ping().await.is_ok();
    crate::metrics::record_db_up(up);
    let pool = store.pool_stats();
    crate::metrics::record_db_pool(pool.idle, pool.used, pool.max);
    if up {
        match store.sample_counts().await {
            Ok(counts) => {
                crate::metrics::record_active_sessions("mcp", counts.mcp_sessions);
                crate::metrics::record_active_sessions("ui", counts.ui_sessions);
                crate::metrics::record_tokens_active("pat", counts.pat_tokens);
                crate::metrics::record_tokens_active("service", counts.service_tokens);
            }
            Err(error) => tracing::warn!(%error, "Failed to sample session and token counts"),
        }
    }
    if let Some(hub) = personal {
        crate::metrics::record_user_backend_states(&hub.backend_states().await);
    }
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
