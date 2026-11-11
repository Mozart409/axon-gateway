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
mod bootstrap;
mod changes;
mod config;
mod crypto;
mod dbconfig;
mod egress;
mod error;
mod fanout;
mod gateway;
mod import;
mod jobs;
mod metrics;
mod oidc;
mod personal;
mod policy;
mod principal;
mod rbac;
mod registry;
mod relay;
mod scim;
mod server;
mod store;
mod telemetry;
mod types;
mod upstream_oauth;
mod watcher;

use std::env;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use tokio::sync::broadcast;

use color_eyre::eyre::{Result, WrapErr};

use kameo::actor::ActorRef;
use kameo::actor::Spawn;
use kameo::mailbox;

use crate::auth::{AuthManager, SharedAuth};
use crate::changes::ChangeBus;
use crate::config::Config;
use crate::dbconfig::DbConfigContext;
use crate::gateway::GatewayActor;
use crate::oidc::OidcProviders;
use crate::personal::PersonalHub;
use crate::registry::RegistryActor;
use crate::server::AppState;

/// How often expired dashboard sessions and login flows are deleted.
const PURGE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);
/// How often the sampler refreshes the gauges that are read from the database and the pool
const METRICS_SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The token auth. Database mode has none of its own: its tokens are service
/// accounts under RBAC, and a standalone gateway with no token is open.
fn setup_auth(config: &Config, multi_user: bool) -> SharedAuth {
    let auth_manager = SharedAuth::new(AuthManager::new(&config.gateway, &config.tokens));
    if auth_manager.load().auth_required() {
        tracing::info!("Authentication enabled");
    } else if !multi_user {
        tracing::warn!("No authentication configured - gateway is open");
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
        // An empty policy until the database answers; the refresh task retries,
        // and picks up changes made through other replicas.
        if let Err(error) = policy.refresh(store).await {
            tracing::warn!(%error, "Could not load the RBAC rows from the database, the policy is empty until the next refresh");
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

/// What the two start modes hand to the common startup
struct Startup {
    config: Config,
    /// `None` in standalone mode without a `[database]`
    store: Option<store::Store>,
    /// The file the config came from; `None` in database mode
    config_path: Option<String>,
    /// `Some` in database mode
    db_config: Option<DbConfigContext>,
    /// The stored configuration's version read before it was loaded
    config_version: Option<i64>,
}

/// Whether `AXON_DATABASE_URL` is set: the configuration lives in the database
fn database_mode() -> bool {
    env::var(bootstrap::ENV_DATABASE_URL).is_ok_and(|url| !url.trim().is_empty())
}

/// The config file named on the command line or in `AXON_GATEWAY_CONFIG`, if any
fn explicit_config_path() -> Option<String> {
    env::args()
        .nth(1)
        .or_else(|| env::var("AXON_GATEWAY_CONFIG").ok())
        .filter(|path| !path.trim().is_empty())
}

/// Database mode: the bootstrap environment and the database are everything the
/// gateway reads; there is no config file.
async fn load_database_mode() -> Result<Startup> {
    if explicit_config_path().is_some() {
        color_eyre::eyre::bail!(
            "database mode reads no config file; import it once with `axon-gateway admin import-config <file>` and start without it"
        );
    }
    let bootstrap = bootstrap::Bootstrap::from_env().wrap_err("invalid bootstrap environment")?;
    let keyring = crypto::Keyring::from_env()
        .wrap_err("failed to read the key encryption key")?
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "database mode needs a key to seal the stored secrets: set AXON_KEK_FILE or AXON_KEK"
            )
        })?;
    let url = bootstrap
        .database_url
        .as_deref()
        .ok_or_else(|| color_eyre::eyre::eyre!("{} is not set", bootstrap::ENV_DATABASE_URL))?;
    let store = store::Store::connect_url(url)
        .await
        .wrap_err("failed to connect to the database")?;
    tracing::info!("Database connected, migrations applied");

    // Read first: a change made while loading shows up as a newer version later
    let config_version = match dbconfig::state_version(&store).await {
        Ok(version) => Some(version),
        Err(error) => {
            tracing::warn!(%error, "Failed to read the stored configuration's version");
            None
        }
    };
    let config = dbconfig::load(&store, &keyring, &bootstrap)
        .await
        .wrap_err("failed to load the configuration from the database")?;
    tracing::info!("Configuration loaded from the database");
    Ok(Startup {
        config,
        store: Some(store),
        config_path: None,
        db_config: Some(DbConfigContext {
            keyring: Arc::new(keyring),
            bootstrap: Arc::new(bootstrap),
        }),
        config_version,
    })
}

/// Standalone mode: the TOML file, hot-reloaded by the watcher
async fn load_standalone() -> Result<Startup> {
    let config_path = explicit_config_path().unwrap_or_else(|| "config.toml".to_string());
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
    Ok(Startup {
        config,
        store,
        config_path: Some(config_path),
        db_config: None,
        config_version: None,
    })
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
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

    let startup = if database_mode() {
        load_database_mode().await?
    } else {
        load_standalone().await?
    };
    let Startup {
        config,
        store,
        config_path,
        db_config,
        config_version,
    } = startup;

    let bind_addr = config.gateway.bind.clone();
    let base_url = config.gateway.base_url.clone();

    // Dashboard login. Built before `config` moves into the gateway actor.
    let oidc = setup_oidc(&config, &base_url, db_config.is_some())?;
    // Tool-list changes (backends, RBAC, toolsets) reach open MCP connections here
    let changes = ChangeBus::new();
    let policy = Arc::new(rbac::PolicyHandle::new().with_change_bus(changes.clone()));

    let audit = start_store_tasks(store.as_ref(), oidc.is_some(), &policy).await;
    let personal = setup_personal(
        &config,
        store.as_ref(),
        db_config.as_ref(),
        &changes,
        oidc.clone(),
    )
    .await?;

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
    let mcp_allowed_hosts = Arc::new(RwLock::new(config::mcp_allowed_hosts(&config.gateway)));

    let registry = spawn_registry(&config, &changes);

    let mut gateway_actor = GatewayActor::new(config, registry);
    if let Some(hub) = &personal {
        gateway_actor = gateway_actor.with_personal(Arc::clone(hub));
    }
    let gateway = GatewayActor::spawn_with_mailbox(gateway_actor, mailbox::unbounded());

    await_gateway_ready(&gateway).await;

    let ui_events = broadcast::channel(256).0;

    // Database changes (policy, users, the catalog, the configuration) reach this
    // replica here
    if let (Some(store), Some(providers)) = (&store, &oidc) {
        let config = db_config.clone().map(|context| {
            Arc::new(fanout::ConfigApplier::new(
                store.clone(),
                context,
                gateway.clone(),
                Arc::clone(providers),
                auth_manager.clone(),
                Arc::clone(&mcp_allowed_hosts),
                ui_events.clone(),
                config_version,
            ))
        });
        fanout::spawn_change_listener(
            store.clone(),
            Arc::clone(&policy),
            changes.clone(),
            fanout::Handles {
                gateway: gateway.clone(),
                personal: personal.clone(),
                config,
            },
        );
    }

    // Start config file watcher for hot reload; database mode has no file
    if let Some(config_path) = &config_path
        && let Err(e) =
            watcher::start_config_watcher(config_path, gateway.clone(), auth_manager.clone())
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
        config_path,
        base_url,
        ui_events,
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
        db_config,
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
    db_config: Option<&DbConfigContext>,
    changes: &ChangeBus,
    oidc: Option<Arc<OidcProviders>>,
) -> Result<Option<Arc<PersonalHub>>> {
    let Some(store) = store.filter(|_| config.personal_backends.enabled) else {
        return Ok(None);
    };
    let keyring = if let Some(context) = db_config {
        Arc::clone(&context.keyring)
    } else {
        Arc::new(
            crypto::Keyring::from_env()
                .wrap_err("failed to read the personal backends key")?
                .ok_or_else(|| {
                    color_eyre::eyre::eyre!(
                        "personal backends need a key: set AXON_KEK_FILE or AXON_KEK (or [personal_backends] enabled = false)"
                    )
                })?,
        )
    };
    let egress = egress::EgressPolicy::new(
        &config.personal_backends.egress_allow,
        &config.personal_backends.egress_deny,
    )
    .wrap_err("invalid [personal_backends] egress rule")?;
    let hub = PersonalHub::new(
        store.clone(),
        keyring,
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

/// The OIDC providers for the dashboard login. Database mode always has the
/// set, possibly empty (then `axon-gateway admin login-link` is the way in);
/// standalone mode has no login.
fn setup_oidc(
    config: &Config,
    base_url: &str,
    database_mode: bool,
) -> Result<Option<Arc<OidcProviders>>> {
    if !database_mode {
        return Ok(None);
    }
    let redirect_url = format!("{}/auth/callback", base_url.trim_end_matches('/'));
    let providers = OidcProviders::new(&config.auth.oidc, &redirect_url)
        .wrap_err("failed to set up OIDC login")?;
    if providers.is_empty() {
        tracing::warn!(
            "No OIDC provider configured - sign in with `axon-gateway admin login-link`"
        );
    } else {
        let ids = providers
            .list()
            .iter()
            .map(|provider| provider.id())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!("Dashboard login via OIDC: {ids}");
    }
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
