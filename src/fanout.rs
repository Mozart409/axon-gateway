//! Fans database change notifications out to this replica's change bus.
//!
//! The database triggers `NOTIFY` on `CHANGES_CHANNEL` when policy rows or a
//! user's opt-outs and toolsets change, whichever replica made the change.
//! Several gateways may share a database in different schemas, so payloads for
//! another schema are ignored. The policy poll stays as the backstop for
//! notifications that get lost. In database mode a `config` notice (and a poll
//! of the stored configuration's version every [`CONFIG_POLL_INTERVAL`]) reloads
//! the gateway's configuration.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use kameo::actor::ActorRef;
use serde::Deserialize;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::auth::SharedAuth;
use crate::changes::{ChangeBus, ChangeScope};
use crate::dbconfig::{self, DbConfigContext};
use crate::gateway::{GatewayActor, GetConfig, GetDetailedStatus, ReloadConfig, ReloadResult};
use crate::oidc::OidcProviders;
use crate::personal::PersonalHub;
use crate::rbac::PolicyHandle;
use crate::server::UiEvent;
use crate::store::Store;

const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// How often the stored configuration's version is compared with the applied
/// one, the backstop for lost `config` notifications
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// What a notification payload says changed
#[derive(Debug, PartialEq, Eq)]
enum Notice {
    /// Groups, mappings, memberships, grants or role bindings
    Policy,
    /// One user's opt-outs, toolsets, personal backends or catalog credentials
    User(Uuid),
    /// The catalog of backends every user may bring a credential for
    Catalog,
    /// The gateway settings, backends, toolsets or OIDC providers (database mode)
    Config,
}

#[derive(Deserialize)]
struct Payload {
    schema: String,
    #[serde(flatten)]
    kind: Kind,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Kind {
    Policy,
    User { user: Uuid },
    Catalog,
    Config,
}

/// Parses a notification payload; `None` when it is malformed or for a schema
/// other than `schema`.
fn notice(payload: &str, schema: &str) -> Option<Notice> {
    let payload: Payload = match serde_json::from_str(payload) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::debug!(%error, payload, "Ignoring an unparsable change notification");
            return None;
        }
    };
    if payload.schema != schema {
        return None;
    }
    Some(match payload.kind {
        Kind::Policy => Notice::Policy,
        Kind::User { user } => Notice::User(user),
        Kind::Catalog => Notice::Catalog,
        Kind::Config => Notice::Config,
    })
}

/// What the listener acts on besides the policy and the change bus
pub struct Handles {
    /// Asked for the running config when the catalog changes
    pub gateway: ActorRef<GatewayActor>,
    /// Drops the slots of users whose backends or credentials changed
    pub personal: Option<Arc<PersonalHub>>,
    /// Reloads the stored configuration; `None` in standalone mode
    pub config: Option<Arc<ConfigApplier>>,
}

/// Loads the stored configuration and applies it to the running gateway
pub struct ConfigApplier {
    store: Store,
    context: DbConfigContext,
    gateway: ActorRef<GatewayActor>,
    oidc: Arc<OidcProviders>,
    auth: SharedAuth,
    allowed_hosts: Arc<RwLock<Vec<String>>>,
    /// Told when a reload changed something, like a file reload is
    ui_events: broadcast::Sender<UiEvent>,
    /// The version of the configuration applied last; the lock also keeps two
    /// reloads from overlapping
    applied: tokio::sync::Mutex<Option<i64>>,
}

impl ConfigApplier {
    /// `applied` is the version read before the configuration the gateway
    /// started with was loaded
    #[expect(
        clippy::too_many_arguments,
        reason = "one handle per thing a reload swaps"
    )]
    pub fn new(
        store: Store,
        context: DbConfigContext,
        gateway: ActorRef<GatewayActor>,
        oidc: Arc<OidcProviders>,
        auth: SharedAuth,
        allowed_hosts: Arc<RwLock<Vec<String>>>,
        ui_events: broadcast::Sender<UiEvent>,
        applied: Option<i64>,
    ) -> Self {
        Self {
            store,
            context,
            gateway,
            oidc,
            auth,
            allowed_hosts,
            ui_events,
            applied: tokio::sync::Mutex::new(applied),
        }
    }

    /// Applies the stored configuration when its version differs from the applied one
    async fn apply_if_changed(&self) {
        let version = match dbconfig::state_version(&self.store).await {
            Ok(version) => version,
            Err(error) => {
                tracing::warn!(%error, "Failed to read the stored configuration's version");
                return;
            }
        };
        let mut applied = self.applied.lock().await;
        if *applied != Some(version) {
            self.apply(&mut applied).await;
        }
    }

    /// Applies the stored configuration
    async fn apply_now(&self) {
        let mut applied = self.applied.lock().await;
        self.apply(&mut applied).await;
    }

    /// Tells the dashboard what a reload changed; silent when nothing did, so the
    /// poll and the reconnect make no noise
    async fn announce(&self, result: &ReloadResult) {
        if result.added.is_empty()
            && result.removed.is_empty()
            && result.changed.is_empty()
            && result.errors.is_empty()
        {
            return;
        }
        // No subscriber is not an error
        let _ = self.ui_events.send(UiEvent::ConfigReloaded {
            added: result.added.clone(),
            removed: result.removed.clone(),
            changed: result.changed.clone(),
            errors: result.errors.clone(),
        });
        match self.gateway.ask(GetDetailedStatus).await {
            Ok(status) => {
                let _ = self.ui_events.send(UiEvent::BackendStatusChanged(status));
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to refresh the UI backend snapshot after a config reload");
            }
        }
    }

    /// A failed load or reload logs a warning and keeps the running config; the
    /// version stays unapplied, so the poll tries again.
    async fn apply(&self, applied: &mut Option<i64>) {
        // Read before the load: a write in between shows up as a newer version
        let version = match dbconfig::state_version(&self.store).await {
            Ok(version) => version,
            Err(error) => {
                tracing::warn!(%error, "Failed to read the stored configuration's version");
                return;
            }
        };
        let DbConfigContext { keyring, bootstrap } = &self.context;
        let config = match dbconfig::load(&self.store, keyring, bootstrap).await {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "Failed to load the stored configuration, keeping the running one");
                return;
            }
        };
        let auth = config.auth.clone();
        let gateway_settings = config.gateway.clone();
        let tokens = config.tokens.clone();
        let reply = self.gateway.ask(ReloadConfig { config }).await;
        if let Ok(result) = &reply {
            self.announce(result).await;
        }
        match reply {
            Ok(result) if result.errors.is_empty() => {
                tracing::info!(
                    added = result.added.len(),
                    removed = result.removed.len(),
                    restarted = result.changed.len(),
                    "Applied the stored configuration"
                );
            }
            Ok(result) => {
                tracing::warn!(
                    added = result.added.len(),
                    removed = result.removed.len(),
                    restarted = result.changed.len(),
                    errors = ?result.errors,
                    "Applied the stored configuration with errors"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "Failed to reload the stored configuration, keeping the running one");
                return;
            }
        }
        if let Err(error) = self.oidc.replace(&auth.oidc) {
            tracing::warn!(%error, "Failed to apply the OIDC providers, keeping the running ones");
        }
        self.auth.reload(&gateway_settings, &tokens);
        let hosts = crate::config::mcp_allowed_hosts(&gateway_settings);
        *self
            .allowed_hosts
            .write()
            .unwrap_or_else(PoisonError::into_inner) = hosts;
        *applied = Some(version);
    }
}

/// Listens for change notifications for as long as the process lives,
/// reconnecting with a backoff when the connection fails.
pub fn spawn_change_listener(
    store: Store,
    policy: Arc<PolicyHandle>,
    changes: ChangeBus,
    handles: Handles,
) {
    if let Some(config) = handles.config.clone() {
        spawn_config_poll(config);
    }
    tokio::spawn(async move {
        let mut backoff = BACKOFF_START;
        let mut first = true;
        loop {
            let (schema, mut listener) = match connect(&store).await {
                Ok(connected) => connected,
                Err(error) => {
                    tracing::warn!(%error, "Failed to listen for change notifications, retrying in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            };
            backoff = BACKOFF_START;
            if !first {
                // Notifications sent while we were not listening are lost
                resync(&store, &policy, &changes, &handles).await;
            }
            first = false;
            tracing::debug!(schema, "Listening for change notifications");

            loop {
                match listener.try_recv().await {
                    Ok(Some(notification)) => match notice(notification.payload(), &schema) {
                        Some(Notice::Policy) => refresh(&store, &policy).await,
                        Some(Notice::User(id)) => {
                            changes.publish(ChangeScope::User(id));
                            if let Some(hub) = &handles.personal {
                                hub.invalidate(id).await;
                            }
                        }
                        Some(Notice::Catalog) => reload_catalog(&handles).await,
                        Some(Notice::Config) => apply_config(&handles).await,
                        None => {}
                    },
                    Ok(None) => {
                        tracing::warn!("Lost the change notification connection, reconnecting");
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Change notification listener failed, retrying in {backoff:?}");
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(BACKOFF_MAX);
                        break;
                    }
                }
            }
        }
    });
}

/// Compares the stored configuration's version with the applied one every
/// [`CONFIG_POLL_INTERVAL`], for notifications that were missed
fn spawn_config_poll(config: Arc<ConfigApplier>) {
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + CONFIG_POLL_INTERVAL;
        let mut interval = tokio::time::interval_at(start, CONFIG_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            config.apply_if_changed().await;
        }
    });
}

async fn connect(store: &Store) -> Result<(String, PgListener), crate::store::StoreError> {
    let schema = store.current_schema().await?;
    let listener = store.listen_changes().await?;
    Ok((schema, listener))
}

async fn refresh(store: &Store, policy: &PolicyHandle) {
    if let Err(error) = policy.refresh(store).await {
        tracing::warn!(%error, "Failed to refresh the RBAC policy after a change notification");
    }
}

/// Rebuilds the catalog from the running config and the database, then drops
/// every slot so each user's backends pick it up
async fn reload_catalog(handles: &Handles) {
    let Some(hub) = &handles.personal else {
        return;
    };
    match handles.gateway.ask(GetConfig).await {
        Ok(config) => {
            if let Err(error) = hub.reload_catalog(&config.0).await {
                tracing::warn!(%error, "Failed to reload the per-user catalog after a change notification");
            }
        }
        Err(error) => {
            tracing::warn!(%error, "Could not read the running config to reload the per-user catalog");
        }
    }
    hub.invalidate_all().await;
}

/// Reloads the stored configuration; nothing in standalone mode
async fn apply_config(handles: &Handles) {
    if let Some(config) = &handles.config {
        config.apply_now().await;
    }
}

/// Catches up after notifications may have been lost
async fn resync(store: &Store, policy: &PolicyHandle, changes: &ChangeBus, handles: &Handles) {
    refresh(store, policy).await;
    apply_config(handles).await;
    reload_catalog(handles).await;
    changes.publish(ChangeScope::All);
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "6f1d0c5e-8f0a-4d63-9a58-0e2a1b7f4c11";

    #[test]
    fn parses_a_policy_notice() {
        let payload = r#"{"schema":"axon","kind":"policy"}"#;
        assert_eq!(notice(payload, "axon"), Some(Notice::Policy));
    }

    #[test]
    fn parses_a_user_notice() {
        let payload = format!(r#"{{"schema":"axon","kind":"user","user":"{USER}"}}"#);
        let expected = Uuid::parse_str(USER).ok().map(Notice::User);
        assert!(expected.is_some());
        assert_eq!(notice(&payload, "axon"), expected);
    }

    #[test]
    fn parses_a_catalog_notice() {
        let payload = r#"{"schema":"axon","kind":"catalog"}"#;
        assert_eq!(notice(payload, "axon"), Some(Notice::Catalog));
        let other = r#"{"schema":"other","kind":"catalog"}"#;
        assert_eq!(notice(other, "axon"), None);
    }

    #[test]
    fn parses_a_config_notice() {
        let payload = r#"{"schema":"axon","kind":"config"}"#;
        assert_eq!(notice(payload, "axon"), Some(Notice::Config));
    }

    #[test]
    fn ignores_other_schemas() {
        let payload = r#"{"schema":"other","kind":"policy"}"#;
        assert_eq!(notice(payload, "axon"), None);
    }

    #[test]
    fn ignores_unparsable_payloads() {
        assert_eq!(notice("not json", "axon"), None);
        assert_eq!(notice(r#"{"schema":"axon","kind":"nope"}"#, "axon"), None);
        assert_eq!(notice(r#"{"schema":"axon","kind":"user"}"#, "axon"), None);
        assert_eq!(
            notice(r#"{"schema":"axon","kind":"user","user":"x"}"#, "axon"),
            None
        );
    }
}
