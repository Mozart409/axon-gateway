//! Fans database change notifications out to this replica's change bus.
//!
//! The database triggers `NOTIFY` on `CHANGES_CHANNEL` when policy rows or a
//! user's opt-outs and toolsets change, whichever replica made the change.
//! Several gateways may share a database in different schemas, so payloads for
//! another schema are ignored. The policy poll stays as the backstop for
//! notifications that get lost.

use std::sync::Arc;
use std::time::Duration;

use kameo::actor::ActorRef;
use serde::Deserialize;
use sqlx::postgres::PgListener;
use uuid::Uuid;

use crate::changes::{ChangeBus, ChangeScope};
use crate::gateway::{GatewayActor, GetConfig};
use crate::personal::PersonalHub;
use crate::rbac::PolicyHandle;
use crate::store::Store;

const BACKOFF_START: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// What a notification payload says changed
#[derive(Debug, PartialEq, Eq)]
enum Notice {
    /// Groups, mappings, memberships, grants or role bindings
    Policy,
    /// One user's opt-outs, toolsets, personal backends or catalog credentials
    User(Uuid),
    /// The catalog of backends every user may bring a credential for
    Catalog,
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
    })
}

/// What the listener acts on besides the policy and the change bus
pub struct Handles {
    /// Asked for the running config when the catalog changes
    pub gateway: ActorRef<GatewayActor>,
    /// Drops the slots of users whose backends or credentials changed
    pub personal: Option<Arc<PersonalHub>>,
}

/// Listens for change notifications for as long as the process lives,
/// reconnecting with a backoff when the connection fails.
pub fn spawn_change_listener(
    store: Store,
    policy: Arc<PolicyHandle>,
    changes: ChangeBus,
    handles: Handles,
) {
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

/// Catches up after notifications may have been lost
async fn resync(store: &Store, policy: &PolicyHandle, changes: &ChangeBus, handles: &Handles) {
    refresh(store, policy).await;
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
