//! Persistent MCP sessions and who owns them.
//!
//! A session of a client before 2026-07-28 lives in rmcp's `LocalSessionManager`, in
//! the memory of the replica that opened it. [`PgSessionStore`] keeps what rmcp needs
//! to rebuild it (the `initialize` parameters) in Postgres, so any replica sharing the
//! database can serve the session. [`SessionOwners`] binds each session to the caller
//! that opened it, so another caller who learns the id cannot use it.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use rmcp::transport::streamable_http_server::session::{
    SessionState, SessionStore, SessionStoreError,
};

use crate::gateway::Caller;
use crate::store::{MCP_SESSION_IDLE, Store, StoreError};

/// rmcp's session store, backed by the gateway's Postgres store.
pub(super) struct PgSessionStore(pub(super) Store);

#[async_trait::async_trait]
impl SessionStore for PgSessionStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionState>, SessionStoreError> {
        match self.0.load_mcp_session(session_id).await? {
            Some(value) => Ok(Some(serde_json::from_value(value)?)),
            None => Ok(None),
        }
    }

    async fn store(&self, session_id: &str, state: &SessionState) -> Result<(), SessionStoreError> {
        let value = serde_json::to_value(state)?;
        Ok(self.0.store_mcp_session(session_id, &value).await?)
    }

    async fn delete(&self, session_id: &str) -> Result<(), SessionStoreError> {
        Ok(self.0.delete_mcp_session(session_id).await?)
    }
}

/// The key a session is bound to: the user behind a principal, else the principal's
/// label (a config service account has no user), the legacy token's name, or `open`.
pub(super) fn session_owner(caller: &Caller) -> String {
    match caller {
        Caller::Principal(principal) => match principal.owner_id() {
            Some(owner) => format!("user:{owner}"),
            None => format!("principal:{}", principal.label()),
        },
        Caller::Token(identity) => format!("token:{}", identity.name),
        Caller::Open => String::from("open"),
    }
}

/// Where the owner of each session is kept: Postgres when the gateway has a database
/// (shared by every replica), else the memory of this process.
#[derive(Clone)]
pub(super) enum SessionOwners {
    Postgres(Store),
    /// Session id to its owner and when it was last used
    Memory(Arc<DashMap<String, (String, Instant)>>),
}

impl SessionOwners {
    pub(super) fn new(store: Option<&Store>) -> Self {
        match store {
            Some(store) => Self::Postgres(store.clone()),
            None => Self::Memory(Arc::default()),
        }
    }

    /// Record `owner` as the owner of the new session `id`.
    pub(super) async fn bind(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        match self {
            Self::Postgres(store) => store.bind_mcp_session(id, owner).await,
            Self::Memory(owners) => {
                let now = Instant::now();
                prune(owners, now);
                owners.insert(id.to_owned(), (owner.to_owned(), now));
                Ok(())
            }
        }
    }

    /// The owner of session `id`; `None` when it is unknown or was never bound.
    pub(super) async fn owner(&self, id: &str) -> Result<Option<String>, StoreError> {
        match self {
            Self::Postgres(store) => store.mcp_session_owner(id).await,
            Self::Memory(owners) => Ok(owners.get_mut(id).map(|mut entry| {
                entry.1 = Instant::now();
                entry.0.clone()
            })),
        }
    }

    /// Drop session `id`. In Postgres that deletes the session row, owner included.
    pub(super) async fn forget(&self, id: &str) -> Result<(), StoreError> {
        match self {
            Self::Postgres(store) => store.delete_mcp_session(id).await,
            Self::Memory(owners) => {
                owners.remove(id);
                Ok(())
            }
        }
    }
}

/// Remove the owners not used for [`MCP_SESSION_IDLE`] as of `now`.
fn prune(owners: &DashMap<String, (String, Instant)>, now: Instant) {
    owners.retain(|_, (_, seen)| now.saturating_duration_since(*seen) <= MCP_SESSION_IDLE);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use uuid::Uuid;

    use super::*;
    use crate::auth::TokenIdentity;
    use crate::policy::OptOuts;
    use crate::policy::{Policy, RbacConfig};
    use crate::principal::{PrincipalPolicy, TokenScope};

    fn principal(owner: Option<Uuid>) -> Caller {
        let effective = Policy::from_config(&RbacConfig::default()).effective(&[]);
        let policy = PrincipalPolicy::new(
            String::from("config:ci"),
            effective,
            OptOuts::default(),
            TokenScope::default(),
        )
        .with_identity(owner, None);
        Caller::Principal(policy)
    }

    fn token(name: &str) -> Caller {
        Caller::Token(TokenIdentity {
            name: name.to_owned(),
            allowed_tools: Vec::new(),
            allowed_backends: Vec::new(),
            rate_limit_per_minute: 0,
        })
    }

    #[test]
    fn owner_keys_tell_the_callers_apart() {
        let user = Uuid::from_u128(7);
        assert_eq!(
            session_owner(&principal(Some(user))),
            format!("user:{user}")
        );
        assert_eq!(session_owner(&principal(None)), "principal:config:ci");
        assert_eq!(session_owner(&token("ci")), "token:ci");
        assert_eq!(session_owner(&Caller::Open), "open");
    }

    #[tokio::test]
    async fn memory_owners_bind_look_up_and_forget() {
        let owners = SessionOwners::new(None);
        assert_eq!(owners.owner("a").await.expect("owner"), None);
        owners.bind("a", "token:x").await.expect("bind");
        assert_eq!(
            owners.owner("a").await.expect("owner"),
            Some(String::from("token:x"))
        );
        owners.forget("a").await.expect("forget");
        assert_eq!(owners.owner("a").await.expect("owner"), None);
    }

    #[test]
    fn idle_owners_are_pruned() {
        let owners = DashMap::new();
        let now = Instant::now();
        owners.insert(String::from("old"), (String::from("x"), now));
        owners.insert(String::from("new"), (String::from("x"), now));
        let later = now + MCP_SESSION_IDLE + Duration::from_secs(1);
        owners.alter("new", |_, (owner, _)| (owner, later));
        prune(&owners, later);
        assert!(!owners.contains_key("old"));
        assert!(owners.contains_key("new"));
    }
}
