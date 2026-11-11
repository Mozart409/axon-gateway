//! Tool-list change notifications for MCP clients.
//!
//! Whatever can change what a caller's `tools/list` returns publishes a
//! [`ChangeScope`] on the [`ChangeBus`]: a backend's tools (registry), grants,
//! groups and roles (policy refresh), a user's opt-outs and toolsets. Every
//! open MCP subscription (a 2026-07-28 `subscriptions/listen`, or the stream of
//! a pre-2026-07-28 session) waits on a [`ChangeSubscription`] and sends
//! `notifications/tools/list_changed` to the callers a change concerns.

use std::time::Duration;

use tokio::sync::broadcast;
use uuid::Uuid;

/// Changes buffered per subscriber. One that falls further behind treats the
/// lag as a change that concerns it, so it loses precision, never a change.
const CAPACITY: usize = 256;

/// How long a subscriber waits after a change for more of the same burst
/// (a backend reconnecting, an admin editing several grants), so a client
/// hears one `list_changed` instead of a dozen.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Whose tool list a change may have changed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeScope {
    /// Backends, grants, groups or roles: any caller's list may differ
    All,
    /// One user's opt-outs or toolsets: only that user's callers
    User(Uuid),
}

impl ChangeScope {
    /// Whether a caller owned by `owner` is concerned. Legacy tokens and open
    /// callers have no owner and hear only [`ChangeScope::All`].
    pub fn concerns(self, owner: Option<Uuid>) -> bool {
        match self {
            Self::All => true,
            Self::User(user) => owner == Some(user),
        }
    }
}

/// Where tool-list changes are published; cheap to clone
#[derive(Debug, Clone)]
pub struct ChangeBus {
    sender: broadcast::Sender<ChangeScope>,
}

impl ChangeBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CAPACITY);
        Self { sender }
    }

    /// Publishes a change. Nothing happens when no client listens.
    pub fn publish(&self, scope: ChangeScope) {
        // An error only means there is no subscriber right now
        let _ = self.sender.send(scope);
    }

    /// A subscription that sees every change published from now on.
    pub fn subscribe(&self) -> ChangeSubscription {
        ChangeSubscription {
            receiver: self.sender.subscribe(),
        }
    }
}

impl Default for ChangeBus {
    fn default() -> Self {
        Self::new()
    }
}

/// One listener's view of the [`ChangeBus`]
#[derive(Debug)]
pub struct ChangeSubscription {
    receiver: broadcast::Receiver<ChangeScope>,
}

impl ChangeSubscription {
    /// Waits for the next change that concerns a caller owned by `owner`,
    /// then for the rest of its burst. `false` once the bus is gone.
    pub async fn changed_for(&mut self, owner: Option<Uuid>) -> bool {
        loop {
            match self.receiver.recv().await {
                Ok(scope) if scope.concerns(owner) => break,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => break,
                Err(broadcast::error::RecvError::Closed) => return false,
            }
        }
        tokio::time::sleep(DEBOUNCE).await;
        // Drop the rest of the burst; a later change wakes the next wait
        while let Ok(_) | Err(broadcast::error::TryRecvError::Lagged(_)) = self.receiver.try_recv()
        {
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_change_concerns_only_that_user() {
        let user = Uuid::new_v4();
        assert!(ChangeScope::User(user).concerns(Some(user)));
        assert!(!ChangeScope::User(user).concerns(Some(Uuid::new_v4())));
        assert!(!ChangeScope::User(user).concerns(None));
        assert!(ChangeScope::All.concerns(None));
    }

    #[tokio::test]
    async fn a_burst_wakes_a_subscriber_once() {
        let bus = ChangeBus::new();
        let mut subscription = bus.subscribe();
        for _ in 0..5 {
            bus.publish(ChangeScope::All);
        }
        assert!(subscription.changed_for(None).await);
        assert!(subscription.receiver.is_empty());
    }

    #[tokio::test]
    async fn another_users_change_is_skipped() {
        let bus = ChangeBus::new();
        let mut subscription = bus.subscribe();
        let me = Uuid::new_v4();
        bus.publish(ChangeScope::User(Uuid::new_v4()));
        bus.publish(ChangeScope::User(me));
        assert!(subscription.changed_for(Some(me)).await);
    }

    #[tokio::test]
    async fn a_dropped_bus_ends_the_subscription() {
        let bus = ChangeBus::new();
        let mut subscription = bus.subscribe();
        drop(bus);
        assert!(!subscription.changed_for(None).await);
    }
}
