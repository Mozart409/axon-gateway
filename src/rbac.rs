//! Runtime RBAC management: the live policy handle and the admin service
//!
//! [`PolicyHandle`] holds the database [`Policy`] and swaps it
//! atomically on [`PolicyHandle::refresh`]; a background task refreshes it so that
//! replicas pick up each other's changes. [`Admin`] is the service layer behind the
//! `/api/v1` admin API (and the admin pages to come): it checks the caller's
//! permissions, validates input, writes through the store (which audits every
//! change) and reloads the policy.

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::changes::{ChangeBus, ChangeScope};
use crate::gateway::GetDetailedStatus;
use crate::policy::{
    GrantConfig, GrantView, GroupView, Permission, Permissions, Policy, RbacSnapshot, Role,
    RoleBinding, RoleSource, RoleSubject, RoleView, parse_permissions, validate_grant,
    validate_group_name, validate_role_name,
};
use crate::principal::TokenScope;
use crate::server::AppState;
use crate::store::{
    Actor, ApiToken, AuditRecord, DEFAULT_TOKEN_LIFETIME, IssuedToken, JwtBinding, JwtBindingError,
    NewToken, NewToolset, RoleDeletion, ServiceAccount, SessionUser, Store, StoreError, TokenError,
    Toolset, ToolsetError, User,
};

/// How often the policy is re-read from the database, so that changes made
/// through another replica show up here.
pub const POLICY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Longest group description, in characters.
const MAX_DESCRIPTION_CHARS: usize = 500;

/// Longest `IdP` subject of a JWT binding, in characters.
const MAX_JWT_SUBJECT_CHARS: usize = 255;

/// Most backends or tool globs one toolset holds.
const MAX_TOOLSET_LIST_ENTRIES: usize = 100;

/// Most backends or tool globs one token may be narrowed to.
const MAX_SCOPE_ENTRIES: usize = 50;

/// Longest backend name or tool glob in a token scope, in characters.
const MAX_SCOPE_ENTRY_CHARS: usize = 200;

/// The live policy, compiled from the database rows.
#[derive(Debug)]
pub struct PolicyHandle {
    current: RwLock<Arc<Policy>>,
    /// The snapshot of the last refresh; `None` until the first one
    last_snapshot: Mutex<Option<RbacSnapshot>>,
    /// Told when a refresh finds the database rows changed
    changes: Option<ChangeBus>,
}

impl Default for PolicyHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyHandle {
    /// A handle on the empty policy; [`PolicyHandle::refresh`] loads the
    /// database rows.
    pub fn new() -> Self {
        let policy = Arc::new(Policy::from_snapshot(&RbacSnapshot::default()));
        Self {
            current: RwLock::new(policy),
            last_snapshot: Mutex::new(None),
            changes: None,
        }
    }

    /// A handle on the policy of `snapshot`, for tests that render with one.
    #[cfg(test)]
    pub fn from_snapshot(snapshot: &RbacSnapshot) -> Self {
        let handle = Self::new();
        *handle
            .current
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(Policy::from_snapshot(snapshot));
        handle
    }

    /// Publishes [`ChangeScope::All`] on `changes` whenever a refresh finds the
    /// database rows changed.
    #[must_use]
    pub fn with_change_bus(mut self, changes: ChangeBus) -> Self {
        self.changes = Some(changes);
        self
    }

    /// The policy as of the last refresh. Hold it for one request, not longer.
    pub fn current(&self) -> Arc<Policy> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reloads the database rows and swaps the policy in.
    ///
    /// # Errors
    /// Fails when the snapshot cannot be read; the previous policy stays.
    pub async fn refresh(&self, store: &Store) -> Result<(), StoreError> {
        let snapshot = store.rbac_snapshot().await?;
        let policy = Arc::new(Policy::from_snapshot(&snapshot));
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = policy;
        if self.remember(snapshot)
            && let Some(changes) = &self.changes
        {
            changes.publish(ChangeScope::All);
        }
        Ok(())
    }

    /// Keeps `snapshot` as the latest one; whether it differs from the one before.
    /// The first snapshot is no change: nobody has listened to the empty policy.
    fn remember(&self, snapshot: RbacSnapshot) -> bool {
        let mut last = self
            .last_snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let changed = last.as_ref().is_some_and(|previous| *previous != snapshot);
        *last = Some(snapshot);
        changed
    }
}

/// Refreshes the policy every [`POLICY_REFRESH_INTERVAL`], so that changes made
/// through other replicas are picked up.
pub fn spawn_policy_refresh(handle: Arc<PolicyHandle>, store: Store) {
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + POLICY_REFRESH_INTERVAL;
        let mut interval = tokio::time::interval_at(start, POLICY_REFRESH_INTERVAL);
        loop {
            interval.tick().await;
            if let Err(error) = handle.refresh(&store).await {
                tracing::warn!(%error, "Failed to refresh the RBAC policy");
            }
        }
    });
}

/// The groups and permissions of a logged-in user under `policy`.
pub fn resolve(policy: &Policy, session: &SessionUser) -> (Vec<String>, Permissions) {
    let groups = policy.groups_for(session.user.id, &session.provider_id, &session.user.groups);
    let permissions = policy.permissions_for(session.user.id, &groups, session.user.is_admin);
    (groups, permissions)
}

/// Why an admin operation did not happen
#[derive(Debug, Error)]
pub enum AdminError {
    #[error("you are not allowed to do that")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    Invalid(String),

    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<TokenError> for AdminError {
    fn from(error: TokenError) -> Self {
        match error {
            TokenError::InvalidName | TokenError::ExpiryInPast | TokenError::ExpiryTooLong(_) => {
                Self::Invalid(error.to_string())
            }
            TokenError::UnknownOwner | TokenError::UnknownToolset => Self::NotFound,
            TokenError::Store(error) => Self::Store(error),
            TokenError::Query(error) => Self::Store(StoreError::Query(error)),
        }
    }
}

impl From<ToolsetError> for AdminError {
    fn from(error: ToolsetError) -> Self {
        match error {
            ToolsetError::InvalidName(_) | ToolsetError::InvalidEntries(_) => {
                Self::Invalid(error.to_string())
            }
            ToolsetError::UnknownOwner => Self::NotFound,
            ToolsetError::NameTaken | ToolsetError::Pinned => Self::Conflict(error.to_string()),
            ToolsetError::Store(error) => Self::Store(error),
            ToolsetError::Query(error) => Self::Store(StoreError::Query(error)),
        }
    }
}

impl From<JwtBindingError> for AdminError {
    fn from(error: JwtBindingError) -> Self {
        match error {
            JwtBindingError::UnknownServiceAccount => Self::NotFound,
            JwtBindingError::AlreadyBound => Self::Conflict(error.to_string()),
            JwtBindingError::Store(error) => Self::Store(error),
            JwtBindingError::Query(error) => Self::Store(StoreError::Query(error)),
        }
    }
}

fn already_exists() -> AdminError {
    AdminError::Conflict("already exists".to_owned())
}

/// Email, else display name, else subject: how the audit log names the user.
fn actor_label(user: &User) -> String {
    [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
        .to_owned()
}

/// Trims a description; blank means none.
fn clean_description(description: Option<&str>) -> Result<Option<String>, AdminError> {
    let Some(description) = description.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(AdminError::Invalid(format!(
            "description must be at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(Some(description.to_owned()))
}

/// A role with the number of role bindings that name it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleEntry {
    pub role: RoleView,
    pub bindings: usize,
}

/// A human user as the users page lists them
#[derive(Debug, Clone)]
pub struct ManagedUser {
    pub user: User,
    pub last_login_at: Option<DateTime<Utc>>,
    pub disabled: bool,
}

fn managed_user(
    user: User,
    last_login_at: Option<DateTime<Utc>>,
    disabled_at: Option<DateTime<Utc>>,
) -> ManagedUser {
    ManagedUser {
        user,
        last_login_at,
        disabled: disabled_at.is_some(),
    }
}

/// The admin operations for one logged-in user.
pub struct Admin<'a> {
    store: &'a Store,
    policy: &'a PolicyHandle,
    actor: Actor,
    permissions: Permissions,
    /// Backends a grant may name
    backends: Vec<String>,
    /// `[[auth.oidc]]` ids an `IdP` mapping may name
    providers: Vec<String>,
}

impl<'a> Admin<'a> {
    pub fn new(
        store: &'a Store,
        policy: &'a PolicyHandle,
        session: &SessionUser,
        backends: Vec<String>,
        providers: Vec<String>,
    ) -> Self {
        let (_, permissions) = resolve(&policy.current(), session);
        Self {
            store,
            policy,
            actor: Actor {
                user_id: Some(session.user.id),
                label: actor_label(&session.user),
            },
            permissions,
            backends,
            providers,
        }
    }

    /// The admin service for a session; `None` outside multi-user mode. The
    /// backends are the gateway's current ones.
    pub async fn from_state(state: &'a AppState, session: &SessionUser) -> Option<Admin<'a>> {
        let (store, oidc) = state.multi_user()?;
        let mut backends: Vec<String> = match state.gateway.ask(GetDetailedStatus).await {
            Ok(status) => status
                .backends
                .into_iter()
                .map(|backend| backend.name)
                .collect(),
            Err(error) => {
                tracing::warn!(?error, "Failed to list backends for an admin request");
                Vec::new()
            }
        };
        // Catalog entries are granted like shared backends
        if let Some(hub) = &state.personal {
            backends.extend(hub.catalog().into_iter().map(|item| item.name));
        }
        let providers = oidc
            .list()
            .iter()
            .map(|provider| provider.id().to_owned())
            .collect();
        Some(Self::new(
            store,
            &state.policy,
            session,
            backends,
            providers,
        ))
    }

    fn require(&self, permission: Permission) -> Result<(), AdminError> {
        self.require_any(&[permission])
    }

    fn require_any(&self, permissions: &[Permission]) -> Result<(), AdminError> {
        if permissions
            .iter()
            .any(|permission| self.permissions.has(*permission))
        {
            Ok(())
        } else {
            Err(AdminError::Forbidden)
        }
    }

    /// A group: missing is not found.
    fn local_group(&self, name: &str) -> Result<GroupView, AdminError> {
        self.policy
            .current()
            .group(name)
            .ok_or(AdminError::NotFound)
    }

    /// Re-reads the policy after a write. The write stands when this fails;
    /// the periodic refresh catches up.
    async fn reload(&self) {
        if let Err(error) = self.policy.refresh(self.store).await {
            tracing::warn!(%error, "Failed to reload the RBAC policy after a change");
        }
    }

    /// The anti-escalation rule: whoever hands out permissions (in a custom role or
    /// by binding a role) must hold every one of them.
    fn require_holds(&self, wanted: &[Permission]) -> Result<(), AdminError> {
        if self.permissions.missing(wanted).is_empty() {
            Ok(())
        } else {
            Err(AdminError::Forbidden)
        }
    }

    /// A custom role: missing is not found, built in cannot be changed.
    fn local_role(&self, name: &str) -> Result<RoleView, AdminError> {
        let role = self
            .policy
            .current()
            .role(name)
            .ok_or(AdminError::NotFound)?;
        match role.source {
            RoleSource::Local => Ok(role),
            RoleSource::Builtin => Err(AdminError::Conflict(
                "built-in role, cannot be changed".to_owned(),
            )),
        }
    }

    /// Everything that lists groups, grants, roles or bindings.
    fn require_listing(&self) -> Result<(), AdminError> {
        self.require_any(&[
            Permission::GroupsManage,
            Permission::RolesManage,
            Permission::AuditRead,
        ])
    }

    /// All groups, by name.
    ///
    /// # Errors
    /// [`AdminError::Forbidden`] without `groups.manage` or `audit.read`.
    pub fn groups(&self) -> Result<Vec<GroupView>, AdminError> {
        self.require_listing()?;
        Ok(self.policy.current().groups())
    }

    /// One group with the ids of its members.
    ///
    /// # Errors
    /// Forbidden like [`Admin::groups`], [`AdminError::NotFound`] for an
    /// unknown group.
    pub fn group(&self, name: &str) -> Result<(GroupView, Vec<Uuid>), AdminError> {
        self.require_listing()?;
        let policy = self.policy.current();
        let group = policy.group(name).ok_or(AdminError::NotFound)?;
        let members = policy.members_of(name);
        Ok((group, members))
    }

    /// All grants, by id.
    ///
    /// # Errors
    /// Forbidden like [`Admin::groups`].
    pub fn grants(&self) -> Result<Vec<GrantView>, AdminError> {
        self.require_listing()?;
        Ok(self.policy.current().grants())
    }

    /// All role bindings, by id.
    ///
    /// # Errors
    /// Forbidden like [`Admin::groups`].
    pub fn role_bindings(&self) -> Result<Vec<RoleBinding>, AdminError> {
        self.require_listing()?;
        Ok(self.policy.current().role_bindings())
    }

    /// All roles (built-in, custom) with their binding counts.
    ///
    /// # Errors
    /// Forbidden like [`Admin::groups`].
    pub fn roles(&self) -> Result<Vec<RoleEntry>, AdminError> {
        self.require_listing()?;
        let policy = self.policy.current();
        let bindings = policy.role_bindings();
        Ok(policy
            .roles()
            .into_iter()
            .map(|role| {
                let count = bindings.iter().filter(|b| b.role == role.name).count();
                RoleEntry {
                    role,
                    bindings: count,
                }
            })
            .collect())
    }

    /// Every permission a role may carry.
    ///
    /// # Errors
    /// Forbidden like [`Admin::groups`].
    pub fn permission_catalog(&self) -> Result<Vec<Permission>, AdminError> {
        self.require_listing()?;
        Ok(Permission::ALL.to_vec())
    }

    /// Up to `limit` users.
    ///
    /// # Errors
    /// Forbidden without `users.manage` or `groups.manage`; a store error.
    pub async fn users(&self, limit: i64) -> Result<Vec<User>, AdminError> {
        self.require_any(&[Permission::UsersManage, Permission::GroupsManage])?;
        Ok(self.store.list_users(limit).await?)
    }

    /// Up to `limit` human users (not service accounts) with their last login
    /// and disabled state.
    ///
    /// # Errors
    /// Forbidden without `users.manage` or `groups.manage`; a store error.
    pub async fn managed_users(&self, limit: i64) -> Result<Vec<ManagedUser>, AdminError> {
        self.require_any(&[Permission::UsersManage, Permission::GroupsManage])?;
        Ok(self
            .store
            .list_user_states(limit)
            .await?
            .into_iter()
            .map(|state| managed_user(state.user, state.last_login_at, state.disabled_at))
            .collect())
    }

    /// Disables or re-enables a human user: a disabled user cannot log in,
    /// their sessions end and their tokens stop working. Setting the state
    /// the user already has is not an error.
    ///
    /// # Errors
    /// Forbidden without `users.manage`, not found for an unknown id or a
    /// service account, conflict when disabling yourself.
    pub async fn set_user_disabled(
        &self,
        id: Uuid,
        disabled: bool,
    ) -> Result<ManagedUser, AdminError> {
        self.require(Permission::UsersManage)?;
        if disabled && self.actor.user_id == Some(id) {
            return Err(AdminError::Conflict(
                "you cannot disable your own account".to_owned(),
            ));
        }
        if self.store.user_state(id).await?.is_none() {
            return Err(AdminError::NotFound);
        }
        self.store
            .set_user_disabled(&self.actor, id, disabled)
            .await?;
        let state = self
            .store
            .user_state(id)
            .await?
            .ok_or(AdminError::NotFound)?;
        Ok(managed_user(
            state.user,
            state.last_login_at,
            state.disabled_at,
        ))
    }

    /// Up to `limit` audit entries, newest first, older than `before`.
    ///
    /// # Errors
    /// Forbidden without `audit.read`; a store error.
    pub async fn audit(
        &self,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Vec<AuditRecord>, AdminError> {
        self.require(Permission::AuditRead)?;
        Ok(self.store.audit_log(limit, before).await?)
    }

    /// Creates a group.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, invalid for a bad name or
    /// description, conflict when the name is taken.
    pub async fn create_group(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        validate_group_name(name).map_err(AdminError::Invalid)?;
        let description = clean_description(description)?;
        if self.policy.current().has_group(name) {
            return Err(already_exists());
        }
        if !self
            .store
            .create_group(&self.actor, name, description.as_deref())
            .await?
        {
            return Err(already_exists());
        }
        self.reload().await;
        Ok(())
    }

    /// Sets (or with `None` clears) a group's description.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, not found for an unknown group.
    pub async fn update_group(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(name)?;
        let description = clean_description(description)?;
        // `false` means the description is already that: nothing to do.
        if self
            .store
            .update_group(&self.actor, name, description.as_deref())
            .await?
        {
            self.reload().await;
        }
        Ok(())
    }

    /// Deletes a group with its mappings, memberships, grants and bindings.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, not found for an unknown group.
    pub async fn delete_group(&self, name: &str) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(name)?;
        if !self.store.delete_group(&self.actor, name).await? {
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }

    /// Maps an `IdP` claim value of a configured provider to a group.
    ///
    /// # Errors
    /// Forbidden without `groups.manage` or without every permission of the
    /// roles bound to the group, invalid for an unknown provider or an empty
    /// value, conflict for an existing mapping.
    pub async fn add_idp_mapping(
        &self,
        group: &str,
        provider: &str,
        value: &str,
    ) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(group)?;
        self.require_holds(&self.policy.current().group_permissions(group))?;
        if !self.providers.iter().any(|id| id == provider) {
            return Err(AdminError::Invalid(format!(
                "unknown OIDC provider {provider:?}"
            )));
        }
        if value.trim().is_empty() {
            return Err(AdminError::Invalid("value must not be empty".to_owned()));
        }
        if !self
            .store
            .add_idp_mapping(&self.actor, group, provider, value)
            .await?
        {
            return Err(already_exists());
        }
        self.reload().await;
        Ok(())
    }

    /// Removes an `IdP` mapping from a group.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, not found for an unknown group or
    /// mapping.
    pub async fn remove_idp_mapping(
        &self,
        group: &str,
        provider: &str,
        value: &str,
    ) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(group)?;
        if !self
            .store
            .remove_idp_mapping(&self.actor, group, provider, value)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }

    /// Adds a user to a group.
    ///
    /// # Errors
    /// Forbidden without `groups.manage` or without every permission of the
    /// roles bound to the group, not found for an unknown group or user,
    /// conflict for an existing member.
    pub async fn add_member(&self, group: &str, user_id: Uuid) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(group)?;
        self.require_holds(&self.policy.current().group_permissions(group))?;
        if !self.store.add_member(&self.actor, group, user_id).await? {
            // The group exists, so either the user is already in or unknown.
            if self.policy.current().members_of(group).contains(&user_id) {
                return Err(already_exists());
            }
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }

    /// Removes a user from a group.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, not found for an unknown group or
    /// non-member.
    pub async fn remove_member(&self, group: &str, user_id: Uuid) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        self.local_group(group)?;
        if !self
            .store
            .remove_member(&self.actor, group, user_id)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }

    /// Stores a grant and returns its id.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`; invalid when the group or backend
    /// is unknown or the tool patterns are bad.
    pub async fn create_grant(&self, grant: GrantConfig) -> Result<i64, AdminError> {
        self.require(Permission::GroupsManage)?;
        let backends: Vec<&str> = self.backends.iter().map(String::as_str).collect();
        validate_grant(&grant, &self.policy.current(), &backends).map_err(AdminError::Invalid)?;
        let id = self.store.create_grant(&self.actor, &grant).await?;
        self.reload().await;
        Ok(id)
    }

    /// Deletes a grant.
    ///
    /// # Errors
    /// Forbidden without `groups.manage`, not found for an unknown id.
    pub async fn delete_grant(&self, id: i64) -> Result<(), AdminError> {
        self.require(Permission::GroupsManage)?;
        if self.store.delete_grant(&self.actor, id).await?.is_none() {
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }

    /// Creates a custom role and returns it.
    ///
    /// # Errors
    /// Forbidden without `roles.manage` or when the role would carry a
    /// permission the caller does not hold, invalid for a bad name, description
    /// or permission list, conflict when the name is a built-in or custom role.
    pub async fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        permissions: &[String],
    ) -> Result<RoleEntry, AdminError> {
        self.require(Permission::RolesManage)?;
        // A built-in name is taken, not malformed.
        if Role::parse(name).is_some() {
            return Err(AdminError::Conflict(
                "built-in role, cannot be changed".to_owned(),
            ));
        }
        validate_role_name(name).map_err(AdminError::Invalid)?;
        let description = clean_description(description)?;
        let permissions = parse_permissions(permissions).map_err(AdminError::Invalid)?;
        self.require_holds(&permissions)?;
        if self.policy.current().role(name).is_some() {
            return Err(already_exists());
        }
        if !self
            .store
            .create_role(&self.actor, name, description.as_deref(), &permissions)
            .await?
        {
            return Err(already_exists());
        }
        self.reload().await;
        // Built here: the policy may not have reloaded yet if the refresh failed.
        Ok(RoleEntry {
            role: RoleView {
                name: name.to_owned(),
                description,
                source: RoleSource::Local,
                permissions,
            },
            bindings: 0,
        })
    }

    /// Replaces a custom role's description and permissions and returns it.
    ///
    /// # Errors
    /// Forbidden without `roles.manage` or when the new permissions include one
    /// the caller does not hold, not found for an unknown role, conflict for a
    /// built-in role, invalid for a bad description or permission list.
    pub async fn update_role(
        &self,
        name: &str,
        description: Option<&str>,
        permissions: &[String],
    ) -> Result<RoleEntry, AdminError> {
        self.require(Permission::RolesManage)?;
        self.local_role(name)?;
        let description = clean_description(description)?;
        let permissions = parse_permissions(permissions).map_err(AdminError::Invalid)?;
        self.require_holds(&permissions)?;
        // `false` means the role already is that: nothing to do.
        if self
            .store
            .update_role(&self.actor, name, description.as_deref(), &permissions)
            .await?
        {
            self.reload().await;
        }
        let bindings = self
            .policy
            .current()
            .role_bindings()
            .iter()
            .filter(|binding| binding.role == name)
            .count();
        Ok(RoleEntry {
            role: RoleView {
                name: name.to_owned(),
                description,
                source: RoleSource::Local,
                permissions,
            },
            bindings,
        })
    }

    /// Deletes a custom role. With `force` the bindings that name it go too.
    ///
    /// # Errors
    /// Forbidden without `roles.manage`, not found for an unknown role,
    /// conflict for a built-in role, or when bindings name the role
    /// and `force` is not set.
    pub async fn delete_role(&self, name: &str, force: bool) -> Result<(), AdminError> {
        self.require(Permission::RolesManage)?;
        self.local_role(name)?;
        match self.store.delete_role(&self.actor, name, force).await? {
            RoleDeletion::Deleted => {}
            RoleDeletion::Missing => return Err(AdminError::NotFound),
            RoleDeletion::HasBindings(count) => {
                return Err(AdminError::Conflict(format!(
                    "{count} role binding(s) name this role; delete them too with force"
                )));
            }
        }
        self.reload().await;
        Ok(())
    }

    /// Binds a role (built-in or custom, by name) to a group or a user and
    /// returns the binding's id.
    ///
    /// # Errors
    /// Forbidden without `roles.manage` or when the role carries a permission
    /// the caller does not hold, invalid for an unknown role or group, not
    /// found for an unknown user, conflict when the binding exists.
    pub async fn create_role_binding(
        &self,
        role: &str,
        subject: RoleSubject,
    ) -> Result<i64, AdminError> {
        self.require(Permission::RolesManage)?;
        let policy = self.policy.current();
        let Some(carried) = policy.role_permissions(role) else {
            return Err(AdminError::Invalid(format!("unknown role {role:?}")));
        };
        self.require_holds(&carried)?;
        if let RoleSubject::Group(group) = &subject
            && !policy.has_group(group)
        {
            return Err(AdminError::Invalid(format!("unknown group {group:?}")));
        }
        let id = match self
            .store
            .create_role_binding(&self.actor, role, &subject)
            .await
        {
            Ok(id) => id,
            // The user id has no row in `users`.
            Err(StoreError::Query(sqlx::Error::Database(error)))
                if error.is_foreign_key_violation() =>
            {
                return Err(AdminError::NotFound);
            }
            Err(error) => return Err(error.into()),
        };
        let Some(id) = id else {
            return Err(already_exists());
        };
        self.reload().await;
        Ok(id)
    }

    /// Deletes a role binding.
    ///
    /// # Errors
    /// Forbidden without `roles.manage`, not found for an unknown id.
    pub async fn delete_role_binding(&self, id: i64) -> Result<(), AdminError> {
        self.require(Permission::RolesManage)?;
        if !self.store.delete_role_binding(&self.actor, id).await? {
            return Err(AdminError::NotFound);
        }
        self.reload().await;
        Ok(())
    }
}

/// Whole days in a token lifetime, for forms and messages.
pub fn lifetime_days(lifetime: Duration) -> u64 {
    lifetime.as_secs() / 86_400
}

/// When a token issued now with `expires_in_days` (default
/// [`DEFAULT_TOKEN_LIFETIME`]) expires. The store enforces the owner's maximum.
fn expiry(expires_in_days: Option<u32>) -> Result<DateTime<Utc>, AdminError> {
    let days = expires_in_days.map_or_else(|| lifetime_days(DEFAULT_TOKEN_LIFETIME), u64::from);
    if days == 0 {
        return Err(AdminError::Invalid(
            "expires_in_days must be at least 1".to_owned(),
        ));
    }
    i64::try_from(days)
        .ok()
        .and_then(TimeDelta::try_days)
        .and_then(|lifetime| Utc::now().checked_add_signed(lifetime))
        .ok_or_else(|| AdminError::Invalid("expires_in_days is too large".to_owned()))
}

/// Trims and deduplicates one scope list. A blank entry is refused rather than
/// dropped: a token narrowed to nothing but blanks would otherwise end up
/// unnarrowed.
fn clean_scope_list(entries: &[String], what: &str) -> Result<Vec<String>, AdminError> {
    if entries.len() > MAX_SCOPE_ENTRIES {
        return Err(AdminError::Invalid(format!(
            "at most {MAX_SCOPE_ENTRIES} {what} per token"
        )));
    }
    let mut cleaned: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() || entry.chars().count() > MAX_SCOPE_ENTRY_CHARS {
            return Err(AdminError::Invalid(format!(
                "each of the {what} must be 1 to {MAX_SCOPE_ENTRY_CHARS} characters"
            )));
        }
        if !cleaned.iter().any(|seen| seen == entry) {
            cleaned.push(entry.to_owned());
        }
    }
    Ok(cleaned)
}

/// Trims and deduplicates one toolset list; like a scope list, a blank entry is
/// refused so that a toolset of blanks cannot end up unnarrowed.
fn clean_toolset_list(entries: &[String], what: &str) -> Result<Vec<String>, AdminError> {
    if entries.len() > MAX_TOOLSET_LIST_ENTRIES {
        return Err(AdminError::Invalid(format!(
            "at most {MAX_TOOLSET_LIST_ENTRIES} {what} per toolset"
        )));
    }
    let mut cleaned: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = entry.trim();
        if entry.is_empty() || entry.chars().count() > MAX_SCOPE_ENTRY_CHARS {
            return Err(AdminError::Invalid(format!(
                "each of the {what} must be 1 to {MAX_SCOPE_ENTRY_CHARS} characters"
            )));
        }
        if !cleaned.iter().any(|seen| seen == entry) {
            cleaned.push(entry.to_owned());
        }
    }
    Ok(cleaned)
}

/// Issues a token for `owner_id`; the owner must already be known to be
/// allowed to have one. `toolset_id` pins it to a toolset of the owner.
async fn issue_token(
    store: &Store,
    actor: &Actor,
    owner_id: Uuid,
    name: &str,
    expires_in_days: Option<u32>,
    scope: &TokenScope,
    toolset_id: Option<Uuid>,
) -> Result<IssuedToken, AdminError> {
    let scope_backends = clean_scope_list(&scope.backends, "backends")?;
    let scope_tools = clean_scope_list(&scope.tools, "tool patterns")?;
    let expires_at = expiry(expires_in_days)?;
    let new = NewToken {
        owner_id,
        name: name.trim(),
        scope_backends: &scope_backends,
        scope_tools: &scope_tools,
        toolset_id,
        expires_at,
    };
    Ok(store.create_token(actor, &new).await?)
}

/// Where a token is in its life
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    Active,
    Expired,
    Revoked,
}

impl TokenState {
    /// The state of `token` now; revoked wins over expired.
    pub fn of(token: &ApiToken) -> Self {
        if token.revoked {
            Self::Revoked
        } else if token.expires_at <= Utc::now() {
            Self::Expired
        } else {
            Self::Active
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

/// The token operations every signed-in user has on their own tokens.
pub struct MyTokens<'a> {
    store: &'a Store,
    actor: Actor,
    owner_id: Uuid,
    /// Told when a toolset of the caller changes
    changes: Option<ChangeBus>,
}

impl<'a> MyTokens<'a> {
    pub fn new(store: &'a Store, session: &SessionUser) -> Self {
        Self {
            store,
            actor: Actor {
                user_id: Some(session.user.id),
                label: actor_label(&session.user),
            },
            owner_id: session.user.id,
            changes: None,
        }
    }

    /// Publishes [`ChangeScope::User`] on `changes` when a toolset of the caller changes.
    #[must_use]
    pub fn with_change_bus(mut self, changes: ChangeBus) -> Self {
        self.changes = Some(changes);
        self
    }

    /// The service for a session; `None` outside multi-user mode.
    pub fn from_state(state: &'a AppState, session: &SessionUser) -> Option<Self> {
        let (store, _) = state.multi_user()?;
        Some(Self::new(store, session).with_change_bus(state.changes.clone()))
    }

    /// Tells the caller's open MCP connections that their tool list may differ.
    fn toolsets_changed(&self) {
        if let Some(changes) = &self.changes {
            changes.publish(ChangeScope::User(self.owner_id));
        }
    }

    /// The caller's tokens, newest first, revoked and expired ones included.
    ///
    /// # Errors
    /// A store error.
    pub async fn list(&self) -> Result<Vec<ApiToken>, AdminError> {
        Ok(self.store.list_tokens(self.owner_id).await?)
    }

    /// Issues a token for the caller. `expires_in_days` defaults to 30 days
    /// and is capped by the store at 90. `toolset_id` pins it to one of the
    /// caller's toolsets.
    ///
    /// # Errors
    /// Invalid for a bad name, scope or expiry, or an expiry beyond the
    /// maximum; not found for a toolset that is not the caller's; a store error.
    pub async fn create(
        &self,
        name: &str,
        expires_in_days: Option<u32>,
        scope: &TokenScope,
        toolset_id: Option<Uuid>,
    ) -> Result<IssuedToken, AdminError> {
        issue_token(
            self.store,
            &self.actor,
            self.owner_id,
            name,
            expires_in_days,
            scope,
            toolset_id,
        )
        .await
    }

    /// The caller's toolsets, by name.
    ///
    /// # Errors
    /// A store error.
    pub async fn toolsets(&self) -> Result<Vec<Toolset>, AdminError> {
        Ok(self.store.list_toolsets(self.owner_id).await?)
    }

    /// One of the caller's toolsets.
    ///
    /// # Errors
    /// Not found for an unknown id or someone else's toolset; a store error.
    pub async fn toolset(&self, id: Uuid) -> Result<Toolset, AdminError> {
        self.store
            .toolset(self.owner_id, id)
            .await?
            .ok_or(AdminError::NotFound)
    }

    /// Creates a toolset for the caller. `scope` holds its tool globs and backends.
    ///
    /// # Errors
    /// Invalid for a bad name or list; conflict when the name is taken; a store error.
    pub async fn create_toolset(
        &self,
        name: &str,
        description: Option<&str>,
        scope: &TokenScope,
    ) -> Result<Toolset, AdminError> {
        let description = clean_description(description)?;
        let tools = clean_toolset_list(&scope.tools, "tool patterns")?;
        let backends = clean_toolset_list(&scope.backends, "backends")?;
        let new = NewToolset {
            name: name.trim(),
            description: description.as_deref(),
            tools: &tools,
            backends: &backends,
        };
        let toolset = self
            .store
            .create_toolset(&self.actor, self.owner_id, &new)
            .await?;
        self.toolsets_changed();
        Ok(toolset)
    }

    /// Replaces name, description and lists of one of the caller's toolsets; the
    /// tokens pinned to it follow at once.
    ///
    /// # Errors
    /// Invalid for a bad name or list; conflict when the name is taken; not found
    /// for an unknown id or someone else's toolset; a store error.
    pub async fn update_toolset(
        &self,
        id: Uuid,
        name: &str,
        description: Option<&str>,
        scope: &TokenScope,
    ) -> Result<Toolset, AdminError> {
        let description = clean_description(description)?;
        let tools = clean_toolset_list(&scope.tools, "tool patterns")?;
        let backends = clean_toolset_list(&scope.backends, "backends")?;
        let new = NewToolset {
            name: name.trim(),
            description: description.as_deref(),
            tools: &tools,
            backends: &backends,
        };
        let toolset = self
            .store
            .update_toolset(&self.actor, self.owner_id, id, &new)
            .await?
            .ok_or(AdminError::NotFound)?;
        self.toolsets_changed();
        Ok(toolset)
    }

    /// Deletes one of the caller's toolsets.
    ///
    /// # Errors
    /// Conflict while a token that is still valid is pinned to it; not found for an
    /// unknown id or someone else's toolset; a store error.
    pub async fn delete_toolset(&self, id: Uuid) -> Result<(), AdminError> {
        if !self
            .store
            .delete_toolset(&self.actor, self.owner_id, id)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        self.toolsets_changed();
        Ok(())
    }

    /// Revokes one of the caller's tokens.
    ///
    /// # Errors
    /// Not found when the caller has no such live token; a store error.
    pub async fn revoke(&self, id: Uuid) -> Result<(), AdminError> {
        if !self
            .store
            .revoke_token(&self.actor, Some(self.owner_id), id)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        Ok(())
    }
}

impl Admin<'_> {
    /// A service account by id (an id of a human is not found).
    async fn account(&self, id: Uuid) -> Result<ServiceAccount, AdminError> {
        self.require(Permission::ServiceAccountsManage)?;
        self.store
            .service_account(id)
            .await?
            .ok_or(AdminError::NotFound)
    }

    /// All service accounts, by name.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`; a store error.
    pub async fn service_accounts(&self) -> Result<Vec<ServiceAccount>, AdminError> {
        self.require(Permission::ServiceAccountsManage)?;
        Ok(self.store.list_service_accounts().await?)
    }

    /// One service account.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown id.
    pub async fn service_account(&self, id: Uuid) -> Result<ServiceAccount, AdminError> {
        self.account(id).await
    }

    /// Creates a service account. Its name follows the group name rules.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, invalid for a bad name or
    /// description, conflict when the name is taken.
    pub async fn create_service_account(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<ServiceAccount, AdminError> {
        self.require(Permission::ServiceAccountsManage)?;
        validate_group_name(name).map_err(AdminError::Invalid)?;
        let description = clean_description(description)?;
        self.store
            .create_service_account(&self.actor, name, description.as_deref())
            .await?
            .ok_or_else(already_exists)
    }

    /// Disables or re-enables a service account; its tokens stop or start
    /// working with it. Setting the state it already has is not an error.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown id.
    pub async fn set_service_account_disabled(
        &self,
        id: Uuid,
        disabled: bool,
    ) -> Result<(), AdminError> {
        self.account(id).await?;
        self.store
            .set_service_account_disabled(&self.actor, id, disabled)
            .await?;
        Ok(())
    }

    /// Deletes a service account with its tokens and group memberships.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown id.
    pub async fn delete_service_account(&self, id: Uuid) -> Result<(), AdminError> {
        self.account(id).await?;
        if !self.store.delete_service_account(&self.actor, id).await? {
            return Err(AdminError::NotFound);
        }
        // Its memberships and bindings went with it.
        self.reload().await;
        Ok(())
    }

    /// The tokens of a service account, newest first.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown id.
    pub async fn service_account_tokens(&self, id: Uuid) -> Result<Vec<ApiToken>, AdminError> {
        self.account(id).await?;
        Ok(self.store.list_tokens(id).await?)
    }

    /// Issues a token for a service account; `expires_in_days` defaults to 30
    /// days and is capped by the store at 365.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown
    /// id, invalid for a bad name, scope or expiry.
    pub async fn issue_service_account_token(
        &self,
        id: Uuid,
        name: &str,
        expires_in_days: Option<u32>,
        scope: &TokenScope,
    ) -> Result<IssuedToken, AdminError> {
        self.account(id).await?;
        issue_token(
            self.store,
            &self.actor,
            id,
            name,
            expires_in_days,
            scope,
            None,
        )
        .await
    }

    /// Revokes a token of a service account.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown
    /// account or a token that is not a live token of it.
    pub async fn revoke_service_account_token(
        &self,
        id: Uuid,
        token_id: Uuid,
    ) -> Result<(), AdminError> {
        self.account(id).await?;
        if !self
            .store
            .revoke_token(&self.actor, Some(id), token_id)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        Ok(())
    }

    /// The `IdP` subjects bound to a service account.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown id.
    pub async fn jwt_bindings(&self, id: Uuid) -> Result<Vec<JwtBinding>, AdminError> {
        self.account(id).await?;
        Ok(self.store.list_jwt_bindings(id).await?)
    }

    /// Binds an `IdP` subject to a service account, so a JWT access token for it
    /// acts as the account. The caller checks that the issuer accepts access tokens.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown
    /// account, invalid for an empty or overlong issuer or subject, conflict
    /// when the subject is bound already.
    pub async fn create_jwt_binding(
        &self,
        id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<JwtBinding, AdminError> {
        self.account(id).await?;
        let (issuer, subject) = (issuer.trim(), subject.trim());
        if issuer.is_empty() || subject.is_empty() {
            return Err(AdminError::Invalid(
                "the issuer and the subject must not be empty".to_owned(),
            ));
        }
        if subject.chars().count() > MAX_JWT_SUBJECT_CHARS {
            return Err(AdminError::Invalid(format!(
                "the subject is longer than {MAX_JWT_SUBJECT_CHARS} characters"
            )));
        }
        Ok(self
            .store
            .create_jwt_binding(&self.actor, id, issuer, subject)
            .await?)
    }

    /// Removes a binding of a service account.
    ///
    /// # Errors
    /// Forbidden without `service_accounts.manage`, not found for an unknown
    /// account or a binding that is not one of its.
    pub async fn delete_jwt_binding(&self, id: Uuid, binding_id: Uuid) -> Result<(), AdminError> {
        self.account(id).await?;
        if !self
            .store
            .delete_jwt_binding(&self.actor, id, binding_id)
            .await?
        {
            return Err(AdminError::NotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AUTHENTICATED_GROUP, IdpMapping};
    use crate::store::LoginUser;
    use crate::store::test_support::{database_url, isolated_url};

    /// A connected store on its own schema, or `None` without a test database.
    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
    }

    /// A user created through the login path, with a session on provider `mock`.
    async fn test_session(store: &Store, subject: &str, is_admin: bool) -> SessionUser {
        let email = format!("{subject}@example.com");
        let login = LoginUser {
            issuer: "https://idp.example",
            subject,
            email: Some(&email),
            display_name: None,
            groups: &[],
            is_admin,
        };
        SessionUser {
            user: store.upsert_user_on_login(&login).await.unwrap(),
            provider_id: "mock".to_owned(),
            csrf_token: "token".to_owned(),
            id_token: None,
        }
    }

    fn admin<'a>(store: &'a Store, handle: &'a PolicyHandle, session: &SessionUser) -> Admin<'a> {
        Admin::new(
            store,
            handle,
            session,
            vec!["files".to_owned()],
            vec!["mock".to_owned()],
        )
    }

    fn grant(group: &str, backend: &str) -> GrantConfig {
        GrantConfig {
            group: group.to_owned(),
            backend: backend.to_owned(),
            include: vec!["*".to_owned()],
            exclude: Vec::new(),
            read_only: false,
            mandatory: false,
        }
    }

    #[test]
    fn the_actor_is_named_by_email_then_name_then_subject() {
        let mut user = User {
            id: Uuid::nil(),
            issuer: "https://idp.example".to_owned(),
            subject: "sub-1".to_owned(),
            email: Some("ada@example.com".to_owned()),
            display_name: Some("Ada".to_owned()),
            groups: Vec::new(),
            is_admin: false,
        };
        assert_eq!(actor_label(&user), "ada@example.com");
        user.email = None;
        assert_eq!(actor_label(&user), "Ada");
        user.display_name = None;
        assert_eq!(actor_label(&user), "sub-1");
    }

    #[test]
    fn descriptions_are_trimmed_and_bounded() {
        assert_eq!(clean_description(None).unwrap(), None);
        assert_eq!(clean_description(Some("  ")).unwrap(), None);
        assert_eq!(
            clean_description(Some(" IT staff ")).unwrap().as_deref(),
            Some("IT staff")
        );
        let long = "x".repeat(MAX_DESCRIPTION_CHARS + 1);
        assert!(matches!(
            clean_description(Some(&long)),
            Err(AdminError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn a_member_may_not_manage_or_read_anything() {
        let Some(store) = test_store("axon_rbac_member").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "mia", false).await;
        let admin = admin(&store, &handle, &session);

        assert!(matches!(
            admin.create_group("dev", None).await,
            Err(AdminError::Forbidden)
        ));
        assert!(matches!(
            admin.create_grant(grant("ops", "files")).await,
            Err(AdminError::Forbidden)
        ));
        assert!(matches!(
            admin
                .create_role_binding(Role::Admin.as_str(), RoleSubject::User(session.user.id))
                .await,
            Err(AdminError::Forbidden)
        ));
        assert!(matches!(admin.groups(), Err(AdminError::Forbidden)));
        assert!(matches!(admin.grants(), Err(AdminError::Forbidden)));
        assert!(matches!(admin.role_bindings(), Err(AdminError::Forbidden)));
        assert!(matches!(admin.users(10).await, Err(AdminError::Forbidden)));
        assert!(matches!(
            admin.audit(10, None).await,
            Err(AdminError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn an_admin_manages_a_group_and_it_is_audited() {
        let Some(store) = test_store("axon_rbac_group").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "root", true).await;
        let admin = admin(&store, &handle, &session);

        admin
            .create_group("dev", Some(" Developers "))
            .await
            .unwrap();
        let (group, members) = admin.group("dev").unwrap();
        assert_eq!(group.description.as_deref(), Some("Developers"));
        assert_eq!(members, Vec::<Uuid>::new());

        // Taken, or not a valid name.
        assert!(matches!(
            admin.create_group("dev", None).await,
            Err(AdminError::Conflict(_))
        ));
        assert!(matches!(
            admin.create_group(AUTHENTICATED_GROUP, None).await,
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            admin.create_group("Not Valid", None).await,
            Err(AdminError::Invalid(_))
        ));

        admin.update_group("dev", None).await.unwrap();
        assert_eq!(admin.group("dev").unwrap().0.description, None);

        admin.add_idp_mapping("dev", "mock", "devs").await.unwrap();
        assert_eq!(
            admin.group("dev").unwrap().0.idp,
            [IdpMapping {
                provider: "mock".to_owned(),
                value: "devs".to_owned()
            }]
        );
        assert!(matches!(
            admin.add_idp_mapping("dev", "mock", "devs").await,
            Err(AdminError::Conflict(_))
        ));
        assert!(matches!(
            admin.add_idp_mapping("dev", "other", "devs").await,
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            admin.add_idp_mapping("dev", "mock", " ").await,
            Err(AdminError::Invalid(_))
        ));
        admin
            .remove_idp_mapping("dev", "mock", "devs")
            .await
            .unwrap();
        assert!(matches!(
            admin.remove_idp_mapping("dev", "mock", "devs").await,
            Err(AdminError::NotFound)
        ));

        admin.delete_group("dev").await.unwrap();
        assert!(matches!(
            admin.delete_group("dev").await,
            Err(AdminError::NotFound)
        ));
        assert!(!handle.current().has_group("dev"));

        let log = admin.audit(50, None).await.unwrap();
        let first = log.last().unwrap();
        assert_eq!(first.action, "group.create");
        assert_eq!(first.actor, "root@example.com");
        assert_eq!(first.actor_user_id, Some(session.user.id));
        assert_eq!(log.first().unwrap().action, "group.delete");
    }

    #[tokio::test]
    async fn an_unknown_group_is_not_found() {
        let Some(store) = test_store("axon_rbac_unknown_group").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "root", true).await;
        let admin = admin(&store, &handle, &session);

        assert!(matches!(
            admin.update_group("missing", None).await,
            Err(AdminError::NotFound)
        ));
        assert!(matches!(
            admin.delete_group("missing").await,
            Err(AdminError::NotFound)
        ));
        assert_eq!(
            admin.audit(10, None).await.unwrap(),
            Vec::<AuditRecord>::new()
        );
    }

    #[tokio::test]
    async fn members_are_added_once_and_must_exist() {
        let Some(store) = test_store("axon_rbac_members").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "root", true).await;
        let bob = test_session(&store, "bob", false).await;
        let admin = admin(&store, &handle, &session);
        admin.create_group("dev", None).await.unwrap();

        admin.add_member("dev", bob.user.id).await.unwrap();
        assert_eq!(admin.group("dev").unwrap().1, [bob.user.id]);
        assert!(matches!(
            admin.add_member("dev", bob.user.id).await,
            Err(AdminError::Conflict(_))
        ));
        assert!(matches!(
            admin.add_member("dev", Uuid::new_v4()).await,
            Err(AdminError::NotFound)
        ));

        admin.remove_member("dev", bob.user.id).await.unwrap();
        assert!(matches!(
            admin.remove_member("dev", bob.user.id).await,
            Err(AdminError::NotFound)
        ));
    }

    #[tokio::test]
    async fn grants_are_validated_against_groups_and_backends() {
        let Some(store) = test_store("axon_rbac_grants").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "root", true).await;
        let admin = admin(&store, &handle, &session);
        admin.create_group("ops", None).await.unwrap();

        assert!(matches!(
            admin.create_grant(grant("nobody", "files")).await,
            Err(AdminError::Invalid(_))
        ));
        assert!(matches!(
            admin.create_grant(grant("ops", "nowhere")).await,
            Err(AdminError::Invalid(_))
        ));

        let id = admin.create_grant(grant("ops", "files")).await.unwrap();
        let grants = admin.grants().unwrap();
        let created = grants.iter().find(|view| view.id == Some(id)).unwrap();
        assert_eq!(created.grant.group, "ops");

        admin.delete_grant(id).await.unwrap();
        assert!(matches!(
            admin.delete_grant(id).await,
            Err(AdminError::NotFound)
        ));
        assert_eq!(admin.grants().unwrap(), Vec::<GrantView>::new());
    }

    #[tokio::test]
    async fn a_role_binding_changes_what_a_user_may_do() {
        let Some(store) = test_store("axon_rbac_bindings").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let root = test_session(&store, "root", true).await;
        let bob = test_session(&store, "bob", false).await;
        let root_admin = admin(&store, &handle, &root);
        assert!(matches!(
            admin(&store, &handle, &bob).audit(10, None).await,
            Err(AdminError::Forbidden)
        ));

        let subject = RoleSubject::User(bob.user.id);
        let id = root_admin
            .create_role_binding(Role::Auditor.as_str(), subject.clone())
            .await
            .unwrap();
        // The handle was reloaded, so bob's next request sees the role.
        admin(&store, &handle, &bob).audit(10, None).await.unwrap();
        assert!(matches!(
            root_admin
                .create_role_binding(Role::Auditor.as_str(), subject)
                .await,
            Err(AdminError::Conflict(_))
        ));
        assert!(matches!(
            root_admin
                .create_role_binding(Role::Auditor.as_str(), RoleSubject::User(Uuid::new_v4()))
                .await,
            Err(AdminError::NotFound)
        ));
        assert!(matches!(
            root_admin
                .create_role_binding(
                    Role::Auditor.as_str(),
                    RoleSubject::Group("nobody".to_owned()),
                )
                .await,
            Err(AdminError::Invalid(_))
        ));
        assert!(
            root_admin
                .role_bindings()
                .unwrap()
                .iter()
                .any(|binding| binding.id == Some(id))
        );

        root_admin.delete_role_binding(id).await.unwrap();
        assert!(matches!(
            root_admin.delete_role_binding(id).await,
            Err(AdminError::NotFound)
        ));
        assert!(matches!(
            admin(&store, &handle, &bob).audit(10, None).await,
            Err(AdminError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn refresh_picks_up_changes_made_elsewhere() {
        let Some(store) = test_store("axon_rbac_refresh").await else {
            return;
        };
        let handle = PolicyHandle::new();
        let session = test_session(&store, "root", true).await;
        let actor = Actor {
            user_id: Some(session.user.id),
            label: "other replica".to_owned(),
        };

        store.create_group(&actor, "dev", None).await.unwrap();
        assert!(!handle.current().has_group("dev"));
        handle.refresh(&store).await.unwrap();
        assert!(handle.current().has_group("dev"));
    }

    #[test]
    fn remember_reports_a_change_only_after_the_first_snapshot() {
        let handle = PolicyHandle::new();
        let mut snapshot = RbacSnapshot::default();

        assert!(!handle.remember(snapshot.clone()), "first load");
        assert!(!handle.remember(snapshot.clone()), "same rows");

        snapshot.memberships.push((Uuid::nil(), "dev".to_owned()));
        assert!(handle.remember(snapshot.clone()), "new membership");
        assert!(!handle.remember(snapshot), "same rows again");
    }

    #[tokio::test]
    async fn refresh_publishes_when_the_rows_changed() {
        let Some(store) = test_store("axon_rbac_refresh_publish").await else {
            return;
        };
        let bus = ChangeBus::new();
        let mut subscription = bus.subscribe();
        let handle = PolicyHandle::new().with_change_bus(bus);
        let session = test_session(&store, "root", true).await;
        let actor = Actor {
            user_id: Some(session.user.id),
            label: "other replica".to_owned(),
        };

        handle.refresh(&store).await.unwrap();
        store.create_group(&actor, "dev", None).await.unwrap();
        handle.refresh(&store).await.unwrap();

        let heard = tokio::time::timeout(Duration::from_secs(5), subscription.changed_for(None))
            .await
            .expect("a change is published");
        assert!(heard);
    }
}
