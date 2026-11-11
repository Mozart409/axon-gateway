//! RBAC policy: groups, roles, tool grants and the view layer
//!
//! Pure logic, no I/O. [`RbacSnapshot`] holds the rows the database manages and
//! [`Policy`] compiles them (plus the built-in [`Role`]s); it maps a login to groups
//! and a user to [`Permissions`] (roles by name, built-in [`Role`]s or custom ones,
//! and the [`Permission`]s they carry); [`EffectivePolicy`] is the allow-only union of the
//! grants of a user's groups and decides what a tool call may do. [`OptOuts`] is
//! the view layer: it only narrows what [`EffectivePolicy::visible`] shows and
//! never denies anything.
//!
//! Grant globs match the tool's original name as its backend reports it, not the
//! `{backend}_` namespaced name.

use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::tool_matches_pattern;

/// Built-in group every logged-in user is a member of. It cannot be created.
pub const AUTHENTICATED_GROUP: &str = "authenticated";

fn all_tools() -> Vec<String> {
    vec!["*".to_string()]
}

/// The `[rbac]` config section. Only parsed from a file for `admin import-config`;
/// the gateway's policy lives in the database.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RbacConfig {
    /// `[[rbac.groups]]`: groups to import
    #[serde(default)]
    pub groups: Vec<RbacGroupConfig>,
    /// `[[rbac.grants]]`: which group may use which backend's tools
    #[serde(default)]
    pub grants: Vec<GrantConfig>,
    /// `[[rbac.role_bindings]]`: which group holds which role
    #[serde(default)]
    pub role_bindings: Vec<RoleBindingConfig>,
    /// `[[rbac.roles]]`: custom roles to import
    #[serde(default)]
    pub roles: Vec<RoleConfig>,
}

/// `[[rbac.roles]]`: a custom role, a named set of [`Permission`]s
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RoleConfig {
    /// Unique name, see [`validate_role_name`]
    pub name: String,
    /// Free text shown next to the role
    #[serde(default)]
    pub description: Option<String>,
    /// Permission names ([`Permission::as_str`]), at least one
    pub permissions: Vec<String>,
}

/// A built-in role: a named set of [`Permission`]s
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Everything
    Admin,
    /// Manages shared backends and the catalog
    BackendAdmin,
    /// Reads the audit log and the backend views
    Auditor,
    /// Every logged-in user
    Member,
}

impl Role {
    /// Every role, in declaration order
    pub const ALL: [Role; 4] = [Role::Admin, Role::BackendAdmin, Role::Auditor, Role::Member];

    /// The role's name in config, the API and the database
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::BackendAdmin => "backend-admin",
            Role::Auditor => "auditor",
            Role::Member => "member",
        }
    }

    /// The role with this name
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }

    /// What the role is for, for display
    pub fn description(self) -> &'static str {
        match self {
            Role::Admin => "Everything",
            Role::BackendAdmin => "Manages shared backends and the catalog",
            Role::Auditor => "Reads the audit log and the backend views",
            Role::Member => "Every logged-in user",
        }
    }

    /// What the role allows
    pub fn permissions(self) -> &'static [Permission] {
        match self {
            Role::Admin => &Permission::ALL,
            Role::BackendAdmin => &[
                Permission::BackendsView,
                Permission::BackendsManage,
                Permission::CatalogManage,
            ],
            Role::Auditor => &[Permission::AuditRead, Permission::BackendsView],
            Role::Member => &[Permission::PersonalBackendsCreate],
        }
    }
}

/// One thing a role may allow
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Permission {
    /// Gateway settings, reload, break-glass operations
    GatewayAdmin,
    /// See shared backends and their status
    BackendsView,
    /// Create, edit and disable shared backends
    BackendsManage,
    /// Publish and edit catalog templates
    CatalogManage,
    /// Add personal MCP servers
    PersonalBackendsCreate,
    /// Disable users, assign roles, see users
    UsersManage,
    /// Groups, `IdP` mappings, memberships and grants
    GroupsManage,
    /// Custom roles
    RolesManage,
    /// Service accounts and their tokens
    ServiceAccountsManage,
    /// List and revoke any user's tokens
    TokensManageAll,
    /// Audit log and usage views (metadata only)
    AuditRead,
    /// Read recorded tool arguments
    AuditReadSensitive,
}

impl Permission {
    /// Every permission, in declaration order
    pub const ALL: [Permission; 12] = [
        Permission::GatewayAdmin,
        Permission::BackendsView,
        Permission::BackendsManage,
        Permission::CatalogManage,
        Permission::PersonalBackendsCreate,
        Permission::UsersManage,
        Permission::GroupsManage,
        Permission::RolesManage,
        Permission::ServiceAccountsManage,
        Permission::TokensManageAll,
        Permission::AuditRead,
        Permission::AuditReadSensitive,
    ];

    /// The permission's name in the API and the docs
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::GatewayAdmin => "gateway.admin",
            Permission::BackendsView => "backends.view",
            Permission::BackendsManage => "backends.manage",
            Permission::CatalogManage => "catalog.manage",
            Permission::PersonalBackendsCreate => "personal_backends.create",
            Permission::UsersManage => "users.manage",
            Permission::GroupsManage => "groups.manage",
            Permission::RolesManage => "roles.manage",
            Permission::ServiceAccountsManage => "service_accounts.manage",
            Permission::TokensManageAll => "tokens.manage_all",
            Permission::AuditRead => "audit.read",
            Permission::AuditReadSensitive => "audit.read_sensitive",
        }
    }

    /// The permission with this name
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|permission| permission.as_str() == value)
    }

    /// What the permission allows, for display
    pub fn description(self) -> &'static str {
        match self {
            Permission::GatewayAdmin => "Gateway settings, reload, break-glass operations",
            Permission::BackendsView => "See shared backends and their status",
            Permission::BackendsManage => "Create, edit and disable shared backends",
            Permission::CatalogManage => "Publish and edit catalog templates",
            Permission::PersonalBackendsCreate => "Add personal MCP servers",
            Permission::UsersManage => "Disable users, assign roles, see users",
            Permission::GroupsManage => "Groups, IdP mappings, memberships and grants",
            Permission::RolesManage => "Custom roles",
            Permission::ServiceAccountsManage => "Service accounts and their tokens",
            Permission::TokensManageAll => "List and revoke any user's tokens",
            Permission::AuditRead => "Audit log and usage views (metadata only)",
            Permission::AuditReadSensitive => "Read recorded tool arguments",
        }
    }
}

/// Who a role binding applies to
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleSubject {
    /// Every member of the group
    Group(String),
    /// One user
    User(Uuid),
}

/// A role granted to a group or a user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBinding {
    /// Database row id; always `Some` for a binding in the policy
    pub id: Option<i64>,
    /// Name of the role granted. A name that no built-in or database role
    /// has (a deleted custom role) grants nothing.
    pub role: String,
    /// Who holds it
    pub subject: RoleSubject,
}

/// `[[rbac.role_bindings]]`: a role granted to a group
#[derive(Debug, Clone, Deserialize)]
pub struct RoleBindingConfig {
    /// A built-in role or one declared in `[[rbac.roles]]`
    pub role: String,
    /// A declared group or [`AUTHENTICATED_GROUP`]
    pub group: String,
}

/// The database-managed RBAC rows, as the store loads them
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RbacSnapshot {
    /// Database groups with their `IdP` mappings
    pub groups: Vec<RbacGroupConfig>,
    /// `(user id, group name)`, database groups only
    pub memberships: Vec<(Uuid, String)>,
    /// `(grant id, grant)`
    pub grants: Vec<(i64, GrantConfig)>,
    /// Role bindings; `id` is always `Some`
    pub role_bindings: Vec<RoleBinding>,
    /// Custom roles, by name
    pub roles: Vec<RoleConfig>,
}

/// Where a role is defined
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleSource {
    /// One of the four [`Role`]s, fixed
    Builtin,
    /// The database: the dashboard, the API or the import
    Local,
}

/// A role as the dashboard lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleView {
    /// Unique name
    pub name: String,
    /// Free text shown next to the role
    pub description: Option<String>,
    /// Where the role is defined
    pub source: RoleSource,
    /// What the role allows, in [`Permission::ALL`] order
    pub permissions: Vec<Permission>,
}

/// A group as the dashboard lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    /// Unique name
    pub name: String,
    /// Free text shown next to the group
    pub description: Option<String>,
    /// `IdP` claim values whose holders are members
    pub idp: Vec<IdpMapping>,
}

/// A grant as the dashboard lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    /// Database row id; always `Some` for a grant in the policy
    pub id: Option<i64>,
    /// The grant itself
    pub grant: GrantSummary,
}

/// The effective roles and permissions of a user
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    roles: BTreeSet<String>,
    permissions: BTreeSet<Permission>,
}

impl Permissions {
    fn add(&mut self, role: &str, permissions: &[Permission]) {
        self.roles.insert(role.to_owned());
        self.permissions.extend(permissions);
    }

    /// Whether some role of the user carries the permission
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// The user's role names, sorted
    pub fn roles(&self) -> impl Iterator<Item = &str> + '_ {
        self.roles.iter().map(String::as_str)
    }

    /// Whether the user holds the built-in [`Role::Admin`]
    pub fn is_admin(&self) -> bool {
        self.roles.contains(Role::Admin.as_str())
    }

    /// The permissions of `wanted` that the user does not hold, in [`Permission`]
    /// order. Empty means the user may hand out `wanted` (the anti-escalation rule
    /// for creating roles and binding them).
    pub fn missing(&self, wanted: &[Permission]) -> Vec<Permission> {
        wanted
            .iter()
            .copied()
            .filter(|permission| !self.has(*permission))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// A group of the database snapshot or of a config file to import
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RbacGroupConfig {
    /// Unique name, `[a-z0-9_-]+`
    pub name: String,
    /// Free text shown next to the group
    #[serde(default)]
    pub description: Option<String>,
    /// Identity provider claim values whose holders are members of this group
    #[serde(default)]
    pub idp: Vec<IdpMapping>,
    /// Service account names that are members of this group (import only; the
    /// database keeps memberships by id)
    #[serde(default)]
    pub service_accounts: Vec<String>,
}

/// `(provider, claim value)` that puts a user into a group
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IdpMapping {
    /// `id` of an `[[auth.oidc]]` provider
    pub provider: String,
    /// Claim value, for example an Entra group object id
    pub value: String,
}

/// A grant of one backend's tools to a group: a database row, an API request body or a
/// `[[rbac.grants]]` entry to import
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GrantConfig {
    /// A declared group or [`AUTHENTICATED_GROUP`]
    pub group: String,
    /// Backend name
    pub backend: String,
    /// Tool globs (original tool names, see [`tool_matches_pattern`]); default `["*"]`
    #[serde(default = "all_tools")]
    pub include: Vec<String>,
    /// Tool globs removed from `include` within this grant
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Only tools annotated `readOnlyHint: true` pass
    #[serde(default)]
    pub read_only: bool,
    /// Users cannot opt out of tools this grant allows
    #[serde(default)]
    pub mandatory: bool,
}

/// The name rule for groups from the API and the import: `[a-z0-9_-]+`, 1 to 64 characters,
/// and not [`AUTHENTICATED_GROUP`].
///
/// # Errors
///
/// Returns a message naming the problem.
pub fn validate_group_name(name: &str) -> Result<(), String> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !valid {
        return Err(format!(
            "rbac group name {name:?} must match [a-z0-9_-]+ and be 1 to 64 characters"
        ));
    }
    if name == AUTHENTICATED_GROUP {
        return Err(format!(
            "rbac group name {AUTHENTICATED_GROUP:?} is built in and cannot be declared"
        ));
    }
    Ok(())
}

/// The name rule for custom roles: `[a-z0-9][a-z0-9_-]{0,62}`, and not the name of a
/// built-in [`Role`].
///
/// # Errors
///
/// Returns a message naming the problem.
pub fn validate_role_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let valid = name.len() <= 63
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !valid {
        return Err(format!(
            "role name {name:?} must match [a-z0-9][a-z0-9_-]{{0,62}}"
        ));
    }
    if Role::parse(name).is_some() {
        return Err(format!("role name {name:?} is built in"));
    }
    Ok(())
}

/// The permissions a custom role names: at least one, every one known. Deduplicated,
/// in [`Permission::ALL`] order.
///
/// # Errors
///
/// Returns a message naming the problem.
pub fn parse_permissions(names: &[String]) -> Result<Vec<Permission>, String> {
    if names.is_empty() {
        return Err("a role needs at least one permission".to_owned());
    }
    let mut permissions = BTreeSet::new();
    for name in names {
        let permission =
            Permission::parse(name).ok_or_else(|| format!("unknown permission {name:?}"))?;
        permissions.insert(permission);
    }
    Ok(permissions.into_iter().collect())
}

/// Check one grant: its group is known to the policy, its backend is among `backends`,
/// `include` is not empty and no pattern is an empty string.
///
/// # Errors
///
/// Returns a message naming the first problem found.
pub fn validate_grant(
    grant: &GrantConfig,
    policy: &Policy,
    backends: &[&str],
) -> Result<(), String> {
    if !policy.has_group(&grant.group) {
        return Err(format!(
            "rbac grant for backend {:?} names unknown group {:?}",
            grant.backend, grant.group
        ));
    }
    if !backends.contains(&grant.backend.as_str()) {
        return Err(format!(
            "rbac grant for group {:?} names unknown backend {:?}",
            grant.group, grant.backend
        ));
    }
    if grant.include.is_empty() {
        return Err(format!(
            "rbac grant for group {:?} on backend {:?} has an empty include list",
            grant.group, grant.backend
        ));
    }
    if grant
        .include
        .iter()
        .chain(&grant.exclude)
        .any(|pattern| pattern.trim().is_empty())
    {
        return Err(format!(
            "rbac grant for group {:?} on backend {:?} has an empty tool pattern",
            grant.group, grant.backend
        ));
    }
    Ok(())
}

impl RbacConfig {
    /// Check the section against the configured backends and OIDC provider ids.
    ///
    /// # Errors
    ///
    /// Returns a message naming the first problem found.
    pub fn validate(&self, backends: &[&str], providers: &[&str]) -> Result<(), String> {
        let mut names: HashSet<&str> = HashSet::new();
        for group in &self.groups {
            validate_group_name(&group.name)?;
            if !names.insert(group.name.as_str()) {
                return Err(format!("duplicate rbac group {:?}", group.name));
            }
            let mut accounts: HashSet<&str> = HashSet::new();
            for account in &group.service_accounts {
                if account.is_empty() {
                    return Err(format!(
                        "rbac group {:?} lists an empty service account name",
                        group.name
                    ));
                }
                if !accounts.insert(account.as_str()) {
                    return Err(format!(
                        "rbac group {:?} lists service account {account:?} twice",
                        group.name
                    ));
                }
            }
            for mapping in &group.idp {
                if !providers.contains(&mapping.provider.as_str()) {
                    return Err(format!(
                        "rbac group {:?} maps idp provider {:?}: no [[auth.oidc]] provider with id {}",
                        group.name, mapping.provider, mapping.provider
                    ));
                }
            }
        }
        for grant in &self.grants {
            if grant.group != AUTHENTICATED_GROUP && !names.contains(grant.group.as_str()) {
                return Err(format!(
                    "rbac grant for backend {:?} names unknown group {:?}",
                    grant.backend, grant.group
                ));
            }
            if !backends.contains(&grant.backend.as_str()) {
                return Err(format!(
                    "rbac grant for group {:?} names unknown backend {:?}",
                    grant.group, grant.backend
                ));
            }
            if grant.include.is_empty() {
                return Err(format!(
                    "rbac grant for group {:?} on backend {:?} has an empty include list",
                    grant.group, grant.backend
                ));
            }
        }
        let mut role_names: HashSet<&str> = HashSet::new();
        for role in &self.roles {
            validate_role_name(&role.name)?;
            if !role_names.insert(role.name.as_str()) {
                return Err(format!("duplicate rbac role {:?}", role.name));
            }
            parse_permissions(&role.permissions)
                .map_err(|message| format!("rbac role {:?}: {message}", role.name))?;
        }
        for binding in &self.role_bindings {
            if binding.group != AUTHENTICATED_GROUP && !names.contains(binding.group.as_str()) {
                return Err(format!(
                    "rbac role binding for role {:?} names unknown group {:?}",
                    binding.role, binding.group
                ));
            }
            if Role::parse(&binding.role).is_none() && !role_names.contains(binding.role.as_str()) {
                return Err(format!(
                    "rbac role binding for group {:?} names unknown role {:?}",
                    binding.group, binding.role
                ));
            }
        }
        Ok(())
    }
}

/// A tool as a grant sees it
#[derive(Debug, Clone, Copy)]
pub struct ToolRef<'a> {
    /// Backend name
    pub backend: &'a str,
    /// Original tool name, as the backend reports it
    pub name: &'a str,
    /// Whether the tool carries `readOnlyHint: true`
    pub read_only_hint: bool,
}

/// A grant, for display and explanations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    /// Group the grant is for
    pub group: String,
    /// Backend the grant covers
    pub backend: String,
    /// Include globs
    pub include: Vec<String>,
    /// Exclude globs
    pub exclude: Vec<String>,
    /// Whether only read-only tools pass
    pub read_only: bool,
    /// Whether users cannot opt out
    pub mandatory: bool,
}

impl From<&GrantConfig> for GrantSummary {
    fn from(grant: &GrantConfig) -> Self {
        Self {
            group: grant.group.clone(),
            backend: grant.backend.clone(),
            include: grant.include.clone(),
            exclude: grant.exclude.clone(),
            read_only: grant.read_only,
            mandatory: grant.mandatory,
        }
    }
}

impl GrantSummary {
    /// Why this grant does not cover the tool, or `None` when it does.
    /// The caller has already checked the backend.
    fn miss(&self, tool: ToolRef<'_>) -> Option<Miss> {
        if !self
            .include
            .iter()
            .any(|pattern| tool_matches_pattern(tool.name, pattern))
        {
            return Some(Miss::NotIncluded);
        }
        if self
            .exclude
            .iter()
            .any(|pattern| tool_matches_pattern(tool.name, pattern))
        {
            return Some(Miss::Excluded);
        }
        if self.read_only && !tool.read_only_hint {
            return Some(Miss::NotReadOnly);
        }
        None
    }
}

/// Why a grant for the tool's backend does not allow the tool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// No include glob matches
    NotIncluded,
    /// An exclude glob matches
    Excluded,
    /// The grant is read-only and the tool has no `readOnlyHint`
    NotReadOnly,
}

/// Which grants allow a tool and why the others do not
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// Grants that allow the tool
    pub allowed_by: Vec<GrantSummary>,
    /// Grants for the tool's backend that do not, with the reason. Both lists empty
    /// means no grant for the user's groups covers this backend.
    pub missed: Vec<(GrantSummary, Miss)>,
}

#[derive(Debug, Clone)]
struct GroupDef {
    name: String,
    description: Option<String>,
    idp: Vec<IdpMapping>,
}

impl GroupDef {
    fn new(group: &RbacGroupConfig) -> Self {
        Self {
            name: group.name.clone(),
            description: group.description.clone(),
            idp: group.idp.clone(),
        }
    }

    fn view(&self) -> GroupView {
        GroupView {
            name: self.name.clone(),
            description: self.description.clone(),
            idp: self.idp.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct RoleDef {
    name: String,
    description: Option<String>,
    /// In [`Permission::ALL`] order
    permissions: Vec<Permission>,
}

impl RoleDef {
    /// A permission name this build does not know (a database row written by a newer
    /// build) is dropped.
    fn new(role: &RoleConfig) -> Self {
        let permissions: BTreeSet<Permission> = role
            .permissions
            .iter()
            .filter_map(|name| {
                let permission = Permission::parse(name);
                if permission.is_none() {
                    tracing::warn!(
                        role = %role.name,
                        permission = %name,
                        "ignoring an unknown permission of a custom role"
                    );
                }
                permission
            })
            .collect();
        Self {
            name: role.name.clone(),
            description: role.description.clone(),
            permissions: permissions.into_iter().collect(),
        }
    }

    fn view(&self) -> RoleView {
        RoleView {
            name: self.name.clone(),
            description: self.description.clone(),
            source: RoleSource::Local,
            permissions: self.permissions.clone(),
        }
    }
}

fn builtin_view(role: Role) -> RoleView {
    RoleView {
        name: role.as_str().to_owned(),
        description: Some(role.description().to_owned()),
        source: RoleSource::Builtin,
        permissions: role.permissions().to_vec(),
    }
}

/// Compiled groups, memberships, grants, roles and role bindings of the database
#[derive(Debug, Clone)]
pub struct Policy {
    /// Groups in database order
    groups: Vec<GroupDef>,
    /// Memberships in groups that exist
    memberships: Vec<(Uuid, String)>,
    /// Grants by id
    grants: Vec<GrantView>,
    /// Bindings by id
    role_bindings: Vec<RoleBinding>,
    /// Custom roles by name
    roles: Vec<RoleDef>,
}

impl Policy {
    /// Compile the database rows. A group named like [`AUTHENTICATED_GROUP`] or like an
    /// earlier group is ignored, and so is a custom role named like a built-in or an
    /// earlier role. Memberships of groups that do not exist are dropped. Grants and
    /// bindings for unknown groups, and bindings of unknown roles, stay listed, so an
    /// admin can delete them, but never take effect.
    pub fn from_snapshot(db: &RbacSnapshot) -> Self {
        let mut groups: Vec<GroupDef> = Vec::new();
        let mut names: HashSet<&str> = HashSet::from([AUTHENTICATED_GROUP]);
        for group in &db.groups {
            if names.insert(group.name.as_str()) {
                groups.push(GroupDef::new(group));
            } else {
                tracing::warn!(
                    group = %group.name,
                    "ignoring database rbac group: the name is reserved or already taken"
                );
            }
        }

        let known: HashSet<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        let memberships = db
            .memberships
            .iter()
            .filter(|(_, group)| known.contains(group.as_str()))
            .cloned()
            .collect();

        let mut db_grants: Vec<&(i64, GrantConfig)> = db.grants.iter().collect();
        db_grants.sort_by_key(|(id, _)| *id);
        let grants = db_grants
            .into_iter()
            .map(|(id, grant)| GrantView {
                id: Some(*id),
                grant: GrantSummary::from(grant),
            })
            .collect();

        let mut role_bindings = db.role_bindings.clone();
        role_bindings.sort_by_key(|binding| binding.id);

        let mut roles: Vec<RoleDef> = Vec::new();
        let mut db_roles: Vec<&RoleConfig> = db.roles.iter().collect();
        db_roles.sort_by(|a, b| a.name.cmp(&b.name));
        for role in db_roles {
            if Role::parse(&role.name).is_none() && !roles.iter().any(|r| r.name == role.name) {
                roles.push(RoleDef::new(role));
            } else {
                tracing::warn!(
                    role = %role.name,
                    "ignoring database rbac role: the name is already taken by a built-in or another role"
                );
            }
        }

        Self {
            groups,
            memberships,
            grants,
            role_bindings,
            roles,
        }
    }

    /// Groups of a login: [`AUTHENTICATED_GROUP`], every group with an idp mapping for
    /// this provider whose value is among the claim values, and every group the user is
    /// a member of. Sorted, deduplicated.
    pub fn groups_for(
        &self,
        user_id: Uuid,
        provider_id: &str,
        claim_values: &[String],
    ) -> Vec<String> {
        let mut groups = BTreeSet::new();
        groups.insert(AUTHENTICATED_GROUP.to_string());
        for group in &self.groups {
            let member = group.idp.iter().any(|mapping| {
                mapping.provider == provider_id && claim_values.contains(&mapping.value)
            });
            if member {
                groups.insert(group.name.clone());
            }
        }
        for (member, group) in &self.memberships {
            if *member == user_id {
                groups.insert(group.clone());
            }
        }
        groups.into_iter().collect()
    }

    /// Groups of a service account: its memberships. No [`AUTHENTICATED_GROUP`] and no
    /// `IdP` mappings, an account has no login. Sorted, deduplicated.
    pub fn groups_for_service_account(&self, account_id: Uuid) -> Vec<String> {
        self.memberships
            .iter()
            .filter(|(member, _)| *member == account_id)
            .map(|(_, group)| group.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Roles and permissions of a user. Everyone is a [`Role::Member`]; `is_admin` (the
    /// provider's `admin_groups`) adds [`Role::Admin`]; bindings on the user or on one of
    /// `groups` add theirs. A binding of an unknown role adds nothing.
    pub fn permissions_for(&self, user_id: Uuid, groups: &[String], is_admin: bool) -> Permissions {
        let mut permissions = Permissions::default();
        permissions.add(Role::Member.as_str(), Role::Member.permissions());
        if is_admin {
            permissions.add(Role::Admin.as_str(), Role::Admin.permissions());
        }
        for binding in &self.role_bindings {
            let applies = match &binding.subject {
                RoleSubject::User(id) => *id == user_id,
                RoleSubject::Group(group) => groups.contains(group) && self.has_group(group),
            };
            if applies && let Some(carried) = self.permissions_of(&binding.role) {
                permissions.add(&binding.role, carried);
            }
        }
        permissions
    }

    /// What a role (built-in or database) allows; `None` for an unknown name
    fn permissions_of(&self, name: &str) -> Option<&[Permission]> {
        match Role::parse(name) {
            Some(role) => Some(role.permissions()),
            None => self
                .roles
                .iter()
                .find(|role| role.name == name)
                .map(|role| role.permissions.as_slice()),
        }
    }

    /// What the role allows, in [`Permission::ALL`] order; `None` for an unknown name
    pub fn role_permissions(&self, name: &str) -> Option<Vec<Permission>> {
        self.permissions_of(name).map(<[Permission]>::to_vec)
    }

    /// The built-in roles, then database roles by name
    pub fn roles(&self) -> Vec<RoleView> {
        Role::ALL
            .into_iter()
            .map(builtin_view)
            .chain(self.roles.iter().map(RoleDef::view))
            .collect()
    }

    /// One role, built-in or custom
    pub fn role(&self, name: &str) -> Option<RoleView> {
        match Role::parse(name) {
            Some(role) => Some(builtin_view(role)),
            None => self
                .roles
                .iter()
                .find(|role| role.name == name)
                .map(RoleDef::view),
        }
    }

    /// The union of the grants of the given groups. Grants for unknown groups never apply.
    pub fn effective(&self, groups: &[String]) -> EffectivePolicy {
        EffectivePolicy {
            grants: self
                .grants
                .iter()
                .filter(|view| {
                    groups.contains(&view.grant.group) && self.has_group(&view.grant.group)
                })
                .map(|view| view.grant.clone())
                .collect(),
        }
    }

    /// Description of a declared group, for display
    pub fn group_description(&self, name: &str) -> Option<&str> {
        self.groups
            .iter()
            .find(|group| group.name == name)
            .and_then(|group| group.description.as_deref())
    }

    /// Groups sorted by name. [`AUTHENTICATED_GROUP`] is not included.
    pub fn groups(&self) -> Vec<GroupView> {
        let mut views: Vec<GroupView> = self.groups.iter().map(GroupDef::view).collect();
        views.sort_by(|a, b| a.name.cmp(&b.name));
        views
    }

    /// One declared group
    pub fn group(&self, name: &str) -> Option<GroupView> {
        self.groups
            .iter()
            .find(|group| group.name == name)
            .map(GroupDef::view)
    }

    /// Whether the name is a database group or [`AUTHENTICATED_GROUP`]
    pub fn has_group(&self, name: &str) -> bool {
        name == AUTHENTICATED_GROUP || self.groups.iter().any(|group| group.name == name)
    }

    /// Grants by id
    pub fn grants(&self) -> Vec<GrantView> {
        self.grants.clone()
    }

    /// Role bindings by id
    pub fn role_bindings(&self) -> Vec<RoleBinding> {
        self.role_bindings.clone()
    }

    /// The union of what the roles bound to a group allow, in [`Permission::ALL`]
    /// order. A role that no longer exists contributes nothing.
    pub fn group_permissions(&self, group: &str) -> Vec<Permission> {
        self.bound_permissions(|name| name == group)
    }

    /// The union of what the roles bound to any group allow: what a member of
    /// the most privileged group can do.
    pub fn bound_group_permissions(&self) -> Vec<Permission> {
        self.bound_permissions(|_| true)
    }

    fn bound_permissions(&self, group: impl Fn(&str) -> bool) -> Vec<Permission> {
        self.role_bindings
            .iter()
            .filter_map(|binding| match &binding.subject {
                RoleSubject::Group(name) if group(name) => self.permissions_of(&binding.role),
                _ => None,
            })
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Users that are members of a group, sorted
    pub fn members_of(&self, group: &str) -> Vec<Uuid> {
        self.memberships
            .iter()
            .filter(|(_, name)| name == group)
            .map(|(user, _)| *user)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// What a set of groups may use. Allow-only: adding a grant never removes access.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    grants: Vec<GrantSummary>,
}

impl EffectivePolicy {
    fn for_backend<'a>(&'a self, backend: &'a str) -> impl Iterator<Item = &'a GrantSummary> {
        self.grants
            .iter()
            .filter(move |grant| grant.backend == backend)
    }

    /// Allowed iff some grant for the tool's backend includes it, does not exclude it and
    /// (if read-only) the tool has the hint. Denied by default.
    pub fn allows(&self, tool: ToolRef<'_>) -> bool {
        self.for_backend(tool.backend)
            .any(|grant| grant.miss(tool).is_none())
    }

    /// Whether at least one grant with `mandatory = true` allows the tool
    pub fn is_mandatory(&self, tool: ToolRef<'_>) -> bool {
        self.for_backend(tool.backend)
            .any(|grant| grant.mandatory && grant.miss(tool).is_none())
    }

    /// Which grants allow the tool and why the others for its backend do not
    pub fn explain(&self, tool: ToolRef<'_>) -> Explanation {
        let mut explanation = Explanation {
            allowed_by: Vec::new(),
            missed: Vec::new(),
        };
        for grant in self.for_backend(tool.backend) {
            match grant.miss(tool) {
                None => explanation.allowed_by.push(grant.clone()),
                Some(miss) => explanation.missed.push((grant.clone(), miss)),
            }
        }
        explanation
    }

    /// Backends with at least one grant, sorted and deduplicated
    pub fn backends(&self) -> Vec<String> {
        self.grants
            .iter()
            .map(|grant| grant.backend.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// View layer: allowed, and either mandatory or not opted out
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the gateway filters tools/list with it in Phase 3"
        )
    )]
    pub fn visible(&self, tool: ToolRef<'_>, opt_outs: &OptOuts) -> bool {
        self.allows(tool) && (self.is_mandatory(tool) || !opt_outs.hides(tool.backend, tool.name))
    }
}

/// A user's opt-outs: whole backends and single tools (original names). Not a deny:
/// it only narrows the view.
#[derive(Debug, Clone, Default)]
pub struct OptOuts {
    backends: HashSet<String>,
    tools: HashSet<(String, String)>,
}

impl OptOuts {
    /// Build from `(backend, tool)` entries; `(backend, None)` hides the whole backend
    pub fn new(entries: impl IntoIterator<Item = (String, Option<String>)>) -> Self {
        let mut opt_outs = Self::default();
        for (backend, tool) in entries {
            match tool {
                Some(tool) => {
                    opt_outs.tools.insert((backend, tool));
                }
                None => {
                    opt_outs.backends.insert(backend);
                }
            }
        }
        opt_outs
    }

    /// Whether the user hid this tool, directly or through its backend
    pub fn hides(&self, backend: &str, tool: &str) -> bool {
        self.hides_backend(backend)
            || self
                .tools
                .contains(&(backend.to_string(), tool.to_string()))
    }

    /// Whether the user hid the whole backend
    pub fn hides_backend(&self, backend: &str) -> bool {
        self.backends.contains(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn grant(group: &str, backend: &str, include: &[&str], exclude: &[&str]) -> GrantConfig {
        GrantConfig {
            group: group.to_string(),
            backend: backend.to_string(),
            include: strings(include),
            exclude: strings(exclude),
            read_only: false,
            mandatory: false,
        }
    }

    fn group(name: &str, idp: &[(&str, &str)]) -> RbacGroupConfig {
        RbacGroupConfig {
            name: name.to_string(),
            description: None,
            idp: idp
                .iter()
                .map(|(provider, value)| IdpMapping {
                    provider: (*provider).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
            service_accounts: Vec::new(),
        }
    }

    fn user() -> Uuid {
        Uuid::from_u128(1)
    }

    fn binding(id: Option<i64>, role: Role, subject: RoleSubject) -> RoleBinding {
        named_binding(id, role.as_str(), subject)
    }

    fn named_binding(id: Option<i64>, role: &str, subject: RoleSubject) -> RoleBinding {
        RoleBinding {
            id,
            role: role.to_string(),
            subject,
        }
    }

    fn tool<'a>(backend: &'a str, name: &'a str, read_only_hint: bool) -> ToolRef<'a> {
        ToolRef {
            backend,
            name,
            read_only_hint,
        }
    }

    /// A snapshot of `groups` and `grants`, the grants numbered from 1
    fn snapshot(groups: Vec<RbacGroupConfig>, grants: Vec<GrantConfig>) -> RbacSnapshot {
        RbacSnapshot {
            groups,
            grants: grants
                .into_iter()
                .zip(1..)
                .map(|(grant, id)| (id, grant))
                .collect(),
            ..RbacSnapshot::default()
        }
    }

    fn effective(db: &RbacSnapshot, groups: &[&str]) -> EffectivePolicy {
        Policy::from_snapshot(db).effective(&strings(groups))
    }

    #[test]
    fn union_across_two_groups() {
        let config = snapshot(
            vec![group("it", &[]), group("dev", &[])],
            vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("dev", "forgejo", &["get_*"], &[]),
            ],
        );
        let both = effective(&config, &["it", "dev"]);
        assert!(both.allows(tool("prometheus", "query", false)));
        assert!(both.allows(tool("forgejo", "get_repo", false)));
        assert!(!both.allows(tool("forgejo", "delete_repo", false)));
        assert_eq!(both.backends(), strings(&["forgejo", "prometheus"]));

        let only_dev = effective(&config, &["dev"]);
        assert!(!only_dev.allows(tool("prometheus", "query", false)));
        assert!(only_dev.allows(tool("forgejo", "get_repo", false)));
        assert_eq!(only_dev.backends(), strings(&["forgejo"]));
    }

    #[test]
    fn denies_by_default() {
        let config = snapshot(
            vec![group("it", &[])],
            vec![grant("it", "prometheus", &["*"], &[])],
        );
        let nobody = effective(&config, &[]);
        assert!(!nobody.allows(tool("prometheus", "query", true)));
        assert_eq!(nobody.backends(), Vec::<String>::new());

        let it = effective(&config, &["it"]);
        assert!(!it.allows(tool("unknown", "query", true)));

        let empty = effective(&RbacSnapshot::default(), &["authenticated", "it"]);
        assert!(!empty.allows(tool("prometheus", "query", true)));
    }

    #[test]
    fn exclude_beats_include_within_a_grant_but_union_can_still_allow() {
        let config = snapshot(
            vec![group("it", &[]), group("ops", &[])],
            vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("ops", "prometheus", &["delete_series"], &[]),
            ],
        );
        let it = effective(&config, &["it"]);
        assert!(it.allows(tool("prometheus", "query", false)));
        assert!(!it.allows(tool("prometheus", "delete_series", false)));

        let both = effective(&config, &["it", "ops"]);
        assert!(both.allows(tool("prometheus", "delete_series", false)));
        assert!(!both.allows(tool("prometheus", "delete_rules", false)));
    }

    #[test]
    fn read_only_grant_passes_only_hinted_tools() {
        let mut read_only = grant("it", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = snapshot(vec![group("it", &[])], vec![read_only]);
        let it = effective(&config, &["it"]);
        assert!(it.allows(tool("prometheus", "query", true)));
        assert!(!it.allows(tool("prometheus", "query", false)));
    }

    #[test]
    fn read_only_grant_does_not_limit_another_grant() {
        let mut read_only = grant("authenticated", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = snapshot(
            vec![group("it", &[])],
            vec![read_only, grant("it", "prometheus", &["*"], &[])],
        );
        assert!(!effective(&config, &["authenticated"]).allows(tool(
            "prometheus",
            "reload",
            false
        )));
        assert!(effective(&config, &["authenticated", "it"]).allows(tool(
            "prometheus",
            "reload",
            false
        )));
    }

    #[test]
    fn mandatory_needs_an_allowing_mandatory_grant() {
        let mut mandatory = grant("authenticated", "hindsight", &["*"], &["forget"]);
        mandatory.mandatory = true;
        let config = snapshot(
            vec![group("it", &[])],
            vec![mandatory, grant("it", "hindsight", &["forget"], &[])],
        );
        let it = effective(&config, &["authenticated", "it"]);
        assert!(it.is_mandatory(tool("hindsight", "recall", false)));
        // allowed only through the non-mandatory grant
        assert!(it.allows(tool("hindsight", "forget", false)));
        assert!(!it.is_mandatory(tool("hindsight", "forget", false)));
        // not allowed at all
        assert!(!it.is_mandatory(tool("prometheus", "query", false)));
        assert!(!effective(&config, &["it"]).is_mandatory(tool("hindsight", "recall", false)));
    }

    #[test]
    fn explain_lists_allowed_by_and_misses() {
        let mut read_only = grant("ops", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = snapshot(
            vec![group("it", &[]), group("dev", &[]), group("ops", &[])],
            vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("dev", "prometheus", &["get_*"], &[]),
                read_only,
                grant("it", "forgejo", &["*"], &[]),
            ],
        );
        let policy = effective(&config, &["it", "dev", "ops"]);

        let explanation = policy.explain(tool("prometheus", "delete_series", false));
        assert_eq!(explanation.allowed_by, Vec::<GrantSummary>::new());
        let misses: Vec<(&str, Miss)> = explanation
            .missed
            .iter()
            .map(|(grant, miss)| (grant.group.as_str(), *miss))
            .collect();
        assert_eq!(
            misses,
            vec![
                ("it", Miss::Excluded),
                ("dev", Miss::NotIncluded),
                ("ops", Miss::NotReadOnly),
            ]
        );

        let explanation = policy.explain(tool("prometheus", "get_rules", true));
        let allowed: Vec<&str> = explanation
            .allowed_by
            .iter()
            .map(|grant| grant.group.as_str())
            .collect();
        assert_eq!(allowed, vec!["it", "dev", "ops"]);
        assert_eq!(explanation.missed, Vec::<(GrantSummary, Miss)>::new());
    }

    #[test]
    fn explain_is_empty_without_a_grant_for_the_backend() {
        let config = snapshot(
            vec![group("it", &[])],
            vec![grant("it", "prometheus", &["*"], &[])],
        );
        let explanation = effective(&config, &["it"]).explain(tool("forgejo", "get_repo", true));
        assert_eq!(explanation.allowed_by, Vec::<GrantSummary>::new());
        assert_eq!(explanation.missed, Vec::<(GrantSummary, Miss)>::new());
    }

    #[test]
    fn explain_matches_allows() {
        let mut read_only = grant("it", "prometheus", &["get_*", "list_*"], &["list_secret"]);
        read_only.read_only = true;
        let config = snapshot(vec![group("it", &[])], vec![read_only]);
        let it = effective(&config, &["it"]);
        for name in ["get_a", "list_b", "list_secret", "other"] {
            for hint in [true, false] {
                let tool = tool("prometheus", name, hint);
                assert_eq!(it.allows(tool), !it.explain(tool).allowed_by.is_empty());
            }
        }
    }

    fn login_snapshot() -> RbacSnapshot {
        snapshot(
            vec![
                group("it", &[("entra", "id-it"), ("entra", "id-admins")]),
                group("dev", &[("entra", "id-dev"), ("github", "id-it")]),
                group("manual", &[]),
            ],
            Vec::new(),
        )
    }

    #[test]
    fn groups_for_always_contains_authenticated() {
        let policy = Policy::from_snapshot(&login_snapshot());
        assert_eq!(
            policy.groups_for(user(), "entra", &[]),
            strings(&["authenticated"])
        );
        assert_eq!(
            policy.groups_for(user(), "entra", &strings(&["unknown"])),
            strings(&["authenticated"])
        );
        assert_eq!(
            Policy::from_snapshot(&RbacSnapshot::default()).groups_for(
                user(),
                "entra",
                &strings(&["x"])
            ),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn groups_for_ignores_other_providers() {
        let policy = Policy::from_snapshot(&login_snapshot());
        // "id-it" is mapped for entra to "it" and for github to "dev"
        assert_eq!(
            policy.groups_for(user(), "entra", &strings(&["id-it"])),
            strings(&["authenticated", "it"])
        );
        assert_eq!(
            policy.groups_for(user(), "github", &strings(&["id-it"])),
            strings(&["authenticated", "dev"])
        );
        assert_eq!(
            policy.groups_for(user(), "other", &strings(&["id-it", "id-dev"])),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn groups_for_handles_multiple_mappings_and_dedups() {
        let policy = Policy::from_snapshot(&login_snapshot());
        // two claim values map to "it": one entry only
        assert_eq!(
            policy.groups_for(
                user(),
                "entra",
                &strings(&["id-it", "id-admins", "id-dev", "id-dev"])
            ),
            strings(&["authenticated", "dev", "it"])
        );
    }

    #[test]
    fn group_description_is_looked_up_by_name() {
        let mut it = group("it", &[]);
        it.description = Some("IT staff".to_string());
        let config = snapshot(vec![it, group("dev", &[])], Vec::new());
        let policy = Policy::from_snapshot(&config);
        assert_eq!(policy.group_description("it"), Some("IT staff"));
        assert_eq!(policy.group_description("dev"), None);
        assert_eq!(policy.group_description("missing"), None);
    }

    #[test]
    fn visible_applies_backend_and_tool_opt_outs() {
        let config = snapshot(
            vec![group("it", &[])],
            vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("it", "forgejo", &["*"], &[]),
            ],
        );
        let it = effective(&config, &["it"]);
        let opt_outs = OptOuts::new([
            ("prometheus".to_string(), None),
            ("forgejo".to_string(), Some("delete_repo".to_string())),
        ]);

        assert!(!it.visible(tool("prometheus", "query", true), &opt_outs));
        assert!(it.visible(tool("forgejo", "get_repo", true), &opt_outs));
        assert!(!it.visible(tool("forgejo", "delete_repo", true), &opt_outs));
        // opt-outs never widen: not allowed stays not visible
        assert!(!it.visible(tool("loki", "query", true), &OptOuts::default()));
        // no opt-outs: visible equals allowed
        assert!(it.visible(tool("prometheus", "query", true), &OptOuts::default()));
    }

    #[test]
    fn mandatory_overrides_opt_outs() {
        let mut mandatory = grant("authenticated", "hindsight", &["recall"], &[]);
        mandatory.mandatory = true;
        let config = snapshot(
            Vec::new(),
            vec![mandatory, grant("authenticated", "hindsight", &["*"], &[])],
        );
        let policy = effective(&config, &["authenticated"]);
        let opt_outs = OptOuts::new([("hindsight".to_string(), None)]);
        assert!(policy.visible(tool("hindsight", "recall", false), &opt_outs));
        assert!(!policy.visible(tool("hindsight", "retain", false), &opt_outs));

        let opt_outs = OptOuts::new([("hindsight".to_string(), Some("recall".to_string()))]);
        assert!(policy.visible(tool("hindsight", "recall", false), &opt_outs));
    }

    #[test]
    fn opt_outs_hide_by_backend_or_tool() {
        let opt_outs = OptOuts::new([
            ("prometheus".to_string(), None),
            ("forgejo".to_string(), Some("delete_repo".to_string())),
        ]);
        assert!(opt_outs.hides_backend("prometheus"));
        assert!(!opt_outs.hides_backend("forgejo"));
        assert!(opt_outs.hides("prometheus", "anything"));
        assert!(opt_outs.hides("forgejo", "delete_repo"));
        assert!(!opt_outs.hides("forgejo", "get_repo"));
        assert!(!opt_outs.hides("loki", "delete_repo"));
        assert!(!OptOuts::default().hides("prometheus", "query"));
    }

    fn valid_config() -> RbacConfig {
        RbacConfig {
            groups: vec![group("it", &[("entra", "x")]), group("dev-2_a", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("authenticated", "forgejo", &["*"], &[]),
            ],
            role_bindings: Vec::new(),
            roles: Vec::new(),
        }
    }

    #[test]
    fn validate_accepts_a_good_config() {
        assert_eq!(
            valid_config().validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );
        assert_eq!(RbacConfig::default().validate(&[], &[]), Ok(()));
    }

    fn validate_err(config: &RbacConfig) -> String {
        config
            .validate(&["prometheus", "forgejo"], &["entra"])
            .unwrap_err()
    }

    #[test]
    fn validate_rejects_bad_group_names() {
        for name in ["", "IT", "it team", "it.team", "ü"] {
            let config = RbacConfig {
                groups: vec![group(name, &[])],
                grants: Vec::new(),
                role_bindings: Vec::new(),
                roles: Vec::new(),
            };
            assert!(validate_err(&config).contains("[a-z0-9_-]+"), "{name:?}");
        }
    }

    #[test]
    fn validate_rejects_duplicate_groups() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("it", &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
            roles: Vec::new(),
        };
        assert!(validate_err(&config).contains("duplicate"));
    }

    #[test]
    fn validate_rejects_the_reserved_group() {
        let config = RbacConfig {
            groups: vec![group(AUTHENTICATED_GROUP, &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
            roles: Vec::new(),
        };
        assert!(validate_err(&config).contains("built in"));
    }

    #[test]
    fn validate_rejects_grants_for_unknown_groups() {
        let mut config = valid_config();
        config.grants.push(grant("nope", "prometheus", &["*"], &[]));
        let err = validate_err(&config);
        assert!(
            err.contains("unknown group") && err.contains("nope"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_grants_for_unknown_backends() {
        let mut config = valid_config();
        config.grants.push(grant("it", "nope", &["*"], &[]));
        let err = validate_err(&config);
        assert!(
            err.contains("unknown backend") && err.contains("nope"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_unknown_providers() {
        let config = RbacConfig {
            groups: vec![group("it", &[("okta", "x")])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
            roles: Vec::new(),
        };
        assert!(validate_err(&config).contains("no [[auth.oidc]] provider with id okta"));
        // an empty provider list is an error too
        assert!(
            config
                .validate(&[], &[])
                .unwrap_err()
                .contains("no [[auth.oidc]] provider with id okta")
        );
    }

    #[test]
    fn validate_rejects_empty_include() {
        let mut config = valid_config();
        config.grants.push(grant("it", "prometheus", &[], &[]));
        assert!(validate_err(&config).contains("empty include"));
    }

    #[test]
    fn parses_a_full_rbac_section() {
        #[derive(Deserialize)]
        struct Root {
            rbac: RbacConfig,
        }
        let root: Root = toml::from_str(
            r#"
            [[rbac.groups]]
            name = "it"
            description = "IT staff"
            idp = [{ provider = "entra", value = "0000-aaaa" }]

            [[rbac.groups]]
            name = "dev"

            [[rbac.grants]]
            group = "it"
            backend = "prometheus"
            include = ["get_*"]
            exclude = ["get_secret"]
            read_only = true
            mandatory = true

            [[rbac.grants]]
            group = "authenticated"
            backend = "forgejo"
            "#,
        )
        .unwrap();
        let rbac = root.rbac;

        assert_eq!(rbac.groups.len(), 2);
        assert_eq!(rbac.groups[0].name, "it");
        assert_eq!(rbac.groups[0].description.as_deref(), Some("IT staff"));
        assert_eq!(
            rbac.groups[0].idp,
            vec![IdpMapping {
                provider: "entra".to_string(),
                value: "0000-aaaa".to_string(),
            }]
        );
        assert_eq!(rbac.groups[1].description, None);
        assert_eq!(rbac.groups[1].idp, Vec::<IdpMapping>::new());

        assert_eq!(rbac.grants.len(), 2);
        let full = &rbac.grants[0];
        assert_eq!(full.include, strings(&["get_*"]));
        assert_eq!(full.exclude, strings(&["get_secret"]));
        assert!(full.read_only && full.mandatory);
        let defaults = &rbac.grants[1];
        assert_eq!(defaults.include, strings(&["*"]));
        assert_eq!(defaults.exclude, Vec::<String>::new());
        assert!(!defaults.read_only && !defaults.mandatory);

        assert_eq!(
            rbac.validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );
    }

    #[test]
    fn an_absent_rbac_section_is_empty() {
        let rbac: RbacConfig = toml::from_str("").unwrap();
        assert_eq!(rbac.groups, Vec::new());
        assert_eq!(rbac.grants, Vec::new());
    }

    #[test]
    fn role_permission_sets() {
        assert_eq!(Role::Admin.permissions().len(), 12);
        for permission in Permission::ALL {
            assert!(Role::Admin.permissions().contains(&permission));
        }
        assert_eq!(
            Role::BackendAdmin.permissions(),
            [
                Permission::BackendsView,
                Permission::BackendsManage,
                Permission::CatalogManage
            ]
        );
        assert_eq!(
            Role::Auditor.permissions(),
            [Permission::AuditRead, Permission::BackendsView]
        );
        assert_eq!(
            Role::Member.permissions(),
            [Permission::PersonalBackendsCreate]
        );
        assert!(
            !Role::Auditor
                .permissions()
                .contains(&Permission::AuditReadSensitive)
        );
    }

    #[test]
    fn role_and_permission_names_round_trip() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::BackendAdmin.as_str(), "backend-admin");
        assert_eq!(Role::parse("Admin"), None);
        assert_eq!(Role::parse(""), None);
        assert_eq!(
            Permission::AuditReadSensitive.as_str(),
            "audit.read_sensitive"
        );
        assert_eq!(
            Permission::PersonalBackendsCreate.as_str(),
            "personal_backends.create"
        );
        let names: HashSet<&str> = Permission::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(names.len(), 12);
    }

    #[test]
    fn role_deserializes_from_kebab_case() {
        #[derive(Deserialize)]
        struct Root {
            role: Role,
        }
        let root: Root = toml::from_str(r#"role = "backend-admin""#).unwrap();
        assert_eq!(root.role, Role::BackendAdmin);
        for role in Role::ALL {
            let root: Root = toml::from_str(&format!("role = {:?}", role.as_str())).unwrap();
            assert_eq!(root.role, role);
        }
        assert!(toml::from_str::<Root>(r#"role = "root""#).is_err());
        assert!(toml::from_str::<Root>(r#"role = "BackendAdmin""#).is_err());
    }

    fn roles_of(permissions: &Permissions) -> Vec<&str> {
        permissions.roles().collect()
    }

    #[test]
    fn a_plain_user_is_only_a_member() {
        let policy = Policy::from_snapshot(&RbacSnapshot::default());
        let permissions = policy.permissions_for(user(), &strings(&["authenticated"]), false);
        assert_eq!(roles_of(&permissions), vec!["member"]);
        assert!(permissions.has(Permission::PersonalBackendsCreate));
        assert!(!permissions.has(Permission::AuditRead));
        assert!(!permissions.is_admin());
    }

    #[test]
    fn admin_flag_adds_the_admin_role() {
        let policy = Policy::from_snapshot(&RbacSnapshot::default());
        let permissions = policy.permissions_for(user(), &[], true);
        assert_eq!(roles_of(&permissions), vec!["admin", "member"]);
        assert!(permissions.is_admin());
        for permission in Permission::ALL {
            assert!(permissions.has(permission));
        }
    }

    #[test]
    fn a_binding_on_a_group_applies_to_its_members_only() {
        let db = RbacSnapshot {
            role_bindings: vec![binding(
                Some(1),
                Role::Auditor,
                RoleSubject::Group("it-sec".to_string()),
            )],
            ..snapshot(
                vec![group("it-sec", &[("entra", "id-sec")]), group("dev", &[])],
                Vec::new(),
            )
        };
        let policy = Policy::from_snapshot(&db);

        let groups = policy.groups_for(user(), "entra", &strings(&["id-sec"]));
        let permissions = policy.permissions_for(user(), &groups, false);
        assert_eq!(roles_of(&permissions), vec!["auditor", "member"]);
        assert!(permissions.has(Permission::AuditRead));
        assert!(permissions.has(Permission::BackendsView));
        assert!(!permissions.has(Permission::AuditReadSensitive));

        // a group the user is not in has no effect
        let groups = policy.groups_for(user(), "entra", &[]);
        let permissions = policy.permissions_for(user(), &groups, false);
        assert_eq!(roles_of(&permissions), vec!["member"]);
        let permissions = policy.permissions_for(user(), &strings(&["dev"]), false);
        assert_eq!(roles_of(&permissions), vec!["member"]);
    }

    #[test]
    fn a_binding_on_a_user_applies_to_that_user() {
        let other = Uuid::from_u128(2);
        let db = RbacSnapshot {
            role_bindings: vec![binding(
                Some(1),
                Role::BackendAdmin,
                RoleSubject::User(user()),
            )],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let permissions = policy.permissions_for(user(), &[], false);
        assert_eq!(roles_of(&permissions), vec!["backend-admin", "member"]);
        assert!(permissions.has(Permission::BackendsManage));
        assert!(!permissions.has(Permission::GroupsManage));
        let permissions = policy.permissions_for(other, &[], false);
        assert_eq!(roles_of(&permissions), vec!["member"]);
    }

    #[test]
    fn a_binding_on_authenticated_applies_to_everyone() {
        let db = RbacSnapshot {
            role_bindings: vec![binding(
                Some(1),
                Role::Auditor,
                RoleSubject::Group(AUTHENTICATED_GROUP.to_string()),
            )],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let groups = policy.groups_for(user(), "entra", &[]);
        assert!(
            policy
                .permissions_for(user(), &groups, false)
                .has(Permission::AuditRead)
        );
    }

    fn db_snapshot() -> RbacSnapshot {
        RbacSnapshot {
            roles: Vec::new(),
            groups: vec![
                RbacGroupConfig {
                    name: "ops".to_string(),
                    description: Some("Operations".to_string()),
                    idp: group("ops", &[("entra", "id-ops")]).idp,
                    service_accounts: Vec::new(),
                },
                group("it", &[("entra", "id-it")]),
                group("beta", &[]),
            ],
            memberships: vec![
                (user(), "beta".to_string()),
                (Uuid::from_u128(2), "beta".to_string()),
                (user(), "ghost".to_string()),
            ],
            grants: vec![
                (7, grant("ops", "loki", &["*"], &[])),
                (3, grant("beta", "forgejo", &["get_*"], &[])),
                (9, grant("ghost", "prometheus", &["*"], &[])),
                (1, grant("it", "prometheus", &["*"], &[])),
            ],
            role_bindings: vec![
                binding(
                    Some(5),
                    Role::Auditor,
                    RoleSubject::Group("ops".to_string()),
                ),
                binding(
                    Some(2),
                    Role::Admin,
                    RoleSubject::Group("ghost".to_string()),
                ),
                binding(
                    Some(1),
                    Role::BackendAdmin,
                    RoleSubject::Group("it".to_string()),
                ),
            ],
        }
    }

    #[test]
    fn groups_match_by_membership_and_idp_mapping() {
        let policy = Policy::from_snapshot(&db_snapshot());
        // membership
        assert_eq!(
            policy.groups_for(user(), "entra", &[]),
            strings(&["authenticated", "beta"])
        );
        // idp mapping
        assert_eq!(
            policy.groups_for(Uuid::from_u128(3), "entra", &strings(&["id-ops", "id-it"])),
            strings(&["authenticated", "it", "ops"])
        );
        // no membership in a group that does not exist
        let groups = policy.groups_for(user(), "entra", &[]);
        assert!(!groups.contains(&"ghost".to_string()));
        assert_eq!(policy.members_of("beta"), vec![user(), Uuid::from_u128(2)]);
        assert_eq!(policy.members_of("it"), Vec::<Uuid>::new());
        assert_eq!(policy.members_of("ghost"), Vec::<Uuid>::new());
    }

    #[test]
    fn grants_take_effect_and_orphans_do_not() {
        let policy = Policy::from_snapshot(&db_snapshot());
        let beta = policy.effective(&strings(&["authenticated", "beta"]));
        assert!(beta.allows(tool("forgejo", "get_repo", false)));
        assert!(!beta.allows(tool("forgejo", "delete_repo", false)));
        let ops = policy.effective(&strings(&["ops"]));
        assert!(ops.allows(tool("loki", "query", false)));
        // an orphan grant is listed but never evaluated, even for a caller naming the group
        let ghost = policy.effective(&strings(&["ghost"]));
        assert!(!ghost.allows(tool("prometheus", "query", false)));
        assert_eq!(ghost.backends(), Vec::<String>::new());
        assert!(policy.grants().iter().any(|view| view.id == Some(9)));
    }

    #[test]
    fn a_reserved_or_repeated_group_name_is_ignored() {
        let db = RbacSnapshot {
            groups: vec![
                group(AUTHENTICATED_GROUP, &[("entra", "id-evil")]),
                group("x", &[("entra", "id-x")]),
                group("x", &[("entra", "id-evil")]),
            ],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let names: Vec<String> = policy.groups().into_iter().map(|g| g.name).collect();
        assert_eq!(names, strings(&["x"]));
        // the first definition wins
        assert_eq!(
            policy.group("x").unwrap().idp,
            vec![IdpMapping {
                provider: "entra".to_string(),
                value: "id-x".to_string(),
            }]
        );
        assert_eq!(
            policy.groups_for(user(), "entra", &strings(&["id-evil"])),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn bindings_follow_their_group() {
        let policy = Policy::from_snapshot(&db_snapshot());
        let ops = policy.groups_for(Uuid::from_u128(3), "entra", &strings(&["id-ops"]));
        let permissions = policy.permissions_for(Uuid::from_u128(3), &ops, false);
        assert!(permissions.has(Permission::AuditRead));
        // a binding on an unknown group is listed but does not apply
        let permissions = policy.permissions_for(Uuid::from_u128(3), &strings(&["ghost"]), false);
        assert!(!permissions.is_admin());
    }

    #[test]
    fn groups_are_listed_sorted_by_name() {
        let db = RbacSnapshot {
            groups: vec![
                group("zeta", &[]),
                group("alpha", &[]),
                group("mid", &[]),
                group("beta", &[]),
            ],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let listed: Vec<String> = policy.groups().into_iter().map(|g| g.name).collect();
        assert_eq!(listed, strings(&["alpha", "beta", "mid", "zeta"]));
        assert!(policy.has_group("beta"));
        assert!(policy.has_group(AUTHENTICATED_GROUP));
        assert!(!policy.has_group("nope"));
        assert_eq!(policy.group("nope"), None);
    }

    #[test]
    fn grants_and_bindings_are_listed_by_id() {
        let policy = Policy::from_snapshot(&db_snapshot());
        let grants: Vec<(Option<i64>, String)> = policy
            .grants()
            .into_iter()
            .map(|view| (view.id, view.grant.backend))
            .collect();
        assert_eq!(
            grants,
            vec![
                (Some(1), "prometheus".to_string()),
                (Some(3), "forgejo".to_string()),
                (Some(7), "loki".to_string()),
                (Some(9), "prometheus".to_string()),
            ]
        );
        assert_eq!(
            policy.role_bindings(),
            vec![
                binding(
                    Some(1),
                    Role::BackendAdmin,
                    RoleSubject::Group("it".to_string())
                ),
                binding(
                    Some(2),
                    Role::Admin,
                    RoleSubject::Group("ghost".to_string())
                ),
                binding(
                    Some(5),
                    Role::Auditor,
                    RoleSubject::Group("ops".to_string())
                ),
            ]
        );
    }

    #[test]
    fn validate_group_name_applies_the_shared_rule() {
        assert_eq!(validate_group_name("it"), Ok(()));
        assert_eq!(validate_group_name("dev-2_a"), Ok(()));
        assert_eq!(validate_group_name(&"a".repeat(64)), Ok(()));
        for name in ["", "IT", "it team", "it.team", "ü"] {
            assert!(
                validate_group_name(name)
                    .unwrap_err()
                    .contains("[a-z0-9_-]+"),
                "{name:?}"
            );
        }
        assert!(
            validate_group_name(&"a".repeat(65))
                .unwrap_err()
                .contains("64")
        );
        assert!(
            validate_group_name(AUTHENTICATED_GROUP)
                .unwrap_err()
                .contains("built in")
        );
    }

    #[test]
    fn validate_grant_checks_group_backend_and_patterns() {
        let policy = Policy::from_snapshot(&db_snapshot());
        let backends = ["prometheus", "forgejo"];
        assert_eq!(
            validate_grant(&grant("it", "prometheus", &["*"], &[]), &policy, &backends),
            Ok(())
        );
        // database groups and the built-in group are known too
        assert_eq!(
            validate_grant(
                &grant("beta", "forgejo", &["get_*"], &["x"]),
                &policy,
                &backends
            ),
            Ok(())
        );
        assert_eq!(
            validate_grant(
                &grant(AUTHENTICATED_GROUP, "forgejo", &["*"], &[]),
                &policy,
                &backends
            ),
            Ok(())
        );

        let err =
            validate_grant(&grant("nope", "forgejo", &["*"], &[]), &policy, &backends).unwrap_err();
        assert!(
            err.contains("unknown group") && err.contains("nope"),
            "{err}"
        );
        let err =
            validate_grant(&grant("it", "nope", &["*"], &[]), &policy, &backends).unwrap_err();
        assert!(
            err.contains("unknown backend") && err.contains("nope"),
            "{err}"
        );
        let err =
            validate_grant(&grant("it", "forgejo", &[], &[]), &policy, &backends).unwrap_err();
        assert!(err.contains("empty include"), "{err}");
        let err = validate_grant(&grant("it", "forgejo", &["*", ""], &[]), &policy, &backends)
            .unwrap_err();
        assert!(err.contains("empty tool pattern"), "{err}");
        let err = validate_grant(&grant("it", "forgejo", &["*"], &[" "]), &policy, &backends)
            .unwrap_err();
        assert!(err.contains("empty tool pattern"), "{err}");
    }

    #[test]
    fn parses_and_validates_role_bindings() {
        #[derive(Deserialize)]
        struct Root {
            rbac: RbacConfig,
        }
        let root: Root = toml::from_str(
            r#"
            [[rbac.groups]]
            name = "it-sec"

            [[rbac.role_bindings]]
            role = "auditor"
            group = "it-sec"

            [[rbac.role_bindings]]
            role = "backend-admin"
            group = "authenticated"
            "#,
        )
        .unwrap();
        let rbac = root.rbac;
        assert_eq!(rbac.role_bindings.len(), 2);
        assert_eq!(rbac.role_bindings[0].role, "auditor");
        assert_eq!(rbac.role_bindings[0].group, "it-sec");
        assert_eq!(rbac.role_bindings[1].role, "backend-admin");
        assert_eq!(rbac.validate(&[], &[]), Ok(()));

        let mut bad = rbac.clone();
        bad.role_bindings.push(RoleBindingConfig {
            role: Role::Admin.as_str().to_string(),
            group: "nope".to_string(),
        });
        let err = bad.validate(&[], &[]).unwrap_err();
        assert!(
            err.contains("unknown group") && err.contains("nope") && err.contains("admin"),
            "{err}"
        );

        let none: RbacConfig = toml::from_str("").unwrap();
        assert!(none.role_bindings.is_empty());
    }

    fn role_config(name: &str, permissions: &[&str]) -> RoleConfig {
        RoleConfig {
            name: name.to_string(),
            description: None,
            permissions: strings(permissions),
        }
    }

    #[test]
    fn custom_role_names_follow_the_rule() {
        assert_eq!(validate_role_name("a"), Ok(()));
        assert_eq!(validate_role_name("0-ops_team"), Ok(()));
        assert_eq!(validate_role_name(&"a".repeat(63)), Ok(()));
        for name in ["", "-a", "_a", "Ops", "ops team", "ops.team", "ü"] {
            assert!(validate_role_name(name).is_err(), "{name:?}");
        }
        assert!(validate_role_name(&"a".repeat(64)).is_err());
        for role in Role::ALL {
            let err = validate_role_name(role.as_str()).unwrap_err();
            assert!(err.contains("built in"), "{err}");
        }
    }

    #[test]
    fn custom_role_permissions_are_checked_and_ordered() {
        assert_eq!(
            parse_permissions(&strings(&["audit.read", "backends.view", "audit.read"])),
            Ok(vec![Permission::BackendsView, Permission::AuditRead])
        );
        assert!(parse_permissions(&[]).is_err());
        let err = parse_permissions(&strings(&["audit.read", "audit.write"])).unwrap_err();
        assert!(err.contains("audit.write"), "{err}");
        for permission in Permission::ALL {
            assert_eq!(Permission::parse(permission.as_str()), Some(permission));
            assert_ne!(permission.description(), "");
        }
        assert_eq!(Permission::parse("Audit.Read"), None);
    }

    #[test]
    fn a_custom_role_resolves_to_its_permissions() {
        let db = RbacSnapshot {
            role_bindings: vec![named_binding(
                Some(1),
                "log-reader",
                RoleSubject::Group("sec".to_string()),
            )],
            roles: vec![role_config("log-reader", &["audit.read"])],
            ..snapshot(vec![group("sec", &[("entra", "id-sec")])], Vec::new())
        };
        let policy = Policy::from_snapshot(&db);

        let groups = policy.groups_for(user(), "entra", &strings(&["id-sec"]));
        let permissions = policy.permissions_for(user(), &groups, false);
        assert_eq!(roles_of(&permissions), vec!["log-reader", "member"]);
        assert!(permissions.has(Permission::AuditRead));
        assert!(!permissions.has(Permission::BackendsView));
        assert!(!permissions.is_admin());

        let listed = policy.roles();
        assert_eq!(listed.len(), 5);
        assert_eq!(listed[0].source, RoleSource::Builtin);
        assert_eq!(listed[4].name, "log-reader");
        assert_eq!(listed[4].source, RoleSource::Local);
        assert_eq!(policy.role("auditor").unwrap().source, RoleSource::Builtin);
        assert_eq!(policy.role("nope"), None);
        assert_eq!(
            policy.role_permissions("log-reader"),
            Some(vec![Permission::AuditRead])
        );
        assert_eq!(policy.role_permissions("nope"), None);
    }

    #[test]
    fn group_permissions_are_the_union_of_the_bound_roles() {
        let db = RbacSnapshot {
            role_bindings: vec![
                named_binding(Some(1), "log-reader", RoleSubject::Group("sec".to_string())),
                named_binding(Some(2), "auditor", RoleSubject::Group("sec".to_string())),
                named_binding(
                    Some(3),
                    "backend-admin",
                    RoleSubject::Group("ops".to_string()),
                ),
            ],
            roles: vec![role_config("log-reader", &["audit.read"])],
            ..snapshot(
                vec![
                    group("sec", &[("entra", "id-sec")]),
                    group("ops", &[("entra", "id-ops")]),
                    group("plain", &[("entra", "id-plain")]),
                ],
                Vec::new(),
            )
        };
        let policy = Policy::from_snapshot(&db);

        let mut sec = policy.role_permissions("log-reader").unwrap();
        sec.extend(policy.role_permissions("auditor").unwrap());
        sec.sort();
        sec.dedup();
        assert_eq!(policy.group_permissions("sec"), sec);
        assert_eq!(
            policy.group_permissions("ops"),
            policy.role_permissions("backend-admin").unwrap()
        );
        assert_eq!(policy.group_permissions("plain"), vec![]);
        assert_eq!(policy.group_permissions("nope"), vec![]);

        let mut all = sec;
        all.extend(policy.group_permissions("ops"));
        all.sort();
        all.dedup();
        assert_eq!(policy.bound_group_permissions(), all);
    }

    #[test]
    fn a_binding_of_an_unknown_role_grants_nothing_and_stays_listed() {
        let db = RbacSnapshot {
            role_bindings: vec![named_binding(
                Some(1),
                "deleted-role",
                RoleSubject::User(user()),
            )],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let permissions = policy.permissions_for(user(), &[], false);
        assert_eq!(roles_of(&permissions), vec!["member"]);
        assert!(!permissions.has(Permission::AuditRead));
        assert_eq!(policy.role_bindings().len(), 1);
        assert_eq!(policy.role("deleted-role"), None);
    }

    #[test]
    fn custom_roles_bind_like_built_in_ones() {
        let db = RbacSnapshot {
            roles: vec![role_config("log-reader", &["audit.read"])],
            role_bindings: vec![named_binding(
                Some(1),
                "log-reader",
                RoleSubject::User(user()),
            )],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        assert_eq!(policy.role("log-reader").unwrap().source, RoleSource::Local);
        assert!(
            policy
                .permissions_for(user(), &[], false)
                .has(Permission::AuditRead)
        );
    }

    #[test]
    fn a_custom_role_cannot_shadow_a_built_in_one() {
        let db = RbacSnapshot {
            roles: vec![
                role_config("log-reader", &["audit.read"]),
                role_config("admin", &["audit.read"]),
                role_config("zeta", &["backends.view"]),
                role_config("alpha", &["backends.view"]),
            ],
            role_bindings: vec![named_binding(
                Some(1),
                "log-reader",
                RoleSubject::User(user()),
            )],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_snapshot(&db);
        let role = policy.role("log-reader").unwrap();
        assert_eq!(role.source, RoleSource::Local);
        assert_eq!(role.permissions, vec![Permission::AuditRead]);
        assert!(
            !policy
                .permissions_for(user(), &[], false)
                .has(Permission::GatewayAdmin)
        );
        // a database role cannot shadow a built-in one
        assert_eq!(policy.role("admin").unwrap().source, RoleSource::Builtin);
        assert_eq!(policy.role("admin").unwrap().permissions.len(), 12);
        // built-ins, then database roles by name
        let names: Vec<String> = policy.roles().into_iter().map(|role| role.name).collect();
        assert_eq!(
            names,
            strings(&[
                "admin",
                "backend-admin",
                "auditor",
                "member",
                "alpha",
                "log-reader",
                "zeta"
            ])
        );
    }

    #[test]
    fn validate_checks_custom_roles_and_the_bindings_naming_them() {
        let mut config = valid_config();
        config
            .roles
            .push(role_config("log-reader", &["audit.read"]));
        assert_eq!(
            config.validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );

        let mut bad = config.clone();
        bad.roles.push(role_config("log-reader", &["audit.read"]));
        assert!(validate_err(&bad).contains("duplicate rbac role"));
        let mut bad = config.clone();
        bad.roles.push(role_config("admin", &["audit.read"]));
        assert!(validate_err(&bad).contains("built in"));
        let mut bad = config.clone();
        bad.roles.push(role_config("Bad Name", &["audit.read"]));
        assert!(validate_err(&bad).contains("must match"));
        let mut bad = config.clone();
        bad.roles.push(role_config("empty", &[]));
        assert!(validate_err(&bad).contains("at least one permission"));
        let mut bad = config.clone();
        bad.roles.push(role_config("odd", &["audit.write"]));
        assert!(validate_err(&bad).contains("unknown permission"));

        let mut bad = config.clone();
        bad.role_bindings.push(RoleBindingConfig {
            role: "nobody-defined-this".to_string(),
            group: AUTHENTICATED_GROUP.to_string(),
        });
        assert!(validate_err(&bad).contains("unknown role"));
        config.role_bindings.push(RoleBindingConfig {
            role: "log-reader".to_string(),
            group: AUTHENTICATED_GROUP.to_string(),
        });
        assert_eq!(
            config.validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );
    }

    #[test]
    fn parses_custom_roles_from_config() {
        #[derive(Deserialize)]
        struct Root {
            rbac: RbacConfig,
        }
        let root: Root = toml::from_str(
            r#"
            [[rbac.roles]]
            name = "log-reader"
            description = "Reads logs"
            permissions = ["audit.read", "backends.view"]

            [[rbac.roles]]
            name = "min"
            permissions = ["backends.view"]
            "#,
        )
        .unwrap();
        assert_eq!(root.rbac.roles.len(), 2);
        assert_eq!(
            root.rbac.roles[0].description.as_deref(),
            Some("Reads logs")
        );
        assert_eq!(root.rbac.roles[1].description, None);
        assert_eq!(root.rbac.validate(&[], &[]), Ok(()));
    }

    #[test]
    fn missing_lists_what_the_user_may_not_hand_out() {
        let policy = Policy::from_snapshot(&RbacSnapshot::default());
        let member = policy.permissions_for(user(), &[], false);
        assert_eq!(
            member.missing(&[Permission::PersonalBackendsCreate]),
            Vec::<Permission>::new()
        );
        assert_eq!(
            member.missing(&[
                Permission::TokensManageAll,
                Permission::PersonalBackendsCreate,
                Permission::AuditRead,
                Permission::TokensManageAll,
            ]),
            vec![Permission::TokensManageAll, Permission::AuditRead]
        );
        let admin = policy.permissions_for(user(), &[], true);
        assert_eq!(admin.missing(&Permission::ALL), Vec::<Permission>::new());
        assert_eq!(member.missing(&[]), Vec::<Permission>::new());
    }

    #[test]
    fn service_account_groups_are_memberships_only() {
        let policy = Policy::from_snapshot(&db_snapshot());
        // `ghost` does not exist, so the membership row for it is dropped
        assert_eq!(policy.groups_for_service_account(user()), ["beta"]);
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(2)),
            ["beta"]
        );
        // no memberships: nothing, not even `authenticated`
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(99)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn service_account_groups_ignore_idp_mappings() {
        let policy = Policy::from_snapshot(&db_snapshot());
        // `ops` and `it` map the claim value "id-ops"/"id-it" for a login, not for an account
        let login = policy.groups_for(Uuid::from_u128(99), "entra", &strings(&["id-ops", "id-it"]));
        assert!(login.contains(&"ops".to_string()));
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(99)),
            Vec::<String>::new()
        );
    }

    fn with_accounts(name: &str, accounts: &[&str]) -> RbacGroupConfig {
        RbacGroupConfig {
            service_accounts: strings(accounts),
            ..group(name, &[])
        }
    }

    #[test]
    fn validate_rejects_bad_service_account_lists() {
        for accounts in [&[""][..], &["ci", "ci"][..]] {
            let config = RbacConfig {
                groups: vec![with_accounts("it", accounts)],
                grants: Vec::new(),
                role_bindings: Vec::new(),
                roles: Vec::new(),
            };
            assert!(
                validate_err(&config).contains("service account"),
                "{accounts:?}"
            );
        }
        let config = RbacConfig {
            groups: vec![with_accounts("it", &["ci", "bot"])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
            roles: Vec::new(),
        };
        assert_eq!(config.validate(&[], &[]), Ok(()));
    }
}
