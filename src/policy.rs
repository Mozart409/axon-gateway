//! RBAC policy: groups, roles, tool grants and the view layer
//!
//! Pure logic, no I/O. [`RbacConfig`] is the config layer and [`RbacSnapshot`] the
//! rows the database manages; [`Policy`] merges both (config wins on a name clash),
//! maps a login to groups and a user to [`Permissions`] (built-in [`Role`]s and the
//! [`Permission`]s they carry); [`EffectivePolicy`] is the allow-only union of the
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

/// Built-in group every logged-in user is a member of. It may not be declared in config.
pub const AUTHENTICATED_GROUP: &str = "authenticated";

fn all_tools() -> Vec<String> {
    vec!["*".to_string()]
}

/// The `[rbac]` config section
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RbacConfig {
    /// `[[rbac.groups]]`: groups declared in config
    #[serde(default)]
    pub groups: Vec<RbacGroupConfig>,
    /// `[[rbac.grants]]`: which group may use which backend's tools
    #[serde(default)]
    pub grants: Vec<GrantConfig>,
    /// `[[rbac.role_bindings]]`: which group holds which role
    #[serde(default)]
    pub role_bindings: Vec<RoleBindingConfig>,
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
    /// Database row id; `None` for a binding from config
    pub id: Option<i64>,
    /// The role granted
    pub role: Role,
    /// Who holds it
    pub subject: RoleSubject,
}

/// `[[rbac.role_bindings]]`: a role granted to a group
#[derive(Debug, Clone, Deserialize)]
pub struct RoleBindingConfig {
    /// The role granted
    pub role: Role,
    /// A declared group or [`AUTHENTICATED_GROUP`]
    pub group: String,
}

/// The database-managed RBAC rows, as the store loads them
#[derive(Debug, Clone, Default)]
pub struct RbacSnapshot {
    /// Database groups with their `IdP` mappings
    pub groups: Vec<RbacGroupConfig>,
    /// `(user id, group name)`, database groups only
    pub memberships: Vec<(Uuid, String)>,
    /// `(grant id, grant)`
    pub grants: Vec<(i64, GrantConfig)>,
    /// Role bindings; `id` is always `Some`
    pub role_bindings: Vec<RoleBinding>,
}

/// Where a group, grant or binding is managed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// `config.toml`, read-only
    Config,
    /// The dashboard or the API
    Local,
}

/// A group as the dashboard lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    /// Unique name
    pub name: String,
    /// Free text shown next to the group
    pub description: Option<String>,
    /// Where the group is managed
    pub source: Source,
    /// `IdP` claim values whose holders are members
    pub idp: Vec<IdpMapping>,
}

/// A grant as the dashboard lists it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    /// Database row id; `None` for a grant from config
    pub id: Option<i64>,
    /// Where the grant is managed
    pub source: Source,
    /// The grant itself
    pub grant: GrantSummary,
}

/// The effective roles and permissions of a user
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Permissions {
    roles: BTreeSet<Role>,
    permissions: BTreeSet<Permission>,
}

impl Permissions {
    fn add(&mut self, role: Role) {
        self.roles.insert(role);
        self.permissions.extend(role.permissions());
    }

    /// Whether some role of the user carries the permission
    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// The user's roles, in [`Role`] order
    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.roles.iter().copied()
    }

    /// Whether the user holds [`Role::Admin`]
    pub fn is_admin(&self) -> bool {
        self.roles.contains(&Role::Admin)
    }
}

/// A group declared in config
#[derive(Debug, Clone, Deserialize)]
pub struct RbacGroupConfig {
    /// Unique name, `[a-z0-9_-]+`
    pub name: String,
    /// Free text shown next to the group
    #[serde(default)]
    pub description: Option<String>,
    /// Identity provider claim values whose holders are members of this group
    #[serde(default)]
    pub idp: Vec<IdpMapping>,
    /// Service account names that are members of this group: a `[[tokens]]` entry's
    /// `name` or a database service account's name
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

/// A grant of one backend's tools to a group
#[derive(Debug, Clone, Deserialize)]
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

/// The name rule for groups from config and the API: `[a-z0-9_-]+`, 1 to 64 characters,
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
        for binding in &self.role_bindings {
            if binding.group != AUTHENTICATED_GROUP && !names.contains(binding.group.as_str()) {
                return Err(format!(
                    "rbac role binding for role {:?} names unknown group {:?}",
                    binding.role.as_str(),
                    binding.group
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
    service_accounts: Vec<String>,
    source: Source,
}

impl GroupDef {
    fn new(group: &RbacGroupConfig, source: Source) -> Self {
        Self {
            name: group.name.clone(),
            description: group.description.clone(),
            idp: group.idp.clone(),
            service_accounts: group.service_accounts.clone(),
            source,
        }
    }

    fn view(&self) -> GroupView {
        GroupView {
            name: self.name.clone(),
            description: self.description.clone(),
            source: self.source,
            idp: self.idp.clone(),
        }
    }
}

/// Compiled groups, memberships, grants and role bindings of config and database
#[derive(Debug, Clone)]
pub struct Policy {
    /// Config groups first, then database groups
    groups: Vec<GroupDef>,
    /// Memberships in database groups that exist
    memberships: Vec<(Uuid, String)>,
    /// Config grants in config order, then database grants by id
    grants: Vec<GrantView>,
    /// Config bindings, then database bindings by id
    role_bindings: Vec<RoleBinding>,
}

impl Policy {
    /// Compile a (validated) config without database rows
    pub fn from_config(config: &RbacConfig) -> Self {
        Self::from_parts(config, &RbacSnapshot::default())
    }

    /// Merge a (validated) config with the database rows. A database group named like a
    /// config group (or [`AUTHENTICATED_GROUP`]) is ignored: config wins. Memberships of
    /// groups that do not exist are dropped. Grants and bindings for unknown groups stay
    /// listed, so an admin can delete them, but never take effect.
    pub fn from_parts(config: &RbacConfig, db: &RbacSnapshot) -> Self {
        let mut groups: Vec<GroupDef> = config
            .groups
            .iter()
            .map(|group| GroupDef::new(group, Source::Config))
            .collect();
        let mut names: HashSet<String> = groups.iter().map(|group| group.name.clone()).collect();
        names.insert(AUTHENTICATED_GROUP.to_string());
        for group in &db.groups {
            if names.insert(group.name.clone()) {
                groups.push(GroupDef::new(group, Source::Local));
            } else {
                tracing::warn!(
                    group = %group.name,
                    "ignoring database rbac group: the name is already taken by a config group"
                );
            }
        }

        let local: HashSet<&str> = groups
            .iter()
            .filter(|group| group.source == Source::Local)
            .map(|group| group.name.as_str())
            .collect();
        let memberships = db
            .memberships
            .iter()
            .filter(|(_, group)| local.contains(group.as_str()))
            .cloned()
            .collect();

        let mut db_grants: Vec<&(i64, GrantConfig)> = db.grants.iter().collect();
        db_grants.sort_by_key(|(id, _)| *id);
        let grants = config
            .grants
            .iter()
            .map(|grant| GrantView {
                id: None,
                source: Source::Config,
                grant: GrantSummary::from(grant),
            })
            .chain(db_grants.into_iter().map(|(id, grant)| GrantView {
                id: Some(*id),
                source: Source::Local,
                grant: GrantSummary::from(grant),
            }))
            .collect();

        let mut db_bindings = db.role_bindings.clone();
        db_bindings.sort_by_key(|binding| binding.id);
        let role_bindings = config
            .role_bindings
            .iter()
            .map(|binding| RoleBinding {
                id: None,
                role: binding.role,
                subject: RoleSubject::Group(binding.group.clone()),
            })
            .chain(db_bindings)
            .collect();

        Self {
            groups,
            memberships,
            grants,
            role_bindings,
        }
    }

    /// Groups of a login: [`AUTHENTICATED_GROUP`], every config or database group with an
    /// idp mapping for this provider whose value is among the claim values, and every
    /// database group the user is a member of. Sorted, deduplicated.
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

    /// Groups of a database service account: its database memberships plus every config
    /// group that lists `name` in `service_accounts`. No [`AUTHENTICATED_GROUP`] and no
    /// `IdP` mappings, an account has no login. Sorted, deduplicated.
    pub fn groups_for_service_account(&self, account_id: Uuid, name: &str) -> Vec<String> {
        self.memberships
            .iter()
            .filter(|(member, _)| *member == account_id)
            .map(|(_, group)| group.clone())
            .chain(self.groups_for_config_account(name))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Groups of a config service account (a `[[tokens]]` entry): the config groups that
    /// list `name` in `service_accounts`, sorted. No [`AUTHENTICATED_GROUP`].
    pub fn groups_for_config_account(&self, name: &str) -> Vec<String> {
        self.groups
            .iter()
            .filter(|group| {
                group.source == Source::Config
                    && group.service_accounts.iter().any(|account| account == name)
            })
            .map(|group| group.name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Roles and permissions of a user. Everyone is a [`Role::Member`]; `is_admin` (the
    /// provider's `admin_groups`) adds [`Role::Admin`]; bindings on the user or on one of
    /// `groups` add theirs.
    pub fn permissions_for(&self, user_id: Uuid, groups: &[String], is_admin: bool) -> Permissions {
        let mut permissions = Permissions::default();
        permissions.add(Role::Member);
        if is_admin {
            permissions.add(Role::Admin);
        }
        for binding in &self.role_bindings {
            let applies = match &binding.subject {
                RoleSubject::User(id) => *id == user_id,
                RoleSubject::Group(group) => groups.contains(group) && self.has_group(group),
            };
            if applies {
                permissions.add(binding.role);
            }
        }
        permissions
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

    /// Config groups, then database groups, each sorted by name.
    /// [`AUTHENTICATED_GROUP`] is not included.
    pub fn groups(&self) -> Vec<GroupView> {
        let mut views: Vec<GroupView> = self.groups.iter().map(GroupDef::view).collect();
        views.sort_by(|a, b| {
            (a.source == Source::Local, &a.name).cmp(&(b.source == Source::Local, &b.name))
        });
        views
    }

    /// One declared group
    pub fn group(&self, name: &str) -> Option<GroupView> {
        self.groups
            .iter()
            .find(|group| group.name == name)
            .map(GroupDef::view)
    }

    /// Whether the name is a config group, a database group or [`AUTHENTICATED_GROUP`]
    pub fn has_group(&self, name: &str) -> bool {
        name == AUTHENTICATED_GROUP || self.groups.iter().any(|group| group.name == name)
    }

    /// Config grants in config order, then database grants by id
    pub fn grants(&self) -> Vec<GrantView> {
        self.grants.clone()
    }

    /// Config bindings (no id), then database bindings by id
    pub fn role_bindings(&self) -> Vec<RoleBinding> {
        self.role_bindings.clone()
    }

    /// Users that are members of a database group, sorted
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
        RoleBinding { id, role, subject }
    }

    fn tool<'a>(backend: &'a str, name: &'a str, read_only_hint: bool) -> ToolRef<'a> {
        ToolRef {
            backend,
            name,
            read_only_hint,
        }
    }

    fn effective(config: &RbacConfig, groups: &[&str]) -> EffectivePolicy {
        Policy::from_config(config).effective(&strings(groups))
    }

    #[test]
    fn union_across_two_groups() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("dev", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("dev", "forgejo", &["get_*"], &[]),
            ],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![grant("it", "prometheus", &["*"], &[])],
            role_bindings: Vec::new(),
        };
        let nobody = effective(&config, &[]);
        assert!(!nobody.allows(tool("prometheus", "query", true)));
        assert_eq!(nobody.backends(), Vec::<String>::new());

        let it = effective(&config, &["it"]);
        assert!(!it.allows(tool("unknown", "query", true)));

        let empty = effective(&RbacConfig::default(), &["authenticated", "it"]);
        assert!(!empty.allows(tool("prometheus", "query", true)));
    }

    #[test]
    fn exclude_beats_include_within_a_grant_but_union_can_still_allow() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("ops", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("ops", "prometheus", &["delete_series"], &[]),
            ],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only],
            role_bindings: Vec::new(),
        };
        let it = effective(&config, &["it"]);
        assert!(it.allows(tool("prometheus", "query", true)));
        assert!(!it.allows(tool("prometheus", "query", false)));
    }

    #[test]
    fn read_only_grant_does_not_limit_another_grant() {
        let mut read_only = grant("authenticated", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only, grant("it", "prometheus", &["*"], &[])],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![mandatory, grant("it", "hindsight", &["forget"], &[])],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("dev", &[]), group("ops", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("dev", "prometheus", &["get_*"], &[]),
                read_only,
                grant("it", "forgejo", &["*"], &[]),
            ],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![grant("it", "prometheus", &["*"], &[])],
            role_bindings: Vec::new(),
        };
        let explanation = effective(&config, &["it"]).explain(tool("forgejo", "get_repo", true));
        assert_eq!(explanation.allowed_by, Vec::<GrantSummary>::new());
        assert_eq!(explanation.missed, Vec::<(GrantSummary, Miss)>::new());
    }

    #[test]
    fn explain_matches_allows() {
        let mut read_only = grant("it", "prometheus", &["get_*", "list_*"], &["list_secret"]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only],
            role_bindings: Vec::new(),
        };
        let it = effective(&config, &["it"]);
        for name in ["get_a", "list_b", "list_secret", "other"] {
            for hint in [true, false] {
                let tool = tool("prometheus", name, hint);
                assert_eq!(it.allows(tool), !it.explain(tool).allowed_by.is_empty());
            }
        }
    }

    fn login_config() -> RbacConfig {
        RbacConfig {
            groups: vec![
                group("it", &[("entra", "id-it"), ("entra", "id-admins")]),
                group("dev", &[("entra", "id-dev"), ("github", "id-it")]),
                group("manual", &[]),
            ],
            grants: Vec::new(),
            role_bindings: Vec::new(),
        }
    }

    #[test]
    fn groups_for_always_contains_authenticated() {
        let policy = Policy::from_config(&login_config());
        assert_eq!(
            policy.groups_for(user(), "entra", &[]),
            strings(&["authenticated"])
        );
        assert_eq!(
            policy.groups_for(user(), "entra", &strings(&["unknown"])),
            strings(&["authenticated"])
        );
        assert_eq!(
            Policy::from_config(&RbacConfig::default()).groups_for(
                user(),
                "entra",
                &strings(&["x"])
            ),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn groups_for_ignores_other_providers() {
        let policy = Policy::from_config(&login_config());
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
        let policy = Policy::from_config(&login_config());
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
        let config = RbacConfig {
            groups: vec![it, group("dev", &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
        };
        let policy = Policy::from_config(&config);
        assert_eq!(policy.group_description("it"), Some("IT staff"));
        assert_eq!(policy.group_description("dev"), None);
        assert_eq!(policy.group_description("missing"), None);
    }

    #[test]
    fn visible_applies_backend_and_tool_opt_outs() {
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("it", "forgejo", &["*"], &[]),
            ],
            role_bindings: Vec::new(),
        };
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
        let config = RbacConfig {
            groups: Vec::new(),
            grants: vec![mandatory, grant("authenticated", "hindsight", &["*"], &[])],
            role_bindings: Vec::new(),
        };
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
        };
        assert!(validate_err(&config).contains("duplicate"));
    }

    #[test]
    fn validate_rejects_the_reserved_group() {
        let config = RbacConfig {
            groups: vec![group(AUTHENTICATED_GROUP, &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
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
        assert!(rbac.groups.is_empty());
        assert!(rbac.grants.is_empty());
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

    fn roles_of(permissions: &Permissions) -> Vec<Role> {
        permissions.roles().collect()
    }

    #[test]
    fn a_plain_user_is_only_a_member() {
        let policy = Policy::from_config(&RbacConfig::default());
        let permissions = policy.permissions_for(user(), &strings(&["authenticated"]), false);
        assert_eq!(roles_of(&permissions), vec![Role::Member]);
        assert!(permissions.has(Permission::PersonalBackendsCreate));
        assert!(!permissions.has(Permission::AuditRead));
        assert!(!permissions.is_admin());
    }

    #[test]
    fn admin_flag_adds_the_admin_role() {
        let policy = Policy::from_config(&RbacConfig::default());
        let permissions = policy.permissions_for(user(), &[], true);
        assert_eq!(roles_of(&permissions), vec![Role::Admin, Role::Member]);
        assert!(permissions.is_admin());
        for permission in Permission::ALL {
            assert!(permissions.has(permission));
        }
    }

    #[test]
    fn a_binding_on_a_group_applies_to_its_members_only() {
        let config = RbacConfig {
            groups: vec![group("it-sec", &[("entra", "id-sec")]), group("dev", &[])],
            grants: Vec::new(),
            role_bindings: vec![RoleBindingConfig {
                role: Role::Auditor,
                group: "it-sec".to_string(),
            }],
        };
        let policy = Policy::from_config(&config);

        let groups = policy.groups_for(user(), "entra", &strings(&["id-sec"]));
        let permissions = policy.permissions_for(user(), &groups, false);
        assert_eq!(roles_of(&permissions), vec![Role::Auditor, Role::Member]);
        assert!(permissions.has(Permission::AuditRead));
        assert!(permissions.has(Permission::BackendsView));
        assert!(!permissions.has(Permission::AuditReadSensitive));

        // a group the user is not in has no effect
        let groups = policy.groups_for(user(), "entra", &[]);
        let permissions = policy.permissions_for(user(), &groups, false);
        assert_eq!(roles_of(&permissions), vec![Role::Member]);
        let permissions = policy.permissions_for(user(), &strings(&["dev"]), false);
        assert_eq!(roles_of(&permissions), vec![Role::Member]);
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
        let policy = Policy::from_parts(&RbacConfig::default(), &db);
        let permissions = policy.permissions_for(user(), &[], false);
        assert_eq!(
            roles_of(&permissions),
            vec![Role::BackendAdmin, Role::Member]
        );
        assert!(permissions.has(Permission::BackendsManage));
        assert!(!permissions.has(Permission::GroupsManage));
        let permissions = policy.permissions_for(other, &[], false);
        assert_eq!(roles_of(&permissions), vec![Role::Member]);
    }

    #[test]
    fn a_binding_on_authenticated_applies_to_everyone() {
        let config = RbacConfig {
            groups: Vec::new(),
            grants: Vec::new(),
            role_bindings: vec![RoleBindingConfig {
                role: Role::Auditor,
                group: AUTHENTICATED_GROUP.to_string(),
            }],
        };
        let policy = Policy::from_config(&config);
        let groups = policy.groups_for(user(), "entra", &[]);
        assert!(
            policy
                .permissions_for(user(), &groups, false)
                .has(Permission::AuditRead)
        );
    }

    fn db_snapshot() -> RbacSnapshot {
        RbacSnapshot {
            groups: vec![
                RbacGroupConfig {
                    name: "ops".to_string(),
                    description: Some("Operations".to_string()),
                    idp: group("ops", &[("entra", "id-ops")]).idp,
                    service_accounts: Vec::new(),
                },
                group("it", &[("entra", "id-evil")]),
                group("beta", &[]),
            ],
            memberships: vec![
                (user(), "beta".to_string()),
                (Uuid::from_u128(2), "beta".to_string()),
                (user(), "ghost".to_string()),
                (user(), "it".to_string()),
            ],
            grants: vec![
                (7, grant("ops", "loki", &["*"], &[])),
                (3, grant("beta", "forgejo", &["get_*"], &[])),
                (9, grant("ghost", "prometheus", &["*"], &[])),
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
            ],
        }
    }

    fn merged_config() -> RbacConfig {
        RbacConfig {
            groups: vec![group("it", &[("entra", "id-it")])],
            grants: vec![grant("it", "prometheus", &["*"], &[])],
            role_bindings: vec![RoleBindingConfig {
                role: Role::BackendAdmin,
                group: "it".to_string(),
            }],
        }
    }

    #[test]
    fn from_config_equals_from_parts_without_database_rows() {
        let config = merged_config();
        let a = Policy::from_config(&config);
        let b = Policy::from_parts(&config, &RbacSnapshot::default());
        assert_eq!(a.groups(), b.groups());
        assert_eq!(a.grants(), b.grants());
        assert_eq!(a.role_bindings(), b.role_bindings());
    }

    #[test]
    fn database_groups_match_by_membership_and_idp_mapping() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        // membership
        assert_eq!(
            policy.groups_for(user(), "entra", &[]),
            strings(&["authenticated", "beta"])
        );
        // idp mapping, config and database
        assert_eq!(
            policy.groups_for(Uuid::from_u128(3), "entra", &strings(&["id-ops", "id-it"])),
            strings(&["authenticated", "it", "ops"])
        );
        // the colliding database group's mapping does not count
        assert_eq!(
            policy.groups_for(Uuid::from_u128(3), "entra", &strings(&["id-evil"])),
            strings(&["authenticated"])
        );
        // no membership in a group that does not exist, none in the ignored "it"
        let groups = policy.groups_for(user(), "entra", &[]);
        assert!(!groups.contains(&"ghost".to_string()));
        assert!(!groups.contains(&"it".to_string()));
        assert_eq!(policy.members_of("beta"), vec![user(), Uuid::from_u128(2)]);
        assert_eq!(policy.members_of("it"), Vec::<Uuid>::new());
        assert_eq!(policy.members_of("ghost"), Vec::<Uuid>::new());
    }

    #[test]
    fn database_grants_take_effect_and_orphans_do_not() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
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
    fn a_database_group_named_like_a_config_group_is_ignored() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        let it = policy.group("it").unwrap();
        assert_eq!(it.source, Source::Config);
        assert_eq!(
            it.idp,
            vec![IdpMapping {
                provider: "entra".to_string(),
                value: "id-it".to_string(),
            }]
        );
        assert_eq!(policy.groups().iter().filter(|g| g.name == "it").count(), 1);

        let db = RbacSnapshot {
            groups: vec![
                group(AUTHENTICATED_GROUP, &[]),
                group("x", &[]),
                group("x", &[]),
            ],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_parts(&RbacConfig::default(), &db);
        let names: Vec<String> = policy.groups().into_iter().map(|g| g.name).collect();
        assert_eq!(names, strings(&["x"]));
    }

    #[test]
    fn database_bindings_follow_their_group() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        let ops = policy.groups_for(Uuid::from_u128(3), "entra", &strings(&["id-ops"]));
        let permissions = policy.permissions_for(Uuid::from_u128(3), &ops, false);
        assert!(permissions.has(Permission::AuditRead));
        // a binding on an unknown group is listed but does not apply
        let permissions = policy.permissions_for(Uuid::from_u128(3), &strings(&["ghost"]), false);
        assert!(!permissions.is_admin());
    }

    #[test]
    fn groups_are_listed_config_first_then_local_each_sorted() {
        let config = RbacConfig {
            groups: vec![group("zeta", &[]), group("alpha", &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
        };
        let db = RbacSnapshot {
            groups: vec![group("mid", &[]), group("beta", &[])],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_parts(&config, &db);
        let listed: Vec<(String, Source)> = policy
            .groups()
            .into_iter()
            .map(|g| (g.name, g.source))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("alpha".to_string(), Source::Config),
                ("zeta".to_string(), Source::Config),
                ("beta".to_string(), Source::Local),
                ("mid".to_string(), Source::Local),
            ]
        );
        assert!(policy.has_group("beta"));
        assert!(policy.has_group(AUTHENTICATED_GROUP));
        assert!(!policy.has_group("nope"));
        assert_eq!(policy.group("nope"), None);
    }

    #[test]
    fn grants_and_bindings_list_config_first_then_database_by_id() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        let grants: Vec<(Option<i64>, Source, String)> = policy
            .grants()
            .into_iter()
            .map(|view| (view.id, view.source, view.grant.backend))
            .collect();
        assert_eq!(
            grants,
            vec![
                (None, Source::Config, "prometheus".to_string()),
                (Some(3), Source::Local, "forgejo".to_string()),
                (Some(7), Source::Local, "loki".to_string()),
                (Some(9), Source::Local, "prometheus".to_string()),
            ]
        );
        assert_eq!(
            policy.role_bindings(),
            vec![
                binding(
                    None,
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
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
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
        assert_eq!(rbac.role_bindings[0].role, Role::Auditor);
        assert_eq!(rbac.role_bindings[0].group, "it-sec");
        assert_eq!(rbac.role_bindings[1].role, Role::BackendAdmin);
        assert_eq!(rbac.validate(&[], &[]), Ok(()));

        let mut bad = rbac.clone();
        bad.role_bindings.push(RoleBindingConfig {
            role: Role::Admin,
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

    #[test]
    fn service_account_groups_are_memberships_only() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        // `it` is a config group: the membership row for it is dropped, `ghost` does not exist
        assert_eq!(
            policy.groups_for_service_account(user(), "nobody"),
            ["beta"]
        );
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(2), "nobody"),
            ["beta"]
        );
        // no memberships: nothing, not even `authenticated`
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(99), "nobody"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn service_account_groups_ignore_idp_mappings() {
        let policy = Policy::from_parts(&merged_config(), &db_snapshot());
        // `ops` and `it` map the claim value "id-ops"/"id-it" for a login, not for an account
        let login = policy.groups_for(Uuid::from_u128(99), "entra", &strings(&["id-ops", "id-it"]));
        assert!(login.contains(&"ops".to_string()));
        assert_eq!(
            policy.groups_for_service_account(Uuid::from_u128(99), "nobody"),
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
    fn config_account_groups_come_from_service_accounts_lists() {
        let config = RbacConfig {
            groups: vec![
                with_accounts("zeta", &["ci", "bot"]),
                with_accounts("alpha", &["ci"]),
                with_accounts("other", &["bot"]),
            ],
            grants: Vec::new(),
            role_bindings: Vec::new(),
        };
        let policy = Policy::from_config(&config);
        assert_eq!(policy.groups_for_config_account("ci"), ["alpha", "zeta"]);
        assert_eq!(policy.groups_for_config_account("bot"), ["other", "zeta"]);
        assert_eq!(
            policy.groups_for_config_account("nobody"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn database_account_groups_add_config_lists_to_memberships() {
        let config = RbacConfig {
            groups: vec![with_accounts("ops", &["svc"]), group("it", &[])],
            grants: Vec::new(),
            role_bindings: Vec::new(),
        };
        let snapshot = RbacSnapshot {
            groups: vec![group("beta", &[])],
            memberships: vec![(user(), "beta".to_string())],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_parts(&config, &snapshot);
        assert_eq!(
            policy.groups_for_service_account(user(), "svc"),
            ["beta", "ops"]
        );
        assert_eq!(policy.groups_for_service_account(user(), "x"), ["beta"]);
        // a database group's own `service_accounts` is never consulted
        let mut db_group = group("dbg", &[]);
        db_group.service_accounts = strings(&["svc"]);
        let snapshot = RbacSnapshot {
            groups: vec![db_group],
            ..RbacSnapshot::default()
        };
        let policy = Policy::from_parts(&config, &snapshot);
        assert_eq!(policy.groups_for_config_account("svc"), ["ops"]);
    }

    #[test]
    fn validate_rejects_bad_service_account_lists() {
        for accounts in [&[""][..], &["ci", "ci"][..]] {
            let config = RbacConfig {
                groups: vec![with_accounts("it", accounts)],
                grants: Vec::new(),
                role_bindings: Vec::new(),
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
        };
        assert_eq!(config.validate(&[], &[]), Ok(()));
    }
}
