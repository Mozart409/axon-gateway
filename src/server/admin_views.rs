//! HTML rendering (maud) for the admin pages: groups, grants, roles, role
//! bindings, users and the audit log.
//!
//! Like `views`, these are pure view functions. The page handlers and the
//! htmx actions live in `admin_ui`; every section here is also the fragment an
//! action answers with (`hx-target` the section's id, `hx-swap="outerHTML"`).
//! Forms and buttons only render for users who hold the permission, the
//! service layer in `rbac` still decides.

use std::collections::{BTreeMap, BTreeSet};

use maud::{Markup, html};
use uuid::Uuid;

use super::AppState;
use super::shell::{Nav, icon, render_shell};
use crate::policy::{
    GrantView, GroupView, Permission, Permissions, RoleBinding, RoleSource, RoleSubject, RoleView,
};
use crate::rbac::{ManagedUser, RoleEntry};
use crate::store::{AuditRecord, ServiceAccount, SessionUser, User};

/// The intro line of a card, under its header
pub(super) const DESC: &str = "card-b pb-0 text-muted";
/// The empty-state line of a card
pub(super) const EMPTY: &str = "card-b text-muted";
pub(super) const TABLE: &str = "tbl";
pub(super) const TD: &str = "align-middle";
pub(super) const CODE: &str = "mono text-text";
/// A form that is the footer of its card
pub(super) const FORM_FOOT: &str = "card-f flex-wrap items-end gap-3";
pub(super) const LABEL: &str = "flex min-w-40 flex-col gap-1 text-xs font-medium text-muted";
pub(super) const INPUT: &str = "input";
pub(super) const BUTTON: &str = "btn primary";
pub(super) const BUTTON_SMALL: &str = "btn sm";
pub(super) const BUTTON_DANGER: &str = "btn sm danger";
/// A link that looks like a small button (`.axon a` would colour it as a link)
pub(super) const LINK_BUTTON: &str = "btn sm text-text";
pub(super) const LINK: &str =
    "font-medium text-accent underline underline-offset-2 hover:opacity-80";

/// What the signed-in user may do on the admin pages
#[derive(Debug, Clone, Copy)]
pub(super) struct Access {
    /// Create and edit groups and grants (`groups.manage`)
    pub manage_groups: bool,
    /// Edit role bindings (`roles.manage`)
    pub manage_roles: bool,
    /// Disable and re-enable users (`users.manage`)
    pub manage_users: bool,
}

impl Access {
    pub(super) fn of(permissions: &Permissions) -> Self {
        Self {
            manage_groups: permissions.has(Permission::GroupsManage),
            manage_roles: permissions.has(Permission::RolesManage),
            manage_users: permissions.has(Permission::UsersManage),
        }
    }
}

/// A configured sign-in provider, as far as the admin pages need it
pub(super) struct ProviderInfo {
    pub id: String,
    pub issuer: String,
    /// Group values that make a user an admin
    pub admin_groups: Vec<String>,
}

/// Everything `/ui/admin/users` shows
pub(super) struct UsersPage {
    pub access: Access,
    /// The signed-in user, who cannot disable themselves
    pub viewer: Uuid,
    pub users: Vec<ManagedUser>,
    /// The configured providers, to spot users of an issuer none of them has
    pub providers: Vec<ProviderInfo>,
}

/// A group and how many users were added to it by hand
pub(super) struct GroupRow {
    pub group: GroupView,
    pub members: usize,
}

/// Everything `/ui/admin` shows
pub(super) struct AdminOverview {
    pub access: Access,
    pub groups: Vec<GroupRow>,
    pub grants: Vec<GrantView>,
    pub bindings: Vec<RoleBinding>,
    /// Roles a binding may name, built-in ones first; a binding naming none of them
    /// is shown as unknown
    pub roles: Vec<RoleView>,
    /// Groups a grant or a role binding may name, `authenticated` first
    pub group_names: Vec<String>,
    /// Configured backends a grant may name
    pub backends: Vec<String>,
    /// Users a role binding may name; empty without the permission to list them
    pub users: Vec<User>,
}

/// Everything `/ui/admin/roles` shows
pub(super) struct RolesPage {
    pub access: Access,
    pub roles: Vec<RoleEntry>,
    /// The configured providers; their `admin_groups` give the built-in `admin` role
    pub providers: Vec<ProviderInfo>,
}

/// Everything `/ui/admin/groups/{name}` shows
pub(super) struct GroupDetail {
    pub access: Access,
    pub group: GroupView,
    /// Ids of the users added by hand
    pub members: Vec<Uuid>,
    pub users: Vec<User>,
    /// Service accounts that may be members too; empty without the permission to list them
    pub accounts: Vec<ServiceAccount>,
    /// Configured `[[auth.oidc]]` ids an `IdP` mapping may name
    pub providers: Vec<String>,
}

impl GroupDetail {
    /// Whether the user may edit this group.
    fn editable(&self) -> bool {
        self.access.manage_groups
    }
}

/// Email, else display name, else subject
fn user_label(user: &User) -> &str {
    [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
}

/// The label of the user with this id, or the id itself when unknown.
fn label_for(users: &[User], id: Uuid) -> String {
    users
        .iter()
        .find(|user| user.id == id)
        .map_or_else(|| id.to_string(), |user| user_label(user).to_owned())
}

/// The label of a group member: a user, a service account (marked as one) or,
/// when unknown, the id itself.
fn member_label(detail: &GroupDetail, id: Uuid) -> String {
    match detail.accounts.iter().find(|account| account.id == id) {
        Some(account) => format!("{} (service account)", account.name),
        None => label_for(&detail.users, id),
    }
}

fn group_href(name: &str) -> String {
    format!("/ui/admin/groups/{name}")
}

fn role_source_badge(source: RoleSource) -> Markup {
    match source {
        RoleSource::Builtin => html! {
            span class="pill accent" { "built-in" }
        },
        RoleSource::Local => html! {
            span class="pill ok" { "local" }
        },
    }
}

/// The first letter or digit, capitalised, for an avatar
fn initials(label: &str) -> String {
    label
        .chars()
        .find(|c| c.is_alphanumeric())
        .into_iter()
        .flat_map(char::to_uppercase)
        .collect()
}

/// Where action errors show: the target of their `HX-Retarget`. Successful
/// actions send it again as an out-of-band swap to clear an old error.
pub(super) fn render_flash_area(oob: bool) -> Markup {
    html! {
        div id="admin-flash" class="empty:hidden" hx-swap-oob=[oob.then_some("true")] {}
    }
}

/// Page frame of the admin pages: the shell around `content`, with `active` marked in the sidebar.
pub(super) fn render_layout(
    state: &AppState,
    user: &SessionUser,
    title: &str,
    active: Nav,
    content: &Markup,
) -> Markup {
    render_shell(state, user, title, active, content)
}

/// The page for a user who may not see an admin page (answered with 403).
pub(super) fn render_forbidden_page(state: &AppState, user: &SessionUser) -> Markup {
    let content = html! {
        section class="card" {
            div class="card-h" { h2 { "Not allowed" } }
            p class=(EMPTY) { "You do not have the permission to view this page." }
        }
    };
    render_layout(state, user, "Not allowed", Nav::None, &content)
}

/// Admin overview (`GET /ui/admin`).
pub(super) fn render_admin_page(
    state: &AppState,
    user: &SessionUser,
    overview: &AdminOverview,
) -> Markup {
    let content = html! {
        div class="page-head" {
            p { "Groups, grants and role bindings." }
        }
        (render_flash_area(false))
        (render_groups_section(overview, false))
        (render_grants_section(overview, false))
        (render_bindings_section(overview, false))
    };
    render_layout(state, user, "Admin", Nav::Admin, &content)
}

/// Groups table and the create form, the swap target of `groups` actions.
/// `oob` renders it as an out-of-band swap next to another fragment.
pub(super) fn render_groups_section(overview: &AdminOverview, oob: bool) -> Markup {
    html! {
        section id="admin-groups" class="card" hx-swap-oob=[oob.then_some("true")] {
            div class="card-h" { h2 id="groups" { "Groups" } }
            p class=(DESC) {
                "Users join a group through an IdP mapping or by being added by hand. "
                "Everyone is also in the built-in authenticated group."
            }
            @if overview.groups.is_empty() {
                p class=(EMPTY) { "No groups yet." }
            } @else {
                div class="tbl-wrap mt-3 border-t border-border" tabindex="0" role="region" aria-label="Groups" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "Name" }
                                th { "Description" }
                                th { "IdP mappings" }
                                th { "Members" }
                            }
                        }
                        tbody {
                            @for row in &overview.groups {
                                tr {
                                    td class=(TD) {
                                        a href=(group_href(&row.group.name)) class=(LINK) {
                                            (row.group.name)
                                        }
                                    }
                                    td class=(TD) {
                                        @if let Some(description) = &row.group.description {
                                            (description)
                                        }
                                    }
                                    td class=(TD) {
                                        @for mapping in &row.group.idp {
                                            div {
                                                code class=(CODE) { (mapping.provider) }
                                                ": "
                                                code class=(CODE) { (mapping.value) }
                                            }
                                        }
                                    }
                                    td class=(TD) { (row.members) }
                                }
                            }
                        }
                    }
                }
            }
            @if overview.access.manage_groups {
                form
                    class=(FORM_FOOT)
                    hx-post="/ui/actions/admin/groups"
                    hx-target="#admin-groups"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Name"
                        input class=(INPUT) type="text" name="name" placeholder="e.g. platform-team" required;
                    }
                    label class=(LABEL) {
                        "Description"
                        input class=(INPUT) type="text" name="description";
                    }
                    button class=(BUTTON) type="submit" { "Create group" }
                }
            }
        }
    }
}

/// `include` or `exclude` globs of a grant, comma separated
fn globs(patterns: &[String]) -> Markup {
    html! {
        @if patterns.is_empty() {
            span class="text-muted" { "-" }
        } @else {
            code class=(CODE) { (patterns.join(", ")) }
        }
    }
}

fn yes_no(value: bool) -> Markup {
    html! {
        @if value {
            span class="pill ok" { "yes" }
        } @else {
            span class="text-muted" { "no" }
        }
    }
}

/// The groups and backends of the grants matrix: the known ones first, then any
/// a grant names that is not known (a grant outlives a removed backend).
fn matrix_axes(overview: &AdminOverview) -> (Vec<&str>, Vec<&str>) {
    let mut groups: Vec<&str> = overview.group_names.iter().map(String::as_str).collect();
    let mut backends: Vec<&str> = overview.backends.iter().map(String::as_str).collect();
    for view in &overview.grants {
        if !groups.contains(&view.grant.group.as_str()) {
            groups.push(&view.grant.group);
        }
        if !backends.contains(&view.grant.backend.as_str()) {
            backends.push(&view.grant.backend);
        }
    }
    (groups, backends)
}

/// One cell of the matrix: every tool, some of them or read-only, or no grant.
fn matrix_cell(overview: &AdminOverview, group: &str, backend: &str) -> Markup {
    let matching: Vec<&GrantView> = overview
        .grants
        .iter()
        .filter(|view| view.grant.group == group && view.grant.backend == backend)
        .collect();
    let full = matching.iter().any(|view| {
        let grant = &view.grant;
        !grant.read_only
            && grant.exclude.is_empty()
            && (grant.include.is_empty() || grant.include.iter().any(|pattern| pattern == "*"))
    });
    let read_only = !matching.is_empty() && matching.iter().all(|view| view.grant.read_only);
    let (state, title) = if matching.is_empty() {
        ("none", format!("{group} has no grant on {backend}"))
    } else if full {
        ("full", format!("{group} may use every tool of {backend}"))
    } else {
        (
            "partial",
            format!("{group} may use some tools of {backend} (include, exclude or read-only)"),
        )
    };
    html! {
        span class="cell cursor-default" data-state=(state) role="img" aria-label=(title) title=(title) {
            @if full {
                (icon("check"))
            } @else if read_only {
                "ro"
            } @else if state == "partial" {
                "sel"
            }
        }
    }
}

/// Read-only groups x backends view of the grants; the forms below change them.
fn grants_matrix(overview: &AdminOverview) -> Markup {
    let (groups, backends) = matrix_axes(overview);
    html! {
        @if !groups.is_empty() && !backends.is_empty() {
            div class="section-t px-3.5 pt-3" { "Access matrix" }
            div class="tbl-wrap mt-2 border-t border-border" tabindex="0" role="region" aria-label="Access matrix" {
                table class="tbl matrix" {
                    thead {
                        tr {
                            th { "Group" }
                            @for backend in &backends {
                                th { code class=(CODE) { (backend) } }
                            }
                        }
                    }
                    tbody {
                        @for group in &groups {
                            tr {
                                td { code class=(CODE) { (group) } }
                                @for backend in &backends {
                                    td { (matrix_cell(overview, group, backend)) }
                                }
                            }
                        }
                    }
                }
            }
            div class="card-f flex-wrap gap-4 text-muted" {
                span class="inline-flex items-center gap-1.5" {
                    span class="cell size-5 cursor-default" data-state="full" { (icon("check")) }
                    "all tools"
                }
                span class="inline-flex items-center gap-1.5" {
                    span class="cell size-5 cursor-default" data-state="partial" {}
                    "some tools or read-only"
                }
                span class="inline-flex items-center gap-1.5" {
                    span class="cell size-5 cursor-default" data-state="none" {}
                    "no grant"
                }
            }
        }
    }
}

/// Grants matrix, table and the add form, the swap target of `grants` actions.
#[allow(clippy::too_many_lines)]
pub(super) fn render_grants_section(overview: &AdminOverview, oob: bool) -> Markup {
    let manage = overview.access.manage_groups;

    html! {
        section id="admin-grants" class="card" hx-swap-oob=[oob.then_some("true")] {
            div class="card-h" { h2 id="grants" { "Grants" } }
            p class=(DESC) {
                "A grant lets a group use a backend's tools. Include and exclude are globs over the tool's original name."
            }
            (grants_matrix(overview))
            @if overview.grants.is_empty() {
                p class=(EMPTY) { "No grants yet." }
            } @else {
                div class="tbl-wrap mt-3 border-t border-border" tabindex="0" role="region" aria-label="Grants" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "Group" }
                                th { "Backend" }
                                th { "Include" }
                                th { "Exclude" }
                                th { "Read-only" }
                                th { "Mandatory" }
                                @if manage {
                                    th { "Actions" }
                                }
                            }
                        }
                        tbody {
                            @for view in &overview.grants {
                                tr {
                                    td class=(TD) { code class=(CODE) { (view.grant.group) } }
                                    td class=(TD) { code class=(CODE) { (view.grant.backend) } }
                                    td class=(TD) { (globs(&view.grant.include)) }
                                    td class=(TD) { (globs(&view.grant.exclude)) }
                                    td class=(TD) { (yes_no(view.grant.read_only)) }
                                    td class=(TD) { (yes_no(view.grant.mandatory)) }
                                    @if manage {
                                        td class=(TD) {
                                            @if let Some(id) = view.id {
                                                button
                                                    class=(BUTTON_DANGER)
                                                    type="button"
                                                    hx-post=(format!("/ui/actions/admin/grants/{id}/delete"))
                                                    hx-target="#admin-grants"
                                                    hx-swap="outerHTML"
                                                    hx-confirm="Delete this grant?"
                                                {
                                                    "Delete"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if manage {
                @if overview.backends.is_empty() {
                    p class=(EMPTY) { "No backends are configured, so there is nothing to grant." }
                } @else {
                    form
                        class=(FORM_FOOT)
                        hx-post="/ui/actions/admin/grants"
                        hx-target="#admin-grants"
                        hx-swap="outerHTML"
                    {
                        label class=(LABEL) {
                            "Group"
                            select class=(INPUT) name="group" required {
                                @for group in &overview.group_names {
                                    option value=(group) { (group) }
                                }
                            }
                        }
                        label class=(LABEL) {
                            "Backend"
                            select class=(INPUT) name="backend" required {
                                @for backend in &overview.backends {
                                    option value=(backend) { (backend) }
                                }
                            }
                        }
                        label class=(LABEL) {
                            "Include"
                            input class=(INPUT) type="text" name="include" placeholder="* (all tools)";
                        }
                        label class=(LABEL) {
                            "Exclude"
                            input class=(INPUT) type="text" name="exclude" placeholder="e.g. delete_*, drop_*";
                        }
                        label class="flex items-center gap-2 pb-2 text-sm text-text" {
                            input class="accent-accent" type="checkbox" name="read_only" value="true";
                            "Read-only"
                        }
                        label class="flex items-center gap-2 pb-2 text-sm text-text" {
                            input class="accent-accent" type="checkbox" name="mandatory" value="true";
                            "Mandatory"
                        }
                        button class=(BUTTON) type="submit" { "Add grant" }
                    }
                }
            }
        }
    }
}

/// Role bindings table and the add form, the swap target of `role-bindings`
/// actions.
#[allow(clippy::too_many_lines)]
pub(super) fn render_bindings_section(overview: &AdminOverview, oob: bool) -> Markup {
    let manage = overview.access.manage_roles;

    html! {
        section id="admin-bindings" class="card" hx-swap-oob=[oob.then_some("true")] {
            div class="card-h" { h2 id="role-bindings" { "Role bindings" } }
            p class=(DESC) {
                "A role binding gives a role to every member of a group, or to one user. "
                "A role you do not hold every permission of cannot be given away."
            }
            @if overview.bindings.is_empty() {
                p class=(EMPTY) { "No role bindings yet." }
            } @else {
                div class="tbl-wrap mt-3 border-t border-border" tabindex="0" role="region" aria-label="Role bindings" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "Role" }
                                th { "Subject" }
                                @if manage {
                                    th { "Actions" }
                                }
                            }
                        }
                        tbody {
                            @for binding in &overview.bindings {
                                tr {
                                    td class=(TD) {
                                        code class=(CODE) { (binding.role) }
                                        @if !overview.roles.iter().any(|role| role.name == binding.role) {
                                            " "
                                            span class="pill warn" { "unknown role" }
                                        }
                                    }
                                    td class=(TD) {
                                        @match &binding.subject {
                                            RoleSubject::Group(group) => {
                                                span class="text-muted" { "group " }
                                                code class=(CODE) { (group) }
                                            }
                                            RoleSubject::User(id) => {
                                                span class="text-muted" { "user " }
                                                (label_for(&overview.users, *id))
                                            }
                                        }
                                    }
                                    @if manage {
                                        td class=(TD) {
                                            @if let Some(id) = binding.id {
                                                button
                                                    class=(BUTTON_DANGER)
                                                    type="button"
                                                    hx-post=(format!("/ui/actions/admin/role-bindings/{id}/delete"))
                                                    hx-target="#admin-bindings"
                                                    hx-swap="outerHTML"
                                                    hx-confirm="Delete this role binding?"
                                                {
                                                    "Delete"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if manage {
                form
                    class=(FORM_FOOT)
                    hx-post="/ui/actions/admin/role-bindings"
                    hx-target="#admin-bindings"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Role"
                        select class=(INPUT) name="role" required {
                            @for role in &overview.roles {
                                option value=(role.name) { (role.name) }
                            }
                        }
                    }
                    label class=(LABEL) {
                        "Group"
                        select class=(INPUT) name="group" {
                            option value="" { "(none)" }
                            @for group in &overview.group_names {
                                option value=(group) { (group) }
                            }
                        }
                    }
                    label class=(LABEL) {
                        "or user"
                        select class=(INPUT) name="user_id" {
                            option value="" { "(none)" }
                            @for user in &overview.users {
                                option value=(user.id) { (user_label(user)) }
                            }
                        }
                    }
                    button class=(BUTTON) type="submit" { "Add role binding" }
                }
            }
        }
    }
}

/// Roles page (`GET /ui/admin/roles`).
pub(super) fn render_roles_page(state: &AppState, user: &SessionUser, page: &RolesPage) -> Markup {
    let content = html! {
        div class="page-head" {
            p {
                "A role is a named set of permissions, given to groups and users by role bindings. "
                "The built-in roles are fixed."
            }
        }
        (render_flash_area(false))
        (render_roles_section(page))
    };
    render_layout(state, user, "Roles", Nav::AdminRoles, &content)
}

/// One checkbox per permission, named `permissions`; the ones in `selected` start checked.
fn permission_checkboxes(selected: &[Permission]) -> Markup {
    html! {
        div class="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-2" {
            @for permission in Permission::ALL {
                label class="flex items-start gap-2 text-sm text-text" {
                    input
                        class="mt-1 accent-accent"
                        type="checkbox"
                        name="permissions"
                        value=(permission.as_str())
                        checked[selected.contains(&permission)];
                    span {
                        code class=(CODE) { (permission.as_str()) }
                        " "
                        span class="text-muted" { (permission.description()) }
                    }
                }
            }
        }
    }
}

/// Roles table with the edit, delete and create forms, the swap target of `roles`
/// actions.
#[allow(clippy::too_many_lines)]
pub(super) fn render_roles_section(page: &RolesPage) -> Markup {
    let manage = page.access.manage_roles;

    html! {
        section id="admin-roles" class="card" {
            div class="card-h" { h2 { "Roles" } }
            div class="tbl-wrap" tabindex="0" role="region" aria-label="Roles" {
                table class=(TABLE) {
                    thead {
                        tr {
                            th { "Name" }
                            th { "Source" }
                            th { "Description" }
                            th { "Permissions" }
                            th { "Bindings" }
                            @if manage {
                                th { "Actions" }
                            }
                        }
                    }
                    tbody {
                        @for entry in &page.roles {
                            @let role = &entry.role;
                            tr {
                                td class=(TD) { code class=(CODE) { (role.name) } }
                                td class=(TD) { (role_source_badge(role.source)) }
                                td class="whitespace-normal align-top" {
                                    @if let Some(description) = &role.description {
                                        (description)
                                    }
                                }
                                td class="min-w-64 whitespace-normal align-top" {
                                    div class="flex flex-wrap gap-1" {
                                        @for permission in &role.permissions {
                                            span class="pill mono" { (permission.as_str()) }
                                        }
                                    }
                                }
                                td class="align-top" {
                                    (entry.bindings)
                                    @if role.name == "admin" {
                                        @for provider in page.providers.iter().filter(|provider| !provider.admin_groups.is_empty()) {
                                            div class="text-xs text-muted" {
                                                "+ admin groups of " (provider.id) ": "
                                                (provider.admin_groups.join(", "))
                                            }
                                        }
                                    }
                                }
                                @if manage {
                                    td class="align-top" {
                                        @if role.source == RoleSource::Local {
                                            (render_role_actions(entry))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if manage {
                div class="card-b border-t border-border" {
                    h3 class="section-t" { "Create a role" }
                    form
                        class="mt-2"
                        hx-post="/ui/actions/admin/roles"
                        hx-target="#admin-roles"
                        hx-swap="outerHTML"
                    {
                        div class="flex flex-wrap items-end gap-3" {
                            label class=(LABEL) {
                                "Name"
                                input
                                    class=(INPUT)
                                    type="text"
                                    name="name"
                                    placeholder="e.g. log-reader"
                                    pattern="[a-z0-9][a-z0-9_\\-]{0,62}"
                                    required;
                            }
                            label class=(LABEL) {
                                "Description"
                                input class=(INPUT) type="text" name="description";
                            }
                        }
                        (permission_checkboxes(&[]))
                        button class=(format!("mt-4 {BUTTON}")) type="submit" { "Create role" }
                    }
                }
            }
        }
    }
}

/// Edit and delete forms of a database role.
fn render_role_actions(entry: &RoleEntry) -> Markup {
    let role = &entry.role;
    let name = &role.name;

    html! {
        details class="mb-2 whitespace-normal" {
            summary class="btn sm ghost w-fit" { "Edit" }
            form
                class="mt-2 min-w-80"
                hx-post=(format!("/ui/actions/admin/roles/{name}/update"))
                hx-target="#admin-roles"
                hx-swap="outerHTML"
            {
                label class=(LABEL) {
                    "Description"
                    input
                        class=(INPUT)
                        type="text"
                        name="description"
                        value=(role.description.as_deref().unwrap_or_default());
                }
                (permission_checkboxes(&role.permissions))
                button class=(format!("mt-3 {BUTTON_SMALL}")) type="submit" { "Save" }
            }
        }
        form
            class="flex items-center gap-2"
            hx-post=(format!("/ui/actions/admin/roles/{name}/delete"))
            hx-target="#admin-roles"
            hx-swap="outerHTML"
            hx-confirm=(format!("Delete the role {name}?"))
        {
            @if entry.bindings > 0 {
                label class="flex items-center gap-1 text-xs text-text" {
                    input class="accent-accent" type="checkbox" name="force" value="true";
                    "also delete its " (entry.bindings) " binding(s)"
                }
            }
            button class=(BUTTON_DANGER) type="submit" { "Delete" }
        }
    }
}

/// Group detail page (`GET /ui/admin/groups/{name}`).
pub(super) fn render_group_page(
    state: &AppState,
    user: &SessionUser,
    detail: &GroupDetail,
) -> Markup {
    let content = html! {
        div class="page-head" {
            p { "Description, IdP mappings and members of this group." }
        }
        (render_flash_area(false))
        (render_group_settings(detail))
        div class="cols" {
            (render_group_mappings(detail))
            (render_group_members(detail))
        }
    };
    render_layout(state, user, &detail.group.name, Nav::Admin, &content)
}

/// Description and delete button of a group.
pub(super) fn render_group_settings(detail: &GroupDetail) -> Markup {
    let name = &detail.group.name;

    html! {
        section id="group-settings" class="card" {
            div class="card-h" { h2 { "Description" } }
            @if detail.editable() {
                form
                    class="card-b flex flex-wrap items-end gap-3"
                    hx-post=(format!("/ui/actions/admin/groups/{name}/update"))
                    hx-target="#group-settings"
                    hx-swap="outerHTML"
                {
                    input
                        class=(format!("{INPUT} w-96 max-w-full"))
                        type="text"
                        name="description"
                        value=(detail.group.description.as_deref().unwrap_or_default());
                    button class=(BUTTON) type="submit" { "Save" }
                }
                div class="card-f" {
                    button
                        class=(BUTTON_DANGER)
                        type="button"
                        hx-post=(format!("/ui/actions/admin/groups/{name}/delete"))
                        hx-confirm=(format!("Delete the group {name}? Its mappings, members and grants go with it."))
                    {
                        "Delete group"
                    }
                }
            } @else {
                @if let Some(description) = &detail.group.description {
                    p class="card-b" { (description) }
                } @else {
                    p class=(EMPTY) { "No description." }
                }
            }
        }
    }
}

/// `IdP` mappings of a group, with the add form.
pub(super) fn render_group_mappings(detail: &GroupDetail) -> Markup {
    let name = &detail.group.name;
    let editable = detail.editable();

    html! {
        section id="group-mappings" class="card" {
            div class="card-h" { h2 { "IdP mappings" } }
            p class=(DESC) {
                "Users whose claim values at the login provider match a mapping are members."
            }
            @if detail.group.idp.is_empty() {
                p class=(EMPTY) { "No mappings." }
            } @else {
                ul class="list mt-3 border-t border-border" {
                    @for mapping in &detail.group.idp {
                        li class="row cursor-default" {
                            span class="row-main" {
                                span {
                                    code class=(CODE) { (mapping.provider) }
                                    ": "
                                    code class=(CODE) { (mapping.value) }
                                }
                            }
                            @if editable {
                                form
                                    hx-post=(format!("/ui/actions/admin/groups/{name}/idp-mappings/remove"))
                                    hx-target="#group-mappings"
                                    hx-swap="outerHTML"
                                {
                                    input type="hidden" name="provider" value=(mapping.provider);
                                    input type="hidden" name="value" value=(mapping.value);
                                    button class=(BUTTON_SMALL) type="submit" { "Remove" }
                                }
                            }
                        }
                    }
                }
            }
            @if editable {
                form
                    class=(FORM_FOOT)
                    hx-post=(format!("/ui/actions/admin/groups/{name}/idp-mappings/add"))
                    hx-target="#group-mappings"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Provider"
                        select class=(INPUT) name="provider" required {
                            @for provider in &detail.providers {
                                option value=(provider) { (provider) }
                            }
                        }
                    }
                    label class=(LABEL) {
                        "Claim value"
                        input class=(INPUT) type="text" name="value" required;
                    }
                    button class=(BUTTON) type="submit" { "Add mapping" }
                }
            }
        }
    }
}

/// Members added by hand to a group, with the add form.
pub(super) fn render_group_members(detail: &GroupDetail) -> Markup {
    let name = &detail.group.name;
    let editable = detail.editable();
    let candidates: Vec<&User> = detail
        .users
        .iter()
        .filter(|user| !detail.members.contains(&user.id))
        .collect();
    let account_candidates: Vec<&ServiceAccount> = detail
        .accounts
        .iter()
        .filter(|account| !detail.members.contains(&account.id))
        .collect();

    html! {
        section id="group-members" class="card" {
            div class="card-h" { h2 { "Members" } }
            p class=(DESC) { "Users added by hand, besides the IdP mappings." }
            @if detail.members.is_empty() {
                p class=(EMPTY) { "No members added by hand." }
            } @else {
                ul class="list mt-3 border-t border-border" {
                    @for id in &detail.members {
                        @let label = member_label(detail, *id);
                        li class="row cursor-default" {
                            span class="avatar" { (initials(&label)) }
                            span class="row-main" { (label) }
                            @if editable {
                                form
                                    hx-post=(format!("/ui/actions/admin/groups/{name}/members/remove"))
                                    hx-target="#group-members"
                                    hx-swap="outerHTML"
                                {
                                    input type="hidden" name="user_id" value=(id);
                                    button class=(BUTTON_SMALL) type="submit" { "Remove" }
                                }
                            }
                        }
                    }
                }
            }
            @if editable && !(candidates.is_empty() && account_candidates.is_empty()) {
                form
                    class=(FORM_FOOT)
                    hx-post=(format!("/ui/actions/admin/groups/{name}/members/add"))
                    hx-target="#group-members"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "User"
                        select class=(INPUT) name="user_id" required {
                            @for user in candidates {
                                option value=(user.id) { (user_label(user)) }
                            }
                            @for account in account_candidates {
                                option value=(account.id) { (account.name) " (service account)" }
                            }
                        }
                    }
                    button class=(BUTTON) type="submit" { "Add member" }
                }
            }
        }
    }
}

/// Users page (`GET /ui/admin/users`).
pub(super) fn render_users_page(state: &AppState, user: &SessionUser, page: &UsersPage) -> Markup {
    let content = html! {
        div class="page-head" {
            p { "Everyone who has signed in, and whether they may still log in." }
        }
        (render_flash_area(false))
        (render_users_section(page))
    };
    render_layout(state, user, "Users", Nav::AdminUsers, &content)
}

/// An issuer for comparing: a trailing slash does not make another one.
fn issuer_key(issuer: &str) -> &str {
    issuer.trim_end_matches('/')
}

/// The emails (lowercased) that appear under more than one issuer spelling; a
/// trailing slash counts, since it makes another user
fn duplicate_emails(users: &[ManagedUser]) -> Vec<String> {
    let mut seen: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for row in users {
        let email = row.user.email.as_deref().map(str::trim).unwrap_or_default();
        if !email.is_empty() {
            seen.entry(email.to_lowercase())
                .or_default()
                .insert(row.user.issuer.as_str());
        }
    }
    seen.into_iter()
        .filter(|(_, issuers)| issuers.len() > 1)
        .map(|(email, _)| email)
        .collect()
}

fn user_state_badge(disabled: bool) -> Markup {
    html! {
        @if disabled {
            span class="pill warn" { "disabled" }
        } @else {
            span class="pill ok" { "enabled" }
        }
    }
}

/// The users table, the swap target of the disable and enable actions.
pub(super) fn render_users_section(page: &UsersPage) -> Markup {
    let duplicates = duplicate_emails(&page.users);
    html! {
        section id="admin-users" class="card" {
            div class="card-h" { h2 { "Users" } }
            p class=(DESC) {
                "A disabled user cannot log in, their sessions end and their tokens stop working. "
                "Service accounts are on their own page."
            }
            @if !duplicates.is_empty() {
                div class="banner mx-3.5 mt-3" {
                    span class="text-warn" { (icon("triangle-alert")) }
                    div {
                        @if duplicates.len() == 1 {
                            "1 person appears"
                        } @else {
                            (duplicates.len()) " people appear"
                        }
                        " under more than one issuer. Users are identified by "
                        "issuer and subject, so a changed issuer spelling creates new, empty "
                        "users. Set the provider's issuer back to the old spelling, or disable "
                        "the stale rows."
                    }
                }
            }
            @if page.users.is_empty() {
                p class=(EMPTY) { "No users yet." }
            } @else {
                div class="tbl-wrap mt-3 border-t border-border" tabindex="0" role="region" aria-label="Users" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "User" }
                                th { "Issuer" }
                                th { "Last login" }
                                th { "Admin" }
                                th { "State" }
                                @if page.access.manage_users {
                                    th {}
                                }
                            }
                        }
                        tbody {
                            @for row in &page.users {
                                (render_user_row(page, row, &duplicates))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_user_row(page: &UsersPage, row: &ManagedUser, duplicates: &[String]) -> Markup {
    let user = &row.user;
    // Without any provider there is nothing to compare against, and `axon:`
    // issuers (the break-glass user) belong to no provider by design.
    let configured = page.providers.is_empty()
        || user.issuer.starts_with("axon:")
        || page
            .providers
            .iter()
            .any(|provider| issuer_key(&provider.issuer) == issuer_key(&user.issuer));
    let duplicate = user
        .email
        .as_deref()
        .is_some_and(|email| duplicates.contains(&email.trim().to_lowercase()));
    let (action, label, button) = if row.disabled {
        ("enable", "Enable", BUTTON_SMALL)
    } else {
        ("disable", "Disable", BUTTON_DANGER)
    };
    html! {
        tr {
            td class=(TD) {
                span class="inline-flex items-center gap-2" {
                    span class="avatar" { (initials(user_label(user))) }
                    (user_label(user))
                }
            }
            td class=(TD) {
                code class=(CODE) { (user.issuer) }
                @if !configured || duplicate {
                    div class="mt-1 flex flex-wrap gap-1" {
                        @if !configured {
                            span
                                class="pill warn"
                                title="No sign-in provider uses this issuer any more; this user cannot log in."
                            {
                                "issuer not configured"
                            }
                        }
                        @if duplicate {
                            span
                                class="pill warn"
                                title="The same email also appears under another issuer."
                            {
                                "duplicate"
                            }
                        }
                    }
                }
            }
            td class=(TD) {
                @if let Some(at) = row.last_login_at {
                    (at.format("%Y-%m-%d %H:%M UTC"))
                } @else {
                    span class="text-muted" { "-" }
                }
            }
            td class=(TD) {
                @if user.is_admin {
                    span class="pill accent" { "admin" }
                }
            }
            td class=(TD) { (user_state_badge(row.disabled)) }
            @if page.access.manage_users {
                td class=(TD) {
                    // Disabling yourself is refused, so the button is left out.
                    @if user.id != page.viewer || row.disabled {
                        button
                            class=(button)
                            type="button"
                            hx-post=(format!("/ui/actions/admin/users/{}/{action}", user.id))
                            hx-target="#admin-users"
                            hx-swap="outerHTML"
                        {
                            (label)
                        }
                    }
                }
            }
        }
    }
}

/// Audit log page (`GET /ui/admin/audit`), newest first. `before` is the
/// entry id this page starts below; `older` is the id for the next page, when
/// there is one.
pub(super) fn render_audit_page(
    state: &AppState,
    user: &SessionUser,
    entries: &[AuditRecord],
    before: Option<i64>,
    older: Option<i64>,
) -> Markup {
    let content = html! {
        div class="page-head" {
            p { "What was changed through the admin pages and by whom, newest first." }
        }
        section class="card" {
            div class="card-h" { h2 { "Audit log" } }
            @if entries.is_empty() {
                p class=(EMPTY) { "No entries." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Audit log" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "Time" }
                                th { "Actor" }
                                th { "Action" }
                                th { "Target" }
                                th { "Details" }
                            }
                        }
                        tbody {
                            @for entry in entries {
                                tr {
                                    td class=(TD) {
                                        (entry.at.format("%Y-%m-%d %H:%M:%S UTC"))
                                    }
                                    td class=(TD) { (entry.actor) }
                                    td class=(TD) { code class=(CODE) { (entry.action) } }
                                    td class=(TD) { code class=(CODE) { (entry.target) } }
                                    td class="min-w-64 whitespace-normal break-all" {
                                        @if !entry.details.is_null() {
                                            code class="mono text-muted" {
                                                (entry.details.to_string())
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if before.is_some() || older.is_some() {
                div class="card-f gap-2" {
                    @if before.is_some() {
                        a href="/ui/admin/audit" class=(LINK_BUTTON) { "Newest" }
                    }
                    @if let Some(id) = older {
                        a href=(format!("/ui/admin/audit?before={id}")) class=(LINK_BUTTON) { "Older" }
                    }
                }
            }
        }
    };
    render_layout(state, user, "Audit log", Nav::AdminAudit, &content)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::policy::{GrantSummary, IdpMapping};
    use crate::server::tests::test_state;
    use crate::server::views::render_ui_backend_detail_page;
    use crate::types::{BackendInfo, BackendState};

    fn session(is_admin: bool) -> SessionUser {
        SessionUser {
            user: User {
                id: Uuid::nil(),
                issuer: String::from("https://idp.example"),
                subject: String::from("sub-1"),
                email: Some(String::from("ada@example.com")),
                display_name: None,
                groups: Vec::new(),
                is_admin,
            },
            provider_id: String::from("pocket"),
            csrf_token: String::from("tok-123"),
        }
    }

    fn user(id: u128, email: &str) -> User {
        User {
            id: Uuid::from_u128(id),
            issuer: String::from("https://idp.example"),
            subject: format!("sub-{id}"),
            email: Some(email.to_owned()),
            display_name: None,
            groups: Vec::new(),
            is_admin: false,
        }
    }

    fn group(name: &str, description: Option<&str>) -> GroupView {
        GroupView {
            name: name.to_owned(),
            description: description.map(str::to_owned),
            idp: vec![IdpMapping {
                provider: String::from("pocket"),
                value: String::from("it-staff"),
            }],
        }
    }

    fn grant(id: i64, group: &str) -> GrantView {
        GrantView {
            id: Some(id),
            grant: GrantSummary {
                group: group.to_owned(),
                backend: String::from("files"),
                include: vec![String::from("*")],
                exclude: vec![String::from("delete_*")],
                read_only: false,
                mandatory: true,
            },
        }
    }

    fn role_view(name: &str, source: RoleSource, permissions: &[Permission]) -> RoleView {
        RoleView {
            name: name.to_owned(),
            description: Some(format!("<b>{name}</b>")),
            source,
            permissions: permissions.to_vec(),
        }
    }

    const FULL: Access = Access {
        manage_groups: true,
        manage_roles: true,
        manage_users: true,
    };

    const AUDITOR: Access = Access {
        manage_groups: false,
        manage_roles: false,
        manage_users: false,
    };

    fn overview(access: Access) -> AdminOverview {
        AdminOverview {
            access,
            groups: vec![
                GroupRow {
                    group: group("ops", Some("Operations")),
                    members: 0,
                },
                GroupRow {
                    group: group("devs", Some("<b>Developers</b>")),
                    members: 3,
                },
            ],
            grants: vec![grant(5, "ops"), grant(7, "devs")],
            bindings: vec![
                RoleBinding {
                    id: Some(8),
                    role: String::from("auditor"),
                    subject: RoleSubject::Group(String::from("ops")),
                },
                RoleBinding {
                    id: Some(9),
                    role: String::from("backend-admin"),
                    subject: RoleSubject::User(Uuid::from_u128(1)),
                },
            ],
            roles: vec![
                role_view("auditor", RoleSource::Builtin, &[Permission::AuditRead]),
                role_view(
                    "backend-admin",
                    RoleSource::Builtin,
                    &[Permission::BackendsView],
                ),
                role_view("log-reader", RoleSource::Local, &[Permission::AuditRead]),
            ],
            group_names: vec![
                String::from("authenticated"),
                String::from("ops"),
                String::from("devs"),
            ],
            backends: vec![String::from("files")],
            users: vec![user(1, "bob@example.com")],
        }
    }

    /// The page body without the shell, whose theme picker posts with htmx
    fn body(html: &str) -> String {
        html.split_once("<main class=\"content\">")
            .map_or_else(|| html.to_owned(), |(_, body)| body.to_owned())
    }

    fn page(overview: &AdminOverview) -> String {
        body(&render_admin_page(&test_state(), &session(true), overview).into_string())
    }

    #[tokio::test]
    async fn every_grant_and_binding_can_be_deleted() {
        let html = page(&overview(FULL));

        assert_eq!(html.matches("/delete\"").count(), 4);
        assert!(html.contains("/ui/actions/admin/grants/5/delete"));
        assert!(html.contains("/ui/actions/admin/grants/7/delete"));
        assert!(html.contains("/ui/actions/admin/role-bindings/8/delete"));
        assert!(html.contains("/ui/actions/admin/role-bindings/9/delete"));
        // Subjects are named by email when the user is known.
        assert!(html.contains("bob@example.com"));
        // Other pages link to the sections by these anchors.
        for anchor in ["groups", "grants", "role-bindings"] {
            assert!(html.contains(&format!("id=\"{anchor}\"")));
        }
    }

    #[tokio::test]
    async fn bindings_offer_custom_roles_and_flag_unknown_ones() {
        let mut overview = overview(FULL);
        overview.bindings.push(RoleBinding {
            id: Some(10),
            role: String::from("gone"),
            subject: RoleSubject::Group(String::from("ops")),
        });
        let html = page(&overview);

        assert!(html.contains("<option value=\"log-reader\">log-reader</option>"));
        assert_eq!(html.matches("unknown role").count(), 1);
    }

    fn roles_page(access: Access) -> RolesPage {
        let entry = |name, source, bindings| RoleEntry {
            role: role_view(name, source, &[Permission::AuditRead]),
            bindings,
        };
        RolesPage {
            access,
            roles: vec![
                entry("auditor", RoleSource::Builtin, 2),
                entry("log-reader", RoleSource::Local, 3),
            ],
            providers: Vec::new(),
        }
    }

    fn provider(id: &str, issuer: &str, admin_groups: &[&str]) -> ProviderInfo {
        ProviderInfo {
            id: id.to_owned(),
            issuer: issuer.to_owned(),
            admin_groups: admin_groups
                .iter()
                .map(|group| (*group).to_owned())
                .collect(),
        }
    }

    #[tokio::test]
    async fn the_admin_role_row_lists_the_admin_groups_of_the_providers() {
        let mut page = roles_page(AUDITOR);
        page.roles.push(RoleEntry {
            role: role_view("admin", RoleSource::Builtin, &[Permission::AuditRead]),
            bindings: 0,
        });
        let html = body(&render_roles_page(&test_state(), &session(false), &page).into_string());
        assert!(!html.contains("admin groups of"));

        page.providers = vec![
            provider("sso", "https://idp.example", &["axon-admins", "ops"]),
            provider("other", "https://other.example", &[]),
        ];
        let html = body(&render_roles_page(&test_state(), &session(false), &page).into_string());
        assert_eq!(html.matches("admin groups of").count(), 1);
        assert!(html.contains("+ admin groups of sso: axon-admins, ops"));
    }

    fn managed(id: u128, email: &str, issuer: &str) -> ManagedUser {
        let mut user = user(id, email);
        user.issuer = issuer.to_owned();
        ManagedUser {
            user,
            last_login_at: None,
            disabled: false,
        }
    }

    fn users_page(users: Vec<ManagedUser>, providers: Vec<ProviderInfo>) -> UsersPage {
        UsersPage {
            access: AUDITOR,
            viewer: Uuid::nil(),
            users,
            providers,
        }
    }

    #[tokio::test]
    async fn the_users_page_flags_an_issuer_no_provider_has() {
        let page = users_page(
            vec![
                managed(1, "bob@example.com", "https://idp.example"),
                managed(2, "eve@example.com", "https://gone.example"),
            ],
            // A trailing slash does not make another issuer.
            vec![provider("sso", "https://idp.example/", &[])],
        );
        let html = body(&render_users_page(&test_state(), &session(true), &page).into_string());

        assert_eq!(html.matches("issuer not configured").count(), 1);
        assert!(html.contains("this user cannot log in"));
        assert!(!html.contains("more than one issuer"));
    }

    #[tokio::test]
    async fn the_users_page_warns_about_one_email_under_two_issuers() {
        let page = users_page(
            vec![
                managed(1, "bob@example.com", "https://idp.example"),
                managed(2, "Bob@example.com", "https://idp.example/"),
                managed(3, "eve@example.com", "https://idp.example"),
            ],
            vec![provider("sso", "https://idp.example", &[])],
        );
        let html = body(&render_users_page(&test_state(), &session(true), &page).into_string());

        assert!(html.contains("1 person appears under more than one issuer"));
        assert_eq!(html.matches(">duplicate<").count(), 2);
        assert!(!html.contains("issuer not configured"));
    }

    #[tokio::test]
    async fn only_custom_roles_can_be_edited_or_deleted() {
        let html =
            render_roles_page(&test_state(), &session(true), &roles_page(FULL)).into_string();

        assert!(html.contains("/ui/actions/admin/roles/log-reader/update"));
        assert!(html.contains("/ui/actions/admin/roles/log-reader/delete"));
        assert!(!html.contains("/ui/actions/admin/roles/auditor/"));
        assert!(html.contains("hx-post=\"/ui/actions/admin/roles\""));
        assert!(html.contains("also delete its 3 binding(s)"));
        assert!(html.contains(">built-in<"));
        // The description is escaped.
        assert!(html.contains("&lt;b&gt;log-reader&lt;/b&gt;"));
        assert!(!html.contains("<b>log-reader</b>"));

        let html = body(
            &render_roles_page(&test_state(), &session(false), &roles_page(AUDITOR)).into_string(),
        );
        assert!(html.contains("log-reader"));
        assert!(!html.contains("hx-post"));
        assert!(!html.contains("name=\"permissions\""));
    }

    #[tokio::test]
    async fn a_group_page_without_the_permission_has_no_forms() {
        let detail = GroupDetail {
            access: AUDITOR,
            group: group("ops", None),
            members: Vec::new(),
            users: vec![user(1, "bob@example.com")],
            accounts: Vec::new(),
            providers: vec![String::from("pocket")],
        };
        let html = body(&render_group_page(&test_state(), &session(true), &detail).into_string());

        assert!(!html.contains("hx-post"));
    }

    #[tokio::test]
    async fn group_page_offers_edits() {
        let detail = GroupDetail {
            access: FULL,
            group: group("devs", None),
            members: vec![Uuid::from_u128(1)],
            users: vec![user(1, "bob@example.com"), user(2, "eve@example.com")],
            accounts: vec![ServiceAccount {
                id: Uuid::from_u128(3),
                name: String::from("ci-bot"),
                description: None,
                disabled: false,
                created_at: Utc::now(),
            }],
            providers: vec![String::from("pocket")],
        };
        let html = body(&render_group_page(&test_state(), &session(true), &detail).into_string());

        assert!(html.contains("/ui/actions/admin/groups/devs/update"));
        assert!(html.contains("/ui/actions/admin/groups/devs/delete"));
        assert!(html.contains("hx-confirm="));
        assert!(html.contains("/ui/actions/admin/groups/devs/idp-mappings/add"));
        assert!(html.contains("/ui/actions/admin/groups/devs/idp-mappings/remove"));
        assert!(html.contains("/ui/actions/admin/groups/devs/members/remove"));
        // Only users that are not members yet can be added.
        let add = html.find("members/add").expect("add form");
        assert!(html[add..].contains("eve@example.com"));
        // Service accounts can be members too, and are marked as such.
        assert!(html[add..].contains("ci-bot (service account)"));
        assert!(!html[add..].contains("<option value=\"00000000-0000-0000-0000-000000000001\">"));
    }

    #[tokio::test]
    async fn an_auditor_sees_tables_without_forms_or_buttons() {
        let html = page(&overview(AUDITOR));

        assert!(html.contains("Operations"));
        assert!(html.contains("files"));
        assert!(!html.contains("hx-post"));
        assert!(!html.contains("<select"));
        assert!(!html.contains("Actions"));
    }

    #[tokio::test]
    async fn names_and_descriptions_are_escaped() {
        let mut overview = overview(FULL);
        overview.groups.push(GroupRow {
            group: GroupView {
                name: String::from("<i>x</i>"),
                description: Some(String::from("<script>alert(1)</script>")),
                idp: vec![IdpMapping {
                    provider: String::from("pocket"),
                    value: String::from("\"><img src=x>"),
                }],
            },
            members: 0,
        });
        let html = page(&overview);

        assert!(html.contains("&lt;b&gt;Developers&lt;/b&gt;"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;i&gt;x&lt;/i&gt;"));
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("<b>Developers</b>"));
    }

    fn entry(id: i64) -> AuditRecord {
        AuditRecord {
            id,
            at: Utc::now(),
            actor_user_id: None,
            actor: String::from("<root>"),
            action: String::from("group.create"),
            target: String::from("devs"),
            details: json!({ "description": "Developers" }),
        }
    }

    #[tokio::test]
    async fn audit_page_links_to_older_entries() {
        let entries = [entry(12), entry(11)];
        let state = test_state();
        let user = session(true);

        let html = render_audit_page(&state, &user, &entries, None, Some(11)).into_string();
        assert!(html.contains("href=\"/ui/admin/audit?before=11\""));
        assert!(!html.contains("Newest"));
        assert!(html.contains("&lt;root&gt;"));
        assert!(html.contains("group.create"));
        assert!(html.contains("{&quot;description&quot;:&quot;Developers&quot;}"));

        let html = render_audit_page(&state, &user, &entries, Some(20), None).into_string();
        assert!(!html.contains("Older"));
        assert!(html.contains("Newest"));
    }

    #[tokio::test]
    async fn user_bar_links_to_admin_only_with_a_permission() {
        let backend = BackendInfo::new(
            String::from("filesystem"),
            BackendState::Connected,
            Vec::new(),
            None,
        );
        let render = |user: &SessionUser| {
            render_ui_backend_detail_page(&backend, &[], &[], &test_state(), Some(user))
                .into_string()
        };

        assert!(render(&session(true)).contains("href=\"/ui/admin\""));
        assert!(!render(&session(false)).contains("/ui/admin"));
    }
}
