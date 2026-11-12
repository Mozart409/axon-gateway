//! HTML rendering (maud) for the admin pages: groups, grants, roles, role
//! bindings, users and the audit log.
//!
//! Like `views`, these are pure view functions. The page handlers and the
//! htmx actions live in `admin_ui`; every section here is also the fragment an
//! action answers with (`hx-target` the section's id, `hx-swap="outerHTML"`).
//! Forms and buttons only render for users who hold the permission, the
//! service layer in `rbac` still decides.

use maud::{DOCTYPE, Markup, PreEscaped, html};
use uuid::Uuid;

use super::AppState;
use super::views::{build_fingerprint, csrf_hx_headers, render_user_bar};
use crate::policy::{
    GrantView, GroupView, Permission, Permissions, RoleBinding, RoleSource, RoleSubject, RoleView,
};
use crate::rbac::{ManagedUser, RoleEntry};
use crate::store::{AuditRecord, ServiceAccount, SessionUser, User};

/// Admin actions answer errors with 4xx/5xx and a flash fragment; htmx drops
/// those responses unless told to swap them.
const HTMX_CONFIG: &str = r#"{"includeIndicatorStyles":false,"allowEval":false,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"[45]..","swap":true,"error":true}]}"#;

pub(super) const CARD: &str = "mb-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900";
pub(super) const HEADING: &str = "text-lg font-semibold text-slate-900 dark:text-slate-100";
pub(super) const MUTED: &str = "text-sm text-slate-600 dark:text-slate-300";
pub(super) const FAINT: &str = "text-slate-500 dark:text-slate-400";
pub(super) const TABLE_WRAP: &str =
    "mt-4 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800";
pub(super) const TABLE: &str = "min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800";
pub(super) const THEAD: &str = "bg-slate-50 dark:bg-slate-800/80";
pub(super) const TBODY: &str =
    "divide-y divide-slate-100 bg-white dark:divide-slate-800 dark:bg-slate-900";
pub(super) const TH: &str = "px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300";
pub(super) const TD: &str = "px-4 py-3 align-top text-slate-700 dark:text-slate-200";
pub(super) const CODE: &str = "text-slate-900 dark:text-slate-100";
pub(super) const FORM_ROW: &str = "mt-4 flex flex-wrap items-end gap-3";
pub(super) const LABEL: &str =
    "flex flex-col gap-1 text-xs font-medium text-slate-600 dark:text-slate-300";
pub(super) const INPUT: &str = "rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100";
pub(super) const BUTTON: &str = "rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300";
pub(super) const BUTTON_SMALL: &str = "rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800";
pub(super) const BUTTON_DANGER: &str = "rounded-md border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50 dark:border-red-900 dark:text-red-300 dark:hover:bg-red-950/40";
pub(super) const LINK: &str = "font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100";
pub(super) const BACK_LINK: &str = "inline-flex items-center text-sm font-medium text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-slate-100";

/// What the signed-in user may do on the admin pages
#[derive(Debug, Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per permission the pages check"
)]
pub(super) struct Access {
    /// Create and edit groups and grants (`groups.manage`)
    pub manage_groups: bool,
    /// Edit role bindings (`roles.manage`)
    pub manage_roles: bool,
    /// Read the audit log (`audit.read`)
    pub read_audit: bool,
    /// Manage service accounts and their tokens (`service_accounts.manage`)
    pub manage_service_accounts: bool,
    /// Disable and re-enable users (`users.manage`)
    pub manage_users: bool,
}

impl Access {
    pub(super) fn of(permissions: &Permissions) -> Self {
        Self {
            manage_groups: permissions.has(Permission::GroupsManage),
            manage_roles: permissions.has(Permission::RolesManage),
            read_audit: permissions.has(Permission::AuditRead),
            manage_service_accounts: permissions.has(Permission::ServiceAccountsManage),
            manage_users: permissions.has(Permission::UsersManage),
        }
    }
}

/// Everything `/ui/admin/users` shows
pub(super) struct UsersPage {
    pub access: Access,
    /// The signed-in user, who cannot disable themselves
    pub viewer: Uuid,
    pub users: Vec<ManagedUser>,
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
            span class="rounded-full bg-sky-100 px-2 py-0.5 text-xs font-semibold text-sky-800 dark:bg-sky-900/40 dark:text-sky-300" {
                "built-in"
            }
        },
        RoleSource::Local => html! {
            span class="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300" {
                "local"
            }
        },
    }
}

/// Where action errors show: the target of their `HX-Retarget`. Successful
/// actions send it again as an out-of-band swap to clear an old error.
pub(super) fn render_flash_area(oob: bool) -> Markup {
    html! {
        div id="admin-flash" class="mb-4" hx-swap-oob=[oob.then_some("true")] {}
    }
}

/// Page frame of the admin pages: head, user bar, content and footer.
pub(super) fn render_layout(
    state: &AppState,
    user: &SessionUser,
    title: &str,
    content: &Markup,
) -> Markup {
    let hx_headers = csrf_hx_headers(user);

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                meta name="csrf-token" content=(user.csrf_token);
                meta name="htmx-config" content=(HTMX_CONFIG);
                script src="/static/htmx-2.0.4.min.js" defer {};
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" hx-headers=(hx_headers) {
                main class="mx-auto max-w-6xl p-6" {
                    (render_user_bar(state, user))
                    (content)
                    footer class="mt-6 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                        (build_fingerprint(state))
                    }
                }
            }
        }
    }
}

/// The page for a user who may not see an admin page (answered with 403).
pub(super) fn render_forbidden_page(state: &AppState, user: &SessionUser) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Not allowed"
            }
            p class=(format!("mt-2 {MUTED}")) {
                "You do not have the permission to view this page."
            }
        }
    };
    render_layout(state, user, "Not allowed", &content)
}

/// Admin overview (`GET /ui/admin`).
pub(super) fn render_admin_page(
    state: &AppState,
    user: &SessionUser,
    overview: &AdminOverview,
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Admin"
            }
            p class=(format!("mt-2 {MUTED}")) {
                "Groups, grants and role bindings."
            }
            @if overview.access.read_audit {
                p class="mt-3 text-sm" {
                    a href="/ui/admin/audit" class=(LINK) { "Audit log" }
                }
                p class="mt-3 text-sm" {
                    a href="/ui/admin/tool-calls" class=(LINK) { "Tool calls" }
                }
                p class="mt-3 text-sm" {
                    a href="/ui/admin/usage" class=(LINK) { "Usage" }
                }
                p class="mt-3 text-sm" {
                    a href="/ui/admin/audit-settings" class=(LINK) { "Audit settings" }
                }
            }
            @if overview.access.manage_users {
                p class="mt-3 text-sm" {
                    a href="/ui/admin/users" class=(LINK) { "Users" }
                }
                @if overview.access.manage_groups {
                    p class="mt-3 text-sm" {
                        a href="/ui/admin/scim" class=(LINK) { "SCIM provisioning" }
                    }
                }
                @if state.personal.is_some() {
                    p class="mt-3 text-sm" {
                        a href="/ui/admin/personal-backends" class=(LINK) { "Personal MCP servers" }
                    }
                }
            }
            @if overview.access.manage_service_accounts {
                p class="mt-3 text-sm" {
                    a href="/ui/admin/service-accounts" class=(LINK) { "Service accounts" }
                }
            }
            p class="mt-3 text-sm" {
                a href="/ui/admin/roles" class=(LINK) { "Roles" }
            }
            @if state.db_config.is_some() {
                p class="mt-3 text-sm" {
                    a href="/ui/admin/config/backends" class=(LINK) { "Backends" }
                    " / "
                    a href="/ui/admin/config/toolsets" class=(LINK) { "Toolsets" }
                    " / "
                    a href="/ui/admin/config/oidc-providers" class=(LINK) { "OIDC providers" }
                    " / "
                    a href="/ui/admin/config/settings" class=(LINK) { "Gateway settings" }
                }
            }
        }
        (render_flash_area(false))
        (render_groups_section(overview, false))
        (render_grants_section(overview, false))
        (render_bindings_section(overview, false))
    };
    render_layout(state, user, "Admin", &content)
}

/// Groups table and the create form, the swap target of `groups` actions.
/// `oob` renders it as an out-of-band swap next to another fragment.
pub(super) fn render_groups_section(overview: &AdminOverview, oob: bool) -> Markup {
    html! {
        section id="admin-groups" class=(CARD) hx-swap-oob=[oob.then_some("true")] {
            h2 class=(HEADING) { "Groups" }
            p class=(format!("mt-1 {MUTED}")) {
                "Users join a group through an IdP mapping or by being added by hand. "
                "Everyone is also in the built-in authenticated group."
            }
            @if overview.groups.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No groups yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Name" }
                                th class=(TH) { "Description" }
                                th class=(TH) { "IdP mappings" }
                                th class=(TH) { "Members" }
                            }
                        }
                        tbody class=(TBODY) {
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
                    class=(FORM_ROW)
                    hx-post="/ui/actions/admin/groups"
                    hx-target="#admin-groups"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Name"
                        input class=(INPUT) type="text" name="name" placeholder="it" required;
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
            span class=(FAINT) { "-" }
        } @else {
            code class=(CODE) { (patterns.join(", ")) }
        }
    }
}

fn yes_no(value: bool) -> Markup {
    html! {
        @if value {
            "yes"
        } @else {
            span class=(FAINT) { "no" }
        }
    }
}

/// Grants table and the add form, the swap target of `grants` actions.
#[allow(clippy::too_many_lines)]
pub(super) fn render_grants_section(overview: &AdminOverview, oob: bool) -> Markup {
    let manage = overview.access.manage_groups;

    html! {
        section id="admin-grants" class=(CARD) hx-swap-oob=[oob.then_some("true")] {
            h2 class=(HEADING) { "Grants" }
            p class=(format!("mt-1 {MUTED}")) {
                "A grant lets a group use a backend's tools. Include and exclude are globs over the tool's original name."
            }
            @if overview.grants.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No grants yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Group" }
                                th class=(TH) { "Backend" }
                                th class=(TH) { "Include" }
                                th class=(TH) { "Exclude" }
                                th class=(TH) { "Read-only" }
                                th class=(TH) { "Mandatory" }
                                @if manage {
                                    th class=(TH) { "Actions" }
                                }
                            }
                        }
                        tbody class=(TBODY) {
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
                    p class=(format!("mt-4 text-sm {FAINT}")) { "No backends are configured, so there is nothing to grant." }
                } @else {
                    form
                        class=(FORM_ROW)
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
                            input class=(INPUT) type="text" name="exclude" placeholder="delete_*, drop_*";
                        }
                        label class="flex items-center gap-2 pb-2 text-sm text-slate-700 dark:text-slate-200" {
                            input type="checkbox" name="read_only" value="true";
                            "Read-only"
                        }
                        label class="flex items-center gap-2 pb-2 text-sm text-slate-700 dark:text-slate-200" {
                            input type="checkbox" name="mandatory" value="true";
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
        section id="admin-bindings" class=(CARD) hx-swap-oob=[oob.then_some("true")] {
            h2 class=(HEADING) { "Role bindings" }
            p class=(format!("mt-1 {MUTED}")) {
                "A role binding gives a role to every member of a group, or to one user. "
                "A role you do not hold every permission of cannot be given away."
            }
            @if overview.bindings.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No role bindings yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Role" }
                                th class=(TH) { "Subject" }
                                @if manage {
                                    th class=(TH) { "Actions" }
                                }
                            }
                        }
                        tbody class=(TBODY) {
                            @for binding in &overview.bindings {
                                tr {
                                    td class=(TD) {
                                        code class=(CODE) { (binding.role) }
                                        @if !overview.roles.iter().any(|role| role.name == binding.role) {
                                            " "
                                            span class="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300" {
                                                "unknown role"
                                            }
                                        }
                                    }
                                    td class=(TD) {
                                        @match &binding.subject {
                                            RoleSubject::Group(group) => {
                                                "group "
                                                code class=(CODE) { (group) }
                                            }
                                            RoleSubject::User(id) => {
                                                "user "
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
                    class=(FORM_ROW)
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
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Roles"
            }
            p class=(format!("mt-2 {MUTED}")) {
                "A role is a named set of permissions, given to groups and users by role bindings. "
                "The built-in roles are fixed."
            }
        }
        (render_flash_area(false))
        (render_roles_section(page))
    };
    render_layout(state, user, "Roles", &content)
}

/// One checkbox per permission, named `permissions`; the ones in `selected` start checked.
fn permission_checkboxes(selected: &[Permission]) -> Markup {
    html! {
        div class="mt-2 grid gap-x-6 gap-y-1 sm:grid-cols-2" {
            @for permission in Permission::ALL {
                label class="flex items-start gap-2 text-sm text-slate-700 dark:text-slate-200" {
                    input
                        class="mt-1"
                        type="checkbox"
                        name="permissions"
                        value=(permission.as_str())
                        checked[selected.contains(&permission)];
                    span {
                        code class=(CODE) { (permission.as_str()) }
                        " "
                        span class=(FAINT) { (permission.description()) }
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
        section id="admin-roles" class=(CARD) {
            h2 class=(HEADING) { "Roles" }
            div class=(TABLE_WRAP) {
                table class=(TABLE) {
                    thead class=(THEAD) {
                        tr {
                            th class=(TH) { "Name" }
                            th class=(TH) { "Source" }
                            th class=(TH) { "Description" }
                            th class=(TH) { "Permissions" }
                            th class=(TH) { "Bindings" }
                            @if manage {
                                th class=(TH) { "Actions" }
                            }
                        }
                    }
                    tbody class=(TBODY) {
                        @for entry in &page.roles {
                            @let role = &entry.role;
                            tr {
                                td class=(TD) { code class=(CODE) { (role.name) } }
                                td class=(TD) { (role_source_badge(role.source)) }
                                td class=(TD) {
                                    @if let Some(description) = &role.description {
                                        (description)
                                    }
                                }
                                td class=(TD) {
                                    @for permission in &role.permissions {
                                        div { code class=(CODE) { (permission.as_str()) } }
                                    }
                                }
                                td class=(TD) { (entry.bindings) }
                                @if manage {
                                    td class=(TD) {
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
                h3 class="mt-6 text-sm font-semibold text-slate-900 dark:text-slate-100" {
                    "Create a role"
                }
                form
                    class="mt-2"
                    hx-post="/ui/actions/admin/roles"
                    hx-target="#admin-roles"
                    hx-swap="outerHTML"
                {
                    div class=(FORM_ROW) {
                        label class=(LABEL) {
                            "Name"
                            input
                                class=(INPUT)
                                type="text"
                                name="name"
                                placeholder="log-reader"
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

/// Edit and delete forms of a database role.
fn render_role_actions(entry: &RoleEntry) -> Markup {
    let role = &entry.role;
    let name = &role.name;

    html! {
        details class="mb-2" {
            summary class="cursor-pointer text-xs text-slate-700 dark:text-slate-200" { "Edit" }
            form
                class="mt-2"
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
                label class="flex items-center gap-1 text-xs text-slate-700 dark:text-slate-200" {
                    input type="checkbox" name="force" value="true";
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
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                (detail.group.name)
            }
        }
        (render_flash_area(false))
        (render_group_settings(detail))
        (render_group_mappings(detail))
        (render_group_members(detail))
    };
    render_layout(state, user, &detail.group.name, &content)
}

/// Description and delete button of a group.
pub(super) fn render_group_settings(detail: &GroupDetail) -> Markup {
    let name = &detail.group.name;

    html! {
        section id="group-settings" class=(CARD) {
            h2 class=(HEADING) { "Description" }
            @if detail.editable() {
                form
                    class=(FORM_ROW)
                    hx-post=(format!("/ui/actions/admin/groups/{name}/update"))
                    hx-target="#group-settings"
                    hx-swap="outerHTML"
                {
                    input
                        class=(format!("{INPUT} w-96"))
                        type="text"
                        name="description"
                        value=(detail.group.description.as_deref().unwrap_or_default());
                    button class=(BUTTON) type="submit" { "Save" }
                }
                div class="mt-4" {
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
                    p class=(format!("mt-2 {MUTED}")) { (description) }
                } @else {
                    p class=(format!("mt-2 text-sm {FAINT}")) { "No description." }
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
        section id="group-mappings" class=(CARD) {
            h2 class=(HEADING) { "IdP mappings" }
            p class=(format!("mt-1 {MUTED}")) {
                "Users whose claim values at the login provider match a mapping are members."
            }
            @if detail.group.idp.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No mappings." }
            } @else {
                ul class="mt-4 space-y-2 text-sm" {
                    @for mapping in &detail.group.idp {
                        li class="flex items-center gap-3" {
                            span {
                                code class=(CODE) { (mapping.provider) }
                                ": "
                                code class=(CODE) { (mapping.value) }
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
                    class=(FORM_ROW)
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
        section id="group-members" class=(CARD) {
            h2 class=(HEADING) { "Members" }
            p class=(format!("mt-1 {MUTED}")) { "Users added by hand, besides the IdP mappings." }
            @if detail.members.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No members added by hand." }
            } @else {
                ul class="mt-4 space-y-2 text-sm" {
                    @for id in &detail.members {
                        li class="flex items-center gap-3" {
                            span { (member_label(detail, *id)) }
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
                    class=(FORM_ROW)
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
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Users"
            }
        }
        (render_flash_area(false))
        (render_users_section(page))
    };
    render_layout(state, user, "Users", &content)
}

fn user_state_badge(disabled: bool) -> Markup {
    html! {
        @if disabled {
            span class="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300" {
                "disabled"
            }
        } @else {
            span class="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300" {
                "enabled"
            }
        }
    }
}

/// The users table, the swap target of the disable and enable actions.
pub(super) fn render_users_section(page: &UsersPage) -> Markup {
    html! {
        section id="admin-users" class=(CARD) {
            h2 class=(HEADING) { "Users" }
            p class=(format!("mt-1 {MUTED}")) {
                "A disabled user cannot log in, their sessions end and their tokens stop working. "
                "Service accounts are on their own page."
            }
            @if page.users.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No users yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "User" }
                                th class=(TH) { "Issuer" }
                                th class=(TH) { "Last login" }
                                th class=(TH) { "Admin" }
                                th class=(TH) { "State" }
                                @if page.access.manage_users {
                                    th class=(TH) {}
                                }
                            }
                        }
                        tbody class=(TBODY) {
                            @for row in &page.users {
                                (render_user_row(page, row))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_user_row(page: &UsersPage, row: &ManagedUser) -> Markup {
    let user = &row.user;
    let (action, label) = if row.disabled {
        ("enable", "Enable")
    } else {
        ("disable", "Disable")
    };
    html! {
        tr {
            td class=(TD) { (user_label(user)) }
            td class=(TD) { code class=(CODE) { (user.issuer) } }
            td class=(format!("{TD} whitespace-nowrap")) {
                @if let Some(at) = row.last_login_at {
                    (at.format("%Y-%m-%d %H:%M UTC"))
                } @else {
                    span class=(FAINT) { "-" }
                }
            }
            td class=(TD) {
                @if user.is_admin {
                    span class="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300" {
                        "admin"
                    }
                }
            }
            td class=(TD) { (user_state_badge(row.disabled)) }
            @if page.access.manage_users {
                td class=(TD) {
                    // Disabling yourself is refused, so the button is left out.
                    @if user.id != page.viewer || row.disabled {
                        button
                            class=(BUTTON_SMALL)
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
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Audit log"
            }
            @if entries.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No entries." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Time" }
                                th class=(TH) { "Actor" }
                                th class=(TH) { "Action" }
                                th class=(TH) { "Target" }
                                th class=(TH) { "Details" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for entry in entries {
                                tr {
                                    td class=(format!("{TD} whitespace-nowrap")) {
                                        (entry.at.format("%Y-%m-%d %H:%M:%S UTC"))
                                    }
                                    td class=(TD) { (entry.actor) }
                                    td class=(TD) { code class=(CODE) { (entry.action) } }
                                    td class=(TD) { code class=(CODE) { (entry.target) } }
                                    td class=(format!("{TD} break-all")) {
                                        @if !entry.details.is_null() {
                                            code class="text-xs text-slate-600 dark:text-slate-300" {
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
            div class="mt-4 flex gap-4 text-sm" {
                @if before.is_some() {
                    a href="/ui/admin/audit" class=(LINK) { "Newest" }
                }
                @if let Some(id) = older {
                    a href=(format!("/ui/admin/audit?before={id}")) class=(LINK) { "Older" }
                }
            }
        }
    };
    render_layout(state, user, "Audit log", &content)
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
        read_audit: true,
        manage_service_accounts: true,
        manage_users: true,
    };

    const AUDITOR: Access = Access {
        manage_groups: false,
        manage_roles: false,
        read_audit: true,
        manage_service_accounts: false,
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

    fn page(overview: &AdminOverview) -> String {
        render_admin_page(&test_state(), &session(true), overview).into_string()
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
        assert!(html.contains("href=\"/ui/admin/roles\""));
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
        }
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

        let html =
            render_roles_page(&test_state(), &session(false), &roles_page(AUDITOR)).into_string();
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
        let html = render_group_page(&test_state(), &session(true), &detail).into_string();

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
        let html = render_group_page(&test_state(), &session(true), &detail).into_string();

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
        assert!(html.contains("href=\"/ui/admin/audit\""));
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
