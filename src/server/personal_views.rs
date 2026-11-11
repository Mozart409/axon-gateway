//! HTML rendering (maud) for the personal MCP server pages: a user's own servers
//! (`/ui/me/backends`), the catalog with the user's credentials and its admin
//! (`/ui/catalog`) and the admin's overview of everybody's personal servers
//! (`/ui/admin/personal-backends`).
//!
//! Like `tokens_views`, these are pure view functions and every section is also
//! the fragment an action answers with (`hx-target` the section's id,
//! `hx-swap="outerHTML"`). A header value or a credential value is never
//! rendered: the lists show header names and whether a credential is set, and
//! the forms that take values start empty.

use chrono::{DateTime, Utc};
use maud::{Markup, PreEscaped, html};

use super::AppState;
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, BUTTON_SMALL, CARD, CODE, FAINT, FORM_ROW, HEADING, INPUT,
    LABEL, MUTED, TABLE, TABLE_WRAP, TBODY, TD, TH, THEAD, render_flash_area, render_layout,
};
use super::personal_api::{CatalogView, PersonalSaved};
use crate::config::CredentialField;
use crate::personal::CatalogSource;
use crate::store::{AdminPersonalBackend, PersonalBackend, SessionUser};

const BACKENDS: &str = "#my-backends";
const CATALOG: &str = "#catalog";
const ADMIN_PERSONAL: &str = "#admin-personal";

/// Empty header rows on the add and replace forms
const HEADER_ROWS: usize = 4;
/// Empty credential field rows on the catalog create form
const FIELD_ROWS: usize = 3;

const FORM_COL: &str = "mt-4 flex flex-col items-start gap-3";
const SUBHEADING: &str = "text-base font-semibold text-slate-900 dark:text-slate-100";
const DIVIDER: &str = "mt-6 border-t border-slate-200 pt-4 dark:border-slate-800";
const BADGE_OK: &str = "rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300";
const BADGE_WARN: &str = "rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300";
const BADGE_OFF: &str = "rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300";

fn when(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// Email, else display name, else subject
fn owner_label(backend: &AdminPersonalBackend) -> &str {
    [
        backend.owner_email.as_deref(),
        backend.owner_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .find(|label| !label.trim().is_empty())
    .unwrap_or(&backend.owner_subject)
}

fn enabled_badge(enabled: bool) -> Markup {
    html! {
        @if enabled {
            span class=(BADGE_OK) { "enabled" }
        } @else {
            span class=(BADGE_OFF) { "disabled" }
        }
    }
}

/// How the last connection went: an error when the newest outcome is one,
/// else the time of the last success
fn status_cell(
    last_ok_at: Option<DateTime<Utc>>,
    last_error_at: Option<DateTime<Utc>>,
    last_error: Option<&str>,
) -> Markup {
    html! {
        @if let Some(failed_at) = last_error_at.filter(|failed| last_ok_at.is_none_or(|ok| failed >= &ok)) {
            span class=(BADGE_WARN) { "error" }
            " "
            span class=(FAINT) { (when(failed_at)) }
            @if let Some(message) = last_error {
                div class=(format!("mt-1 break-words {MUTED}")) { (message) }
            }
        } @else if let Some(ok_at) = last_ok_at {
            span class=(BADGE_OK) { "ok" }
            " "
            span class=(FAINT) { (when(ok_at)) }
        } @else {
            span class=(FAINT) { "not tested" }
        }
    }
}

/// A button that posts a switch of `enabled` to `path`
fn enabled_toggle(path: &str, target: &str, enabled: bool) -> Markup {
    html! {
        form hx-post=(path) hx-target=(target) hx-swap="outerHTML" {
            input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
            button class=(BUTTON_SMALL) type="submit" {
                @if enabled {
                    "Disable"
                } @else {
                    "Enable"
                }
            }
        }
    }
}

/// Empty rows of a header name and a password-type value; the keys repeat
fn header_rows() -> Markup {
    html! {
        div class="flex flex-col gap-2" {
            @for _ in 0..HEADER_ROWS {
                div class="flex flex-wrap gap-2" {
                    input
                        class=(format!("{INPUT} w-48"))
                        type="text"
                        name="header_name"
                        placeholder="Authorization"
                        autocomplete="off";
                    input
                        class=(format!("{INPUT} w-72"))
                        type="password"
                        name="header_value"
                        placeholder="value"
                        autocomplete="new-password";
                }
            }
        }
    }
}

/// The result of saving a server, shown once in the response of the action
fn render_saved(saved: &PersonalSaved) -> Markup {
    let (classes, text) = match &saved.test {
        Some(Ok(tools)) => (
            "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200",
            format!("Connection test: {tools} tools."),
        ),
        Some(Err(error)) => (
            "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200",
            format!("Connection test failed: {error}"),
        ),
        None => (
            "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-200",
            String::from("Not tested."),
        ),
    };
    html! {
        div class=(format!("mt-4 rounded-lg border p-4 text-sm {classes}")) role="status" {
            p class="font-semibold" {
                "Saved " code { (saved.backend.prefix) }
            }
            p class="mt-1 break-words" { (text) }
        }
    }
}

/// One of the user's servers: the overview cells and the edit forms
fn render_backend_row(backend: &PersonalBackend) -> Markup {
    let base = format!("/ui/actions/me/backends/{}", backend.prefix);
    html! {
        tr {
            td class=(TD) { code class=(CODE) { (backend.prefix) } }
            td class=(TD) { span class="break-all" { (backend.url) } }
            td class=(TD) {
                @if backend.header_names.is_empty() {
                    span class=(FAINT) { "none" }
                }
                @for name in &backend.header_names {
                    div { code class=(CODE) { (name) } }
                }
            }
            td class=(TD) { (enabled_badge(backend.enabled)) }
            td class=(TD) {
                (status_cell(backend.last_ok_at, backend.last_error_at, backend.last_error.as_deref()))
            }
            td class=(TD) {
                div class="flex flex-wrap items-start gap-2" {
                    (enabled_toggle(&format!("{base}/enabled"), BACKENDS, backend.enabled))
                    button
                        class=(BUTTON_DANGER)
                        type="button"
                        hx-post=(format!("{base}/delete"))
                        hx-target=(BACKENDS)
                        hx-swap="outerHTML"
                        hx-confirm=(format!("Delete the server {}? Its tools disappear from your session.", backend.prefix))
                    {
                        "Delete"
                    }
                }
                details class="mt-2" {
                    summary class="cursor-pointer text-xs text-slate-600 dark:text-slate-300" { "Edit" }
                    form class=(FORM_COL) hx-post=(format!("{base}/update")) hx-target=(BACKENDS) hx-swap="outerHTML" {
                        label class=(LABEL) {
                            "URL"
                            input
                                class=(format!("{INPUT} w-72"))
                                type="url"
                                name="url"
                                value=(backend.url)
                                required;
                        }
                        button class=(BUTTON_SMALL) type="submit" { "Save URL" }
                    }
                    form class=(FORM_COL) hx-post=(format!("{base}/headers")) hx-target=(BACKENDS) hx-swap="outerHTML" {
                        p class=(MUTED) {
                            "Saving replaces all headers of this server: enter every header it needs, "
                            "not only the ones that change. Saving no header removes them all."
                        }
                        (header_rows())
                        button class=(BUTTON_SMALL) type="submit" { "Replace headers" }
                    }
                }
            }
        }
    }
}

/// A user's own servers and the add form, the swap target of the `me/backends`
/// actions. `saved` is the server an action just saved, with its test result.
pub(super) fn render_backends_section(
    backends: &[PersonalBackend],
    saved: Option<&PersonalSaved>,
) -> Markup {
    html! {
        section id="my-backends" class=(CARD) {
            h2 class=(HEADING) { "My MCP servers" }
            p class=(format!("mt-1 {MUTED}")) {
                "Add your own MCP server and its tools show up in your session, next to the shared ones. "
                "A tool of a server with the prefix "
                code class=(CODE) { "work" }
                " is named "
                code class=(CODE) { "<prefix>_<tool>" }
                ", here "
                code class=(CODE) { "work_search" }
                " for the tool "
                code class=(CODE) { "search" }
                ". Header values are stored encrypted and are never shown again."
            }
            @if let Some(saved) = saved {
                (render_saved(saved))
            }
            @if backends.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No servers yet." }
            } @else {
                div class=(format!("mt-4 {TABLE_WRAP}")) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Prefix" }
                                th class=(TH) { "URL" }
                                th class=(TH) { "Headers" }
                                th class=(TH) { "State" }
                                th class=(TH) { "Status" }
                                th class=(TH) { "Actions" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for backend in backends {
                                (render_backend_row(backend))
                            }
                        }
                    }
                }
            }
            div class=(DIVIDER) {
                h3 class=(SUBHEADING) { "Add a server" }
                p class=(format!("mt-1 {MUTED}")) {
                    "The server is tested when you add it and is kept whatever the test finds."
                }
                form class=(FORM_COL) hx-post="/ui/actions/me/backends" hx-target=(BACKENDS) hx-swap="outerHTML" {
                    div class=(FORM_ROW) {
                        label class=(LABEL) {
                            "Prefix"
                            input
                                class=(INPUT)
                                type="text"
                                name="prefix"
                                maxlength="32"
                                placeholder="work"
                                required;
                        }
                        label class=(LABEL) {
                            "URL"
                            input
                                class=(format!("{INPUT} w-96"))
                                type="url"
                                name="url"
                                placeholder="https://mcp.example.com/mcp"
                                required;
                        }
                    }
                    p class=(MUTED) { "Headers sent with every request, such as Authorization (optional):" }
                    (header_rows())
                    button class=(BUTTON) type="submit" { "Add server" }
                }
            }
        }
    }
}

/// My MCP servers page (`GET /ui/me/backends`).
pub(super) fn render_backends_page(
    state: &AppState,
    user: &SessionUser,
    backends: &[PersonalBackend],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "My MCP servers"
            }
        }
        (render_flash_area(false))
        (render_backends_section(backends, None))
    };
    render_layout(state, user, "My MCP servers", &content)
}

/// What a credential field is called: its label, else its name
fn field_label(field: &CredentialField) -> &str {
    field.label.as_deref().unwrap_or(&field.name)
}

/// The user's credential for an entry: its state, never its values
fn credential_state(view: &CatalogView) -> Markup {
    html! {
        @if let Some(credential) = &view.credential {
            span class=(BADGE_OK) { "set" }
            " "
            span class=(FAINT) { "updated " (when(credential.updated_at)) }
            div class="mt-1" {
                (status_cell(credential.last_ok_at, credential.last_error_at, credential.last_error.as_deref()))
            }
        } @else {
            span class=(BADGE_OFF) { "not set" }
        }
    }
}

/// The admin's forms for one entry of the database: edit and delete
fn render_entry_admin(view: &CatalogView) -> Markup {
    let item = &view.item;
    let base = format!("/ui/actions/catalog/{}", item.name);
    html! {
        details class="mt-3" {
            summary class="cursor-pointer text-xs text-slate-600 dark:text-slate-300" { "Edit entry" }
            form class=(FORM_ROW) hx-post=(format!("{base}/update")) hx-target=(CATALOG) hx-swap="outerHTML" {
                label class=(LABEL) {
                    "Description"
                    input
                        class=(format!("{INPUT} w-72"))
                        type="text"
                        name="description"
                        maxlength="500"
                        value=(item.description.as_deref().unwrap_or_default());
                }
                label class=(LABEL) {
                    "URL"
                    input
                        class=(format!("{INPUT} w-72"))
                        type="url"
                        name="url"
                        value=(item.url)
                        required;
                }
                label class=(LABEL) {
                    "State"
                    select class=(INPUT) name="enabled" {
                        option value="true" selected[item.enabled] { "enabled" }
                        option value="false" selected[!item.enabled] { "disabled" }
                    }
                }
                button class=(BUTTON_SMALL) type="submit" { "Save entry" }
            }
            button
                class=(format!("mt-3 {BUTTON_DANGER}"))
                type="button"
                hx-post=(format!("{base}/delete"))
                hx-target=(CATALOG)
                hx-swap="outerHTML"
                hx-confirm=(format!("Delete the catalog entry {}? Every user's credential for it goes with it.", item.name))
            {
                "Delete entry"
            }
        }
    }
}

/// One catalog entry: what it is, the user's credential and its form, and for
/// a catalog manager the url and the entry's admin forms
fn render_entry(view: &CatalogView) -> Markup {
    let item = &view.item;
    let base = format!("/ui/actions/catalog/{}", item.name);
    let classes = if item.enabled {
        "mt-6 border-t border-slate-200 pt-4 dark:border-slate-800"
    } else {
        "mt-6 border-t border-slate-200 pt-4 opacity-60 dark:border-slate-800"
    };
    html! {
        div class=(classes) {
            div class="flex flex-wrap items-center gap-3" {
                h3 class=(SUBHEADING) { (item.name) }
                @if !item.enabled {
                    span class=(BADGE_OFF) { "disabled" }
                }
                @if item.source == CatalogSource::Config {
                    span class=(BADGE_OFF) { "from config file" }
                }
                @if let Some(description) = &item.description {
                    span class=(MUTED) { (description) }
                }
            }
            @if view.manage {
                p class=(format!("mt-1 break-all {MUTED}")) { code class=(CODE) { (item.url) } }
            }
            p class=(format!("mt-2 {MUTED}")) {
                "Fields: "
                @for (index, field) in item.credential_fields.iter().enumerate() {
                    @if index > 0 {
                        ", "
                    }
                    (field_label(field))
                    @if view.manage {
                        " ("
                        code class=(CODE) {
                            (field.header) ": " (field.prefix.as_deref().unwrap_or_default()) "<value>"
                        }
                        ")"
                    }
                }
            }
            div class="mt-2 text-sm" {
                "Your credential: "
                (credential_state(view))
            }
            @if item.enabled {
                form class=(FORM_COL) hx-post=(format!("{base}/credential")) hx-target=(CATALOG) hx-swap="outerHTML" {
                    div class=(FORM_ROW) {
                        @for field in &item.credential_fields {
                            label class=(LABEL) {
                                (field_label(field))
                                input
                                    class=(format!("{INPUT} w-72"))
                                    type="password"
                                    name=(format!("field:{}", field.name))
                                    autocomplete="new-password";
                            }
                        }
                    }
                    p class=(MUTED) {
                        "Saving replaces your stored credential. Fields left empty are not stored."
                    }
                    button class=(BUTTON_SMALL) type="submit" { "Save credential" }
                }
            }
            @if view.credential.is_some() {
                button
                    class=(format!("mt-3 {BUTTON_DANGER}"))
                    type="button"
                    hx-post=(format!("{base}/credential/delete"))
                    hx-target=(CATALOG)
                    hx-swap="outerHTML"
                    hx-confirm=(format!("Remove your credential for {}?", item.name))
                {
                    "Remove credential"
                }
            }
            @if view.manage && item.source == CatalogSource::Database {
                (render_entry_admin(view))
            }
        }
    }
}

/// Empty rows of a credential field: name, label, header and prefix; the keys repeat
fn field_rows() -> Markup {
    html! {
        div class="flex flex-col gap-2" {
            @for _ in 0..FIELD_ROWS {
                div class="flex flex-wrap gap-2" {
                    input class=(format!("{INPUT} w-36")) type="text" name="field_name" placeholder="name: token" maxlength="64";
                    input class=(format!("{INPUT} w-40")) type="text" name="field_label" placeholder="label: API token";
                    input class=(format!("{INPUT} w-44")) type="text" name="field_header" placeholder="header: Authorization";
                    input class=(format!("{INPUT} w-36")) type="text" name="field_prefix" placeholder="prefix: Bearer ";
                }
            }
        }
    }
}

/// The create form of the catalog admin
fn render_catalog_create() -> Markup {
    html! {
        div class=(DIVIDER) {
            h3 class=(SUBHEADING) { "New catalog entry" }
            p class=(format!("mt-1 {MUTED}")) {
                "Each credential field is one input for the user and one header the gateway sends: "
                "its value, with the prefix put in front. Empty rows are ignored."
            }
            form class=(FORM_COL) hx-post="/ui/actions/catalog" hx-target=(CATALOG) hx-swap="outerHTML" {
                div class=(FORM_ROW) {
                    label class=(LABEL) {
                        "Name (the tool prefix)"
                        input class=(INPUT) type="text" name="name" maxlength="32" required;
                    }
                    label class=(LABEL) {
                        "Description"
                        input class=(format!("{INPUT} w-72")) type="text" name="description" maxlength="500";
                    }
                    label class=(LABEL) {
                        "URL"
                        input class=(format!("{INPUT} w-96")) type="url" name="url" required;
                    }
                }
                (field_rows())
                button class=(BUTTON) type="submit" { "Create entry" }
            }
        }
    }
}

/// The catalog and the user's credentials, with the admin of it for a catalog
/// `manage`r; the swap target of the `catalog` actions
pub(super) fn render_catalog_section(entries: &[CatalogView], manage: bool) -> Markup {
    html! {
        section id="catalog" class=(CARD) {
            h2 class=(HEADING) { "Catalog" }
            p class=(format!("mt-1 {MUTED}")) {
                "Servers the admin has set up for you to use with your own credential. "
                "Store yours here and the tools appear in your session, named "
                code class=(CODE) { "<name>_<tool>" }
                ". Credentials are stored encrypted and are never shown again."
            }
            @if entries.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No catalog entries." }
            }
            @for view in entries {
                (render_entry(view))
            }
            @if manage {
                (render_catalog_create())
            }
        }
    }
}

/// Catalog page (`GET /ui/catalog`).
pub(super) fn render_catalog_page(
    state: &AppState,
    user: &SessionUser,
    entries: &[CatalogView],
    manage: bool,
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Catalog"
            }
        }
        (render_flash_area(false))
        (render_catalog_section(entries, manage))
    };
    render_layout(state, user, "Catalog", &content)
}

/// Every user's personal servers, the swap target of the admin actions
pub(super) fn render_admin_section(backends: &[AdminPersonalBackend]) -> Markup {
    html! {
        section id="admin-personal" class=(CARD) {
            h2 class=(HEADING) { "Personal MCP servers" }
            p class=(format!("mt-1 {MUTED}")) {
                "The servers users brought themselves. Disabling one takes its tools out of the "
                "owner's session; header values are never shown."
            }
            @if backends.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No personal servers yet." }
            } @else {
                div class=(format!("mt-4 {TABLE_WRAP}")) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Owner" }
                                th class=(TH) { "Prefix" }
                                th class=(TH) { "URL" }
                                th class=(TH) { "State" }
                                th class=(TH) { "Status" }
                                th class=(TH) { "Actions" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for backend in backends {
                                @let base = format!(
                                    "/ui/actions/admin/personal-backends/{}/{}",
                                    backend.owner_id, backend.prefix
                                );
                                tr {
                                    td class=(TD) { (owner_label(backend)) }
                                    td class=(TD) { code class=(CODE) { (backend.prefix) } }
                                    td class=(TD) { span class="break-all" { (backend.url) } }
                                    td class=(TD) { (enabled_badge(backend.enabled)) }
                                    td class=(TD) {
                                        (status_cell(backend.last_ok_at, backend.last_error_at, backend.last_error.as_deref()))
                                    }
                                    td class=(TD) {
                                        div class="flex flex-wrap items-start gap-2" {
                                            (enabled_toggle(&format!("{base}/enabled"), ADMIN_PERSONAL, backend.enabled))
                                            button
                                                class=(BUTTON_DANGER)
                                                type="button"
                                                hx-post=(format!("{base}/delete"))
                                                hx-target=(ADMIN_PERSONAL)
                                                hx-swap="outerHTML"
                                                hx-confirm=(format!("Delete the server {} of {}?", backend.prefix, owner_label(backend)))
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
    }
}

/// Personal servers overview page (`GET /ui/admin/personal-backends`).
pub(super) fn render_admin_page(
    state: &AppState,
    user: &SessionUser,
    backends: &[AdminPersonalBackend],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Personal MCP servers"
            }
        }
        (render_flash_area(false))
        (render_admin_section(backends))
    };
    render_layout(state, user, "Personal MCP servers", &content)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Duration as Span;
    use uuid::Uuid;

    use super::*;
    use crate::personal::CatalogItem;
    use crate::server::tests::test_state;
    use crate::store::{SealedColumns, User, UserCredential};

    fn session() -> SessionUser {
        SessionUser {
            user: User {
                id: Uuid::nil(),
                issuer: String::from("https://idp.example"),
                subject: String::from("sub-1"),
                email: Some(String::from("ada@example.com")),
                display_name: None,
                groups: Vec::new(),
                is_admin: true,
            },
            provider_id: String::from("pocket"),
            csrf_token: String::from("tok-123"),
            id_token: None,
        }
    }

    fn backend(prefix: &str) -> PersonalBackend {
        PersonalBackend {
            id: Uuid::from_u128(5),
            owner_id: Uuid::nil(),
            prefix: prefix.to_owned(),
            url: String::from("https://mcp.example.com/mcp"),
            header_names: vec![String::from("authorization")],
            secret: Some(SealedColumns {
                kek_id: String::from("k1"),
                dek: b"sealed-dek-bytes".to_vec(),
                data: b"hunter2-secret-value".to_vec(),
            }),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_ok_at: None,
            last_error_at: None,
            last_error: None,
        }
    }

    fn field(name: &str, label: Option<&str>) -> CredentialField {
        CredentialField {
            name: name.to_owned(),
            label: label.map(str::to_owned),
            header: String::from("Authorization"),
            prefix: Some(String::from("Bearer ")),
        }
    }

    fn item(name: &str, source: CatalogSource, enabled: bool) -> CatalogItem {
        CatalogItem {
            name: name.to_owned(),
            description: Some(String::from("for <everyone>")),
            url: String::from("https://catalog.example.com/mcp"),
            credential_fields: vec![field("token", Some("API token")), field("org", None)],
            enabled,
            source,
            idle_timeout: Some(Duration::from_secs(300)),
            timeout_secs: 30,
        }
    }

    fn credential(name: &str) -> UserCredential {
        UserCredential {
            user_id: Uuid::nil(),
            backend: name.to_owned(),
            secret: SealedColumns {
                kek_id: String::from("k1"),
                dek: b"sealed-dek-bytes".to_vec(),
                data: b"hunter2-secret-value".to_vec(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_ok_at: None,
            last_error_at: Some(Utc::now()),
            last_error: Some(String::from("401 <denied>")),
        }
    }

    fn view(item: CatalogItem, credential: Option<UserCredential>, manage: bool) -> CatalogView {
        CatalogView {
            item,
            credential,
            manage,
        }
    }

    #[test]
    fn header_values_are_never_rendered() {
        let html = render_backends_section(&[backend("work")], None).into_string();

        assert!(html.contains(">authorization<"));
        assert!(!html.contains("hunter2"));
        assert!(!html.contains("sealed-dek"));
        // the forms that take values start empty and hide what is typed
        assert_eq!(
            html.matches("name=\"header_value\"").count(),
            2 * HEADER_ROWS
        );
        assert!(!html.contains("name=\"header_value\" value="));
        assert!(html.contains("type=\"password\""));
        assert!(html.contains("replaces all headers"));
    }

    #[test]
    fn a_server_renders_its_actions_and_status() {
        let mut failing = backend("work");
        failing.last_error_at = Some(Utc::now());
        failing.last_error = Some(String::from("refused <x>"));
        let html = render_backends_section(&[failing], None).into_string();

        assert!(html.contains("hx-post=\"/ui/actions/me/backends\""));
        assert!(html.contains("/ui/actions/me/backends/work/enabled"));
        assert!(html.contains("/ui/actions/me/backends/work/update"));
        assert!(html.contains("/ui/actions/me/backends/work/headers"));
        assert!(html.contains("/ui/actions/me/backends/work/delete"));
        assert!(html.contains("hx-confirm="));
        assert!(html.contains("name=\"enabled\" value=\"false\""));
        assert!(html.contains(">error<"));
        assert!(html.contains("refused &lt;x&gt;"));
        assert!(html.contains("&lt;prefix&gt;_&lt;tool&gt;"));
    }

    #[test]
    fn no_servers_says_so() {
        let html = render_backends_section(&[], None).into_string();
        assert!(html.contains("No servers yet."));
        assert!(html.contains("Add a server"));
    }

    #[tokio::test]
    async fn the_test_result_shows_once() {
        let saved = |test| PersonalSaved {
            backend: backend("work"),
            test: Some(test),
        };
        let ok = render_backends_section(&[], Some(&saved(Ok(7)))).into_string();
        assert!(ok.contains("Connection test: 7 tools."));

        let failed =
            render_backends_section(&[], Some(&saved(Err(String::from("<down>"))))).into_string();
        assert!(failed.contains("Connection test failed: &lt;down&gt;"));

        let listed =
            render_backends_page(&test_state(), &session(), &[backend("work")]).into_string();
        assert!(!listed.contains("Connection test"));
    }

    #[test]
    fn the_credential_form_has_one_password_input_per_field() {
        let entries = [view(
            item("shared", CatalogSource::Config, true),
            None,
            false,
        )];
        let html = render_catalog_section(&entries, false).into_string();

        assert!(html.contains("/ui/actions/catalog/shared/credential\""));
        assert_eq!(html.matches("type=\"password\"").count(), 2);
        assert!(html.contains("name=\"field:token\""));
        assert!(html.contains("name=\"field:org\""));
        // the label, else the name
        assert!(html.contains("API token"));
        assert!(html.contains(">not set<"));
        // a plain user sees neither the url nor the admin forms
        assert!(!html.contains("catalog.example.com"));
        assert!(!html.contains("New catalog entry"));
        // nothing to remove without a credential
        assert!(!html.contains("credential/delete"));
    }

    #[test]
    fn a_stored_credential_shows_its_state_and_not_its_values() {
        let entries = [view(
            item("shared", CatalogSource::Config, true),
            Some(credential("shared")),
            false,
        )];
        let html = render_catalog_section(&entries, false).into_string();

        assert!(html.contains(">set<"));
        assert!(html.contains("401 &lt;denied&gt;"));
        assert!(html.contains("/ui/actions/catalog/shared/credential/delete"));
        assert!(html.contains("hx-confirm="));
        assert!(!html.contains("hunter2"));
        assert!(!html.contains("sealed-dek"));
    }

    #[test]
    fn config_entries_have_no_edit_form() {
        let entries = [
            view(item("fromfile", CatalogSource::Config, true), None, true),
            view(item("indb", CatalogSource::Database, true), None, true),
        ];
        let html = render_catalog_section(&entries, true).into_string();

        assert!(html.contains("from config file"));
        assert!(!html.contains("/ui/actions/catalog/fromfile/update"));
        assert!(!html.contains("/ui/actions/catalog/fromfile/delete"));
        assert!(html.contains("/ui/actions/catalog/indb/update"));
        assert!(html.contains("/ui/actions/catalog/indb/delete"));
        // a manager sees the url and the create form
        assert!(html.contains("catalog.example.com"));
        assert!(html.contains("hx-post=\"/ui/actions/catalog\""));
        assert!(html.contains("name=\"field_prefix\""));
    }

    #[test]
    fn a_disabled_entry_is_greyed_and_has_no_credential_form() {
        let entries = [view(
            item("off", CatalogSource::Database, false),
            None,
            false,
        )];
        let html = render_catalog_section(&entries, false).into_string();

        assert!(html.contains("opacity-60"));
        assert!(html.contains(">disabled<"));
        assert!(!html.contains("type=\"password\""));
        assert!(!html.contains("/ui/actions/catalog/off/credential\""));
    }

    #[test]
    fn the_catalog_admin_shows_for_a_manager_with_no_entries() {
        let html = render_catalog_section(&[], true).into_string();
        assert!(html.contains("No catalog entries."));
        assert!(html.contains("New catalog entry"));
        assert_eq!(html.matches("name=\"field_name\"").count(), FIELD_ROWS);

        let plain = render_catalog_section(&[], false).into_string();
        assert!(!plain.contains("New catalog entry"));
    }

    #[test]
    fn descriptions_are_escaped() {
        let entries = [view(
            item("shared", CatalogSource::Config, true),
            None,
            false,
        )];
        let html = render_catalog_section(&entries, false).into_string();
        assert!(html.contains("for &lt;everyone&gt;"));
        assert!(!html.contains("<everyone>"));
    }

    fn admin_backend(enabled: bool) -> AdminPersonalBackend {
        AdminPersonalBackend {
            id: Uuid::from_u128(5),
            owner_id: Uuid::from_u128(8),
            owner_email: Some(String::from("ada@example.com")),
            owner_name: None,
            owner_subject: String::from("sub-1"),
            prefix: String::from("work"),
            url: String::from("https://mcp.example.com/mcp"),
            header_names: vec![String::from("authorization")],
            enabled,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_ok_at: Some(Utc::now() - Span::hours(1)),
            last_error_at: None,
            last_error: None,
        }
    }

    #[test]
    fn the_admin_overview_lists_owners_with_toggle_and_delete() {
        let html = render_admin_section(&[admin_backend(false)]).into_string();

        assert!(html.contains("ada@example.com"));
        assert!(html.contains(">disabled<"));
        assert!(html.contains(">Enable<"));
        assert!(html.contains(">ok<"));
        assert!(html.contains(
            "/ui/actions/admin/personal-backends/00000000-0000-0000-0000-000000000008/work/enabled"
        ));
        assert!(html.contains(
            "/ui/actions/admin/personal-backends/00000000-0000-0000-0000-000000000008/work/delete"
        ));
        assert!(html.contains("hx-confirm="));
        assert!(!html.contains("authorization"));

        let empty = render_admin_section(&[]).into_string();
        assert!(empty.contains("No personal servers yet."));
    }
}
