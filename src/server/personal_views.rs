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
//!
//! The add and create forms sit in a slide-over drawer built on the native
//! Popover API (see `config_views`). The constraint attributes on the inputs
//! mirror the rules `personal_api` and `personal` enforce; the server still
//! validates every field.

use chrono::{DateTime, Utc};
use maud::{Markup, html};

use super::AppState;
use super::admin_views::{render_flash_area, render_layout};
use super::config_views::{drawer_foot, drawer_head, drawer_trigger};
use super::personal_api::{CatalogView, PersonalSaved};
use super::shell::Nav;
use crate::config::CredentialField;
use crate::personal::{CatalogAuth, CatalogItem, CatalogSource};
use crate::store::{AdminPersonalBackend, PersonalBackend, SessionUser};

const BACKENDS: &str = "#my-backends";
const CATALOG: &str = "#catalog";
const ADMIN_PERSONAL: &str = "#admin-personal";

/// Empty header rows on the add and replace forms
const HEADER_ROWS: usize = 4;
/// Empty credential field rows on the catalog create form
const FIELD_ROWS: usize = 3;

/// `MAX_URL_CHARS` of `personal_api`
const URL_MAX: &str = "2048";
/// `MAX_HEADER_VALUE_CHARS` of `personal_api`
const HEADER_VALUE_MAX: &str = "4096";
/// `MAX_CLIENT_ID_CHARS` of `personal_api`
const CLIENT_ID_MAX: &str = "512";
/// `MAX_CLIENT_SECRET_CHARS` of `personal_api`
const CLIENT_SECRET_MAX: &str = "4096";
/// `check_prefix` of `personal`: `[a-z][a-z0-9-]{1,30}`
const PREFIX_PATTERN: &str = r"[a-z][a-z0-9\-]{1,30}";
/// `clean_url` of `personal_api`: an `http` or `https` URL
const URL_PATTERN: &str = "https?://.+";
const PREFIX_ERROR: &str =
    "2 to 31 characters: a lowercase letter, then lowercase letters, digits or dashes.";
const URL_ERROR: &str = "Enter a full http or https URL.";

/// A row of two inputs: a header name and its value
const HEADER_ROW: &str = "grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-2";
/// A row of the four inputs of a credential field
const FIELD_ROW: &str = "grid grid-cols-2 gap-2";

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
            span class="pill ok" { "enabled" }
        } @else {
            span class="pill" { "disabled" }
        }
    }
}

/// A labelled field: the input, an optional hint and the error the browser's
/// constraint check shows
fn field(label: &str, id: &str, input: &Markup, hint: Option<&str>, error: Option<&str>) -> Markup {
    html! {
        div class="field" {
            label for=(id) { (label) }
            (input)
            @if let Some(hint) = hint {
                p class="hint" { (hint) }
            }
            @if let Some(error) = error {
                p class="field-error" { (error) }
            }
        }
    }
}

/// The URL input of a personal server or catalog entry
fn url_field(id: &str, value: &str, placeholder: &str) -> Markup {
    let input = html! {
        input
            class="input mono"
            id=(id)
            type="url"
            name="url"
            value=(value)
            placeholder=[(!placeholder.is_empty()).then_some(placeholder)]
            maxlength=(URL_MAX)
            pattern=(URL_PATTERN)
            autocomplete="off"
            required;
    };
    field("URL", id, &input, None, Some(URL_ERROR))
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
            span class="pill warn" { "error" }
            " "
            span class="muted" { (when(failed_at)) }
            @if let Some(message) = last_error {
                div class="muted mt-1 break-words" { (message) }
            }
        } @else if let Some(ok_at) = last_ok_at {
            span class="pill ok" { "ok" }
            " "
            span class="muted" { (when(ok_at)) }
        } @else {
            span class="muted" { "not tested" }
        }
    }
}

/// A button that posts a switch of `enabled` to `path`
fn enabled_toggle(path: &str, target: &str, enabled: bool) -> Markup {
    html! {
        form hx-post=(path) hx-target=(target) hx-swap="outerHTML" {
            input type="hidden" name="enabled" value=(if enabled { "false" } else { "true" });
            button class="btn sm" type="submit" {
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
                div class=(HEADER_ROW) {
                    input
                        class="input mono"
                        type="text"
                        name="header_name"
                        placeholder="Authorization"
                        aria-label="Header name"
                        autocomplete="off";
                    input
                        class="input"
                        type="password"
                        name="header_value"
                        placeholder="value"
                        maxlength=(HEADER_VALUE_MAX)
                        aria-label="Header value"
                        autocomplete="new-password";
                }
            }
        }
    }
}

/// The result of saving a server, shown once in the response of the action
fn render_saved(saved: &PersonalSaved) -> Markup {
    let (tone, text) = match &saved.test {
        Some(Ok(tools)) => ("ok", format!("Connection test: {tools} tools.")),
        Some(Err(error)) => ("warn", format!("Connection test failed: {error}")),
        None => ("ok", String::from("Not tested.")),
    };
    html! {
        div class="card-f flex-wrap" role="status" {
            span class=(format!("pill {tone}")) {
                "Saved " span class="mono" { (saved.backend.prefix) }
            }
            span class="muted min-w-0 break-words" { (text) }
        }
    }
}

/// One of the user's servers: the overview cells and the edit forms
fn render_backend_row(backend: &PersonalBackend) -> Markup {
    let base = format!("/ui/actions/me/backends/{}", backend.prefix);
    html! {
        tr {
            td { span class="mono" { (backend.prefix) } }
            td class="wrap break-all" { (backend.url) }
            td class="wrap" {
                @if backend.header_names.is_empty() {
                    span class="muted" { "none" }
                }
                @for name in &backend.header_names {
                    div { span class="mono" { (name) } }
                }
            }
            td { (enabled_badge(backend.enabled)) }
            td class="wrap" {
                (status_cell(backend.last_ok_at, backend.last_error_at, backend.last_error.as_deref()))
            }
            td class="wrap" {
                div class="flex flex-wrap items-start gap-2" {
                    (enabled_toggle(&format!("{base}/enabled"), BACKENDS, backend.enabled))
                    button
                        class="btn sm danger"
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
                    summary class="muted cursor-pointer" { "Edit" }
                    div class="mt-2 flex w-80 max-w-full flex-col gap-3" {
                        form class="flex flex-col gap-2" hx-post=(format!("{base}/update")) hx-target=(BACKENDS) hx-swap="outerHTML" {
                            (url_field(&format!("url-{}", backend.prefix), &backend.url, ""))
                            div { button class="btn sm" type="submit" { "Save URL" } }
                        }
                        form class="flex flex-col gap-2" hx-post=(format!("{base}/headers")) hx-target=(BACKENDS) hx-swap="outerHTML" {
                            p class="hint" {
                                "Saving replaces all headers of this server: enter every header it needs, "
                                "not only the ones that change. Saving no header removes them all."
                            }
                            (header_rows())
                            div { button class="btn sm" type="submit" { "Replace headers" } }
                        }
                    }
                }
            }
        }
    }
}

/// The add form of the user's servers, in a drawer
fn render_add_server() -> Markup {
    let prefix = html! {
        input
            class="input mono"
            id="add-server-prefix"
            type="text"
            name="prefix"
            maxlength="31"
            pattern=(PREFIX_PATTERN)
            placeholder="work"
            autocomplete="off"
            required;
    };
    html! {
        div id="add-server" popover class="drawer" aria-labelledby="add-server-title" {
            (drawer_head("add-server", "Add a server"))
            form
                class="drawer-form"
                hx-post="/ui/actions/me/backends"
                hx-target=(BACKENDS)
                hx-swap="outerHTML"
            {
                div class="drawer-b" {
                    p class="hint" {
                        "The server is tested when you add it and is kept whatever the test finds."
                    }
                    (field("Prefix", "add-server-prefix", &prefix, None, Some(PREFIX_ERROR)))
                    (url_field("add-server-url", "", "https://mcp.example.com/mcp"))
                    div class="section-t" { "Headers" }
                    p class="hint" { "Headers sent with every request, such as Authorization (optional):" }
                    (header_rows())
                }
                (drawer_foot("add-server", "Add server"))
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
        section id="my-backends" class="card" {
            div class="card-h" {
                h2 { "My MCP servers" }
                span class="muted" { (backends.len()) }
                span class="spacer" {}
                (drawer_trigger("add-server", "Add a server"))
            }
            div class="card-b" {
                p class="muted" {
                    "Add your own MCP server and its tools show up in your session, next to the shared ones. "
                    "A tool of a server with the prefix "
                    span class="mono" { "work" }
                    " is named "
                    span class="mono" { "<prefix>_<tool>" }
                    ", here "
                    span class="mono" { "work_search" }
                    " for the tool "
                    span class="mono" { "search" }
                    ". Header values are stored encrypted and are never shown again."
                }
            }
            @if let Some(saved) = saved {
                (render_saved(saved))
            }
            @if backends.is_empty() {
                div class="card-b muted" { "No servers yet." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="My MCP servers" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Prefix" }
                                th { "URL" }
                                th { "Headers" }
                                th { "State" }
                                th { "Status" }
                                th { "Actions" }
                            }
                        }
                        tbody {
                            @for backend in backends {
                                (render_backend_row(backend))
                            }
                        }
                    }
                }
            }
            (render_add_server())
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
        div class="page-head" {
            h1 { "My MCP servers" }
        }
        (render_flash_area(false))
        (render_backends_section(backends, None))
    };
    render_layout(state, user, "My MCP servers", Nav::MyServers, &content)
}

/// What a credential field is called: its label, else its name
fn field_label(field: &CredentialField) -> &str {
    field.label.as_deref().unwrap_or(&field.name)
}

/// The user's credential for an entry: its state, never its values
fn credential_state(view: &CatalogView) -> Markup {
    html! {
        @if let Some(credential) = &view.credential {
            span class="pill ok" { "set" }
            " "
            span class="muted" { "updated " (when(credential.updated_at)) }
            div class="mt-1" {
                (status_cell(credential.last_ok_at, credential.last_error_at, credential.last_error.as_deref()))
            }
        } @else {
            span class="pill" { "not set" }
        }
    }
}

/// What the admin form shows of an entry's OAuth settings: the client id, the
/// scopes and whether a client secret is stored (its value never is)
struct OauthSettings {
    client_id: String,
    scopes: String,
    secret_set: bool,
}

fn oauth_settings(item: &CatalogItem) -> OauthSettings {
    match &item.auth {
        CatalogAuth::OAuth {
            client,
            scopes,
            client_unusable,
        } => OauthSettings {
            client_id: client
                .as_ref()
                .map(|client| client.client_id.clone())
                .unwrap_or_default(),
            scopes: scopes.join(" "),
            secret_set: *client_unusable
                || client
                    .as_ref()
                    .is_some_and(|client| client.client_secret.is_some()),
        },
        CatalogAuth::Fields | CatalogAuth::Passthrough(_) => OauthSettings {
            client_id: String::new(),
            scopes: String::new(),
            secret_set: false,
        },
    }
}

/// The `auth` choice and the OAuth inputs of the admin forms. `current` is
/// `None` on the create form, which has no stored secret to keep or clear.
/// `scope` keeps the ids of the inputs apart.
fn oauth_inputs(scope: &str, oauth: bool, current: Option<&OauthSettings>) -> Markup {
    let client_id = current.map_or("", |settings| settings.client_id.as_str());
    let scopes = current.map_or("", |settings| settings.scopes.as_str());
    let secret_set = current.is_some_and(|settings| settings.secret_set);
    let auth = html! {
        select class="input" id=(format!("{scope}-auth")) name="auth" {
            option value="fields" selected[!oauth] { "credential fields" }
            option value="oauth" selected[oauth] { "OAuth (users connect their account)" }
        }
    };
    let id_input = html! {
        input
            class="input mono"
            id=(format!("{scope}-client-id"))
            type="text"
            name="oauth_client_id"
            value=(client_id)
            maxlength=(CLIENT_ID_MAX)
            autocomplete="off";
    };
    let scopes_input = html! {
        input
            class="input mono"
            id=(format!("{scope}-scopes"))
            type="text"
            name="oauth_scopes"
            value=(scopes)
            autocomplete="off";
    };
    let secret_input = html! {
        input
            class="input"
            id=(format!("{scope}-client-secret"))
            type="password"
            name="oauth_client_secret"
            placeholder=(if secret_set { "stored; leave empty to keep it" } else { "" })
            maxlength=(CLIENT_SECRET_MAX)
            autocomplete="new-password";
    };
    html! {
        (field("Sign-in", &format!("{scope}-auth"), &auth, None, None))
        (field("OAuth client ID (optional)", &format!("{scope}-client-id"), &id_input, None, None))
        (field("OAuth scopes (space or comma separated)", &format!("{scope}-scopes"), &scopes_input, None, None))
        (field("OAuth client secret", &format!("{scope}-client-secret"), &secret_input, None, None))
        @if secret_set {
            label class="flex items-center gap-2" {
                input type="checkbox" name="clear_oauth_secret" value="true";
                " Clear the stored client secret"
            }
        }
    }
}

/// The admin's forms for one entry of the database: edit and delete
fn render_entry_admin(view: &CatalogView) -> Markup {
    let item = &view.item;
    let base = format!("/ui/actions/catalog/{}", item.name);
    let scope = format!("ent-{}", item.name);
    let settings = oauth_settings(item);
    let oauth = matches!(item.auth, CatalogAuth::OAuth { .. });
    let description = html! {
        input
            class="input"
            id=(format!("{scope}-description"))
            type="text"
            name="description"
            maxlength="500"
            value=(item.description.as_deref().unwrap_or_default());
    };
    let state = html! {
        select class="input" id=(format!("{scope}-enabled")) name="enabled" {
            option value="true" selected[item.enabled] { "enabled" }
            option value="false" selected[!item.enabled] { "disabled" }
        }
    };
    html! {
        details class="w-full" {
            summary class="muted cursor-pointer" { "Edit entry" }
            div class="mt-3 flex flex-col gap-3" {
                form class="flex flex-col gap-3" hx-post=(format!("{base}/update")) hx-target=(CATALOG) hx-swap="outerHTML" {
                    (field("Description", &format!("{scope}-description"), &description, None, None))
                    (url_field(&format!("{scope}-url"), &item.url, ""))
                    (field("State", &format!("{scope}-enabled"), &state, None, None))
                    p class="hint" {
                        "The credential fields apply when Sign-in is \"credential fields\". "
                        "Users' stored values are kept by field name, so a renamed field is a new one they enter again. "
                        "Empty rows are ignored."
                    }
                    (field_rows(&item.credential_fields))
                    (oauth_inputs(&scope, oauth, Some(&settings)))
                    div { button class="btn sm primary" type="submit" { "Save entry" } }
                }
                div {
                    button
                        class="btn sm danger"
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
    }
}

/// The credential an entry takes: its fields, the user's stored credential
/// and the forms for it
fn render_credential(view: &CatalogView, base: &str) -> Markup {
    let item = &view.item;
    html! {
        p class="muted" {
            "Fields: "
            @for (index, field) in item.credential_fields.iter().enumerate() {
                @if index > 0 {
                    ", "
                }
                (field_label(field))
                @if view.manage {
                    " ("
                    span class="mono" {
                        (field.header) ": " (field.prefix.as_deref().unwrap_or_default()) "<value>"
                    }
                    ")"
                }
            }
        }
        div {
            "Your credential: "
            (credential_state(view))
        }
        @if item.enabled {
            form class="flex flex-col gap-3" hx-post=(format!("{base}/credential")) hx-target=(CATALOG) hx-swap="outerHTML" {
                @for (index, credential_field) in item.credential_fields.iter().enumerate() {
                    @let id = format!("cred-{}-{index}", item.name);
                    @let input = html! {
                        input
                            class="input"
                            id=(id)
                            type="password"
                            name=(format!("field:{}", credential_field.name))
                            maxlength=(HEADER_VALUE_MAX)
                            autocomplete="new-password";
                    };
                    (field(field_label(credential_field), &id, &input, None, None))
                }
                p class="hint" {
                    "Saving replaces your stored credential. Fields left empty are not stored."
                }
                div { button class="btn sm primary" type="submit" { "Save credential" } }
            }
        }
        @if view.credential.is_some() {
            div {
                button
                    class="btn sm danger"
                    type="button"
                    hx-post=(format!("{base}/credential/delete"))
                    hx-target=(CATALOG)
                    hx-swap="outerHTML"
                    hx-confirm=(format!("Remove your credential for {}?", item.name))
                {
                    "Remove credential"
                }
            }
        }
    }
}

/// The OAuth connection of an entry: its state and the buttons to connect,
/// connect again and disconnect. Connecting is a form post whose answer sends
/// the browser to the service's sign-in (`HX-Redirect`).
fn render_connection(view: &CatalogView, base: &str, client_unusable: bool) -> Markup {
    let item = &view.item;
    let connect = if view.connection.is_some() {
        "Reconnect"
    } else {
        "Connect"
    };
    html! {
        div {
            "Your connection: "
            @if let Some(connection) = &view.connection {
                @if let Some(message) = &connection.last_error {
                    span class="pill warn" { "Reconnect needed" }
                    @if let Some(failed_at) = connection.last_error_at {
                        " "
                        span class="muted" { (when(failed_at)) }
                    }
                    div class="muted mt-1 break-words" { (message) }
                } @else {
                    span class="pill ok" { "Connected" }
                    " "
                    span class="muted" { "token expires " (when(connection.expires_at)) }
                }
            } @else {
                span class="pill" { "Not connected" }
            }
        }
        @if client_unusable {
            p class="muted" {
                "The administrator's OAuth client secret for this service cannot be read, "
                "so it cannot be connected until it is set again."
            }
        } @else if item.enabled {
            form hx-post=(format!("{base}/connect")) hx-swap="none" {
                button class="btn sm primary" type="submit" { (connect) }
            }
        }
        @if view.connection.is_some() {
            div {
                button
                    class="btn sm danger"
                    type="button"
                    hx-post=(format!("{base}/disconnect"))
                    hx-target=(CATALOG)
                    hx-swap="outerHTML"
                    hx-confirm=(format!("Disconnect {}?", item.name))
                {
                    "Disconnect"
                }
            }
        }
    }
}

/// How an entry signs the user in, as the pill of its card
fn auth_pill(auth: &CatalogAuth) -> Markup {
    html! {
        @match auth {
            CatalogAuth::Fields => { span class="pill" { "Credentials" } }
            CatalogAuth::OAuth { .. } => { span class="pill accent" { "OAuth" } }
            CatalogAuth::Passthrough(_) => { span class="pill ok" { "Your sign-in" } }
        }
    }
}

/// One catalog entry: what it is, the user's credential and its form, and for
/// a catalog manager the url and the entry's admin forms
fn render_entry(view: &CatalogView) -> Markup {
    let item = &view.item;
    let base = format!("/ui/actions/catalog/{}", item.name);
    let classes = if item.enabled {
        "card flex flex-col"
    } else {
        "card flex flex-col opacity-60"
    };
    let initial: String = item
        .name
        .chars()
        .take(1)
        .flat_map(char::to_uppercase)
        .collect();
    html! {
        article class=(classes) {
            div class="card-b flex flex-1 flex-col gap-2" {
                div class="flex flex-wrap items-center gap-2" {
                    span class="avatar" aria-hidden="true" { (initial) }
                    h3 class="mono font-semibold" { (item.name) }
                    @if !item.enabled {
                        span class="pill" { "disabled" }
                    }
                    @if item.source == CatalogSource::Config {
                        span class="pill" { "from backend config" }
                    }
                    span class="spacer" {}
                    (auth_pill(&item.auth))
                }
                @if let Some(description) = &item.description {
                    p class="muted" { (description) }
                }
                @if view.manage {
                    p class="mono muted break-all" { (item.url) }
                }
                @match &item.auth {
                    CatalogAuth::Fields => { (render_credential(view, &base)) }
                    CatalogAuth::OAuth { client_unusable, .. } => {
                        (render_connection(view, &base, *client_unusable))
                    }
                    CatalogAuth::Passthrough(_) => {
                        div {
                            span class="pill ok" { "Uses your sign-in" }
                            " "
                            span class="muted" {
                                "The gateway trades your sign-in for a token this service accepts."
                            }
                        }
                    }
                }
            }
            @if view.manage && item.source == CatalogSource::Database {
                div class="card-f" { (render_entry_admin(view)) }
            }
        }
    }
}

/// Rows of a credential field: name, label, header and prefix; the keys
/// repeat. One row per `existing` field, prefilled, then empty rows up to
/// `FIELD_ROWS` rows in all (and never fewer than one empty row).
fn field_rows(existing: &[CredentialField]) -> Markup {
    let empty = FIELD_ROWS.saturating_sub(existing.len()).max(1);
    html! {
        div class="flex flex-col gap-2" {
            @for field in existing {
                div class=(FIELD_ROW) {
                    input class="input mono" type="text" name="field_name" placeholder="name: token" aria-label="Field name" maxlength="64" value=(field.name);
                    input class="input" type="text" name="field_label" placeholder="label: API token" aria-label="Field label" value=(field.label.as_deref().unwrap_or_default());
                    input class="input mono" type="text" name="field_header" placeholder="header: Authorization" aria-label="Header" value=(field.header);
                    input class="input mono" type="text" name="field_prefix" placeholder="prefix: Bearer " aria-label="Prefix" value=(field.prefix.as_deref().unwrap_or_default());
                }
            }
            @for _ in 0..empty {
                div class=(FIELD_ROW) {
                    input class="input mono" type="text" name="field_name" placeholder="name: token" aria-label="Field name" maxlength="64";
                    input class="input" type="text" name="field_label" placeholder="label: API token" aria-label="Field label";
                    input class="input mono" type="text" name="field_header" placeholder="header: Authorization" aria-label="Header";
                    input class="input mono" type="text" name="field_prefix" placeholder="prefix: Bearer " aria-label="Prefix";
                }
            }
        }
    }
}

/// The create form of the catalog admin, in a drawer
fn render_catalog_create() -> Markup {
    let name = html! {
        input
            class="input mono"
            id="new-entry-name"
            type="text"
            name="name"
            maxlength="31"
            pattern=(PREFIX_PATTERN)
            autocomplete="off"
            required;
    };
    let description = html! {
        input
            class="input"
            id="new-entry-description"
            type="text"
            name="description"
            maxlength="500"
            autocomplete="off";
    };
    html! {
        div id="new-entry" popover class="drawer" aria-labelledby="new-entry-title" {
            (drawer_head("new-entry", "New catalog entry"))
            form
                class="drawer-form"
                hx-post="/ui/actions/catalog"
                hx-target=(CATALOG)
                hx-swap="outerHTML"
            {
                div class="drawer-b" {
                    div class="section-t" { "Server" }
                    div class="form-grid" {
                        (field("Name (the tool prefix)", "new-entry-name", &name, None, Some(PREFIX_ERROR)))
                        (field("Description", "new-entry-description", &description, None, None))
                    }
                    (url_field("new-entry-url", "", ""))
                    div class="section-t" { "Credential fields" }
                    p class="hint" {
                        "Each credential field is one input for the user and one header the gateway sends: "
                        "its value, with the prefix put in front. Empty rows are ignored. "
                        "For an OAuth entry leave the rows empty: each user connects their own account, "
                        "with the static client below or, without one, a client the gateway registers itself."
                    }
                    (field_rows(&[]))
                    div class="section-t" { "How users sign in" }
                    (oauth_inputs("new-entry", false, None))
                }
                (drawer_foot("new-entry", "Create entry"))
            }
        }
    }
}

/// The catalog and the user's credentials, with the admin of it for a catalog
/// `manage`r; the swap target of the `catalog` actions
pub(super) fn render_catalog_section(entries: &[CatalogView], manage: bool) -> Markup {
    html! {
        section id="catalog" class="flex flex-col gap-4" {
            div class="flex flex-wrap items-center gap-3" {
                p class="muted min-w-0 flex-1" {
                    "Servers the admin has set up for you to use with your own credential or account. "
                    "Store a credential or connect here and the tools appear in your session, named "
                    span class="mono" { "<name>_<tool>" }
                    ". Credentials are stored encrypted and are never shown again."
                }
                @if manage {
                    (drawer_trigger("new-entry", "New entry"))
                }
            }
            @if entries.is_empty() {
                div class="card card-b muted" { "No catalog entries." }
            }
            div class="cards" {
                @for view in entries {
                    (render_entry(view))
                }
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
        div class="page-head" {
            h1 { "Catalog" }
        }
        (render_flash_area(false))
        (render_catalog_section(entries, manage))
    };
    render_layout(state, user, "Catalog", Nav::Catalog, &content)
}

/// Every user's personal servers, the swap target of the admin actions
pub(super) fn render_admin_section(backends: &[AdminPersonalBackend]) -> Markup {
    html! {
        section id="admin-personal" class="card" {
            div class="card-h" {
                h2 { "Personal MCP servers" }
                span class="muted" { (backends.len()) }
            }
            div class="card-b" {
                p class="muted" {
                    "The servers users brought themselves. Disabling one takes its tools out of the "
                    "owner's session; header values are never shown."
                }
            }
            @if backends.is_empty() {
                div class="card-b muted" { "No personal servers yet." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Personal MCP servers" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Owner" }
                                th { "Prefix" }
                                th { "URL" }
                                th { "State" }
                                th { "Status" }
                                th { "Actions" }
                            }
                        }
                        tbody {
                            @for backend in backends {
                                @let base = format!(
                                    "/ui/actions/admin/personal-backends/{}/{}",
                                    backend.owner_id, backend.prefix
                                );
                                tr {
                                    td { (owner_label(backend)) }
                                    td { span class="mono" { (backend.prefix) } }
                                    td class="wrap break-all" { (backend.url) }
                                    td { (enabled_badge(backend.enabled)) }
                                    td class="wrap" {
                                        (status_cell(backend.last_ok_at, backend.last_error_at, backend.last_error.as_deref()))
                                    }
                                    td {
                                        div class="flex flex-wrap items-start gap-2" {
                                            (enabled_toggle(&format!("{base}/enabled"), ADMIN_PERSONAL, backend.enabled))
                                            button
                                                class="btn sm danger"
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
        div class="page-head" {
            h1 { "Personal MCP servers" }
        }
        (render_flash_area(false))
        (render_admin_section(backends))
    };
    render_layout(state, user, "Personal MCP servers", Nav::Admin, &content)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use chrono::Duration as Span;
    use uuid::Uuid;

    use super::*;
    use crate::personal::CatalogItem;
    use crate::personal::ConnectionStatus;
    use crate::server::tests::test_state;
    use crate::store::{SealedColumns, User, UserCredential};
    use crate::upstream_oauth::ClientCredentials;

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
            auth: crate::personal::CatalogAuth::Fields,
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
            connection: None,
            manage,
        }
    }

    fn oauth_item(name: &str) -> CatalogItem {
        CatalogItem {
            credential_fields: Vec::new(),
            auth: CatalogAuth::OAuth {
                client: Some(ClientCredentials {
                    client_id: String::from("axon-client"),
                    client_secret: Some(String::from("hunter2-client-secret")),
                }),
                scopes: vec![String::from("read"), String::from("write")],
                client_unusable: false,
            },
            ..item(name, CatalogSource::Database, true)
        }
    }

    fn connection(last_error: Option<&str>) -> ConnectionStatus {
        ConnectionStatus {
            backend: String::from("linear"),
            issuer: String::from("https://auth.example.com"),
            expires_at: Utc::now() + Span::hours(1),
            last_error: last_error.map(str::to_owned),
            last_error_at: last_error.map(|_| Utc::now()),
            created_at: Utc::now(),
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

        assert!(html.contains("from backend config"));
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
    fn field_rows_prefill_the_existing_fields_and_end_with_an_empty_row() {
        let none = field_rows(&[]).into_string();
        assert_eq!(none.matches("name=\"field_name\"").count(), FIELD_ROWS);

        let two = [field("token", Some("API token")), field("org", None)];
        let html = field_rows(&two).into_string();
        assert_eq!(html.matches("name=\"field_name\"").count(), FIELD_ROWS);
        assert!(html.contains("value=\"token\""));
        assert!(html.contains("value=\"API token\""));
        assert!(html.contains("value=\"Bearer \""));
        assert!(html.contains("value=\"org\""));

        let many: Vec<CredentialField> = (0..FIELD_ROWS + 2)
            .map(|index| field(&format!("f{index}"), None))
            .collect();
        let html = field_rows(&many).into_string();
        assert_eq!(html.matches("name=\"field_name\"").count(), FIELD_ROWS + 3);
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

    #[test]
    fn an_oauth_entry_offers_connect_and_no_credential_form() {
        let entries = [view(oauth_item("linear"), None, false)];
        let html = render_catalog_section(&entries, false).into_string();

        assert!(html.contains(">Not connected<"));
        assert!(html.contains("hx-post=\"/ui/actions/catalog/linear/connect\""));
        assert!(html.contains(">Connect<"));
        assert!(!html.contains("disconnect"));
        assert!(!html.contains("type=\"password\""));
        assert!(!html.contains("/credential"));
        assert!(!html.contains("Uses your sign-in"));
    }

    #[test]
    fn a_connected_entry_shows_its_expiry_and_can_be_disconnected() {
        let mut entry = view(oauth_item("linear"), None, false);
        entry.connection = Some(connection(None));
        let html = render_catalog_section(&[entry], false).into_string();

        assert!(html.contains(">Connected<"));
        assert!(html.contains("token expires "));
        assert!(html.contains(">Reconnect<"));
        assert!(html.contains("/ui/actions/catalog/linear/disconnect"));
        assert!(!html.contains("Reconnect needed"));
    }

    #[test]
    fn a_failed_refresh_asks_to_reconnect_and_escapes_the_error() {
        let mut entry = view(oauth_item("linear"), None, false);
        entry.connection = Some(connection(Some("invalid_grant <revoked>")));
        let html = render_catalog_section(&[entry], false).into_string();

        assert!(html.contains(">Reconnect needed<"));
        assert!(html.contains("invalid_grant &lt;revoked&gt;"));
        assert!(html.contains(">Reconnect<"));
        assert!(html.contains("/ui/actions/catalog/linear/disconnect"));
        assert!(!html.contains(">Connected<"));
    }

    #[test]
    fn a_passthrough_entry_has_no_buttons_and_no_forms() {
        let passthrough = CatalogItem {
            credential_fields: Vec::new(),
            auth: CatalogAuth::Passthrough(crate::config::PassthroughConfig {
                grant: crate::config::PassthroughGrant::TokenExchange,
                provider: String::from("pocket"),
                audience: None,
                scope: None,
                resource: None,
                assertion_scope: None,
            }),
            ..item("internal", CatalogSource::Config, true)
        };
        let html = render_catalog_section(&[view(passthrough, None, false)], false).into_string();

        assert!(html.contains("Uses your sign-in"));
        assert!(!html.contains("<form"));
        assert!(!html.contains("<button"));
        assert!(!html.contains("type=\"password\""));
    }

    #[test]
    fn the_admin_form_never_echoes_the_client_secret() {
        let entries = [view(oauth_item("linear"), None, true)];
        let html = render_catalog_section(&entries, true).into_string();

        assert!(html.contains("value=\"axon-client\""));
        assert!(html.contains("value=\"read write\""));
        assert!(html.contains("<option value=\"oauth\" selected>"));
        assert!(html.contains("name=\"clear_oauth_secret\""));
        assert!(html.contains("stored; leave empty to keep it"));
        assert!(!html.contains("hunter2"));
        // the create form has a secret input but nothing stored to clear
        assert_eq!(html.matches("name=\"oauth_client_secret\"").count(), 2);
        assert_eq!(html.matches("name=\"clear_oauth_secret\"").count(), 1);
    }
}
