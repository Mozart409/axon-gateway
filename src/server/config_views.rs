//! HTML rendering (maud) for the configuration pages under `/ui/admin/config`:
//! shared backends, gateway toolsets, OIDC providers and the global settings.
//!
//! Like `admin_views`, these are pure view functions. The edit sections and the
//! settings section are also the fragments an action answers with
//! (`hx-target` the section's id, `hx-swap="outerHTML"`); creating and deleting
//! answer with an `HX-Redirect`. Forms only render for users who may write, the
//! service layer in `config_api` still decides. A secret value is never
//! rendered: the forms show whether one is set, and an empty secret input keeps
//! it.
//!
//! The create forms of the list pages sit in a slide-over drawer built on the
//! native Popover API (no script, which the page CSP would refuse anyway): a
//! trigger button with `popovertarget`, and a `popover` element with the
//! `.drawer` classes. The constraint attributes on the inputs (`required`,
//! `type="url"`, `pattern`, `maxlength`) only mirror what the server already
//! enforces; the server still validates every field.

use std::fmt::Display;

use maud::{Markup, html};

use super::AppState;
use super::admin_views::{render_flash_area, render_layout};
use super::config_api::{BackendView, ProviderSource, ProviderView, ToolsetView};
use super::shell::{Nav, icon};
use crate::config::{
    BackendConfig, CredentialField, CredentialMode, GatewaySettings, OidcProviderConfig,
    PassthroughConfig, PassthroughGrant, ToolsetConfig, TransportType,
};
use crate::store::SessionUser;
use crate::upstream_oauth::redirect_uri;

const EDIT: &str = "#config-edit";
const SETTINGS: &str = "#config-settings";

/// Empty header and environment rows on the backend forms
const SECRET_ROWS: usize = 3;

/// A stored header or variable: its fixed name, a value that is empty to keep
/// it and the "remove" checkbox
const STORED_ROW: &str = "grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)_auto] items-center gap-2";
/// An empty row for a new header or variable
const NEW_ROW: &str = "grid grid-cols-[minmax(0,1fr)_minmax(0,2fr)] gap-2";
/// The body of a card that holds a form
const FORM_BODY: &str = "card-b flex flex-col gap-4";

/// What the backend forms need besides the backend itself
#[derive(Debug, Clone, Copy)]
pub(super) struct FormEnv<'a> {
    /// The gateway's public URL, for the addresses the OAuth section names
    base_url: &'a str,
    /// The ids of the configured OIDC providers, the choices of passthrough
    providers: &'a [String],
}

impl<'a> FormEnv<'a> {
    pub(super) fn new(base_url: &'a str, providers: &'a [String]) -> Self {
        Self {
            base_url,
            providers,
        }
    }
}

/// The pages the sub-navigation links to
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Section {
    Backends,
    Toolsets,
    Providers,
    Settings,
}

/// What the viewer may see and do on the configuration pages
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub(super) struct PageCtx {
    /// Backends and toolsets are readable (`backends.view` or `backends.manage`)
    pub read_backends: bool,
    /// Providers and settings are readable (`gateway.admin`)
    pub read_gateway: bool,
    /// The forms of this page render and work
    pub can_write: bool,
    /// `AXON_ALLOW_STDIO`: stdio backends may be saved
    pub allow_stdio: bool,
}

fn when(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
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

fn set_badge(set: bool) -> Markup {
    html! {
        @if set {
            span class="pill ok" { "set" }
        } @else {
            span class="muted" { "-" }
        }
    }
}

/// One entry per line of a list field
fn lines(items: &[String]) -> String {
    items.join("\n")
}

/// The value of a credential mode, as the form and the JSON API spell it
fn mode_value(mode: CredentialMode) -> &'static str {
    match mode {
        CredentialMode::Shared => "shared",
        CredentialMode::PerUser => "per_user",
        CredentialMode::OAuth => "oauth",
        CredentialMode::Passthrough => "passthrough",
    }
}

/// The credential mode as a table cell and a note read it
fn mode_name(mode: CredentialMode) -> &'static str {
    match mode {
        CredentialMode::Shared => "shared",
        CredentialMode::PerUser => "per user",
        CredentialMode::OAuth => "OAuth",
        CredentialMode::Passthrough => "passthrough",
    }
}

fn transport_name(transport: TransportType) -> &'static str {
    match transport {
        TransportType::Sse => "sse",
        TransportType::Http => "http",
        TransportType::Stdio => "stdio",
    }
}

// -- drawer -------------------------------------------------------------------

/// The button that opens the drawer `id`
pub(super) fn drawer_trigger(id: &str, label: &str) -> Markup {
    html! {
        button class="btn sm primary" type="button" popovertarget=(id) {
            (icon("plus"))
            (label)
        }
    }
}

/// The header of the drawer `id`: its title and the close button
pub(super) fn drawer_head(id: &str, title: &str) -> Markup {
    html! {
        div class="drawer-h" {
            h2 id=(format!("{id}-title")) { (title) }
            span class="spacer" {}
            button
                class="btn icon ghost"
                type="button"
                aria-label="Close"
                popovertarget=(id)
                popovertargetaction="hide"
            {
                (icon("x"))
            }
        }
    }
}

/// The footer of the drawer `id`: cancel and the submit button of its form
pub(super) fn drawer_foot(id: &str, submit: &str) -> Markup {
    html! {
        div class="drawer-f" {
            button class="btn" type="button" popovertarget=(id) popovertargetaction="hide" {
                "Cancel"
            }
            button class="btn primary" type="submit" { (submit) }
        }
    }
}

// -- fields -------------------------------------------------------------------

/// The constraints a text input carries, each one a rule the server enforces
#[derive(Clone, Copy)]
struct Rule<'a> {
    required: bool,
    /// `type="url"`
    url: bool,
    pattern: Option<&'a str>,
    /// Shown under the field while the browser flags it
    error: &'a str,
}

impl Rule<'_> {
    fn constrained(&self) -> bool {
        self.required || self.url || self.pattern.is_some()
    }
}

const NO_RULE: Rule<'static> = Rule {
    required: false,
    url: false,
    pattern: None,
    error: "",
};
const REQUIRED_RULE: Rule<'static> = Rule {
    required: true,
    url: false,
    pattern: None,
    error: "Required.",
};

fn text_field(scope: &str, label: &str, name: &str, value: &str, rule: Rule) -> Markup {
    let id = format!("{scope}-{name}");
    html! {
        div class="field" {
            label for=(id) { (label) }
            input
                class="input"
                id=(id)
                type=(if rule.url { "url" } else { "text" })
                name=(name)
                value=(value)
                required[rule.required]
                pattern=[rule.pattern]
                autocomplete="off";
            @if rule.constrained() {
                p class="field-error" { (rule.error) }
            }
        }
    }
}

fn number_field(scope: &str, label: &str, name: &str, value: Option<impl Display>) -> Markup {
    let value = value.map(|value| value.to_string()).unwrap_or_default();
    let id = format!("{scope}-{name}");
    html! {
        div class="field" {
            label for=(id) { (label) }
            input
                class="input"
                id=(id)
                type="number"
                min="0"
                name=(name)
                value=(value)
                autocomplete="off";
            p class="field-error" { "Enter a whole number, 0 or more." }
        }
    }
}

fn lines_field(scope: &str, label: &str, name: &str, items: &[String]) -> Markup {
    let id = format!("{scope}-{name}");
    html! {
        div class="field" {
            label for=(id) { (label) " (one per line)" }
            textarea class="input mono" id=(id) name=(name) rows="3" { (lines(items)) }
        }
    }
}

fn check_field(label: &str, name: &str, checked: bool) -> Markup {
    html! {
        label class="flex items-center gap-2" {
            input type="checkbox" name=(name) value="true" checked[checked];
            (label)
        }
    }
}

/// A select over `(value, label)` options
fn select_field(
    scope: &str,
    label: &str,
    name: &str,
    options: &[(&str, &str)],
    selected: &str,
) -> Markup {
    let id = format!("{scope}-{name}");
    html! {
        div class="field" {
            label for=(id) { (label) }
            select class="input" id=(id) name=(name) {
                @for (value, text) in options {
                    option value=(value) selected[*value == selected] { (text) }
                }
            }
        }
    }
}

/// A password input for a secret whose stored value is never shown: empty keeps
/// it, and a "clear" checkbox appears while one is stored
fn secret_field(scope: &str, label: &str, name: &str, clear_name: &str, set: bool) -> Markup {
    let id = format!("{scope}-{name}");
    html! {
        div class="field" {
            label for=(id) { (label) }
            input
                class="input"
                id=(id)
                type="password"
                name=(name)
                placeholder=(if set { "stored; leave empty to keep it" } else { "" })
                autocomplete="new-password";
        }
        @if set {
            label class="flex items-center gap-2" {
                input type="checkbox" name=(clear_name) value="true";
                "Clear the stored value"
            }
        }
    }
}

/// Rows of a name and a password-type value for headers or variables: the
/// stored ones first (name fixed, value empty keeps it, a checkbox removes the
/// row), then empty ones for new entries. The keys repeat.
fn secret_rows(prefix: &str, placeholder: &str, existing: &[String]) -> Markup {
    let name_key = format!("{prefix}_name");
    let value_key = format!("{prefix}_value");
    let remove_key = format!("{prefix}_remove");
    html! {
        div class="flex flex-col gap-2" {
            @for name in existing {
                div class=(STORED_ROW) {
                    input
                        class="input mono"
                        type="text"
                        name=(name_key)
                        value=(name)
                        aria-label="Name"
                        readonly;
                    input
                        class="input"
                        type="password"
                        name=(value_key)
                        placeholder="stored; leave empty to keep it"
                        aria-label="Value"
                        autocomplete="new-password";
                    label class="flex items-center gap-1 muted" {
                        input type="checkbox" name=(remove_key) value=(name);
                        "remove"
                    }
                }
            }
            @for _ in 0..SECRET_ROWS {
                div class=(NEW_ROW) {
                    input
                        class="input mono"
                        type="text"
                        name=(name_key)
                        placeholder=(format!("e.g. {placeholder}"))
                        aria-label="Name"
                        autocomplete="off";
                    input
                        class="input"
                        type="password"
                        name=(value_key)
                        placeholder="value"
                        aria-label="Value"
                        autocomplete="new-password";
                }
            }
        }
    }
}

/// The page frame: title, sub-navigation, the flash area and the body
fn page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    current: Section,
    title: &str,
    intro: &str,
    body: &Markup,
) -> Markup {
    let mut links = Vec::new();
    if ctx.read_backends {
        links.push((Section::Backends, "/ui/admin/config/backends", "Backends"));
        links.push((
            Section::Toolsets,
            "/ui/admin/config/toolsets",
            "Gateway toolsets",
        ));
    }
    if ctx.read_gateway {
        links.push((
            Section::Providers,
            "/ui/admin/config/oidc-providers",
            "OIDC providers",
        ));
        links.push((Section::Settings, "/ui/admin/config/settings", "Settings"));
    }
    let content = html! {
        div class="page-head" {
            div class="flex min-w-0 flex-1 flex-col gap-1" {
                p { (intro) }
            }
        }
        nav class="tabs" aria-label="Configuration" {
            @for (section, href, label) in &links {
                a class="tab" href=(href) aria-current=[(*section == current).then_some("page")] {
                    (label)
                }
            }
        }
        (render_flash_area(false))
        (body)
    };
    render_layout(state, user, title, Nav::Config, &content)
}

/// The link back to a list, above an edit section
fn back_to(href: &str, label: &str) -> Markup {
    html! {
        div {
            a class="btn sm ghost" href=(href) { (label) }
        }
    }
}

/// The "Saved." note an action answers with
fn saved_note() -> Markup {
    html! {
        div class="card-f" {
            span class="pill ok" role="status" { (icon("check")) "Saved." }
        }
    }
}

// -- backends -----------------------------------------------------------------

/// One row of the credential fields of a per-user backend: its key, label,
/// header and prefix. Unlike header values these are not secret, so the stored
/// rows show them.
fn credential_row(field: Option<&CredentialField>) -> Markup {
    let name = field.map_or("", |field| field.name.as_str());
    let label = field
        .and_then(|field| field.label.as_deref())
        .unwrap_or_default();
    let header = field.map_or("", |field| field.header.as_str());
    let prefix = field
        .and_then(|field| field.prefix.as_deref())
        .unwrap_or_default();
    html! {
        div class="form-grid" {
            input
                class="input mono"
                type="text"
                name="credential_name"
                value=(name)
                placeholder="e.g. api_key"
                aria-label="Key"
                autocomplete="off";
            input
                class="input"
                type="text"
                name="credential_label"
                value=(label)
                placeholder="e.g. API key"
                aria-label="Label"
                autocomplete="off";
            input
                class="input mono"
                type="text"
                name="credential_header"
                value=(header)
                placeholder="e.g. Authorization"
                aria-label="Header"
                autocomplete="off";
            input
                class="input mono"
                type="text"
                name="credential_prefix"
                value=(prefix)
                placeholder="e.g. Bearer "
                aria-label="Prefix"
                autocomplete="off";
        }
    }
}

/// The credential mode select and the section of each mode. Only the section
/// of the selected mode shows (a `:has()` rule in the stylesheet, no script);
/// all of them are in the form, and the server reads only the selected one.
fn credential_fields(
    scope: &str,
    view: Option<&BackendView>,
    config: &BackendConfig,
    env: FormEnv<'_>,
) -> Markup {
    let passthrough = config.passthrough.as_ref();
    let oauth = config.oauth.as_ref();
    let provider = passthrough.map_or("", |passthrough| passthrough.provider.as_str());
    let mut providers: Vec<(&str, &str)> = vec![("", "Choose a provider")];
    providers.extend(env.providers.iter().map(|id| (id.as_str(), id.as_str())));
    if !provider.is_empty() && !env.providers.iter().any(|id| id == provider) {
        providers.push((provider, provider));
    }
    let grant = match passthrough.map(|passthrough| passthrough.grant) {
        Some(PassthroughGrant::EntraObo) => "entra_obo",
        _ => "token_exchange",
    };
    let passthrough_text = |pick: fn(&PassthroughConfig) -> Option<&str>| {
        passthrough.and_then(pick).unwrap_or_default().to_owned()
    };
    let callback = redirect_uri(env.base_url);
    html! {
        (select_field(
            scope,
            "Credential mode",
            "credential_mode",
            &[
                ("shared", "Shared (one connection with the backend's token and headers)"),
                ("per_user", "Per user (each user stores their own credential)"),
                ("oauth", "OAuth (each user connects their account)"),
                ("passthrough", "Identity passthrough (the gateway exchanges the user's sign-in)"),
            ],
            mode_value(config.credential_mode),
        ))
        fieldset class="mode-section mode-per_user" {
            legend class="section-t" { "Per-user credential" }
            p class="hint" {
                "Each user enters a value per key. The gateway sends it in the header, "
                "after the prefix. Empty rows are ignored."
            }
            @for field in &config.credential_fields {
                (credential_row(Some(field)))
            }
            @for _ in 0..SECRET_ROWS {
                (credential_row(None))
            }
        }
        fieldset class="mode-section mode-oauth" {
            legend class="section-t" { "OAuth client" }
            p class="muted" {
                "Leave the client empty to use the gateway's client metadata document or dynamic registration. "
                "Users are sent back to " span class="mono" { (callback) } "."
            }
            (text_field(scope, "Client ID", "oauth_client_id", oauth.map_or("", |oauth| oauth.client_id.as_str()), NO_RULE))
            (secret_field(
                scope,
                "Client secret (empty for a public client)",
                "oauth_client_secret",
                "clear_oauth_secret",
                view.is_some_and(|view| view.oauth_client_secret_set),
            ))
            (lines_field(scope, "Scopes (empty uses the ones the backend advertises)", "oauth_scopes", oauth.map_or(&[], |oauth| oauth.scopes.as_slice())))
        }
        fieldset class="mode-section mode-passthrough" {
            legend class="section-t" { "Identity passthrough" }
            p class="hint" {
                "The gateway trades the user's sign-in token from this provider for one the backend accepts."
            }
            (select_field(
                scope,
                "Grant",
                "passthrough_grant",
                &[
                    ("token_exchange", "Token exchange (RFC 8693)"),
                    ("entra_obo", "Entra on-behalf-of"),
                ],
                grant,
            ))
            (select_field(scope, "OIDC provider", "passthrough_provider", &providers, provider))
            (text_field(scope, "Audience", "passthrough_audience", &passthrough_text(|passthrough| passthrough.audience.as_deref()), NO_RULE))
            (text_field(scope, "Scope", "passthrough_scope", &passthrough_text(|passthrough| passthrough.scope.as_deref()), NO_RULE))
            (text_field(scope, "Resource", "passthrough_resource", &passthrough_text(|passthrough| passthrough.resource.as_deref()), NO_RULE))
            (text_field(scope, "Assertion scope (Entra; default: the gateway's own API)", "passthrough_assertion_scope", &passthrough_text(|passthrough| passthrough.assertion_scope.as_deref()), NO_RULE))
        }
    }
}

fn backend_fields(view: Option<&BackendView>, ctx: PageCtx, env: FormEnv<'_>) -> Markup {
    let defaults = BackendConfig {
        transport: TransportType::Http,
        ..BackendConfig::default()
    };
    let config = view.map_or(&defaults, |view| &view.config);
    let args = config.args.clone().unwrap_or_default();
    let header_names: &[String] = view
        .map(|view| view.header_names.as_slice())
        .unwrap_or_default();
    let env_names: &[String] = view
        .map(|view| view.env_names.as_slice())
        .unwrap_or_default();
    let scope = if view.is_some() { "bk-edit" } else { "bk-new" };
    html! {
        @if view.is_none() {
            (text_field(scope, "Name", "name", "", REQUIRED_RULE))
        }
        div class="field" {
            label for=(format!("{scope}-transport")) { "Transport" }
            select class="input" id=(format!("{scope}-transport")) name="transport" {
                @for transport in [TransportType::Http, TransportType::Sse, TransportType::Stdio] {
                    option
                        value=(transport_name(transport))
                        selected[config.transport == transport]
                        disabled[transport == TransportType::Stdio && !ctx.allow_stdio]
                    {
                        (transport_name(transport))
                    }
                }
            }
        }
        @if !ctx.allow_stdio {
            div class="banner" {
                (icon("triangle-alert"))
                span { "stdio backends are off: start the gateway with AXON_ALLOW_STDIO=true." }
            }
        }
        (text_field(scope, "URL (http and sse)", "url", config.url.as_deref().unwrap_or_default(), NO_RULE))
        @if view.is_some() {
            p class="hint" { "Changing it needs the secrets entered again." }
        }
        (text_field(scope, "Command (stdio)", "command", config.command.as_deref().unwrap_or_default(), NO_RULE))
        (lines_field(scope, "Arguments (stdio)", "args", &args))
        (check_field("Enabled", "enabled", config.enabled))
        (lines_field(scope, "Allowed tools (empty exposes all)", "allowed_tools", &config.allowed_tools))
        div class="form-grid" {
            (number_field(scope, "Call timeout (s)", "timeout_secs", Some(config.timeout_secs)))
            (number_field(scope, "Health check every (s, 0 = off)", "health_check_interval_secs", Some(config.health_check_interval_secs)))
            (number_field(scope, "Failures before the breaker opens", "max_consecutive_failures", Some(config.max_consecutive_failures)))
            (number_field(scope, "Breaker cooldown (s)", "circuit_breaker_cooldown_secs", Some(config.circuit_breaker_cooldown_secs)))
            (number_field(scope, "Idle timeout (s, empty = gateway default)", "idle_timeout_secs", config.idle_timeout_secs))
        }
        (credential_fields(scope, view, config, env))
        (secret_field(
            scope,
            "Auth token (Bearer)",
            "auth_token",
            "clear_auth_token",
            view.is_some_and(|view| view.auth_token_set),
        ))
        div class="flex flex-col gap-1" {
            h3 class="section-t" { "Headers" }
            p class="hint" { "Values are secret. Empty rows are ignored." }
            div class="mt-1" { (secret_rows("header", "Authorization", header_names)) }
        }
        div class="flex flex-col gap-1" {
            h3 class="section-t" { "Environment (stdio)" }
            p class="hint" { "Values are secret. Empty rows are ignored." }
            div class="mt-1" { (secret_rows("env", "API_KEY", env_names)) }
        }
    }
}

fn backend_row(view: &BackendView) -> Markup {
    let config = &view.config;
    let target = config
        .url
        .as_deref()
        .or(config.command.as_deref())
        .unwrap_or_default();
    html! {
        tr {
            td {
                a class="mono" href=(format!("/ui/admin/config/backends/{}", config.name)) {
                    (config.name)
                }
            }
            td { (mode_name(config.credential_mode)) }
            td { (transport_name(config.transport)) }
            td { span class="mono" { (target) } }
            td { (enabled_badge(config.enabled)) }
            td { (set_badge(view.auth_token_set)) }
            td { (view.header_names.len()) }
        }
    }
}

/// `GET /ui/admin/config/backends`
pub(super) fn render_backends_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    env: FormEnv<'_>,
    backends: &[BackendView],
) -> Markup {
    let body = html! {
        section class="card" {
            div class="card-h" {
                h2 { "Backends" }
                span class="muted" { (backends.len()) }
                span class="spacer" {}
                @if ctx.can_write {
                    (drawer_trigger("new-backend", "Add a backend"))
                }
            }
            @if backends.is_empty() {
                div class="card-b muted" { "No backends in the database yet." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Backends" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Name" }
                                th { "Mode" }
                                th { "Transport" }
                                th { "Target" }
                                th { "State" }
                                th { "Auth token" }
                                th { "Headers" }
                            }
                        }
                        tbody {
                            @for view in backends {
                                (backend_row(view))
                            }
                        }
                    }
                }
            }
        }
        @if ctx.can_write {
            div id="new-backend" popover class="drawer" aria-labelledby="new-backend-title" {
                (drawer_head("new-backend", "Add a backend"))
                form
                    class="drawer-form"
                    hx-post="/ui/actions/admin/config/backends"
                    hx-swap="none"
                {
                    div class="drawer-b" { (backend_fields(None, ctx, env)) }
                    (drawer_foot("new-backend", "Create backend"))
                }
            }
        }
    };
    page(
        state,
        user,
        ctx,
        Section::Backends,
        "Backends",
        "The shared MCP backends the gateway aggregates. A change applies on every replica within moments.",
        &body,
    )
}

/// The edit section of a backend, also the fragment a save answers with
pub(super) fn render_backend_edit(
    view: &BackendView,
    ctx: PageCtx,
    env: FormEnv<'_>,
    saved: bool,
) -> Markup {
    let config = &view.config;
    let base = format!("/ui/actions/admin/config/backends/{}", config.name);
    html! {
        section id="config-edit" class="card" {
            div class="card-h" {
                h2 class="mono" { (config.name) }
                (enabled_badge(config.enabled))
            }
            div class="card-b flex flex-col gap-2" {
                p class="muted" {
                    "Created " (when(view.created_at)) ", changed " (when(view.updated_at)) ". "
                    "Credential mode: " span class="mono" { (mode_name(config.credential_mode)) } "."
                }
            }
            @if saved {
                (saved_note())
            }
            @if ctx.can_write {
                form hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                    div class=(FORM_BODY) { (backend_fields(Some(view), ctx, env)) }
                    div class="card-f" {
                        button class="btn primary" type="submit" { "Save backend" }
                    }
                }
                div class="card-f" {
                    button
                        class="btn danger"
                        type="button"
                        hx-post=(format!("{base}/delete"))
                        hx-swap="none"
                        hx-confirm=(format!("Delete the backend {}?", config.name))
                    {
                        (icon("trash-2"))
                        "Delete backend"
                    }
                }
            }
        }
    }
}

/// `GET /ui/admin/config/backends/{name}`
pub(super) fn render_backend_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    env: FormEnv<'_>,
    view: &BackendView,
) -> Markup {
    let body = html! {
        (back_to("/ui/admin/config/backends", "All backends"))
        (render_backend_edit(view, ctx, env, false))
    };
    page(
        state,
        user,
        ctx,
        Section::Backends,
        &view.config.name,
        "A shared backend.",
        &body,
    )
}

// -- toolsets -----------------------------------------------------------------

fn toolset_fields(config: Option<&ToolsetConfig>) -> Markup {
    let empty = ToolsetConfig {
        name: String::new(),
        tools: Vec::new(),
        backends: Vec::new(),
        description: None,
    };
    let toolset = config.unwrap_or(&empty);
    let scope = if config.is_some() {
        "ts-edit"
    } else {
        "ts-new"
    };
    html! {
        @if config.is_none() {
            (text_field(scope, "Name", "name", "", REQUIRED_RULE))
        }
        (text_field(scope, "Description", "description", toolset.description.as_deref().unwrap_or_default(), NO_RULE))
        (lines_field(scope, "Tool patterns (globs such as backend_*)", "tools", &toolset.tools))
        (lines_field(scope, "Backends (empty = all)", "backends", &toolset.backends))
    }
}

/// `GET /ui/admin/config/toolsets`
pub(super) fn render_toolsets_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    toolsets: &[ToolsetView],
) -> Markup {
    let body = html! {
        section class="card" {
            div class="card-h" {
                h2 { "Gateway toolsets" }
                span class="muted" { (toolsets.len()) }
                span class="spacer" {}
                @if ctx.can_write {
                    (drawer_trigger("new-toolset", "Add a toolset"))
                }
            }
            div class="card-b" {
                p class="muted" {
                    "A toolset exposes a subset of the tools at " span class="mono" { "/mcp/toolset/{name}" } "."
                }
            }
            @if toolsets.is_empty() {
                div class="card-b muted" { "No toolsets in the database yet." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Gateway toolsets" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Name" }
                                th { "Description" }
                                th { "Tools" }
                                th { "Backends" }
                            }
                        }
                        tbody {
                            @for view in toolsets {
                                tr {
                                    td {
                                        a class="mono" href=(format!("/ui/admin/config/toolsets/{}", view.config.name)) {
                                            (view.config.name)
                                        }
                                    }
                                    td { (view.config.description.as_deref().unwrap_or_default()) }
                                    td { span class="mono" { (view.config.tools.join(", ")) } }
                                    td { (view.config.backends.join(", ")) }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if ctx.can_write {
            div id="new-toolset" popover class="drawer" aria-labelledby="new-toolset-title" {
                (drawer_head("new-toolset", "Add a toolset"))
                form
                    class="drawer-form"
                    hx-post="/ui/actions/admin/config/toolsets"
                    hx-swap="none"
                {
                    div class="drawer-b" { (toolset_fields(None)) }
                    (drawer_foot("new-toolset", "Create toolset"))
                }
            }
        }
    };
    page(
        state,
        user,
        ctx,
        Section::Toolsets,
        "Gateway toolsets",
        "Gateway toolsets, as opposed to the toolsets people make for themselves.",
        &body,
    )
}

/// The edit section of a toolset, also the fragment a save answers with
pub(super) fn render_toolset_edit(view: &ToolsetView, ctx: PageCtx, saved: bool) -> Markup {
    let base = format!("/ui/actions/admin/config/toolsets/{}", view.config.name);
    html! {
        section id="config-edit" class="card" {
            div class="card-h" {
                h2 class="mono" { (view.config.name) }
            }
            div class="card-b" {
                p class="muted" {
                    "Created " (when(view.created_at)) ", changed " (when(view.updated_at)) "."
                }
            }
            @if saved {
                (saved_note())
            }
            @if ctx.can_write {
                form hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                    div class=(FORM_BODY) { (toolset_fields(Some(&view.config))) }
                    div class="card-f" {
                        button class="btn primary" type="submit" { "Save toolset" }
                    }
                }
                div class="card-f" {
                    button
                        class="btn danger"
                        type="button"
                        hx-post=(format!("{base}/delete"))
                        hx-swap="none"
                        hx-confirm=(format!("Delete the toolset {}?", view.config.name))
                    {
                        (icon("trash-2"))
                        "Delete toolset"
                    }
                }
            }
        }
    }
}

/// `GET /ui/admin/config/toolsets/{name}`
pub(super) fn render_toolset_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    view: &ToolsetView,
) -> Markup {
    let body = html! {
        (back_to("/ui/admin/config/toolsets", "All toolsets"))
        (render_toolset_edit(view, ctx, false))
    };
    page(
        state,
        user,
        ctx,
        Section::Toolsets,
        &view.config.name,
        "A gateway toolset.",
        &body,
    )
}

// -- OIDC providers -----------------------------------------------------------

/// `[a-z0-9-]+`, the rule `Config::validate` holds a provider id to
const PROVIDER_ID: Rule<'static> = Rule {
    required: true,
    url: false,
    pattern: Some(r"[a-z0-9\-]+"),
    error: "Lowercase letters, digits and dashes only.",
};
/// The issuer must parse as a URL
const ISSUER: Rule<'static> = Rule {
    required: true,
    url: true,
    pattern: None,
    error: "Enter the issuer as a full URL, such as https://idp.example.com.",
};

fn provider_fields(view: Option<&ProviderView>) -> Markup {
    let defaults = OidcProviderConfig::default();
    let config = view.map_or(&defaults, |view| &view.config);
    let scope = if view.is_some() {
        "oidc-edit"
    } else {
        "oidc-new"
    };
    html! {
        @if view.is_none() {
            (text_field(scope, "Id (a-z, 0-9, -)", "id", "", PROVIDER_ID))
        }
        (text_field(scope, "Button label", "display_name", config.display_name.as_deref().unwrap_or_default(), NO_RULE))
        (text_field(scope, "Issuer URL", "issuer", &config.issuer, ISSUER))
        (text_field(scope, "Client ID", "client_id", &config.client_id, REQUIRED_RULE))
        (secret_field(
            scope,
            "Client secret (empty for a public client)",
            "client_secret",
            "clear_client_secret",
            view.is_some_and(|view| view.client_secret_set),
        ))
        (lines_field(scope, "Scopes", "scopes", &config.scopes))
        (text_field(scope, "Groups claim", "groups_claim", &config.groups_claim, NO_RULE))
        (lines_field(scope, "Allowed email domains (empty = any)", "allowed_email_domains", &config.allowed_email_domains))
        (lines_field(scope, "Admin groups", "admin_groups", &config.admin_groups))
        (check_field("Accept access tokens this provider issued as bearer tokens", "accept_access_tokens", config.accept_access_tokens))
        (text_field(scope, "Access token audience (default: client ID)", "access_token_audience", config.access_token_audience.as_deref().unwrap_or_default(), NO_RULE))
        (check_field("Fetch groups from Microsoft Graph on a groups overage", "graph_overage", config.graph_overage))
        (text_field(scope, "Graph URL (default: graph.microsoft.com)", "graph_url", config.graph_url.as_deref().unwrap_or_default(), NO_RULE))
        (text_field(scope, "SCIM match claim (default: sub)", "scim_match_claim", config.scim_match_claim.as_deref().unwrap_or_default(), NO_RULE))
        (number_field(scope, "Position (empty: last on create, unchanged on save)", "position", view.and_then(|view| view.position)))
    }
}

fn source_badge(source: ProviderSource) -> Markup {
    html! {
        @if source == ProviderSource::Env {
            span class="pill accent" { "env" }
        } @else {
            span class="pill" { "database" }
        }
    }
}

/// One address to register at the identity provider, with its copy button
fn copy_value(label: &str, hint: &str, value: &str) -> Markup {
    html! {
        div class="flex flex-col gap-1" {
            p class="section-t" { (label) }
            div class="copyline" {
                code class="mono" { (value) }
                button
                    class="btn sm ghost"
                    type="button"
                    data-copy=(value)
                    aria-label=(format!("Copy the {}", label.to_lowercase()))
                {
                    "Copy"
                }
            }
            p class="hint" { (hint) }
        }
    }
}

/// The card with the addresses the identity provider must be told about
fn idp_values(base_url: &str) -> Markup {
    let base = base_url.trim_end_matches('/');
    html! {
        section class="card" {
            div class="card-h" { h2 { "Values for your identity provider" } }
            div class=(FORM_BODY) {
                (copy_value(
                    "Redirect URI",
                    "Where the provider sends users after they sign in.",
                    &format!("{base}/auth/callback"),
                ))
                (copy_value(
                    "Post-logout redirect URI",
                    "Where the provider sends users after they sign out.",
                    &format!("{base}/"),
                ))
                (copy_value(
                    "Upstream OAuth callback",
                    "For OAuth backends; register it with the backend's authorization server.",
                    &redirect_uri(base_url),
                ))
                p class="muted" {
                    "Keep each issuer URL exactly as the provider writes it in its tokens. "
                    "Users are identified by issuer and subject, so a changed spelling "
                    "(localhost vs 127.0.0.1, a trailing slash) creates new, empty users."
                }
                p class="hint" id="copy-feedback" aria-live="polite" { "" }
            }
        }
        script src="/static/copy-url.js" defer {}
    }
}

/// `GET /ui/admin/config/oidc-providers`
pub(super) fn render_providers_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    providers: &[ProviderView],
) -> Markup {
    let body = html! {
        (idp_values(&state.base_url))
        section class="card" {
            div class="card-h" {
                h2 { "OIDC providers" }
                span class="muted" { (providers.len()) }
                span class="spacer" {}
                @if ctx.can_write {
                    (drawer_trigger("new-provider", "Add a provider"))
                }
            }
            div class="card-b" {
                p class="muted" {
                    "The login buttons, in this order. The provider set by the AXON_OIDC_* environment is read-only. "
                    "Provider changes apply on every replica within moments."
                }
            }
            @if providers.is_empty() {
                div class="card-b muted" {
                    "No providers: the break-glass link (axon-gateway admin login-link) is the way in."
                }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="OIDC providers" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Id" }
                                th { "Source" }
                                th { "Issuer" }
                                th { "Client ID" }
                                th { "Scopes" }
                                th { "Admin groups" }
                                th { "Secret" }
                            }
                        }
                        tbody {
                            @for view in providers {
                                tr {
                                    td {
                                        a class="mono" href=(format!("/ui/admin/config/oidc-providers/{}", view.config.id)) {
                                            (view.config.id)
                                        }
                                    }
                                    td { (source_badge(view.source)) }
                                    td { span class="mono" { (view.config.issuer) } }
                                    td { span class="mono" { (view.config.client_id) } }
                                    td { span class="mono" { (view.config.scopes.join(" ")) } }
                                    td { (view.config.admin_groups.join(", ")) }
                                    td { (set_badge(view.client_secret_set)) }
                                }
                            }
                        }
                    }
                }
            }
        }
        @if ctx.can_write {
            div id="new-provider" popover class="drawer" aria-labelledby="new-provider-title" {
                (drawer_head("new-provider", "Add a provider"))
                form
                    class="drawer-form"
                    hx-post="/ui/actions/admin/config/oidc-providers"
                    hx-swap="none"
                {
                    div class="drawer-b" { (provider_fields(None)) }
                    (drawer_foot("new-provider", "Create provider"))
                }
            }
        }
    };
    page(
        state,
        user,
        ctx,
        Section::Providers,
        "OIDC providers",
        "Who may log in to the dashboard.",
        &body,
    )
}

/// The edit section of a provider, also the fragment a save answers with. The
/// environment provider is shown read-only.
pub(super) fn render_provider_edit(view: &ProviderView, ctx: PageCtx, saved: bool) -> Markup {
    let config = &view.config;
    let base = format!("/ui/actions/admin/config/oidc-providers/{}", config.id);
    html! {
        section id="config-edit" class="card" {
            div class="card-h" {
                h2 class="mono" { (config.id) }
                (source_badge(view.source))
            }
            @if view.source == ProviderSource::Env {
                div class="card-b flex flex-col gap-3" {
                    p class="muted" {
                        "This provider is set by the environment (AXON_OIDC_*) and cannot be changed here."
                    }
                    dl class="kv" {
                        dt { "Issuer" }
                        dd { span class="mono" { (config.issuer) } }
                        dt { "Client ID" }
                        dd { span class="mono" { (config.client_id) } }
                        dt { "Client secret" }
                        dd { (set_badge(view.client_secret_set)) }
                        dt { "Admin groups" }
                        dd { (config.admin_groups.join(", ")) }
                    }
                }
            } @else {
                @if let Some(at) = view.updated_at {
                    div class="card-b" { p class="muted" { "Changed " (when(at)) "." } }
                }
                @if saved {
                    (saved_note())
                }
                @if ctx.can_write {
                    form hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                        div class=(FORM_BODY) { (provider_fields(Some(view))) }
                        div class="card-f" {
                            button class="btn primary" type="submit" { "Save provider" }
                        }
                    }
                    div class="card-f" {
                        button
                            class="btn danger"
                            type="button"
                            hx-post=(format!("{base}/delete"))
                            hx-swap="none"
                            hx-confirm=(format!("Delete the provider {}? People who log in with it can no longer do so.", config.id))
                        {
                            (icon("trash-2"))
                            "Delete provider"
                        }
                    }
                }
            }
        }
    }
}

/// `GET /ui/admin/config/oidc-providers/{id}`
pub(super) fn render_provider_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    view: &ProviderView,
) -> Markup {
    let body = html! {
        (back_to("/ui/admin/config/oidc-providers", "All providers"))
        (render_provider_edit(view, ctx, false))
    };
    page(
        state,
        user,
        ctx,
        Section::Providers,
        &view.config.id,
        "An OIDC provider.",
        &body,
    )
}

// -- settings -----------------------------------------------------------------

/// The settings form, also the fragment a save answers with
pub(super) fn render_settings_section(
    settings: &GatewaySettings,
    ctx: PageCtx,
    saved: bool,
) -> Markup {
    let personal = &settings.personal_backends;
    let scope = "settings";
    html! {
        section id="config-settings" class="card" {
            div class="card-h" {
                h2 { "Gateway settings" }
            }
            div class="card-b" {
                p class="muted" {
                    "Personal backend settings apply after a restart; the others on every replica within moments."
                }
            }
            @if saved {
                (saved_note())
            }
            @if ctx.can_write {
                form hx-post="/ui/actions/admin/config/settings" hx-target=(SETTINGS) hx-swap="outerHTML" {
                    div class=(FORM_BODY) {
                        div class="form-grid" {
                            (number_field(scope, "Rate limit (requests per minute per token, 0 = unlimited)", "rate_limit_per_minute", Some(settings.rate_limit_per_minute)))
                            (number_field(scope, "Idle timeout (s, 0 = always connected)", "idle_timeout_secs", Some(settings.idle_timeout_secs)))
                        }
                        (lines_field(scope, "Allowed hosts (besides loopback and the base URL)", "allowed_hosts", &settings.allowed_hosts))
                        h3 class="section-t" { "Personal backends" }
                        (check_field("Let people add personal backends and store catalog credentials", "personal_enabled", personal.enabled))
                        div class="form-grid" {
                            (number_field(scope, "Max personal backends per user", "personal_max_per_user", Some(personal.max_per_user)))
                            (number_field(scope, "Max tool calls per minute per user (0 = unlimited)", "personal_max_calls_per_minute", Some(personal.max_calls_per_minute)))
                            (number_field(scope, "Max open connections per replica", "personal_max_instances", Some(personal.max_instances)))
                        }
                        (lines_field(scope, "Egress allow (hosts or CIDRs, empty = any public host)", "personal_egress_allow", &personal.egress_allow))
                        (lines_field(scope, "Egress deny (hosts or CIDRs)", "personal_egress_deny", &personal.egress_deny))
                    }
                    div class="card-f" {
                        button class="btn primary" type="submit" { "Save settings" }
                    }
                }
            } @else {
                div class="card-b" {
                    dl class="kv" {
                        dt { "Rate limit" }
                        dd { (settings.rate_limit_per_minute) }
                        dt { "Idle timeout" }
                        dd { (settings.idle_timeout_secs) " s" }
                        dt { "Allowed hosts" }
                        dd { (settings.allowed_hosts.join(", ")) }
                    }
                }
            }
        }
    }
}

/// `GET /ui/admin/config/settings`
pub(super) fn render_settings_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    settings: &GatewaySettings,
) -> Markup {
    let body = render_settings_section(settings, ctx, false);
    page(
        state,
        user,
        ctx,
        Section::Settings,
        "Settings",
        "Limits and host names of the gateway.",
        &body,
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::config::UpstreamOAuthConfig;
    use crate::server::tests::test_state;
    use crate::store::User;

    const CTX: PageCtx = PageCtx {
        read_backends: true,
        read_gateway: true,
        can_write: true,
        allow_stdio: false,
    };

    const BASE: &str = "https://axon.example.com";

    fn env(providers: &[String]) -> FormEnv<'_> {
        FormEnv::new(BASE, providers)
    }

    fn session() -> SessionUser {
        SessionUser {
            user: User {
                id: Uuid::nil(),
                issuer: String::from("https://idp.example"),
                subject: String::from("sub-1"),
                email: None,
                display_name: None,
                groups: Vec::new(),
                is_admin: true,
            },
            provider_id: String::from("pocket"),
            csrf_token: String::from("tok-123"),
        }
    }

    fn provider(id: &str) -> ProviderView {
        ProviderView {
            source: ProviderSource::Database,
            config: OidcProviderConfig {
                id: id.to_owned(),
                issuer: String::from("https://idp.example"),
                client_id: String::from("axon"),
                admin_groups: vec![String::from("axon-admins")],
                ..OidcProviderConfig::default()
            },
            client_secret_set: true,
            position: Some(0),
            updated_at: None,
        }
    }

    fn view() -> BackendView {
        BackendView {
            config: BackendConfig {
                name: "wiki".to_owned(),
                url: Some("http://localhost:9000/mcp".to_owned()),
                transport: TransportType::Http,
                ..BackendConfig::default()
            },
            auth_token_set: true,
            oauth_client_secret_set: false,
            header_names: vec!["X-Key".to_owned()],
            env_names: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_backend_form_keeps_secrets_unless_typed_or_cleared() {
        let html = render_backend_edit(&view(), CTX, env(&[]), false).into_string();
        assert!(html.contains("name=\"clear_auth_token\""));
        assert!(html.contains("stored; leave empty to keep it"));
        assert!(html.contains("name=\"header_remove\" value=\"X-Key\""));
        assert!(!html.contains("name=\"name\""));
    }

    #[test]
    fn the_create_form_says_when_stdio_is_off() {
        let html = backend_fields(None, CTX, env(&[])).into_string();
        assert!(html.contains("stdio backends are off"));
        assert!(html.contains("name=\"name\""));
    }

    #[test]
    fn the_backend_form_has_the_mode_select_and_a_section_per_mode() {
        let providers = vec![String::from("pocket")];
        let html = backend_fields(None, CTX, env(&providers)).into_string();
        assert!(html.contains("name=\"credential_mode\""));
        for mode in ["shared", "per_user", "oauth", "passthrough"] {
            assert!(
                html.contains(&format!("<option value=\"{mode}\"")),
                "{mode}"
            );
        }
        for section in ["mode-per_user", "mode-oauth", "mode-passthrough"] {
            assert!(html.contains(&format!("fieldset class=\"mode-section {section}\"")));
        }
        assert!(html.contains("name=\"credential_header\""));
        assert!(html.contains("name=\"oauth_client_secret\""));
        assert!(html.contains("<option value=\"pocket\""));
        assert!(html.contains("Users are sent back to"));
        assert!(html.contains("https://axon.example.com/oauth/upstream/callback"));
        assert!(!html.contains("JSON API"));
    }

    #[test]
    fn the_backend_form_shows_the_stored_mode_and_its_values() {
        let mut view = view();
        view.config.credential_mode = CredentialMode::OAuth;
        view.config.oauth = Some(UpstreamOAuthConfig {
            client_id: String::from("axon-client"),
            client_secret_env: None,
            client_secret: None,
            scopes: vec![String::from("read"), String::from("write")],
        });
        view.oauth_client_secret_set = true;
        view.config.credential_fields = vec![CredentialField {
            name: String::from("token"),
            label: Some(String::from("API token")),
            header: String::from("Authorization"),
            prefix: Some(String::from("Bearer ")),
        }];
        let html = render_backend_edit(&view, CTX, env(&[]), false).into_string();
        assert!(html.contains("<option value=\"oauth\" selected"));
        assert!(html.contains("value=\"axon-client\""));
        assert!(html.contains("read\nwrite"));
        assert!(html.contains("name=\"clear_oauth_secret\""));
        assert!(html.contains("value=\"Bearer \""));
    }

    #[tokio::test]
    async fn the_backends_table_has_a_mode_column() {
        let mut oauth = view();
        oauth.config.credential_mode = CredentialMode::PerUser;
        let html =
            render_backends_page(&test_state(), &session(), CTX, env(&[]), &[oauth]).into_string();
        assert!(html.contains("<th>Mode</th>"));
        assert!(html.contains("<td>per user</td>"));
    }

    #[tokio::test]
    async fn the_providers_page_lists_the_values_for_the_identity_provider() {
        let html = render_providers_page(&test_state(), &session(), CTX, &[provider("pocket")])
            .into_string();
        assert!(html.contains("Values for your identity provider"));
        assert!(html.contains("http://127.0.0.1:8080/auth/callback"));
        assert!(html.contains("<code class=\"mono\">http://127.0.0.1:8080/</code>"));
        assert!(html.contains("http://127.0.0.1:8080/oauth/upstream/callback"));
        assert!(html.contains("data-copy=\"http://127.0.0.1:8080/auth/callback\""));
        assert!(html.contains("Keep each issuer URL exactly as the provider writes it"));
        assert!(html.contains("<th>Admin groups</th>"));
        assert!(html.contains("axon-admins"));
    }

    #[tokio::test]
    async fn every_config_page_has_exactly_one_h1() {
        let h1s = |html: String| html.matches("<h1").count();
        let providers = [provider("pocket")];
        assert_eq!(
            h1s(render_providers_page(&test_state(), &session(), CTX, &providers).into_string()),
            1
        );
        assert_eq!(
            h1s(
                render_backends_page(&test_state(), &session(), CTX, env(&[]), &[view()])
                    .into_string()
            ),
            1
        );
        assert_eq!(
            h1s(
                render_backend_page(&test_state(), &session(), CTX, env(&[]), &view())
                    .into_string()
            ),
            1
        );
        assert_eq!(
            h1s(render_toolsets_page(&test_state(), &session(), CTX, &[]).into_string()),
            1
        );
        assert_eq!(
            h1s(
                render_settings_page(&test_state(), &session(), CTX, &GatewaySettings::default())
                    .into_string()
            ),
            1
        );
    }

    #[tokio::test]
    async fn the_toolsets_tab_is_called_gateway_toolsets() {
        let html = render_toolsets_page(&test_state(), &session(), CTX, &[]).into_string();
        assert!(html.contains("Gateway toolsets"));
        assert!(!html.contains(">Toolsets<"));
    }
}
