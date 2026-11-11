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

use std::fmt::Display;

use maud::{Markup, PreEscaped, html};

use super::AppState;
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, CARD, CODE, FAINT, HEADING, INPUT, LABEL, LINK, MUTED, TABLE,
    TABLE_WRAP, TBODY, TD, TH, THEAD, render_flash_area, render_layout,
};
use super::config_api::{BackendView, ProviderSource, ProviderView, ToolsetView};
use crate::config::{
    BackendConfig, GatewaySettings, OidcProviderConfig, ToolsetConfig, TransportType,
};
use crate::store::SessionUser;

const EDIT: &str = "#config-edit";
const SETTINGS: &str = "#config-settings";

/// Empty header and environment rows on the backend forms
const SECRET_ROWS: usize = 3;

const FORM_COL: &str = "mt-4 flex flex-col items-start gap-3";
const SUBHEADING: &str = "text-base font-semibold text-slate-900 dark:text-slate-100";
const DIVIDER: &str = "mt-6 border-t border-slate-200 pt-4 dark:border-slate-800";
const TEXTAREA: &str = "rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-mono text-sm text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100";
const BADGE_OK: &str = "rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300";
const BADGE_OFF: &str = "rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300";
const BADGE_INFO: &str = "rounded-full bg-sky-100 px-2 py-0.5 text-xs font-semibold text-sky-800 dark:bg-sky-900/40 dark:text-sky-300";

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
            span class=(BADGE_OK) { "enabled" }
        } @else {
            span class=(BADGE_OFF) { "disabled" }
        }
    }
}

fn set_badge(set: bool) -> Markup {
    html! {
        @if set {
            span class=(BADGE_OK) { "set" }
        } @else {
            span class=(FAINT) { "-" }
        }
    }
}

/// One entry per line of a list field
fn lines(items: &[String]) -> String {
    items.join("\n")
}

fn transport_name(transport: TransportType) -> &'static str {
    match transport {
        TransportType::Sse => "sse",
        TransportType::Http => "http",
        TransportType::Stdio => "stdio",
    }
}

fn text_field(label: &str, name: &str, value: &str, required: bool) -> Markup {
    html! {
        label class=(LABEL) {
            (label)
            input
                class=(format!("{INPUT} w-72"))
                type="text"
                name=(name)
                value=(value)
                required[required]
                autocomplete="off";
        }
    }
}

fn number_field(label: &str, name: &str, value: Option<impl Display>) -> Markup {
    let value = value.map(|value| value.to_string()).unwrap_or_default();
    html! {
        label class=(LABEL) {
            (label)
            input
                class=(format!("{INPUT} w-40"))
                type="number"
                min="0"
                name=(name)
                value=(value)
                autocomplete="off";
        }
    }
}

fn lines_field(label: &str, name: &str, items: &[String]) -> Markup {
    html! {
        label class=(LABEL) {
            (label) " (one per line)"
            textarea class=(format!("{TEXTAREA} w-72")) name=(name) rows="3" { (lines(items)) }
        }
    }
}

fn check_field(label: &str, name: &str, checked: bool) -> Markup {
    html! {
        label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200" {
            input type="checkbox" name=(name) value="true" checked[checked];
            (label)
        }
    }
}

/// A password input for a secret whose stored value is never shown: empty keeps
/// it, and a "clear" checkbox appears while one is stored
fn secret_field(label: &str, name: &str, clear_name: &str, set: bool) -> Markup {
    html! {
        label class=(LABEL) {
            (label)
            input
                class=(format!("{INPUT} w-72"))
                type="password"
                name=(name)
                placeholder=(if set { "stored; leave empty to keep it" } else { "" })
                autocomplete="new-password";
        }
        @if set {
            label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200" {
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
                div class="flex flex-wrap items-center gap-2" {
                    input
                        class=(format!("{INPUT} w-48"))
                        type="text"
                        name=(name_key)
                        value=(name)
                        readonly;
                    input
                        class=(format!("{INPUT} w-72"))
                        type="password"
                        name=(value_key)
                        placeholder="stored; leave empty to keep it"
                        autocomplete="new-password";
                    label class="flex items-center gap-1 text-xs text-slate-600 dark:text-slate-300" {
                        input type="checkbox" name=(remove_key) value=(name);
                        "remove"
                    }
                }
            }
            @for _ in 0..SECRET_ROWS {
                div class="flex flex-wrap gap-2" {
                    input
                        class=(format!("{INPUT} w-48"))
                        type="text"
                        name=(name_key)
                        placeholder=(placeholder)
                        autocomplete="off";
                    input
                        class=(format!("{INPUT} w-72"))
                        type="password"
                        name=(value_key)
                        placeholder="value"
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
        links.push((Section::Toolsets, "/ui/admin/config/toolsets", "Toolsets"));
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
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                (title)
            }
            p class=(format!("mt-2 {MUTED}")) { (intro) }
            nav class="mt-4 flex flex-wrap gap-4 text-sm" {
                @for (section, href, label) in &links {
                    @if *section == current {
                        span class="font-semibold text-slate-900 dark:text-slate-100" aria-current="page" { (label) }
                    } @else {
                        a href=(href) class=(LINK) { (label) }
                    }
                }
            }
        }
        (render_flash_area(false))
        (body)
    };
    render_layout(state, user, title, &content)
}

const JSON_ONLY: &str = "Per-user, OAuth and passthrough backends, credential fields and the \
                         OAuth client are edited through the JSON API \
                         (PUT /api/v1/admin/config/backends/{name}); saving here keeps them.";

// -- backends -----------------------------------------------------------------

fn backend_fields(view: Option<&BackendView>, ctx: PageCtx) -> Markup {
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
    html! {
        @if view.is_none() {
            (text_field("Name", "name", "", true))
        }
        label class=(LABEL) {
            "Transport"
            select class=(INPUT) name="transport" {
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
            p class=(MUTED) {
                "stdio backends are off: start the gateway with AXON_ALLOW_STDIO=true."
            }
        }
        (text_field("URL (http and sse)", "url", config.url.as_deref().unwrap_or_default(), false))
        @if view.is_some() {
            p class=(MUTED) { "Changing it needs the secrets entered again." }
        }
        (text_field("Command (stdio)", "command", config.command.as_deref().unwrap_or_default(), false))
        (lines_field("Arguments (stdio)", "args", &args))
        (check_field("Enabled", "enabled", config.enabled))
        (lines_field("Allowed tools (empty exposes all)", "allowed_tools", &config.allowed_tools))
        div class="flex flex-wrap gap-3" {
            (number_field("Call timeout (s)", "timeout_secs", Some(config.timeout_secs)))
            (number_field("Health check every (s, 0 = off)", "health_check_interval_secs", Some(config.health_check_interval_secs)))
            (number_field("Failures before the breaker opens", "max_consecutive_failures", Some(config.max_consecutive_failures)))
            (number_field("Breaker cooldown (s)", "circuit_breaker_cooldown_secs", Some(config.circuit_breaker_cooldown_secs)))
            (number_field("Idle timeout (s, empty = gateway default)", "idle_timeout_secs", config.idle_timeout_secs))
        }
        (secret_field(
            "Auth token (Bearer)",
            "auth_token",
            "clear_auth_token",
            view.is_some_and(|view| view.auth_token_set),
        ))
        div {
            h3 class=(SUBHEADING) { "Headers" }
            p class=(MUTED) { "Values are secret. Empty rows are ignored." }
            div class="mt-2" { (secret_rows("header", "Authorization", header_names)) }
        }
        div {
            h3 class=(SUBHEADING) { "Environment (stdio)" }
            p class=(MUTED) { "Values are secret. Empty rows are ignored." }
            div class="mt-2" { (secret_rows("env", "API_KEY", env_names)) }
        }
        @if config.oauth.is_some() {
            (secret_field(
                "OAuth client secret",
                "oauth_client_secret",
                "clear_oauth_secret",
                view.is_some_and(|view| view.oauth_client_secret_set),
            ))
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
            td class=(TD) {
                a href=(format!("/ui/admin/config/backends/{}", config.name)) class=(LINK) {
                    (config.name)
                }
            }
            td class=(TD) { (transport_name(config.transport)) }
            td class=(TD) { code class=(CODE) { (target) } }
            td class=(TD) { (enabled_badge(config.enabled)) }
            td class=(TD) { (set_badge(view.auth_token_set)) }
            td class=(TD) { (view.header_names.len()) }
        }
    }
}

/// `GET /ui/admin/config/backends`
pub(super) fn render_backends_page(
    state: &AppState,
    user: &SessionUser,
    ctx: PageCtx,
    backends: &[BackendView],
) -> Markup {
    let body = html! {
        section class=(CARD) {
            h2 class=(HEADING) { "Backends" }
            p class=(format!("mt-1 {MUTED}")) { (JSON_ONLY) }
            @if backends.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No backends in the database yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Name" }
                                th class=(TH) { "Transport" }
                                th class=(TH) { "Target" }
                                th class=(TH) { "State" }
                                th class=(TH) { "Auth token" }
                                th class=(TH) { "Headers" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for view in backends {
                                (backend_row(view))
                            }
                        }
                    }
                }
            }
            @if ctx.can_write {
                details class=(DIVIDER) {
                    summary class="cursor-pointer text-sm font-medium text-slate-700 dark:text-slate-200" {
                        "Add a backend"
                    }
                    form
                        class=(FORM_COL)
                        hx-post="/ui/actions/admin/config/backends"
                        hx-swap="none"
                    {
                        (backend_fields(None, ctx))
                        button class=(BUTTON) type="submit" { "Create backend" }
                    }
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
pub(super) fn render_backend_edit(view: &BackendView, ctx: PageCtx, saved: bool) -> Markup {
    let config = &view.config;
    let base = format!("/ui/actions/admin/config/backends/{}", config.name);
    html! {
        section id="config-edit" class=(CARD) {
            h2 class=(HEADING) { (config.name) }
            p class=(format!("mt-1 {MUTED}")) {
                "Created " (when(view.created_at)) ", changed " (when(view.updated_at)) ". "
                "Credential mode: " code class=(CODE) { (format!("{:?}", config.credential_mode)) } "."
            }
            p class=(format!("mt-1 {MUTED}")) { (JSON_ONLY) }
            @if saved {
                p class="mt-3 text-sm font-medium text-emerald-700 dark:text-emerald-300" { "Saved." }
            }
            @if ctx.can_write {
                form class=(FORM_COL) hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                    (backend_fields(Some(view), ctx))
                    button class=(BUTTON) type="submit" { "Save backend" }
                }
                div class=(DIVIDER) {
                    button
                        class=(BUTTON_DANGER)
                        type="button"
                        hx-post=(format!("{base}/delete"))
                        hx-swap="none"
                        hx-confirm=(format!("Delete the backend {}?", config.name))
                    {
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
    view: &BackendView,
) -> Markup {
    let body = html! {
        p class="mb-4 text-sm" {
            a href="/ui/admin/config/backends" class=(LINK) { "All backends" }
        }
        (render_backend_edit(view, ctx, false))
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
    html! {
        @if config.is_none() {
            (text_field("Name", "name", "", true))
        }
        (text_field("Description", "description", toolset.description.as_deref().unwrap_or_default(), false))
        (lines_field("Tool patterns (globs such as backend_*)", "tools", &toolset.tools))
        (lines_field("Backends (empty = all)", "backends", &toolset.backends))
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
        section class=(CARD) {
            h2 class=(HEADING) { "Toolsets" }
            p class=(format!("mt-1 {MUTED}")) {
                "A toolset exposes a subset of the tools at " code class=(CODE) { "/mcp/toolset/{name}" } "."
            }
            @if toolsets.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No toolsets in the database yet." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Name" }
                                th class=(TH) { "Description" }
                                th class=(TH) { "Tools" }
                                th class=(TH) { "Backends" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for view in toolsets {
                                tr {
                                    td class=(TD) {
                                        a href=(format!("/ui/admin/config/toolsets/{}", view.config.name)) class=(LINK) {
                                            (view.config.name)
                                        }
                                    }
                                    td class=(TD) { (view.config.description.as_deref().unwrap_or_default()) }
                                    td class=(TD) { code class=(CODE) { (view.config.tools.join(", ")) } }
                                    td class=(TD) { (view.config.backends.join(", ")) }
                                }
                            }
                        }
                    }
                }
            }
            @if ctx.can_write {
                details class=(DIVIDER) {
                    summary class="cursor-pointer text-sm font-medium text-slate-700 dark:text-slate-200" {
                        "Add a toolset"
                    }
                    form
                        class=(FORM_COL)
                        hx-post="/ui/actions/admin/config/toolsets"
                        hx-swap="none"
                    {
                        (toolset_fields(None))
                        button class=(BUTTON) type="submit" { "Create toolset" }
                    }
                }
            }
        }
    };
    page(
        state,
        user,
        ctx,
        Section::Toolsets,
        "Toolsets",
        "Gateway toolsets, as opposed to the toolsets people make for themselves.",
        &body,
    )
}

/// The edit section of a toolset, also the fragment a save answers with
pub(super) fn render_toolset_edit(view: &ToolsetView, ctx: PageCtx, saved: bool) -> Markup {
    let base = format!("/ui/actions/admin/config/toolsets/{}", view.config.name);
    html! {
        section id="config-edit" class=(CARD) {
            h2 class=(HEADING) { (view.config.name) }
            p class=(format!("mt-1 {MUTED}")) {
                "Created " (when(view.created_at)) ", changed " (when(view.updated_at)) "."
            }
            @if saved {
                p class="mt-3 text-sm font-medium text-emerald-700 dark:text-emerald-300" { "Saved." }
            }
            @if ctx.can_write {
                form class=(FORM_COL) hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                    (toolset_fields(Some(&view.config)))
                    button class=(BUTTON) type="submit" { "Save toolset" }
                }
                div class=(DIVIDER) {
                    button
                        class=(BUTTON_DANGER)
                        type="button"
                        hx-post=(format!("{base}/delete"))
                        hx-swap="none"
                        hx-confirm=(format!("Delete the toolset {}?", view.config.name))
                    {
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
        p class="mb-4 text-sm" {
            a href="/ui/admin/config/toolsets" class=(LINK) { "All toolsets" }
        }
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

fn provider_fields(view: Option<&ProviderView>) -> Markup {
    let defaults = OidcProviderConfig::default();
    let config = view.map_or(&defaults, |view| &view.config);
    html! {
        @if view.is_none() {
            (text_field("Id (a-z, 0-9, -)", "id", "", true))
        }
        (text_field("Button label", "display_name", config.display_name.as_deref().unwrap_or_default(), false))
        (text_field("Issuer URL", "issuer", &config.issuer, true))
        (text_field("Client ID", "client_id", &config.client_id, true))
        (secret_field(
            "Client secret (empty for a public client)",
            "client_secret",
            "clear_client_secret",
            view.is_some_and(|view| view.client_secret_set),
        ))
        (lines_field("Scopes", "scopes", &config.scopes))
        (text_field("Groups claim", "groups_claim", &config.groups_claim, false))
        (lines_field("Allowed email domains (empty = any)", "allowed_email_domains", &config.allowed_email_domains))
        (lines_field("Admin groups", "admin_groups", &config.admin_groups))
        (check_field("Accept access tokens this provider issued as bearer tokens", "accept_access_tokens", config.accept_access_tokens))
        (text_field("Access token audience (default: client ID)", "access_token_audience", config.access_token_audience.as_deref().unwrap_or_default(), false))
        (check_field("Fetch groups from Microsoft Graph on a groups overage", "graph_overage", config.graph_overage))
        (text_field("Graph URL (default: graph.microsoft.com)", "graph_url", config.graph_url.as_deref().unwrap_or_default(), false))
        (text_field("SCIM match claim (default: sub)", "scim_match_claim", config.scim_match_claim.as_deref().unwrap_or_default(), false))
        (number_field("Position (empty: last on create, unchanged on save)", "position", view.and_then(|view| view.position)))
    }
}

fn source_badge(source: ProviderSource) -> Markup {
    html! {
        @if source == ProviderSource::Env {
            span class=(BADGE_INFO) { "env" }
        } @else {
            span class=(BADGE_OFF) { "database" }
        }
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
        section class=(CARD) {
            h2 class=(HEADING) { "OIDC providers" }
            p class=(format!("mt-1 {MUTED}")) {
                "The login buttons, in this order. The provider set by the AXON_OIDC_* environment is read-only. "
                "Provider changes apply on every replica within moments."
            }
            @if providers.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) {
                    "No providers: the break-glass link (axon-gateway admin login-link) is the way in."
                }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Id" }
                                th class=(TH) { "Source" }
                                th class=(TH) { "Issuer" }
                                th class=(TH) { "Client ID" }
                                th class=(TH) { "Secret" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for view in providers {
                                tr {
                                    td class=(TD) {
                                        a href=(format!("/ui/admin/config/oidc-providers/{}", view.config.id)) class=(LINK) {
                                            (view.config.id)
                                        }
                                    }
                                    td class=(TD) { (source_badge(view.source)) }
                                    td class=(TD) { code class=(CODE) { (view.config.issuer) } }
                                    td class=(TD) { code class=(CODE) { (view.config.client_id) } }
                                    td class=(TD) { (set_badge(view.client_secret_set)) }
                                }
                            }
                        }
                    }
                }
            }
            @if ctx.can_write {
                details class=(DIVIDER) {
                    summary class="cursor-pointer text-sm font-medium text-slate-700 dark:text-slate-200" {
                        "Add a provider"
                    }
                    form
                        class=(FORM_COL)
                        hx-post="/ui/actions/admin/config/oidc-providers"
                        hx-swap="none"
                    {
                        (provider_fields(None))
                        button class=(BUTTON) type="submit" { "Create provider" }
                    }
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
        section id="config-edit" class=(CARD) {
            h2 class=(HEADING) { (config.id) " " (source_badge(view.source)) }
            @if view.source == ProviderSource::Env {
                p class=(format!("mt-1 {MUTED}")) {
                    "This provider is set by the environment (AXON_OIDC_*) and cannot be changed here."
                }
                dl class="mt-4 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm" {
                    dt class=(FAINT) { "Issuer" }
                    dd { code class=(CODE) { (config.issuer) } }
                    dt class=(FAINT) { "Client ID" }
                    dd { code class=(CODE) { (config.client_id) } }
                    dt class=(FAINT) { "Client secret" }
                    dd { (set_badge(view.client_secret_set)) }
                    dt class=(FAINT) { "Admin groups" }
                    dd { (config.admin_groups.join(", ")) }
                }
            } @else {
                @if let Some(at) = view.updated_at {
                    p class=(format!("mt-1 {MUTED}")) { "Changed " (when(at)) "." }
                }
                @if saved {
                    p class="mt-3 text-sm font-medium text-emerald-700 dark:text-emerald-300" { "Saved." }
                }
                @if ctx.can_write {
                    form class=(FORM_COL) hx-post=(format!("{base}/update")) hx-target=(EDIT) hx-swap="outerHTML" {
                        (provider_fields(Some(view)))
                        button class=(BUTTON) type="submit" { "Save provider" }
                    }
                    div class=(DIVIDER) {
                        button
                            class=(BUTTON_DANGER)
                            type="button"
                            hx-post=(format!("{base}/delete"))
                            hx-swap="none"
                            hx-confirm=(format!("Delete the provider {}? People who log in with it can no longer do so.", config.id))
                        {
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
        p class="mb-4 text-sm" {
            a href="/ui/admin/config/oidc-providers" class=(LINK) { "All providers" }
        }
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
    html! {
        section id="config-settings" class=(CARD) {
            h2 class=(HEADING) { "Gateway settings" }
            p class=(format!("mt-1 {MUTED}")) {
                "Personal backend settings apply after a restart; the others on every replica within moments."
            }
            @if saved {
                p class="mt-3 text-sm font-medium text-emerald-700 dark:text-emerald-300" { "Saved." }
            }
            @if ctx.can_write {
                form class=(FORM_COL) hx-post="/ui/actions/admin/config/settings" hx-target=(SETTINGS) hx-swap="outerHTML" {
                    (number_field("Rate limit (requests per minute per token, 0 = unlimited)", "rate_limit_per_minute", Some(settings.rate_limit_per_minute)))
                    (number_field("Idle timeout (s, 0 = always connected)", "idle_timeout_secs", Some(settings.idle_timeout_secs)))
                    (lines_field("Allowed hosts (besides loopback and the base URL)", "allowed_hosts", &settings.allowed_hosts))
                    h3 class=(SUBHEADING) { "Personal backends" }
                    (check_field("Let people add personal backends and store catalog credentials", "personal_enabled", personal.enabled))
                    (number_field("Max personal backends per user", "personal_max_per_user", Some(personal.max_per_user)))
                    (number_field("Max tool calls per minute per user (0 = unlimited)", "personal_max_calls_per_minute", Some(personal.max_calls_per_minute)))
                    (number_field("Max open connections per replica", "personal_max_instances", Some(personal.max_instances)))
                    (lines_field("Egress allow (hosts or CIDRs, empty = any public host)", "personal_egress_allow", &personal.egress_allow))
                    (lines_field("Egress deny (hosts or CIDRs)", "personal_egress_deny", &personal.egress_deny))
                    button class=(BUTTON) type="submit" { "Save settings" }
                }
            } @else {
                dl class="mt-4 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm" {
                    dt class=(FAINT) { "Rate limit" }
                    dd { (settings.rate_limit_per_minute) }
                    dt class=(FAINT) { "Idle timeout" }
                    dd { (settings.idle_timeout_secs) " s" }
                    dt class=(FAINT) { "Allowed hosts" }
                    dd { (settings.allowed_hosts.join(", ")) }
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

    use super::*;

    const CTX: PageCtx = PageCtx {
        read_backends: true,
        read_gateway: true,
        can_write: true,
        allow_stdio: false,
    };

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
        let html = render_backend_edit(&view(), CTX, false).into_string();
        assert!(html.contains("name=\"clear_auth_token\""));
        assert!(html.contains("stored; leave empty to keep it"));
        assert!(html.contains("name=\"header_remove\" value=\"X-Key\""));
        assert!(!html.contains("name=\"name\""));
    }

    #[test]
    fn the_create_form_says_when_stdio_is_off() {
        let html = backend_fields(None, CTX).into_string();
        assert!(html.contains("stdio backends are off"));
        assert!(html.contains("name=\"name\""));
    }
}
