//! HTML rendering (maud) for the gateway's pages and HTMX fragments.
//!
//! These are pure view functions: they take borrowed state/status and return
//! `Markup`. All request handling, routing, and side effects live in the parent
//! `server` module.

use chrono::{DateTime, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::shell::{Nav, current_theme, icon, render_shell};
use super::{AppState, FlashLevel, FlashMessage};
use crate::gateway::DetailedGatewayStatus;
use crate::policy::{AUTHENTICATED_GROUP, EffectivePolicy, Explanation, Miss, OptOuts, ToolRef};
use crate::store::SessionUser;
use crate::types::{
    BackendInfo, BackendState, NamespacedTool, PromptDefinition, ResourceDefinition,
};

/// htmx under the page CSP: no injected indicator `<style>` and no `eval`.
const HTMX_CONFIG: &str = r#"{"includeIndicatorStyles":false,"allowEval":false}"#;

/// The icon sprite for pages rendered without the shell (see `shell::icon`).
const ICON_SPRITE: &str = include_str!("../../static/icons.svg");

/// One "Sign in with ..." choice on the login page.
pub(super) struct LoginOption {
    pub display_name: String,
    /// Already URL-encoded by the caller.
    pub href: String,
}

/// A centered card page without the shell (landing, login, 404, auth error).
fn render_card_page(
    state: &AppState,
    page_title: &str,
    eyebrow: &str,
    heading: &str,
    body: &Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(current_theme().slug()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (page_title) }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=2";
            }
            body class="axon" {
                main class="mx-auto flex min-h-screen w-full max-w-xl items-center p-6" {
                    section class="card w-full" {
                        div class="card-b flex flex-col gap-4 p-6" {
                            div class="flex flex-col gap-1" {
                                p class="section-t" { (eyebrow) }
                                h1 class="text-xl font-semibold" { (heading) }
                            }
                            (body)
                        }
                        div class="card-f" {
                            p class="mono muted break-all" { (build_fingerprint(state)) }
                        }
                    }
                }
            }
        }
    }
}

/// Landing page (`GET /`).
pub(super) fn render_landing_page(state: &AppState) -> Markup {
    let mcp_server_url = build_mcp_server_url(&state.base_url);

    let body = html! {
        p class="muted" {
            "Use the dashboard for live backend health, and the MCP endpoint for agent calls."
        }
        div class="flex flex-col gap-2" {
            p class="section-t" { "Axon Gateway MCP Server" }
            p class="hint" { "Copy this URL into your MCP client configuration." }
            div class="copyline" {
                code class="mono" id="mcp-server-url" { (mcp_server_url.as_str()) }
                button
                    class="btn sm ghost"
                    data-url=(mcp_server_url.as_str())
                    id="copy-mcp-url"
                    type="button"
                {
                    "Copy MCP URL"
                }
            }
            p class="hint" id="copy-mcp-url-feedback" aria-live="polite" { "" }
        }
        div class="flex flex-wrap gap-2" {
            a class="btn primary" href="/ui" { "Open Dashboard" }
            a class="btn" href="/health" { "Health" }
        }
        script src="/static/copy-url.js" defer {}
    };
    render_card_page(
        state,
        "Axon Gateway",
        "Axon Gateway",
        "One endpoint for your MCP backends",
        &body,
    )
}

/// Global 404 page for unmatched routes.
pub(super) fn render_not_found_page(state: &AppState) -> Markup {
    let body = html! {
        p class="muted" { "The page you requested does not exist on this gateway instance." }
        div class="flex flex-wrap gap-2" {
            a class="btn primary" href="/" { "Go Home" }
            a class="btn" href="/ui" { "Open Dashboard" }
        }
    };
    render_card_page(state, "Page Not Found", "404", "Route not found", &body)
}

/// Login page (`GET /auth/login`).
pub(super) fn render_login_page(state: &AppState, options: &[LoginOption]) -> Markup {
    let body = html! {
        @if options.is_empty() {
            p class="muted" { "No login providers are configured." }
        } @else {
            div class="flex flex-col gap-2" {
                @for option in options {
                    a class="btn primary w-full justify-center" href=(option.href) {
                        "Sign in with " (option.display_name)
                    }
                }
            }
        }
    };
    render_card_page(
        state,
        "Sign in - Axon Gateway",
        "Axon Gateway",
        "Sign in to Axon Gateway",
        &body,
    )
}

/// Login failure page; `message` must be generic, never provider details.
pub(super) fn render_auth_error_page(state: &AppState, title: &str, message: &str) -> Markup {
    let body = html! {
        p class="muted" { (message) }
        div class="flex flex-wrap gap-2" {
            a class="btn primary" href="/auth/login" { "Try again" }
            a class="btn" href="/" { "Home" }
        }
    };
    let page_title = format!("{title} - Axon Gateway");
    render_card_page(state, &page_title, "Sign-in failed", title, &body)
}

/// `hx-headers` value that makes every htmx request carry the CSRF token.
pub(super) fn csrf_hx_headers(user: &SessionUser) -> String {
    serde_json::json!({ "X-CSRF-Token": user.csrf_token }).to_string()
}

/// Full dashboard page (`GET /ui`).
pub(super) fn render_ui_page(
    status: &DetailedGatewayStatus,
    state: &AppState,
    user: Option<&SessionUser>,
) -> Markup {
    let mcp_server_url = build_mcp_server_url(&state.base_url);
    let content = html! {
        div class="flex flex-col gap-4" {
            div class="page-head" {
                p { "Live backend health, with SSE updates and HTMX actions." }
                // Database mode has no config file to reload
                @if state.config_path.is_some() {
                    span class="spacer" {}
                    button
                        class="btn primary"
                        hx-post="/ui/actions/reload"
                        hx-target="#flash"
                        hx-swap="innerHTML"
                    {
                        (icon("refresh-cw")) "Reload Config"
                    }
                }
            }
            section class="card" {
                div class="card-h" {
                    (icon("plug"))
                    h2 { "Connect your client" }
                }
                div class="card-b flex flex-col gap-2" {
                    div class="copyline" {
                        code class="mono" id="mcp-server-url" { (mcp_server_url.as_str()) }
                        button
                            class="btn sm ghost"
                            data-url=(mcp_server_url.as_str())
                            id="copy-mcp-url"
                            type="button"
                        {
                            (icon("copy")) "Copy MCP URL"
                        }
                    }
                    p class="hint" id="copy-mcp-url-feedback" aria-live="polite" { "" }
                }
            }
            div
                class="flex flex-col gap-4"
                hx-ext="sse"
                sse-connect="/ui/events"
            {
                div id="flash" class="empty:hidden" sse-swap="flash" {}
                div id="backend-panel" sse-swap="backend_status_changed" {
                    (render_backend_panel(status))
                }
            }
            script src="/static/copy-url.js" defer {}
        }
    };
    match user {
        Some(user) => render_shell(state, user, "Overview", Nav::Overview, &content),
        None => render_standalone_page(state, "Axon Gateway Dashboard", &content),
    }
}

/// A dashboard page without a session (standalone mode has no users, so no shell).
fn render_standalone_page(state: &AppState, title: &str, content: &Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(current_theme().slug()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                meta name="htmx-config" content=(HTMX_CONFIG);
                script src="/static/htmx-2.0.4.min.js" defer {};
                script src="/static/htmx-ext-sse-2.2.2.js" defer {};
                link rel="stylesheet" href="/styles/output.css?v=2";
            }
            body class="axon" {
                (PreEscaped(ICON_SPRITE))
                main class="content mx-auto w-full max-w-6xl" {
                    h1 class="text-xl font-semibold" { (title) }
                    (content)
                    footer class="card-f border-t-0 px-0" {
                        p class="mono muted break-all" { (build_fingerprint(state)) }
                    }
                }
            }
        }
    }
}

/// One tool or prompt in a backend's detail card.
fn render_detail_item(name: &str, description: Option<&str>) -> Markup {
    html! {
        li class="px-3.5 py-2.5" {
            p class="mono font-medium" { (name) }
            @if let Some(description) = description {
                p class="muted" { (description) }
            }
        }
    }
}

/// Backend detail page (`GET /ui/backends/{name}`).
#[allow(clippy::too_many_lines)]
pub(super) fn render_ui_backend_detail_page(
    backend: &BackendInfo,
    prompts: &[PromptDefinition],
    resources: &[ResourceDefinition],
    state: &AppState,
    user: Option<&SessionUser>,
) -> Markup {
    let state_text = backend_state_text(backend.state);
    let tone = backend_state_tone(backend.state);

    let content = html! {
        div class="flex flex-col gap-4" {
            div class="page-head" {
                a class="btn sm ghost" href="/ui" { (PreEscaped("&larr;")) " Back to dashboard" }
            }
            section class="card" {
                div class="card-h" {
                    span class={"dot " (tone)} {}
                    h2 { code { (&backend.name) } }
                    span class={"pill " (tone)} { (state_text) }
                }
                div class="card-b flex flex-col gap-3" {
                    div class="flex flex-wrap items-center gap-4 muted" {
                        span { "State: " (state_text) }
                        span { "Tools: " (backend.tool_count) }
                        span { "Prompts: " (prompts.len()) }
                        span { "Resources: " (resources.len()) }
                    }
                    @if let Some(error) = &backend.last_error {
                        div class="banner text-err" {
                            (icon("circle-alert"))
                            span { "Last error: " code { (error) } }
                        }
                    }
                }
            }

            div class="cols" {
                section class="card" {
                    div class="card-h" {
                        (icon("wrench"))
                        h2 { "Tools" }
                        span class="pill" { (backend.tools.len()) }
                    }
                    @if backend.tools.is_empty() {
                        p class="card-b muted" { "No tools exposed by this backend." }
                    } @else {
                        ul class="m-0 list-none divide-y divide-border p-0" {
                            @for tool in &backend.tools {
                                (render_detail_item(
                                    &tool.original_name,
                                    tool.definition.description.as_deref(),
                                ))
                            }
                        }
                    }
                }

                section class="card" {
                    div class="card-h" {
                        (icon("scroll-text"))
                        h2 { "Prompts" }
                        span class="pill" { (prompts.len()) }
                    }
                    @if prompts.is_empty() {
                        p class="card-b muted" { "No prompts exposed by this backend." }
                    } @else {
                        ul class="m-0 list-none divide-y divide-border p-0" {
                            @for prompt in prompts {
                                (render_detail_item(&prompt.name, prompt.description.as_deref()))
                            }
                        }
                    }
                }

                section class="card" {
                    div class="card-h" {
                        (icon("library"))
                        h2 { "Resources" }
                        span class="pill" { (resources.len()) }
                    }
                    @if resources.is_empty() {
                        p class="card-b muted" { "No resources exposed by this backend." }
                    } @else {
                        ul class="m-0 list-none divide-y divide-border p-0" {
                            @for resource in resources {
                                li class="px-3.5 py-2.5" {
                                    p class="mono break-all font-medium" { (&resource.uri) }
                                    @if let Some(name) = &resource.name {
                                        p { (name) }
                                    }
                                    @if let Some(description) = &resource.description {
                                        p class="muted" { (description) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    match user {
        Some(user) => render_shell(state, user, "Backend detail", Nav::Overview, &content),
        None => render_standalone_page(state, "Axon Gateway Backend Detail", &content),
    }
}

/// How one tool stands for one user.
enum ToolState {
    /// Allowed by a mandatory grant: cannot be hidden
    Mandatory,
    /// Allowed and shown
    On,
    /// Allowed, hidden by the user (`via_backend`: by hiding the whole backend)
    Hidden { via_backend: bool },
    /// No grant of the user's groups allows it; the text says why
    NotGranted(String),
}

fn tool_ref(tool: &NamespacedTool) -> ToolRef<'_> {
    ToolRef {
        backend: &tool.backend_name,
        name: &tool.original_name,
        read_only_hint: tool.definition.read_only_hint(),
    }
}

fn tool_state(tool: &NamespacedTool, effective: &EffectivePolicy, opt_outs: &OptOuts) -> ToolState {
    let tool_ref = tool_ref(tool);
    if !effective.allows(tool_ref) {
        return ToolState::NotGranted(not_granted_reason(&effective.explain(tool_ref)));
    }
    if effective.is_mandatory(tool_ref) {
        ToolState::Mandatory
    } else if opt_outs.hides_backend(&tool.backend_name) {
        ToolState::Hidden { via_backend: true }
    } else if opt_outs.hides(&tool.backend_name, &tool.original_name) {
        ToolState::Hidden { via_backend: false }
    } else {
        ToolState::On
    }
}

/// Why no grant allows a tool, in words.
fn not_granted_reason(explanation: &Explanation) -> String {
    if explanation.missed.is_empty() {
        return String::from("no grant for this backend");
    }
    explanation
        .missed
        .iter()
        .map(|(grant, miss)| match miss {
            Miss::NotIncluded => format!("not included by the grant of group {}", grant.group),
            Miss::Excluded => format!("excluded by the grant of group {}", grant.group),
            Miss::NotReadOnly => format!(
                "the grant of group {} is read-only and this tool is not marked read-only",
                grant.group
            ),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Hide/show form for one tool (`tool` is `Some`) or a whole backend. `hide` is
/// the value the form posts: true while the thing is currently shown.
fn render_opt_out_form(backend: &str, tool: Option<&str>, hide: bool, label: &str) -> Markup {
    html! {
        form
            class="m-0"
            hx-post="/ui/actions/tools/opt-out"
            hx-target="closest section"
            hx-swap="outerHTML"
        {
            input type="hidden" name="backend" value=(backend);
            @if let Some(tool) = tool {
                input type="hidden" name="tool" value=(tool);
            }
            input type="hidden" name="hidden" value=(hide.to_string());
            button class="btn sm" type="submit" {
                (label)
            }
        }
    }
}

/// One tool row in a backend's table.
fn render_tool_row(
    tool: &NamespacedTool,
    effective: &EffectivePolicy,
    opt_outs: &OptOuts,
) -> Markup {
    let state = tool_state(tool, effective, opt_outs);

    html! {
        tr class="align-top" {
            td {
                code class="mono" { (tool.namespaced_name) }
                @if tool.definition.read_only_hint() {
                    span class="pill accent ml-2" { "read-only" }
                }
            }
            td class="muted whitespace-normal" {
                @if let Some(description) = &tool.definition.description {
                    (description)
                }
            }
            td {
                @match &state {
                    ToolState::Mandatory => {
                        span class="pill warn" { "mandatory" }
                        p class="hint" { "required by your admin" }
                    }
                    ToolState::On => {
                        span class="pill ok" { "on" }
                    }
                    ToolState::Hidden { via_backend } => {
                        span class="pill" { "hidden by you" }
                        @if *via_backend {
                            p class="hint" { "with the whole backend" }
                        }
                    }
                    ToolState::NotGranted(reason) => {
                        span class="pill err" { "not granted" }
                        p class="hint whitespace-normal" { (reason) }
                    }
                }
            }
            td {
                @match &state {
                    ToolState::On => {
                        (render_opt_out_form(&tool.backend_name, Some(&tool.original_name), true, "Hide"))
                    }
                    ToolState::Hidden { via_backend: false } => {
                        (render_opt_out_form(&tool.backend_name, Some(&tool.original_name), false, "Show"))
                    }
                    ToolState::Mandatory
                    | ToolState::Hidden { via_backend: true }
                    | ToolState::NotGranted(_) => {}
                }
            }
        }
    }
}

/// One backend's section of the "My tools" page, also the htmx swap target of
/// the hide/show forms (`hx-target="closest section"`).
pub(super) fn render_tool_backend_section(
    backend: &BackendInfo,
    effective: &EffectivePolicy,
    opt_outs: &OptOuts,
) -> Markup {
    let granted = effective.backends().contains(&backend.name);
    let backend_hidden = opt_outs.hides_backend(&backend.name);
    let mut tools: Vec<&NamespacedTool> = backend.tools.iter().collect();
    tools.sort_by(|a, b| a.namespaced_name.cmp(&b.namespaced_name));

    html! {
        section class="card" {
            div class="card-h" {
                h2 {
                    code { (backend.name) }
                }
                span class="spacer" {}
                @if granted {
                    (render_opt_out_form(
                        &backend.name,
                        None,
                        !backend_hidden,
                        if backend_hidden { "Show backend" } else { "Hide backend" },
                    ))
                }
            }
            @if !granted {
                p class="card-b muted" {
                    "No access \u{2014} ask an admin"
                }
            } @else {
                @if backend_hidden {
                    p class="card-b muted" {
                        "You hid this backend. Its mandatory tools stay visible."
                    }
                }
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Tools" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "Tool" }
                                th { "Description" }
                                th { "State" }
                                th { "Actions" }
                            }
                        }
                        tbody {
                            @for tool in tools {
                                (render_tool_row(tool, effective, opt_outs))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// "My tools" page (`GET /ui/tools`, multi-user mode only): the user's RBAC
/// groups and every tool with its state.
pub(super) fn render_my_tools_page(
    state: &AppState,
    user: &SessionUser,
    groups: &[String],
    backends: &[BackendInfo],
    effective: &EffectivePolicy,
    opt_outs: &OptOuts,
) -> Markup {
    let mut sections: Vec<&BackendInfo> = backends
        .iter()
        .filter(|backend| !backend.tools.is_empty())
        .collect();
    sections.sort_by(|a, b| a.name.cmp(&b.name));

    let content = html! {
        div class="flex flex-col gap-4" {
            div class="page-head" {
                p {
                    "Hiding a tool or a backend only removes it from your own tool list. "
                    "Tools your admin marked mandatory stay visible, even when you hide their backend."
                }
            }
            section class="card" {
                div class="card-h" {
                    (icon("users"))
                    h2 { "Your groups" }
                }
                ul class="card-b m-0 flex list-none flex-col gap-2" {
                    @let policy = state.policy.current();
                    @for group in groups {
                        li {
                            code class="mono" { (group) }
                            @if group == AUTHENTICATED_GROUP {
                                span class="pill ml-2" { "built in" }
                            }
                            @if let Some(description) = policy.group_description(group) {
                                span class="muted ml-2" { (description) }
                            }
                        }
                    }
                }
            }
            @if sections.is_empty() {
                section class="card" {
                    p class="card-b muted m-0" { "No tools are available yet." }
                }
            }
            @for backend in sections {
                (render_tool_backend_section(backend, effective, opt_outs))
            }
        }
    };
    render_shell(state, user, "My tools", Nav::MyTools, &content)
}

/// Build/runtime fingerprint shown in page footers.
pub(super) fn build_fingerprint(state: &AppState) -> String {
    let started_utc: DateTime<Utc> = state.started_at.into();
    let started = started_utc.format("%Y-%m-%d %H:%M:%S UTC");
    let git_sha = option_env!("AXON_GIT_SHA").unwrap_or("dev");

    format!(
        "v{} | {git_sha} | pid:{} | started:{started}",
        env!("CARGO_PKG_VERSION"),
        state.process_id
    )
}

fn build_mcp_server_url(base_url: &str) -> String {
    format!("{}/mcp", base_url.trim_end_matches('/'))
}

/// Flash message fragment (HTMX swap target).
pub(super) fn render_flash(flash: &FlashMessage) -> Markup {
    let classes = match flash.level {
        FlashLevel::Success => "card card-b text-sm text-ok",
        FlashLevel::Error => "card card-b text-sm text-err",
        FlashLevel::Info => "card card-b text-sm text-text",
    };

    html! {
        div class=(classes) {
            (flash.message)
        }
    }
}

/// Backend health panel (full and SSE-pushed updates): the "Needs attention"
/// list (only while a backend is not healthy) above the backend tiles.
pub(super) fn render_backend_panel(status: &DetailedGatewayStatus) -> Markup {
    let attention: Vec<&BackendInfo> = status
        .backends
        .iter()
        .filter(|backend| needs_attention(backend.state))
        .collect();
    let count_in = |tone: &str| {
        status
            .backends
            .iter()
            .filter(|backend| backend_state_tone(backend.state) == tone)
            .count()
    };
    let (healthy, degraded, down) = (count_in("ok"), count_in("warn"), count_in("err"));

    html! {
        div class="flex flex-col gap-4" {
            @if !attention.is_empty() {
                section class="card" {
                    div class="card-h" {
                        span class="text-warn" { (icon("triangle-alert")) }
                        h2 { "Needs attention" }
                        span class="pill warn" { (attention.len()) }
                    }
                    div class="list" {
                        @for backend in &attention {
                            a
                                class="row text-text"
                                href=(format!("/ui/backends/{}", backend.name))
                            {
                                span class={"dot " (backend_state_tone(backend.state))} {}
                                div class="row-main" {
                                    span class="font-medium" { (backend.name) }
                                    span class="row-sub" {
                                        @if let Some(error) = &backend.last_error {
                                            (backend_state_text(backend.state)) ": " (error)
                                        } @else {
                                            (backend_state_text(backend.state))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            section class="card" {
                div class="card-h" {
                    (icon("server"))
                    h2 { "Backends" }
                    @if healthy > 0 {
                        span class="pill ok" { (healthy) " healthy" }
                    }
                    @if degraded > 0 {
                        span class="pill warn" { (degraded) " degraded" }
                    }
                    @if down > 0 {
                        span class="pill err" { (down) " down" }
                    }
                    span class="spacer" {}
                    span class="muted" { (status.backend_count) " active backend actors" }
                }
                div class="card-b" {
                    @if status.backends.is_empty() {
                        p class="muted" { "No backends currently connected." }
                    } @else {
                        div class="tiles" {
                            @for backend in &status.backends {
                                (render_backend_row(backend))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A single backend tile within the panel.
pub(super) fn render_backend_row(backend: &BackendInfo) -> Markup {
    let state_text = backend_state_text(backend.state);
    let tone = backend_state_tone(backend.state);

    html! {
        div class="tile" {
            div class="tile-h" {
                span class={"dot " (tone)} {}
                a
                    href=(format!("/ui/backends/{}", backend.name))
                    class="mono min-w-0 truncate font-medium"
                {
                    (backend.name)
                }
                span class="spacer" {}
                span class={"pill " (tone)} { (state_text) }
            }
            div class="tile-meta" {
                span { (backend.tool_count) " tools" }
            }
            @if let Some(error) = &backend.last_error {
                code class="mono break-all text-err" { (error) }
            }
            div class="flex flex-wrap gap-2" {
                button
                    class="btn sm"
                    hx-post=(format!("/ui/actions/backends/{}/reconnect", backend.name))
                    hx-target="#flash"
                    hx-swap="innerHTML"
                {
                    "Reconnect"
                }
                @if backend.state == BackendState::Disconnected {
                    button
                        class="btn sm"
                        hx-post=(format!("/ui/actions/backends/{}/enable", backend.name))
                        hx-target="#flash"
                        hx-swap="innerHTML"
                    {
                        "Enable"
                    }
                } @else {
                    button
                        class="btn sm"
                        hx-post=(format!("/ui/actions/backends/{}/disable", backend.name))
                        hx-target="#flash"
                        hx-swap="innerHTML"
                    {
                        "Disable"
                    }
                }
            }
        }
    }
}

fn backend_state_text(state: BackendState) -> &'static str {
    match state {
        BackendState::Disconnected => "Disconnected",
        BackendState::Connecting => "Connecting",
        BackendState::Connected => "Connected",
        BackendState::Failed => "Failed",
        BackendState::CircuitOpen => "Circuit Open",
        BackendState::Reconnecting => "Reconnecting",
        BackendState::Idle => "Idle",
    }
}

/// The `dot`/`pill` modifier of a state: `ok`, `warn`, `err`, or none (idle).
fn backend_state_tone(state: BackendState) -> &'static str {
    match state {
        BackendState::Connected => "ok",
        BackendState::Idle => "",
        BackendState::Connecting | BackendState::Reconnecting => "warn",
        BackendState::Failed | BackendState::CircuitOpen | BackendState::Disconnected => "err",
    }
}

/// Backends in any state but connected or idle are listed under "Needs attention".
fn needs_attention(state: BackendState) -> bool {
    !matches!(state, BackendState::Connected | BackendState::Idle)
}
