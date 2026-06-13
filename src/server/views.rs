//! HTML rendering (maud) for the gateway's pages and HTMX fragments.
//!
//! These are pure view functions: they take borrowed state/status and return
//! `Markup`. All request handling, routing, and side effects live in the parent
//! `server` module.

use chrono::{DateTime, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::{AppState, FlashLevel, FlashMessage};
use crate::gateway::DetailedGatewayStatus;
use crate::types::{BackendInfo, BackendState, PromptDefinition, ResourceDefinition};

/// Landing page (`GET /`).
#[allow(clippy::too_many_lines)]
pub(super) fn render_landing_page(state: &AppState) -> Markup {
    let mcp_server_url = build_mcp_server_url(&state.base_url);

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-4xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                            "Axon Gateway"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" {
                            "One endpoint for your MCP backends"
                        }
                        p class="mt-3 text-slate-600 dark:text-slate-300" {
                            "Use the dashboard for live backend health, and the MCP endpoint for agent calls."
                        }
                        div class="mt-6 rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-950" {
                            p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                                "Axon Gateway MCP Server"
                            }
                            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" {
                                "Copy this URL into your MCP client configuration."
                            }
                            div class="mt-3 flex flex-col gap-2 sm:flex-row" {
                                code class="block flex-1 overflow-x-auto rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100" id="mcp-server-url" {
                                    (mcp_server_url.as_str())
                                }
                                button
                                    class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                    data-url=(mcp_server_url.as_str())
                                    id="copy-mcp-url"
                                    type="button"
                                {
                                    "Copy MCP URL"
                                }
                            }
                            p class="mt-2 text-xs text-slate-500 dark:text-slate-400" id="copy-mcp-url-feedback" aria-live="polite" {
                                ""
                            }
                        }
                        div class="mt-6 flex flex-wrap gap-3" {
                            a
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                href="/ui"
                            {
                                "Open Dashboard"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/status"
                            {
                                "Gateway Status"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/health"
                            {
                                "Health"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                            (build_fingerprint(state))
                        }
                    }
                }
                script {
                    (PreEscaped(
                        r#"
                        (() => {
                            const copyButton = document.getElementById("copy-mcp-url");
                            if (!copyButton) {
                                return;
                            }

                            const feedback = document.getElementById("copy-mcp-url-feedback");
                            copyButton.addEventListener("click", async () => {
                                const mcpUrl = copyButton.dataset.url ?? "";

                                try {
                                    await navigator.clipboard.writeText(mcpUrl);
                                    if (feedback) {
                                        feedback.textContent = "Copied MCP server URL.";
                                    }
                                } catch (_error) {
                                    if (feedback) {
                                        feedback.textContent = "Copy failed. Copy the URL manually.";
                                    }
                                }
                            });
                        })();
                        "#,
                    ))
                }
            }
        }
    }
}

/// Global 404 page for unmatched routes.
pub(super) fn render_not_found_page(state: &AppState) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Page Not Found" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" { "404" }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" { "Route not found" }
                        p class="mt-3 text-slate-600 dark:text-slate-300" {
                            "The page you requested does not exist on this gateway instance."
                        }
                        div class="mt-6 flex justify-center gap-3" {
                            a
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                href="/"
                            {
                                "Go Home"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/ui"
                            {
                                "Open Dashboard"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                            (build_fingerprint(state))
                        }
                    }
                }
            }
        }
    }
}

/// Full dashboard page (`GET /ui`).
pub(super) fn render_ui_page(status: &DetailedGatewayStatus, state: &AppState) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway Dashboard" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                script src="https://unpkg.com/htmx.org@2.0.4" defer {};
                script src="https://unpkg.com/htmx-ext-sse@2.2.2" defer {};
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto max-w-6xl p-6" {
                    section class="mb-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h1 class="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                            "Axon Gateway"
                        }
                        p class="mt-2 text-sm text-slate-600 dark:text-slate-300" {
                            "Server-rendered dashboard with SSE updates and HTMX actions."
                        }
                        div class="mt-4 flex flex-wrap gap-3" {
                            button
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                hx-post="/ui/actions/reload"
                                hx-target="#flash"
                                hx-swap="innerHTML"
                            {
                                "Reload Config"
                            }
                        }
                    }
                    div
                        hx-ext="sse"
                        sse-connect="/ui/events"
                    {
                        div id="flash" sse-swap="flash" {}
                        div id="backend-panel" sse-swap="backend_status_changed" {
                            (render_backend_panel(status))
                        }
                    }
                    footer class="mt-6 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                        (build_fingerprint(state))
                    }
                }
            }
        }
    }
}

/// Backend detail page (`GET /ui/backends/{name}`).
pub(super) fn render_ui_backend_detail_page(
    backend: &BackendInfo,
    prompts: &[PromptDefinition],
    resources: &[ResourceDefinition],
    state: &AppState,
) -> Markup {
    let state_text = backend_state_text(backend.state);
    let state_class = backend_state_class(backend.state);

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway Backend Detail" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto max-w-6xl p-6" {
                    section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        a
                            href="/ui"
                            class="inline-flex items-center text-sm font-medium text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-slate-100"
                        {
                            (PreEscaped("&larr;")) " Back to dashboard"
                        }
                        h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                            code { (&backend.name) }
                        }
                        div class="mt-3 flex flex-wrap items-center gap-3 text-sm text-slate-600 dark:text-slate-300" {
                            span { "State:" }
                            span class=(state_class) { (state_text) }
                            span { "Tools: " (backend.tool_count) }
                            span { "Prompts: " (prompts.len()) }
                            span { "Resources: " (resources.len()) }
                        }
                        @if let Some(error) = &backend.last_error {
                            p class="mt-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300" {
                                "Last error: " code { (error) }
                            }
                        }
                    }

                    section class="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" { "Tools" }
                        @if backend.tools.is_empty() {
                            p class="mt-3 text-sm text-slate-500 dark:text-slate-400" { "No tools exposed by this backend." }
                        } @else {
                            ul class="mt-4 space-y-3" {
                                @for tool in &backend.tools {
                                    li class="rounded-md border border-slate-200 p-3 dark:border-slate-800" {
                                        p class="font-mono text-sm text-slate-900 dark:text-slate-100" { (&tool.original_name) }
                                        @if let Some(description) = &tool.definition.description {
                                            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" { (description) }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section class="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" { "Prompts" }
                        @if prompts.is_empty() {
                            p class="mt-3 text-sm text-slate-500 dark:text-slate-400" { "No prompts exposed by this backend." }
                        } @else {
                            ul class="mt-4 space-y-3" {
                                @for prompt in prompts {
                                    li class="rounded-md border border-slate-200 p-3 dark:border-slate-800" {
                                        p class="font-mono text-sm text-slate-900 dark:text-slate-100" { (&prompt.name) }
                                        @if let Some(description) = &prompt.description {
                                            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" { (description) }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    section class="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" { "Resources" }
                        @if resources.is_empty() {
                            p class="mt-3 text-sm text-slate-500 dark:text-slate-400" { "No resources exposed by this backend." }
                        } @else {
                            ul class="mt-4 space-y-3" {
                                @for resource in resources {
                                    li class="rounded-md border border-slate-200 p-3 dark:border-slate-800" {
                                        p class="font-mono text-xs break-all text-slate-900 dark:text-slate-100" { (&resource.uri) }
                                        @if let Some(name) = &resource.name {
                                            p class="mt-1 text-sm text-slate-700 dark:text-slate-200" { (name) }
                                        }
                                        @if let Some(description) = &resource.description {
                                            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" { (description) }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    footer class="mt-6 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                        (build_fingerprint(state))
                    }
                }
            }
        }
    }
}

/// Build/runtime fingerprint shown in page footers.
fn build_fingerprint(state: &AppState) -> String {
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
        FlashLevel::Success => {
            "rounded-md border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300"
        }
        FlashLevel::Error => {
            "rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
        }
        FlashLevel::Info => {
            "rounded-md border border-slate-200 bg-slate-100 px-4 py-3 text-sm text-slate-800 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200"
        }
    };

    html! {
        div class=(classes) {
            (flash.message)
        }
    }
}

/// Backend table panel (full and SSE-pushed updates).
pub(super) fn render_backend_panel(status: &DetailedGatewayStatus) -> Markup {
    html! {
        section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
            h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" { "Backends" }
            p class="mt-1 text-sm text-slate-600 dark:text-slate-300" { (status.backend_count) " active backend actors" }
            @if status.backends.is_empty() {
                p class="mt-4 text-sm text-slate-500 dark:text-slate-400" { "No backends currently connected." }
            } @else {
                div class="mt-4 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800" {
                    table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800" {
                        thead class="bg-slate-50 dark:bg-slate-800/80" {
                            tr {
                                th class="px-4 py-3 text-left font-medium text-orange-600 dark:text-orange-300" { "Name" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "State" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Tools" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Actions" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Last Error" }
                            }
                        }
                        tbody class="divide-y divide-slate-100 bg-white dark:divide-slate-800 dark:bg-slate-900" {
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

/// A single backend row within the panel.
pub(super) fn render_backend_row(backend: &BackendInfo) -> Markup {
    let state_text = backend_state_text(backend.state);
    let state_class = backend_state_class(backend.state);

    html! {
        tr class="align-top" {
            td class="px-4 py-3" {
                a
                    href=(format!("/ui/backends/{}", backend.name))
                    class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 hover:decoration-orange-500 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100 dark:hover:decoration-orange-400"
                {
                    code { (backend.name) }
                }
            }
            td class="px-4 py-3" { span class=(state_class) { (state_text) } }
            td class="px-4 py-3 text-slate-700 dark:text-slate-200" { (backend.tool_count) }
            td class="px-4 py-3" {
                div class="flex flex-wrap gap-2" {
                    button
                        class="rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                        hx-post=(format!("/ui/actions/backends/{}/reconnect", backend.name))
                        hx-target="#flash"
                        hx-swap="innerHTML"
                    {
                        "Reconnect"
                    }
                    @if backend.state == BackendState::Disconnected {
                        button
                            class="rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                            hx-post=(format!("/ui/actions/backends/{}/enable", backend.name))
                            hx-target="#flash"
                            hx-swap="innerHTML"
                        {
                            "Enable"
                        }
                    } @else {
                        button
                            class="rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                            hx-post=(format!("/ui/actions/backends/{}/disable", backend.name))
                            hx-target="#flash"
                            hx-swap="innerHTML"
                        {
                            "Disable"
                        }
                    }
                }
            }
            td class="px-4 py-3" {
                @if let Some(error) = &backend.last_error {
                    code class="text-xs text-red-700 dark:text-red-400" { (error) }
                } @else {
                    (PreEscaped("&mdash;"))
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
    }
}

fn backend_state_class(state: BackendState) -> &'static str {
    match state {
        BackendState::Connected => "text-emerald-700 dark:text-emerald-400",
        BackendState::Connecting | BackendState::Reconnecting => {
            "text-amber-700 dark:text-amber-400"
        }
        BackendState::Failed | BackendState::CircuitOpen | BackendState::Disconnected => {
            "text-red-700 dark:text-red-400"
        }
    }
}
