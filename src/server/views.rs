//! HTML rendering (maud) for the gateway's pages and HTMX fragments.
//!
//! These are pure view functions: they take borrowed state/status and return
//! `Markup`. All request handling, routing, and side effects live in the parent
//! `server` module.

use chrono::{DateTime, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::{AppState, FlashLevel, FlashMessage};
use crate::gateway::DetailedGatewayStatus;
use crate::policy::{
    AUTHENTICATED_GROUP, EffectivePolicy, Explanation, Miss, OptOuts, Permission, ToolRef,
};
use crate::rbac::resolve;
use crate::store::SessionUser;
use crate::types::{
    BackendInfo, BackendState, NamespacedTool, PromptDefinition, ResourceDefinition,
};

/// One "Sign in with ..." choice on the login page.
pub(super) struct LoginOption {
    pub display_name: String,
    /// Already URL-encoded by the caller.
    pub href: String,
}

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

/// Login page (`GET /auth/login`).
pub(super) fn render_login_page(state: &AppState, options: &[LoginOption]) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Sign in - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                            "Axon Gateway"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" {
                            "Sign in to Axon Gateway"
                        }
                        @if options.is_empty() {
                            p class="mt-3 text-slate-600 dark:text-slate-300" {
                                "No login providers are configured."
                            }
                        } @else {
                            div class="mt-6 flex flex-col items-center gap-3" {
                                @for option in options {
                                    a
                                        class="w-full max-w-xs rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                        href=(option.href)
                                    {
                                        "Sign in with " (option.display_name)
                                    }
                                }
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

/// Login failure page; `message` must be generic, never provider details.
pub(super) fn render_auth_error_page(state: &AppState, title: &str, message: &str) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                            "Sign-in failed"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" { (title) }
                        p class="mt-3 text-slate-600 dark:text-slate-300" { (message) }
                        div class="mt-6 flex justify-center gap-3" {
                            a
                                class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                                href="/auth/login"
                            {
                                "Try again"
                            }
                            a
                                class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                                href="/"
                            {
                                "Home"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:text-slate-400 dark:border-slate-700" {
                            (build_fingerprint(state))
                        }
                    }
                }
            }
        }
    }
}

/// Header strip for signed-in users: name, admin badge and the logout form.
/// The "Admin" link shows for users who may open the admin pages.
pub(super) fn render_user_bar(state: &AppState, user: &SessionUser) -> Markup {
    let (_, permissions) = resolve(&state.policy.current(), user);
    let admin_pages = permissions.has(Permission::GroupsManage)
        || permissions.has(Permission::RolesManage)
        || permissions.has(Permission::AuditRead);
    let name = user
        .user
        .display_name
        .as_deref()
        .or(user.user.email.as_deref())
        .unwrap_or(&user.user.subject);

    html! {
        div class="mb-4 flex flex-wrap items-center justify-end gap-3 text-sm text-slate-600 dark:text-slate-300" {
            a
                class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                href="/ui/tools"
            {
                "My tools"
            }
            a
                class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                href="/ui/tokens"
            {
                "Tokens"
            }
            a
                class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                href="/ui/me/apps"
            {
                "Connected apps"
            }
            a
                class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                href="/ui/toolsets"
            {
                "Toolsets"
            }
            a
                class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                href="/ui/me/usage"
            {
                "My usage"
            }
            @if state.personal.is_some() {
                a
                    class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                    href="/ui/me/backends"
                {
                    "My MCP servers"
                }
                a
                    class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                    href="/ui/catalog"
                {
                    "Catalog"
                }
            }
            @if admin_pages {
                a
                    class="font-medium text-orange-700 underline decoration-orange-300 underline-offset-2 hover:text-orange-900 dark:text-orange-200 dark:decoration-orange-700 dark:hover:text-orange-100"
                    href="/ui/admin"
                {
                    "Admin"
                }
            }
            span class="font-medium text-slate-900 dark:text-slate-100" { (name) }
            @if permissions.is_admin() {
                span class="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300" {
                    "admin"
                }
            }
            form method="post" action="/auth/logout" {
                input type="hidden" name="csrf_token" value=(user.csrf_token);
                button
                    class="rounded-lg border border-slate-300 bg-white px-3 py-1 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                    type="submit"
                {
                    "Log out"
                }
            }
        }
    }
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
    let hx_headers = user.map(csrf_hx_headers);

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Axon Gateway Dashboard" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                @if let Some(user) = user {
                    meta name="csrf-token" content=(user.csrf_token);
                }
                script src="https://unpkg.com/htmx.org@2.0.4" defer {};
                script src="https://unpkg.com/htmx-ext-sse@2.2.2" defer {};
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" hx-headers=[hx_headers.as_deref()] {
                main class="mx-auto max-w-6xl p-6" {
                    @if let Some(user) = user {
                        (render_user_bar(state, user))
                    }
                    section class="mb-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        h1 class="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                            "Axon Gateway"
                        }
                        p class="mt-2 text-sm text-slate-600 dark:text-slate-300" {
                            "Server-rendered dashboard with SSE updates and HTMX actions."
                        }
                        // Database mode has no config file to reload
                        @if state.config_path.is_some() {
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
#[allow(clippy::too_many_lines)]
pub(super) fn render_ui_backend_detail_page(
    backend: &BackendInfo,
    prompts: &[PromptDefinition],
    resources: &[ResourceDefinition],
    state: &AppState,
    user: Option<&SessionUser>,
) -> Markup {
    let hx_headers = user.map(csrf_hx_headers);
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
                @if let Some(user) = user {
                    meta name="csrf-token" content=(user.csrf_token);
                }
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" hx-headers=[hx_headers.as_deref()] {
                main class="mx-auto max-w-6xl p-6" {
                    @if let Some(user) = user {
                        (render_user_bar(state, user))
                    }
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
            hx-post="/ui/actions/tools/opt-out"
            hx-target="closest section"
            hx-swap="outerHTML"
        {
            input type="hidden" name="backend" value=(backend);
            @if let Some(tool) = tool {
                input type="hidden" name="tool" value=(tool);
            }
            input type="hidden" name="hidden" value=(hide.to_string());
            button
                class="rounded-md border border-slate-300 px-2 py-1 text-xs text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-200 dark:hover:bg-slate-800"
                type="submit"
            {
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
            td class="px-4 py-3" {
                code class="text-slate-900 dark:text-slate-100" { (tool.namespaced_name) }
                @if tool.definition.read_only_hint() {
                    span class="ml-2 rounded-full bg-sky-100 px-2 py-0.5 text-xs font-semibold text-sky-800 dark:bg-sky-900/40 dark:text-sky-300" {
                        "read-only"
                    }
                }
            }
            td class="px-4 py-3 text-slate-600 dark:text-slate-300" {
                @if let Some(description) = &tool.definition.description {
                    (description)
                }
            }
            td class="px-4 py-3" {
                @match &state {
                    ToolState::Mandatory => {
                        span class="font-medium text-amber-700 dark:text-amber-400" { "mandatory" }
                        p class="mt-1 text-xs text-slate-500 dark:text-slate-400" { "required by your admin" }
                    }
                    ToolState::On => {
                        span class="font-medium text-emerald-700 dark:text-emerald-400" { "on" }
                    }
                    ToolState::Hidden { via_backend } => {
                        span class="font-medium text-slate-500 dark:text-slate-400" { "hidden by you" }
                        @if *via_backend {
                            p class="mt-1 text-xs text-slate-500 dark:text-slate-400" { "with the whole backend" }
                        }
                    }
                    ToolState::NotGranted(reason) => {
                        span class="font-medium text-red-700 dark:text-red-400" { "not granted" }
                        p class="mt-1 text-xs text-slate-500 dark:text-slate-400" { (reason) }
                    }
                }
            }
            td class="px-4 py-3" {
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
        section class="mt-6 rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
            div class="flex flex-wrap items-center justify-between gap-3" {
                h2 class="text-lg font-semibold text-slate-900 dark:text-slate-100" {
                    code { (backend.name) }
                }
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
                p class="mt-3 text-sm text-slate-500 dark:text-slate-400" {
                    "No access \u{2014} ask an admin"
                }
            } @else {
                @if backend_hidden {
                    p class="mt-3 text-sm text-slate-600 dark:text-slate-300" {
                        "You hid this backend. Its mandatory tools stay visible."
                    }
                }
                div class="mt-4 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800" {
                    table class="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800" {
                        thead class="bg-slate-50 dark:bg-slate-800/80" {
                            tr {
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Tool" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Description" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "State" }
                                th class="px-4 py-3 text-left font-medium text-slate-600 dark:text-slate-300" { "Actions" }
                            }
                        }
                        tbody class="divide-y divide-slate-100 bg-white dark:divide-slate-800 dark:bg-slate-900" {
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
    let hx_headers = csrf_hx_headers(user);
    let mut sections: Vec<&BackendInfo> = backends
        .iter()
        .filter(|backend| !backend.tools.is_empty())
        .collect();
    sections.sort_by(|a, b| a.name.cmp(&b.name));

    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "My tools - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                meta name="csrf-token" content=(user.csrf_token);
                script src="https://unpkg.com/htmx.org@2.0.4" defer {};
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" hx-headers=(hx_headers) {
                main class="mx-auto max-w-6xl p-6" {
                    (render_user_bar(state, user))
                    section class="rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        a
                            href="/ui"
                            class="inline-flex items-center text-sm font-medium text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-slate-100"
                        {
                            (PreEscaped("&larr;")) " Back to dashboard"
                        }
                        h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                            "My tools"
                        }
                        p class="mt-2 text-sm text-slate-600 dark:text-slate-300" {
                            "Hiding a tool or a backend only removes it from your own tool list. "
                            "Tools your admin marked mandatory stay visible, even when you hide their backend."
                        }
                        h2 class="mt-4 text-sm font-semibold text-slate-900 dark:text-slate-100" { "Your groups" }
                        ul class="mt-2 space-y-1 text-sm" {
                            @let policy = state.policy.current();
                            @for group in groups {
                                li {
                                    code class="text-slate-900 dark:text-slate-100" { (group) }
                                    @if group == AUTHENTICATED_GROUP {
                                        span class="ml-2 text-xs text-slate-500 dark:text-slate-400" { "built in" }
                                    }
                                    @if let Some(description) = policy.group_description(group) {
                                        span class="ml-2 text-slate-600 dark:text-slate-300" { (description) }
                                    }
                                }
                            }
                        }
                    }
                    @if sections.is_empty() {
                        p class="mt-6 text-sm text-slate-500 dark:text-slate-400" { "No tools are available yet." }
                    }
                    @for backend in sections {
                        (render_tool_backend_section(backend, effective, opt_outs))
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
        BackendState::Idle => "Idle",
    }
}

fn backend_state_class(state: BackendState) -> &'static str {
    match state {
        BackendState::Connected => "text-emerald-700 dark:text-emerald-400",
        BackendState::Idle => "text-slate-600 dark:text-slate-400",
        BackendState::Connecting | BackendState::Reconnecting => {
            "text-amber-700 dark:text-amber-400"
        }
        BackendState::Failed | BackendState::CircuitOpen | BackendState::Disconnected => {
            "text-red-700 dark:text-red-400"
        }
    }
}
