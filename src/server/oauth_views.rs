//! HTML for the MCP OAuth pages: the consent page, the error page shown instead of a
//! redirect, and the "Connected apps" page. Client names are text a stranger chose, so
//! they only ever go through maud's escaping.

use chrono::{DateTime, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::AppState;
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, CARD, CODE, FAINT, HEADING, MUTED, TABLE, TABLE_WRAP, TBODY,
    TD, TH, THEAD, render_flash_area, render_layout,
};
use super::views::build_fingerprint;
use crate::store::{AuthRequest, OauthGrant, SessionUser};

/// The consent page's view of a pending request
pub(super) struct Consent<'a> {
    pub request: &'a AuthRequest,
    /// The host of the client's metadata document URL, for such clients
    pub client_host: Option<&'a str>,
    /// `host[:port]` the browser goes back to
    pub redirect_host: &'a str,
}

fn when(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The name a client is shown under: its own name, else its id
fn client_label<'a>(name: Option<&'a str>, client_id: &'a str) -> &'a str {
    name.filter(|name| !name.trim().is_empty())
        .unwrap_or(client_id)
}

/// Page of an authorization request that cannot continue and must not redirect (unknown
/// client, redirect URI that is not the client's).
pub(super) fn render_error_page(state: &AppState, title: &str, message: &str) -> Markup {
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
                            "Authorization"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" { (title) }
                        p class="mt-3 text-slate-600 dark:text-slate-300" { (message) }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:text-slate-400 dark:border-slate-700" {
                            (build_fingerprint(state))
                        }
                    }
                }
            }
        }
    }
}

/// The consent page: who asks, as whom, for what, with Approve and Deny
pub(super) fn render_consent_page(
    state: &AppState,
    user: &SessionUser,
    consent: &Consent<'_>,
) -> Markup {
    let request = consent.request;
    let name = client_label(request.client_name.as_deref(), &request.client_id);
    let acting_as = user
        .user
        .email
        .as_deref()
        .or(user.user.display_name.as_deref())
        .unwrap_or(&user.user.subject);
    let page = html! {
        section class=(CARD) {
            h1 class="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Connect " (name) "?"
            }
            p class=(format!("mt-2 {MUTED}")) {
                "An app wants to use this gateway's tools as you. It can use only what you may "
                "use, and you can end the connection at any time under Connected apps."
            }
            dl class="mt-4 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm" {
                dt class=(FAINT) { "App" }
                dd { (name) }
                @if let Some(host) = consent.client_host {
                    dt class=(FAINT) { "App metadata from" }
                    dd { code class=(CODE) { (host) } }
                } @else {
                    dt class=(FAINT) { "Client id" }
                    dd { code class=(CODE) { (request.client_id) } }
                }
                dt class=(FAINT) { "Returns to" }
                dd { code class=(CODE) { (consent.redirect_host) } }
                dt class=(FAINT) { "Acting as" }
                dd { (acting_as) }
                dt class=(FAINT) { "Resource" }
                dd { code class=(CODE) { (request.resource) } }
            }
            form method="post" action="/oauth/authorize/decision" class="mt-6 flex gap-3" {
                input type="hidden" name="csrf_token" value=(user.csrf_token);
                input type="hidden" name="request" value=(request.id);
                button class=(BUTTON) type="submit" name="decision" value="approve" {
                    "Approve"
                }
                button
                    class="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
                    type="submit"
                    name="decision"
                    value="deny"
                {
                    "Deny"
                }
            }
        }
    };
    render_layout(state, user, "Connect an app", &page)
}

/// The grants table with its Revoke buttons, as one swappable section.
pub(super) fn render_apps_section(grants: &[OauthGrant]) -> Markup {
    html! {
        section id="my-apps" class=(CARD) {
            h2 class=(HEADING) { "Connected apps" }
            p class=(format!("mt-1 {MUTED}")) {
                "Apps you let sign in to this gateway as you, such as an MCP client. Revoking one "
                "ends its access at once; it has to ask you again to reconnect."
            }
            @if grants.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No connected apps." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "App" }
                                th class=(TH) { "Resource" }
                                th class=(TH) { "Connected" }
                                th class=(TH) { "Last used" }
                                th class=(TH) { "Actions" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for grant in grants {
                                tr {
                                    td class=(TD) {
                                        (client_label(grant.client_name.as_deref(), &grant.client_id))
                                        @if let Some(host) = super::oauth::cimd_host(&grant.client_id) {
                                            div class=(format!("text-xs {FAINT}")) { (host) }
                                        } @else if grant.client_name.is_some() {
                                            div class=(format!("text-xs {FAINT}")) { (grant.client_id) }
                                        }
                                    }
                                    td class=(TD) { code class=(CODE) { (grant.resource) } }
                                    td class=(TD) { (when(grant.created_at)) }
                                    td class=(TD) {
                                        @if let Some(at) = grant.last_used_at {
                                            (when(at))
                                        } @else {
                                            span class=(FAINT) { "never" }
                                        }
                                    }
                                    td class=(TD) {
                                        button
                                            class=(BUTTON_DANGER)
                                            type="button"
                                            hx-post=(format!("/ui/actions/me/apps/{}/revoke", grant.id))
                                            hx-target="#my-apps"
                                            hx-swap="outerHTML"
                                            hx-confirm="Revoke this app? It stops working at once."
                                        {
                                            "Revoke"
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

/// Connected apps page (`GET /ui/me/apps`).
pub(super) fn render_apps_page(
    state: &AppState,
    user: &SessionUser,
    grants: &[OauthGrant],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Connected apps"
            }
        }
        (render_flash_area(false))
        (render_apps_section(grants))
    };
    render_layout(state, user, "Connected apps", &content)
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    fn grant(name: Option<&str>) -> OauthGrant {
        OauthGrant {
            id: Uuid::nil(),
            client_id: String::from("https://app.example/oauth/client.json"),
            client_name: name.map(String::from),
            user_id: Uuid::nil(),
            user_email: None,
            scope: String::from("mcp"),
            resource: String::from("https://gw.example/mcp"),
            created_at: Utc::now(),
            last_used_at: None,
        }
    }

    #[test]
    fn a_client_name_is_escaped() {
        let html = render_apps_section(&[grant(Some("<script>alert(1)</script>"))]).into_string();
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("app.example"));
        assert!(html.contains("/ui/actions/me/apps/00000000-0000-0000-0000-000000000000/revoke"));
    }

    #[test]
    fn no_grants_say_so() {
        let html = render_apps_section(&[]).into_string();
        assert!(html.contains("No connected apps."));
    }

    #[test]
    fn the_label_falls_back_to_the_client_id() {
        assert_eq!(client_label(None, "id"), "id");
        assert_eq!(client_label(Some("  "), "id"), "id");
        assert_eq!(client_label(Some("App"), "id"), "App");
    }
}
