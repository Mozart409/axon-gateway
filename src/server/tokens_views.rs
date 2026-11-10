//! HTML rendering (maud) for the token pages: a user's personal access tokens
//! (`/ui/tokens`) and the admin's service accounts with their tokens
//! (`/ui/admin/service-accounts`).
//!
//! Like `admin_views`, these are pure view functions and every section is
//! also the fragment an action answers with (`hx-target` the section's id,
//! `hx-swap="outerHTML"`). A token's secret is rendered only when a section is
//! given the [`IssuedToken`] that was just created; no list shows it.

use chrono::{DateTime, Utc};
use maud::{Markup, PreEscaped, html};

use super::AppState;
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, BUTTON_SMALL, CARD, CODE, FAINT, FORM_ROW, HEADING, INPUT,
    LABEL, MUTED, TABLE, TABLE_WRAP, TBODY, TD, TH, THEAD, render_flash_area, render_layout,
};
use crate::rbac::{TokenState, lifetime_days};
use crate::store::{
    ApiToken, DEFAULT_TOKEN_LIFETIME, IssuedToken, MAX_SERVICE_TOKEN_LIFETIME,
    MAX_USER_TOKEN_LIFETIME, PAT_PREFIX, ServiceAccount, SessionUser, Toolset,
};

/// A service account with its tokens
pub(super) struct AccountRow {
    pub account: ServiceAccount,
    pub tokens: Vec<ApiToken>,
}

/// Everything `/ui/admin/service-accounts` shows
pub(super) struct ServiceAccountsOverview {
    pub accounts: Vec<AccountRow>,
    /// Configured backends a token may be narrowed to
    pub backends: Vec<String>,
}

/// The token that was just created, for the one-time display: the name of the
/// service account it belongs to (none for a user's own) and the token.
pub(super) struct Issued<'a> {
    pub account: Option<&'a str>,
    pub issued: &'a IssuedToken,
}

fn when(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The box that shows a new token's plaintext, once
fn render_issued(issued: &Issued<'_>) -> Markup {
    html! {
        div
            class="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-800 dark:bg-emerald-950/40"
            role="status"
        {
            p class="text-sm font-semibold text-emerald-900 dark:text-emerald-200" {
                "Token " code { (issued.issued.token.name) } " created"
                @if let Some(account) = issued.account {
                    " for " code { (account) }
                }
            }
            p class="mt-1 text-sm text-emerald-900 dark:text-emerald-200" {
                "Copy it now: it will not be shown again."
            }
            code
                class="mt-2 block select-all break-all rounded-md bg-white px-3 py-2 font-mono text-sm text-slate-900 dark:bg-slate-900 dark:text-slate-100"
            {
                (issued.issued.plaintext)
            }
        }
    }
}

fn state_badge(state: TokenState) -> Markup {
    let classes = match state {
        TokenState::Active => {
            "rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300"
        }
        TokenState::Expired => {
            "rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800 dark:bg-amber-900/40 dark:text-amber-300"
        }
        TokenState::Revoked => {
            "rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-300"
        }
    };
    html! {
        span class=(classes) { (state.as_str()) }
    }
}

/// What a token is narrowed to
fn scope_cell(token: &ApiToken) -> Markup {
    html! {
        @if token.scope_backends.is_empty() && token.scope_tools.is_empty() && token.toolset_name.is_none() {
            span class=(FAINT) { "none" }
        }
        @if let Some(name) = &token.toolset_name {
            div {
                "toolset: "
                code class=(CODE) { (name) }
            }
        }
        @if !token.scope_backends.is_empty() {
            div {
                "backends: "
                code class=(CODE) { (token.scope_backends.join(", ")) }
            }
        }
        @if !token.scope_tools.is_empty() {
            div {
                "tools: "
                code class=(CODE) { (token.scope_tools.join(", ")) }
            }
        }
    }
}

/// The tokens of one owner. A live token has a revoke button that posts to
/// `revoke_path(token)` and swaps `target`.
fn render_token_table(
    tokens: &[ApiToken],
    target: &str,
    revoke_path: impl Fn(&ApiToken) -> String,
) -> Markup {
    html! {
        @if tokens.is_empty() {
            p class=(format!("mt-4 text-sm {FAINT}")) { "No tokens yet." }
        } @else {
            div class=(TABLE_WRAP) {
                table class=(TABLE) {
                    thead class=(THEAD) {
                        tr {
                            th class=(TH) { "Name" }
                            th class=(TH) { "Token" }
                            th class=(TH) { "Scope" }
                            th class=(TH) { "Created" }
                            th class=(TH) { "Expires" }
                            th class=(TH) { "Last used" }
                            th class=(TH) { "State" }
                            th class=(TH) { "Actions" }
                        }
                    }
                    tbody class=(TBODY) {
                        @for token in tokens {
                            @let state = TokenState::of(token);
                            tr {
                                td class=(TD) { (token.name) }
                                td class=(TD) {
                                    code class=(CODE) { (PAT_PREFIX) (token.public_id) "_" (PreEscaped("&hellip;")) }
                                }
                                td class=(TD) { (scope_cell(token)) }
                                td class=(TD) { (when(token.created_at)) }
                                td class=(TD) { (when(token.expires_at)) }
                                td class=(TD) {
                                    @if let Some(at) = token.last_used_at {
                                        (when(at))
                                    } @else {
                                        span class=(FAINT) { "never" }
                                    }
                                }
                                td class=(TD) { (state_badge(state)) }
                                td class=(TD) {
                                    @if state == TokenState::Active {
                                        button
                                            class=(BUTTON_DANGER)
                                            type="button"
                                            hx-post=(revoke_path(token))
                                            hx-target=(target)
                                            hx-swap="outerHTML"
                                            hx-confirm="Revoke this token? Clients using it stop working."
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

/// The form that issues a token. The backends are a multi-select (the
/// `scope_backends` key repeats), the tool globs one comma separated field. With
/// `toolsets` there is a select to pin the token to one of them.
fn render_token_form(
    action: &str,
    target: &str,
    max_days: u64,
    backends: &[String],
    toolsets: &[Toolset],
) -> Markup {
    html! {
        form
            class=(FORM_ROW)
            hx-post=(action)
            hx-target=(target)
            hx-swap="outerHTML"
        {
            label class=(LABEL) {
                "Name"
                input class=(INPUT) type="text" name="name" maxlength="100" placeholder="laptop" required;
            }
            label class=(LABEL) {
                "Expires in (days)"
                input
                    class=(format!("{INPUT} w-28"))
                    type="number"
                    name="expires_in_days"
                    min="1"
                    max=(max_days)
                    value=(lifetime_days(DEFAULT_TOKEN_LIFETIME));
            }
            @if !backends.is_empty() {
                label class=(LABEL) {
                    "Backends (none selected: all you may use)"
                    select class=(INPUT) name="scope_backends" multiple size=(backends.len().min(4)) {
                        @for backend in backends {
                            option value=(backend) { (backend) }
                        }
                    }
                }
            }
            label class=(LABEL) {
                "Tool globs (comma separated, optional)"
                input class=(format!("{INPUT} w-72")) type="text" name="scope_tools" placeholder="files_read_*, prom_*";
            }
            @if !toolsets.is_empty() {
                label class=(LABEL) {
                    "Toolset (optional, edits apply at once)"
                    select class=(INPUT) name="toolset_id" {
                        option value="" { "none" }
                        @for toolset in toolsets {
                            option value=(toolset.id) { (toolset.name) }
                        }
                    }
                }
            }
            button class=(BUTTON) type="submit" { "Create token" }
        }
    }
}

/// A user's own tokens and the create form, the swap target of the `tokens`
/// actions. `backends` are the backends the user is granted, `toolsets` the
/// user's own toolsets a token may be pinned to.
pub(super) fn render_tokens_section(
    tokens: &[ApiToken],
    backends: &[String],
    toolsets: &[Toolset],
    issued: Option<&IssuedToken>,
) -> Markup {
    html! {
        section id="my-tokens" class=(CARD) {
            h2 class=(HEADING) { "Personal access tokens" }
            p class=(format!("mt-1 {MUTED}")) {
                "A token lets a client such as an agent call /mcp as you, with "
                "Authorization: Bearer. It can only use what you may use, narrowed by its scope, "
                "and your hidden tools stay hidden. Tokens last "
                (lifetime_days(DEFAULT_TOKEN_LIFETIME)) " days unless you choose otherwise, at most "
                (lifetime_days(MAX_USER_TOKEN_LIFETIME)) ". They stop working when you have not "
                "logged in to the dashboard for 90 days."
            }
            @if let Some(issued) = issued {
                (render_issued(&Issued { account: None, issued }))
            }
            (render_token_table(tokens, "#my-tokens", |token| {
                format!("/ui/actions/tokens/{}/revoke", token.id)
            }))
            (render_token_form(
                "/ui/actions/tokens",
                "#my-tokens",
                lifetime_days(MAX_USER_TOKEN_LIFETIME),
                backends,
                toolsets,
            ))
        }
    }
}

/// Personal access tokens page (`GET /ui/tokens`).
pub(super) fn render_tokens_page(
    state: &AppState,
    user: &SessionUser,
    tokens: &[ApiToken],
    backends: &[String],
    toolsets: &[Toolset],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Tokens"
            }
        }
        (render_flash_area(false))
        (render_tokens_section(tokens, backends, toolsets, None))
    };
    render_layout(state, user, "Tokens", &content)
}

fn account_state_badge(account: &ServiceAccount) -> Markup {
    html! {
        @if account.disabled {
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

/// One service account: its buttons, tokens and the issue form
fn render_account(row: &AccountRow, backends: &[String]) -> Markup {
    let account = &row.account;
    let base = format!("/ui/actions/admin/service-accounts/{}", account.id);

    html! {
        div class="mt-6 border-t border-slate-200 pt-4 dark:border-slate-800" {
            div class="flex flex-wrap items-center gap-3" {
                h3 class="text-base font-semibold text-slate-900 dark:text-slate-100" {
                    (account.name)
                }
                (account_state_badge(account))
                @if let Some(description) = &account.description {
                    span class=(MUTED) { (description) }
                }
                form
                    hx-post=(format!("{base}/disabled"))
                    hx-target="#service-accounts"
                    hx-swap="outerHTML"
                {
                    input type="hidden" name="disabled" value=(if account.disabled { "false" } else { "true" });
                    button class=(BUTTON_SMALL) type="submit" {
                        @if account.disabled {
                            "Enable"
                        } @else {
                            "Disable"
                        }
                    }
                }
                button
                    class=(BUTTON_DANGER)
                    type="button"
                    hx-post=(format!("{base}/delete"))
                    hx-target="#service-accounts"
                    hx-swap="outerHTML"
                    hx-confirm=(format!("Delete the service account {}? Its tokens and group memberships go with it.", account.name))
                {
                    "Delete"
                }
            }
            (render_token_table(&row.tokens, "#service-accounts", |token| {
                format!("{base}/tokens/{}/revoke", token.id)
            }))
            (render_token_form(
                &format!("{base}/tokens"),
                "#service-accounts",
                lifetime_days(MAX_SERVICE_TOKEN_LIFETIME),
                backends,
                &[],
            ))
        }
    }
}

/// Service accounts with their tokens and the create form, the swap target of
/// the `service-accounts` actions.
pub(super) fn render_service_accounts_section(
    overview: &ServiceAccountsOverview,
    issued: Option<&Issued<'_>>,
) -> Markup {
    html! {
        section id="service-accounts" class=(CARD) {
            h2 class=(HEADING) { "Service accounts" }
            p class=(format!("mt-1 {MUTED}")) {
                "A service account is a principal for an agent or a script. Add it to groups on a "
                "group's page to give it tools; its tokens last "
                (lifetime_days(DEFAULT_TOKEN_LIFETIME)) " days unless you choose otherwise, at most "
                (lifetime_days(MAX_SERVICE_TOKEN_LIFETIME)) ". Disabling an account stops all its tokens."
            }
            @if let Some(issued) = issued {
                (render_issued(issued))
            }
            @if overview.accounts.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No service accounts yet." }
            }
            @for row in &overview.accounts {
                (render_account(row, &overview.backends))
            }
            form
                class=(FORM_ROW)
                hx-post="/ui/actions/admin/service-accounts"
                hx-target="#service-accounts"
                hx-swap="outerHTML"
            {
                label class=(LABEL) {
                    "Name"
                    input class=(INPUT) type="text" name="name" placeholder="ci-agent" required;
                }
                label class=(LABEL) {
                    "Description"
                    input class=(INPUT) type="text" name="description";
                }
                button class=(BUTTON) type="submit" { "Create service account" }
            }
        }
    }
}

/// Service accounts page (`GET /ui/admin/service-accounts`).
pub(super) fn render_service_accounts_page(
    state: &AppState,
    user: &SessionUser,
    overview: &ServiceAccountsOverview,
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Service accounts"
            }
        }
        (render_flash_area(false))
        (render_service_accounts_section(overview, None))
    };
    render_layout(state, user, "Service accounts", &content)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use uuid::Uuid;

    use super::*;
    use crate::server::tests::test_state;
    use crate::store::User;

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

    fn token(name: &str, revoked: bool, expires_in: Duration) -> ApiToken {
        ApiToken {
            id: Uuid::from_u128(7),
            public_id: String::from("0123456789abcdef"),
            owner_id: Uuid::nil(),
            name: name.to_owned(),
            scope_backends: vec![String::from("files")],
            scope_tools: Vec::new(),
            created_at: Utc::now(),
            expires_at: Utc::now() + expires_in,
            last_used_at: None,
            revoked,
            toolset_id: None,
            toolset_name: None,
        }
    }

    fn issued(name: &str) -> IssuedToken {
        IssuedToken {
            token: token(name, false, Duration::days(30)),
            plaintext: format!("{PAT_PREFIX}0123456789abcdef_{}", "ab".repeat(32)),
        }
    }

    #[tokio::test]
    async fn the_secret_shows_only_in_the_one_time_box() {
        let issued = issued("laptop");
        let tokens = [issued.token.clone()];

        let fresh = render_tokens_section(&tokens, &[String::from("files")], &[], Some(&issued))
            .into_string();
        assert!(fresh.contains(&issued.plaintext));
        assert!(fresh.contains("will not be shown again"));

        let listed = render_tokens_page(
            &test_state(),
            &session(),
            &tokens,
            &[String::from("files")],
            &[],
        )
        .into_string();
        assert!(!listed.contains(&issued.plaintext));
        assert!(!listed.contains(&"ab".repeat(32)));
        assert!(listed.contains("axon_pat_0123456789abcdef_"));
        assert!(listed.contains("/ui/actions/tokens/00000000-0000-0000-0000-000000000007/revoke"));
    }

    #[tokio::test]
    async fn only_live_tokens_can_be_revoked() {
        let tokens = [
            token("live", false, Duration::days(1)),
            token("old", false, Duration::days(-1)),
            token("gone", true, Duration::days(1)),
        ];
        let html = render_tokens_section(&tokens, &[], &[], None).into_string();

        assert_eq!(html.matches("/revoke\"").count(), 1);
        assert!(html.contains(">active<"));
        assert!(html.contains(">expired<"));
        assert!(html.contains(">revoked<"));
        // No granted backend, no backend select.
        assert!(!html.contains("scope_backends"));
    }

    #[tokio::test]
    async fn names_are_escaped() {
        let issued = issued("<script>alert(1)</script>");
        let overview = ServiceAccountsOverview {
            accounts: vec![AccountRow {
                account: ServiceAccount {
                    id: Uuid::from_u128(9),
                    name: String::from("<i>bot</i>"),
                    description: Some(String::from("<b>x</b>")),
                    disabled: true,
                    created_at: Utc::now(),
                },
                tokens: vec![issued.token.clone()],
            }],
            backends: vec![String::from("files")],
        };
        let html = render_service_accounts_section(
            &overview,
            Some(&Issued {
                account: Some("<i>bot</i>"),
                issued: &issued,
            }),
        )
        .into_string();

        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&lt;i&gt;bot&lt;/i&gt;"));
        assert!(html.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(!html.contains("<script>alert"));
        assert!(!html.contains("<i>bot</i>"));
        assert!(html.contains("hx-confirm="));
        assert!(html.contains(">Enable<"));
        assert!(html.contains(
            "/ui/actions/admin/service-accounts/00000000-0000-0000-0000-000000000009/disabled"
        ));
    }
}
