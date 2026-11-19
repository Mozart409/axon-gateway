//! HTML rendering (maud) for the tool-call audit pages: the call list, one
//! call with its stored arguments, and the capture rules with the retention
//! settings.
//!
//! Pure view functions in the style of `admin_views`, whose layout and class
//! constants they reuse. The handlers live in `audit_ui`. Arguments are only
//! rendered for a viewer who holds `audit.read_sensitive`, and only after the
//! "Show arguments" button posted: the read is an action and is audited.

use std::fmt::Write as _;

use maud::{Markup, html};
use serde_json::Value;

use super::AppState;
use super::admin_views::{
    BUTTON, BUTTON_DANGER, CODE, DESC, EMPTY, FORM_FOOT, INPUT, LABEL, LINK, LINK_BUTTON, TABLE,
    TD, render_flash_area, render_layout,
};
use super::shell::{Nav, icon};
use crate::audit::{AuditSettings, CaptureMode, CaptureRule, StoredArguments, ToolCallRecord};
use crate::audit_admin::MAX_RETENTION_DAYS;
use crate::store::SessionUser;

const BADGE: &str = "pill warn";

/// What `/ui/admin/tool-calls` shows: a page of calls and the filter values
/// that produced it.
pub(super) struct CallsPage {
    pub calls: Vec<ToolCallRecord>,
    /// The filter fields as typed, to fill the form and to build pager links
    pub user: String,
    pub backend: String,
    pub tool: String,
    pub outcome: String,
    /// The `before` of this page, when it is not the newest
    pub before: Option<i64>,
    /// The `before` of the next, older page, when there is one
    pub older: Option<i64>,
}

/// What `/ui/admin/tool-calls/{id}` shows
pub(super) struct CallDetail {
    pub call: ToolCallRecord,
    /// Whether the viewer holds `audit.read_sensitive`
    pub can_read_arguments: bool,
}

/// What `/ui/admin/audit-settings` shows
pub(super) struct SettingsPage {
    pub settings: AuditSettings,
    pub rules: Vec<CaptureRule>,
    /// Backends a rule may name
    pub backends: Vec<String>,
    /// Whether the viewer holds `gateway.admin`
    pub manage: bool,
}

/// Percent-encodes a query value.
pub(super) fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// The list URL with this page's filters and `before`.
fn calls_href(page: &CallsPage, before: Option<i64>) -> String {
    let mut params: Vec<String> = [
        ("user", &page.user),
        ("backend", &page.backend),
        ("tool", &page.tool),
        ("outcome", &page.outcome),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .map(|(name, value)| format!("{name}={}", encode_component(value)))
    .collect();
    if let Some(id) = before {
        params.push(format!("before={id}"));
    }
    if params.is_empty() {
        "/ui/admin/tool-calls".to_owned()
    } else {
        format!("/ui/admin/tool-calls?{}", params.join("&"))
    }
}

fn outcome_badge(outcome: &str) -> Markup {
    html! {
        @match outcome {
            "ok" => { span class="pill ok" { "ok" } }
            "tool_error" => { span class="pill warn" { "tool error" } }
            _ => { span class="pill err" { (outcome) } }
        }
    }
}

fn time(call: &ToolCallRecord) -> String {
    call.at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn mode_label(mode: CaptureMode) -> Markup {
    html! {
        @if mode == CaptureMode::Full {
            span class=(BADGE) { "full" }
        } @else {
            (mode.as_str())
        }
    }
}

/// The call list (`GET /ui/admin/tool-calls`).
pub(super) fn render_calls_page(state: &AppState, user: &SessionUser, page: &CallsPage) -> Markup {
    let content = html! {
        div class="page-head" {
            p {
                "Every call through the gateway, newest first. Arguments are stored only as "
                "the capture rules say."
            }
        }
        section class="card" {
            form class="card-b flex flex-wrap items-end gap-3" method="get" action="/ui/admin/tool-calls" {
                label class=(LABEL) {
                    "User id"
                    input class=(INPUT) type="text" name="user" value=(page.user);
                }
                label class=(LABEL) {
                    "Backend"
                    input class=(INPUT) type="text" name="backend" value=(page.backend);
                }
                label class=(LABEL) {
                    "Tool"
                    input class=(INPUT) type="text" name="tool" value=(page.tool);
                }
                label class=(LABEL) {
                    "Outcome"
                    select class=(INPUT) name="outcome" {
                        @for (value, label) in [("", "any"), ("ok", "ok"), ("error", "error"), ("tool_error", "tool error")] {
                            option value=(value) selected[page.outcome == value] { (label) }
                        }
                    }
                }
                button class=(BUTTON) type="submit" { "Filter" }
            }
        }
        (render_flash_area(false))
        section class="card" {
            div class="card-h" { h2 { "Tool calls" } }
            @if page.calls.is_empty() {
                p class=(EMPTY) { "No calls." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Tool calls" {
                    table class=(TABLE) {
                        thead {
                            tr {
                                th { "Time" }
                                th { "Principal" }
                                th { "Backend" }
                                th { "Tool" }
                                th { "Outcome" }
                                th { "Duration" }
                                th { "Arguments" }
                                th { "" }
                            }
                        }
                        tbody {
                            @for call in &page.calls {
                                tr {
                                    td class=(TD) { (time(call)) }
                                    td class=(TD) { (call.principal_label) }
                                    td class=(TD) { code class=(CODE) { (call.backend) } }
                                    td class=(TD) { code class=(CODE) { (call.tool) } }
                                    td class=(TD) { (outcome_badge(&call.outcome)) }
                                    td class=(TD) { (call.duration_ms) " ms" }
                                    td class=(TD) {
                                        @if let Some(capture) = &call.arguments_capture {
                                            (capture)
                                        } @else {
                                            span class="text-muted" { "-" }
                                        }
                                    }
                                    td class=(TD) {
                                        a href=(format!("/ui/admin/tool-calls/{}", call.id)) class=(LINK) {
                                            "Details"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if page.before.is_some() || page.older.is_some() {
                div class="card-f gap-2" {
                    @if page.before.is_some() {
                        a href=(calls_href(page, None)) class=(LINK_BUTTON) { "Newest" }
                    }
                    @if let Some(id) = page.older {
                        a href=(calls_href(page, Some(id))) class=(LINK_BUTTON) { "Older" }
                    }
                }
            }
        }
    };
    render_layout(state, user, "Tool calls", Nav::AdminToolCalls, &content)
}

fn detail_row(label: &str, value: &Markup) -> Markup {
    html! {
        dt { (label) }
        dd { (value) }
    }
}

fn optional(value: Option<&str>) -> Markup {
    html! {
        @if let Some(value) = value {
            (value)
        } @else {
            span class="text-muted" { "-" }
        }
    }
}

/// One call (`GET /ui/admin/tool-calls/{id}`).
pub(super) fn render_call_page(
    state: &AppState,
    user: &SessionUser,
    detail: &CallDetail,
) -> Markup {
    let call = &detail.call;
    let content = html! {
        div class="page-head" {
            p { "Tool call " (call.id) }
            span class="spacer" {}
            a href="/ui/admin/tool-calls" class=(LINK_BUTTON) { "Back to tool calls" }
        }
        section class="card" {
            div class="card-h" { h2 { "Details" } }
            dl class="kv card-b" {
                (detail_row("Time", &html! { (time(call)) }))
                (detail_row("Principal", &html! { (call.principal_label) }))
                (detail_row("User id", &optional(call.user_id.map(|id| id.to_string()).as_deref())))
                (detail_row("Token id", &optional(call.token_id.map(|id| id.to_string()).as_deref())))
                (detail_row("Auth method", &html! { (call.auth_method) }))
                (detail_row("Backend", &html! { code class=(CODE) { (call.backend) } }))
                (detail_row("Tool", &html! { code class=(CODE) { (call.tool) } }))
                (detail_row("Outcome", &outcome_badge(&call.outcome)))
                (detail_row("Error code", &optional(call.error_code.map(|code| code.to_string()).as_deref())))
                (detail_row("Error message", &optional(call.error_message.as_deref())))
                (detail_row("Duration", &html! { (call.duration_ms) " ms" }))
                (detail_row("Trace id", &optional(call.trace_id.as_deref())))
                (detail_row("Client IP", &optional(call.client_ip.as_deref())))
                (detail_row("User agent", &optional(call.user_agent.as_deref())))
            }
        }
        (render_flash_area(false))
        @if detail.can_read_arguments {
            (render_arguments_placeholder(call))
        }
    };
    render_layout(state, user, "Tool call", Nav::AdminToolCalls, &content)
}

/// The arguments block before the read: a button, or why there is nothing.
pub(super) fn render_arguments_placeholder(call: &ToolCallRecord) -> Markup {
    html! {
        section id="call-arguments" class="card" {
            div class="card-h" { h2 { "Arguments" } }
            @if let Some(capture) = &call.arguments_capture {
                p class=(EMPTY) {
                    "Stored " (capture) ". Showing them is recorded in the audit log."
                }
                div class="card-f" {
                    button
                        class=(BUTTON)
                        type="button"
                        hx-post=(format!("/ui/actions/admin/tool-calls/{}/arguments", call.id))
                        hx-target="#call-arguments"
                        hx-swap="outerHTML"
                    {
                        "Show arguments"
                    }
                }
            } @else {
                p class=(EMPTY) {
                    "No arguments are stored for this call: they were not captured, or are past their retention."
                }
            }
        }
    }
}

/// The arguments block after the read (the answer to the button).
pub(super) fn render_arguments_block(stored: &StoredArguments) -> Markup {
    let text = serde_json::to_string_pretty(&stored.arguments)
        .unwrap_or_else(|_| Value::to_string(&stored.arguments));
    html! {
        section id="call-arguments" class="card" {
            div class="card-h" { h2 { "Arguments" } }
            p class=(DESC) {
                "Stored " (stored.capture) ". This read was recorded in the audit log."
            }
            div class="card-b" {
                pre class="code" { (text) }
            }
        }
    }
}

/// The audit settings page (`GET /ui/admin/audit-settings`).
pub(super) fn render_settings_page(
    state: &AppState,
    user: &SessionUser,
    page: &SettingsPage,
) -> Markup {
    let content = html! {
        div class="page-head" {
            p {
                "What the tool call audit keeps, and for how long. "
                a href="/ui/admin/tool-calls" class=(LINK) { "Tool calls" }
            }
        }
        (render_flash_area(false))
        (render_retention_section(page, false))
        (render_rules_section(page, false))
    };
    render_layout(
        state,
        user,
        "Audit settings",
        Nav::AdminAuditSettings,
        &content,
    )
}

/// The retention form, the swap target of the settings action.
pub(super) fn render_retention_section(page: &SettingsPage, oob: bool) -> Markup {
    let settings = &page.settings;
    html! {
        section id="audit-settings" class="card" hx-swap-oob=[oob.then_some("true")] {
            div class="card-h" { h2 { "Retention" } }
            p class=(EMPTY) {
                "Arguments are kept for " (settings.arguments_retention_days) " days, call metadata for "
                (settings.metadata_retention_days) " days. Older rows are deleted hourly."
            }
            @if page.manage {
                form
                    class=(FORM_FOOT)
                    hx-post="/ui/actions/admin/audit-settings"
                    hx-target="#audit-settings"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Arguments (days)"
                        input class=(INPUT) type="number" name="arguments_retention_days"
                            min="1" max=(MAX_RETENTION_DAYS) required
                            value=(settings.arguments_retention_days);
                    }
                    label class=(LABEL) {
                        "Metadata (days)"
                        input class=(INPUT) type="number" name="metadata_retention_days"
                            min="1" max=(MAX_RETENTION_DAYS) required
                            value=(settings.metadata_retention_days);
                    }
                    button class=(BUTTON) type="submit" { "Save" }
                }
            }
        }
    }
}

/// The table of capture rules, with delete buttons for those who may manage.
fn rules_table(page: &SettingsPage) -> Markup {
    html! {
        div class="tbl-wrap mt-3 border-t border-border" tabindex="0" role="region" aria-label="Capture rules" {
            table class=(TABLE) {
                thead {
                    tr {
                        th { "Backend" }
                        th { "Tool pattern" }
                        th { "Capture" }
                        th { "Dropped keys" }
                        @if page.manage {
                            th { "Actions" }
                        }
                    }
                }
                tbody {
                    @for rule in &page.rules {
                        tr {
                            td class=(TD) { code class=(CODE) { (rule.backend) } }
                            td class=(TD) { code class=(CODE) { (rule.tool_pattern) } }
                            td class=(TD) { (mode_label(rule.mode)) }
                            td class=(TD) {
                                @if rule.drop_keys.is_empty() {
                                    span class="text-muted" { "-" }
                                } @else {
                                    code class=(CODE) { (rule.drop_keys.join(", ")) }
                                }
                            }
                            @if page.manage {
                                td class=(TD) {
                                    button
                                        class=(BUTTON_DANGER)
                                        type="button"
                                        hx-post=(format!("/ui/actions/admin/audit-rules/{}/delete", rule.id))
                                        hx-target="#audit-rules"
                                        hx-swap="outerHTML"
                                        hx-confirm="Delete this rule?"
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

/// The capture rules and the create form, the swap target of the rule actions.
pub(super) fn render_rules_section(page: &SettingsPage, oob: bool) -> Markup {
    html! {
        section id="audit-rules" class="card" hx-swap-oob=[oob.then_some("true")] {
            div class="card-h" { h2 { "Capture rules" } }
            p class=(DESC) {
                "Without a rule, a tool annotated read-only is not captured and every other "
                "tool is captured redacted: values under keys such as password, secret or "
                "token are masked and long strings are cut. The most specific rule wins: an "
                "exact backend over *, an exact tool name over a prefix, then the longer "
                "pattern, then the newer rule."
            }
            div class="banner mx-3.5 mt-3" {
                span class="text-warn" { (icon("triangle-alert")) }
                div {
                    strong { "Full capture needs a review first. " }
                    "It stores arguments exactly as sent, which are personal data (GDPR: purpose "
                    "limitation, retention, data-subject requests). Logging what employees do "
                    "with their tools is also subject to co-determination of the works council "
                    "(section 87(1) no. 6 BetrVG). Involve the works council and the data "
                    "protection officer before enabling it."
                }
            }
            @if page.rules.is_empty() {
                p class=(EMPTY) { "No rules yet." }
            } @else {
                (rules_table(page))
            }
            @if page.manage {
                form
                    class=(FORM_FOOT)
                    hx-post="/ui/actions/admin/audit-rules"
                    hx-target="#audit-rules"
                    hx-swap="outerHTML"
                {
                    label class=(LABEL) {
                        "Backend"
                        select class=(INPUT) name="backend" required {
                            option value="*" { "* (all backends)" }
                            @for backend in &page.backends {
                                option value=(backend) { (backend) }
                            }
                        }
                    }
                    label class=(LABEL) {
                        "Tool pattern"
                        input class=(INPUT) type="text" name="tool_pattern" required placeholder="run_query or pg*";
                    }
                    label class=(LABEL) {
                        "Capture"
                        select class=(INPUT) name="mode" required {
                            option value="none" { "none" }
                            option value="redacted" selected { "redacted" }
                            option value="full" { "full (needs a review)" }
                        }
                    }
                    label class=(LABEL) {
                        "Drop keys"
                        input class=(INPUT) type="text" name="drop_keys" placeholder="content, body";
                    }
                    button class=(BUTTON) type="submit" { "Add rule" }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;

    fn call(id: i64, capture: Option<&str>) -> ToolCallRecord {
        ToolCallRecord {
            id,
            at: Utc::now(),
            user_id: None,
            principal_label: "alice".to_owned(),
            token_id: None,
            auth_method: "pat".to_owned(),
            backend: "files".to_owned(),
            tool: "read_file".to_owned(),
            outcome: "ok".to_owned(),
            error_code: None,
            error_message: None,
            duration_ms: 3,
            trace_id: None,
            client_ip: None,
            user_agent: None,
            arguments_capture: capture.map(str::to_owned),
        }
    }

    fn page(manage: bool) -> SettingsPage {
        SettingsPage {
            settings: AuditSettings {
                arguments_retention_days: 30,
                metadata_retention_days: 365,
            },
            rules: vec![CaptureRule {
                id: 7,
                backend: "pg".to_owned(),
                tool_pattern: "run_*".to_owned(),
                mode: CaptureMode::Full,
                drop_keys: vec!["content".to_owned()],
            }],
            backends: vec!["pg".to_owned()],
            manage,
        }
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(encode_component("read_file-1.x~"), "read_file-1.x~");
        assert_eq!(encode_component("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }

    #[test]
    fn pager_links_keep_the_filters() {
        let mut page = CallsPage {
            calls: Vec::new(),
            user: String::new(),
            backend: "files".to_owned(),
            tool: "a b".to_owned(),
            outcome: String::new(),
            before: None,
            older: None,
        };
        assert_eq!(
            calls_href(&page, Some(42)),
            "/ui/admin/tool-calls?backend=files&tool=a%20b&before=42"
        );
        assert_eq!(
            calls_href(&page, None),
            "/ui/admin/tool-calls?backend=files&tool=a%20b"
        );
        page.backend.clear();
        page.tool.clear();
        assert_eq!(calls_href(&page, None), "/ui/admin/tool-calls");
    }

    #[test]
    fn the_arguments_button_posts_and_shows_no_arguments() {
        let html = render_arguments_placeholder(&call(5, Some("redacted"))).into_string();
        assert!(html.contains("Show arguments"));
        assert!(html.contains("hx-post=\"/ui/actions/admin/tool-calls/5/arguments\""));
        assert!(!html.contains("<pre"));

        let html = render_arguments_placeholder(&call(5, None)).into_string();
        assert!(!html.contains("Show arguments"));
    }

    #[test]
    fn stored_arguments_are_escaped() {
        let stored = StoredArguments {
            call_id: 5,
            at: Utc::now(),
            capture: "full".to_owned(),
            arguments: json!({"q": "<script>alert(1)</script>"}),
        };
        let html = render_arguments_block(&stored).into_string();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("recorded in the audit log"));
    }

    #[test]
    fn rules_render_with_the_gdpr_warning_and_management_only_for_admins() {
        let admin = render_rules_section(&page(true), false).into_string();
        assert!(admin.contains("BetrVG"));
        assert!(admin.contains("GDPR"));
        assert!(admin.contains("Add rule"));
        assert!(admin.contains("/ui/actions/admin/audit-rules/7/delete"));

        let viewer = render_rules_section(&page(false), false).into_string();
        assert!(viewer.contains("BetrVG"));
        assert!(!viewer.contains("Add rule"));
        assert!(!viewer.contains("/delete"));
    }

    #[test]
    fn the_retention_form_is_for_admins() {
        let admin = render_retention_section(&page(true), false).into_string();
        assert!(admin.contains("name=\"arguments_retention_days\""));
        assert!(admin.contains("30 days"));
        let viewer = render_retention_section(&page(false), true).into_string();
        assert!(!viewer.contains("<form"));
        assert!(viewer.contains("hx-swap-oob=\"true\""));
    }
}
