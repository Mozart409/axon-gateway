//! HTML rendering (maud) for the usage pages: a user's tool-call usage over a
//! window of days (totals, calls per day, backends, busiest tools) and, for
//! audit readers, the users by calls.
//!
//! Pure view functions in the style of `audit_views`, whose layout and class
//! constants they reuse. The handlers live in `usage_ui`. Calls per day are a
//! table with CSS bars, no chart library. The audit has no flag for personal
//! backends, so their calls show under the backend name they carry.

use maud::{Markup, PreEscaped, html};
use uuid::Uuid;

use super::AppState;
use super::admin_views::{
    BACK_LINK, CARD, CODE, FAINT, HEADING, LINK, MUTED, TABLE, TABLE_WRAP, TBODY, TD, TH, THEAD,
    render_layout,
};
use crate::store::{DailyUsage, SessionUser, UsageReport, UsageUser, UserUsageRow};

const H1: &str = "mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100";
const STATS: &str = "mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4";
const STAT: &str = "rounded-lg border border-slate-200 px-4 py-3 dark:border-slate-800";
const STAT_VALUE: &str = "text-2xl font-semibold text-slate-900 dark:text-slate-100";
const BAR_TRACK: &str = "h-2 w-full min-w-24 rounded bg-slate-100 dark:bg-slate-800";
/// The bar is an SVG rect: a `style` attribute would need `unsafe-inline` in the CSP.
const BAR: &str = "block h-2 w-full fill-orange-500 dark:fill-orange-400";
const NUMBER: &str = "whitespace-nowrap text-right tabular-nums";
/// The windows offered as links, in days
const WINDOWS: [i32; 3] = [7, 30, 90];

/// A count with thousands separators: `12345` as `12,345`.
fn thousands(value: i64) -> String {
    let digits = value.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if value < 0 {
        out.push('-');
    }
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A share between 0 and 1 as a percentage with one decimal: `12.5%`.
fn percent(rate: f64) -> String {
    format!("{:.1}%", rate * 100.0)
}

/// A duration in whole milliseconds, `-` when there was no call.
fn millis(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.0} ms"))
}

/// The width of a bar in whole percent: at least 1 for a day with calls.
fn bar_percent(calls: i64, most: i64) -> i64 {
    if calls <= 0 || most <= 0 {
        return 0;
    }
    (calls.saturating_mul(100) / most).clamp(1, 100)
}

fn window_links(base: &str, days: i32) -> Markup {
    html! {
        p class=(format!("mt-3 flex flex-wrap gap-3 text-sm {MUTED}")) {
            "Window:"
            @for window in WINDOWS {
                @if window == days {
                    span class="font-semibold text-slate-900 dark:text-slate-100" aria-current="true" {
                        (window) " days"
                    }
                } @else {
                    a href=(format!("{base}?days={window}")) class=(LINK) { (window) " days" }
                }
            }
        }
    }
}

fn stat(label: &str, value: &str) -> Markup {
    html! {
        div class=(STAT) {
            p class=(format!("text-xs {FAINT}")) { (label) }
            p class=(STAT_VALUE) { (value) }
        }
    }
}

fn totals_section(report: &UsageReport) -> Markup {
    let totals = &report.totals;
    html! {
        section class=(CARD) {
            h2 class=(HEADING) { "Totals" }
            div class=(STATS) {
                (stat("Calls", &thousands(totals.calls)))
                (stat("Errors", &thousands(totals.errors)))
                (stat("Error rate", &percent(totals.error_rate)))
                (stat("Tools", &thousands(totals.tools)))
                (stat("Backends", &thousands(totals.backends)))
                (stat("Median duration", &millis(totals.p50_ms)))
                (stat("p95 duration", &millis(totals.p95_ms)))
            }
        }
    }
}

fn daily_section(daily: &[DailyUsage]) -> Markup {
    let most = daily.iter().map(|day| day.calls).max().unwrap_or(0);
    html! {
        section class=(CARD) {
            h2 class=(HEADING) { "Calls per day" }
            p class=(format!("mt-1 {MUTED}")) { "UTC days, oldest first." }
            div class=(format!("mt-4 {TABLE_WRAP}")) {
                table class=(TABLE) {
                    thead class=(THEAD) {
                        tr {
                            th class=(TH) { "Date" }
                            th class=(TH) { "" }
                            th class=(format!("{TH} text-right")) { "Calls" }
                            th class=(format!("{TH} text-right")) { "Errors" }
                        }
                    }
                    tbody class=(TBODY) {
                        @for day in daily {
                            tr {
                                td class=(format!("{TD} whitespace-nowrap")) { (day.day.to_string()) }
                                td class=(format!("{TD} w-full")) {
                                    div class=(BAR_TRACK) {
                                        svg class=(BAR) aria-hidden="true" {
                                            rect width=(format!("{}%", bar_percent(day.calls, most))) height="100%" rx="4" {}
                                        }
                                    }
                                }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(day.calls)) }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(day.errors)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn backends_section(report: &UsageReport) -> Markup {
    html! {
        section class=(CARD) {
            h2 class=(HEADING) { "Backends" }
            div class=(format!("mt-4 {TABLE_WRAP}")) {
                table class=(TABLE) {
                    thead class=(THEAD) {
                        tr {
                            th class=(TH) { "Backend" }
                            th class=(format!("{TH} text-right")) { "Calls" }
                            th class=(format!("{TH} text-right")) { "Errors" }
                            th class=(format!("{TH} text-right")) { "Error rate" }
                            th class=(format!("{TH} text-right")) { "p95 duration" }
                        }
                    }
                    tbody class=(TBODY) {
                        @for backend in &report.backends {
                            tr {
                                td class=(TD) { code class=(CODE) { (backend.backend) } }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(backend.calls)) }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(backend.errors)) }
                                td class=(format!("{TD} {NUMBER}")) { (percent(backend.error_rate)) }
                                td class=(format!("{TD} {NUMBER}")) { (millis(backend.p95_ms)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn tools_section(report: &UsageReport) -> Markup {
    html! {
        section class=(CARD) {
            h2 class=(HEADING) { "Top tools" }
            div class=(format!("mt-4 {TABLE_WRAP}")) {
                table class=(TABLE) {
                    thead class=(THEAD) {
                        tr {
                            th class=(TH) { "Tool" }
                            th class=(TH) { "Backend" }
                            th class=(format!("{TH} text-right")) { "Calls" }
                            th class=(format!("{TH} text-right")) { "Errors" }
                        }
                    }
                    tbody class=(TBODY) {
                        @for tool in &report.tools {
                            tr {
                                td class=(TD) { code class=(CODE) { (tool.tool) } }
                                td class=(TD) { code class=(CODE) { (tool.backend) } }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(tool.calls)) }
                                td class=(format!("{TD} {NUMBER}")) { (thousands(tool.errors)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The window links and the sections of a report, or the empty state; `base`
/// is the page's own path, for the window links.
fn usage_body(report: &UsageReport, base: &str) -> Markup {
    html! {
        (window_links(base, report.days))
        @if report.totals.calls == 0 {
            section class=(CARD) {
                p class=(format!("text-sm {FAINT}")) {
                    "No calls in the last " (report.days) " days."
                }
            }
        } @else {
            (totals_section(report))
            (daily_section(&report.daily))
            (backends_section(report))
            (tools_section(report))
        }
    }
}

/// The signed-in user's own usage (`GET /ui/me/usage`).
pub(super) fn render_my_usage_page(
    state: &AppState,
    user: &SessionUser,
    report: &UsageReport,
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class=(H1) { "My usage" }
            p class=(format!("mt-2 {MUTED}")) {
                "Your tool calls through the gateway in the last " (report.days) " days."
            }
        }
        (usage_body(report, "/ui/me/usage"))
    };
    render_layout(state, user, "My usage", &content)
}

fn user_href(user_id: Uuid, days: i32) -> String {
    format!("/ui/admin/usage/{user_id}?days={days}")
}

/// The users-by-calls table, or the empty state.
fn users_table(days: i32, rows: &[UserUsageRow]) -> Markup {
    html! {
        section class=(CARD) {
            @if rows.is_empty() {
                p class=(format!("text-sm {FAINT}")) { "No calls in the last " (days) " days." }
            } @else {
                div class=(TABLE_WRAP) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "User" }
                                th class=(format!("{TH} text-right")) { "Calls" }
                                th class=(format!("{TH} text-right")) { "Errors" }
                                th class=(TH) { "Last call" }
                            }
                        }
                        tbody class=(TBODY) {
                            @for row in rows {
                                tr {
                                    td class=(TD) {
                                        a href=(user_href(row.user_id, days)) class=(LINK) {
                                            (row.user.label())
                                        }
                                        @if let Some(email) = row.user.email.as_deref()
                                            .filter(|email| *email != row.user.label())
                                        {
                                            span class=(format!("ml-2 text-xs {FAINT}")) { (email) }
                                        }
                                    }
                                    td class=(format!("{TD} {NUMBER}")) { (thousands(row.calls)) }
                                    td class=(format!("{TD} {NUMBER}")) { (thousands(row.errors)) }
                                    td class=(format!("{TD} whitespace-nowrap")) {
                                        (row.last_call.format("%Y-%m-%d %H:%M:%S UTC").to_string())
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

/// The users by calls (`GET /ui/admin/usage`).
pub(super) fn render_users_usage_page(
    state: &AppState,
    user: &SessionUser,
    days: i32,
    rows: &[UserUsageRow],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
            h1 class=(H1) { "Usage" }
            p class=(format!("mt-2 {MUTED}")) {
                "Users by tool calls in the last " (days) " days, most calls first."
            }
            (window_links("/ui/admin/usage", days))
        }
        (users_table(days, rows))
    };
    render_layout(state, user, "Usage", &content)
}

/// One user's usage as an audit reader sees it (`GET /ui/admin/usage/{user_id}`).
pub(super) fn render_user_usage_page(
    state: &AppState,
    user: &SessionUser,
    user_id: Uuid,
    subject: &UsageUser,
    report: &UsageReport,
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href=(format!("/ui/admin/usage?days={}", report.days)) class=(BACK_LINK) {
                (PreEscaped("&larr;")) " Back to usage"
            }
            h1 class=(H1) { "Usage of " (subject.label()) }
            p class=(format!("mt-2 {MUTED}")) {
                "Tool calls in the last " (report.days) " days. "
                a href=(format!("/ui/admin/tool-calls?user={user_id}")) class=(LINK) { "Show the calls" }
            }
        }
        (usage_body(report, &format!("/ui/admin/usage/{user_id}")))
    };
    render_layout(state, user, "Usage", &content)
}

#[cfg(test)]
mod tests {
    use chrono::{NaiveDate, TimeZone, Utc};

    use super::*;
    use crate::store::{BackendUsage, ToolUsage, UsageTotals};

    fn report(calls: i64) -> UsageReport {
        let day = |d: u32, calls: i64, errors: i64| DailyUsage {
            day: NaiveDate::from_ymd_opt(2026, 3, d).unwrap(),
            calls,
            errors,
        };
        UsageReport {
            days: 3,
            since: Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap(),
            totals: UsageTotals {
                calls,
                errors: 1_234,
                error_rate: 0.1234,
                tools: 2,
                backends: 1,
                p50_ms: (calls > 0).then_some(12.4),
                p95_ms: (calls > 0).then_some(250.6),
            },
            daily: vec![day(1, 0, 0), day(2, 5, 1), day(3, 10, 2)],
            backends: vec![BackendUsage {
                backend: "<b>files</b>".to_owned(),
                calls,
                errors: 1_234,
                error_rate: 0.5,
                p95_ms: Some(250.6),
            }],
            tools: vec![ToolUsage {
                backend: "files".to_owned(),
                tool: "read<file>".to_owned(),
                calls: 7,
                errors: 0,
            }],
        }
    }

    fn row(name: &str, email: Option<&str>) -> UserUsageRow {
        UserUsageRow {
            user_id: Uuid::nil(),
            user: UsageUser {
                display_name: Some(name.to_owned()),
                email: email.map(str::to_owned),
                subject: "sub".to_owned(),
            },
            calls: 1_500,
            errors: 3,
            last_call: Utc.with_ymd_and_hms(2026, 3, 3, 9, 8, 7).unwrap(),
        }
    }

    #[test]
    fn counts_get_thousands_separators() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(thousands(-12_345), "-12,345");
    }

    #[test]
    fn rates_and_durations_are_formatted() {
        assert_eq!(percent(0.1234), "12.3%");
        assert_eq!(percent(0.0), "0.0%");
        assert_eq!(millis(Some(250.6)), "251 ms");
        assert_eq!(millis(None), "-");
    }

    #[test]
    fn bars_are_scaled_to_the_busiest_day() {
        assert_eq!(bar_percent(0, 10), 0);
        assert_eq!(bar_percent(10, 10), 100);
        assert_eq!(bar_percent(5, 10), 50);
        assert_eq!(bar_percent(1, 1_000), 1);
        assert_eq!(bar_percent(3, 0), 0);
    }

    #[test]
    fn an_empty_report_says_so() {
        let html = usage_body(&report(0), "/ui/me/usage").into_string();
        assert!(html.contains("No calls in the last 3 days."));
        assert!(!html.contains("Calls per day"));
        assert!(html.contains("/ui/me/usage?days=7"));
        // 3 days is not one of the window links, so none is marked current
        assert!(!html.contains("aria-current"));
        assert!(html.contains("/ui/me/usage?days=90"));
    }

    #[test]
    fn a_report_shows_formatted_numbers_and_bars() {
        let html = usage_body(&report(12_345), "/ui/me/usage").into_string();
        assert!(html.contains("12,345"));
        assert!(html.contains("1,234"));
        assert!(html.contains("12.3%"));
        assert!(html.contains("12 ms"));
        assert!(html.contains("251 ms"));
        assert!(html.contains("2026-03-02"));
        assert!(html.contains(r#"width="50%""#));
        assert!(html.contains(r#"width="100%""#));
        assert!(html.contains(r#"width="0%""#));
        assert!(html.contains("Top tools"));
    }

    #[test]
    fn backend_and_tool_names_are_escaped() {
        let html = usage_body(&report(5), "/ui/me/usage").into_string();
        assert!(html.contains("&lt;b&gt;files&lt;/b&gt;"));
        assert!(html.contains("read&lt;file&gt;"));
        assert!(!html.contains("<b>files"));
    }

    #[test]
    fn the_users_table_links_each_user_and_escapes_names() {
        let rows = [row("<script>alert(1)</script>", Some("a@example.com"))];
        let html = users_table(30, &rows).into_string();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains(&format!("/ui/admin/usage/{}?days=30", Uuid::nil())));
        assert!(html.contains("a@example.com"));
        assert!(html.contains("1,500"));
        assert!(html.contains("2026-03-03 09:08:07 UTC"));
    }

    #[test]
    fn an_email_is_not_repeated_when_it_is_the_label() {
        let mut one = row("x", Some("a@example.com"));
        one.user.display_name = None;
        let html = users_table(30, &[one]).into_string();
        assert_eq!(html.matches("a@example.com").count(), 1);
    }

    #[test]
    fn the_users_table_has_an_empty_state() {
        let html = users_table(7, &[]).into_string();
        assert!(html.contains("No calls in the last 7 days."));
        assert!(!html.contains("<table"));
    }
}
