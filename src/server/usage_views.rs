//! HTML rendering (maud) for the usage pages: a user's tool-call usage over a
//! window of days (KPIs, calls per day, backends, busiest tools) and, for
//! audit readers, the users by calls.
//!
//! Pure view functions in the style of `audit_views`. The shell supplies the
//! title (its `h1`), so the pages carry none. The handlers live in `usage_ui`.
//! The charts are inline SVG computed here: the CSP forbids `style=`
//! attributes and inline scripts, so bar geometry is in SVG attributes, colors
//! come from classes and hover readouts are `<title>` children. The audit has
//! no flag for personal backends, so their calls show under the backend name
//! they carry.

use maud::{Markup, PreEscaped, html};
use uuid::Uuid;

use super::AppState;
use super::admin_views::render_layout;
use super::shell::Nav;
use crate::store::{DailyUsage, SessionUser, UsageReport, UsageUser, UserUsageRow};

const BACK_LINK: &str =
    "inline-flex min-h-6 items-center gap-1 text-xs font-medium text-muted hover:text-text";
const LINK: &str = "font-medium text-accent hover:underline";
const NUMBER: &str = "text-right tabular-nums";
/// The windows offered as links, in days
const WINDOWS: [i32; 3] = [7, 30, 90];

/// The calls-per-day chart's coordinate space. The SVG stretches to its
/// container's width (`preserveAspectRatio="none"`) and is `CHART_H` px tall,
/// so a unit is about a pixel at the usual width.
const CHART_W: f64 = 720.0;
const CHART_H: f64 = 200.0;
/// The gap between bars, and the widest a bar gets (few days in the window)
const BAR_GAP: f64 = 2.0;
const BAR_MAX_W: f64 = 48.0;

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

/// The width of a bar in whole percent: at least 1 for a count above zero.
fn bar_percent(calls: i64, most: i64) -> i64 {
    if calls <= 0 || most <= 0 {
        return 0;
    }
    (calls.saturating_mul(100) / most).clamp(1, 100)
}

/// `1 call` / `2 calls`
fn calls_label(calls: i64) -> String {
    format!(
        "{} {}",
        thousands(calls),
        if calls == 1 { "call" } else { "calls" }
    )
}

/// `1 error` / `2 errors`
fn errors_label(errors: i64) -> String {
    format!(
        "{} {}",
        thousands(errors),
        if errors == 1 { "error" } else { "errors" }
    )
}

/// The top of the y axis: the next 1, 2 or 5 times a power of ten, made even
/// so the middle gridline has a whole label.
fn axis_top(most: i64) -> i64 {
    let most = most.max(1);
    let mut magnitude = 1_i64;
    while magnitude.saturating_mul(10) <= most {
        magnitude = magnitude.saturating_mul(10);
    }
    let top = [1, 2, 5, 10]
        .into_iter()
        .map(|step| step * magnitude)
        .find(|top| *top >= most)
        .unwrap_or(most);
    top + top % 2
}

/// A count as a share of a ceiling, in `0.0..=1.0`.
#[allow(
    clippy::cast_precision_loss,
    reason = "call counts stay far below 2^52"
)]
fn ratio(part: i64, whole: i64) -> f64 {
    if part <= 0 || whole <= 0 {
        return 0.0;
    }
    (part as f64 / whole as f64).min(1.0)
}

/// A segment height in chart units: at least 1 for a count above zero.
fn segment_height(count: i64, top: i64) -> f64 {
    if count <= 0 {
        return 0.0;
    }
    (ratio(count, top) * CHART_H).max(1.0)
}

/// The window choice: links styled as the mockup's segmented control.
fn window_links(base: &str, days: i32) -> Markup {
    html! {
        div class="seg" role="group" aria-label="Time range" {
            @for window in WINDOWS {
                a href=(format!("{base}?days={window}"))
                    aria-current=[(window == days).then_some("true")] { (window) " days" }
            }
        }
    }
}

/// The head of a page: what it shows on the left, the window choice on the right.
fn page_head(lead: &Markup, base: &str, days: i32) -> Markup {
    html! {
        div class="page-head" {
            div class="flex min-w-64 flex-1 flex-col gap-1" { (lead) }
            (window_links(base, days))
        }
    }
}

fn kpi(label: &str, value: &str, sub: &str, is_error: bool) -> Markup {
    html! {
        div class="card kpi" {
            span class="kpi-label" { (label) }
            span class=(if is_error { "kpi-value tabular-nums text-err" } else { "kpi-value tabular-nums" }) {
                (value)
            }
            span class="text-xs text-muted" { (sub) }
        }
    }
}

fn kpis_section(report: &UsageReport) -> Markup {
    let totals = &report.totals;
    html! {
        div class="kpis" {
            (kpi(
                "Tool calls",
                &thousands(totals.calls),
                &format!("in the last {} days", report.days),
                false,
            ))
            (kpi(
                "Errors",
                &thousands(totals.errors),
                &format!("{} of calls", percent(totals.error_rate)),
                totals.errors > 0,
            ))
            (kpi(
                "p95 latency",
                &millis(totals.p95_ms),
                &format!("p50 {}", millis(totals.p50_ms)),
                false,
            ))
            (kpi(
                "Tools",
                &thousands(totals.tools),
                &format!("on {} backends", thousands(totals.backends)),
                false,
            ))
        }
    }
}

/// A horizontal share bar: an SVG track and fill (a `style` width would need
/// `unsafe-inline`; SVG geometry attributes are not CSS).
fn share_bar(percent: i64) -> Markup {
    html! {
        svg class="block h-1.5 w-full" aria-hidden="true" {
            rect class="fill-surface-2" width="100%" height="100%" rx="3" {}
            @if percent > 0 {
                rect class="fill-accent" width=(format!("{percent}%")) height="100%" rx="3" {}
            }
        }
    }
}

/// The stacked bars of the days: successful calls in the accent color, errors
/// on top in the error color, one `<title>` per day for the hover readout.
fn daily_section(daily: &[DailyUsage]) -> Markup {
    let most = daily.iter().map(|day| day.calls).max().unwrap_or(0);
    let top = axis_top(most);
    let has_errors = daily.iter().any(|day| day.errors > 0);
    #[allow(
        clippy::cast_precision_loss,
        reason = "a window has at most a few hundred days"
    )]
    let slot = CHART_W / daily.len().max(1) as f64;
    let bar_w = (slot - BAR_GAP).clamp(1.0, BAR_MAX_W);
    let pad = (slot - bar_w) / 2.0;
    let last = daily.len().saturating_sub(1);
    let first_day = daily
        .first()
        .map(|day| day.day.format("%b %-d").to_string());
    let middle_day = (daily.len() > 2)
        .then(|| daily.get(daily.len() / 2))
        .flatten()
        .map(|day| day.day.format("%b %-d").to_string());
    let last_day = (last > 0)
        .then(|| daily.get(last))
        .flatten()
        .map(|day| day.day.format("%b %-d").to_string());
    html! {
        section class="card" {
            div class="card-h" {
                h2 { "Calls per day" }
                span class="muted text-xs" { "UTC days, oldest first" }
                span class="spacer" {}
                @if has_errors {
                    div class="legend" {
                        span { span class="swatch bg-accent" {} "Successful" }
                        span { span class="swatch bg-err" {} "Errors" }
                    }
                }
            }
            div class="card-b" {
                div class="chart" {
                    div class="chart-y" aria-hidden="true" {
                        span { (thousands(top)) }
                        span { (thousands(top / 2)) }
                        span { "0" }
                    }
                    div {
                        svg class="chart-svg" viewBox=(format!("0 0 {CHART_W} {CHART_H}"))
                            preserveAspectRatio="none" role="img"
                            aria-label="Calls per day, successful and failed" {
                            line class="chart-grid" x1="0" x2=(CHART_W) y1="0.5" y2="0.5" {}
                            line class="chart-grid" x1="0" x2=(CHART_W)
                                y1=(CHART_H / 2.0) y2=(CHART_H / 2.0) {}
                            @for (index, day) in daily.iter().enumerate() {
                                @let ok_h = segment_height((day.calls - day.errors).max(0), top);
                                @let err_h = segment_height(day.errors, top);
                                @let left = slot * f64::from(u32::try_from(index).unwrap_or(0));
                                g class="bar-g" {
                                    title {
                                        (day.day.to_string()) ": " (calls_label(day.calls))
                                        ", " (errors_label(day.errors))
                                    }
                                    rect class="bar-hit" x=(format!("{left:.2}"))
                                        y="0" width=(format!("{slot:.2}")) height=(CHART_H) {}
                                    @if ok_h > 0.0 {
                                        rect class="fill-accent" x=(format!("{:.2}", left + pad))
                                            y=(format!("{:.2}", CHART_H - ok_h))
                                            width=(format!("{bar_w:.2}"))
                                            height=(format!("{ok_h:.2}")) {}
                                    }
                                    @if err_h > 0.0 {
                                        rect class="fill-err" x=(format!("{:.2}", left + pad))
                                            y=(format!("{:.2}", CHART_H - ok_h - err_h))
                                            width=(format!("{bar_w:.2}"))
                                            height=(format!("{err_h:.2}")) {}
                                    }
                                }
                            }
                        }
                        div class="x-axis" {
                            span { (first_day.unwrap_or_default()) }
                            @if let Some(middle) = middle_day { span { (middle) } }
                            @if let Some(end) = last_day { span { (end) } }
                        }
                    }
                }
            }
        }
    }
}

/// The backends by calls, each with a bar for its share of all calls.
fn backends_section(report: &UsageReport) -> Markup {
    let total = report.totals.calls;
    html! {
        section class="card" {
            div class="card-h" {
                h2 { "Backends" }
                span class="spacer" {}
                span class="text-xs text-muted" { "calls · error rate" }
            }
            div class="card-b flex flex-col gap-3" {
                @for backend in &report.backends {
                    div class="flex flex-col gap-1" {
                        div class="flex items-baseline gap-2" {
                            span class="mono" { (backend.backend) }
                            span class="text-xs text-muted" { "p95 " (millis(backend.p95_ms)) }
                            span class="spacer" {}
                            span class="tabular-nums" { (thousands(backend.calls)) }
                            span class=(if backend.errors > 0 {
                                "w-16 text-right tabular-nums text-err"
                            } else {
                                "w-16 text-right tabular-nums text-muted"
                            }) { (percent(backend.error_rate)) }
                        }
                        (share_bar(bar_percent(backend.calls, total)))
                    }
                }
            }
        }
    }
}

fn tools_section(report: &UsageReport) -> Markup {
    html! {
        section class="card" {
            div class="card-h" {
                h2 { "Top tools" }
                span class="text-xs text-muted" { (thousands(report.totals.tools)) " used" }
            }
            div class="tbl-wrap" tabindex="0" role="region" aria-label="Top tools" {
                table class="tbl" {
                    thead {
                        tr {
                            th { "Tool" }
                            th { "Backend" }
                            th class="text-right" { "Calls" }
                            th class="text-right" { "Errors" }
                        }
                    }
                    tbody {
                        @for tool in &report.tools {
                            tr {
                                td class="mono" { (tool.tool) }
                                td class="mono text-muted" { (tool.backend) }
                                td class=(NUMBER) { (thousands(tool.calls)) }
                                td class=(if tool.errors > 0 {
                                    "text-right tabular-nums text-err"
                                } else {
                                    "text-right tabular-nums text-muted"
                                }) { (thousands(tool.errors)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The sections of a report, or the empty state.
fn usage_body(report: &UsageReport) -> Markup {
    html! {
        @if report.totals.calls == 0 {
            section class="card" {
                p class="card-b text-muted" { "No calls in the last " (report.days) " days." }
            }
        } @else {
            (kpis_section(report))
            (daily_section(&report.daily))
            (backends_section(report))
            (tools_section(report))
        }
    }
}

/// The live region for the signed-in user's own usage: refetches the body on
/// `usage_changed` SSE events.
pub(super) fn my_usage_region(days: i32, report: &UsageReport) -> Markup {
    html! {
        div hx-ext="sse" sse-connect="/ui/events" {
            div id="my-usage-region"
                hx-get=(format!("/ui/partials/usage?days={days}"))
                hx-trigger="sse:usage_changed"
                hx-swap="outerHTML" {
                (usage_body(report))
            }
        }
    }
}

/// The live region for the users-by-calls table: refetches on `usage_changed`.
pub(super) fn users_usage_region(days: i32, rows: &[UserUsageRow]) -> Markup {
    html! {
        div hx-ext="sse" sse-connect="/ui/events" {
            div id="users-usage-region"
                hx-get=(format!("/ui/partials/admin/usage?days={days}"))
                hx-trigger="sse:usage_changed"
                hx-swap="outerHTML" {
                (users_table(days, rows))
            }
        }
    }
}

/// The live region for one user's usage: refetches on `usage_changed`.
pub(super) fn user_usage_region(user_id: Uuid, days: i32, report: &UsageReport) -> Markup {
    html! {
        div hx-ext="sse" sse-connect="/ui/events" {
            div id="user-usage-region"
                hx-get=(format!("/ui/partials/admin/usage/{user_id}?days={days}"))
                hx-trigger="sse:usage_changed"
                hx-swap="outerHTML" {
                (usage_body(report))
            }
        }
    }
}

/// The signed-in user's own usage (`GET /ui/me/usage`).
pub(super) fn render_my_usage_page(
    state: &AppState,
    user: &SessionUser,
    report: &UsageReport,
) -> Markup {
    let lead = html! {
        a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
        p { "Your tool calls through the gateway in the last " (report.days) " days." }
    };
    let content = html! {
        (page_head(&lead, "/ui/me/usage", report.days))
        (my_usage_region(report.days, report))
    };
    render_layout(state, user, "My usage", Nav::Usage, &content)
}

fn user_href(user_id: Uuid, days: i32) -> String {
    format!("/ui/admin/usage/{user_id}?days={days}")
}

/// The users-by-calls table, or the empty state.
fn users_table(days: i32, rows: &[UserUsageRow]) -> Markup {
    html! {
        section class="card" {
            @if rows.is_empty() {
                p class="card-b text-muted" { "No calls in the last " (days) " days." }
            } @else {
                div class="tbl-wrap" tabindex="0" role="region" aria-label="Users by calls" {
                    table class="tbl" {
                        thead {
                            tr {
                                th { "User" }
                                th class="text-right" { "Calls" }
                                th class="text-right" { "Errors" }
                                th { "Last call" }
                            }
                        }
                        tbody {
                            @for row in rows {
                                tr {
                                    td {
                                        a href=(user_href(row.user_id, days)) class=(LINK) {
                                            (row.user.label())
                                        }
                                        @if let Some(email) = row.user.email.as_deref()
                                            .filter(|email| *email != row.user.label())
                                        {
                                            span class="ml-2 text-xs text-muted" { (email) }
                                        }
                                    }
                                    td class=(NUMBER) { (thousands(row.calls)) }
                                    td class=(if row.errors > 0 {
                                        "text-right tabular-nums text-err"
                                    } else {
                                        "text-right tabular-nums text-muted"
                                    }) { (thousands(row.errors)) }
                                    td class="mono text-muted" {
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
    let lead = html! {
        a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to admin" }
        p { "Users by tool calls in the last " (days) " days, most calls first." }
    };
    let content = html! {
        (page_head(&lead, "/ui/admin/usage", days))
        (users_usage_region(days, rows))
    };
    render_layout(state, user, "Usage", Nav::Admin, &content)
}

/// One user's usage as an audit reader sees it (`GET /ui/admin/usage/{user_id}`).
pub(super) fn render_user_usage_page(
    state: &AppState,
    user: &SessionUser,
    user_id: Uuid,
    subject: &UsageUser,
    report: &UsageReport,
) -> Markup {
    let lead = html! {
        a href=(format!("/ui/admin/usage?days={}", report.days)) class=(BACK_LINK) {
            (PreEscaped("&larr;")) " Back to usage"
        }
        p class="font-semibold text-text" { "Usage of " (subject.label()) }
        p {
            "Tool calls in the last " (report.days) " days. "
            a href=(format!("/ui/admin/tool-calls?user={user_id}")) class=(LINK) { "Show the calls" }
        }
    };
    let content = html! {
        (page_head(&lead, &format!("/ui/admin/usage/{user_id}"), report.days))
        (user_usage_region(user_id, report.days, report))
    };
    render_layout(state, user, "Usage", Nav::Admin, &content)
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
        let html = usage_body(&report(0)).into_string();
        assert!(html.contains("No calls in the last 3 days."));
        assert!(!html.contains("Calls per day"));
        assert!(!html.contains("<svg"));
    }

    #[test]
    fn the_window_links_mark_the_current_window() {
        let html = window_links("/ui/me/usage", 3).into_string();
        assert!(html.contains("/ui/me/usage?days=7"));
        // 3 days is not one of the window links, so none is marked current
        assert!(!html.contains("aria-current"));
        assert!(html.contains("/ui/me/usage?days=90"));
        let html = window_links("/ui/me/usage", 30).into_string();
        assert_eq!(html.matches("aria-current").count(), 1);
    }

    #[test]
    fn a_report_shows_formatted_numbers_and_charts() {
        let html = usage_body(&report(12_345)).into_string();
        assert!(html.contains("12,345"));
        assert!(html.contains("1,234"));
        assert!(html.contains("12.3%"));
        assert!(html.contains("12 ms"));
        assert!(html.contains("251 ms"));
        // the hover readouts of the days, the stacked bars and the share bar
        assert!(html.contains("2026-03-02: 5 calls, 1 error"));
        assert!(html.contains("2026-03-03: 10 calls, 2 errors"));
        assert!(html.contains("fill-accent"));
        assert!(html.contains("fill-err"));
        assert!(html.contains(r#"width="100%""#));
        assert!(html.contains("Top tools"));
        assert!(!html.contains("style="));
    }

    #[test]
    fn the_axis_top_is_a_round_even_number() {
        assert_eq!(axis_top(0), 2);
        assert_eq!(axis_top(1), 2);
        assert_eq!(axis_top(5), 6);
        assert_eq!(axis_top(10), 10);
        assert_eq!(axis_top(11), 20);
        assert_eq!(axis_top(480), 500);
    }

    #[test]
    fn backend_and_tool_names_are_escaped() {
        let html = usage_body(&report(5)).into_string();
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

    #[test]
    fn my_usage_region_has_expected_wiring() {
        let html = my_usage_region(7, &report(12_345)).into_string();
        assert!(html.contains("sse-connect=\"/ui/events\""));
        assert!(html.contains("id=\"my-usage-region\""));
        assert!(html.contains("hx-get=\"/ui/partials/usage?days=7\""));
        assert!(html.contains("hx-trigger=\"sse:usage_changed\""));
        assert!(html.contains("hx-swap=\"outerHTML\""));
    }

    #[test]
    fn users_usage_region_has_expected_wiring() {
        let rows = [row("alice", Some("a@example.com"))];
        let html = users_usage_region(30, &rows).into_string();
        assert!(html.contains("sse-connect=\"/ui/events\""));
        assert!(html.contains("id=\"users-usage-region\""));
        assert!(html.contains("hx-get=\"/ui/partials/admin/usage?days=30\""));
        assert!(html.contains("hx-trigger=\"sse:usage_changed\""));
        assert!(html.contains("hx-swap=\"outerHTML\""));
    }

    #[test]
    fn user_usage_region_has_expected_wiring() {
        let html = user_usage_region(Uuid::nil(), 7, &report(5)).into_string();
        assert!(html.contains("sse-connect=\"/ui/events\""));
        assert!(html.contains("id=\"user-usage-region\""));
        assert!(html.contains(&format!(
            "hx-get=\"/ui/partials/admin/usage/{}?days=7\"",
            Uuid::nil()
        )));
        assert!(html.contains("hx-trigger=\"sse:usage_changed\""));
        assert!(html.contains("hx-swap=\"outerHTML\""));
    }
}
