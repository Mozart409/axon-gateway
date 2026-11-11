//! Per-user usage aggregates over the tool-call audit
//!
//! Read-only queries on `tool_calls`. The window is whole UTC days: `days`
//! days ending with today, so the daily series and the totals cover the same
//! calls. An error is any outcome but `ok`. The audit keeps no flag for
//! personal backends, so their calls show under the backend name they carry.

use std::collections::HashMap;

use chrono::{DateTime, Days, NaiveDate, NaiveTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::{Store, StoreError};

/// The window of a report when the caller names none, in days
pub const DEFAULT_USAGE_DAYS: i32 = 30;
/// The longest window of a report, in days
pub const MAX_USAGE_DAYS: i32 = 90;
/// Tools in the top list
const TOP_TOOLS: i64 = 10;

/// Totals over the window
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct UsageTotals {
    pub calls: i64,
    pub errors: i64,
    /// Between 0 and 1; 0 without calls
    pub error_rate: f64,
    /// Distinct (backend, tool) pairs
    pub tools: i64,
    pub backends: i64,
    /// `None` without calls
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// One UTC day of the window
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyUsage {
    pub day: NaiveDate,
    pub calls: i64,
    pub errors: i64,
}

#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct BackendUsage {
    pub backend: String,
    pub calls: i64,
    pub errors: i64,
    pub error_rate: f64,
    pub p95_ms: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ToolUsage {
    pub backend: String,
    pub tool: String,
    pub calls: i64,
    pub errors: i64,
}

/// One user's usage over the window
#[derive(Debug, Clone, PartialEq)]
pub struct UsageReport {
    /// The window in days, after clamping
    pub days: i32,
    /// First instant of the window (00:00 UTC of its first day)
    pub since: DateTime<Utc>,
    pub totals: UsageTotals,
    /// Oldest day first, one entry per day of the window, empty days included
    pub daily: Vec<DailyUsage>,
    /// Most calls first
    pub backends: Vec<BackendUsage>,
    /// The ten busiest tools, most calls first
    pub tools: Vec<ToolUsage>,
}

/// How a user is named on the usage pages
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UsageUser {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub subject: String,
}

impl UsageUser {
    /// Display name, else email, else subject.
    #[must_use]
    pub fn label(&self) -> &str {
        [self.display_name.as_deref(), self.email.as_deref()]
            .into_iter()
            .flatten()
            .find(|label| !label.trim().is_empty())
            .unwrap_or(&self.subject)
    }
}

/// A row of the users-by-calls table
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserUsageRow {
    pub user_id: Uuid,
    #[sqlx(flatten)]
    pub user: UsageUser,
    pub calls: i64,
    pub errors: i64,
    pub last_call: DateTime<Utc>,
}

/// The window as (days after clamping, first day, first instant)
fn window(today: NaiveDate, days: i32) -> (i32, NaiveDate, DateTime<Utc>) {
    let days = days.clamp(1, MAX_USAGE_DAYS);
    let back = Days::new(u64::try_from(days - 1).unwrap_or(0));
    let first = today.checked_sub_days(back).unwrap_or(today);
    (days, first, first.and_time(NaiveTime::MIN).and_utc())
}

impl Store {
    /// A user's usage over the last `days` days (clamped to 1..=90).
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn user_usage(&self, user_id: Uuid, days: i32) -> Result<UsageReport, StoreError> {
        let (days, first, since) = window(Utc::now().date_naive(), days);

        let totals: UsageTotals = sqlx::query_as(
            "select count(*) as calls, \
                    count(*) filter (where outcome <> 'ok') as errors, \
                    coalesce((count(*) filter (where outcome <> 'ok'))::float8 \
                             / nullif(count(*), 0), 0)::float8 as error_rate, \
                    count(distinct (backend, tool)) as tools, \
                    count(distinct backend) as backends, \
                    percentile_cont(0.5) within group (order by duration_ms) as p50_ms, \
                    percentile_cont(0.95) within group (order by duration_ms) as p95_ms \
             from tool_calls where user_id = $1 and at >= $2",
        )
        .bind(user_id)
        .bind(since)
        .fetch_one(&self.pool)
        .await?;

        let per_day: Vec<(NaiveDate, i64, i64)> = sqlx::query_as(
            "select (at at time zone 'utc')::date as day, count(*) as calls, \
                    count(*) filter (where outcome <> 'ok') as errors \
             from tool_calls where user_id = $1 and at >= $2 \
             group by 1 order by 1",
        )
        .bind(user_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        let per_day: HashMap<NaiveDate, (i64, i64)> = per_day
            .into_iter()
            .map(|(day, calls, errors)| (day, (calls, errors)))
            .collect();
        let daily = first
            .iter_days()
            .take(usize::try_from(days).unwrap_or(0))
            .map(|day| {
                let (calls, errors) = per_day.get(&day).copied().unwrap_or((0, 0));
                DailyUsage { day, calls, errors }
            })
            .collect();

        let backends = sqlx::query_as(
            "select backend, count(*) as calls, \
                    count(*) filter (where outcome <> 'ok') as errors, \
                    coalesce((count(*) filter (where outcome <> 'ok'))::float8 \
                             / nullif(count(*), 0), 0)::float8 as error_rate, \
                    percentile_cont(0.95) within group (order by duration_ms) as p95_ms \
             from tool_calls where user_id = $1 and at >= $2 \
             group by backend order by calls desc, backend",
        )
        .bind(user_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        let tools = sqlx::query_as(
            "select backend, tool, count(*) as calls, \
                    count(*) filter (where outcome <> 'ok') as errors \
             from tool_calls where user_id = $1 and at >= $2 \
             group by backend, tool order by calls desc, backend, tool limit $3",
        )
        .bind(user_id)
        .bind(since)
        .bind(TOP_TOOLS)
        .fetch_all(&self.pool)
        .await?;

        Ok(UsageReport {
            days,
            since,
            totals,
            daily,
            backends,
            tools,
        })
    }

    /// The users with calls in the last `days` days (clamped to 1..=90), most
    /// calls first, at most `limit`.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn usage_by_user(
        &self,
        days: i32,
        limit: i64,
    ) -> Result<Vec<UserUsageRow>, StoreError> {
        let (_, _, since) = window(Utc::now().date_naive(), days);
        Ok(sqlx::query_as(
            "select u.id as user_id, u.display_name, u.email, u.subject, \
                    count(*) as calls, \
                    count(*) filter (where t.outcome <> 'ok') as errors, \
                    max(t.at) as last_call \
             from tool_calls t join users u on u.id = t.user_id \
             where t.at >= $1 \
             group by u.id order by calls desc, last_call desc limit $2",
        )
        .bind(since)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// How a user is named, or `None` for an unknown id.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn usage_user(&self, user_id: Uuid) -> Result<Option<UsageUser>, StoreError> {
        Ok(
            sqlx::query_as("select display_name, email, subject from users where id = $1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::LoginUser;
    use super::super::test_support::{database_url, isolated_url};
    use super::*;
    use crate::audit::{CallOutcome, NewToolCall};

    /// A connected store on its own schema, or `None` without a test database.
    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
    }

    async fn test_user(store: &Store, subject: &str, name: Option<&str>) -> Uuid {
        let login = LoginUser {
            issuer: "https://idp.example",
            subject,
            email: None,
            display_name: name,
            groups: &[],
            is_admin: false,
        };
        store.upsert_user_on_login(&login).await.unwrap().id
    }

    fn call(user: Uuid, backend: &str, tool: &str, outcome: CallOutcome, ms: i32) -> NewToolCall {
        NewToolCall {
            user_id: Some(user),
            principal_label: "alice".to_string(),
            token_id: None,
            auth_method: "pat".to_string(),
            backend: backend.to_string(),
            tool: tool.to_string(),
            outcome,
            error_code: None,
            error_message: None,
            duration_ms: ms,
            trace_id: None,
            client_ip: None,
            user_agent: None,
            arguments: None,
        }
    }

    fn close(value: Option<f64>, expected: f64) -> bool {
        value.is_some_and(|value| (value - expected).abs() < 1e-9)
    }

    #[test]
    fn the_window_is_whole_days_ending_today() {
        let today = NaiveDate::from_ymd_opt(2026, 3, 2).unwrap();
        let (days, first, since) = window(today, 3);
        assert_eq!(days, 3);
        assert_eq!(first, NaiveDate::from_ymd_opt(2026, 2, 28).unwrap());
        assert_eq!(since.to_rfc3339(), "2026-02-28T00:00:00+00:00");
        assert_eq!(window(today, 0).0, 1);
        assert_eq!(window(today, 1000).0, MAX_USAGE_DAYS);
    }

    #[test]
    fn a_user_is_named_by_display_name_then_email_then_subject() {
        let mut user = UsageUser {
            display_name: Some(" ".to_string()),
            email: Some("a@example.com".to_string()),
            subject: "sub".to_string(),
        };
        assert_eq!(user.label(), "a@example.com");
        user.display_name = Some("Alice".to_string());
        assert_eq!(user.label(), "Alice");
        user.display_name = None;
        user.email = None;
        assert_eq!(user.label(), "sub");
    }

    #[tokio::test]
    async fn a_report_aggregates_one_users_calls_in_the_window() {
        let Some(store) = test_store("axon_store_usage_report").await else {
            return;
        };
        let alice = test_user(&store, "alice", None).await;
        let bob = test_user(&store, "bob", None).await;
        store
            .insert_tool_calls(&[
                call(alice, "files", "read_file", CallOutcome::Ok, 10),
                call(alice, "files", "write_file", CallOutcome::Error, 30),
                call(alice, "pg", "query", CallOutcome::ToolError, 20),
                call(alice, "files", "old_tool", CallOutcome::Ok, 1),
                call(bob, "files", "read_file", CallOutcome::Ok, 5),
            ])
            .await
            .unwrap();
        sqlx::query(
            "update tool_calls set at = now() - interval '40 days' where tool = 'old_tool'",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        let report = store.user_usage(alice, 30).await.unwrap();
        assert_eq!(report.days, 30);
        assert_eq!(report.totals.calls, 3);
        assert_eq!(report.totals.errors, 2);
        assert!(close(Some(report.totals.error_rate), 2.0 / 3.0));
        assert_eq!(report.totals.tools, 3);
        assert_eq!(report.totals.backends, 2);
        assert!(close(report.totals.p50_ms, 20.0));
        assert!(close(report.totals.p95_ms, 29.0));

        assert_eq!(report.daily.len(), 30);
        let today = report.daily.last().unwrap();
        assert_eq!((today.calls, today.errors), (3, 2));
        assert_eq!(report.daily.iter().map(|day| day.calls).sum::<i64>(), 3);

        assert_eq!(report.backends.len(), 2);
        assert_eq!(report.backends[0].backend, "files");
        assert_eq!(report.backends[0].calls, 2);
        assert_eq!(report.backends[0].errors, 1);
        assert!(close(Some(report.backends[0].error_rate), 0.5));
        assert!(close(report.backends[0].p95_ms, 29.0));
        assert_eq!(report.backends[1].backend, "pg");

        assert_eq!(report.tools.len(), 3);
        assert!(report.tools.iter().all(|tool| tool.calls == 1));
        assert_eq!(report.tools[0].backend, "files");
        assert_eq!(report.tools[0].tool, "read_file");

        // A longer window sees the old call too.
        let longer = store.user_usage(alice, 90).await.unwrap();
        assert_eq!(longer.totals.calls, 4);
        assert_eq!(longer.daily.len(), 90);
    }

    #[tokio::test]
    async fn a_user_without_calls_has_an_empty_report() {
        let Some(store) = test_store("axon_store_usage_empty").await else {
            return;
        };
        let alice = test_user(&store, "alice", None).await;

        let report = store.user_usage(alice, 7).await.unwrap();
        assert_eq!(report.totals.calls, 0);
        assert_eq!(report.totals.errors, 0);
        assert!(close(Some(report.totals.error_rate), 0.0));
        assert_eq!(report.totals.p50_ms, None);
        assert_eq!(report.totals.p95_ms, None);
        assert_eq!(report.daily.len(), 7);
        assert!(report.daily.iter().all(|day| day.calls == 0));
        assert_eq!(report.backends.len(), 0);
        assert_eq!(report.tools.len(), 0);
    }

    #[tokio::test]
    async fn the_top_tools_stop_at_ten() {
        let Some(store) = test_store("axon_store_usage_top").await else {
            return;
        };
        let alice = test_user(&store, "alice", None).await;
        let calls: Vec<NewToolCall> = (0..12)
            .map(|n| call(alice, "files", &format!("tool_{n:02}"), CallOutcome::Ok, 1))
            .collect();
        store.insert_tool_calls(&calls).await.unwrap();

        let report = store.user_usage(alice, 1).await.unwrap();
        assert_eq!(report.totals.tools, 12);
        assert_eq!(report.tools.len(), 10);
    }

    #[tokio::test]
    async fn users_are_listed_by_calls() {
        let Some(store) = test_store("axon_store_usage_users").await else {
            return;
        };
        let alice = test_user(&store, "alice", Some("Alice")).await;
        let bob = test_user(&store, "bob", None).await;
        let carol = test_user(&store, "carol", None).await;
        store
            .insert_tool_calls(&[
                call(bob, "files", "a", CallOutcome::Ok, 1),
                call(bob, "files", "b", CallOutcome::Error, 1),
                call(bob, "files", "c", CallOutcome::Ok, 1),
                call(alice, "files", "a", CallOutcome::Ok, 1),
                call(alice, "files", "old", CallOutcome::Ok, 1),
                call(carol, "files", "old", CallOutcome::Ok, 1),
            ])
            .await
            .unwrap();
        sqlx::query("update tool_calls set at = now() - interval '40 days' where tool = 'old'")
            .execute(&store.pool)
            .await
            .unwrap();

        let rows = store.usage_by_user(30, 10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].user_id, bob);
        assert_eq!(rows[0].user.label(), "bob");
        assert_eq!((rows[0].calls, rows[0].errors), (3, 1));
        assert_eq!(rows[1].user_id, alice);
        assert_eq!(rows[1].user.label(), "Alice");
        assert_eq!((rows[1].calls, rows[1].errors), (1, 0));
        assert!(rows[0].last_call <= Utc::now());

        assert_eq!(store.usage_by_user(30, 1).await.unwrap().len(), 1);
        assert_eq!(store.usage_by_user(90, 10).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn an_unknown_user_has_no_name() {
        let Some(store) = test_store("axon_store_usage_user").await else {
            return;
        };
        let alice = test_user(&store, "alice", Some("Alice")).await;
        let user = store.usage_user(alice).await.unwrap().unwrap();
        assert_eq!(user.label(), "Alice");
        assert_eq!(store.usage_user(Uuid::new_v4()).await.unwrap(), None);
    }
}
