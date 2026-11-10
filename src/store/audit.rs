//! Tool-call audit storage: calls, their arguments, capture rules, retention
//!
//! Admin writes (rules, settings) and reads of stored arguments run in one
//! transaction together with their `audit_log` row, like the RBAC changes. The
//! writer's batch insert does not audit: the calls are the audit.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::FromRow;

use super::rbac::{Actor, audit};
use super::{Store, StoreError};
use crate::audit::{
    AuditSettings, CaptureMode, CaptureRule, NewCaptureRule, NewToolCall, PurgeCounts,
    StoredArguments, ToolCallFilter, ToolCallRecord,
};

#[derive(FromRow)]
struct RuleRow {
    id: i64,
    backend: String,
    tool_pattern: String,
    mode: String,
    drop_keys: Vec<String>,
}

impl From<RuleRow> for CaptureRule {
    fn from(row: RuleRow) -> Self {
        Self {
            id: row.id,
            backend: row.backend,
            tool_pattern: row.tool_pattern,
            // The column is checked in the database; the fallback is the
            // safer of the capturing modes.
            mode: CaptureMode::parse(&row.mode).unwrap_or(CaptureMode::Redacted),
            drop_keys: row.drop_keys,
        }
    }
}

fn rule_json(rule: &CaptureRule) -> serde_json::Value {
    json!({
        "backend": rule.backend,
        "tool_pattern": rule.tool_pattern,
        "mode": rule.mode.as_str(),
        "drop_keys": rule.drop_keys,
    })
}

impl Store {
    /// Writes a batch of calls, and the arguments of those that have any, in
    /// one transaction.
    ///
    /// # Errors
    /// Fails when the transaction fails; nothing of the batch is stored then.
    pub async fn insert_tool_calls(&self, calls: &[NewToolCall]) -> Result<(), StoreError> {
        if calls.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for call in calls {
            let (id, at): (i64, DateTime<Utc>) = sqlx::query_as(
                "insert into tool_calls \
                 (user_id, principal_label, token_id, auth_method, backend, tool, outcome, \
                  error_code, error_message, duration_ms, trace_id, client_ip, user_agent) \
                 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                 returning id, at",
            )
            .bind(call.user_id)
            .bind(&call.principal_label)
            .bind(call.token_id)
            .bind(&call.auth_method)
            .bind(&call.backend)
            .bind(&call.tool)
            .bind(call.outcome.as_str())
            .bind(call.error_code)
            .bind(call.error_message.as_deref())
            .bind(call.duration_ms)
            .bind(call.trace_id.as_deref())
            .bind(call.client_ip.as_deref())
            .bind(call.user_agent.as_deref())
            .fetch_one(&mut *tx)
            .await?;
            if let Some((mode, arguments)) = &call.arguments {
                sqlx::query(
                    "insert into audit_arguments (call_id, at, capture, arguments) \
                     values ($1, $2, $3, $4)",
                )
                .bind(id)
                .bind(at)
                .bind(mode.as_str())
                .bind(arguments)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Up to `limit` calls matching `filter`, newest first (by id), older than
    /// `before_id` when given.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_tool_calls(
        &self,
        filter: &ToolCallFilter,
        before_id: Option<i64>,
        limit: i64,
    ) -> Result<Vec<ToolCallRecord>, StoreError> {
        Ok(sqlx::query_as(
            "select t.id, t.at, t.user_id, t.principal_label, t.token_id, t.auth_method, \
                    t.backend, t.tool, t.outcome, t.error_code, t.error_message, t.duration_ms, \
                    t.trace_id, t.client_ip, t.user_agent, a.capture as arguments_capture \
             from tool_calls t left join audit_arguments a on a.call_id = t.id \
             where ($1::uuid is null or t.user_id = $1) \
               and ($2::text is null or t.backend = $2) \
               and ($3::text is null or t.tool = $3) \
               and ($4::text is null or t.outcome = $4) \
               and ($5::bigint is null or t.id < $5) \
             order by t.id desc limit $6",
        )
        .bind(filter.user_id)
        .bind(filter.backend.as_deref())
        .bind(filter.tool.as_deref())
        .bind(filter.outcome.as_deref())
        .bind(before_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// One call, without its arguments. `None` when there is none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn tool_call(&self, id: i64) -> Result<Option<ToolCallRecord>, StoreError> {
        Ok(sqlx::query_as(
            "select t.id, t.at, t.user_id, t.principal_label, t.token_id, t.auth_method, \
                    t.backend, t.tool, t.outcome, t.error_code, t.error_message, t.duration_ms, \
                    t.trace_id, t.client_ip, t.user_agent, a.capture as arguments_capture \
             from tool_calls t left join audit_arguments a on a.call_id = t.id \
             where t.id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// The stored arguments of a call, and the `audit.arguments_read` row that
    /// records the read, in one transaction. `None` (and no audit row) when the
    /// call has no stored arguments, because they were never captured or are
    /// past their retention.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn tool_call_arguments(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<Option<StoredArguments>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let stored: Option<StoredArguments> = sqlx::query_as(
            "select call_id, at, capture, arguments from audit_arguments where call_id = $1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        audit(
            &mut tx,
            actor,
            "audit.arguments_read",
            &format!("tool_call:{id}"),
            json!({ "capture": stored.capture }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(stored))
    }

    /// All capture rules, oldest first.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn capture_rules(&self) -> Result<Vec<CaptureRule>, StoreError> {
        let rows: Vec<RuleRow> = sqlx::query_as(
            "select id, backend, tool_pattern, mode, drop_keys from audit_capture_rules \
             order by id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(CaptureRule::from).collect())
    }

    /// Stores a capture rule and returns its id.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn create_capture_rule(
        &self,
        actor: &Actor,
        rule: &NewCaptureRule,
    ) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let id: i64 = sqlx::query_scalar(
            "insert into audit_capture_rules (backend, tool_pattern, mode, drop_keys, created_by) \
             values ($1, $2, $3, $4, $5) returning id",
        )
        .bind(&rule.backend)
        .bind(&rule.tool_pattern)
        .bind(rule.mode.as_str())
        .bind(rule.drop_keys.as_slice())
        .bind(&actor.label)
        .fetch_one(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "audit.rule_create",
            &format!("audit_rule:{id}"),
            json!({
                "backend": rule.backend,
                "tool_pattern": rule.tool_pattern,
                "mode": rule.mode.as_str(),
                "drop_keys": rule.drop_keys,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Deletes a capture rule and returns it. `None` when there was none.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_capture_rule(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<Option<CaptureRule>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<RuleRow> = sqlx::query_as(
            "delete from audit_capture_rules where id = $1 \
             returning id, backend, tool_pattern, mode, drop_keys",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let rule = CaptureRule::from(row);
        audit(
            &mut tx,
            actor,
            "audit.rule_delete",
            &format!("audit_rule:{id}"),
            rule_json(&rule),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(rule))
    }

    /// The retention settings.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn audit_settings(&self) -> Result<AuditSettings, StoreError> {
        Ok(sqlx::query_as(
            "select arguments_retention_days, metadata_retention_days from audit_settings",
        )
        .fetch_one(&self.pool)
        .await?)
    }

    /// Replaces the retention settings. Returns whether anything changed; a
    /// write that changes nothing records nothing.
    ///
    /// # Errors
    /// Fails when the transaction fails, e.g. for a retention under one day.
    pub async fn update_audit_settings(
        &self,
        actor: &Actor,
        settings: &AuditSettings,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let old: AuditSettings = sqlx::query_as(
            "select arguments_retention_days, metadata_retention_days from audit_settings \
             for update",
        )
        .fetch_one(&mut *tx)
        .await?;
        if old == *settings {
            return Ok(false);
        }
        sqlx::query(
            "update audit_settings set arguments_retention_days = $1, \
             metadata_retention_days = $2",
        )
        .bind(settings.arguments_retention_days)
        .bind(settings.metadata_retention_days)
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "audit.settings_update",
            "audit_settings",
            json!({
                "arguments_retention_days": [old.arguments_retention_days, settings.arguments_retention_days],
                "metadata_retention_days": [old.metadata_retention_days, settings.metadata_retention_days],
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes arguments and calls older than their retention, as the settings
    /// stand now. Deleting a call deletes its arguments too.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn purge_audit(&self) -> Result<PurgeCounts, StoreError> {
        let mut tx = self.pool.begin().await?;
        let settings: AuditSettings = sqlx::query_as(
            "select arguments_retention_days, metadata_retention_days from audit_settings",
        )
        .fetch_one(&mut *tx)
        .await?;
        let arguments =
            sqlx::query("delete from audit_arguments where at < now() - make_interval(days => $1)")
                .bind(settings.arguments_retention_days)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        let calls =
            sqlx::query("delete from tool_calls where at < now() - make_interval(days => $1)")
                .bind(settings.metadata_retention_days)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        tx.commit().await?;
        Ok(PurgeCounts { arguments, calls })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use uuid::Uuid;

    use super::super::LoginUser;
    use super::super::test_support::{database_url, isolated_url};
    use super::*;
    use crate::audit::CallOutcome;

    /// A connected store on its own schema, or `None` without a test database.
    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
    }

    async fn test_user(store: &Store, subject: &str) -> Uuid {
        let login = LoginUser {
            issuer: "https://idp.example",
            subject,
            email: None,
            display_name: None,
            groups: &[],
            is_admin: false,
        };
        store.upsert_user_on_login(&login).await.unwrap().id
    }

    fn cli() -> Actor {
        Actor {
            user_id: None,
            label: "cli".to_string(),
        }
    }

    fn call(backend: &str, tool: &str) -> NewToolCall {
        NewToolCall {
            user_id: None,
            principal_label: "alice".to_string(),
            token_id: None,
            auth_method: "pat".to_string(),
            backend: backend.to_string(),
            tool: tool.to_string(),
            outcome: CallOutcome::Ok,
            error_code: None,
            error_message: None,
            duration_ms: 5,
            trace_id: None,
            client_ip: None,
            user_agent: None,
            arguments: None,
        }
    }

    fn with_args(mut call: NewToolCall, mode: CaptureMode, arguments: Value) -> NewToolCall {
        call.arguments = Some((mode, arguments));
        call
    }

    fn new_rule(backend: &str, pattern: &str, mode: CaptureMode) -> NewCaptureRule {
        NewCaptureRule {
            backend: backend.to_string(),
            tool_pattern: pattern.to_string(),
            mode,
            drop_keys: vec!["content".to_string()],
        }
    }

    async fn audited(store: &Store) -> Vec<(String, String)> {
        sqlx::query_as("select action, target from audit_log order by id")
            .fetch_all(&store.pool)
            .await
            .unwrap()
    }

    async fn count(store: &Store, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("select count(*) from {table}")))
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    fn entry(action: &str, target: &str) -> (String, String) {
        (action.to_string(), target.to_string())
    }

    #[tokio::test]
    async fn a_batch_stores_calls_and_their_arguments() {
        let Some(store) = test_store("axon_store_audit_insert").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        let mut first = with_args(
            call("files", "write_file"),
            CaptureMode::Redacted,
            json!({"path": "/x", "token": "[redacted]"}),
        );
        first.user_id = Some(user);
        first.error_message = Some("boom".to_string());
        first.error_code = Some(-32603);
        first.outcome = CallOutcome::Error;
        first.trace_id = Some("trace".to_string());
        first.client_ip = Some("10.0.0.1".to_string());
        first.user_agent = Some("agent/1".to_string());
        let second = call("files", "read_file");

        store.insert_tool_calls(&[first, second]).await.unwrap();
        store.insert_tool_calls(&[]).await.unwrap();

        let calls = store
            .list_tool_calls(&ToolCallFilter::default(), None, 10)
            .await
            .unwrap();
        assert_eq!(calls.len(), 2);
        // Newest first.
        assert_eq!(calls[0].tool, "read_file");
        assert_eq!(calls[0].arguments_capture, None);
        assert_eq!(calls[1].tool, "write_file");
        assert_eq!(calls[1].user_id, Some(user));
        assert_eq!(calls[1].outcome, "error");
        assert_eq!(calls[1].error_code, Some(-32603));
        assert_eq!(calls[1].error_message.as_deref(), Some("boom"));
        assert_eq!(calls[1].duration_ms, 5);
        assert_eq!(calls[1].trace_id.as_deref(), Some("trace"));
        assert_eq!(calls[1].client_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(calls[1].user_agent.as_deref(), Some("agent/1"));
        assert_eq!(calls[1].arguments_capture.as_deref(), Some("redacted"));
        assert_eq!(count(&store, "audit_arguments").await, 1);

        let one = store.tool_call(calls[1].id).await.unwrap().unwrap();
        assert_eq!(one, calls[1]);
        assert_eq!(store.tool_call(999_999).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_failing_batch_stores_nothing() {
        let Some(store) = test_store("axon_store_audit_atomic").await else {
            return;
        };
        let good = call("files", "read_file");
        // Postgres rejects a null byte in text, which breaks the second row.
        let bad = call("files", "bad\0tool");
        assert!(store.insert_tool_calls(&[good, bad]).await.is_err());
        assert_eq!(count(&store, "tool_calls").await, 0);
    }

    #[tokio::test]
    async fn listing_filters_and_pages_by_id() {
        let Some(store) = test_store("axon_store_audit_list").await else {
            return;
        };
        let alice = test_user(&store, "alice").await;
        let bob = test_user(&store, "bob").await;
        let mut calls = Vec::new();
        for index in 0..6 {
            let mut item = call(
                if index % 2 == 0 { "files" } else { "git" },
                if index < 3 { "read" } else { "write" },
            );
            item.user_id = Some(if index < 4 { alice } else { bob });
            if index == 5 {
                item.outcome = CallOutcome::ToolError;
            }
            calls.push(item);
        }
        store.insert_tool_calls(&calls).await.unwrap();

        let all = ToolCallFilter::default();
        let page = store.list_tool_calls(&all, None, 4).await.unwrap();
        assert_eq!(page.len(), 4);
        let ids: Vec<i64> = page.iter().map(|call| call.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(ids, sorted);
        let older = store
            .list_tool_calls(&all, page.last().map(|call| call.id), 4)
            .await
            .unwrap();
        assert_eq!(older.len(), 2);
        assert!(older[0].id < ids[3]);

        let by_user = ToolCallFilter {
            user_id: Some(bob),
            ..ToolCallFilter::default()
        };
        assert_eq!(
            store
                .list_tool_calls(&by_user, None, 10)
                .await
                .unwrap()
                .len(),
            2
        );
        let by_backend = ToolCallFilter {
            backend: Some("git".to_string()),
            ..ToolCallFilter::default()
        };
        assert_eq!(
            store
                .list_tool_calls(&by_backend, None, 10)
                .await
                .unwrap()
                .len(),
            3
        );
        let by_tool = ToolCallFilter {
            tool: Some("read".to_string()),
            ..ToolCallFilter::default()
        };
        assert_eq!(
            store
                .list_tool_calls(&by_tool, None, 10)
                .await
                .unwrap()
                .len(),
            3
        );
        let by_outcome = ToolCallFilter {
            outcome: Some("tool_error".to_string()),
            ..ToolCallFilter::default()
        };
        let errors = store.list_tool_calls(&by_outcome, None, 10).await.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].user_id, Some(bob));
        let combined = ToolCallFilter {
            user_id: Some(alice),
            backend: Some("git".to_string()),
            tool: Some("write".to_string()),
            outcome: None,
        };
        assert_eq!(
            store
                .list_tool_calls(&combined, None, 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn deleting_a_user_keeps_their_calls() {
        let Some(store) = test_store("axon_store_audit_user_delete").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        let mut item = call("files", "read_file");
        item.user_id = Some(user);
        store.insert_tool_calls(&[item]).await.unwrap();

        sqlx::query("delete from users where id = $1")
            .bind(user)
            .execute(&store.pool)
            .await
            .unwrap();
        let calls = store
            .list_tool_calls(&ToolCallFilter::default(), None, 10)
            .await
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].user_id, None);
        assert_eq!(calls[0].principal_label, "alice");
    }

    #[tokio::test]
    async fn reading_arguments_is_audited_in_the_same_transaction() {
        let Some(store) = test_store("axon_store_audit_read").await else {
            return;
        };
        let arguments = json!({"query": "select 1"});
        store
            .insert_tool_calls(&[
                with_args(
                    call("pg", "run_query"),
                    CaptureMode::Full,
                    arguments.clone(),
                ),
                call("pg", "list_tables"),
            ])
            .await
            .unwrap();
        let calls = store
            .list_tool_calls(&ToolCallFilter::default(), None, 10)
            .await
            .unwrap();
        let with = calls[1].id;
        let without = calls[0].id;

        let stored = store
            .tool_call_arguments(&cli(), with)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.call_id, with);
        assert_eq!(stored.capture, "full");
        assert_eq!(stored.arguments, arguments);
        assert_eq!(
            audited(&store).await,
            vec![entry("audit.arguments_read", &format!("tool_call:{with}"))]
        );

        // Nothing stored, nothing read, nothing audited.
        assert!(
            store
                .tool_call_arguments(&cli(), without)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .tool_call_arguments(&cli(), 999_999)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(count(&store, "audit_log").await, 1);
    }

    #[tokio::test]
    async fn capture_rules_create_list_and_delete_with_audit() {
        let Some(store) = test_store("axon_store_audit_rules").await else {
            return;
        };
        assert_eq!(
            store.capture_rules().await.unwrap(),
            Vec::<CaptureRule>::new()
        );

        let first = store
            .create_capture_rule(&cli(), &new_rule("pg", "run_*", CaptureMode::Full))
            .await
            .unwrap();
        let second = store
            .create_capture_rule(&cli(), &new_rule("*", "*", CaptureMode::None))
            .await
            .unwrap();
        assert!(second > first);

        let rules = store.capture_rules().await.unwrap();
        assert_eq!(
            rules,
            vec![
                CaptureRule {
                    id: first,
                    backend: "pg".to_string(),
                    tool_pattern: "run_*".to_string(),
                    mode: CaptureMode::Full,
                    drop_keys: vec!["content".to_string()],
                },
                CaptureRule {
                    id: second,
                    backend: "*".to_string(),
                    tool_pattern: "*".to_string(),
                    mode: CaptureMode::None,
                    drop_keys: vec!["content".to_string()],
                },
            ]
        );
        let created_by: String =
            sqlx::query_scalar("select created_by from audit_capture_rules where id = $1")
                .bind(first)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(created_by, "cli");

        let deleted = store
            .delete_capture_rule(&cli(), first)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deleted.id, first);
        assert_eq!(deleted.tool_pattern, "run_*");
        assert_eq!(
            store.delete_capture_rule(&cli(), first).await.unwrap(),
            None
        );
        assert_eq!(store.capture_rules().await.unwrap().len(), 1);

        assert_eq!(
            audited(&store).await,
            vec![
                entry("audit.rule_create", &format!("audit_rule:{first}")),
                entry("audit.rule_create", &format!("audit_rule:{second}")),
                entry("audit.rule_delete", &format!("audit_rule:{first}")),
            ]
        );
    }

    #[tokio::test]
    async fn the_database_rejects_a_bad_rule_mode() {
        let Some(store) = test_store("axon_store_audit_rule_check").await else {
            return;
        };
        let result = sqlx::query(
            "insert into audit_capture_rules (backend, tool_pattern, mode) values ('*', '*', 'all')",
        )
        .execute(&store.pool)
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn settings_default_update_and_validate() {
        let Some(store) = test_store("axon_store_audit_settings").await else {
            return;
        };
        let defaults = store.audit_settings().await.unwrap();
        assert_eq!(
            defaults,
            AuditSettings {
                arguments_retention_days: 30,
                metadata_retention_days: 365,
            }
        );

        let changed = AuditSettings {
            arguments_retention_days: 7,
            metadata_retention_days: 90,
        };
        assert!(store.update_audit_settings(&cli(), &changed).await.unwrap());
        assert_eq!(store.audit_settings().await.unwrap(), changed);
        // The same values again change nothing and record nothing.
        assert!(!store.update_audit_settings(&cli(), &changed).await.unwrap());
        assert_eq!(
            audited(&store).await,
            vec![entry("audit.settings_update", "audit_settings")]
        );

        let invalid = AuditSettings {
            arguments_retention_days: 0,
            metadata_retention_days: 90,
        };
        assert!(store.update_audit_settings(&cli(), &invalid).await.is_err());
        assert_eq!(store.audit_settings().await.unwrap(), changed);
        assert_eq!(count(&store, "audit_settings").await, 1);
        // The table holds a single row.
        let second = sqlx::query("insert into audit_settings (id) values (false)")
            .execute(&store.pool)
            .await;
        assert!(second.is_err());
    }

    /// Moves a call (and its arguments) into the past.
    async fn age(store: &Store, id: i64, days: i32) {
        for table in ["tool_calls", "audit_arguments"] {
            let column = if table == "tool_calls" {
                "id"
            } else {
                "call_id"
            };
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "update {table} set at = now() - make_interval(days => $1) where {column} = $2"
            )))
            .bind(days)
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn purge_applies_both_retentions() {
        let Some(store) = test_store("axon_store_audit_purge").await else {
            return;
        };
        for tool in ["fresh", "args_old", "all_old"] {
            store
                .insert_tool_calls(&[with_args(
                    call("files", tool),
                    CaptureMode::Redacted,
                    json!({"a": 1}),
                )])
                .await
                .unwrap();
        }
        let ids: Vec<(String, i64)> = sqlx::query_as("select tool, id from tool_calls order by id")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        let id_of = |tool: &str| ids.iter().find(|(name, _)| name == tool).unwrap().1;
        // Defaults: 30 days for arguments, 365 for metadata.
        age(&store, id_of("args_old"), 40).await;
        age(&store, id_of("all_old"), 400).await;

        let purged = store.purge_audit().await.unwrap();
        assert_eq!(
            purged,
            PurgeCounts {
                arguments: 2,
                calls: 1
            }
        );
        let left = store
            .list_tool_calls(&ToolCallFilter::default(), None, 10)
            .await
            .unwrap();
        let tools: Vec<(&str, Option<&str>)> = left
            .iter()
            .map(|call| (call.tool.as_str(), call.arguments_capture.as_deref()))
            .collect();
        assert_eq!(tools, vec![("args_old", None), ("fresh", Some("redacted"))]);
        // A second run finds nothing.
        assert_eq!(store.purge_audit().await.unwrap(), PurgeCounts::default());
    }

    #[tokio::test]
    async fn purge_reads_the_settings_each_time() {
        let Some(store) = test_store("axon_store_audit_purge_settings").await else {
            return;
        };
        store
            .insert_tool_calls(&[
                with_args(call("files", "a"), CaptureMode::Full, json!({})),
                call("files", "b"),
            ])
            .await
            .unwrap();
        let id: i64 = sqlx::query_scalar("select id from tool_calls where tool = 'a'")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        age(&store, id, 10).await;
        assert_eq!(store.purge_audit().await.unwrap(), PurgeCounts::default());

        let shorter = AuditSettings {
            arguments_retention_days: 5,
            metadata_retention_days: 8,
        };
        store.update_audit_settings(&cli(), &shorter).await.unwrap();
        // Metadata older than 8 days goes with its arguments (cascade).
        let purged = store.purge_audit().await.unwrap();
        assert_eq!(purged.calls, 1);
        assert_eq!(count(&store, "tool_calls").await, 1);
        assert_eq!(count(&store, "audit_arguments").await, 0);
    }
}
