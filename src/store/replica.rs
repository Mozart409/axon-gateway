//! State shared between gateway replicas on one database
//!
//! A rate-limit counter, a job lease, MCP sessions and the change
//! notification channel the triggers of migration 0009 publish to.

use std::time::Duration;

use sqlx::postgres::PgListener;

use super::tokens::hash_secret;
use super::{Store, StoreError};

/// Channel the change triggers notify; the payload is JSON naming the schema
pub const CHANGES_CHANNEL: &str = "axon_changes";

/// How long an MCP session may go unused before it is purged
pub const MCP_SESSION_IDLE: Duration = Duration::from_hours(24);

impl Store {
    /// Counts one request against `key` in the current minute. `true` when it
    /// is within `limit` and so allowed.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn hit_rate_limit(&self, key: &str, limit: u32) -> Result<bool, StoreError> {
        let count: i32 = sqlx::query_scalar(
            "insert into rate_limit_windows (key, window_start, count) \
             values ($1, date_trunc('minute', now()), 1) \
             on conflict (key, window_start) \
             do update set count = rate_limit_windows.count + 1 \
             returning count",
        )
        .bind(key)
        .fetch_one(&self.pool)
        .await?;
        Ok(i64::from(count) <= i64::from(limit))
    }

    /// Deletes rate-limit windows that can no longer matter.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn purge_rate_limits(&self) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "delete from rate_limit_windows where window_start < now() - interval '2 minutes'",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Takes the lease on `job` when it last ran at least `min_gap` ago.
    /// `true` when this caller should run it.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn claim_job(&self, job: &str, min_gap: Duration) -> Result<bool, StoreError> {
        let claimed: Option<String> = sqlx::query_scalar(
            "insert into job_runs (job, last_run_at) values ($1, now()) \
             on conflict (job) do update set last_run_at = now() \
             where job_runs.last_run_at <= now() - make_interval(secs => $2) \
             returning job",
        )
        .bind(job)
        .bind(min_gap.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?;
        Ok(claimed.is_some())
    }

    /// Saves the state of an MCP session, keeping its owner.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn store_mcp_session(
        &self,
        id: &str,
        state: &serde_json::Value,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into mcp_sessions (id_hash, state) values ($1, $2) \
             on conflict (id_hash) do update \
             set state = excluded.state, last_seen_at = now()",
        )
        .bind(hash_secret(id))
        .bind(state)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The saved state of an MCP session, if it has one.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn load_mcp_session(
        &self,
        id: &str,
    ) -> Result<Option<serde_json::Value>, StoreError> {
        let state: Option<Option<serde_json::Value>> = sqlx::query_scalar(
            "update mcp_sessions set last_seen_at = now() \
             where id_hash = $1 returning state",
        )
        .bind(hash_secret(id))
        .fetch_optional(&self.pool)
        .await?;
        Ok(state.flatten())
    }

    /// Forgets an MCP session.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn delete_mcp_session(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("delete from mcp_sessions where id_hash = $1")
            .bind(hash_secret(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Records who owns an MCP session, keeping its state.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn bind_mcp_session(&self, id: &str, owner: &str) -> Result<(), StoreError> {
        sqlx::query(
            "insert into mcp_sessions (id_hash, owner) values ($1, $2) \
             on conflict (id_hash) do update \
             set owner = excluded.owner, last_seen_at = now()",
        )
        .bind(hash_secret(id))
        .bind(owner)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The owner of an MCP session. Refreshes `last_seen_at` when it is more
    /// than a minute old, so a busy session does not write on every request.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn mcp_session_owner(&self, id: &str) -> Result<Option<String>, StoreError> {
        let owner: Option<Option<String>> = sqlx::query_scalar(
            "with touched as ( \
                 update mcp_sessions set last_seen_at = now() \
                 where id_hash = $1 and last_seen_at < now() - interval '1 minute' \
             ) \
             select owner from mcp_sessions where id_hash = $1",
        )
        .bind(hash_secret(id))
        .fetch_optional(&self.pool)
        .await?;
        Ok(owner.flatten())
    }

    /// Deletes MCP sessions unused for longer than [`MCP_SESSION_IDLE`].
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn purge_mcp_sessions(&self) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "delete from mcp_sessions where last_seen_at < now() - make_interval(secs => $1)",
        )
        .bind(MCP_SESSION_IDLE.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// A listener subscribed to [`CHANGES_CHANNEL`], on its own connection.
    ///
    /// # Errors
    /// Fails when it cannot connect or subscribe.
    pub async fn listen_changes(&self) -> Result<PgListener, StoreError> {
        let mut listener = PgListener::connect_with(&self.pool).await?;
        listener.listen(CHANGES_CHANNEL).await?;
        Ok(listener)
    }

    /// The schema this store's connections resolve names in. Change
    /// notifications carry it, so a replica can ignore other schemas'.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn current_schema(&self) -> Result<String, StoreError> {
        Ok(sqlx::query_scalar("select current_schema()")
            .fetch_one(&self.pool)
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::auth::LoginUser;
    use super::super::test_support::{database_url, isolated_url};
    use super::*;

    /// A connected store on its own schema, or `None` without a test database.
    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
    }

    /// The next notification on `listener`, parsed, within a few seconds.
    async fn next_change(listener: &mut PgListener) -> serde_json::Value {
        let notification = tokio::time::timeout(Duration::from_secs(5), listener.try_recv())
            .await
            .expect("no notification within 5s")
            .unwrap()
            .expect("listener lost its connection");
        serde_json::from_str(notification.payload()).unwrap()
    }

    #[tokio::test]
    async fn rate_limit_allows_up_to_the_limit() {
        let Some(store) = test_store("replica_rate").await else {
            return;
        };
        assert!(store.hit_rate_limit("a", 2).await.unwrap());
        assert!(store.hit_rate_limit("a", 2).await.unwrap());
        assert!(!store.hit_rate_limit("a", 2).await.unwrap());
        assert!(!store.hit_rate_limit("a", 2).await.unwrap());
        assert!(store.hit_rate_limit("b", 2).await.unwrap());
        // fresh windows are kept
        assert_eq!(store.purge_rate_limits().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn rate_limit_purge_drops_old_windows() {
        let Some(store) = test_store("replica_rate_purge").await else {
            return;
        };
        sqlx::query(
            "insert into rate_limit_windows (key, window_start, count) \
             values ('old', now() - interval '10 minutes', 1)",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.purge_rate_limits().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn job_is_claimed_once_per_gap() {
        let Some(store) = test_store("replica_job").await else {
            return;
        };
        let gap = Duration::from_secs(3600);
        assert!(store.claim_job("sweep", gap).await.unwrap());
        assert!(!store.claim_job("sweep", gap).await.unwrap());
        assert!(store.claim_job("other", gap).await.unwrap());
        assert!(store.claim_job("sweep", Duration::ZERO).await.unwrap());
    }

    #[tokio::test]
    async fn mcp_session_round_trip() {
        let Some(store) = test_store("replica_session").await else {
            return;
        };
        assert_eq!(store.load_mcp_session("s1").await.unwrap(), None);
        assert_eq!(store.mcp_session_owner("s1").await.unwrap(), None);

        // an owner alone leaves the state empty
        store.bind_mcp_session("s1", "alice").await.unwrap();
        assert_eq!(store.load_mcp_session("s1").await.unwrap(), None);
        assert_eq!(
            store.mcp_session_owner("s1").await.unwrap().as_deref(),
            Some("alice")
        );

        // storing state keeps the owner
        let state = json!({"initialized": true});
        store.store_mcp_session("s1", &state).await.unwrap();
        assert_eq!(store.load_mcp_session("s1").await.unwrap(), Some(state));
        assert_eq!(
            store.mcp_session_owner("s1").await.unwrap().as_deref(),
            Some("alice")
        );

        // rebinding keeps the state
        store.bind_mcp_session("s1", "bob").await.unwrap();
        assert!(store.load_mcp_session("s1").await.unwrap().is_some());
        assert_eq!(
            store.mcp_session_owner("s1").await.unwrap().as_deref(),
            Some("bob")
        );

        // a fresh row survives the purge, a deleted one is gone
        assert_eq!(store.purge_mcp_sessions().await.unwrap(), 0);
        assert!(store.load_mcp_session("s1").await.unwrap().is_some());
        store.delete_mcp_session("s1").await.unwrap();
        assert_eq!(store.load_mcp_session("s1").await.unwrap(), None);
        assert_eq!(store.mcp_session_owner("s1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn mcp_session_purge_drops_idle_rows() {
        let Some(store) = test_store("replica_session_purge").await else {
            return;
        };
        store.bind_mcp_session("idle", "alice").await.unwrap();
        store.bind_mcp_session("fresh", "bob").await.unwrap();
        sqlx::query(
            "update mcp_sessions set last_seen_at = now() - interval '2 days' \
             where owner = 'alice'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.purge_mcp_sessions().await.unwrap(), 1);
        assert_eq!(store.mcp_session_owner("idle").await.unwrap(), None);
        assert_eq!(
            store.mcp_session_owner("fresh").await.unwrap().as_deref(),
            Some("bob")
        );
    }

    #[tokio::test]
    async fn grant_insert_notifies_policy_change() {
        let Some(store) = test_store("replica_notify_policy").await else {
            return;
        };
        let mut listener = store.listen_changes().await.unwrap();
        sqlx::query(
            "insert into rbac_grants (group_name, backend, include) \
             values ('ops', 'prom', '{*}')",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let change = next_change(&mut listener).await;
        assert_eq!(
            change,
            json!({"schema": "replica_notify_policy", "kind": "policy"})
        );
        assert_eq!(
            store.current_schema().await.unwrap(),
            "replica_notify_policy"
        );
    }

    #[tokio::test]
    async fn opt_out_insert_and_delete_notify_the_user() {
        let Some(store) = test_store("replica_notify_user").await else {
            return;
        };
        let login = LoginUser {
            issuer: "https://idp.example",
            subject: "alice",
            email: None,
            display_name: None,
            groups: &[],
            is_admin: false,
        };
        let user_id = store.upsert_user_on_login(&login).await.unwrap().id;
        let mut listener = store.listen_changes().await.unwrap();

        sqlx::query("insert into tool_opt_outs (user_id, backend) values ($1, 'prom')")
            .bind(user_id)
            .execute(&store.pool)
            .await
            .unwrap();
        let expected = json!({
            "schema": "replica_notify_user",
            "kind": "user",
            "user": user_id.to_string(),
        });
        assert_eq!(next_change(&mut listener).await, expected);

        // a delete has no NEW row but still names the user
        sqlx::query("delete from tool_opt_outs where user_id = $1")
            .bind(user_id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(next_change(&mut listener).await, expected);
    }
}
