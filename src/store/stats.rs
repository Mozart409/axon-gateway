//! Counts the metrics sampler reads (sessions, tokens, pool)

use sqlx::Row;

use super::auth::SESSION_IDLE_TIMEOUT;
use super::{MCP_SESSION_IDLE, Store, StoreError};

/// What the sampler counts in the database
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreCounts {
    /// MCP sessions seen within [`MCP_SESSION_IDLE`]
    pub mcp_sessions: u64,
    /// Dashboard sessions neither expired nor idle for longer than the idle timeout
    pub ui_sessions: u64,
    /// Personal access tokens of users, neither revoked nor expired
    pub pat_tokens: u64,
    /// Tokens of service accounts, neither revoked nor expired
    pub service_tokens: u64,
}

/// The connections of the pool, as the pool counts them
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStats {
    pub idle: u32,
    pub used: u32,
    pub max: u32,
}

impl Store {
    /// The live sessions and usable tokens.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn sample_counts(&self) -> Result<StoreCounts, StoreError> {
        let mcp_sessions: i64 = sqlx::query_scalar(
            "select count(*) from mcp_sessions \
             where last_seen_at > now() - make_interval(secs => $1)",
        )
        .bind(MCP_SESSION_IDLE.as_secs_f64())
        .fetch_one(&self.pool)
        .await?;
        let ui_sessions: i64 = sqlx::query_scalar(
            "select count(*) from sessions \
             where expires_at > now() \
               and last_seen_at > now() - make_interval(secs => $1)",
        )
        .bind(SESSION_IDLE_TIMEOUT.as_secs_f64())
        .fetch_one(&self.pool)
        .await?;
        let tokens = sqlx::query(
            "select u.kind, count(*) as count \
             from api_tokens t join users u on u.id = t.owner_id \
             where t.revoked_at is null and t.expires_at > now() \
             group by u.kind",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut counts = StoreCounts {
            mcp_sessions: u64::try_from(mcp_sessions).unwrap_or(0),
            ui_sessions: u64::try_from(ui_sessions).unwrap_or(0),
            ..StoreCounts::default()
        };
        for row in tokens {
            let kind: String = row.try_get("kind")?;
            let count = u64::try_from(row.try_get::<i64, _>("count")?).unwrap_or(0);
            if kind == "service" {
                counts.service_tokens = count;
            } else {
                counts.pat_tokens = count;
            }
        }
        Ok(counts)
    }

    /// The pool's connections: idle, in use and the configured maximum.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        let size = self.pool.size();
        let idle = u32::try_from(self.pool.num_idle())
            .unwrap_or(u32::MAX)
            .min(size);
        PoolStats {
            idle,
            used: size - idle,
            max: self.pool.options().get_max_connections(),
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

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

    async fn user(store: &Store, subject: &str, kind: &str) -> Uuid {
        sqlx::query_scalar(
            "insert into users (issuer, subject, kind) values ($1, $2, $3) returning id",
        )
        .bind("https://idp.example")
        .bind(subject)
        .bind(kind)
        .fetch_one(&store.pool)
        .await
        .unwrap()
    }

    async fn token(store: &Store, owner: Uuid, public_id: &str, expires: &str, revoked: bool) {
        sqlx::query(
            "insert into api_tokens (public_id, secret_hash, owner_id, name, expires_at, revoked_at) \
             values ($1, '\\x00'::bytea, $2, 'laptop', now() + $3::text::interval, \
                     case when $4 then now() end)",
        )
        .bind(public_id)
        .bind(owner)
        .bind(expires)
        .bind(revoked)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    async fn session(store: &Store, owner: Uuid, hash: &str, expires: &str, seen: &str) {
        sqlx::query(
            "insert into sessions \
                 (token_hash, user_id, provider_id, csrf_token, expires_at, last_seen_at) \
             values ($1, $2, 'idp', 'csrf', now() + $3::text::interval, now() + $4::text::interval)",
        )
        .bind(hash)
        .bind(owner)
        .bind(expires)
        .bind(seen)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn counts_only_live_sessions_and_usable_tokens() {
        let Some(store) = test_store("stats_counts").await else {
            return;
        };
        assert_eq!(store.sample_counts().await.unwrap(), StoreCounts::default());

        let alice = user(&store, "alice", "user").await;
        let bot = user(&store, "bot", "service").await;

        store.bind_mcp_session("fresh", "alice").await.unwrap();
        store.bind_mcp_session("idle", "carol").await.unwrap();
        sqlx::query(
            "update mcp_sessions set last_seen_at = now() - interval '2 days' \
             where owner = 'carol'",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        session(&store, alice, "live", "1 day", "0 seconds").await;
        session(&store, alice, "expired", "-1 minute", "0 seconds").await;
        session(&store, alice, "idle", "1 day", "-2 days").await;

        token(&store, alice, "live", "1 day", false).await;
        token(&store, alice, "expired", "-1 day", false).await;
        token(&store, alice, "revoked", "1 day", true).await;
        token(&store, bot, "svc", "1 day", false).await;
        token(&store, bot, "svc-revoked", "1 day", true).await;

        assert_eq!(
            store.sample_counts().await.unwrap(),
            StoreCounts {
                mcp_sessions: 1,
                ui_sessions: 1,
                pat_tokens: 1,
                service_tokens: 1,
            }
        );
    }

    #[tokio::test]
    async fn the_pool_reports_its_connections() {
        let Some(store) = test_store("stats_pool").await else {
            return;
        };
        store.ping().await.unwrap();
        let pool = store.pool_stats();
        assert!(pool.max >= 1);
        assert!(pool.idle + pool.used <= pool.max);
    }
}
