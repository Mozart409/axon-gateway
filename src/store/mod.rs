//! Optional Postgres store for users and, later, per-user state
//!
//! Connects from a URL held in an environment variable (never in the config
//! file) and applies the embedded migrations on startup.

use std::time::Duration;

use serde::Deserialize;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use thiserror::Error;

mod audit;
mod auth;
mod break_glass;
mod rbac;
mod replica;
mod tokens;
mod toolsets;
mod views;

pub use auth::{LoginUser, OidcFlow, SESSION_MAX_AGE, SessionUser, User};
pub use break_glass::{BREAK_GLASS_CODE_TTL, BREAK_GLASS_SESSION_MAX_AGE};
pub use rbac::{Actor, AuditRecord};
pub use replica::MCP_SESSION_IDLE;
pub use tokens::{
    ApiToken, DEFAULT_TOKEN_LIFETIME, IssuedToken, MAX_SERVICE_TOKEN_LIFETIME,
    MAX_USER_TOKEN_LIFETIME, NewToken, PAT_PREFIX, ServiceAccount, TokenError,
};
pub use toolsets::{NewToolset, Toolset, ToolsetError};

const MAX_CONNECTIONS: u32 = 10;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

fn default_url_env() -> String {
    "AXON_DATABASE_URL".to_string()
}

/// `[database]` section: where to find the Postgres URL
#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    /// Name of the environment variable that holds the connection URL
    #[serde(default = "default_url_env")]
    pub url_env: String,
}

/// Errors from the Postgres store
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database URL environment variable {0} is not set or empty")]
    MissingEnv(String),

    #[error("failed to connect to the database: {0}")]
    Connect(#[source] sqlx::Error),

    #[error("failed to apply database migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),

    #[error("failed to gather randomness for a secret: {0}")]
    Random(String),
}

/// Handle to the Postgres store; cheap to clone
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connects using the URL in `config.url_env` and applies migrations.
    ///
    /// # Errors
    /// Fails when the variable is unset or empty, the database is unreachable
    /// or a migration cannot be applied.
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, StoreError> {
        let url = std::env::var(&config.url_env)
            .ok()
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| StoreError::MissingEnv(config.url_env.clone()))?;
        Self::connect_url(&url).await
    }

    pub(crate) async fn connect_url(url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(url)
            .await
            .map_err(StoreError::Connect)?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Round-trips a trivial query, for readiness probes.
    ///
    /// # Errors
    /// Fails when the pool cannot hand out a working connection.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use sqlx::PgPool;

    /// Base URL of the test database; tests skip without it.
    pub(crate) fn database_url() -> Option<String> {
        std::env::var("AXON_TEST_DATABASE_URL")
            .ok()
            .filter(|url| !url.is_empty())
    }

    /// Recreates a fresh schema and returns a URL whose `search_path` points
    /// at it, so parallel tests (and their migration tables) never collide.
    pub(crate) async fn isolated_url(base: &str, schema: &str) -> String {
        let pool = PgPool::connect(base)
            .await
            .expect("the test database must be reachable");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "drop schema if exists {schema} cascade"
        )))
        .execute(&pool)
        .await
        .expect("the test database must allow dropping the test schema");
        sqlx::query(sqlx::AssertSqlSafe(format!("create schema {schema}")))
            .execute(&pool)
            .await
            .expect("the test database must allow creating the test schema");
        pool.close().await;

        let separator = if base.contains('?') { '&' } else { '?' };
        format!("{base}{separator}options=-csearch_path%3D{schema}")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{database_url, isolated_url};
    use super::*;

    #[tokio::test]
    async fn connect_names_the_missing_variable() {
        let config = DatabaseConfig {
            url_env: "AXON_TEST_UNSET_DATABASE_URL".to_string(),
        };
        let err = Store::connect(&config).await.unwrap_err();
        assert!(
            matches!(&err, StoreError::MissingEnv(name) if name == "AXON_TEST_UNSET_DATABASE_URL")
        );
    }

    #[test]
    fn url_env_defaults() {
        let config: DatabaseConfig = toml::from_str("").unwrap();
        assert_eq!(config.url_env, "AXON_DATABASE_URL");
    }

    #[tokio::test]
    async fn ping_and_idempotent_migrations() {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return;
        };
        let url = isolated_url(&base, "axon_store_migrations").await;

        let store = Store::connect_url(&url).await.unwrap();
        store.ping().await.unwrap();
        // A second connect re-runs the migrations against the same schema.
        let again = Store::connect_url(&url).await.unwrap();
        again.ping().await.unwrap();
    }

    #[tokio::test]
    async fn users_reject_duplicate_issuer_and_subject() {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return;
        };
        let url = isolated_url(&base, "axon_store_users").await;
        let store = Store::connect_url(&url).await.unwrap();

        let insert = "insert into users (issuer, subject) values ($1, $2)";
        sqlx::query(insert)
            .bind("https://idp.example")
            .bind("alice")
            .execute(&store.pool)
            .await
            .unwrap();
        // Same subject at another issuer is a different identity.
        sqlx::query(insert)
            .bind("https://other.example")
            .bind("alice")
            .execute(&store.pool)
            .await
            .unwrap();
        let err = sqlx::query(insert)
            .bind("https://idp.example")
            .bind("alice")
            .execute(&store.pool)
            .await
            .unwrap_err();
        assert!(matches!(&err, sqlx::Error::Database(e) if e.is_unique_violation()));
    }
}
