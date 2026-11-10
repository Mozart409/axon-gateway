//! Break-glass admin login: one-time codes and the built-in admin user
//!
//! `axon-gateway admin login-link` stores the hash of a code; redeeming it
//! consumes the code and opens a short admin session for the break-glass user.
//! Disabling that user in the database switches the whole mechanism off. Both
//! steps are audited, each in the transaction of the change itself.

use std::fmt;
use std::time::Duration;

use serde_json::json;
use uuid::Uuid;

use super::auth::{hash_secret, random_secret};
use super::rbac::{Actor, audit};
use super::{Store, StoreError};

/// A login link works for this long
pub const BREAK_GLASS_CODE_TTL: Duration = Duration::from_mins(15);
/// A break-glass session ends this long after login, however active
pub const BREAK_GLASS_SESSION_MAX_AGE: Duration = Duration::from_hours(1);

/// `users.issuer` of the break-glass user
const BREAK_GLASS_ISSUER: &str = "axon:break-glass";
/// `users.subject` of the break-glass user
const BREAK_GLASS_SUBJECT: &str = "break-glass";
/// `sessions.provider_id` of a break-glass session; no configured provider has it
const BREAK_GLASS_PROVIDER: &str = "break-glass";
/// Audit label of the redeeming side
const BREAK_GLASS_LABEL: &str = "break-glass";

/// The plaintext token of a new break-glass session; only its hash is stored
pub struct NewBreakGlassSession {
    /// Goes into the session cookie
    pub token: String,
    /// The break-glass user
    pub user_id: Uuid,
}

impl fmt::Debug for NewBreakGlassSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewBreakGlassSession")
            .field("token", &"<redacted>")
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl Store {
    /// Creates a one-time login code and returns it in plaintext; only its
    /// hash is stored. Expired codes are deleted on the way. Audited as
    /// `break_glass.link_created` by `cli`.
    ///
    /// # Errors
    /// Fails when the system cannot supply randomness or a query fails.
    pub async fn create_break_glass_code(&self) -> Result<String, StoreError> {
        let code = random_secret()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("delete from break_glass_codes where expires_at <= now()")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "insert into break_glass_codes (code_hash, expires_at) \
             values ($1, now() + make_interval(secs => $2))",
        )
        .bind(hash_secret(&code))
        .bind(BREAK_GLASS_CODE_TTL.as_secs_f64())
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            &Actor {
                user_id: None,
                label: "cli".to_owned(),
            },
            "break_glass.link_created",
            BREAK_GLASS_SUBJECT,
            json!({ "expires_in_secs": BREAK_GLASS_CODE_TTL.as_secs() }),
        )
        .await?;
        tx.commit().await?;
        Ok(code)
    }

    /// Consumes `code` and opens a break-glass admin session. `None` when the
    /// code is unknown, used or expired, or when the break-glass user is
    /// disabled (the code is spent then too). Audited as `break_glass.login`.
    ///
    /// # Errors
    /// Fails when the system cannot supply randomness or a query fails.
    pub async fn redeem_break_glass_code(
        &self,
        code: &str,
    ) -> Result<Option<NewBreakGlassSession>, StoreError> {
        let token = random_secret()?;
        let csrf_token = random_secret()?;
        let mut tx = self.pool.begin().await?;

        let consumed = sqlx::query(
            "delete from break_glass_codes where code_hash = $1 and expires_at > now()",
        )
        .bind(hash_secret(code))
        .execute(&mut *tx)
        .await?;
        if consumed.rows_affected() == 0 {
            return Ok(None);
        }

        // A disabled user makes the update's `where` fail, so no row comes back.
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "insert into users (issuer, subject, display_name, kind, is_admin, last_login_at) \
             values ($1, $2, 'Break-glass admin', 'user', true, now()) \
             on conflict (issuer, subject) do update set \
                 display_name = excluded.display_name, \
                 is_admin = true, \
                 last_login_at = now() \
             where users.disabled_at is null \
             returning id",
        )
        .bind(BREAK_GLASS_ISSUER)
        .bind(BREAK_GLASS_SUBJECT)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(user_id) = user_id else {
            // The code stays consumed.
            tx.commit().await?;
            return Ok(None);
        };

        sqlx::query(
            "insert into sessions (token_hash, user_id, provider_id, csrf_token, id_token, expires_at) \
             values ($1, $2, $3, $4, null, now() + make_interval(secs => $5))",
        )
        .bind(hash_secret(&token))
        .bind(user_id)
        .bind(BREAK_GLASS_PROVIDER)
        .bind(&csrf_token)
        .bind(BREAK_GLASS_SESSION_MAX_AGE.as_secs_f64())
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            &Actor {
                user_id: Some(user_id),
                label: BREAK_GLASS_LABEL.to_owned(),
            },
            "break_glass.login",
            BREAK_GLASS_SUBJECT,
            json!({ "session_max_age_secs": BREAK_GLASS_SESSION_MAX_AGE.as_secs() }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(NewBreakGlassSession { token, user_id }))
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn a_code_opens_one_admin_session_and_only_once() {
        let Some(store) = test_store("axon_break_glass_once").await else {
            return;
        };
        let code = store.create_break_glass_code().await.unwrap();

        let session = store
            .redeem_break_glass_code(&code)
            .await
            .unwrap()
            .expect("the code is valid");
        let resolved = store
            .session_user(&session.token)
            .await
            .unwrap()
            .expect("the session resolves");
        assert!(resolved.user.is_admin);
        assert_eq!(resolved.user.id, session.user_id);
        assert_eq!(resolved.user.issuer, BREAK_GLASS_ISSUER);
        assert_eq!(resolved.provider_id, BREAK_GLASS_PROVIDER);
        assert_eq!(resolved.id_token, None);

        assert!(
            store
                .redeem_break_glass_code(&code)
                .await
                .unwrap()
                .is_none(),
            "a code is single use"
        );
        assert!(
            store
                .redeem_break_glass_code("not-a-code")
                .await
                .unwrap()
                .is_none()
        );

        let log = store.audit_log(10, None).await.unwrap();
        let actions: Vec<(&str, &str)> = log
            .iter()
            .map(|row| (row.action.as_str(), row.actor.as_str()))
            .collect();
        assert_eq!(
            actions,
            [
                ("break_glass.login", "break-glass"),
                ("break_glass.link_created", "cli"),
            ]
        );
        assert_eq!(log[0].actor_user_id, Some(session.user_id));
    }

    #[tokio::test]
    async fn the_session_lasts_an_hour() {
        let Some(store) = test_store("axon_break_glass_ttl").await else {
            return;
        };
        let code = store.create_break_glass_code().await.unwrap();
        store.redeem_break_glass_code(&code).await.unwrap().unwrap();

        let (minutes,): (f64,) = sqlx::query_as(
            "select (extract(epoch from expires_at - now()) / 60)::float8 from sessions",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!((59.0..=60.0).contains(&minutes), "{minutes}");
    }

    #[tokio::test]
    async fn an_expired_code_fails_and_is_purged_by_the_next_one() {
        let Some(store) = test_store("axon_break_glass_expired").await else {
            return;
        };
        sqlx::query(
            "insert into break_glass_codes (code_hash, expires_at) \
             values ($1, now() - interval '1 second')",
        )
        .bind(hash_secret("old-code"))
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(
            store
                .redeem_break_glass_code("old-code")
                .await
                .unwrap()
                .is_none()
        );

        let (rows,): (i64,) = sqlx::query_as("select count(*) from break_glass_codes")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "the expired code is still stored");
        store.create_break_glass_code().await.unwrap();
        let (rows,): (i64,) = sqlx::query_as("select count(*) from break_glass_codes")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "only the fresh code is left");
    }

    #[tokio::test]
    async fn a_disabled_break_glass_user_cannot_log_in() {
        let Some(store) = test_store("axon_break_glass_disabled").await else {
            return;
        };
        let code = store.create_break_glass_code().await.unwrap();
        store.redeem_break_glass_code(&code).await.unwrap().unwrap();

        sqlx::query("update users set disabled_at = now() where issuer = $1")
            .bind(BREAK_GLASS_ISSUER)
            .execute(&store.pool)
            .await
            .unwrap();
        let code = store.create_break_glass_code().await.unwrap();
        assert!(
            store
                .redeem_break_glass_code(&code)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .redeem_break_glass_code(&code)
                .await
                .unwrap()
                .is_none(),
            "the code is spent either way"
        );

        let (sessions,): (i64,) = sqlx::query_as("select count(*) from sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(sessions, 1, "no new session was opened");
    }
}
