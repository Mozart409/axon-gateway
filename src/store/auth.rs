//! Users, in-flight OIDC logins and browser sessions
//!
//! Only the SHA-256 (hex) of the OIDC `state` and of the session token is
//! stored, so a dump of the database logs nobody in. Timeouts are bound as
//! seconds into `make_interval`, so the database clock decides every expiry.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

use super::rbac::{Actor, audit};
use super::{SealedColumns, Store, StoreError};
use crate::crypto::{Keyring, Sealed};

/// A session that has not been used for this long is gone
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_hours(12);
/// A session ends this long after login, however active
pub const SESSION_MAX_AGE: Duration = Duration::from_hours(168);
/// `last_seen_at` is updated at most this often
const SESSION_TOUCH_INTERVAL: Duration = Duration::from_secs(60);
/// A login must come back from the provider within this long
const OIDC_FLOW_TTL: Duration = Duration::from_mins(10);
/// Size of the random session and CSRF tokens, before hex encoding
const SECRET_BYTES: usize = 32;

/// Identity and authorization from a verified ID token
pub struct LoginUser<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub display_name: Option<&'a str>,
    pub groups: &'a [String],
    pub is_admin: bool,
}

/// A user as stored, with the groups and admin flag of the last login
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct User {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub is_admin: bool,
}

/// A human user with what the users page needs on top of [`User`]
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct UserState {
    #[sqlx(flatten)]
    pub user: User,
    pub last_login_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
}

/// The plaintext token of a new session; only its hash is stored. The CSRF
/// token is read back with the session.
pub struct NewSession {
    /// Goes into the session cookie
    pub token: String,
}

impl fmt::Debug for NewSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewSession")
            .field("token", &"<redacted>")
            .finish()
    }
}

/// What a valid session cookie resolves to
#[derive(Clone)]
pub struct SessionUser {
    pub user: User,
    pub provider_id: String,
    pub csrf_token: String,
}

impl fmt::Debug for SessionUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionUser")
            .field("user", &self.user)
            .field("provider_id", &self.provider_id)
            .field("csrf_token", &"<redacted>")
            .finish()
    }
}

/// A login between the redirect to the provider and the callback
#[derive(Clone, FromRow)]
pub struct OidcFlow {
    pub provider_id: String,
    pub pkce_verifier: String,
    pub nonce: String,
    pub return_to: String,
}

impl fmt::Debug for OidcFlow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcFlow")
            .field("provider_id", &self.provider_id)
            .field("pkce_verifier", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("return_to", &self.return_to)
            .finish()
    }
}

#[derive(FromRow)]
struct SessionRow {
    id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    groups: Vec<String>,
    is_admin: bool,
    provider_id: String,
    csrf_token: String,
}

impl From<SessionRow> for SessionUser {
    fn from(row: SessionRow) -> Self {
        Self {
            user: User {
                id: row.id,
                issuer: row.issuer,
                subject: row.subject,
                email: row.email,
                display_name: row.display_name,
                groups: row.groups,
                is_admin: row.is_admin,
            },
            provider_id: row.provider_id,
            csrf_token: row.csrf_token,
        }
    }
}

/// The SHA-256 of a secret, hex encoded: the only form that is stored
pub(super) fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

/// What the sealed ID token of a session is bound to: its token hash
fn id_token_aad(token_hash: &str) -> String {
    format!("session-id-token:{token_hash}")
}

/// 32 random bytes, hex encoded
pub(super) fn random_secret() -> Result<String, StoreError> {
    let mut raw = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut raw).map_err(|error| StoreError::Random(error.to_string()))?;
    Ok(hex::encode(raw))
}

/// [`Store::set_user_disabled`] inside the caller's transaction, which must be
/// committed for the change to count (SCIM does this together with its own rows).
pub(super) async fn set_user_disabled_in(
    conn: &mut PgConnection,
    actor: &Actor,
    id: Uuid,
    disabled: bool,
) -> Result<bool, StoreError> {
    let name: Option<String> = sqlx::query_scalar(
        "update users set disabled_at = case when $2 then now() else null end \
         where id = $1 and kind = 'user' and (disabled_at is not null) <> $2 \
         returning coalesce(nullif(btrim(email), ''), subject)",
    )
    .bind(id)
    .bind(disabled)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(name) = name else {
        return Ok(false);
    };
    if disabled {
        sqlx::query("delete from sessions where user_id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    audit(
        conn,
        actor,
        if disabled {
            "user.disable"
        } else {
            "user.enable"
        },
        &format!("user:{name}"),
        json!({ "user_id": id }),
    )
    .await?;
    Ok(true)
}

/// A session's sealed ID token: `kek_id`, `dek` and `data`, all set or all null.
type SealedIdToken = (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>);

impl Store {
    /// Creates the user or updates the existing one by `(issuer, subject)`,
    /// refreshing email, display name, groups and admin flag from the token.
    /// The groups of a user whose groups come from SCIM (`groups_source`) are
    /// left as they are.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn upsert_user_on_login(&self, login: &LoginUser<'_>) -> Result<User, StoreError> {
        Ok(sqlx::query_as(
            "insert into users (issuer, subject, email, display_name, groups, is_admin, last_login_at) \
             values ($1, $2, $3, $4, $5, $6, now()) \
             on conflict (issuer, subject) do update set \
                 email = excluded.email, \
                 display_name = excluded.display_name, \
                 groups = case when users.groups_source = 'scim' \
                               then users.groups else excluded.groups end, \
                 is_admin = excluded.is_admin, \
                 last_login_at = now() \
             returning id, issuer, subject, email, display_name, groups, is_admin",
        )
        .bind(login.issuer)
        .bind(login.subject)
        .bind(login.email)
        .bind(login.display_name)
        .bind(login.groups)
        .bind(login.is_admin)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Whether the user is disabled. `false` for an unknown id.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn user_disabled(&self, id: Uuid) -> Result<bool, StoreError> {
        let disabled: Option<bool> =
            sqlx::query_scalar("select disabled_at is not null from users where id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(disabled.unwrap_or(false))
    }

    /// One human user with their last login and disabled state; `None` for an
    /// unknown id or a service account.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn user_state(&self, id: Uuid) -> Result<Option<UserState>, StoreError> {
        Ok(sqlx::query_as(
            "select id, issuer, subject, email, display_name, groups, is_admin, \
                    last_login_at, disabled_at \
             from users where kind = 'user' and id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Up to `limit` human users (not service accounts) with their last login
    /// and disabled state, ordered by email, display name or subject.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_user_states(&self, limit: i64) -> Result<Vec<UserState>, StoreError> {
        Ok(sqlx::query_as(
            "select id, issuer, subject, email, display_name, groups, is_admin, \
                    last_login_at, disabled_at \
             from users where kind = 'user' \
             order by lower(coalesce(email, display_name, subject)), id limit $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Disables or re-enables a human user. Disabling also ends the user's
    /// sessions; their tokens stop working through the disabled flag.
    /// `false` when there is no such user (service accounts are not users
    /// here) or it is already in that state.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn set_user_disabled(
        &self,
        actor: &Actor,
        id: Uuid,
        disabled: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        if !set_user_disabled_in(&mut tx, actor, id, disabled).await? {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Opens a session for `user_id` and returns its plaintext secrets. An
    /// `id_token` is kept sealed with the keyring (for the logout hint); a
    /// session without one just logs out without a hint.
    ///
    /// # Errors
    /// Fails when the system cannot supply randomness or the insert fails.
    pub async fn create_session(
        &self,
        user_id: Uuid,
        provider_id: &str,
        id_token: Option<(&Keyring, &str)>,
    ) -> Result<NewSession, StoreError> {
        let token = random_secret()?;
        let csrf_token = random_secret()?;
        let token_hash = hash_secret(&token);
        // A token that cannot be sealed is not kept: the login still works, the
        // logout just has no hint
        let sealed = id_token.and_then(|(keyring, id_token)| {
            keyring
                .seal(id_token.as_bytes(), id_token_aad(&token_hash).as_bytes())
                .map(SealedColumns::from)
                .inspect_err(|error| tracing::warn!(%error, "could not seal an ID token"))
                .ok()
        });
        sqlx::query(
            "insert into sessions (token_hash, user_id, provider_id, csrf_token, \
                                   id_token_kek_id, id_token_dek, id_token_data, expires_at) \
             values ($1, $2, $3, $4, $5, $6, $7, now() + make_interval(secs => $8))",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(provider_id)
        .bind(&csrf_token)
        .bind(sealed.as_ref().map(|sealed| sealed.kek_id.as_str()))
        .bind(sealed.as_ref().map(|sealed| sealed.dek.as_slice()))
        .bind(sealed.as_ref().map(|sealed| sealed.data.as_slice()))
        .bind(SESSION_MAX_AGE.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(NewSession { token })
    }

    /// Resolves a session cookie, if the session exists, its user is not
    /// disabled, it has not passed its maximum age and has not been idle too
    /// long. `last_seen_at` is bumped at
    /// most once a minute.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn session_user(&self, token: &str) -> Result<Option<SessionUser>, StoreError> {
        let row: Option<SessionRow> = sqlx::query_as(
            "with session as ( \
                 select s.id as session_id, u.id, u.issuer, u.subject, u.email, u.display_name, \
                        u.groups, u.is_admin, s.provider_id, s.csrf_token \
                 from sessions s join users u on u.id = s.user_id \
                 where s.token_hash = $1 \
                   and u.disabled_at is null \
                   and s.expires_at > now() \
                   and s.last_seen_at > now() - make_interval(secs => $2) \
             ), touched as ( \
                 update sessions set last_seen_at = now() \
                 where id in (select session_id from session) \
                   and last_seen_at < now() - make_interval(secs => $3) \
             ) \
             select id, issuer, subject, email, display_name, groups, is_admin, \
                    provider_id, csrf_token \
             from session",
        )
        .bind(hash_secret(token))
        .bind(SESSION_IDLE_TIMEOUT.as_secs_f64())
        .bind(SESSION_TOUCH_INTERVAL.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(SessionUser::from))
    }

    /// The ID token a session was opened with, for the logout hint. `None`
    /// when there is none, and, after a warning that never carries the value,
    /// when the lookup or the unsealing fails: the logout then has no hint.
    pub async fn session_id_token(&self, token: &str, keyring: &Keyring) -> Option<String> {
        let token_hash = hash_secret(token);
        let row: Result<Option<SealedIdToken>, _> = sqlx::query_as(
            "select id_token_kek_id, id_token_dek, id_token_data from sessions \
                 where token_hash = $1",
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await;
        let (Some(kek_id), Some(dek), Some(data)) = (match row {
            Ok(Some(columns)) => columns,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "could not read the ID token of a session");
                return None;
            }
        }) else {
            return None;
        };
        let sealed = Sealed::from(&SealedColumns { kek_id, dek, data });
        match keyring.open(&sealed, id_token_aad(&token_hash).as_bytes()) {
            Ok(plaintext) => String::from_utf8(plaintext).ok(),
            Err(error) => {
                tracing::warn!(%error, "could not open the ID token of a session");
                None
            }
        }
    }

    /// Ends a session. `false` when there was none.
    ///
    /// # Errors
    /// Fails when the delete fails.
    pub async fn delete_session(&self, token: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("delete from sessions where token_hash = $1")
            .bind(hash_secret(token))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Records a login in progress, keyed by the hash of its `state`.
    ///
    /// # Errors
    /// Fails when the insert fails, e.g. on a repeated `state`.
    pub async fn create_oidc_flow(&self, state: &str, flow: &OidcFlow) -> Result<(), StoreError> {
        sqlx::query(
            "insert into oidc_flows (state_hash, provider_id, pkce_verifier, nonce, return_to, expires_at) \
             values ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
        )
        .bind(hash_secret(state))
        .bind(&flow.provider_id)
        .bind(&flow.pkce_verifier)
        .bind(&flow.nonce)
        .bind(&flow.return_to)
        .bind(OIDC_FLOW_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consumes the login for `state`. A flow can be taken once; a second
    /// callback with the same `state`, or one after the TTL, finds nothing.
    ///
    /// # Errors
    /// Fails when the delete fails.
    pub async fn take_oidc_flow(&self, state: &str) -> Result<Option<OidcFlow>, StoreError> {
        Ok(sqlx::query_as(
            "delete from oidc_flows where state_hash = $1 and expires_at > now() \
             returning provider_id, pkce_verifier, nonce, return_to",
        )
        .bind(hash_secret(state))
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Deletes expired logins and expired or idle sessions, and returns how
    /// many rows went.
    ///
    /// # Errors
    /// Fails when a delete fails.
    pub async fn purge_expired(&self) -> Result<u64, StoreError> {
        let flows = sqlx::query("delete from oidc_flows where expires_at <= now()")
            .execute(&self.pool)
            .await?;
        let sessions = sqlx::query(
            "delete from sessions \
             where expires_at <= now() or last_seen_at <= now() - make_interval(secs => $1)",
        )
        .bind(SESSION_IDLE_TIMEOUT.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(flows.rows_affected() + sessions.rows_affected())
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

    fn login(groups: &[String], is_admin: bool) -> LoginUser<'_> {
        LoginUser {
            issuer: "https://idp.example",
            subject: "alice",
            email: Some("alice@example.com"),
            display_name: Some("Alice"),
            groups,
            is_admin,
        }
    }

    fn flow() -> OidcFlow {
        OidcFlow {
            provider_id: "main".to_string(),
            pkce_verifier: "verifier-secret".to_string(),
            nonce: "nonce-secret".to_string(),
            return_to: "/ui".to_string(),
        }
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let new = NewSession {
            token: "tok-secret".to_string(),
        };
        let rendered = format!("{new:?}");
        assert!(!rendered.contains("tok-secret"));

        let session = SessionUser {
            user: User {
                id: Uuid::nil(),
                issuer: "https://idp.example".to_string(),
                subject: "alice".to_string(),
                email: None,
                display_name: None,
                groups: Vec::new(),
                is_admin: false,
            },
            provider_id: "main".to_string(),
            csrf_token: "csrf-secret".to_string(),
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("csrf-secret"));

        let rendered = format!("{:?}", flow());
        assert!(!rendered.contains("verifier-secret"));
        assert!(!rendered.contains("nonce-secret"));
    }

    #[test]
    fn hashing_is_sha256_hex() {
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn upsert_creates_then_updates_and_keeps_the_id() {
        let Some(store) = test_store("axon_store_upsert").await else {
            return;
        };

        let first_groups = vec!["dev".to_string()];
        let created = store
            .upsert_user_on_login(&login(&first_groups, false))
            .await
            .unwrap();
        assert_eq!(created.groups, first_groups);
        assert!(!created.is_admin);

        let second_groups = vec!["dev".to_string(), "ops".to_string()];
        let updated = store
            .upsert_user_on_login(&login(&second_groups, true))
            .await
            .unwrap();
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.groups, second_groups);
        assert!(updated.is_admin);

        let count: i64 = sqlx::query_scalar("select count(*) from users")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn session_round_trip_stores_only_the_hash() {
        let Some(store) = test_store("axon_store_session").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();

        let new = store.create_session(user.id, "main", None).await.unwrap();

        let found = store.session_user(&new.token).await.unwrap().unwrap();
        assert_eq!(found.user, user);
        assert_eq!(found.provider_id, "main");
        assert_eq!(found.csrf_token.len(), 64);
        assert_ne!(found.csrf_token, new.token);

        let stored: String = sqlx::query_scalar("select token_hash from sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_ne!(stored, new.token);
        assert_eq!(stored, hash_secret(&new.token));

        assert!(store.session_user("unknown-token").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_id_token_is_sealed_at_rest() {
        let Some(store) = test_store("axon_store_session_id_token").await else {
            return;
        };
        let keyring = Keyring::from_text("k1:0123456789abcdef0123456789abcdef-secret").unwrap();
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();
        let id_token = "header.payload.signature-secret";
        let new = store
            .create_session(user.id, "main", Some((&keyring, id_token)))
            .await
            .unwrap();

        let plaintext_column: i64 = sqlx::query_scalar(
            "select count(*) from information_schema.columns \
             where table_schema = current_schema() and table_name = 'sessions' \
             and column_name = 'id_token'",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(plaintext_column, 0);
        let data: Vec<u8> = sqlx::query_scalar("select id_token_data from sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(
            !data
                .windows(id_token.len())
                .any(|window| window == id_token.as_bytes())
        );

        assert_eq!(
            store
                .session_id_token(&new.token, &keyring)
                .await
                .as_deref(),
            Some(id_token)
        );
        // Moved to another session row, the sealed token no longer opens
        let other = store.create_session(user.id, "main", None).await.unwrap();
        sqlx::query(
            "update sessions set id_token_kek_id = o.id_token_kek_id, id_token_dek = o.id_token_dek, \
                    id_token_data = o.id_token_data \
             from sessions o where o.token_hash = $1 and sessions.token_hash = $2",
        )
        .bind(hash_secret(&new.token))
        .bind(hash_secret(&other.token))
        .execute(&store.pool)
        .await
        .unwrap();
        assert_eq!(store.session_id_token(&other.token, &keyring).await, None);
        assert_eq!(
            store.session_id_token("unknown-token", &keyring).await,
            None
        );
    }

    #[tokio::test]
    async fn expired_and_idle_sessions_resolve_to_none() {
        let Some(store) = test_store("axon_store_session_expiry").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();

        let expired = store.create_session(user.id, "main", None).await.unwrap();
        sqlx::query(
            "update sessions set expires_at = now() - interval '1 second' where token_hash = $1",
        )
        .bind(hash_secret(&expired.token))
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.session_user(&expired.token).await.unwrap().is_none());

        let idle = store.create_session(user.id, "main", None).await.unwrap();
        sqlx::query(
            "update sessions set last_seen_at = now() - interval '13 hours' where token_hash = $1",
        )
        .bind(hash_secret(&idle.token))
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(store.session_user(&idle.token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_session_ends_it() {
        let Some(store) = test_store("axon_store_session_delete").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();
        let new = store.create_session(user.id, "main", None).await.unwrap();

        assert!(store.delete_session(&new.token).await.unwrap());
        assert!(store.session_user(&new.token).await.unwrap().is_none());
        assert!(!store.delete_session(&new.token).await.unwrap());
    }

    #[tokio::test]
    async fn oidc_flow_is_single_use_and_stored_hashed() {
        let Some(store) = test_store("axon_store_flow").await else {
            return;
        };
        store.create_oidc_flow("state-1", &flow()).await.unwrap();

        let stored: String = sqlx::query_scalar("select state_hash from oidc_flows")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_ne!(stored, "state-1");

        let taken = store.take_oidc_flow("state-1").await.unwrap().unwrap();
        assert_eq!(taken.provider_id, "main");
        assert_eq!(taken.pkce_verifier, "verifier-secret");
        assert_eq!(taken.nonce, "nonce-secret");
        assert_eq!(taken.return_to, "/ui");
        assert!(store.take_oidc_flow("state-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn expired_oidc_flow_is_not_taken() {
        let Some(store) = test_store("axon_store_flow_expiry").await else {
            return;
        };
        store.create_oidc_flow("state-1", &flow()).await.unwrap();
        sqlx::query("update oidc_flows set expires_at = now() - interval '1 second'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.take_oidc_flow("state-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn purge_expired_removes_only_dead_rows() {
        let Some(store) = test_store("axon_store_purge").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();

        let live = store.create_session(user.id, "main", None).await.unwrap();
        let expired = store.create_session(user.id, "main", None).await.unwrap();
        let idle = store.create_session(user.id, "main", None).await.unwrap();
        sqlx::query(
            "update sessions set expires_at = now() - interval '1 second' where token_hash = $1",
        )
        .bind(hash_secret(&expired.token))
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "update sessions set last_seen_at = now() - interval '13 hours' where token_hash = $1",
        )
        .bind(hash_secret(&idle.token))
        .execute(&store.pool)
        .await
        .unwrap();
        store.create_oidc_flow("dead", &flow()).await.unwrap();
        store.create_oidc_flow("alive", &flow()).await.unwrap();
        sqlx::query(
            "update oidc_flows set expires_at = now() - interval '1 second' where state_hash = $1",
        )
        .bind(hash_secret("dead"))
        .execute(&store.pool)
        .await
        .unwrap();

        assert_eq!(store.purge_expired().await.unwrap(), 3);
        assert!(store.session_user(&live.token).await.unwrap().is_some());
        assert!(store.take_oidc_flow("alive").await.unwrap().is_some());
        assert_eq!(store.purge_expired().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn deleting_a_user_cascades_to_sessions() {
        let Some(store) = test_store("axon_store_cascade").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();
        let new = store.create_session(user.id, "main", None).await.unwrap();

        sqlx::query("delete from users where id = $1")
            .bind(user.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.session_user(&new.token).await.unwrap().is_none());
        let count: i64 = sqlx::query_scalar("select count(*) from sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    fn cli() -> Actor {
        Actor {
            user_id: None,
            label: "cli".to_string(),
        }
    }

    #[tokio::test]
    async fn disabling_a_user_ends_their_sessions_and_audits_once() {
        let Some(store) = test_store("axon_store_user_disable").await else {
            return;
        };
        let user = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();
        let new = store.create_session(user.id, "main", None).await.unwrap();
        assert!(!store.user_disabled(user.id).await.unwrap());

        assert!(
            store
                .set_user_disabled(&cli(), user.id, true)
                .await
                .unwrap()
        );
        assert!(store.user_disabled(user.id).await.unwrap());
        assert!(store.session_user(&new.token).await.unwrap().is_none());
        let sessions: i64 = sqlx::query_scalar("select count(*) from sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(sessions, 0);
        // The login still updates the row and returns the user; the caller refuses it.
        let again = store
            .upsert_user_on_login(&login(&[], false))
            .await
            .unwrap();
        assert_eq!(again.id, user.id);
        assert!(store.user_disabled(user.id).await.unwrap());

        // No transition, no second audit row.
        assert!(
            !store
                .set_user_disabled(&cli(), user.id, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .set_user_disabled(&cli(), user.id, false)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_user_disabled(&cli(), user.id, false)
                .await
                .unwrap()
        );
        assert!(!store.user_disabled(user.id).await.unwrap());

        let rows: Vec<(String, String)> =
            sqlx::query_as("select action, target from audit_log order by id")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    "user.disable".to_string(),
                    "user:alice@example.com".to_string()
                ),
                (
                    "user.enable".to_string(),
                    "user:alice@example.com".to_string()
                ),
            ]
        );
    }

    #[tokio::test]
    async fn set_user_disabled_skips_service_accounts_and_unknown_ids() {
        let Some(store) = test_store("axon_store_user_disable_kind").await else {
            return;
        };
        let account: Uuid = sqlx::query_scalar(
            "insert into users (issuer, subject, kind) values ('service', 'ci', 'service') \
             returning id",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();

        assert!(
            !store
                .set_user_disabled(&cli(), account, true)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_user_disabled(&cli(), Uuid::new_v4(), true)
                .await
                .unwrap()
        );
        assert!(!store.user_disabled(account).await.unwrap());
    }

    #[tokio::test]
    async fn list_user_states_lists_humans_with_state() {
        let Some(store) = test_store("axon_store_user_states").await else {
            return;
        };
        let user = store.upsert_user_on_login(&login(&[], true)).await.unwrap();
        sqlx::query(
            "insert into users (issuer, subject, kind) values ('service', 'ci', 'service')",
        )
        .execute(&store.pool)
        .await
        .unwrap();

        let states = store.list_user_states(10).await.unwrap();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].user, user);
        assert!(states[0].last_login_at.is_some());
        assert!(states[0].disabled_at.is_none());

        store
            .set_user_disabled(&cli(), user.id, true)
            .await
            .unwrap();
        let states = store.list_user_states(10).await.unwrap();
        assert!(states[0].disabled_at.is_some());
    }
}
