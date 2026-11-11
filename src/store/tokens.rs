//! Personal access tokens and service accounts
//!
//! A token reads `axon_pat_<public id>_<secret>`. The public id (16 hex chars)
//! is the lookup key; only the SHA-256 of the secret (64 hex chars) is stored
//! and it is compared in constant time. A service account is a `users` row
//! with `kind = 'service'`, so groups, role bindings and opt-outs apply to it
//! unchanged. Lifetimes are checked against the database clock.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::principal::TokenScope;

use super::auth::User;
use super::rbac::{Actor, audit};
use super::{Store, StoreError};

/// Every token starts with this, so secret scanners can find a leaked one
pub const PAT_PREFIX: &str = "axon_pat_";
/// The lifetime a client should offer when the user does not pick one
pub const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_hours(30 * 24);
/// The longest a token owned by a user may live
pub const MAX_USER_TOKEN_LIFETIME: Duration = Duration::from_hours(90 * 24);
/// The longest a token owned by a service account may live
pub const MAX_SERVICE_TOKEN_LIFETIME: Duration = Duration::from_hours(365 * 24);
/// A user's tokens stop working when they have not logged in for this long
pub const INACTIVE_OWNER_SUSPEND: Duration = Duration::from_hours(90 * 24);
/// `last_used_at` is updated at most this often
pub(super) const TOKEN_TOUCH_INTERVAL: Duration = Duration::from_secs(60);
/// The `issuer` of every service account
const SERVICE_ISSUER: &str = "axon:service-account";
/// Characters in the public id (8 random bytes, hex encoded)
pub(super) const PUBLIC_ID_LEN: usize = 16;
/// Characters in the secret (32 random bytes, hex encoded)
pub(super) const SECRET_LEN: usize = 64;
/// Longest accepted token name, in characters
const MAX_NAME_CHARS: usize = 100;

/// Errors from issuing a token
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("the token name must be 1 to {MAX_NAME_CHARS} characters")]
    InvalidName,

    #[error("the token must expire in the future")]
    ExpiryInPast,

    #[error("the token would outlive the owner's maximum of {0} days")]
    ExpiryTooLong(u64),

    #[error("the token owner does not exist")]
    UnknownOwner,

    #[error("the toolset does not exist or belongs to someone else")]
    UnknownToolset,

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

/// A non-human principal owned by admins
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub disabled: bool,
    pub created_at: DateTime<Utc>,
}

/// A token as stored; the secret is not kept, only its hash
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ApiToken {
    pub id: Uuid,
    pub public_id: String,
    pub owner_id: Uuid,
    pub name: String,
    /// Backends the token is narrowed to; empty means no narrowing
    pub scope_backends: Vec<String>,
    /// Tool globs the token is narrowed to; empty means no narrowing
    pub scope_tools: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    /// The user toolset the token is pinned to, a live link
    pub toolset_id: Option<Uuid>,
    /// Name of the pinned toolset
    pub toolset_name: Option<String>,
}

/// What to issue a token for
#[derive(Debug, Clone, Copy)]
pub struct NewToken<'a> {
    pub owner_id: Uuid,
    pub name: &'a str,
    pub scope_backends: &'a [String],
    pub scope_tools: &'a [String],
    /// A toolset of the owner to pin the token to
    pub toolset_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// A new token with its plaintext, which is shown once and never stored
pub struct IssuedToken {
    pub token: ApiToken,
    pub plaintext: String,
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedToken")
            .field("token", &self.token)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

/// What a valid token resolves to
#[derive(Debug, Clone)]
pub struct TokenPrincipal {
    pub token: ApiToken,
    pub owner: User,
    pub is_service_account: bool,
    /// Tools and backends of the pinned toolset as they are now, `None` when not pinned
    pub toolset: Option<TokenScope>,
}

#[derive(FromRow)]
struct TokenAuthRow {
    token_id: Uuid,
    public_id: String,
    name: String,
    scope_backends: Vec<String>,
    scope_tools: Vec<String>,
    toolset_id: Option<Uuid>,
    toolset_name: Option<String>,
    toolset_tools: Option<Vec<String>>,
    toolset_backends: Option<Vec<String>>,
    token_created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    secret_hash: Vec<u8>,
    owner_id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    groups: Vec<String>,
    is_admin: bool,
    kind: String,
}

/// The public id and secret of a well-formed token, or `None`
fn parse_pat(plaintext: &str) -> Option<(&str, &str)> {
    let rest = plaintext.strip_prefix(PAT_PREFIX)?;
    let (public_id, secret) = rest.split_once('_')?;
    (public_id.len() == PUBLIC_ID_LEN
        && secret.len() == SECRET_LEN
        && is_lower_hex(public_id)
        && is_lower_hex(secret))
    .then_some((public_id, secret))
}

pub(super) fn is_lower_hex(text: &str) -> bool {
    text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The SHA-256 of a token secret: the only form that is stored
pub(super) fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// `N` random bytes, hex encoded
pub(super) fn random_hex<const N: usize>() -> Result<String, StoreError> {
    let mut raw = [0_u8; N];
    getrandom::fill(&mut raw).map_err(|error| StoreError::Random(error.to_string()))?;
    Ok(hex::encode(raw))
}

impl Store {
    /// Creates a service account. `None` when the name is taken.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn create_service_account(
        &self,
        actor: &Actor,
        name: &str,
        description: Option<&str>,
    ) -> Result<Option<ServiceAccount>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let account: Option<ServiceAccount> = sqlx::query_as(
            "insert into users (issuer, subject, display_name, kind, description) \
             values ($1, $2, $2, 'service', $3) \
             on conflict (issuer, subject) do nothing \
             returning id, subject as name, description, disabled_at is not null as disabled, created_at",
        )
        .bind(SERVICE_ISSUER)
        .bind(name)
        .bind(description)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account) = account else {
            return Ok(None);
        };
        audit(
            &mut tx,
            actor,
            "service_account.create",
            &format!("service_account:{name}"),
            json!({ "description": description }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(account))
    }

    /// All service accounts, by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_service_accounts(&self) -> Result<Vec<ServiceAccount>, StoreError> {
        Ok(sqlx::query_as(
            "select id, subject as name, description, disabled_at is not null as disabled, created_at \
             from users where kind = 'service' order by subject",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// One service account by id.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn service_account(&self, id: Uuid) -> Result<Option<ServiceAccount>, StoreError> {
        Ok(sqlx::query_as(
            "select id, subject as name, description, disabled_at is not null as disabled, created_at \
             from users where kind = 'service' and id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Disables or re-enables a service account, which suspends or restores
    /// its tokens. `false` when it does not exist or is already in that state.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn set_service_account_disabled(
        &self,
        actor: &Actor,
        id: Uuid,
        disabled: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let name: Option<String> = sqlx::query_scalar(
            "update users set disabled_at = case when $2 then now() else null end \
             where id = $1 and kind = 'service' and (disabled_at is not null) <> $2 \
             returning subject",
        )
        .bind(id)
        .bind(disabled)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(name) = name else {
            return Ok(false);
        };
        audit(
            &mut tx,
            actor,
            if disabled {
                "service_account.disable"
            } else {
                "service_account.enable"
            },
            &format!("service_account:{name}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a service account with its tokens, memberships and bindings.
    /// `false` when it does not exist.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_service_account(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let name: Option<String> = sqlx::query_scalar(
            "delete from users where id = $1 and kind = 'service' returning subject",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(name) = name else {
            return Ok(false);
        };
        audit(
            &mut tx,
            actor,
            "service_account.delete",
            &format!("service_account:{name}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Issues a token for `new.owner_id` and returns its plaintext, the only
    /// time it exists. The expiry must be in the future and within the
    /// owner's maximum lifetime (users 90 days, service accounts 365).
    ///
    /// # Errors
    /// Fails on an invalid name or expiry, an unknown owner, missing
    /// randomness or when the transaction fails.
    pub async fn create_token(
        &self,
        actor: &Actor,
        new: &NewToken<'_>,
    ) -> Result<IssuedToken, TokenError> {
        if new.name.trim().is_empty() || new.name.chars().count() > MAX_NAME_CHARS {
            return Err(TokenError::InvalidName);
        }
        let public_id = random_hex::<8>()?;
        let secret = random_hex::<32>()?;

        let mut tx = self.pool.begin().await?;
        let (kind, in_past, too_long): (String, bool, bool) = sqlx::query_as(
            "select kind, $2 <= now(), \
                    $2 > now() + make_interval(secs => case kind when 'service' then $3 else $4 end) \
             from users where id = $1",
        )
        .bind(new.owner_id)
        .bind(new.expires_at)
        .bind(MAX_SERVICE_TOKEN_LIFETIME.as_secs_f64())
        .bind(MAX_USER_TOKEN_LIFETIME.as_secs_f64())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(TokenError::UnknownOwner)?;
        if in_past {
            return Err(TokenError::ExpiryInPast);
        }
        if too_long {
            let ceiling = if kind == "service" {
                MAX_SERVICE_TOKEN_LIFETIME
            } else {
                MAX_USER_TOKEN_LIFETIME
            };
            return Err(TokenError::ExpiryTooLong(ceiling.as_secs() / 86_400));
        }

        if let Some(toolset_id) = new.toolset_id {
            let owned: Option<(Uuid,)> = sqlx::query_as(
                "select id from user_toolsets where id = $1 and owner_id = $2 for share",
            )
            .bind(toolset_id)
            .bind(new.owner_id)
            .fetch_optional(&mut *tx)
            .await?;
            if owned.is_none() {
                return Err(TokenError::UnknownToolset);
            }
        }

        let token: ApiToken = sqlx::query_as(
            "with t as ( \
                 insert into api_tokens \
                     (public_id, secret_hash, owner_id, name, scope_backends, scope_tools, \
                      toolset_id, expires_at) \
                 values ($1, $2, $3, $4, $5, $6, $8, $7) \
                 returning * \
             ) \
             select t.id, t.public_id, t.owner_id, t.name, t.scope_backends, t.scope_tools, \
                    t.created_at, t.expires_at, t.last_used_at, t.revoked_at is not null as revoked, \
                    t.toolset_id, s.name as toolset_name \
             from t left join user_toolsets s on s.id = t.toolset_id",
        )
        .bind(&public_id)
        .bind(hash_secret(&secret))
        .bind(new.owner_id)
        .bind(new.name)
        .bind(new.scope_backends)
        .bind(new.scope_tools)
        .bind(new.expires_at)
        .bind(new.toolset_id)
        .fetch_one(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "token.create",
            &format!("token:{public_id}"),
            json!({
                "owner_id": new.owner_id,
                "name": new.name,
                "scope_backends": new.scope_backends,
                "scope_tools": new.scope_tools,
                "toolset_id": new.toolset_id,
                "expires_at": new.expires_at,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedToken {
            token,
            plaintext: format!("{PAT_PREFIX}{public_id}_{secret}"),
        })
    }

    /// The tokens of one owner, newest first, revoked and expired ones
    /// included.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_tokens(&self, owner_id: Uuid) -> Result<Vec<ApiToken>, StoreError> {
        Ok(sqlx::query_as(
            "select t.id, t.public_id, t.owner_id, t.name, t.scope_backends, t.scope_tools, \
                    t.created_at, t.expires_at, t.last_used_at, t.revoked_at is not null as revoked, \
                    t.toolset_id, s.name as toolset_name \
             from api_tokens t left join user_toolsets s on s.id = t.toolset_id \
             where t.owner_id = $1 order by t.created_at desc, t.id",
        )
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Revokes a token. `owner_id` restricts it to that owner's tokens; `None`
    /// is for admins. `false` when there is no such live token.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn revoke_token(
        &self,
        actor: &Actor,
        owner_id: Option<Uuid>,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let revoked: Option<(String, Uuid)> = sqlx::query_as(
            "update api_tokens set revoked_at = now() \
             where id = $1 and revoked_at is null and ($2::uuid is null or owner_id = $2) \
             returning public_id, owner_id",
        )
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((public_id, token_owner)) = revoked else {
            return Ok(false);
        };
        audit(
            &mut tx,
            actor,
            "token.revoke",
            &format!("token:{public_id}"),
            json!({ "owner_id": token_owner }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Resolves a plaintext token to its principal. `None` for anything that
    /// is not a valid PAT, and for a token that is revoked or expired, or
    /// whose owner is disabled or (for users) has not logged in for
    /// [`INACTIVE_OWNER_SUSPEND`]. `last_used_at` and the IP are updated at
    /// most once a minute.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn authenticate_token(
        &self,
        plaintext: &str,
        ip: Option<&str>,
    ) -> Result<Option<TokenPrincipal>, StoreError> {
        let Some((public_id, secret)) = parse_pat(plaintext) else {
            return Ok(None);
        };
        let row: Option<TokenAuthRow> = sqlx::query_as(
            "select t.id as token_id, t.public_id, t.name, t.scope_backends, t.scope_tools, \
                    s.id as toolset_id, s.name as toolset_name, s.tools as toolset_tools, \
                    s.backends as toolset_backends, \
                    t.created_at as token_created_at, t.expires_at, t.last_used_at, t.secret_hash, \
                    u.id as owner_id, u.issuer, u.subject, u.email, u.display_name, \
                    u.groups, u.is_admin, u.kind \
             from api_tokens t join users u on u.id = t.owner_id \
                  left join user_toolsets s on s.id = t.toolset_id \
             where t.public_id = $1 \
               and t.revoked_at is null \
               and t.expires_at > now() \
               and u.disabled_at is null \
               and (u.kind <> 'user' or u.last_login_at > now() - make_interval(secs => $2))",
        )
        .bind(public_id)
        .bind(INACTIVE_OWNER_SUSPEND.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let matches: bool = row
            .secret_hash
            .as_slice()
            .ct_eq(hash_secret(secret).as_slice())
            .into();
        if !matches {
            return Ok(None);
        }

        sqlx::query(
            "update api_tokens set last_used_at = now(), last_used_ip = $2 \
             where id = $1 and (last_used_at is null or last_used_at < now() - make_interval(secs => $3))",
        )
        .bind(row.token_id)
        .bind(ip)
        .bind(TOKEN_TOUCH_INTERVAL.as_secs_f64())
        .execute(&self.pool)
        .await?;

        Ok(Some(TokenPrincipal {
            is_service_account: row.kind == "service",
            toolset: row
                .toolset_tools
                .zip(row.toolset_backends)
                .map(|(tools, backends)| TokenScope { backends, tools }),
            token: ApiToken {
                id: row.token_id,
                public_id: row.public_id,
                owner_id: row.owner_id,
                name: row.name,
                scope_backends: row.scope_backends,
                scope_tools: row.scope_tools,
                created_at: row.token_created_at,
                expires_at: row.expires_at,
                last_used_at: row.last_used_at,
                revoked: false,
                toolset_id: row.toolset_id,
                toolset_name: row.toolset_name,
            },
            owner: User {
                id: row.owner_id,
                issuer: row.issuer,
                subject: row.subject,
                email: row.email,
                display_name: row.display_name,
                groups: row.groups,
                is_admin: row.is_admin,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration as ChronoDuration;

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

    fn cli() -> Actor {
        Actor {
            user_id: None,
            label: "cli".to_string(),
        }
    }

    async fn user(store: &Store, subject: &str) -> Uuid {
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

    fn days(count: i64) -> DateTime<Utc> {
        Utc::now() + ChronoDuration::days(count)
    }

    async fn issue(store: &Store, owner_id: Uuid, expires_at: DateTime<Utc>) -> IssuedToken {
        store
            .create_token(
                &cli(),
                &NewToken {
                    owner_id,
                    name: "laptop",
                    scope_backends: &[],
                    scope_tools: &[],
                    toolset_id: None,
                    expires_at,
                },
            )
            .await
            .unwrap()
    }

    fn new(owner_id: Uuid, name: &str, expires_at: DateTime<Utc>) -> NewToken<'_> {
        NewToken {
            owner_id,
            name,
            scope_backends: &[],
            scope_tools: &[],
            toolset_id: None,
            expires_at,
        }
    }

    async fn last_used(store: &Store, id: Uuid) -> (Option<DateTime<Utc>>, Option<String>) {
        sqlx::query_as("select last_used_at, last_used_ip from api_tokens where id = $1")
            .bind(id)
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    #[test]
    fn debug_output_redacts_the_plaintext() {
        let issued = IssuedToken {
            token: ApiToken {
                id: Uuid::nil(),
                public_id: "0123456789abcdef".to_string(),
                owner_id: Uuid::nil(),
                name: "laptop".to_string(),
                scope_backends: Vec::new(),
                scope_tools: Vec::new(),
                created_at: Utc::now(),
                expires_at: Utc::now(),
                last_used_at: None,
                revoked: false,
                toolset_id: None,
                toolset_name: None,
            },
            plaintext: "axon_pat_plaintext-secret".to_string(),
        };
        assert!(!format!("{issued:?}").contains("plaintext-secret"));
    }

    #[test]
    fn parsing_is_strict() {
        let public_id = "0123456789abcdef";
        let secret = "ab".repeat(32);
        let good = format!("axon_pat_{public_id}_{secret}");
        assert_eq!(parse_pat(&good), Some((public_id, secret.as_str())));

        assert!(parse_pat("").is_none());
        assert!(parse_pat("axon_pat_").is_none());
        assert!(parse_pat(&good.replace("axon_pat_", "axon_xxx_")).is_none());
        assert!(parse_pat(&format!("{good}0")).is_none());
        assert!(parse_pat(&good[..good.len() - 1]).is_none());
        assert!(parse_pat(&format!("axon_pat_{}_{secret}", "0123456789abcdeF")).is_none());
        assert!(parse_pat(&format!("axon_pat_{public_id}_{}", "g".repeat(64))).is_none());
        assert!(parse_pat(&format!("axon_pat_{public_id}{secret}")).is_none());
        assert!(parse_pat(&format!(" {good}")).is_none());
    }

    #[test]
    fn hashing_is_sha256() {
        assert_eq!(
            hex::encode(hash_secret("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn issued_token_authenticates_and_stores_only_the_hash() {
        let Some(store) = test_store("axon_store_tokens_round_trip").await else {
            return;
        };
        let owner = user(&store, "alice").await;
        let scope_tools = vec!["list_*".to_string()];
        let issued = store
            .create_token(
                &cli(),
                &NewToken {
                    owner_id: owner,
                    name: "laptop",
                    scope_backends: &["forgejo".to_string()],
                    scope_tools: &scope_tools,
                    toolset_id: None,
                    expires_at: days(30),
                },
            )
            .await
            .unwrap();

        let (prefix_and_id, secret) = issued.plaintext.rsplit_once('_').unwrap();
        assert_eq!(
            prefix_and_id,
            format!("{PAT_PREFIX}{}", issued.token.public_id)
        );
        assert_eq!(secret.len(), SECRET_LEN);
        assert_eq!(issued.token.public_id.len(), PUBLIC_ID_LEN);

        let stored: Vec<u8> = sqlx::query_scalar("select secret_hash from api_tokens")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, hash_secret(secret));

        let principal = store
            .authenticate_token(&issued.plaintext, Some("10.0.0.1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.token.id, issued.token.id);
        assert_eq!(principal.token.name, "laptop");
        assert_eq!(principal.token.scope_backends, vec!["forgejo".to_string()]);
        assert_eq!(principal.token.scope_tools, scope_tools);
        assert_eq!(principal.owner.id, owner);
        assert_eq!(principal.owner.subject, "alice");
        assert!(!principal.is_service_account);
    }

    #[tokio::test]
    async fn wrong_unknown_and_malformed_tokens_resolve_to_none() {
        let Some(store) = test_store("axon_store_tokens_invalid").await else {
            return;
        };
        let owner = user(&store, "alice").await;
        let issued = issue(&store, owner, days(30)).await;
        let public_id = &issued.token.public_id;

        let wrong_secret = format!("{PAT_PREFIX}{public_id}_{}", "0".repeat(SECRET_LEN));
        assert!(
            store
                .authenticate_token(&wrong_secret, None)
                .await
                .unwrap()
                .is_none()
        );
        let unknown_id = format!(
            "{PAT_PREFIX}{}_{}",
            "f".repeat(PUBLIC_ID_LEN),
            "0".repeat(SECRET_LEN)
        );
        assert!(
            store
                .authenticate_token(&unknown_id, None)
                .await
                .unwrap()
                .is_none()
        );
        for malformed in ["", "axon_pat_", "not-a-token", "axon_pat_zz_zz"] {
            assert!(
                store
                    .authenticate_token(malformed, None)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        // The real one still works after all that.
        assert!(
            store
                .authenticate_token(&issued.plaintext, None)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn revoked_and_expired_tokens_resolve_to_none() {
        let Some(store) = test_store("axon_store_tokens_dead").await else {
            return;
        };
        let owner = user(&store, "alice").await;

        let revoked = issue(&store, owner, days(30)).await;
        assert!(
            store
                .revoke_token(&cli(), Some(owner), revoked.token.id)
                .await
                .unwrap()
        );
        assert!(
            store
                .authenticate_token(&revoked.plaintext, None)
                .await
                .unwrap()
                .is_none()
        );

        let expired = issue(&store, owner, days(30)).await;
        sqlx::query("update api_tokens set expires_at = now() - interval '1 second' where id = $1")
            .bind(expired.token.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .authenticate_token(&expired.plaintext, None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_service_account_and_inactive_user_resolve_to_none() {
        let Some(store) = test_store("axon_store_tokens_suspended").await else {
            return;
        };
        let account = store
            .create_service_account(&cli(), "ci", None)
            .await
            .unwrap()
            .unwrap();
        let service_token = issue(&store, account.id, days(30)).await;
        let principal = store
            .authenticate_token(&service_token.plaintext, None)
            .await
            .unwrap()
            .unwrap();
        assert!(principal.is_service_account);
        assert_eq!(principal.owner.subject, "ci");
        assert_eq!(principal.owner.issuer, SERVICE_ISSUER);

        assert!(
            store
                .set_service_account_disabled(&cli(), account.id, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .authenticate_token(&service_token.plaintext, None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .set_service_account_disabled(&cli(), account.id, false)
                .await
                .unwrap()
        );
        assert!(
            store
                .authenticate_token(&service_token.plaintext, None)
                .await
                .unwrap()
                .is_some()
        );

        // A service account has no login, so it is never "inactive".
        let owner = user(&store, "alice").await;
        let user_token = issue(&store, owner, days(30)).await;
        assert!(
            store
                .authenticate_token(&user_token.plaintext, None)
                .await
                .unwrap()
                .is_some()
        );
        sqlx::query("update users set last_login_at = now() - interval '91 days' where id = $1")
            .bind(owner)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .authenticate_token(&user_token.plaintext, None)
                .await
                .unwrap()
                .is_none()
        );
        sqlx::query("update users set last_login_at = now() - interval '89 days' where id = $1")
            .bind(owner)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .authenticate_token(&user_token.plaintext, None)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn last_used_is_touched_at_most_once_a_minute() {
        let Some(store) = test_store("axon_store_tokens_touch").await else {
            return;
        };
        let owner = user(&store, "alice").await;
        let issued = issue(&store, owner, days(30)).await;
        assert_eq!(last_used(&store, issued.token.id).await, (None, None));

        store
            .authenticate_token(&issued.plaintext, Some("10.0.0.1"))
            .await
            .unwrap()
            .unwrap();
        let (first_at, first_ip) = last_used(&store, issued.token.id).await;
        assert!(first_at.is_some());
        assert_eq!(first_ip.as_deref(), Some("10.0.0.1"));

        // Within the interval nothing changes, not even the IP.
        store
            .authenticate_token(&issued.plaintext, Some("10.0.0.2"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            last_used(&store, issued.token.id).await,
            (first_at, first_ip)
        );

        sqlx::query(
            "update api_tokens set last_used_at = now() - interval '2 minutes' where id = $1",
        )
        .bind(issued.token.id)
        .execute(&store.pool)
        .await
        .unwrap();
        store
            .authenticate_token(&issued.plaintext, Some("10.0.0.2"))
            .await
            .unwrap()
            .unwrap();
        let (later_at, later_ip) = last_used(&store, issued.token.id).await;
        assert!(later_at.unwrap() > Utc::now() - ChronoDuration::minutes(1));
        assert_eq!(later_ip.as_deref(), Some("10.0.0.2"));
    }

    #[tokio::test]
    async fn lifetime_limits_differ_for_users_and_service_accounts() {
        let Some(store) = test_store("axon_store_tokens_lifetime").await else {
            return;
        };
        let owner = user(&store, "alice").await;
        let account = store
            .create_service_account(&cli(), "ci", None)
            .await
            .unwrap()
            .unwrap();

        issue(&store, owner, days(89)).await;
        issue(&store, account.id, days(364)).await;
        let err = store
            .create_token(&cli(), &new(owner, "long", days(91)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::ExpiryTooLong(90)));
        let err = store
            .create_token(&cli(), &new(account.id, "long", days(366)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::ExpiryTooLong(365)));
        // Beyond the user maximum but fine for a service account.
        issue(&store, account.id, days(200)).await;

        let err = store
            .create_token(&cli(), &new(owner, "past", days(-1)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::ExpiryInPast));
        let err = store
            .create_token(&cli(), &new(owner, "", days(1)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidName));
        let err = store
            .create_token(&cli(), &new(owner, "   ", days(1)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidName));
        let too_long = "n".repeat(101);
        let err = store
            .create_token(&cli(), &new(owner, &too_long, days(1)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidName));
        issue(&store, owner, days(1)).await;
        let longest = "n".repeat(100);
        store
            .create_token(&cli(), &new(owner, &longest, days(1)))
            .await
            .unwrap();
        let err = store
            .create_token(&cli(), &new(Uuid::new_v4(), "ghost", days(1)))
            .await
            .unwrap_err();
        assert!(matches!(err, TokenError::UnknownOwner));
    }

    #[tokio::test]
    async fn tokens_list_newest_first_and_revoke_checks_the_owner() {
        let Some(store) = test_store("axon_store_tokens_list").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let bob = user(&store, "bob").await;
        let first = issue(&store, alice, days(30)).await;
        let second = issue(&store, alice, days(30)).await;
        let other = issue(&store, bob, days(30)).await;

        let listed = store.list_tokens(alice).await.unwrap();
        assert_eq!(
            listed.iter().map(|t| t.id).collect::<Vec<_>>(),
            vec![second.token.id, first.token.id]
        );
        assert!(listed.iter().all(|t| !t.revoked));

        // Bob cannot revoke Alice's token; an admin (no owner) can.
        assert!(
            !store
                .revoke_token(&cli(), Some(bob), first.token.id)
                .await
                .unwrap()
        );
        assert!(
            store
                .revoke_token(&cli(), None, first.token.id)
                .await
                .unwrap()
        );
        // Already revoked, or unknown, is a no-op.
        assert!(
            !store
                .revoke_token(&cli(), None, first.token.id)
                .await
                .unwrap()
        );
        assert!(
            !store
                .revoke_token(&cli(), None, Uuid::new_v4())
                .await
                .unwrap()
        );
        assert!(
            store
                .revoke_token(&cli(), Some(bob), other.token.id)
                .await
                .unwrap()
        );

        let listed = store.list_tokens(alice).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(!listed[0].revoked);
        assert!(listed[1].revoked);
    }

    #[tokio::test]
    async fn service_accounts_create_reject_duplicates_disable_and_delete() {
        let Some(store) = test_store("axon_store_tokens_accounts").await else {
            return;
        };
        let ci = store
            .create_service_account(&cli(), "ci", Some("Builds"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ci.name, "ci");
        assert_eq!(ci.description.as_deref(), Some("Builds"));
        assert!(!ci.disabled);
        assert!(
            store
                .create_service_account(&cli(), "ci", None)
                .await
                .unwrap()
                .is_none()
        );
        let bot = store
            .create_service_account(&cli(), "bot", None)
            .await
            .unwrap()
            .unwrap();

        let listed = store.list_service_accounts().await.unwrap();
        assert_eq!(
            listed.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["bot", "ci"]
        );
        assert_eq!(
            store.service_account(ci.id).await.unwrap(),
            Some(ci.clone())
        );
        assert!(
            store
                .service_account(Uuid::new_v4())
                .await
                .unwrap()
                .is_none()
        );
        // A human user is not a service account.
        let alice = user(&store, "alice").await;
        assert!(store.service_account(alice).await.unwrap().is_none());
        assert!(
            !store
                .set_service_account_disabled(&cli(), alice, true)
                .await
                .unwrap()
        );
        assert!(!store.delete_service_account(&cli(), alice).await.unwrap());

        assert!(
            store
                .set_service_account_disabled(&cli(), ci.id, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .service_account(ci.id)
                .await
                .unwrap()
                .unwrap()
                .disabled
        );
        // Already disabled: nothing changes.
        assert!(
            !store
                .set_service_account_disabled(&cli(), ci.id, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .set_service_account_disabled(&cli(), ci.id, false)
                .await
                .unwrap()
        );

        let issued = issue(&store, bot.id, days(30)).await;
        assert!(store.delete_service_account(&cli(), bot.id).await.unwrap());
        assert!(!store.delete_service_account(&cli(), bot.id).await.unwrap());
        assert!(store.service_account(bot.id).await.unwrap().is_none());
        assert!(
            store
                .authenticate_token(&issued.plaintext, None)
                .await
                .unwrap()
                .is_none()
        );
        let tokens: i64 = sqlx::query_scalar("select count(*) from api_tokens")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(tokens, 0);
    }

    #[tokio::test]
    async fn changes_are_audited_without_the_secret() {
        let Some(store) = test_store("axon_store_tokens_audit").await else {
            return;
        };
        let account = store
            .create_service_account(&cli(), "ci", None)
            .await
            .unwrap()
            .unwrap();
        // A duplicate and a no-op write no audit row.
        store
            .create_service_account(&cli(), "ci", None)
            .await
            .unwrap();
        store
            .set_service_account_disabled(&cli(), account.id, false)
            .await
            .unwrap();

        let issued = issue(&store, account.id, days(30)).await;
        let secret = issued.plaintext.rsplit_once('_').unwrap().1.to_string();
        store
            .revoke_token(&cli(), None, issued.token.id)
            .await
            .unwrap();
        store
            .set_service_account_disabled(&cli(), account.id, true)
            .await
            .unwrap();
        store
            .set_service_account_disabled(&cli(), account.id, false)
            .await
            .unwrap();
        store
            .delete_service_account(&cli(), account.id)
            .await
            .unwrap();

        let rows: Vec<(String, String, String)> =
            sqlx::query_as("select action, target, details::text from audit_log order by id")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        let token_target = format!("token:{}", issued.token.public_id);
        let summary: Vec<(&str, &str)> = rows
            .iter()
            .map(|(action, target, _)| (action.as_str(), target.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                ("service_account.create", "service_account:ci"),
                ("token.create", token_target.as_str()),
                ("token.revoke", token_target.as_str()),
                ("service_account.disable", "service_account:ci"),
                ("service_account.enable", "service_account:ci"),
                ("service_account.delete", "service_account:ci"),
            ]
        );
        for (action, target, details) in &rows {
            assert!(!action.contains(&secret));
            assert!(!target.contains(&secret));
            assert!(!details.contains(&secret));
            assert!(!details.contains(&issued.plaintext));
        }
    }

    #[tokio::test]
    async fn list_users_excludes_service_accounts() {
        let Some(store) = test_store("axon_store_tokens_list_users").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        store
            .create_service_account(&cli(), "ci", None)
            .await
            .unwrap()
            .unwrap();

        let users = store.list_users(10).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, alice);
    }
}
