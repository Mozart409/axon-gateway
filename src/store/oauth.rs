//! The MCP OAuth authorization server: clients, pending requests, codes, grants and tokens
//!
//! A *grant* is one user's consent for one client; it is what the "Connected apps" page
//! lists and what revocation ends. Access and refresh tokens hang off a grant, so
//! revoking the grant (or detecting a replayed code or refresh token) kills them all.
//! Only the SHA-256 of a code or a token secret is stored; a token's public id is what
//! the lookup uses and the hash is compared in constant time, as for personal access
//! tokens.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use serde_json::json;
use sqlx::FromRow;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::auth::User;
use super::rbac::{Actor, audit};
use super::tokens::{
    INACTIVE_OWNER_SUSPEND, PUBLIC_ID_LEN, SECRET_LEN, TOKEN_TOUCH_INTERVAL, hash_secret,
    is_lower_hex, random_hex,
};
use super::{Store, StoreError};

/// Prefix of an access token
pub const OAUTH_ACCESS_PREFIX: &str = "axon_oat_";
/// Prefix of a refresh token
pub const OAUTH_REFRESH_PREFIX: &str = "axon_ort_";
/// Prefix of a client id issued by dynamic registration
pub const OAUTH_CLIENT_PREFIX: &str = "axon_client_";
/// How long an access token lives
pub const ACCESS_TOKEN_TTL: Duration = Duration::from_hours(1);
/// How long a refresh token lives
pub const REFRESH_TOKEN_TTL: Duration = Duration::from_hours(30 * 24);
/// How long an authorization code may wait to be redeemed
pub const CODE_TTL: Duration = Duration::from_secs(60);
/// How long a validated authorization request may wait for the login and consent
pub const REQUEST_TTL: Duration = Duration::from_mins(10);
/// A registered client nobody used for this long is deleted
pub const CLIENT_IDLE_EXPIRY: Duration = Duration::from_hours(30 * 24);
/// Revoked and dead grants are kept this long, then deleted
const GRANT_RETENTION: Duration = Duration::from_hours(30 * 24);

/// A client registered by dynamic client registration
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct OauthClient {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// The validated metadata of a client to register
pub struct NewOauthClient<'a> {
    pub client_name: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub grant_types: &'a [String],
    pub response_types: &'a [String],
}

/// An authorization request that passed validation and waits for the user
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AuthRequest {
    pub id: String,
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub scope: String,
    pub resource: String,
}

/// What an authorization request is stored with
pub struct NewAuthRequest<'a> {
    pub client_id: &'a str,
    pub client_name: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub state: Option<&'a str>,
    pub scope: &'a str,
    pub resource: &'a str,
}

/// What an authorization code is bound to
pub struct NewCode<'a> {
    pub client_id: &'a str,
    pub client_name: Option<&'a str>,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub user_id: Uuid,
    pub scope: &'a str,
    pub resource: &'a str,
}

/// What the token endpoint received with an authorization code
pub struct CodeRedemption<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: &'a str,
    /// The `resource` parameter when the client sent one; it must be the code's
    pub resource: Option<&'a str>,
}

/// A new access and refresh token; the plaintexts exist only here
pub struct IssuedOauthTokens {
    pub grant_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub scope: String,
}

impl fmt::Debug for IssuedOauthTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedOauthTokens")
            .field("grant_id", &self.grant_id)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .finish()
    }
}

/// A live grant, for the "Connected apps" pages
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct OauthGrant {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: Option<String>,
    pub user_id: Uuid,
    pub user_email: Option<String>,
    pub scope: String,
    pub resource: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Who an access token authenticates
#[derive(Debug, Clone)]
pub struct OauthPrincipal {
    pub grant_id: Uuid,
    pub client_id: String,
    pub client_name: Option<String>,
    pub resource: String,
    pub owner: User,
}

/// What looking up an access token found
#[derive(Debug)]
pub enum AccessLookup {
    Valid(Box<OauthPrincipal>),
    /// A genuine token past its expiry
    Expired,
    /// Unknown, malformed, wrong secret, revoked grant or an owner who may not sign in
    Invalid,
}

#[derive(FromRow)]
struct CodeRow {
    client_id: String,
    client_name: Option<String>,
    redirect_uri: String,
    code_challenge: String,
    user_id: Uuid,
    scope: String,
    resource: String,
    grant_id: Option<Uuid>,
    live: bool,
    user_active: bool,
}

#[allow(clippy::struct_excessive_bools)] // a query row: each flag is one SQL predicate
#[derive(FromRow)]
struct RefreshRow {
    id: Uuid,
    secret_hash: Vec<u8>,
    live: bool,
    used: bool,
    grant_id: Uuid,
    client_id: String,
    scope: String,
    revoked: bool,
    user_active: bool,
}

#[derive(FromRow)]
struct AccessRow {
    secret_hash: Vec<u8>,
    expired: bool,
    grant_id: Uuid,
    client_id: String,
    client_name: Option<String>,
    resource: String,
    owner_id: Uuid,
    issuer: String,
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    groups: Vec<String>,
    is_admin: bool,
}

/// The public id and secret of a well-formed token with `prefix`, or `None`
fn parse_token<'a>(plaintext: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = plaintext.strip_prefix(prefix)?;
    let (public_id, secret) = rest.split_once('_')?;
    (public_id.len() == PUBLIC_ID_LEN
        && secret.len() == SECRET_LEN
        && is_lower_hex(public_id)
        && is_lower_hex(secret))
    .then_some((public_id, secret))
}

/// Whether `verifier` is a valid RFC 7636 code verifier whose S256 transform is `challenge`
#[must_use]
pub fn pkce_matches(challenge: &str, verifier: &str) -> bool {
    let valid = (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if !valid {
        return false;
    }
    let computed =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.to_owned()));
    computed
        .as_str()
        .as_bytes()
        .ct_eq(challenge.as_bytes())
        .into()
}

/// Inserts one token of `kind` under `grant_id` and returns its plaintext
async fn insert_token(
    conn: &mut sqlx::PgConnection,
    grant_id: Uuid,
    kind: &str,
    prefix: &str,
    ttl: Duration,
) -> Result<String, StoreError> {
    let public_id = random_hex::<8>()?;
    let secret = random_hex::<32>()?;
    sqlx::query(
        "insert into oauth_tokens (grant_id, kind, public_id, secret_hash, expires_at) \
         values ($1, $2, $3, $4, now() + make_interval(secs => $5))",
    )
    .bind(grant_id)
    .bind(kind)
    .bind(&public_id)
    .bind(hash_secret(&secret))
    .bind(ttl.as_secs_f64())
    .execute(conn)
    .await?;
    Ok(format!("{prefix}{public_id}_{secret}"))
}

/// An access and a refresh token for the grant
async fn issue_pair(
    conn: &mut sqlx::PgConnection,
    grant_id: Uuid,
    scope: String,
) -> Result<IssuedOauthTokens, StoreError> {
    let access_token = insert_token(
        conn,
        grant_id,
        "access",
        OAUTH_ACCESS_PREFIX,
        ACCESS_TOKEN_TTL,
    )
    .await?;
    let refresh_token = insert_token(
        conn,
        grant_id,
        "refresh",
        OAUTH_REFRESH_PREFIX,
        REFRESH_TOKEN_TTL,
    )
    .await?;
    Ok(IssuedOauthTokens {
        grant_id,
        access_token,
        refresh_token,
        scope,
    })
}

async fn revoke_grant_in(conn: &mut sqlx::PgConnection, grant_id: Uuid) -> Result<(), StoreError> {
    sqlx::query("update oauth_grants set revoked_at = now() where id = $1 and revoked_at is null")
        .bind(grant_id)
        .execute(conn)
        .await?;
    Ok(())
}

impl Store {
    /// Registers a client and returns it with its new `client_id`.
    ///
    /// # Errors
    /// Fails when the randomness or the query fails.
    pub async fn create_oauth_client(
        &self,
        client: &NewOauthClient<'_>,
    ) -> Result<OauthClient, StoreError> {
        let client_id = format!("{OAUTH_CLIENT_PREFIX}{}", random_hex::<16>()?);
        let row = sqlx::query_as(
            "insert into oauth_clients \
                 (client_id, client_name, redirect_uris, grant_types, response_types) \
             values ($1, $2, $3, $4, $5) \
             returning client_id, client_name, redirect_uris, grant_types, response_types, created_at",
        )
        .bind(client_id)
        .bind(client.client_name)
        .bind(client.redirect_uris)
        .bind(client.grant_types)
        .bind(client.response_types)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// A registered client, or `None`.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn oauth_client(&self, client_id: &str) -> Result<Option<OauthClient>, StoreError> {
        Ok(sqlx::query_as(
            "select client_id, client_name, redirect_uris, grant_types, response_types, created_at \
             from oauth_clients where client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Notes that the client was used, at most once an hour. Nothing happens for a
    /// client without a row (a metadata document client).
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn touch_oauth_client(&self, client_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "update oauth_clients set last_used_at = now() \
             where client_id = $1 \
               and (last_used_at is null or last_used_at < now() - interval '1 hour')",
        )
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Stores a validated authorization request and returns its id.
    ///
    /// # Errors
    /// Fails when the randomness or the query fails.
    pub async fn create_auth_request(
        &self,
        request: &NewAuthRequest<'_>,
    ) -> Result<String, StoreError> {
        let id = random_hex::<16>()?;
        sqlx::query(
            "insert into oauth_requests \
                 (id, client_id, client_name, redirect_uri, code_challenge, state, scope, \
                  resource, expires_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
        )
        .bind(&id)
        .bind(request.client_id)
        .bind(request.client_name)
        .bind(request.redirect_uri)
        .bind(request.code_challenge)
        .bind(request.state)
        .bind(request.scope)
        .bind(request.resource)
        .bind(REQUEST_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// A pending authorization request, or `None` when unknown, used or expired.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn auth_request(&self, id: &str) -> Result<Option<AuthRequest>, StoreError> {
        Ok(sqlx::query_as(
            "select id, client_id, client_name, redirect_uri, code_challenge, state, scope, resource \
             from oauth_requests where id = $1 and expires_at > now()",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Takes a pending authorization request: it can be decided once.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn take_auth_request(&self, id: &str) -> Result<Option<AuthRequest>, StoreError> {
        Ok(sqlx::query_as(
            "delete from oauth_requests where id = $1 and expires_at > now() \
             returning id, client_id, client_name, redirect_uri, code_challenge, state, scope, resource",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Issues an authorization code and returns its plaintext (32 random bytes, hex).
    ///
    /// # Errors
    /// Fails when the randomness or the query fails.
    pub async fn create_oauth_code(&self, code: &NewCode<'_>) -> Result<String, StoreError> {
        let plaintext = random_hex::<32>()?;
        sqlx::query(
            "insert into oauth_codes \
                 (code_hash, client_id, client_name, redirect_uri, code_challenge, user_id, \
                  scope, resource, expires_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))",
        )
        .bind(hash_secret(&plaintext))
        .bind(code.client_id)
        .bind(code.client_name)
        .bind(code.redirect_uri)
        .bind(code.code_challenge)
        .bind(code.user_id)
        .bind(code.scope)
        .bind(code.resource)
        .bind(CODE_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(plaintext)
    }

    /// Redeems an authorization code: checks what it is bound to, consumes it, creates the
    /// grant and issues the first tokens. `None` is `invalid_grant`: an unknown, expired,
    /// mismatched or already used code. A code used twice revokes the grant made from it.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn redeem_oauth_code(
        &self,
        redemption: &CodeRedemption<'_>,
    ) -> Result<Option<IssuedOauthTokens>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<CodeRow> = sqlx::query_as(
            "select c.client_id, c.client_name, c.redirect_uri, c.code_challenge, c.user_id, \
                    c.scope, c.resource, c.grant_id, c.expires_at > now() as live, \
                    (u.disabled_at is null and u.kind = 'user') as user_active \
             from oauth_codes c join users u on u.id = c.user_id \
             where c.code_hash = $1 for update of c",
        )
        .bind(hash_secret(redemption.code))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        if let Some(grant_id) = row.grant_id {
            revoke_grant_in(&mut tx, grant_id).await?;
            tx.commit().await?;
            return Ok(None);
        }
        let bound = row.live
            && row.user_active
            && row.client_id == redemption.client_id
            && row.redirect_uri == redemption.redirect_uri
            && redemption
                .resource
                .is_none_or(|resource| resource == row.resource)
            && pkce_matches(&row.code_challenge, redemption.code_verifier);
        if !bound {
            return Ok(None);
        }

        let grant_id = Uuid::new_v4();
        sqlx::query(
            "insert into oauth_grants (id, client_id, client_name, user_id, scope, resource) \
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(grant_id)
        .bind(&row.client_id)
        .bind(&row.client_name)
        .bind(row.user_id)
        .bind(&row.scope)
        .bind(&row.resource)
        .execute(&mut *tx)
        .await?;
        sqlx::query("update oauth_codes set grant_id = $2 where code_hash = $1")
            .bind(hash_secret(redemption.code))
            .bind(grant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update oauth_clients set last_used_at = now() where client_id = $1")
            .bind(&row.client_id)
            .execute(&mut *tx)
            .await?;
        let issued = issue_pair(&mut tx, grant_id, row.scope).await?;
        tx.commit().await?;
        Ok(Some(issued))
    }

    /// Exchanges a refresh token for a new pair; the old refresh token is spent. `None` is
    /// `invalid_grant`. Presenting a refresh token that was already spent revokes the grant.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn refresh_oauth_token(
        &self,
        refresh_token: &str,
        client_id: &str,
    ) -> Result<Option<IssuedOauthTokens>, StoreError> {
        let Some((public_id, secret)) = parse_token(refresh_token, OAUTH_REFRESH_PREFIX) else {
            return Ok(None);
        };
        let mut tx = self.pool.begin().await?;
        let row: Option<RefreshRow> = sqlx::query_as(
            "select t.id, t.secret_hash, t.expires_at > now() as live, \
                    t.used_at is not null as used, \
                    g.id as grant_id, g.client_id, g.scope, g.revoked_at is not null as revoked, \
                    (u.disabled_at is null and u.kind = 'user') as user_active \
             from oauth_tokens t \
                  join oauth_grants g on g.id = t.grant_id \
                  join users u on u.id = g.user_id \
             where t.public_id = $1 and t.kind = 'refresh' for update of t",
        )
        .bind(public_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let secret_ok: bool = row
            .secret_hash
            .as_slice()
            .ct_eq(hash_secret(secret).as_slice())
            .into();
        if !secret_ok || row.revoked || row.client_id != client_id {
            return Ok(None);
        }
        if row.used {
            revoke_grant_in(&mut tx, row.grant_id).await?;
            tx.commit().await?;
            return Ok(None);
        }
        if !row.live || !row.user_active {
            return Ok(None);
        }

        sqlx::query("update oauth_tokens set used_at = now() where id = $1")
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update oauth_grants set last_used_at = now() where id = $1")
            .bind(row.grant_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("update oauth_clients set last_used_at = now() where client_id = $1")
            .bind(&row.client_id)
            .execute(&mut *tx)
            .await?;
        let issued = issue_pair(&mut tx, row.grant_id, row.scope).await?;
        tx.commit().await?;
        Ok(Some(issued))
    }

    /// Revokes the grant an access or refresh token belongs to (RFC 7009). A token that is
    /// unknown, malformed or has the wrong secret does nothing.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn revoke_oauth_token(&self, plaintext: &str) -> Result<(), StoreError> {
        let Some((public_id, secret)) = parse_token(plaintext, OAUTH_ACCESS_PREFIX)
            .or_else(|| parse_token(plaintext, OAUTH_REFRESH_PREFIX))
        else {
            return Ok(());
        };
        let row: Option<(Uuid, Vec<u8>)> =
            sqlx::query_as("select grant_id, secret_hash from oauth_tokens where public_id = $1")
                .bind(public_id)
                .fetch_optional(&self.pool)
                .await?;
        let Some((grant_id, secret_hash)) = row else {
            return Ok(());
        };
        let secret_ok: bool = secret_hash
            .as_slice()
            .ct_eq(hash_secret(secret).as_slice())
            .into();
        if secret_ok {
            let mut conn = self.pool.acquire().await?;
            revoke_grant_in(&mut conn, grant_id).await?;
        }
        Ok(())
    }

    /// Resolves an access token. `last_used_at` of the grant is updated at most once a
    /// minute.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn authenticate_oauth_access(
        &self,
        plaintext: &str,
    ) -> Result<AccessLookup, StoreError> {
        let Some((public_id, secret)) = parse_token(plaintext, OAUTH_ACCESS_PREFIX) else {
            return Ok(AccessLookup::Invalid);
        };
        let row: Option<AccessRow> = sqlx::query_as(
            "select t.secret_hash, t.expires_at <= now() as expired, \
                    g.id as grant_id, g.client_id, g.client_name, g.resource, \
                    u.id as owner_id, u.issuer, u.subject, u.email, u.display_name, \
                    u.groups, u.is_admin \
             from oauth_tokens t \
                  join oauth_grants g on g.id = t.grant_id \
                  join users u on u.id = g.user_id \
             where t.public_id = $1 and t.kind = 'access' \
               and g.revoked_at is null \
               and u.disabled_at is null and u.kind = 'user' \
               and u.last_login_at > now() - make_interval(secs => $2)",
        )
        .bind(public_id)
        .bind(INACTIVE_OWNER_SUSPEND.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(AccessLookup::Invalid);
        };
        let secret_ok: bool = row
            .secret_hash
            .as_slice()
            .ct_eq(hash_secret(secret).as_slice())
            .into();
        if !secret_ok {
            return Ok(AccessLookup::Invalid);
        }
        if row.expired {
            return Ok(AccessLookup::Expired);
        }

        sqlx::query(
            "update oauth_grants set last_used_at = now() \
             where id = $1 \
               and (last_used_at is null or last_used_at < now() - make_interval(secs => $2))",
        )
        .bind(row.grant_id)
        .bind(TOKEN_TOUCH_INTERVAL.as_secs_f64())
        .execute(&self.pool)
        .await?;

        Ok(AccessLookup::Valid(Box::new(OauthPrincipal {
            grant_id: row.grant_id,
            client_id: row.client_id,
            client_name: row.client_name,
            resource: row.resource,
            owner: User {
                id: row.owner_id,
                issuer: row.issuer,
                subject: row.subject,
                email: row.email,
                display_name: row.display_name,
                groups: row.groups,
                is_admin: row.is_admin,
            },
        })))
    }

    /// The live grants of `user_id`, or of everyone with `None`, newest first. A grant is live
    /// while it is not revoked and holds a refresh token that is unspent and unexpired.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_oauth_grants(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<Vec<OauthGrant>, StoreError> {
        Ok(sqlx::query_as(
            "select g.id, g.client_id, g.client_name, g.user_id, u.email as user_email, \
                    g.scope, g.resource, g.created_at, g.last_used_at \
             from oauth_grants g join users u on u.id = g.user_id \
             where g.revoked_at is null \
               and ($1::uuid is null or g.user_id = $1) \
               and exists (select 1 from oauth_tokens t \
                           where t.grant_id = g.id and t.kind = 'refresh' \
                             and t.used_at is null and t.expires_at > now()) \
             order by g.created_at desc, g.id",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Revokes a grant of `owner` (a user revoking their own), audited as that user.
    /// `false` when there is no such live grant.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn revoke_oauth_grant(
        &self,
        id: Uuid,
        owner: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let actor = match owner {
            Some(owner) => {
                let label: Option<String> = sqlx::query_scalar(
                    "select coalesce(nullif(btrim(email), ''), subject) from users where id = $1",
                )
                .bind(owner)
                .fetch_optional(&self.pool)
                .await?;
                Actor {
                    user_id: Some(owner),
                    label: label.unwrap_or_else(|| owner.to_string()),
                }
            }
            None => Actor {
                user_id: None,
                label: "system".to_owned(),
            },
        };
        self.revoke_grant_as(&actor, id, owner).await
    }

    /// Revokes anyone's grant on behalf of the admin `actor`. `false` when there is no such
    /// live grant.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn admin_revoke_oauth_grant(
        &self,
        actor: &Actor,
        id: Uuid,
    ) -> Result<bool, StoreError> {
        self.revoke_grant_as(actor, id, None).await
    }

    /// Revokes a grant, only one of `owner` when given, with its audit row
    async fn revoke_grant_as(
        &self,
        actor: &Actor,
        id: Uuid,
        owner: Option<Uuid>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let revoked: Option<(Uuid, String)> = sqlx::query_as(
            "update oauth_grants set revoked_at = now() \
             where id = $1 and revoked_at is null and ($2::uuid is null or user_id = $2) \
             returning user_id, client_id",
        )
        .bind(id)
        .bind(owner)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((user_id, client_id)) = revoked else {
            return Ok(false);
        };
        audit(
            &mut tx,
            actor,
            "oauth_grant.revoke",
            &format!("oauth_grant:{id}"),
            json!({ "user_id": user_id, "client_id": client_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes what can no longer matter: expired requests, codes and tokens, grants revoked
    /// or unused for 30 days, and registered clients unused for 30 days. Returns the number
    /// of rows deleted.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn purge_oauth(&self) -> Result<u64, StoreError> {
        let mut purged = 0;
        for (sql, seconds) in [
            ("delete from oauth_requests where expires_at < now()", None),
            ("delete from oauth_codes where expires_at < now()", None),
            ("delete from oauth_tokens where expires_at < now()", None),
            (
                "delete from oauth_grants g \
                 where g.revoked_at < now() - make_interval(secs => $1) \
                    or (coalesce(g.last_used_at, g.created_at) < now() - make_interval(secs => $1) \
                        and not exists (select 1 from oauth_tokens t \
                                        where t.grant_id = g.id and t.kind = 'refresh' \
                                          and t.expires_at > now()))",
                Some(GRANT_RETENTION.as_secs_f64()),
            ),
            (
                "delete from oauth_clients \
                 where coalesce(last_used_at, created_at) < now() - make_interval(secs => $1)",
                Some(CLIENT_IDLE_EXPIRY.as_secs_f64()),
            ),
        ] {
            let mut query = sqlx::query(sql);
            if let Some(seconds) = seconds {
                query = query.bind(seconds);
            }
            purged += query.execute(&self.pool).await?.rows_affected();
        }
        Ok(purged)
    }
}

#[cfg(test)]
mod tests {
    use super::super::auth::LoginUser;
    use super::super::test_support::{database_url, isolated_url};
    use super::*;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const REDIRECT: &str = "http://127.0.0.1:4000/callback";
    const RESOURCE: &str = "https://gw.example/mcp";

    /// A connected store on its own schema, or `None` without a test database.
    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
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

    async fn new_code(store: &Store, user_id: Uuid) -> String {
        store
            .create_oauth_code(&NewCode {
                client_id: "axon_client_x",
                client_name: Some("Example"),
                redirect_uri: REDIRECT,
                code_challenge: CHALLENGE,
                user_id,
                scope: "mcp",
                resource: RESOURCE,
            })
            .await
            .unwrap()
    }

    fn redemption<'a>(code: &'a str, verifier: &'a str) -> CodeRedemption<'a> {
        CodeRedemption {
            code,
            client_id: "axon_client_x",
            redirect_uri: REDIRECT,
            code_verifier: verifier,
            resource: None,
        }
    }

    async fn issue(store: &Store, user_id: Uuid) -> IssuedOauthTokens {
        let code = new_code(store, user_id).await;
        store
            .redeem_oauth_code(&redemption(&code, VERIFIER))
            .await
            .unwrap()
            .expect("the code redeems")
    }

    #[test]
    fn pkce_checks_the_s256_transform() {
        assert!(pkce_matches(CHALLENGE, VERIFIER));
        assert!(!pkce_matches(CHALLENGE, "short"));
        assert!(!pkce_matches(
            CHALLENGE,
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"
        ));
        assert!(!pkce_matches(VERIFIER, VERIFIER));
    }

    #[test]
    fn token_parsing_is_strict() {
        let id = "0123456789abcdef";
        let secret = "a".repeat(64);
        let good = format!("{OAUTH_ACCESS_PREFIX}{id}_{secret}");
        assert_eq!(
            parse_token(&good, OAUTH_ACCESS_PREFIX),
            Some((id, secret.as_str()))
        );
        assert_eq!(parse_token(&good, OAUTH_REFRESH_PREFIX), None);
        let upper = format!("{OAUTH_ACCESS_PREFIX}{id}_{}", "A".repeat(64));
        assert_eq!(parse_token(&upper, OAUTH_ACCESS_PREFIX), None);
    }

    #[tokio::test]
    async fn a_code_is_single_use_and_replaying_it_revokes_the_grant() {
        let Some(store) = test_store("oauth_code_single_use").await else {
            return;
        };
        let user_id = user(&store, "alice").await;
        let code = new_code(&store, user_id).await;

        let issued = store
            .redeem_oauth_code(&redemption(&code, VERIFIER))
            .await
            .unwrap()
            .expect("the first redemption works");
        assert!(issued.access_token.starts_with(OAUTH_ACCESS_PREFIX));
        assert!(issued.refresh_token.starts_with(OAUTH_REFRESH_PREFIX));
        let lookup = store
            .authenticate_oauth_access(&issued.access_token)
            .await
            .unwrap();
        assert!(matches!(lookup, AccessLookup::Valid(_)));

        let replay = store
            .redeem_oauth_code(&redemption(&code, VERIFIER))
            .await
            .unwrap();
        assert!(replay.is_none());
        let lookup = store
            .authenticate_oauth_access(&issued.access_token)
            .await
            .unwrap();
        assert!(matches!(lookup, AccessLookup::Invalid));
        let grants = store.list_oauth_grants(Some(user_id)).await.unwrap();
        assert_eq!(grants.len(), 0);
    }

    #[tokio::test]
    async fn a_code_is_bound_to_its_request() {
        let Some(store) = test_store("oauth_code_binding").await else {
            return;
        };
        let user_id = user(&store, "alice").await;
        let code = new_code(&store, user_id).await;

        let wrong_verifier = "x".repeat(43);
        let wrong = redemption(&code, &wrong_verifier);
        assert!(store.redeem_oauth_code(&wrong).await.unwrap().is_none());
        let mut other_redirect = redemption(&code, VERIFIER);
        other_redirect.redirect_uri = "http://127.0.0.1:4001/callback";
        assert!(
            store
                .redeem_oauth_code(&other_redirect)
                .await
                .unwrap()
                .is_none()
        );
        let mut other_resource = redemption(&code, VERIFIER);
        other_resource.resource = Some("https://gw.example/mcp/toolset/x");
        assert!(
            store
                .redeem_oauth_code(&other_resource)
                .await
                .unwrap()
                .is_none()
        );
        let mut other_client = redemption(&code, VERIFIER);
        other_client.client_id = "axon_client_y";
        assert!(
            store
                .redeem_oauth_code(&other_client)
                .await
                .unwrap()
                .is_none()
        );

        // The failed attempts did not spend the code
        let right = redemption(&code, VERIFIER);
        assert!(store.redeem_oauth_code(&right).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn refresh_rotates_and_a_spent_token_revokes_the_grant() {
        let Some(store) = test_store("oauth_refresh_rotation").await else {
            return;
        };
        let user_id = user(&store, "alice").await;
        let first = issue(&store, user_id).await;

        let other = store
            .refresh_oauth_token(&first.refresh_token, "axon_client_other")
            .await
            .unwrap();
        assert!(other.is_none(), "another client cannot use the token");
        let second = store
            .refresh_oauth_token(&first.refresh_token, "axon_client_x")
            .await
            .unwrap()
            .expect("the first refresh works");
        assert_ne!(second.refresh_token, first.refresh_token);
        assert_eq!(second.grant_id, first.grant_id);
        let grants = store.list_oauth_grants(Some(user_id)).await.unwrap();
        assert_eq!(grants.len(), 1);

        // The spent token is replayed: the whole grant dies, the new tokens with it
        let replay = store
            .refresh_oauth_token(&first.refresh_token, "axon_client_x")
            .await
            .unwrap();
        assert!(replay.is_none());
        let newer = store
            .refresh_oauth_token(&second.refresh_token, "axon_client_x")
            .await
            .unwrap();
        assert!(newer.is_none());
        let lookup = store
            .authenticate_oauth_access(&second.access_token)
            .await
            .unwrap();
        assert!(matches!(lookup, AccessLookup::Invalid));
        let grants = store.list_oauth_grants(Some(user_id)).await.unwrap();
        assert_eq!(grants.len(), 0);
    }

    #[tokio::test]
    async fn expired_tokens_codes_and_requests_are_refused_and_purged() {
        let Some(store) = test_store("oauth_expiry").await else {
            return;
        };
        let user_id = user(&store, "alice").await;
        let issued = issue(&store, user_id).await;

        sqlx::query(
            "update oauth_tokens set expires_at = now() - interval '1 minute' \
             where kind = 'access'",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let lookup = store
            .authenticate_oauth_access(&issued.access_token)
            .await
            .unwrap();
        assert!(matches!(lookup, AccessLookup::Expired));

        let stale = new_code(&store, user_id).await;
        sqlx::query(
            "update oauth_codes set expires_at = now() - interval '1 second' \
             where grant_id is null",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let redeemed = store
            .redeem_oauth_code(&redemption(&stale, VERIFIER))
            .await
            .unwrap();
        assert!(redeemed.is_none());

        let request = store
            .create_auth_request(&NewAuthRequest {
                client_id: "axon_client_x",
                client_name: None,
                redirect_uri: REDIRECT,
                code_challenge: CHALLENGE,
                state: Some("s"),
                scope: "mcp",
                resource: RESOURCE,
            })
            .await
            .unwrap();
        assert!(store.auth_request(&request).await.unwrap().is_some());
        sqlx::query("update oauth_requests set expires_at = now() - interval '1 second'")
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(store.auth_request(&request).await.unwrap().is_none());
        assert!(store.take_auth_request(&request).await.unwrap().is_none());

        // The access token, the stale code and the request go; the grant stays
        assert_eq!(store.purge_oauth().await.unwrap(), 3);
        let grants = store.list_oauth_grants(Some(user_id)).await.unwrap();
        assert_eq!(grants.len(), 1);
    }

    #[tokio::test]
    async fn unused_clients_are_deleted_and_used_ones_kept() {
        let Some(store) = test_store("oauth_client_cleanup").await else {
            return;
        };
        let uris = vec![String::from(REDIRECT)];
        let grant_types = vec![String::from("authorization_code")];
        let response_types = vec![String::from("code")];
        let new = |name| NewOauthClient {
            client_name: Some(name),
            redirect_uris: &uris,
            grant_types: &grant_types,
            response_types: &response_types,
        };
        let idle = store.create_oauth_client(&new("idle")).await.unwrap();
        let used = store.create_oauth_client(&new("used")).await.unwrap();
        let fresh = store.create_oauth_client(&new("fresh")).await.unwrap();
        assert!(idle.client_id.starts_with(OAUTH_CLIENT_PREFIX));
        assert_eq!(idle.client_id.len(), OAUTH_CLIENT_PREFIX.len() + 32);

        sqlx::query(
            "update oauth_clients set created_at = now() - interval '40 days' \
             where client_id in ($1, $2)",
        )
        .bind(&idle.client_id)
        .bind(&used.client_id)
        .execute(&store.pool)
        .await
        .unwrap();
        sqlx::query(
            "update oauth_clients set last_used_at = now() - interval '2 days' \
             where client_id = $1",
        )
        .bind(&used.client_id)
        .execute(&store.pool)
        .await
        .unwrap();

        assert_eq!(store.purge_oauth().await.unwrap(), 1);
        assert!(store.oauth_client(&idle.client_id).await.unwrap().is_none());
        assert!(store.oauth_client(&used.client_id).await.unwrap().is_some());
        let fresh = store.oauth_client(&fresh.client_id).await.unwrap().unwrap();
        assert_eq!(fresh.client_name.as_deref(), Some("fresh"));
    }

    #[tokio::test]
    async fn revoking_a_token_or_a_grant_ends_the_grant() {
        let Some(store) = test_store("oauth_revocation").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let bob = user(&store, "bob").await;
        let issued = issue(&store, alice).await;

        // Another user cannot revoke it, a malformed token does nothing
        let revoked = store
            .revoke_oauth_grant(issued.grant_id, Some(bob))
            .await
            .unwrap();
        assert!(!revoked);
        store.revoke_oauth_token("garbage").await.unwrap();
        assert_eq!(store.list_oauth_grants(Some(alice)).await.unwrap().len(), 1);

        store
            .revoke_oauth_token(&issued.refresh_token)
            .await
            .unwrap();
        let lookup = store
            .authenticate_oauth_access(&issued.access_token)
            .await
            .unwrap();
        assert!(matches!(lookup, AccessLookup::Invalid));
        assert_eq!(store.list_oauth_grants(None).await.unwrap().len(), 0);
        let again = store
            .revoke_oauth_grant(issued.grant_id, Some(alice))
            .await
            .unwrap();
        assert!(!again);
    }

    #[tokio::test]
    async fn revoking_a_grant_is_audited_with_the_actor() {
        let Some(store) = test_store("oauth_revocation_audit").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let mine = issue(&store, alice).await;
        let theirs = issue(&store, alice).await;
        let admin = Actor {
            user_id: None,
            label: "root".to_owned(),
        };

        assert!(
            store
                .revoke_oauth_grant(mine.grant_id, Some(alice))
                .await
                .unwrap()
        );
        assert!(
            store
                .admin_revoke_oauth_grant(&admin, theirs.grant_id)
                .await
                .unwrap()
        );
        // Nothing live is left: no new row for a repeat
        assert!(
            !store
                .admin_revoke_oauth_grant(&admin, theirs.grant_id)
                .await
                .unwrap()
        );

        let rows: Vec<(String, String, String)> =
            sqlx::query_as("select action, actor, target from audit_log order by id")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [
                (
                    "oauth_grant.revoke".to_owned(),
                    "alice".to_owned(),
                    format!("oauth_grant:{}", mine.grant_id)
                ),
                (
                    "oauth_grant.revoke".to_owned(),
                    "root".to_owned(),
                    format!("oauth_grant:{}", theirs.grant_id)
                ),
            ]
        );
    }
}
