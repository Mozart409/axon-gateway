//! OAuth client state: registrations at backends' authorization servers, pending
//! authorization requests, per-user tokens and identity provider refresh tokens
//!
//! The store only keeps the three parts of each sealed secret (see `crypto`);
//! sealing lives in `upstream_oauth`. Writing the outcome of a refresh
//! (`updated_at`, `last_error*`) never notifies other replicas; inserting or
//! deleting a token row does.

use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

use super::personal::SealedColumns;
use super::{Store, StoreError};

/// How long an authorization request waits for the redirect back
const REQUEST_TTL: Duration = Duration::from_mins(10);
/// Longest stored error text, in characters
const MAX_ERROR_CHARS: usize = 500;

const CLIENT_COLUMNS: &str =
    "backend, issuer, client_id, secret_kek_id, secret_dek, secret_data, created_at";
const REQUEST_COLUMNS: &str = "state, user_id, backend, issuer, client_id, token_endpoint, \
     redirect_uri, pkce_verifier, return_to, token_auth_method, iss_supported, created_at";
const TOKEN_COLUMNS: &str = "user_id, backend, issuer, client_id, token_endpoint, scope, \
     token_auth_method, secret_kek_id, secret_dek, secret_data, expires_at, created_at, \
     updated_at, last_error, last_error_at";

/// A client registered at one backend's authorization server, shared by every user
// The fields mirror the row; not all are read yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    pub backend: String,
    pub issuer: String,
    pub client_id: String,
    /// The sealed client secret of a confidential registration
    pub secret: Option<SealedColumns>,
    pub created_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ClientRow {
    backend: String,
    issuer: String,
    client_id: String,
    secret_kek_id: Option<String>,
    secret_dek: Option<Vec<u8>>,
    secret_data: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
}

impl From<ClientRow> for UpstreamClient {
    fn from(row: ClientRow) -> Self {
        let secret = match (row.secret_kek_id, row.secret_dek, row.secret_data) {
            (Some(kek_id), Some(dek), Some(data)) => Some(SealedColumns { kek_id, dek, data }),
            _ => None,
        };
        Self {
            backend: row.backend,
            issuer: row.issuer,
            client_id: row.client_id,
            secret,
            created_at: row.created_at,
        }
    }
}

/// An authorization request to store until the redirect comes back
#[derive(Debug, Clone)]
pub struct NewUpstreamRequest {
    pub state: String,
    pub user_id: Uuid,
    pub backend: String,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub return_to: Option<String>,
    /// How the token endpoint authenticates the client (`none`,
    /// `client_secret_basic` or `client_secret_post`)
    pub token_auth_method: String,
    /// Whether the server returns `iss` on the redirect (RFC 9207)
    pub iss_supported: bool,
}

/// A stored authorization request, as taken back on the callback
// The fields mirror the row; not all are read yet.
#[allow(dead_code)]
#[derive(Clone, FromRow)]
pub struct UpstreamRequest {
    pub state: String,
    pub user_id: Uuid,
    pub backend: String,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub return_to: Option<String>,
    pub token_auth_method: String,
    pub iss_supported: bool,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for UpstreamRequest {
    // By hand, so the PKCE verifier can never end up in a log line.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamRequest")
            .field("state", &"<redacted>")
            .field("user_id", &self.user_id)
            .field("backend", &self.backend)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("token_endpoint", &self.token_endpoint)
            .field("redirect_uri", &self.redirect_uri)
            .field("pkce_verifier", &"<redacted>")
            .field("return_to", &self.return_to)
            .field("token_auth_method", &self.token_auth_method)
            .field("iss_supported", &self.iss_supported)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// One user's sealed tokens for a backend
// The fields mirror the row; not all are read yet.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct UpstreamToken {
    pub user_id: Uuid,
    pub backend: String,
    pub issuer: String,
    pub client_id: String,
    pub token_endpoint: String,
    pub scope: Option<String>,
    /// How the token endpoint authenticates the client, as chosen at connect
    pub token_auth_method: String,
    /// The sealed JSON with the access token and the refresh token if any
    pub secret: SealedColumns,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
}

/// Tokens to store for one user and backend
#[derive(Debug, Clone)]
pub struct NewUpstreamToken<'a> {
    pub user_id: Uuid,
    pub backend: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub token_endpoint: &'a str,
    pub scope: Option<&'a str>,
    pub token_auth_method: &'a str,
    pub secret: &'a SealedColumns,
    pub expires_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct TokenRow {
    user_id: Uuid,
    backend: String,
    issuer: String,
    client_id: String,
    token_endpoint: String,
    scope: Option<String>,
    token_auth_method: String,
    secret_kek_id: String,
    secret_dek: Vec<u8>,
    secret_data: Vec<u8>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_error: Option<String>,
    last_error_at: Option<DateTime<Utc>>,
}

impl From<TokenRow> for UpstreamToken {
    fn from(row: TokenRow) -> Self {
        Self {
            user_id: row.user_id,
            backend: row.backend,
            issuer: row.issuer,
            client_id: row.client_id,
            token_endpoint: row.token_endpoint,
            scope: row.scope,
            token_auth_method: row.token_auth_method,
            secret: SealedColumns {
                kek_id: row.secret_kek_id,
                dek: row.secret_dek,
                data: row.secret_data,
            },
            expires_at: row.expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_error: row.last_error,
            last_error_at: row.last_error_at,
        }
    }
}

#[derive(FromRow)]
// The columns are named `secret_*` in the database.
#[allow(clippy::struct_field_names)]
struct SealedRow {
    secret_kek_id: String,
    secret_dek: Vec<u8>,
    secret_data: Vec<u8>,
}

impl From<SealedRow> for SealedColumns {
    fn from(row: SealedRow) -> Self {
        Self {
            kek_id: row.secret_kek_id,
            dek: row.secret_dek,
            data: row.secret_data,
        }
    }
}

impl Store {
    /// The client registered for `backend` at `issuer`, if any.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn get_upstream_client(
        &self,
        backend: &str,
        issuer: &str,
    ) -> Result<Option<UpstreamClient>, StoreError> {
        let row: Option<ClientRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {CLIENT_COLUMNS} from upstream_oauth_clients where backend = $1 and issuer = $2"
        )))
        .bind(backend)
        .bind(issuer)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(UpstreamClient::from))
    }

    /// Stores the client registered for `backend` at `issuer`; a registration
    /// that is already there is replaced.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn upsert_upstream_client(
        &self,
        backend: &str,
        issuer: &str,
        client_id: &str,
        secret: Option<&SealedColumns>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into upstream_oauth_clients \
             (backend, issuer, client_id, secret_kek_id, secret_dek, secret_data) \
             values ($1, $2, $3, $4, $5, $6) \
             on conflict (backend, issuer) do update set \
             client_id = excluded.client_id, secret_kek_id = excluded.secret_kek_id, \
             secret_dek = excluded.secret_dek, secret_data = excluded.secret_data, \
             created_at = now()",
        )
        .bind(backend)
        .bind(issuer)
        .bind(client_id)
        .bind(secret.map(|s| s.kek_id.as_str()))
        .bind(secret.map(|s| s.dek.as_slice()))
        .bind(secret.map(|s| s.data.as_slice()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Deletes the registration for `backend` at `issuer`, so the next sign-in
    /// registers again. `false` when there was none.
    ///
    /// # Errors
    /// Fails when the query fails.
    // For the admin view of a later slice.
    #[allow(dead_code)]
    pub async fn delete_upstream_client(
        &self,
        backend: &str,
        issuer: &str,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("delete from upstream_oauth_clients where backend = $1 and issuer = $2")
                .bind(backend)
                .bind(issuer)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Stores an authorization request until the redirect comes back.
    ///
    /// # Errors
    /// Fails when the query fails (an unknown user or a repeated state included).
    pub async fn create_upstream_request(
        &self,
        request: &NewUpstreamRequest,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into upstream_oauth_requests \
             (state, user_id, backend, issuer, client_id, token_endpoint, redirect_uri, \
              pkce_verifier, return_to, token_auth_method, iss_supported) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&request.state)
        .bind(request.user_id)
        .bind(&request.backend)
        .bind(&request.issuer)
        .bind(&request.client_id)
        .bind(&request.token_endpoint)
        .bind(&request.redirect_uri)
        .bind(&request.pkce_verifier)
        .bind(request.return_to.as_deref())
        .bind(&request.token_auth_method)
        .bind(request.iss_supported)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Takes the request for `state`: it is deleted, so a state works once.
    /// `None` when it is unknown, already taken or older than 10 minutes.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn take_upstream_request(
        &self,
        state: &str,
    ) -> Result<Option<UpstreamRequest>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "delete from upstream_oauth_requests \
             where state = $1 and created_at > now() - make_interval(secs => $2) \
             returning {REQUEST_COLUMNS}"
        )))
        .bind(state)
        .bind(REQUEST_TTL.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Stores the tokens of `token.user_id` for `token.backend` and clears the
    /// last error. Only a new row notifies other replicas; a refresh does not.
    ///
    /// # Errors
    /// Fails when the query fails (an unknown user included).
    pub async fn upsert_upstream_token(
        &self,
        token: &NewUpstreamToken<'_>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into upstream_oauth_tokens \
             (user_id, backend, issuer, client_id, token_endpoint, scope, token_auth_method, \
              secret_kek_id, secret_dek, secret_data, expires_at) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             on conflict (user_id, backend) do update set \
             issuer = excluded.issuer, client_id = excluded.client_id, \
             token_endpoint = excluded.token_endpoint, scope = excluded.scope, \
             token_auth_method = excluded.token_auth_method, \
             secret_kek_id = excluded.secret_kek_id, secret_dek = excluded.secret_dek, \
             secret_data = excluded.secret_data, expires_at = excluded.expires_at, \
             updated_at = now(), last_error = null, last_error_at = null",
        )
        .bind(token.user_id)
        .bind(token.backend)
        .bind(token.issuer)
        .bind(token.client_id)
        .bind(token.token_endpoint)
        .bind(token.scope)
        .bind(token.token_auth_method)
        .bind(&token.secret.kek_id)
        .bind(&token.secret.dek)
        .bind(&token.secret.data)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The tokens of `user_id` for `backend`, if any.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn get_upstream_token(
        &self,
        user_id: Uuid,
        backend: &str,
    ) -> Result<Option<UpstreamToken>, StoreError> {
        let row: Option<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {TOKEN_COLUMNS} from upstream_oauth_tokens \
             where user_id = $1 and backend = $2"
        )))
        .bind(user_id)
        .bind(backend)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(UpstreamToken::from))
    }

    /// All tokens of `user_id`, by backend.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_upstream_tokens(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UpstreamToken>, StoreError> {
        let rows: Vec<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {TOKEN_COLUMNS} from upstream_oauth_tokens \
             where user_id = $1 order by backend"
        )))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(UpstreamToken::from).collect())
    }

    /// Deletes the tokens of `user_id` for `backend`. `false` when there are none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn delete_upstream_token(
        &self,
        user_id: Uuid,
        backend: &str,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("delete from upstream_oauth_tokens where user_id = $1 and backend = $2")
                .bind(user_id)
                .bind(backend)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Records why a refresh failed (cut to 500 characters). Does not notify
    /// other replicas.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn record_upstream_token_error(
        &self,
        user_id: Uuid,
        backend: &str,
        error: &str,
    ) -> Result<(), StoreError> {
        let error: String = error.chars().take(MAX_ERROR_CHARS).collect();
        sqlx::query(
            "update upstream_oauth_tokens set last_error = $3, last_error_at = now() \
             where user_id = $1 and backend = $2",
        )
        .bind(user_id)
        .bind(backend)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Stores the refresh token the identity provider `provider` gave `user_id`.
    ///
    /// # Errors
    /// Fails when the query fails (an unknown user included).
    pub async fn upsert_idp_refresh_token(
        &self,
        user_id: Uuid,
        provider: &str,
        secret: &SealedColumns,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into idp_refresh_tokens \
             (user_id, provider, secret_kek_id, secret_dek, secret_data) \
             values ($1, $2, $3, $4, $5) \
             on conflict (user_id, provider) do update set \
             secret_kek_id = excluded.secret_kek_id, secret_dek = excluded.secret_dek, \
             secret_data = excluded.secret_data, updated_at = now()",
        )
        .bind(user_id)
        .bind(provider)
        .bind(&secret.kek_id)
        .bind(&secret.dek)
        .bind(&secret.data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The sealed refresh token of `user_id` at `provider`, if any.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn get_idp_refresh_token(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<SealedColumns>, StoreError> {
        let row: Option<SealedRow> = sqlx::query_as(
            "select secret_kek_id, secret_dek, secret_data from idp_refresh_tokens \
             where user_id = $1 and provider = $2",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(SealedColumns::from))
    }

    /// Deletes the refresh token of `user_id` at `provider`. `false` when there is none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn delete_idp_refresh_token(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("delete from idp_refresh_tokens where user_id = $1 and provider = $2")
                .bind(user_id)
                .bind(provider)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes authorization requests older than 10 minutes. Returns the number
    /// of rows deleted.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn purge_upstream_oauth(&self) -> Result<u64, StoreError> {
        let result = sqlx::query(
            "delete from upstream_oauth_requests \
             where created_at < now() - make_interval(secs => $1)",
        )
        .bind(REQUEST_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
