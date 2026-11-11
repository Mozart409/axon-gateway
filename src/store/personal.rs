//! Personal backends, the admin catalog and per-user credentials
//!
//! A personal backend is an MCP server one user added for themselves; a catalog
//! entry is one an admin offers to everyone, who then store their own credentials
//! for it. The store only keeps the three parts of each sealed secret (see
//! `crypto`); it never sees plaintext. Outcome columns (`last_*`) are written on
//! every call and never notify other replicas, configuration columns do.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use sqlx::types::Json;
use thiserror::Error;
use uuid::Uuid;

use crate::config::CredentialField;

use super::{Store, StoreError};

/// Longest stored error text, in characters
const MAX_ERROR_CHARS: usize = 500;

const PERSONAL_COLUMNS: &str = "id, owner_id, prefix, url, header_names, secret_kek_id, secret_dek, secret_data, \
     enabled, created_at, updated_at, last_ok_at, last_error_at, last_error";
const CATALOG_COLUMNS: &str = "name, description, url, credential_fields, enabled, created_by, \
     created_at, updated_at, auth, oauth_client_id, oauth_scopes, oauth_secret_kek_id, \
     oauth_secret_dek, oauth_secret_data";
const CREDENTIAL_COLUMNS: &str = "user_id, backend, secret_kek_id, secret_dek, secret_data, \
     created_at, updated_at, last_ok_at, last_error_at, last_error";

/// Errors from changing personal backends and the catalog
#[derive(Debug, Error)]
pub enum PersonalError {
    #[error("already exists")]
    Exists,

    #[error(transparent)]
    Store(#[from] StoreError),
}

fn map_unique(error: sqlx::Error) -> PersonalError {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => PersonalError::Exists,
        _ => PersonalError::Store(StoreError::Query(error)),
    }
}

/// One part of the secret an update sets; `None` for [`SecretUpdate::Clear`]
/// (and unused for [`SecretUpdate::Keep`])
fn secret_part<'a, T: ?Sized>(
    update: &'a SecretUpdate,
    part: impl FnOnce(&'a SealedColumns) -> &'a T,
) -> Option<&'a T> {
    match update {
        SecretUpdate::Set(secret) => Some(part(secret)),
        SecretUpdate::Keep | SecretUpdate::Clear => None,
    }
}

/// The three parts of one sealed secret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedColumns {
    pub kek_id: String,
    pub dek: Vec<u8>,
    pub data: Vec<u8>,
}

/// A personal backend as stored
#[derive(Debug, Clone)]
pub struct PersonalBackend {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub prefix: String,
    pub url: String,
    pub header_names: Vec<String>,
    /// The sealed header values; `None` when the backend sends no secret
    pub secret: Option<SealedColumns>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(FromRow)]
struct PersonalRow {
    id: Uuid,
    owner_id: Uuid,
    prefix: String,
    url: String,
    header_names: Vec<String>,
    secret_kek_id: Option<String>,
    secret_dek: Option<Vec<u8>>,
    secret_data: Option<Vec<u8>>,
    enabled: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_ok_at: Option<DateTime<Utc>>,
    last_error_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl From<PersonalRow> for PersonalBackend {
    fn from(row: PersonalRow) -> Self {
        let secret = match (row.secret_kek_id, row.secret_dek, row.secret_data) {
            (Some(kek_id), Some(dek), Some(data)) => Some(SealedColumns { kek_id, dek, data }),
            _ => None,
        };
        Self {
            id: row.id,
            owner_id: row.owner_id,
            prefix: row.prefix,
            url: row.url,
            header_names: row.header_names,
            secret,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_ok_at: row.last_ok_at,
            last_error_at: row.last_error_at,
            last_error: row.last_error,
        }
    }
}

/// The fields of a personal backend to create
#[derive(Debug, Clone)]
pub struct NewPersonalBackend {
    /// Chosen by the caller, because the sealed headers are bound to it
    pub id: Uuid,
    pub owner_id: Uuid,
    pub prefix: String,
    pub url: String,
    pub header_names: Vec<String>,
    pub secret: Option<SealedColumns>,
}

/// A personal backend with its owner, as the admin overview lists it. The
/// sealed headers are not read.
#[derive(Debug, Clone, FromRow)]
pub struct AdminPersonalBackend {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub owner_email: Option<String>,
    pub owner_name: Option<String>,
    pub owner_subject: String,
    pub prefix: String,
    pub url: String,
    pub header_names: Vec<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// The fields of a personal backend to change; `None` keeps the stored value
#[derive(Debug, Clone, Default)]
pub struct PersonalBackendUpdate {
    pub url: Option<String>,
    pub enabled: Option<bool>,
    /// The header names and their sealed values, replaced together
    pub headers: Option<(Vec<String>, Option<SealedColumns>)>,
}

/// How the users of a catalog entry authenticate to its backend
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CatalogAuthMode {
    /// The values of `credential_fields`, sent as headers
    #[default]
    Fields,
    /// OAuth: each user connects their own account
    OAuth,
}

impl CatalogAuthMode {
    /// The value of the `auth` column
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fields => "fields",
            Self::OAuth => "oauth",
        }
    }
}

/// A catalog entry as stored
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub credential_fields: Vec<CredentialField>,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub auth: CatalogAuthMode,
    /// The static OAuth client; without it the gateway uses a client ID metadata
    /// document or registers itself
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Vec<String>,
    /// The sealed client secret of the static OAuth client
    pub oauth_secret: Option<SealedColumns>,
}

#[derive(FromRow)]
struct CatalogRow {
    name: String,
    description: Option<String>,
    url: String,
    credential_fields: Json<Vec<CredentialField>>,
    enabled: bool,
    created_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    auth: String,
    oauth_client_id: Option<String>,
    oauth_scopes: Vec<String>,
    oauth_secret_kek_id: Option<String>,
    oauth_secret_dek: Option<Vec<u8>>,
    oauth_secret_data: Option<Vec<u8>>,
}

impl From<CatalogRow> for CatalogEntry {
    fn from(row: CatalogRow) -> Self {
        let oauth_secret = match (
            row.oauth_secret_kek_id,
            row.oauth_secret_dek,
            row.oauth_secret_data,
        ) {
            (Some(kek_id), Some(dek), Some(data)) => Some(SealedColumns { kek_id, dek, data }),
            _ => None,
        };
        Self {
            name: row.name,
            description: row.description,
            url: row.url,
            credential_fields: row.credential_fields.0,
            enabled: row.enabled,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
            // The column's check constraint leaves no other value
            auth: if row.auth == "oauth" {
                CatalogAuthMode::OAuth
            } else {
                CatalogAuthMode::Fields
            },
            oauth_client_id: row.oauth_client_id,
            oauth_scopes: row.oauth_scopes,
            oauth_secret,
        }
    }
}

/// The fields of a catalog entry to create
#[derive(Debug, Clone, Default)]
pub struct NewCatalogEntry {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub credential_fields: Vec<CredentialField>,
    pub created_by: Option<String>,
    pub auth: CatalogAuthMode,
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Vec<String>,
    pub oauth_secret: Option<SealedColumns>,
}

/// What to do with a stored sealed secret
// `Clear` and `Set` are built by the admin form of a later slice.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SecretUpdate {
    /// Leave it as it is
    #[default]
    Keep,
    /// Remove it
    Clear,
    /// Replace it
    Set(SealedColumns),
}

/// The fields of a catalog entry to change; `None` keeps the stored value
#[derive(Debug, Clone, Default)]
pub struct CatalogEntryUpdate {
    /// `Some("")` clears the description
    pub description: Option<String>,
    pub url: Option<String>,
    pub credential_fields: Option<Vec<CredentialField>>,
    pub enabled: Option<bool>,
    pub auth: Option<CatalogAuthMode>,
    /// `Some("")` clears the static client id
    pub oauth_client_id: Option<String>,
    pub oauth_scopes: Option<Vec<String>>,
    pub oauth_secret: SecretUpdate,
}

/// One user's sealed credentials for a backend
#[derive(Debug, Clone)]
pub struct UserCredential {
    pub user_id: Uuid,
    pub backend: String,
    pub secret: SealedColumns,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(FromRow)]
struct CredentialRow {
    user_id: Uuid,
    backend: String,
    secret_kek_id: String,
    secret_dek: Vec<u8>,
    secret_data: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_ok_at: Option<DateTime<Utc>>,
    last_error_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
}

impl From<CredentialRow> for UserCredential {
    fn from(row: CredentialRow) -> Self {
        Self {
            user_id: row.user_id,
            backend: row.backend,
            secret: SealedColumns {
                kek_id: row.secret_kek_id,
                dek: row.secret_dek,
                data: row.secret_data,
            },
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_ok_at: row.last_ok_at,
            last_error_at: row.last_error_at,
            last_error: row.last_error,
        }
    }
}

/// Where a sealed secret lives, for key rotation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    Personal(Uuid),
    Credential { user_id: Uuid, backend: String },
}

#[derive(FromRow)]
struct SealedPersonalRow {
    id: Uuid,
    secret_kek_id: String,
    secret_dek: Vec<u8>,
    secret_data: Vec<u8>,
}

fn truncated(error: &str) -> String {
    error.chars().take(MAX_ERROR_CHARS).collect()
}

impl Store {
    /// The personal backends of one user, by prefix.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_personal_backends(
        &self,
        owner_id: Uuid,
    ) -> Result<Vec<PersonalBackend>, StoreError> {
        let rows: Vec<PersonalRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {PERSONAL_COLUMNS} from personal_backends where owner_id = $1 order by prefix"
        )))
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Every user's personal backends with their owners, by owner and prefix.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_all_personal_backends(
        &self,
    ) -> Result<Vec<AdminPersonalBackend>, StoreError> {
        Ok(sqlx::query_as(
            "select b.id, b.owner_id, u.email as owner_email, u.display_name as owner_name, \
             u.subject as owner_subject, b.prefix, b.url, b.header_names, b.enabled, \
             b.created_at, b.updated_at, b.last_ok_at, b.last_error_at, b.last_error \
             from personal_backends b join users u on u.id = b.owner_id \
             order by coalesce(u.email, u.display_name, u.subject), b.owner_id, b.prefix",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// The personal backend of `owner_id` with this prefix.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn personal_backend(
        &self,
        owner_id: Uuid,
        prefix: &str,
    ) -> Result<Option<PersonalBackend>, StoreError> {
        let row: Option<PersonalRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {PERSONAL_COLUMNS} from personal_backends where owner_id = $1 and prefix = $2"
        )))
        .bind(owner_id)
        .bind(prefix)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Creates a personal backend.
    ///
    /// # Errors
    /// Fails with [`PersonalError::Exists`] when the owner already has a backend with
    /// this prefix, or when the query fails (an unknown owner included).
    pub async fn create_personal_backend(
        &self,
        new: &NewPersonalBackend,
    ) -> Result<PersonalBackend, PersonalError> {
        let row: PersonalRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into personal_backends \
             (id, owner_id, prefix, url, header_names, secret_kek_id, secret_dek, secret_data) \
             values ($1, $2, $3, $4, $5, $6, $7, $8) returning {PERSONAL_COLUMNS}"
        )))
        .bind(new.id)
        .bind(new.owner_id)
        .bind(&new.prefix)
        .bind(&new.url)
        .bind(&new.header_names)
        .bind(new.secret.as_ref().map(|s| s.kek_id.as_str()))
        .bind(new.secret.as_ref().map(|s| s.dek.as_slice()))
        .bind(new.secret.as_ref().map(|s| s.data.as_slice()))
        .fetch_one(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(row.into())
    }

    /// Changes the given fields of a personal backend of `owner_id` and bumps
    /// `updated_at`. `None` when there is no such backend.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn update_personal_backend(
        &self,
        owner_id: Uuid,
        prefix: &str,
        update: &PersonalBackendUpdate,
    ) -> Result<Option<PersonalBackend>, StoreError> {
        let (names, secret) = match &update.headers {
            Some((names, secret)) => (Some(names), secret.as_ref()),
            None => (None, None),
        };
        let row: Option<PersonalRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "update personal_backends set \
             url = coalesce($3, url), \
             enabled = coalesce($4, enabled), \
             header_names = case when $5 then $6::text[] else header_names end, \
             secret_kek_id = case when $5 then $7::text else secret_kek_id end, \
             secret_dek = case when $5 then $8::bytea else secret_dek end, \
             secret_data = case when $5 then $9::bytea else secret_data end, \
             updated_at = now() \
             where owner_id = $1 and prefix = $2 returning {PERSONAL_COLUMNS}"
        )))
        .bind(owner_id)
        .bind(prefix)
        .bind(update.url.as_deref())
        .bind(update.enabled)
        .bind(names.is_some())
        .bind(names.cloned().unwrap_or_default())
        .bind(secret.map(|s| s.kek_id.as_str()))
        .bind(secret.map(|s| s.dek.as_slice()))
        .bind(secret.map(|s| s.data.as_slice()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Deletes a personal backend of `owner_id`. `false` when there is none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn delete_personal_backend(
        &self,
        owner_id: Uuid,
        prefix: &str,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("delete from personal_backends where owner_id = $1 and prefix = $2")
                .bind(owner_id)
                .bind(prefix)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Records the outcome of a call through a personal backend: success, or the
    /// error text (cut to 500 characters). Does not notify other replicas.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn record_personal_outcome(
        &self,
        id: Uuid,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        match error {
            None => {
                sqlx::query("update personal_backends set last_ok_at = now() where id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await?;
            }
            Some(error) => {
                sqlx::query(
                    "update personal_backends set last_error_at = now(), last_error = $2 \
                     where id = $1",
                )
                .bind(id)
                .bind(truncated(error))
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(())
    }

    /// Every catalog entry, by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_catalog_entries(&self) -> Result<Vec<CatalogEntry>, StoreError> {
        let rows: Vec<CatalogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {CATALOG_COLUMNS} from catalog_entries order by name"
        )))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// One catalog entry by name.
    #[cfg(test)]
    pub async fn catalog_entry(&self, name: &str) -> Result<Option<CatalogEntry>, StoreError> {
        let row: Option<CatalogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {CATALOG_COLUMNS} from catalog_entries where name = $1"
        )))
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Creates a catalog entry.
    ///
    /// # Errors
    /// Fails with [`PersonalError::Exists`] when the name is taken, or when the query
    /// fails.
    pub async fn create_catalog_entry(
        &self,
        new: &NewCatalogEntry,
    ) -> Result<CatalogEntry, PersonalError> {
        let row: CatalogRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into catalog_entries \
             (name, description, url, credential_fields, created_by, auth, oauth_client_id, \
              oauth_scopes, oauth_secret_kek_id, oauth_secret_dek, oauth_secret_data) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) returning {CATALOG_COLUMNS}"
        )))
        .bind(&new.name)
        .bind(new.description.as_deref())
        .bind(&new.url)
        .bind(Json(&new.credential_fields))
        .bind(new.created_by.as_deref())
        .bind(new.auth.as_str())
        .bind(new.oauth_client_id.as_deref())
        .bind(&new.oauth_scopes)
        .bind(new.oauth_secret.as_ref().map(|s| s.kek_id.as_str()))
        .bind(new.oauth_secret.as_ref().map(|s| s.dek.as_slice()))
        .bind(new.oauth_secret.as_ref().map(|s| s.data.as_slice()))
        .fetch_one(&self.pool)
        .await
        .map_err(map_unique)?;
        Ok(row.into())
    }

    /// Changes the given fields of a catalog entry and bumps `updated_at`. `None`
    /// when there is no such entry.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn update_catalog_entry(
        &self,
        name: &str,
        update: &CatalogEntryUpdate,
    ) -> Result<Option<CatalogEntry>, StoreError> {
        let row: Option<CatalogRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "update catalog_entries set \
             description = case when $2 then nullif($3, '') else description end, \
             url = coalesce($4, url), \
             credential_fields = coalesce($5::jsonb, credential_fields), \
             enabled = coalesce($6, enabled), \
             auth = coalesce($7::text, auth), \
             oauth_client_id = case when $8 then nullif($9::text, '') else oauth_client_id end, \
             oauth_scopes = coalesce($10::text[], oauth_scopes), \
             oauth_secret_kek_id = case when $11 then $12::text else oauth_secret_kek_id end, \
             oauth_secret_dek = case when $11 then $13::bytea else oauth_secret_dek end, \
             oauth_secret_data = case when $11 then $14::bytea else oauth_secret_data end, \
             updated_at = now() \
             where name = $1 returning {CATALOG_COLUMNS}"
        )))
        .bind(name)
        .bind(update.description.is_some())
        .bind(update.description.as_deref())
        .bind(update.url.as_deref())
        .bind(update.credential_fields.as_ref().map(Json))
        .bind(update.enabled)
        .bind(update.auth.map(CatalogAuthMode::as_str))
        .bind(update.oauth_client_id.is_some())
        .bind(update.oauth_client_id.as_deref())
        .bind(update.oauth_scopes.as_deref())
        .bind(update.oauth_secret != SecretUpdate::Keep)
        .bind(secret_part(&update.oauth_secret, |s| s.kek_id.as_str()))
        .bind(secret_part(&update.oauth_secret, |s| s.dek.as_slice()))
        .bind(secret_part(&update.oauth_secret, |s| s.data.as_slice()))
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Deletes a catalog entry together with every user's credentials for it, in
    /// one transaction. `false` when there is no such entry.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_catalog_entry(&self, name: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("delete from catalog_entries where name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        sqlx::query("delete from user_credentials where backend = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The stored credentials of one user, by backend.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_user_credentials(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserCredential>, StoreError> {
        let rows: Vec<CredentialRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {CREDENTIAL_COLUMNS} from user_credentials where user_id = $1 order by backend"
        )))
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Stores the credentials of `user_id` for `backend`, replacing earlier ones.
    ///
    /// # Errors
    /// Fails when the query fails (an unknown user included).
    pub async fn set_user_credential(
        &self,
        user_id: Uuid,
        backend: &str,
        secret: &SealedColumns,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into user_credentials (user_id, backend, secret_kek_id, secret_dek, secret_data) \
             values ($1, $2, $3, $4, $5) \
             on conflict (user_id, backend) do update set \
             secret_kek_id = excluded.secret_kek_id, secret_dek = excluded.secret_dek, \
             secret_data = excluded.secret_data, updated_at = now()",
        )
        .bind(user_id)
        .bind(backend)
        .bind(&secret.kek_id)
        .bind(&secret.dek)
        .bind(&secret.data)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Deletes the credentials of `user_id` for `backend`. `false` when there are none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn delete_user_credential(
        &self,
        user_id: Uuid,
        backend: &str,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("delete from user_credentials where user_id = $1 and backend = $2")
                .bind(user_id)
                .bind(backend)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Records the outcome of a call made with stored credentials: success, or the
    /// error text (cut to 500 characters). Does not notify other replicas.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn record_credential_outcome(
        &self,
        user_id: Uuid,
        backend: &str,
        error: Option<&str>,
    ) -> Result<(), StoreError> {
        match error {
            None => {
                sqlx::query(
                    "update user_credentials set last_ok_at = now() \
                     where user_id = $1 and backend = $2",
                )
                .bind(user_id)
                .bind(backend)
                .execute(&self.pool)
                .await?;
            }
            Some(error) => {
                sqlx::query(
                    "update user_credentials set last_error_at = now(), last_error = $3 \
                     where user_id = $1 and backend = $2",
                )
                .bind(user_id)
                .bind(backend)
                .bind(truncated(error))
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(())
    }

    /// How many backends a user has: personal backends plus stored credentials.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn count_user_backends(&self, user_id: Uuid) -> Result<i64, StoreError> {
        Ok(sqlx::query_scalar(
            "select (select count(*) from personal_backends where owner_id = $1) \
                  + (select count(*) from user_credentials where user_id = $1)",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?)
    }

    /// Every sealed secret in both tables, for key rotation.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn sealed_secrets(&self) -> Result<Vec<(SecretRef, SealedColumns)>, StoreError> {
        let personal: Vec<SealedPersonalRow> = sqlx::query_as(
            "select id, secret_kek_id, secret_dek, secret_data from personal_backends \
             where secret_kek_id is not null",
        )
        .fetch_all(&self.pool)
        .await?;
        let credentials: Vec<CredentialRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {CREDENTIAL_COLUMNS} from user_credentials"
        )))
        .fetch_all(&self.pool)
        .await?;

        let mut secrets: Vec<(SecretRef, SealedColumns)> = personal
            .into_iter()
            .map(|row| {
                (
                    SecretRef::Personal(row.id),
                    SealedColumns {
                        kek_id: row.secret_kek_id,
                        dek: row.secret_dek,
                        data: row.secret_data,
                    },
                )
            })
            .collect();
        secrets.extend(credentials.into_iter().map(|row| {
            let credential = UserCredential::from(row);
            (
                SecretRef::Credential {
                    user_id: credential.user_id,
                    backend: credential.backend,
                },
                credential.secret,
            )
        }));
        Ok(secrets)
    }

    /// Replaces one sealed secret. `false` when it no longer exists.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn replace_sealed(
        &self,
        target: &SecretRef,
        sealed: &SealedColumns,
    ) -> Result<bool, StoreError> {
        let result = match target {
            SecretRef::Personal(id) => {
                sqlx::query(
                    "update personal_backends \
                     set secret_kek_id = $2, secret_dek = $3, secret_data = $4 \
                     where id = $1 and secret_kek_id is not null",
                )
                .bind(id)
                .bind(&sealed.kek_id)
                .bind(&sealed.dek)
                .bind(&sealed.data)
                .execute(&self.pool)
                .await?
            }
            SecretRef::Credential { user_id, backend } => {
                sqlx::query(
                    "update user_credentials \
                     set secret_kek_id = $3, secret_dek = $4, secret_data = $5 \
                     where user_id = $1 and backend = $2",
                )
                .bind(user_id)
                .bind(backend)
                .bind(&sealed.kek_id)
                .bind(&sealed.dek)
                .bind(&sealed.data)
                .execute(&self.pool)
                .await?
            }
        };
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::postgres::PgListener;

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

    fn sealed(tag: u8) -> SealedColumns {
        SealedColumns {
            kek_id: format!("k{tag}"),
            dek: vec![tag, 1, 2],
            data: vec![tag, 3, 4, 5],
        }
    }

    fn new_backend(
        owner_id: Uuid,
        prefix: &str,
        secret: Option<SealedColumns>,
    ) -> NewPersonalBackend {
        NewPersonalBackend {
            id: Uuid::new_v4(),
            owner_id,
            prefix: prefix.to_string(),
            url: format!("https://{prefix}.example/mcp"),
            header_names: vec!["Authorization".to_string()],
            secret,
        }
    }

    fn field(name: &str) -> CredentialField {
        CredentialField {
            name: name.to_string(),
            label: None,
            header: "Authorization".to_string(),
            prefix: Some("Bearer ".to_string()),
        }
    }

    fn new_entry(name: &str) -> NewCatalogEntry {
        NewCatalogEntry {
            name: name.to_string(),
            description: Some("a catalog backend".to_string()),
            url: format!("https://{name}.example/mcp"),
            credential_fields: vec![field("token")],
            created_by: Some("admin".to_string()),
            ..Default::default()
        }
    }

    /// The next notification on `listener`, parsed, within a few seconds.
    /// The next change notice of `schema` within `wait`; other schemas' (tests
    /// running in parallel) are skipped.
    async fn change_within(
        listener: &mut PgListener,
        schema: &str,
        wait: Duration,
    ) -> Option<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notification = tokio::time::timeout_at(deadline, listener.try_recv())
                .await
                .ok()?
                .unwrap()
                .expect("listener lost its connection");
            let change: serde_json::Value = serde_json::from_str(notification.payload()).unwrap();
            if change["schema"] == schema {
                return Some(change);
            }
        }
    }

    async fn next_change(listener: &mut PgListener, schema: &str) -> serde_json::Value {
        change_within(listener, schema, Duration::from_secs(5))
            .await
            .expect("no notification within 5s")
    }

    #[test]
    fn long_errors_are_cut() {
        assert_eq!(truncated("short"), "short");
        assert_eq!(truncated(&"x".repeat(900)).chars().count(), MAX_ERROR_CHARS);
    }

    #[tokio::test]
    async fn personal_backend_round_trip() {
        let Some(store) = test_store("axon_personal_crud").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let bob = user(&store, "bob").await;

        let created = store
            .create_personal_backend(&new_backend(alice, "zeta", Some(sealed(1))))
            .await
            .unwrap();
        assert_eq!(created.prefix, "zeta");
        assert_eq!(created.header_names, ["Authorization"]);
        assert_eq!(created.secret, Some(sealed(1)));
        assert!(created.enabled);
        assert!(created.last_ok_at.is_none());
        store
            .create_personal_backend(&new_backend(alice, "alpha", None))
            .await
            .unwrap();

        let duplicate = store
            .create_personal_backend(&new_backend(alice, "zeta", None))
            .await;
        assert!(matches!(duplicate, Err(PersonalError::Exists)));
        // the same prefix of another user is fine
        store
            .create_personal_backend(&new_backend(bob, "zeta", None))
            .await
            .unwrap();

        let listed = store.list_personal_backends(alice).await.unwrap();
        let prefixes: Vec<_> = listed.iter().map(|b| b.prefix.as_str()).collect();
        assert_eq!(prefixes, ["alpha", "zeta"]);
        assert_eq!(listed[0].secret, None);

        let found = store
            .personal_backend(alice, "zeta")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, created.id);
        assert_eq!(found.secret, Some(sealed(1)));
        assert!(
            store
                .personal_backend(bob, "alpha")
                .await
                .unwrap()
                .is_none()
        );

        assert!(store.delete_personal_backend(alice, "zeta").await.unwrap());
        assert!(!store.delete_personal_backend(alice, "zeta").await.unwrap());
        assert!(store.personal_backend(bob, "zeta").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn personal_backend_keeps_the_id_it_is_given() {
        let Some(store) = test_store("axon_personal_given_id").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let mut new = new_backend(alice, "mine", None);
        new.id = Uuid::new_v4();
        let created = store.create_personal_backend(&new).await.unwrap();
        assert_eq!(created.id, new.id);
        let again = store.create_personal_backend(&new).await;
        assert!(matches!(again, Err(PersonalError::Exists)));
    }

    #[tokio::test]
    async fn every_personal_backend_is_listed_with_its_owner() {
        let Some(store) = test_store("axon_personal_admin_list").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let bob = user(&store, "bob").await;
        store
            .create_personal_backend(&new_backend(bob, "beta", Some(sealed(1))))
            .await
            .unwrap();
        store
            .create_personal_backend(&new_backend(alice, "alpha", None))
            .await
            .unwrap();

        let listed = store.list_all_personal_backends().await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].owner_subject, "alice");
        assert_eq!(listed[0].owner_id, alice);
        assert_eq!(listed[0].prefix, "alpha");
        assert_eq!(listed[1].owner_subject, "bob");
        assert_eq!(listed[1].header_names, ["Authorization"]);
        assert!(listed[1].enabled);
    }

    #[tokio::test]
    async fn personal_update_keeps_unspecified_fields() {
        let Some(store) = test_store("axon_personal_update").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let created = store
            .create_personal_backend(&new_backend(alice, "prom", Some(sealed(1))))
            .await
            .unwrap();

        let disabled = store
            .update_personal_backend(
                alice,
                "prom",
                &PersonalBackendUpdate {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!disabled.enabled);
        assert_eq!(disabled.url, created.url);
        assert_eq!(disabled.header_names, created.header_names);
        assert_eq!(disabled.secret, Some(sealed(1)));
        assert!(disabled.updated_at >= created.updated_at);

        let moved = store
            .update_personal_backend(
                alice,
                "prom",
                &PersonalBackendUpdate {
                    url: Some("https://other.example/mcp".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(moved.url, "https://other.example/mcp");
        assert!(!moved.enabled);
        assert_eq!(moved.secret, Some(sealed(1)));

        // headers are replaced together with their secret, and may drop it
        let rekeyed = store
            .update_personal_backend(
                alice,
                "prom",
                &PersonalBackendUpdate {
                    headers: Some((vec!["X-Key".to_string()], Some(sealed(2)))),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rekeyed.header_names, ["X-Key"]);
        assert_eq!(rekeyed.secret, Some(sealed(2)));
        assert_eq!(rekeyed.url, "https://other.example/mcp");
        let bare = store
            .update_personal_backend(
                alice,
                "prom",
                &PersonalBackendUpdate {
                    headers: Some((Vec::new(), None)),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bare.header_names, Vec::<String>::new());
        assert_eq!(bare.secret, None);

        assert!(
            store
                .update_personal_backend(alice, "missing", &PersonalBackendUpdate::default())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn outcomes_stay_quiet_and_config_changes_notify() {
        let Some(store) = test_store("axon_personal_notify").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let mut listener = store.listen_changes().await.unwrap();
        let schema = store.current_schema().await.unwrap();

        let created = store
            .create_personal_backend(&new_backend(alice, "prom", None))
            .await
            .unwrap();
        let change = next_change(&mut listener, &schema).await;
        assert_eq!(change["kind"], "user");
        assert_eq!(change["user"], alice.to_string());

        store
            .record_personal_outcome(created.id, None)
            .await
            .unwrap();
        store
            .record_personal_outcome(created.id, Some(&"e".repeat(900)))
            .await
            .unwrap();
        let quiet = change_within(&mut listener, &schema, Duration::from_millis(500)).await;
        assert_eq!(quiet, None, "an outcome update must not notify");

        let found = store
            .personal_backend(alice, "prom")
            .await
            .unwrap()
            .unwrap();
        assert!(found.last_ok_at.is_some());
        assert!(found.last_error_at.is_some());
        assert_eq!(found.last_error.unwrap().chars().count(), MAX_ERROR_CHARS);

        store
            .update_personal_backend(
                alice,
                "prom",
                &PersonalBackendUpdate {
                    enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let change = next_change(&mut listener, &schema).await;
        assert_eq!(change["kind"], "user");
        assert_eq!(change["user"], alice.to_string());
    }

    #[tokio::test]
    async fn catalog_round_trip_and_delete_drops_credentials() {
        let Some(store) = test_store("axon_personal_catalog").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let mut listener = store.listen_changes().await.unwrap();
        let schema = store.current_schema().await.unwrap();

        let created = store
            .create_catalog_entry(&new_entry("zulip"))
            .await
            .unwrap();
        assert_eq!(created.credential_fields.len(), 1);
        assert_eq!(created.credential_fields[0].name, "token");
        assert!(created.enabled);
        assert_eq!(created.created_by.as_deref(), Some("admin"));
        let change = next_change(&mut listener, &schema).await;
        assert_eq!(change["kind"], "catalog");
        assert!(change.get("user").is_none());
        store
            .create_catalog_entry(&new_entry("atlas"))
            .await
            .unwrap();
        assert!(matches!(
            store.create_catalog_entry(&new_entry("zulip")).await,
            Err(PersonalError::Exists)
        ));

        let names: Vec<_> = store
            .list_catalog_entries()
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["atlas", "zulip"]);

        // unspecified fields stay, a description can be cleared
        let updated = store
            .update_catalog_entry(
                "zulip",
                &CatalogEntryUpdate {
                    enabled: Some(false),
                    credential_fields: Some(vec![field("key"), field("secret")]),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.credential_fields.len(), 2);
        assert_eq!(updated.url, created.url);
        assert_eq!(updated.description.as_deref(), Some("a catalog backend"));
        let cleared = store
            .update_catalog_entry(
                "zulip",
                &CatalogEntryUpdate {
                    description: Some(String::new()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cleared.description, None);
        assert_eq!(cleared.credential_fields.len(), 2);
        assert!(
            store
                .update_catalog_entry("missing", &CatalogEntryUpdate::default())
                .await
                .unwrap()
                .is_none()
        );

        store
            .set_user_credential(alice, "zulip", &sealed(1))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "atlas", &sealed(2))
            .await
            .unwrap();
        assert!(store.delete_catalog_entry("zulip").await.unwrap());
        assert!(!store.delete_catalog_entry("zulip").await.unwrap());
        assert!(store.catalog_entry("zulip").await.unwrap().is_none());
        let left = store.list_user_credentials(alice).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].backend, "atlas");
    }

    #[tokio::test]
    async fn credentials_upsert_and_record_outcomes() {
        let Some(store) = test_store("axon_personal_credentials").await else {
            return;
        };
        let alice = user(&store, "alice").await;

        store
            .set_user_credential(alice, "zulip", &sealed(1))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "atlas", &sealed(2))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "zulip", &sealed(3))
            .await
            .unwrap();

        let listed = store.list_user_credentials(alice).await.unwrap();
        let backends: Vec<_> = listed.iter().map(|c| c.backend.as_str()).collect();
        assert_eq!(backends, ["atlas", "zulip"]);
        assert_eq!(listed[1].secret, sealed(3));

        store
            .record_credential_outcome(alice, "zulip", None)
            .await
            .unwrap();
        store
            .record_credential_outcome(alice, "zulip", Some("401 unauthorized"))
            .await
            .unwrap();
        let listed = store.list_user_credentials(alice).await.unwrap();
        assert!(listed[1].last_ok_at.is_some());
        assert!(listed[1].last_error_at.is_some());
        assert_eq!(listed[1].last_error.as_deref(), Some("401 unauthorized"));
        assert!(listed[0].last_ok_at.is_none());

        assert!(store.delete_user_credential(alice, "zulip").await.unwrap());
        assert!(!store.delete_user_credential(alice, "zulip").await.unwrap());
        assert_eq!(store.list_user_credentials(alice).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn counts_personal_backends_and_credentials() {
        let Some(store) = test_store("axon_personal_count").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let bob = user(&store, "bob").await;
        assert_eq!(store.count_user_backends(alice).await.unwrap(), 0);

        store
            .create_personal_backend(&new_backend(alice, "one", None))
            .await
            .unwrap();
        store
            .create_personal_backend(&new_backend(alice, "two", None))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "zulip", &sealed(1))
            .await
            .unwrap();
        store
            .set_user_credential(bob, "zulip", &sealed(2))
            .await
            .unwrap();
        assert_eq!(store.count_user_backends(alice).await.unwrap(), 3);
        assert_eq!(store.count_user_backends(bob).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn sealed_secrets_are_listed_and_replaced() {
        let Some(store) = test_store("axon_personal_rotation").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        let with_secret = store
            .create_personal_backend(&new_backend(alice, "sealed", Some(sealed(1))))
            .await
            .unwrap();
        store
            .create_personal_backend(&new_backend(alice, "plain", None))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "zulip", &sealed(2))
            .await
            .unwrap();

        let secrets = store.sealed_secrets().await.unwrap();
        assert_eq!(secrets.len(), 2);
        let personal = SecretRef::Personal(with_secret.id);
        let credential = SecretRef::Credential {
            user_id: alice,
            backend: "zulip".to_string(),
        };
        assert!(secrets.contains(&(personal.clone(), sealed(1))));
        assert!(secrets.contains(&(credential.clone(), sealed(2))));

        assert!(store.replace_sealed(&personal, &sealed(7)).await.unwrap());
        assert!(store.replace_sealed(&credential, &sealed(8)).await.unwrap());
        let found = store
            .personal_backend(alice, "sealed")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.secret, Some(sealed(7)));
        let listed = store.list_user_credentials(alice).await.unwrap();
        assert_eq!(listed[0].secret, sealed(8));

        let gone = SecretRef::Credential {
            user_id: alice,
            backend: "missing".to_string(),
        };
        assert!(!store.replace_sealed(&gone, &sealed(9)).await.unwrap());
        assert!(
            !store
                .replace_sealed(&SecretRef::Personal(Uuid::nil()), &sealed(9))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_cascades() {
        let Some(store) = test_store("axon_personal_cascade").await else {
            return;
        };
        let alice = user(&store, "alice").await;
        store
            .create_personal_backend(&new_backend(alice, "prom", Some(sealed(1))))
            .await
            .unwrap();
        store
            .set_user_credential(alice, "zulip", &sealed(2))
            .await
            .unwrap();

        sqlx::query("delete from users where id = $1")
            .bind(alice)
            .execute(&store.pool)
            .await
            .unwrap();
        assert!(
            store
                .list_personal_backends(alice)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(store.list_user_credentials(alice).await.unwrap().is_empty());
        assert_eq!(store.count_user_backends(alice).await.unwrap(), 0);
    }
}
