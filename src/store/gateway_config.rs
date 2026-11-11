//! The gateway's configuration in the database: backends, gateway toolsets,
//! OIDC providers and the global settings
//!
//! Each row keeps its config type as JSON in `spec`, without secret values; the
//! secrets of a backend or provider are sealed in the `secret_*` columns. The
//! store only moves the three parts of a sealed secret (see `crypto`), it never
//! sees plaintext. Every write runs in one transaction together with its
//! `audit_log` row, and every write bumps `gateway_config_state.version` and
//! notifies the other replicas (the migration's trigger does both).

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::FromRow;
use sqlx::types::Json;
use thiserror::Error;

use super::personal::{SealedColumns, SecretUpdate};
use super::rbac::{Actor, audit};
use super::{Store, StoreError};
use crate::config::{BackendConfig, GatewaySettings, OidcProviderConfig, ToolsetConfig};

const BACKEND_COLUMNS: &str =
    "name, spec, secret_kek_id, secret_dek, secret_data, created_at, updated_at";
const TOOLSET_COLUMNS: &str = "name, spec, created_at, updated_at";
const PROVIDER_COLUMNS: &str =
    "id, position, spec, secret_kek_id, secret_dek, secret_data, created_at, updated_at";

/// Errors from creating configuration rows
#[derive(Debug, Error)]
pub enum GatewayConfigError {
    #[error("already exists")]
    Exists,

    #[error(transparent)]
    Store(#[from] StoreError),
}

fn map_unique(error: sqlx::Error) -> GatewayConfigError {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => GatewayConfigError::Exists,
        _ => GatewayConfigError::Store(StoreError::Query(error)),
    }
}

fn query_error(error: sqlx::Error) -> GatewayConfigError {
    GatewayConfigError::Store(StoreError::Query(error))
}

fn sealed_columns(
    kek_id: Option<String>,
    dek: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
) -> Option<SealedColumns> {
    match (kek_id, dek, data) {
        (Some(kek_id), Some(dek), Some(data)) => Some(SealedColumns { kek_id, dek, data }),
        _ => None,
    }
}

/// The bound values of a [`SecretUpdate`]: whether to write the columns at all,
/// then the three parts (all `None` clears them)
type SecretBinds<'a> = (bool, Option<&'a str>, Option<&'a [u8]>, Option<&'a [u8]>);

fn secret_binds(update: &SecretUpdate) -> SecretBinds<'_> {
    match update {
        SecretUpdate::Keep => (false, None, None, None),
        SecretUpdate::Clear => (true, None, None, None),
        SecretUpdate::Set(secret) => (
            true,
            Some(secret.kek_id.as_str()),
            Some(secret.dek.as_slice()),
            Some(secret.data.as_slice()),
        ),
    }
}

/// A backend as stored: the spec holds no secret values
#[derive(Debug, Clone)]
pub struct GatewayBackendRow {
    pub name: String,
    /// A [`BackendConfig`] as JSON, secrets blanked
    pub spec: Value,
    /// The sealed secrets; `None` when the backend has none
    pub secret: Option<SealedColumns>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct BackendRow {
    name: String,
    spec: Value,
    secret_kek_id: Option<String>,
    secret_dek: Option<Vec<u8>>,
    secret_data: Option<Vec<u8>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<BackendRow> for GatewayBackendRow {
    fn from(row: BackendRow) -> Self {
        Self {
            name: row.name,
            spec: row.spec,
            secret: sealed_columns(row.secret_kek_id, row.secret_dek, row.secret_data),
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// A gateway toolset as stored
#[derive(Debug, Clone, FromRow)]
pub struct GatewayToolsetRow {
    pub name: String,
    /// A [`ToolsetConfig`] as JSON
    pub spec: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An OIDC provider as stored: the spec holds no client secret
#[derive(Debug, Clone)]
pub struct OidcProviderRow {
    pub id: String,
    /// Sort key of the login buttons, lowest first
    pub position: i32,
    /// An [`OidcProviderConfig`] as JSON, `client_secret_env` blanked
    pub spec: Value,
    /// The sealed client secret; `None` for a public client
    pub secret: Option<SealedColumns>,
    pub updated_at: DateTime<Utc>,
}

#[derive(FromRow)]
struct ProviderRow {
    id: String,
    position: i32,
    spec: Value,
    secret_kek_id: Option<String>,
    secret_dek: Option<Vec<u8>>,
    secret_data: Option<Vec<u8>>,
    updated_at: DateTime<Utc>,
}

impl From<ProviderRow> for OidcProviderRow {
    fn from(row: ProviderRow) -> Self {
        Self {
            id: row.id,
            position: row.position,
            spec: row.spec,
            secret: sealed_columns(row.secret_kek_id, row.secret_dek, row.secret_data),
            updated_at: row.updated_at,
        }
    }
}

/// The global settings row
#[derive(Debug, Clone, FromRow)]
pub struct GatewaySettingsRow {
    /// A [`GatewaySettings`] as JSON
    pub spec: Value,
}

/// Where a sealed configuration secret lives, for key rotation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSecretRef {
    Backend(String),
    OidcProvider(String),
}

#[derive(FromRow)]
struct SealedConfigRow {
    key: String,
    secret_kek_id: String,
    secret_dek: Vec<u8>,
    secret_data: Vec<u8>,
}

impl Store {
    /// Every backend, by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_gateway_backends(&self) -> Result<Vec<GatewayBackendRow>, StoreError> {
        let rows: Vec<BackendRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {BACKEND_COLUMNS} from gateway_backends order by name"
        )))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// One backend by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn gateway_backend(
        &self,
        name: &str,
    ) -> Result<Option<GatewayBackendRow>, StoreError> {
        let row: Option<BackendRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {BACKEND_COLUMNS} from gateway_backends where name = $1"
        )))
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Creates a backend named `spec.name`; `secret_keys` names the secret
    /// values set (for the audit row, never their content).
    ///
    /// # Errors
    /// Fails with [`GatewayConfigError::Exists`] when the name is taken, or when
    /// the transaction fails.
    pub async fn create_gateway_backend(
        &self,
        actor: &Actor,
        spec: &BackendConfig,
        secret: Option<&SealedColumns>,
        secret_keys: &[String],
    ) -> Result<GatewayBackendRow, GatewayConfigError> {
        let mut tx = self.pool.begin().await.map_err(query_error)?;
        let row: BackendRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into gateway_backends \
             (name, spec, secret_kek_id, secret_dek, secret_data) \
             values ($1, $2, $3, $4, $5) returning {BACKEND_COLUMNS}"
        )))
        .bind(&spec.name)
        .bind(Json(spec))
        .bind(secret.map(|s| s.kek_id.as_str()))
        .bind(secret.map(|s| s.dek.as_slice()))
        .bind(secret.map(|s| s.data.as_slice()))
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique)?;
        audit(
            &mut tx,
            actor,
            "backend.create",
            &format!("backend:{}", spec.name),
            json!({ "secrets": secret_keys }),
        )
        .await?;
        tx.commit().await.map_err(query_error)?;
        Ok(row.into())
    }

    /// Replaces the spec of backend `name` and applies `secret`. `None` when
    /// there is no such backend.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn update_gateway_backend(
        &self,
        actor: &Actor,
        name: &str,
        spec: &BackendConfig,
        secret: &SecretUpdate,
        secret_keys: &[String],
    ) -> Result<Option<GatewayBackendRow>, StoreError> {
        let (write, kek_id, dek, data) = secret_binds(secret);
        let mut tx = self.pool.begin().await?;
        let row: Option<BackendRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "update gateway_backends set spec = $2, \
             secret_kek_id = case when $3 then $4::text else secret_kek_id end, \
             secret_dek = case when $3 then $5::bytea else secret_dek end, \
             secret_data = case when $3 then $6::bytea else secret_data end, \
             updated_at = now() \
             where name = $1 returning {BACKEND_COLUMNS}"
        )))
        .bind(name)
        .bind(Json(spec))
        .bind(write)
        .bind(kek_id)
        .bind(dek)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        audit(
            &mut tx,
            actor,
            "backend.update",
            &format!("backend:{name}"),
            json!({ "secrets": secret_keys }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(row.into()))
    }

    /// Deletes a backend. `false` when there is no such backend.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_gateway_backend(
        &self,
        actor: &Actor,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("delete from gateway_backends where name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "backend.delete",
            &format!("backend:{name}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Every gateway toolset, by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_gateway_toolsets(&self) -> Result<Vec<GatewayToolsetRow>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {TOOLSET_COLUMNS} from gateway_toolsets order by name"
        )))
        .fetch_all(&self.pool)
        .await?)
    }

    /// One gateway toolset by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn gateway_toolset(
        &self,
        name: &str,
    ) -> Result<Option<GatewayToolsetRow>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {TOOLSET_COLUMNS} from gateway_toolsets where name = $1"
        )))
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Creates a toolset named `spec.name`.
    ///
    /// # Errors
    /// Fails with [`GatewayConfigError::Exists`] when the name is taken, or when
    /// the transaction fails.
    pub async fn create_gateway_toolset(
        &self,
        actor: &Actor,
        spec: &ToolsetConfig,
    ) -> Result<GatewayToolsetRow, GatewayConfigError> {
        let mut tx = self.pool.begin().await.map_err(query_error)?;
        let row: GatewayToolsetRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into gateway_toolsets (name, spec) values ($1, $2) \
             returning {TOOLSET_COLUMNS}"
        )))
        .bind(&spec.name)
        .bind(Json(spec))
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique)?;
        audit(
            &mut tx,
            actor,
            "toolset.create",
            &format!("toolset:{}", spec.name),
            json!({}),
        )
        .await?;
        tx.commit().await.map_err(query_error)?;
        Ok(row)
    }

    /// Replaces the spec of toolset `name`. `None` when there is no such toolset.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn update_gateway_toolset(
        &self,
        actor: &Actor,
        name: &str,
        spec: &ToolsetConfig,
    ) -> Result<Option<GatewayToolsetRow>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<GatewayToolsetRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "update gateway_toolsets set spec = $2, updated_at = now() \
             where name = $1 returning {TOOLSET_COLUMNS}"
        )))
        .bind(name)
        .bind(Json(spec))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        audit(
            &mut tx,
            actor,
            "toolset.update",
            &format!("toolset:{name}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(row))
    }

    /// Deletes a toolset. `false` when there is no such toolset.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_gateway_toolset(
        &self,
        actor: &Actor,
        name: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("delete from gateway_toolsets where name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "toolset.delete",
            &format!("toolset:{name}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Every OIDC provider, by position then id.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_oidc_providers(&self) -> Result<Vec<OidcProviderRow>, StoreError> {
        let rows: Vec<ProviderRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {PROVIDER_COLUMNS} from oidc_providers order by position, id"
        )))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// One OIDC provider by id.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn oidc_provider(&self, id: &str) -> Result<Option<OidcProviderRow>, StoreError> {
        let row: Option<ProviderRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {PROVIDER_COLUMNS} from oidc_providers where id = $1"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Creates a provider with id `spec.id`; `position` `None` puts it last.
    ///
    /// # Errors
    /// Fails with [`GatewayConfigError::Exists`] when the id is taken, or when
    /// the transaction fails.
    pub async fn create_oidc_provider(
        &self,
        actor: &Actor,
        spec: &OidcProviderConfig,
        position: Option<i32>,
        secret: Option<&SealedColumns>,
    ) -> Result<OidcProviderRow, GatewayConfigError> {
        let mut tx = self.pool.begin().await.map_err(query_error)?;
        let row: ProviderRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into oidc_providers \
             (id, position, spec, secret_kek_id, secret_dek, secret_data) \
             values ($1, coalesce($2, (select coalesce(max(position), -1) + 1 from oidc_providers)), \
                     $3, $4, $5, $6) \
             returning {PROVIDER_COLUMNS}"
        )))
        .bind(&spec.id)
        .bind(position)
        .bind(Json(spec))
        .bind(secret.map(|s| s.kek_id.as_str()))
        .bind(secret.map(|s| s.dek.as_slice()))
        .bind(secret.map(|s| s.data.as_slice()))
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique)?;
        audit(
            &mut tx,
            actor,
            "oidc_provider.create",
            &format!("oidc_provider:{}", spec.id),
            json!({ "secret_set": secret.is_some() }),
        )
        .await?;
        tx.commit().await.map_err(query_error)?;
        Ok(row.into())
    }

    /// Replaces the spec of provider `id` and applies `secret`; `position`
    /// `None` keeps the stored one. `None` when there is no such provider.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn update_oidc_provider(
        &self,
        actor: &Actor,
        id: &str,
        spec: &OidcProviderConfig,
        position: Option<i32>,
        secret: &SecretUpdate,
    ) -> Result<Option<OidcProviderRow>, StoreError> {
        let (write, kek_id, dek, data) = secret_binds(secret);
        let mut tx = self.pool.begin().await?;
        let row: Option<ProviderRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "update oidc_providers set spec = $2, position = coalesce($3, position), \
             secret_kek_id = case when $4 then $5::text else secret_kek_id end, \
             secret_dek = case when $4 then $6::bytea else secret_dek end, \
             secret_data = case when $4 then $7::bytea else secret_data end, \
             updated_at = now() \
             where id = $1 returning {PROVIDER_COLUMNS}"
        )))
        .bind(id)
        .bind(Json(spec))
        .bind(position)
        .bind(write)
        .bind(kek_id)
        .bind(dek)
        .bind(data)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let secret_change = match secret {
            SecretUpdate::Keep => "kept",
            SecretUpdate::Clear => "cleared",
            SecretUpdate::Set(_) => "set",
        };
        audit(
            &mut tx,
            actor,
            "oidc_provider.update",
            &format!("oidc_provider:{id}"),
            json!({ "secret": secret_change }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(row.into()))
    }

    /// Deletes a provider. `false` when there is no such provider.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_oidc_provider(&self, actor: &Actor, id: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("delete from oidc_providers where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "oidc_provider.delete",
            &format!("oidc_provider:{id}"),
            json!({}),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// The global settings; `None` until they were first saved (the defaults apply).
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn gateway_settings(&self) -> Result<Option<GatewaySettingsRow>, StoreError> {
        Ok(
            sqlx::query_as("select spec, updated_at from gateway_settings where id = 1")
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Saves the global settings.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn put_gateway_settings(
        &self,
        actor: &Actor,
        settings: &GatewaySettings,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into gateway_settings (id, spec) values (1, $1) \
             on conflict (id) do update set spec = excluded.spec, updated_at = now()",
        )
        .bind(Json(settings))
        .execute(&mut *tx)
        .await?;
        audit(&mut tx, actor, "settings.update", "settings", json!({})).await?;
        tx.commit().await?;
        Ok(())
    }

    /// The configuration version: it grows with every change to the four
    /// configuration tables, so a replica that missed a notification notices.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn config_version(&self) -> Result<i64, StoreError> {
        Ok(
            sqlx::query_scalar("select version from gateway_config_state where id = 1")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    /// Every sealed secret of the configuration tables, for key rotation.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn config_sealed_secrets(
        &self,
    ) -> Result<Vec<(ConfigSecretRef, SealedColumns)>, StoreError> {
        let backends: Vec<SealedConfigRow> = sqlx::query_as(
            "select name as key, secret_kek_id, secret_dek, secret_data from gateway_backends \
             where secret_kek_id is not null order by name",
        )
        .fetch_all(&self.pool)
        .await?;
        let providers: Vec<SealedConfigRow> = sqlx::query_as(
            "select id as key, secret_kek_id, secret_dek, secret_data from oidc_providers \
             where secret_kek_id is not null order by id",
        )
        .fetch_all(&self.pool)
        .await?;

        let sealed = |row: &SealedConfigRow| SealedColumns {
            kek_id: row.secret_kek_id.clone(),
            dek: row.secret_dek.clone(),
            data: row.secret_data.clone(),
        };
        let mut secrets: Vec<(ConfigSecretRef, SealedColumns)> = backends
            .iter()
            .map(|row| (ConfigSecretRef::Backend(row.key.clone()), sealed(row)))
            .collect();
        secrets.extend(
            providers
                .iter()
                .map(|row| (ConfigSecretRef::OidcProvider(row.key.clone()), sealed(row))),
        );
        Ok(secrets)
    }

    /// Replaces one sealed configuration secret. `false` when it no longer exists.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn replace_config_sealed(
        &self,
        target: &ConfigSecretRef,
        sealed: &SealedColumns,
    ) -> Result<bool, StoreError> {
        let (table, key_column, key) = match target {
            ConfigSecretRef::Backend(name) => ("gateway_backends", "name", name),
            ConfigSecretRef::OidcProvider(id) => ("oidc_providers", "id", id),
        };
        let result = sqlx::query(sqlx::AssertSqlSafe(format!(
            "update {table} set secret_kek_id = $2, secret_dek = $3, secret_data = $4 \
             where {key_column} = $1 and secret_kek_id is not null"
        )))
        .bind(key)
        .bind(&sealed.kek_id)
        .bind(&sealed.dek)
        .bind(&sealed.data)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{database_url, isolated_url};
    use super::*;

    async fn test_store(schema: &str) -> Option<Store> {
        let Some(base) = database_url() else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;
        Some(Store::connect_url(&url).await.unwrap())
    }

    fn actor() -> Actor {
        Actor {
            user_id: None,
            label: "test".to_owned(),
        }
    }

    fn sealed(tag: u8) -> SealedColumns {
        SealedColumns {
            kek_id: format!("k{tag}"),
            dek: vec![tag; 4],
            data: vec![tag; 8],
        }
    }

    fn backend(name: &str) -> BackendConfig {
        BackendConfig {
            name: name.to_owned(),
            url: Some("http://localhost:9000/mcp".to_owned()),
            ..BackendConfig::default()
        }
    }

    #[tokio::test]
    async fn backends_round_trip_with_audit_and_version() {
        let Some(store) = test_store("axon_store_gateway_backends").await else {
            return;
        };
        let before = store.config_version().await.unwrap();

        let created = store
            .create_gateway_backend(&actor(), &backend("wiki"), Some(&sealed(1)), &[])
            .await
            .unwrap();
        assert_eq!(created.secret, Some(sealed(1)));
        let again = store
            .create_gateway_backend(&actor(), &backend("wiki"), None, &[])
            .await;
        assert!(matches!(again, Err(GatewayConfigError::Exists)));

        let updated = store
            .update_gateway_backend(&actor(), "wiki", &backend("wiki"), &SecretUpdate::Keep, &[])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.secret, Some(sealed(1)), "keep leaves the secret");
        let cleared = store
            .update_gateway_backend(
                &actor(),
                "wiki",
                &backend("wiki"),
                &SecretUpdate::Clear,
                &[],
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cleared.secret, None);
        assert!(store.config_version().await.unwrap() > before);

        assert!(
            store
                .delete_gateway_backend(&actor(), "wiki")
                .await
                .unwrap()
        );
        assert!(
            !store
                .delete_gateway_backend(&actor(), "wiki")
                .await
                .unwrap()
        );
        assert!(store.list_gateway_backends().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn providers_list_by_position_then_id() {
        let Some(store) = test_store("axon_store_oidc_providers").await else {
            return;
        };
        let provider = |id: &str| OidcProviderConfig {
            id: id.to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            client_id: "cid".to_owned(),
            ..OidcProviderConfig::default()
        };
        for (id, position) in [("b", Some(1)), ("a", Some(1)), ("c", None)] {
            store
                .create_oidc_provider(&actor(), &provider(id), position, None)
                .await
                .unwrap();
        }
        let ids: Vec<String> = store
            .list_oidc_providers()
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
    }

    #[tokio::test]
    async fn sealed_secrets_list_and_replace() {
        let Some(store) = test_store("axon_store_config_sealed").await else {
            return;
        };
        store
            .create_gateway_backend(&actor(), &backend("wiki"), Some(&sealed(1)), &[])
            .await
            .unwrap();
        store
            .create_gateway_backend(&actor(), &backend("plain"), None, &[])
            .await
            .unwrap();

        let secrets = store.config_sealed_secrets().await.unwrap();
        assert_eq!(
            secrets,
            [(ConfigSecretRef::Backend("wiki".to_owned()), sealed(1))]
        );
        let target = ConfigSecretRef::Backend("wiki".to_owned());
        assert!(
            store
                .replace_config_sealed(&target, &sealed(2))
                .await
                .unwrap()
        );
        let gone = ConfigSecretRef::OidcProvider("nope".to_owned());
        assert!(
            !store
                .replace_config_sealed(&gone, &sealed(2))
                .await
                .unwrap()
        );
    }
}
