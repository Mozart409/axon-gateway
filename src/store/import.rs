//! The writes of `admin import-config`
//!
//! Every function runs on one connection (the import's transaction) instead of
//! opening its own, and reports whether the row was created, updated or already
//! what the file says. They write no audit row of their own: the import writes
//! one `config.import` row for the whole run.

use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use super::personal::{SealedColumns, SecretUpdate};
use super::rbac::{Actor, audit};
use super::tokens::{MAX_SERVICE_TOKEN_LIFETIME, PAT_PREFIX, hash_secret, random_hex};
use super::{Store, StoreError};
use crate::config::{BackendConfig, GatewaySettings, OidcProviderConfig, ToolsetConfig};
use crate::policy::{GrantConfig, Permission};

/// The `issuer` of every service account, as in `tokens.rs`
const SERVICE_ISSUER: &str = "axon:service-account";

/// What an import step did to one row
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Updated,
    /// The row already was what the file says
    Unchanged,
}

/// The `returning (xmax = 0)` of an upsert that only touches a row when it
/// differs: `true` inserted, `false` updated, no row left alone
fn change(inserted: Option<bool>) -> Change {
    match inserted {
        Some(true) => Change::Created,
        Some(false) => Change::Updated,
        None => Change::Unchanged,
    }
}

/// A created or already existing row
fn created(inserted: bool) -> Change {
    if inserted {
        Change::Created
    } else {
        Change::Unchanged
    }
}

type SealedParts = (Option<String>, Option<Vec<u8>>, Option<Vec<u8>>);

fn sealed_from(parts: Option<SealedParts>) -> Option<SealedColumns> {
    match parts {
        Some((Some(kek_id), Some(dek), Some(data))) => Some(SealedColumns { kek_id, dek, data }),
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

/// The actor of the CLI commands, for the audit log
#[must_use]
pub fn cli_actor() -> Actor {
    Actor {
        user_id: None,
        label: "cli".to_owned(),
    }
}

impl Store {
    /// Starts the transaction the whole import runs in; dropping it without a
    /// commit rolls everything back.
    ///
    /// # Errors
    /// Fails when no connection can be had.
    pub async fn begin_import(
        &self,
    ) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, StoreError> {
        Ok(self.pool.begin().await?)
    }
}

/// Saves the global settings.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_settings(
    conn: &mut PgConnection,
    settings: &GatewaySettings,
) -> Result<Change, StoreError> {
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into gateway_settings (id, spec) values (1, $1) \
         on conflict (id) do update set spec = excluded.spec, updated_at = now() \
         where gateway_settings.spec is distinct from excluded.spec \
         returning (xmax = 0)",
    )
    .bind(Json(settings))
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// The sealed secrets of backend `name`; `None` when it has none or does not exist.
///
/// # Errors
/// Fails when the query fails.
pub async fn stored_backend_secret(
    conn: &mut PgConnection,
    name: &str,
) -> Result<Option<SealedColumns>, StoreError> {
    let parts: Option<SealedParts> = sqlx::query_as(
        "select secret_kek_id, secret_dek, secret_data from gateway_backends where name = $1",
    )
    .bind(name)
    .fetch_optional(conn)
    .await?;
    Ok(sealed_from(parts))
}

/// Creates or updates backend `spec.name`; `secret` says what happens to the
/// sealed secrets (`Keep` leaves them, and the row alone decides the change).
///
/// # Errors
/// Fails when the query fails.
pub async fn import_backend(
    conn: &mut PgConnection,
    spec: &BackendConfig,
    secret: &SecretUpdate,
) -> Result<Change, StoreError> {
    let (write, kek_id, dek, data) = secret_binds(secret);
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into gateway_backends (name, spec, secret_kek_id, secret_dek, secret_data) \
         values ($1, $2, $4, $5, $6) \
         on conflict (name) do update set spec = excluded.spec, \
         secret_kek_id = case when $3 then excluded.secret_kek_id \
                         else gateway_backends.secret_kek_id end, \
         secret_dek = case when $3 then excluded.secret_dek \
                      else gateway_backends.secret_dek end, \
         secret_data = case when $3 then excluded.secret_data \
                       else gateway_backends.secret_data end, \
         updated_at = now() \
         where gateway_backends.spec is distinct from excluded.spec or $3 \
         returning (xmax = 0)",
    )
    .bind(&spec.name)
    .bind(Json(spec))
    .bind(write)
    .bind(kek_id)
    .bind(dek)
    .bind(data)
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// Creates or updates gateway toolset `spec.name`.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_toolset(
    conn: &mut PgConnection,
    spec: &ToolsetConfig,
) -> Result<Change, StoreError> {
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into gateway_toolsets (name, spec) values ($1, $2) \
         on conflict (name) do update set spec = excluded.spec, updated_at = now() \
         where gateway_toolsets.spec is distinct from excluded.spec \
         returning (xmax = 0)",
    )
    .bind(&spec.name)
    .bind(Json(spec))
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// The sealed client secret of provider `id`; `None` when it has none or does
/// not exist.
///
/// # Errors
/// Fails when the query fails.
pub async fn stored_provider_secret(
    conn: &mut PgConnection,
    id: &str,
) -> Result<Option<SealedColumns>, StoreError> {
    let parts: Option<SealedParts> = sqlx::query_as(
        "select secret_kek_id, secret_dek, secret_data from oidc_providers where id = $1",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?;
    Ok(sealed_from(parts))
}

/// Creates or updates provider `spec.id` at `position`; `secret` as for
/// [`import_backend`].
///
/// # Errors
/// Fails when the query fails.
pub async fn import_oidc_provider(
    conn: &mut PgConnection,
    spec: &OidcProviderConfig,
    position: i32,
    secret: &SecretUpdate,
) -> Result<Change, StoreError> {
    let (write, kek_id, dek, data) = secret_binds(secret);
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into oidc_providers (id, position, spec, secret_kek_id, secret_dek, secret_data) \
         values ($1, $2, $3, $5, $6, $7) \
         on conflict (id) do update set spec = excluded.spec, position = excluded.position, \
         secret_kek_id = case when $4 then excluded.secret_kek_id \
                         else oidc_providers.secret_kek_id end, \
         secret_dek = case when $4 then excluded.secret_dek \
                      else oidc_providers.secret_dek end, \
         secret_data = case when $4 then excluded.secret_data \
                       else oidc_providers.secret_data end, \
         updated_at = now() \
         where oidc_providers.spec is distinct from excluded.spec \
            or oidc_providers.position <> excluded.position or $4 \
         returning (xmax = 0)",
    )
    .bind(&spec.id)
    .bind(position)
    .bind(Json(spec))
    .bind(write)
    .bind(kek_id)
    .bind(dek)
    .bind(data)
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// Creates group `name` or sets its description.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_group(
    conn: &mut PgConnection,
    name: &str,
    description: Option<&str>,
) -> Result<Change, StoreError> {
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into rbac_groups (name, description) values ($1, $2) \
         on conflict (name) do update set description = excluded.description \
         where rbac_groups.description is distinct from excluded.description \
         returning (xmax = 0)",
    )
    .bind(name)
    .bind(description)
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// Maps an `IdP` claim value to `group`, which must exist.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_idp_mapping(
    conn: &mut PgConnection,
    group: &str,
    provider: &str,
    value: &str,
) -> Result<Change, StoreError> {
    let result = sqlx::query(
        "insert into rbac_group_idp_mappings (group_name, provider, value) values ($1, $2, $3) \
         on conflict do nothing",
    )
    .bind(group)
    .bind(provider)
    .bind(value)
    .execute(conn)
    .await?;
    Ok(created(result.rows_affected() > 0))
}

/// Adds a grant unless an identical one exists.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_grant(
    conn: &mut PgConnection,
    grant: &GrantConfig,
) -> Result<Change, StoreError> {
    let result = sqlx::query(
        "insert into rbac_grants (group_name, backend, include, exclude, read_only, mandatory) \
         select $1::text, $2::text, $3::text[], $4::text[], $5::boolean, $6::boolean \
         where not exists ( \
             select 1 from rbac_grants \
             where group_name = $1 and backend = $2 and include = $3 and exclude = $4 \
               and read_only = $5 and mandatory = $6)",
    )
    .bind(&grant.group)
    .bind(&grant.backend)
    .bind(grant.include.as_slice())
    .bind(grant.exclude.as_slice())
    .bind(grant.read_only)
    .bind(grant.mandatory)
    .execute(conn)
    .await?;
    Ok(created(result.rows_affected() > 0))
}

/// Creates a custom role or replaces its description and permissions.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_role(
    conn: &mut PgConnection,
    name: &str,
    description: Option<&str>,
    permissions: &[Permission],
) -> Result<Change, StoreError> {
    let names: Vec<&str> = permissions
        .iter()
        .copied()
        .map(Permission::as_str)
        .collect();
    let inserted: Option<bool> = sqlx::query_scalar(
        "insert into rbac_roles (name, description, permissions) values ($1, $2, $3) \
         on conflict (name) do update set description = excluded.description, \
         permissions = excluded.permissions, updated_at = now() \
         where rbac_roles.description is distinct from excluded.description \
            or rbac_roles.permissions is distinct from excluded.permissions \
         returning (xmax = 0)",
    )
    .bind(name)
    .bind(description)
    .bind(names.as_slice())
    .fetch_optional(conn)
    .await?;
    Ok(change(inserted))
}

/// Binds `role` to `group`.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_role_binding(
    conn: &mut PgConnection,
    role: &str,
    group: &str,
) -> Result<Change, StoreError> {
    let id: Option<i64> = sqlx::query_scalar(
        "insert into rbac_role_bindings (role, group_name) values ($1, $2) \
         on conflict do nothing returning id",
    )
    .bind(role)
    .bind(group)
    .fetch_optional(conn)
    .await?;
    Ok(created(id.is_some()))
}

/// The service account `name`, created when missing; `true` when it was created.
///
/// # Errors
/// Fails when a query fails.
pub async fn import_service_account(
    conn: &mut PgConnection,
    name: &str,
) -> Result<(Uuid, bool), StoreError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "insert into users (issuer, subject, display_name, kind) \
         values ($1, $2, $2, 'service') \
         on conflict (issuer, subject) do nothing returning id",
    )
    .bind(SERVICE_ISSUER)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(id) = id {
        return Ok((id, true));
    }
    let id: Uuid = sqlx::query_scalar(
        "select id from users where issuer = $1 and subject = $2 and kind = 'service'",
    )
    .bind(SERVICE_ISSUER)
    .bind(name)
    .fetch_one(conn)
    .await?;
    Ok((id, false))
}

/// Puts `user_id` into `group`, which must exist.
///
/// # Errors
/// Fails when the query fails.
pub async fn import_membership(
    conn: &mut PgConnection,
    group: &str,
    user_id: Uuid,
) -> Result<Change, StoreError> {
    let result = sqlx::query(
        "insert into rbac_memberships (group_name, user_id) values ($1, $2) on conflict do nothing",
    )
    .bind(group)
    .bind(user_id)
    .execute(conn)
    .await?;
    Ok(created(result.rows_affected() > 0))
}

/// Issues a token named `name` to a service account, valid for the longest
/// time a service token may live, and returns its plaintext. The `config.import`
/// row covers it in the audit log.
///
/// # Errors
/// Fails when randomness or a query fails.
pub async fn import_service_token(
    conn: &mut PgConnection,
    owner_id: Uuid,
    name: &str,
) -> Result<String, StoreError> {
    let public_id = random_hex::<8>()?;
    let secret = random_hex::<32>()?;
    let no_scope: &[String] = &[];
    sqlx::query(
        "insert into api_tokens \
         (public_id, secret_hash, owner_id, name, scope_backends, scope_tools, expires_at) \
         values ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
    )
    .bind(&public_id)
    .bind(hash_secret(&secret))
    .bind(owner_id)
    .bind(name)
    .bind(no_scope)
    .bind(no_scope)
    .bind(MAX_SERVICE_TOKEN_LIFETIME.as_secs_f64())
    .execute(conn)
    .await?;
    Ok(format!("{PAT_PREFIX}{public_id}_{secret}"))
}

/// Appends the audit row of the whole import.
///
/// # Errors
/// Fails when the query fails.
pub async fn audit_import(
    conn: &mut PgConnection,
    details: serde_json::Value,
) -> Result<(), StoreError> {
    audit(conn, &cli_actor(), "config.import", "config", details).await
}
