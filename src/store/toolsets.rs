//! Toolsets owned by a user
//!
//! A toolset is a named set of tool globs and backends that only ever narrows what
//! its owner may use. A personal access token pinned to one reads its lists on every
//! request (see `authenticate_token`), and `/mcp/toolset/<name>` applies the caller's
//! own toolset of that name. Every write is audited in its own transaction.

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::FromRow;
use thiserror::Error;
use uuid::Uuid;

use crate::policy::validate_group_name;

use super::rbac::{Actor, audit};
use super::{Store, StoreError};

/// Most tool globs, and most backends, in one toolset
pub const MAX_TOOLSET_ENTRIES: usize = 100;
/// Longest accepted description, in characters
const MAX_DESCRIPTION_CHARS: usize = 500;

/// Errors from changing a toolset
#[derive(Debug, Error)]
pub enum ToolsetError {
    #[error("{0}")]
    InvalidName(String),

    #[error("{0}")]
    InvalidEntries(String),

    #[error("the toolset owner does not exist")]
    UnknownOwner,

    #[error("the owner already has a toolset with that name")]
    NameTaken,

    #[error("a token that is still valid is pinned to the toolset")]
    Pinned,

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

/// A toolset as stored
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct Toolset {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// Globs on the namespaced tool name; empty means no narrowing
    pub tools: Vec<String>,
    /// Backends matched exactly; empty means no narrowing
    pub backends: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The editable fields of a toolset, for create and update
#[derive(Debug, Clone, Copy)]
pub struct NewToolset<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub tools: &'a [String],
    pub backends: &'a [String],
}

fn check_entries(what: &str, entries: &[String]) -> Result<(), ToolsetError> {
    if entries.len() > MAX_TOOLSET_ENTRIES {
        return Err(ToolsetError::InvalidEntries(format!(
            "a toolset takes at most {MAX_TOOLSET_ENTRIES} {what}"
        )));
    }
    if entries
        .iter()
        .any(|entry| entry.is_empty() || entry.trim() != entry)
    {
        return Err(ToolsetError::InvalidEntries(format!(
            "{what} entries must not be empty or have surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate(new: &NewToolset<'_>) -> Result<(), ToolsetError> {
    validate_group_name(new.name).map_err(ToolsetError::InvalidName)?;
    check_entries("tools", new.tools)?;
    check_entries("backends", new.backends)?;
    if new
        .description
        .is_some_and(|text| text.chars().count() > MAX_DESCRIPTION_CHARS)
    {
        return Err(ToolsetError::InvalidEntries(format!(
            "the description takes at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(())
}

fn map_unique(error: sqlx::Error) -> ToolsetError {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => ToolsetError::NameTaken,
        _ => ToolsetError::Query(error),
    }
}

/// The label of a user in the audit target, `None` when there is no such user
async fn owner_label(
    conn: &mut sqlx::PgConnection,
    owner_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let label: Option<(String,)> =
        sqlx::query_as("select coalesce(email, display_name, subject) from users where id = $1")
            .bind(owner_id)
            .fetch_optional(conn)
            .await?;
    Ok(label.map(|(label,)| label))
}

impl Store {
    /// Creates a toolset for `owner_id`.
    ///
    /// # Errors
    /// Fails on an invalid name or entry list, an unknown owner, a name the owner
    /// already uses, or when the transaction fails.
    pub async fn create_toolset(
        &self,
        actor: &Actor,
        owner_id: Uuid,
        new: &NewToolset<'_>,
    ) -> Result<Toolset, ToolsetError> {
        validate(new)?;
        let mut tx = self.pool.begin().await?;
        let label = owner_label(&mut tx, owner_id)
            .await?
            .ok_or(ToolsetError::UnknownOwner)?;
        let toolset: Toolset = sqlx::query_as(
            "insert into user_toolsets (owner_id, name, description, tools, backends) \
             values ($1, $2, $3, $4, $5) returning id, owner_id, name, description, tools, backends, created_at, updated_at",
        )
        .bind(owner_id)
        .bind(new.name)
        .bind(new.description)
        .bind(new.tools)
        .bind(new.backends)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique)?;
        audit(
            &mut tx,
            actor,
            "toolset.create",
            &format!("toolset:{label}/{}", toolset.name),
            json!({
                "toolset_id": toolset.id,
                "owner_id": owner_id,
                "tools": new.tools,
                "backends": new.backends,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(toolset)
    }

    /// The toolsets of one owner, by name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_toolsets(&self, owner_id: Uuid) -> Result<Vec<Toolset>, StoreError> {
        Ok(sqlx::query_as(
            "select id, owner_id, name, description, tools, backends, created_at, updated_at from user_toolsets where owner_id = $1 order by name",
        )
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// One toolset of `owner_id`; `None` for an unknown id or someone else's.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn toolset(&self, owner_id: Uuid, id: Uuid) -> Result<Option<Toolset>, StoreError> {
        Ok(sqlx::query_as(
            "select id, owner_id, name, description, tools, backends, created_at, updated_at from user_toolsets where id = $1 and owner_id = $2",
        )
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// The toolset of `owner_id` with this name.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn toolset_by_name(
        &self,
        owner_id: Uuid,
        name: &str,
    ) -> Result<Option<Toolset>, StoreError> {
        Ok(sqlx::query_as(
            "select id, owner_id, name, description, tools, backends, created_at, updated_at from user_toolsets where owner_id = $1 and name = $2",
        )
        .bind(owner_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Replaces name, description, tools and backends of a toolset of `owner_id`.
    /// `None` when there is no such toolset. Tokens pinned to it follow at once.
    ///
    /// # Errors
    /// Fails on an invalid name or entry list, a name the owner already uses, or when
    /// the transaction fails.
    pub async fn update_toolset(
        &self,
        actor: &Actor,
        owner_id: Uuid,
        id: Uuid,
        new: &NewToolset<'_>,
    ) -> Result<Option<Toolset>, ToolsetError> {
        validate(new)?;
        let mut tx = self.pool.begin().await?;
        let updated: Option<Toolset> = sqlx::query_as(
            "update user_toolsets \
             set name = $3, description = $4, tools = $5, backends = $6, updated_at = now() \
             where id = $1 and owner_id = $2 returning id, owner_id, name, description, tools, backends, created_at, updated_at",
        )
        .bind(id)
        .bind(owner_id)
        .bind(new.name)
        .bind(new.description)
        .bind(new.tools)
        .bind(new.backends)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_unique)?;
        let Some(toolset) = updated else {
            return Ok(None);
        };
        let label = owner_label(&mut tx, owner_id)
            .await?
            .ok_or(ToolsetError::UnknownOwner)?;
        audit(
            &mut tx,
            actor,
            "toolset.update",
            &format!("toolset:{label}/{}", toolset.name),
            json!({
                "toolset_id": toolset.id,
                "owner_id": owner_id,
                "tools": new.tools,
                "backends": new.backends,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(toolset))
    }

    /// Deletes a toolset of `owner_id`. `false` when there is no such toolset.
    /// Revoked and expired tokens that pinned it lose the link; a token that is
    /// still valid blocks the delete.
    ///
    /// # Errors
    /// Fails with [`ToolsetError::Pinned`] while a valid token is pinned to it, or
    /// when the transaction fails.
    pub async fn delete_toolset(
        &self,
        actor: &Actor,
        owner_id: Uuid,
        id: Uuid,
    ) -> Result<bool, ToolsetError> {
        let mut tx = self.pool.begin().await?;
        let found: Option<(String,)> = sqlx::query_as(
            "select name from user_toolsets where id = $1 and owner_id = $2 for update",
        )
        .bind(id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((name,)) = found else {
            return Ok(false);
        };
        let (pinned,): (bool,) = sqlx::query_as(
            "select exists (select 1 from api_tokens \
                            where toolset_id = $1 and revoked_at is null and expires_at > now())",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        if pinned {
            return Err(ToolsetError::Pinned);
        }
        sqlx::query("update api_tokens set toolset_id = null where toolset_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("delete from user_toolsets where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let label = owner_label(&mut tx, owner_id)
            .await?
            .ok_or(ToolsetError::UnknownOwner)?;
        audit(
            &mut tx,
            actor,
            "toolset.delete",
            &format!("toolset:{label}/{name}"),
            json!({ "toolset_id": id, "owner_id": owner_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn new<'a>(name: &'a str, tools: &'a [String], backends: &'a [String]) -> NewToolset<'a> {
        NewToolset {
            name,
            description: None,
            tools,
            backends,
        }
    }

    #[test]
    fn a_plain_toolset_is_valid() {
        let tools = strings(&["prom_*", "forgejo_get_repo"]);
        assert!(validate(&new("daily-ops", &tools, &strings(&["prom"]))).is_ok());
        assert!(validate(&new("empty", &[], &[])).is_ok());
    }

    #[test]
    fn the_name_follows_the_group_name_rule() {
        for name in ["", "Daily", "a b", "authenticated"] {
            assert!(
                matches!(
                    validate(&new(name, &[], &[])),
                    Err(ToolsetError::InvalidName(_))
                ),
                "{name:?}"
            );
        }
    }

    #[test]
    fn entries_are_non_empty_trimmed_and_capped() {
        for bad in ["", " ", " prom_*", "prom_* "] {
            let tools = strings(&[bad]);
            assert!(
                matches!(
                    validate(&new("ok", &tools, &[])),
                    Err(ToolsetError::InvalidEntries(_))
                ),
                "{bad:?}"
            );
        }
        let backends = strings(&[""]);
        assert!(validate(&new("ok", &[], &backends)).is_err());
        let many = vec!["x".to_string(); MAX_TOOLSET_ENTRIES + 1];
        assert!(validate(&new("ok", &many, &[])).is_err());
        assert!(validate(&new("ok", &[], &many)).is_err());
        let at_limit = vec!["x".to_string(); MAX_TOOLSET_ENTRIES];
        assert!(validate(&new("ok", &at_limit, &at_limit)).is_ok());
    }
}
