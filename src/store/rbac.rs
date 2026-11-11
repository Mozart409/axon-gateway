//! Dashboard-managed RBAC: groups, `IdP` mappings, memberships, grants, custom roles
//! and role bindings
//!
//! Every write runs in one transaction together with its `audit_log` row, and
//! a write that changes nothing records nothing.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection};
use uuid::Uuid;

use super::auth::User;
use super::{Store, StoreError};
use crate::policy::{
    GrantConfig, IdpMapping, Permission, RbacGroupConfig, RbacSnapshot, RoleBinding, RoleConfig,
    RoleSubject,
};

/// Who made an admin change, for the audit log
#[derive(Debug, Clone)]
pub struct Actor {
    pub user_id: Option<Uuid>,
    /// Email or display name of the user, or `config` / `cli`
    pub label: String,
}

/// One row of the audit log
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct AuditRecord {
    pub id: i64,
    pub at: DateTime<Utc>,
    /// `None` for changes without a user, or once the user is deleted
    pub actor_user_id: Option<Uuid>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: Value,
}

#[derive(FromRow)]
struct GrantRow {
    id: i64,
    group_name: String,
    backend: String,
    include: Vec<String>,
    exclude: Vec<String>,
    read_only: bool,
    mandatory: bool,
}

impl From<GrantRow> for (i64, GrantConfig) {
    fn from(row: GrantRow) -> Self {
        (
            row.id,
            GrantConfig {
                group: row.group_name,
                backend: row.backend,
                include: row.include,
                exclude: row.exclude,
                read_only: row.read_only,
                mandatory: row.mandatory,
            },
        )
    }
}

fn grant_json(grant: &GrantConfig) -> Value {
    json!({
        "group": grant.group,
        "backend": grant.backend,
        "include": grant.include,
        "exclude": grant.exclude,
        "read_only": grant.read_only,
        "mandatory": grant.mandatory,
    })
}

/// What [`Store::delete_role`] did
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleDeletion {
    /// The role and its bindings are gone
    Deleted,
    /// There is no such role
    Missing,
    /// Nothing was deleted: this many bindings name the role and `force` was not set
    HasBindings(i64),
}

fn permission_names(permissions: &[Permission]) -> Vec<String> {
    permissions
        .iter()
        .copied()
        .map(|permission| permission.as_str().to_owned())
        .collect()
}

/// Appends the audit row of a change; runs inside the change's transaction
pub(super) async fn audit(
    conn: &mut PgConnection,
    actor: &Actor,
    action: &str,
    target: &str,
    details: Value,
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into audit_log (actor_user_id, actor, action, target, details) \
         values ($1, $2, $3, $4, $5)",
    )
    .bind(actor.user_id)
    .bind(&actor.label)
    .bind(action)
    .bind(target)
    .bind(details)
    .execute(conn)
    .await?;
    Ok(())
}

impl Store {
    /// All stored RBAC state: groups with their `IdP` mappings by name,
    /// memberships, grants by id, custom roles by name and role bindings by id.
    /// A binding may name a role that no longer exists; it grants nothing.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn rbac_snapshot(&self) -> Result<RbacSnapshot, StoreError> {
        let groups: Vec<(String, Option<String>)> =
            sqlx::query_as("select name, description from rbac_groups order by name")
                .fetch_all(&self.pool)
                .await?;
        let mappings: Vec<(String, String, String)> = sqlx::query_as(
            "select group_name, provider, value from rbac_group_idp_mappings \
             order by group_name, provider, value",
        )
        .fetch_all(&self.pool)
        .await?;
        let memberships: Vec<(Uuid, String)> = sqlx::query_as(
            "select user_id, group_name from rbac_memberships order by group_name, user_id",
        )
        .fetch_all(&self.pool)
        .await?;
        let grants: Vec<GrantRow> = sqlx::query_as(
            "select id, group_name, backend, include, exclude, read_only, mandatory \
             from rbac_grants order by id",
        )
        .fetch_all(&self.pool)
        .await?;
        let bindings: Vec<(i64, String, Option<String>, Option<Uuid>)> = sqlx::query_as(
            "select id, role, group_name, user_id from rbac_role_bindings order by id",
        )
        .fetch_all(&self.pool)
        .await?;
        let roles: Vec<(String, Option<String>, Vec<String>)> =
            sqlx::query_as("select name, description, permissions from rbac_roles order by name")
                .fetch_all(&self.pool)
                .await?;

        let mut idp: HashMap<String, Vec<IdpMapping>> = HashMap::new();
        for (group, provider, value) in mappings {
            idp.entry(group)
                .or_default()
                .push(IdpMapping { provider, value });
        }
        let groups = groups
            .into_iter()
            .map(|(name, description)| RbacGroupConfig {
                idp: idp.remove(&name).unwrap_or_default(),
                name,
                description,
                service_accounts: Vec::new(),
            })
            .collect();

        let mut role_bindings = Vec::with_capacity(bindings.len());
        for (id, role, group, user_id) in bindings {
            let subject = match (group, user_id) {
                (Some(group), _) => RoleSubject::Group(group),
                (None, Some(user_id)) => RoleSubject::User(user_id),
                (None, None) => continue,
            };
            role_bindings.push(RoleBinding {
                id: Some(id),
                role,
                subject,
            });
        }

        Ok(RbacSnapshot {
            groups,
            memberships,
            grants: grants.into_iter().map(Into::into).collect(),
            role_bindings,
            roles: roles
                .into_iter()
                .map(|(name, description, permissions)| RoleConfig {
                    name,
                    description,
                    permissions,
                })
                .collect(),
        })
    }

    /// Creates a group. `false` when the name is taken.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn create_group(
        &self,
        actor: &Actor,
        name: &str,
        description: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "insert into rbac_groups (name, description) values ($1, $2) on conflict do nothing",
        )
        .bind(name)
        .bind(description)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.create",
            &format!("group:{name}"),
            json!({ "description": description }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Sets a group's description. `false` when the group is missing or the
    /// description is already that.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn update_group(
        &self,
        actor: &Actor,
        name: &str,
        description: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "update rbac_groups set description = $2 \
             where name = $1 and description is distinct from $2",
        )
        .bind(name)
        .bind(description)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.update",
            &format!("group:{name}"),
            json!({ "description": description }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a group with its mappings and memberships, and the grants and
    /// role bindings that name it. `false` when it does not exist.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_group(&self, actor: &Actor, name: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let idp_mappings: i64 = sqlx::query_scalar(
            "select count(*) from rbac_group_idp_mappings where group_name = $1",
        )
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        let members: i64 =
            sqlx::query_scalar("select count(*) from rbac_memberships where group_name = $1")
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
        let deleted = sqlx::query("delete from rbac_groups where name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() == 0 {
            return Ok(false);
        }
        let grants = sqlx::query("delete from rbac_grants where group_name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        let role_bindings = sqlx::query("delete from rbac_role_bindings where group_name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            actor,
            "group.delete",
            &format!("group:{name}"),
            json!({
                "idp_mappings": idp_mappings,
                "members": members,
                "grants": grants.rows_affected(),
                "role_bindings": role_bindings.rows_affected(),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Maps an `IdP` claim value to a group. `false` when the group is missing
    /// or the mapping exists.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn add_idp_mapping(
        &self,
        actor: &Actor,
        group: &str,
        provider: &str,
        value: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "insert into rbac_group_idp_mappings (group_name, provider, value) \
             select $1::text, $2::text, $3::text \
             where exists (select 1 from rbac_groups where name = $1) \
             on conflict do nothing",
        )
        .bind(group)
        .bind(provider)
        .bind(value)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.idp_mapping.add",
            &format!("group:{group}"),
            json!({ "provider": provider, "value": value }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Removes an `IdP` mapping. `false` when there was none.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn remove_idp_mapping(
        &self,
        actor: &Actor,
        group: &str,
        provider: &str,
        value: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "delete from rbac_group_idp_mappings \
             where group_name = $1 and provider = $2 and value = $3",
        )
        .bind(group)
        .bind(provider)
        .bind(value)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.idp_mapping.remove",
            &format!("group:{group}"),
            json!({ "provider": provider, "value": value }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Adds a user to a group. `false` when the group or user is missing or
    /// the user is already a member.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn add_member(
        &self,
        actor: &Actor,
        group: &str,
        user_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "insert into rbac_memberships (group_name, user_id) \
             select $1::text, $2::uuid \
             where exists (select 1 from rbac_groups where name = $1) \
               and exists (select 1 from users where id = $2) \
             on conflict do nothing",
        )
        .bind(group)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.member.add",
            &format!("group:{group}"),
            json!({ "user_id": user_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Removes a user from a group. `false` when they were not a member.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn remove_member(
        &self,
        actor: &Actor,
        group: &str,
        user_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let result =
            sqlx::query("delete from rbac_memberships where group_name = $1 and user_id = $2")
                .bind(group)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "group.member.remove",
            &format!("group:{group}"),
            json!({ "user_id": user_id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Stores a grant and returns its id.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn create_grant(
        &self,
        actor: &Actor,
        grant: &GrantConfig,
    ) -> Result<i64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let id: i64 = sqlx::query_scalar(
            "insert into rbac_grants (group_name, backend, include, exclude, read_only, mandatory) \
             values ($1, $2, $3, $4, $5, $6) returning id",
        )
        .bind(&grant.group)
        .bind(&grant.backend)
        .bind(grant.include.as_slice())
        .bind(grant.exclude.as_slice())
        .bind(grant.read_only)
        .bind(grant.mandatory)
        .fetch_one(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "grant.create",
            &format!("grant:{id}"),
            grant_json(grant),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Deletes a grant and returns it. `None` when there was none.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_grant(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<Option<GrantConfig>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<GrantRow> = sqlx::query_as(
            "delete from rbac_grants where id = $1 \
             returning id, group_name, backend, include, exclude, read_only, mandatory",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let (_, grant) = <(i64, GrantConfig)>::from(row);
        audit(
            &mut tx,
            actor,
            "grant.delete",
            &format!("grant:{id}"),
            grant_json(&grant),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(grant))
    }

    /// Creates a custom role. `false` when the name is taken.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn create_role(
        &self,
        actor: &Actor,
        name: &str,
        description: Option<&str>,
        permissions: &[Permission],
    ) -> Result<bool, StoreError> {
        let names = permission_names(permissions);
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "insert into rbac_roles (name, description, permissions) values ($1, $2, $3) \
             on conflict do nothing",
        )
        .bind(name)
        .bind(description)
        .bind(names.as_slice())
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "role.create",
            &format!("role:{name}"),
            json!({ "description": description, "permissions": names }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Replaces a custom role's description and permissions. `false` when the
    /// role is missing or already is that.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn update_role(
        &self,
        actor: &Actor,
        name: &str,
        description: Option<&str>,
        permissions: &[Permission],
    ) -> Result<bool, StoreError> {
        let names = permission_names(permissions);
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "update rbac_roles set description = $2, permissions = $3, updated_at = now() \
             where name = $1 and (description is distinct from $2 or permissions <> $3)",
        )
        .bind(name)
        .bind(description)
        .bind(names.as_slice())
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "role.update",
            &format!("role:{name}"),
            json!({ "description": description, "permissions": names }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Deletes a custom role. Bindings that name it block the deletion unless
    /// `force` is set, which deletes them too.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_role(
        &self,
        actor: &Actor,
        name: &str,
        force: bool,
    ) -> Result<RoleDeletion, StoreError> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query("delete from rbac_roles where name = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        if deleted.rows_affected() == 0 {
            return Ok(RoleDeletion::Missing);
        }
        let bound: i64 =
            sqlx::query_scalar("select count(*) from rbac_role_bindings where role = $1")
                .bind(name)
                .fetch_one(&mut *tx)
                .await?;
        if bound > 0 && !force {
            tx.rollback().await?;
            return Ok(RoleDeletion::HasBindings(bound));
        }
        sqlx::query("delete from rbac_role_bindings where role = $1")
            .bind(name)
            .execute(&mut *tx)
            .await?;
        audit(
            &mut tx,
            actor,
            "role.delete",
            &format!("role:{name}"),
            json!({ "role_bindings": bound }),
        )
        .await?;
        tx.commit().await?;
        Ok(RoleDeletion::Deleted)
    }

    /// Binds a role (by name, built-in or custom) to a group or user and returns
    /// the binding's id. `None` when the binding exists.
    ///
    /// # Errors
    /// Fails when the transaction fails, e.g. for a user that does not exist.
    pub async fn create_role_binding(
        &self,
        actor: &Actor,
        role: &str,
        subject: &RoleSubject,
    ) -> Result<Option<i64>, StoreError> {
        let (group, user_id, details) = match subject {
            RoleSubject::Group(group) => (
                Some(group.as_str()),
                None,
                json!({ "role": role, "group": group }),
            ),
            RoleSubject::User(user_id) => (
                None,
                Some(*user_id),
                json!({ "role": role, "user_id": user_id }),
            ),
        };
        let mut tx = self.pool.begin().await?;
        let id: Option<i64> = sqlx::query_scalar(
            "insert into rbac_role_bindings (role, group_name, user_id) values ($1, $2, $3) \
             on conflict do nothing returning id",
        )
        .bind(role)
        .bind(group)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(id) = id else {
            return Ok(None);
        };
        audit(
            &mut tx,
            actor,
            "role_binding.create",
            &format!("role_binding:{id}"),
            details,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    /// Deletes a role binding. `false` when there was none.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_role_binding(&self, actor: &Actor, id: i64) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, Option<String>, Option<Uuid>)> = sqlx::query_as(
            "delete from rbac_role_bindings where id = $1 returning role, group_name, user_id",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((role, group, user_id)) = row else {
            return Ok(false);
        };
        let details = match (group, user_id) {
            (Some(group), _) => json!({ "role": role, "group": group }),
            (None, user_id) => json!({ "role": role, "user_id": user_id }),
        };
        audit(
            &mut tx,
            actor,
            "role_binding.delete",
            &format!("role_binding:{id}"),
            details,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Up to `limit` users (not service accounts), ordered by email, display name or subject.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_users(&self, limit: i64) -> Result<Vec<User>, StoreError> {
        Ok(sqlx::query_as(
            "select id, issuer, subject, email, display_name, groups, is_admin from users \
             where kind = 'user' \
             order by lower(coalesce(email, display_name, subject)), id limit $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Up to `limit` audit rows, newest first, older than `before_id` when
    /// given.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn audit_log(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        Ok(sqlx::query_as(
            "select id, at, actor_user_id, actor, action, target, details from audit_log \
             where ($2::bigint is null or id < $2) order by id desc limit $1",
        )
        .bind(limit)
        .bind(before_id)
        .fetch_all(&self.pool)
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::LoginUser;
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

    /// Creates a user through the login path and returns its id.
    async fn test_user(store: &Store, subject: &str) -> Uuid {
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

    fn cli() -> Actor {
        Actor {
            user_id: None,
            label: "cli".to_string(),
        }
    }

    fn grant(group: &str, backend: &str) -> GrantConfig {
        GrantConfig {
            group: group.to_string(),
            backend: backend.to_string(),
            include: vec!["*".to_string()],
            exclude: vec!["delete_*".to_string()],
            read_only: true,
            mandatory: false,
        }
    }

    /// The `(action, target)` of every audit row, oldest first.
    async fn audited(store: &Store) -> Vec<(String, String)> {
        sqlx::query_as("select action, target from audit_log order by id")
            .fetch_all(&store.pool)
            .await
            .unwrap()
    }

    async fn count(store: &Store, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("select count(*) from {table}")))
            .fetch_one(&store.pool)
            .await
            .unwrap()
    }

    fn entry(action: &str, target: &str) -> (String, String) {
        (action.to_string(), target.to_string())
    }

    #[tokio::test]
    async fn groups_create_update_and_reject_duplicates() {
        let Some(store) = test_store("axon_store_rbac_groups").await else {
            return;
        };

        assert!(
            store
                .create_group(&cli(), "ops", Some("Operators"))
                .await
                .unwrap()
        );
        assert!(!store.create_group(&cli(), "ops", None).await.unwrap());
        assert!(store.update_group(&cli(), "ops", None).await.unwrap());
        // Unchanged description and unknown groups are no-ops.
        assert!(!store.update_group(&cli(), "ops", None).await.unwrap());
        assert!(
            !store
                .update_group(&cli(), "missing", Some("x"))
                .await
                .unwrap()
        );

        let snapshot = store.rbac_snapshot().await.unwrap();
        assert_eq!(snapshot.groups.len(), 1);
        assert_eq!(snapshot.groups[0].name, "ops");
        assert_eq!(snapshot.groups[0].description, None);

        assert_eq!(
            audited(&store).await,
            [
                entry("group.create", "group:ops"),
                entry("group.update", "group:ops"),
            ]
        );
    }

    #[tokio::test]
    async fn deleting_a_group_removes_everything_that_names_it() {
        let Some(store) = test_store("axon_store_rbac_group_delete").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        store.create_group(&cli(), "ops", None).await.unwrap();
        store.create_group(&cli(), "dev", None).await.unwrap();
        store
            .add_idp_mapping(&cli(), "ops", "main", "abc")
            .await
            .unwrap();
        store.add_member(&cli(), "ops", user).await.unwrap();
        store.add_member(&cli(), "dev", user).await.unwrap();
        store
            .create_grant(&cli(), &grant("ops", "github"))
            .await
            .unwrap();
        store
            .create_grant(&cli(), &grant("dev", "github"))
            .await
            .unwrap();
        store
            .create_role_binding(&cli(), "auditor", &RoleSubject::Group("ops".to_string()))
            .await
            .unwrap();

        assert!(store.delete_group(&cli(), "ops").await.unwrap());
        assert!(!store.delete_group(&cli(), "ops").await.unwrap());

        assert_eq!(count(&store, "rbac_groups").await, 1);
        assert_eq!(count(&store, "rbac_group_idp_mappings").await, 0);
        assert_eq!(count(&store, "rbac_memberships").await, 1);
        assert_eq!(count(&store, "rbac_grants").await, 1);
        assert_eq!(count(&store, "rbac_role_bindings").await, 0);

        let log = store.audit_log(1, None).await.unwrap();
        assert_eq!(log[0].action, "group.delete");
        assert_eq!(log[0].target, "group:ops");
        assert_eq!(
            log[0].details,
            json!({ "idp_mappings": 1, "members": 1, "grants": 1, "role_bindings": 1 })
        );
    }

    #[tokio::test]
    async fn idp_mappings_add_and_remove() {
        let Some(store) = test_store("axon_store_rbac_mappings").await else {
            return;
        };
        store.create_group(&cli(), "ops", None).await.unwrap();

        assert!(
            store
                .add_idp_mapping(&cli(), "ops", "main", "abc")
                .await
                .unwrap()
        );
        assert!(
            !store
                .add_idp_mapping(&cli(), "ops", "main", "abc")
                .await
                .unwrap()
        );
        assert!(
            !store
                .add_idp_mapping(&cli(), "missing", "main", "abc")
                .await
                .unwrap()
        );
        assert!(
            store
                .add_idp_mapping(&cli(), "ops", "other", "abc")
                .await
                .unwrap()
        );

        let snapshot = store.rbac_snapshot().await.unwrap();
        assert_eq!(
            snapshot.groups[0].idp,
            [
                IdpMapping {
                    provider: "main".to_string(),
                    value: "abc".to_string(),
                },
                IdpMapping {
                    provider: "other".to_string(),
                    value: "abc".to_string(),
                },
            ]
        );

        assert!(
            store
                .remove_idp_mapping(&cli(), "ops", "main", "abc")
                .await
                .unwrap()
        );
        assert!(
            !store
                .remove_idp_mapping(&cli(), "ops", "main", "abc")
                .await
                .unwrap()
        );
        assert_eq!(count(&store, "rbac_group_idp_mappings").await, 1);

        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log[0].action, "group.idp_mapping.remove");
        assert_eq!(
            log[0].details,
            json!({ "provider": "main", "value": "abc" })
        );
        assert_eq!(log.len(), 4);
    }

    #[tokio::test]
    async fn members_add_and_remove() {
        let Some(store) = test_store("axon_store_rbac_members").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        store.create_group(&cli(), "ops", None).await.unwrap();

        assert!(store.add_member(&cli(), "ops", user).await.unwrap());
        assert!(!store.add_member(&cli(), "ops", user).await.unwrap());
        assert!(!store.add_member(&cli(), "missing", user).await.unwrap());
        assert!(
            !store
                .add_member(&cli(), "ops", Uuid::new_v4())
                .await
                .unwrap()
        );
        assert_eq!(
            store.rbac_snapshot().await.unwrap().memberships,
            [(user, "ops".to_string())]
        );

        assert!(store.remove_member(&cli(), "ops", user).await.unwrap());
        assert!(!store.remove_member(&cli(), "ops", user).await.unwrap());
        assert_eq!(count(&store, "rbac_memberships").await, 0);

        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log[0].action, "group.member.remove");
        assert_eq!(log[0].details, json!({ "user_id": user }));
        assert_eq!(log.len(), 3);
    }

    #[tokio::test]
    async fn grants_round_trip_through_the_snapshot() {
        let Some(store) = test_store("axon_store_rbac_grants").await else {
            return;
        };
        let first = store
            .create_grant(&cli(), &grant("ops", "github"))
            .await
            .unwrap();
        // Grants may name a group that is not stored here.
        let second = store
            .create_grant(&cli(), &grant("authenticated", "loki"))
            .await
            .unwrap();
        assert!(second > first);

        let snapshot = store.rbac_snapshot().await.unwrap();
        assert_eq!(snapshot.grants.len(), 2);
        assert_eq!(snapshot.grants[0].0, first);
        let stored = &snapshot.grants[0].1;
        assert_eq!(stored.group, "ops");
        assert_eq!(stored.backend, "github");
        assert_eq!(stored.include, ["*"]);
        assert_eq!(stored.exclude, ["delete_*"]);
        assert!(stored.read_only);
        assert!(!stored.mandatory);

        let deleted = store.delete_grant(&cli(), first).await.unwrap().unwrap();
        assert_eq!(deleted.backend, "github");
        assert!(store.delete_grant(&cli(), first).await.unwrap().is_none());
        assert_eq!(store.rbac_snapshot().await.unwrap().grants.len(), 1);

        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log[0].action, "grant.delete");
        assert_eq!(log[0].target, format!("grant:{first}"));
        assert_eq!(log[0].details["backend"], "github");
        assert_eq!(log[0].details["exclude"], json!(["delete_*"]));
        assert_eq!(log.len(), 3);
    }

    #[tokio::test]
    async fn role_bindings_for_groups_and_users() {
        let Some(store) = test_store("axon_store_rbac_bindings").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        let group = RoleSubject::Group("ops".to_string());
        let person = RoleSubject::User(user);

        let for_group = store
            .create_role_binding(&cli(), "admin", &group)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .create_role_binding(&cli(), "admin", &group)
                .await
                .unwrap()
                .is_none()
        );
        let for_user = store
            .create_role_binding(&cli(), "admin", &person)
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .create_role_binding(&cli(), "admin", &person)
                .await
                .unwrap()
                .is_none()
        );
        // The same subject may hold another role.
        assert!(
            store
                .create_role_binding(&cli(), "auditor", &group)
                .await
                .unwrap()
                .is_some()
        );

        let snapshot = store.rbac_snapshot().await.unwrap();
        assert_eq!(snapshot.role_bindings.len(), 3);
        assert_eq!(snapshot.role_bindings[0].id, Some(for_group));
        assert_eq!(snapshot.role_bindings[1].id, Some(for_user));

        assert!(store.delete_role_binding(&cli(), for_group).await.unwrap());
        assert!(store.delete_role_binding(&cli(), for_user).await.unwrap());
        assert!(!store.delete_role_binding(&cli(), for_user).await.unwrap());
        assert_eq!(count(&store, "rbac_role_bindings").await, 1);

        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log[0].action, "role_binding.delete");
        assert_eq!(log[0].details, json!({ "role": "admin", "user_id": user }));
        assert_eq!(log[1].details, json!({ "role": "admin", "group": "ops" }));
        assert_eq!(log[3].action, "role_binding.create");
        assert_eq!(log[3].details, json!({ "role": "admin", "user_id": user }));
        assert_eq!(log.len(), 5);
    }

    #[tokio::test]
    async fn bindings_of_unknown_roles_stay_in_the_snapshot() {
        let Some(store) = test_store("axon_store_rbac_unknown_role").await else {
            return;
        };
        // No check constraint limits the role: a deleted custom role leaves its name behind.
        sqlx::query("insert into rbac_role_bindings (role, group_name) values ('root', 'ops')")
            .execute(&store.pool)
            .await
            .unwrap();
        store
            .create_role_binding(&cli(), "member", &RoleSubject::Group("ops".to_string()))
            .await
            .unwrap();

        let snapshot = store.rbac_snapshot().await.unwrap();
        let roles: Vec<&str> = snapshot
            .role_bindings
            .iter()
            .map(|binding| binding.role.as_str())
            .collect();
        assert_eq!(roles, ["root", "member"]);
    }

    #[tokio::test]
    async fn custom_roles_round_trip_through_the_snapshot() {
        let Some(store) = test_store("axon_store_rbac_roles").await else {
            return;
        };
        let permissions = [Permission::BackendsView, Permission::AuditRead];

        assert!(
            store
                .create_role(&cli(), "log-reader", Some("Reads logs"), &permissions)
                .await
                .unwrap()
        );
        assert!(
            !store
                .create_role(&cli(), "log-reader", None, &permissions)
                .await
                .unwrap()
        );
        let snapshot = store.rbac_snapshot().await.unwrap();
        assert_eq!(
            snapshot.roles,
            [RoleConfig {
                name: "log-reader".to_string(),
                description: Some("Reads logs".to_string()),
                permissions: vec!["backends.view".to_string(), "audit.read".to_string()],
            }]
        );

        assert!(
            store
                .update_role(&cli(), "log-reader", None, &[Permission::AuditRead])
                .await
                .unwrap()
        );
        // Unchanged and missing roles are no-ops.
        assert!(
            !store
                .update_role(&cli(), "log-reader", None, &[Permission::AuditRead])
                .await
                .unwrap()
        );
        assert!(
            !store
                .update_role(&cli(), "missing", None, &[Permission::AuditRead])
                .await
                .unwrap()
        );

        assert_eq!(
            audited(&store).await,
            [
                entry("role.create", "role:log-reader"),
                entry("role.update", "role:log-reader"),
            ]
        );
    }

    #[tokio::test]
    async fn deleting_a_role_needs_force_when_bindings_name_it() {
        let Some(store) = test_store("axon_store_rbac_role_delete").await else {
            return;
        };
        let group = RoleSubject::Group("ops".to_string());
        store
            .create_role(&cli(), "log-reader", None, &[Permission::AuditRead])
            .await
            .unwrap();
        store
            .create_role(&cli(), "other", None, &[Permission::AuditRead])
            .await
            .unwrap();
        store
            .create_role_binding(&cli(), "log-reader", &group)
            .await
            .unwrap();
        store
            .create_role_binding(&cli(), "auditor", &group)
            .await
            .unwrap();

        assert_eq!(
            store
                .delete_role(&cli(), "log-reader", false)
                .await
                .unwrap(),
            RoleDeletion::HasBindings(1)
        );
        assert_eq!(count(&store, "rbac_roles").await, 2);
        assert_eq!(count(&store, "rbac_role_bindings").await, 2);

        assert_eq!(
            store.delete_role(&cli(), "log-reader", true).await.unwrap(),
            RoleDeletion::Deleted
        );
        assert_eq!(
            store.delete_role(&cli(), "log-reader", true).await.unwrap(),
            RoleDeletion::Missing
        );
        assert_eq!(
            store.delete_role(&cli(), "other", false).await.unwrap(),
            RoleDeletion::Deleted
        );
        assert_eq!(count(&store, "rbac_roles").await, 0);
        // The built-in binding stays.
        assert_eq!(count(&store, "rbac_role_bindings").await, 1);

        let log = store.audit_log(1, None).await.unwrap();
        assert_eq!(log[0].action, "role.delete");
        assert_eq!(log[0].target, "role:other");
        assert_eq!(log[0].details, json!({ "role_bindings": 0 }));
    }

    #[tokio::test]
    async fn audit_rows_carry_the_actor_and_only_real_changes() {
        let Some(store) = test_store("axon_store_rbac_audit").await else {
            return;
        };
        let admin = test_user(&store, "admin").await;
        let actor = Actor {
            user_id: Some(admin),
            label: "admin@example.com".to_string(),
        };

        assert!(store.create_group(&actor, "ops", None).await.unwrap());
        assert!(!store.create_group(&actor, "ops", None).await.unwrap());
        assert!(!store.delete_group(&actor, "missing").await.unwrap());
        assert!(store.delete_grant(&actor, 99).await.unwrap().is_none());

        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].actor_user_id, Some(admin));
        assert_eq!(log[0].actor, "admin@example.com");
        assert_eq!(log[0].action, "group.create");
        assert_eq!(log[0].target, "group:ops");
        assert_eq!(log[0].details, json!({ "description": null }));
    }

    #[tokio::test]
    async fn audit_log_pages_by_id_newest_first() {
        let Some(store) = test_store("axon_store_rbac_audit_paging").await else {
            return;
        };
        for name in ["a", "b", "c", "d", "e"] {
            store.create_group(&cli(), name, None).await.unwrap();
        }

        let first = store.audit_log(2, None).await.unwrap();
        let targets: Vec<&str> = first.iter().map(|row| row.target.as_str()).collect();
        assert_eq!(targets, ["group:e", "group:d"]);

        let second = store.audit_log(2, Some(first[1].id)).await.unwrap();
        let targets: Vec<&str> = second.iter().map(|row| row.target.as_str()).collect();
        assert_eq!(targets, ["group:c", "group:b"]);

        let last = store.audit_log(2, Some(second[1].id)).await.unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].target, "group:a");
        assert_eq!(
            store.audit_log(2, Some(last[0].id)).await.unwrap(),
            Vec::<AuditRecord>::new()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_cascades_and_keeps_the_audit_label() {
        let Some(store) = test_store("axon_store_rbac_user_delete").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        let actor = Actor {
            user_id: Some(user),
            label: "alice".to_string(),
        };
        store.create_group(&actor, "ops", None).await.unwrap();
        store.add_member(&actor, "ops", user).await.unwrap();
        store
            .create_role_binding(&actor, "admin", &RoleSubject::User(user))
            .await
            .unwrap();

        sqlx::query("delete from users where id = $1")
            .bind(user)
            .execute(&store.pool)
            .await
            .unwrap();

        assert_eq!(count(&store, "rbac_memberships").await, 0);
        assert_eq!(count(&store, "rbac_role_bindings").await, 0);
        let log = store.audit_log(10, None).await.unwrap();
        assert_eq!(log.len(), 3);
        assert!(log.iter().all(|row| row.actor_user_id.is_none()));
        assert!(log.iter().all(|row| row.actor == "alice"));
    }

    #[tokio::test]
    async fn users_are_listed_by_email_then_name_then_subject() {
        let Some(store) = test_store("axon_store_rbac_users").await else {
            return;
        };
        let login = |subject, email, display_name| LoginUser {
            issuer: "https://idp.example",
            subject,
            email,
            display_name,
            groups: &[],
            is_admin: false,
        };
        store
            .upsert_user_on_login(&login("s3", None, None))
            .await
            .unwrap();
        store
            .upsert_user_on_login(&login("s1", Some("Zed@example.com"), None))
            .await
            .unwrap();
        store
            .upsert_user_on_login(&login("s2", None, Some("alice")))
            .await
            .unwrap();

        let subjects: Vec<String> = store
            .list_users(10)
            .await
            .unwrap()
            .into_iter()
            .map(|user| user.subject)
            .collect();
        assert_eq!(subjects, ["s2", "s3", "s1"]);
        assert_eq!(store.list_users(2).await.unwrap().len(), 2);
    }
}
