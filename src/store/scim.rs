//! SCIM 2.0 provisioning state: one bearer token per provider, and the users
//! and groups an identity provider pushed.
//!
//! A SCIM user is linked to the `users` row of the same login (by `externalId`
//! or by `userName` = email), either when SCIM creates or updates it or when
//! the person logs in. For a linked user, `users.groups` holds the SCIM
//! groups the user is in (each group's `externalId` and `displayName` as claim
//! values) and `users.groups_source` is `scim`, so a login does not overwrite
//! them. Every change that touches those groups rewrites the snapshots in the
//! same transaction and notifies the replicas (`axon_changes`, kind `user`).
//! `active = false` disables the linked user through the same path as an
//! admin does, and only a user SCIM disabled is ever enabled by SCIM.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, PgConnection};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::scim::ScimError;

use super::auth::set_user_disabled_in;
use super::rbac::{Actor, audit};
use super::tokens::{TOKEN_TOUCH_INTERVAL, hash_secret, random_hex};
use super::{Store, StoreError};

/// Every SCIM token starts with this, so secret scanners can find a leaked one
pub const SCIM_TOKEN_PREFIX: &str = "axon_scim_";
/// Random bytes of a token, before hex encoding
const TOKEN_BYTES: usize = 32;

/// The columns of a [`ScimUser`]
macro_rules! user_columns {
    () => {
        "id, provider, user_name, external_id, display_name, given_name, family_name, \
         name_formatted, emails, active, user_id, linked_by, created_at, updated_at"
    };
}

/// The columns of a [`ScimGroup`]
macro_rules! group_columns {
    () => {
        "id, provider, display_name, external_id, created_at, updated_at"
    };
}

/// A `where` condition on `$2` (what to match: `id`, `name` or `external_id`,
/// or null for everything) and `$3` (the value)
macro_rules! lookup_condition {
    ($name:literal) => {
        concat!(
            "($2::text is null \
              or ($2 = 'id' and id::text = lower($3::text)) \
              or ($2 = 'name' and lower(",
            $name,
            ") = lower($3::text)) \
              or ($2 = 'external_id' and external_id = $3::text))"
        )
    };
}

/// An email of a SCIM user
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScimEmail {
    pub value: String,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

/// The attributes of a SCIM user that a client writes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAttrs {
    pub user_name: String,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name_formatted: Option<String>,
    pub emails: Vec<ScimEmail>,
    pub active: bool,
}

impl Default for UserAttrs {
    fn default() -> Self {
        Self {
            user_name: String::new(),
            external_id: None,
            display_name: None,
            given_name: None,
            family_name: None,
            name_formatted: None,
            emails: Vec::new(),
            active: true,
        }
    }
}

/// A SCIM user as stored
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ScimUser {
    pub id: Uuid,
    pub provider: String,
    pub user_name: String,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub name_formatted: Option<String>,
    pub emails: Value,
    pub active: bool,
    /// The login this user is linked to
    pub user_id: Option<Uuid>,
    /// `external_id` or `email`: how it was linked
    pub linked_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ScimUser {
    /// The writable attributes, for a patch to start from
    #[must_use]
    pub fn attrs(&self) -> UserAttrs {
        UserAttrs {
            user_name: self.user_name.clone(),
            external_id: self.external_id.clone(),
            display_name: self.display_name.clone(),
            given_name: self.given_name.clone(),
            family_name: self.family_name.clone(),
            name_formatted: self.name_formatted.clone(),
            emails: serde_json::from_value(self.emails.clone()).unwrap_or_default(),
            active: self.active,
        }
    }
}

/// A SCIM group as stored, without its members
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ScimGroup {
    pub id: Uuid,
    pub provider: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One member of a SCIM group
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ScimMember {
    pub group_id: Uuid,
    /// The SCIM user's id
    pub user_id: Uuid,
    pub user_name: String,
}

/// One change to a group, from a PATCH or a PUT
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupChange {
    SetDisplayName(String),
    SetExternalId(Option<String>),
    AddMembers(Vec<Uuid>),
    RemoveMembers(Vec<Uuid>),
    ReplaceMembers(Vec<Uuid>),
}

/// How a provider's SCIM users find the logins they stand for
#[derive(Debug, Clone)]
pub struct LinkRule {
    /// The provider's issuer, which a login's `users` row carries
    pub issuer: String,
    /// `scim_match_claim` is `sub`: the `externalId` is the login's subject
    pub by_subject: bool,
}

/// What a list or `filter` matches on
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupKey {
    Id,
    /// `userName` of a user, `displayName` of a group
    Name,
    ExternalId,
}

impl LookupKey {
    fn as_str(self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Name => "name",
            Self::ExternalId => "external_id",
        }
    }
}

/// An `eq` filter on one attribute
#[derive(Debug, Clone, Copy)]
pub struct Lookup<'a> {
    pub key: LookupKey,
    pub value: &'a str,
}

/// A provider's SCIM token and counts, for the admin overview
#[derive(Debug, Clone, FromRow)]
pub struct ScimProviderState {
    // Selected with the row and set by scim_admin's constructors; nothing reads it back
    #[allow(dead_code)]
    pub provider: String,
    pub token_created_at: Option<DateTime<Utc>>,
    pub token_last_used_at: Option<DateTime<Utc>>,
    pub users: i64,
    pub groups: i64,
}

/// Why a SCIM write did not happen
#[derive(Debug, Error)]
pub enum ScimStoreError {
    /// The `userName` or group `displayName` is taken
    #[error("{0}")]
    Conflict(String),

    #[error("not found")]
    NotFound,

    /// A request the data does not allow, such as a member that is no user
    #[error("{0}")]
    Invalid(String),

    /// The caller's patch did not apply to the user as stored
    #[error("{}", .0.detail)]
    Patch(ScimError),

    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for ScimStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

fn scim_actor(provider: &str) -> Actor {
    Actor {
        user_id: None,
        label: format!("scim:{provider}"),
    }
}

/// A unique violation becomes a conflict with `message`
fn conflict_or(error: sqlx::Error, message: String) -> ScimStoreError {
    match &error {
        sqlx::Error::Database(database) if database.is_unique_violation() => {
            ScimStoreError::Conflict(message)
        }
        _ => error.into(),
    }
}

/// The only id of a lookup; ambiguity links nobody
fn unambiguous(ids: &[Uuid]) -> Option<Uuid> {
    match ids {
        [id] => Some(*id),
        _ => None,
    }
}

fn emails_value(emails: &[ScimEmail]) -> Value {
    serde_json::to_value(emails).unwrap_or_else(|_| json!([]))
}

async fn audit_scim(
    conn: &mut PgConnection,
    provider: &str,
    action: &str,
    target: &str,
    details: Value,
) -> Result<(), StoreError> {
    audit(conn, &scim_actor(provider), action, target, details).await
}

/// Writes every writable attribute of a SCIM user and finishes the write
async fn write_user(
    conn: &mut PgConnection,
    provider: &str,
    rule: &LinkRule,
    id: Uuid,
    attrs: &UserAttrs,
) -> Result<ScimUser, ScimStoreError> {
    let before: Option<ScimUser> = sqlx::query_as(concat!(
        "select ",
        user_columns!(),
        " from scim_users where provider = $1 and id = $2 for no key update"
    ))
    .bind(provider)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(before) = before else {
        return Err(ScimStoreError::NotFound);
    };
    let changed = changed_attributes(&before.attrs(), attrs);
    let user: Option<ScimUser> = sqlx::query_as(concat!(
        "update scim_users set user_name = $3, external_id = $4, display_name = $5, \
             given_name = $6, family_name = $7, name_formatted = $8, emails = $9, \
             active = $10, updated_at = now() \
         where provider = $1 and id = $2 returning ",
        user_columns!()
    ))
    .bind(provider)
    .bind(id)
    .bind(&attrs.user_name)
    .bind(&attrs.external_id)
    .bind(&attrs.display_name)
    .bind(&attrs.given_name)
    .bind(&attrs.family_name)
    .bind(&attrs.name_formatted)
    .bind(emails_value(&attrs.emails))
    .bind(attrs.active)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| conflict_or(error, user_name_taken(&attrs.user_name)))?;
    let Some(user) = user else {
        return Err(ScimStoreError::NotFound);
    };
    Ok(finish_user(conn, rule, user, "scim.user.update", &changed).await?)
}

/// The names of the attributes that differ, for the audit row (never values)
fn changed_attributes(before: &UserAttrs, after: &UserAttrs) -> Vec<&'static str> {
    [
        ("userName", before.user_name != after.user_name),
        ("externalId", before.external_id != after.external_id),
        ("displayName", before.display_name != after.display_name),
        ("givenName", before.given_name != after.given_name),
        ("familyName", before.family_name != after.family_name),
        ("formatted", before.name_formatted != after.name_formatted),
        ("emails", before.emails != after.emails),
        ("active", before.active != after.active),
    ]
    .into_iter()
    .filter_map(|(name, differs)| differs.then_some(name))
    .collect()
}

/// Rewrites `users.groups` of the logins linked to these SCIM users from their
/// group memberships and tells the replicas about each of them.
async fn refresh_groups(conn: &mut PgConnection, scim_user_ids: &[Uuid]) -> Result<(), StoreError> {
    if scim_user_ids.is_empty() {
        return Ok(());
    }
    // Lock the logins first, in a statement of their own: under READ COMMITTED
    // the update below then takes its snapshot after the lock, so it sees the
    // memberships a concurrent transaction committed while this one waited.
    sqlx::query(
        "select u.id from users u join scim_users s on s.user_id = u.id \
         where s.id = any($1) order by u.id for no key update of u",
    )
    .bind(scim_user_ids)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "with updated as ( \
             update users u set \
                 groups = coalesce(( \
                     select array_agg(distinct v order by v) \
                     from scim_group_members m \
                     join scim_groups g on g.id = m.group_id \
                     cross join lateral unnest( \
                         array_remove(array[g.display_name, g.external_id], null) \
                     ) as t(v) \
                     where m.scim_user_id = s.id \
                 ), '{}'::text[]), \
                 groups_source = 'scim' \
             from scim_users s \
             where s.id = any($1) and s.user_id = u.id \
             returning u.id \
         ) \
         select pg_notify( \
             'axon_changes', \
             json_build_object('schema', current_schema(), 'kind', 'user', 'user', id)::text \
         ) from updated",
    )
    .bind(scim_user_ids)
    .execute(conn)
    .await?;
    Ok(())
}

/// Brings the linked login's disabled state in line with `active`: an inactive
/// SCIM user is disabled (remembering that SCIM did it), an active one is
/// enabled again only when SCIM was the one that disabled it.
async fn sync_active(
    conn: &mut PgConnection,
    provider: &str,
    scim_user_id: Uuid,
) -> Result<(), StoreError> {
    let row: Option<(Option<Uuid>, bool, bool)> =
        sqlx::query_as("select user_id, active, disabled_by_scim from scim_users where id = $1")
            .bind(scim_user_id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((Some(user_id), active, disabled_by_scim)) = row else {
        return Ok(());
    };
    let actor = scim_actor(provider);
    let flag = if !active {
        // Not ours to re-enable when an admin had already disabled it
        set_user_disabled_in(conn, &actor, user_id, true)
            .await?
            .then_some(true)
    } else if disabled_by_scim {
        set_user_disabled_in(conn, &actor, user_id, false).await?;
        Some(false)
    } else {
        None
    };
    if let Some(flag) = flag {
        sqlx::query("update scim_users set disabled_by_scim = $2 where id = $1")
            .bind(scim_user_id)
            .bind(flag)
            .execute(conn)
            .await?;
    }
    Ok(())
}

/// Links an unlinked SCIM user to the login of the provider's issuer it stands
/// for: by subject = `externalId` when the match claim is `sub`, else (or when
/// that finds nothing) by email = `userName`. `true` when it linked.
async fn try_link(
    conn: &mut PgConnection,
    rule: &LinkRule,
    user: &ScimUser,
) -> Result<bool, StoreError> {
    if user.user_id.is_some() {
        return Ok(false);
    }
    let mut found = None;
    if rule.by_subject
        && let Some(external_id) = user.external_id.as_deref()
    {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "select id from users u \
             where issuer = $1 and subject = $2 and kind = 'user' \
               and not exists (select 1 from scim_users s where s.user_id = u.id) \
             limit 2",
        )
        .bind(&rule.issuer)
        .bind(external_id)
        .fetch_all(&mut *conn)
        .await?;
        found = unambiguous(&ids).map(|id| (id, "external_id"));
    }
    if found.is_none() {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "select id from users u \
             where issuer = $1 and lower(btrim(email)) = lower($2) and kind = 'user' \
               and not exists (select 1 from scim_users s where s.user_id = u.id) \
             limit 2",
        )
        .bind(&rule.issuer)
        .bind(user.user_name.trim())
        .fetch_all(&mut *conn)
        .await?;
        found = unambiguous(&ids).map(|id| (id, "email"));
    }
    let Some((login_id, how)) = found else {
        return Ok(false);
    };
    sqlx::query("update scim_users set user_id = $2, linked_by = $3 where id = $1")
        .bind(user.id)
        .bind(login_id)
        .bind(how)
        .execute(conn)
        .await?;
    Ok(true)
}

async fn fetch_user(conn: &mut PgConnection, id: Uuid) -> Result<ScimUser, StoreError> {
    Ok(sqlx::query_as(concat!(
        "select ",
        user_columns!(),
        " from scim_users where id = $1"
    ))
    .bind(id)
    .fetch_one(conn)
    .await?)
}

/// What every user write does after the row is written: link, apply the groups
/// and the active flag, audit. Returns the row as it is now.
async fn finish_user(
    conn: &mut PgConnection,
    rule: &LinkRule,
    user: ScimUser,
    action: &str,
    changed: &[&str],
) -> Result<ScimUser, StoreError> {
    if try_link(conn, rule, &user).await? {
        refresh_groups(conn, &[user.id]).await?;
    }
    sync_active(conn, &user.provider, user.id).await?;
    audit_scim(
        conn,
        &user.provider,
        action,
        &format!("scim-user:{}", user.user_name),
        json!({ "id": user.id, "active": user.active, "changed": changed }),
    )
    .await?;
    fetch_user(conn, user.id).await
}

async fn members_of(conn: &mut PgConnection, group_id: Uuid) -> Result<HashSet<Uuid>, StoreError> {
    let ids: Vec<Uuid> =
        sqlx::query_scalar("select scim_user_id from scim_group_members where group_id = $1")
            .bind(group_id)
            .fetch_all(conn)
            .await?;
    Ok(ids.into_iter().collect())
}

fn sorted_ids<'a>(ids: impl Iterator<Item = &'a Uuid>) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = ids.copied().collect();
    ids.sort_unstable();
    ids
}

/// Fails unless every id is a SCIM user of the provider
async fn check_members(
    conn: &mut PgConnection,
    provider: &str,
    ids: &[Uuid],
) -> Result<(), ScimStoreError> {
    if ids.is_empty() {
        return Ok(());
    }
    let known: Vec<Uuid> =
        sqlx::query_scalar("select id from scim_users where provider = $1 and id = any($2)")
            .bind(provider)
            .bind(ids)
            .fetch_all(conn)
            .await?;
    let known: HashSet<Uuid> = known.into_iter().collect();
    match ids.iter().find(|id| !known.contains(id)) {
        Some(missing) => Err(ScimStoreError::Invalid(format!(
            "member {missing} is not a user of this provider"
        ))),
        None => Ok(()),
    }
}

async fn insert_members(
    conn: &mut PgConnection,
    group_id: Uuid,
    ids: &[Uuid],
) -> Result<(), StoreError> {
    sqlx::query(
        "insert into scim_group_members (group_id, scim_user_id) \
         select $1, unnest($2::uuid[]) on conflict do nothing",
    )
    .bind(group_id)
    .bind(ids)
    .execute(conn)
    .await?;
    Ok(())
}

/// Applies `changes` to a group in the caller's transaction and refreshes the
/// groups of every login it touches.
async fn apply_group_changes(
    conn: &mut PgConnection,
    provider: &str,
    id: Uuid,
    changes: &[GroupChange],
) -> Result<ScimGroup, ScimStoreError> {
    let locked: Option<Uuid> =
        sqlx::query_scalar("select id from scim_groups where provider = $1 and id = $2 for update")
            .bind(provider)
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    if locked.is_none() {
        return Err(ScimStoreError::NotFound);
    }
    let before = members_of(conn, id).await?;
    let mut renamed = false;
    for change in changes {
        match change {
            GroupChange::SetDisplayName(name) => {
                sqlx::query("update scim_groups set display_name = $2 where id = $1")
                    .bind(id)
                    .bind(name)
                    .execute(&mut *conn)
                    .await
                    .map_err(|error| conflict_or(error, format!("group {name} already exists")))?;
                renamed = true;
            }
            GroupChange::SetExternalId(external_id) => {
                sqlx::query("update scim_groups set external_id = $2 where id = $1")
                    .bind(id)
                    .bind(external_id)
                    .execute(&mut *conn)
                    .await?;
                renamed = true;
            }
            GroupChange::AddMembers(ids) => {
                check_members(conn, provider, ids).await?;
                insert_members(conn, id, ids).await?;
            }
            GroupChange::RemoveMembers(ids) => {
                sqlx::query(
                    "delete from scim_group_members where group_id = $1 and scim_user_id = any($2)",
                )
                .bind(id)
                .bind(ids)
                .execute(&mut *conn)
                .await?;
            }
            GroupChange::ReplaceMembers(ids) => {
                check_members(conn, provider, ids).await?;
                sqlx::query("delete from scim_group_members where group_id = $1")
                    .bind(id)
                    .execute(&mut *conn)
                    .await?;
                insert_members(conn, id, ids).await?;
            }
        }
    }
    let group: ScimGroup = sqlx::query_as(concat!(
        "update scim_groups set updated_at = now() where id = $1 returning ",
        group_columns!()
    ))
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    let after = members_of(conn, id).await?;
    // A new name or externalId changes the groups of everyone in it
    let affected: Vec<Uuid> = if renamed {
        before.union(&after).copied().collect()
    } else {
        before.symmetric_difference(&after).copied().collect()
    };
    refresh_groups(conn, &affected).await?;
    audit_scim(
        conn,
        provider,
        "scim.group.update",
        &format!("scim-group:{}", group.display_name),
        json!({
            "id": id,
            "members": after.len(),
            "added": sorted_ids(after.difference(&before)),
            "removed": sorted_ids(before.difference(&after)),
            "renamed": renamed,
        }),
    )
    .await?;
    Ok(group)
}

impl Store {
    // ---- tokens ----

    /// Creates the provider's SCIM token, replacing the old one, and returns
    /// its plaintext: the only time it exists.
    ///
    /// # Errors
    /// Fails when the system cannot supply randomness or the transaction fails.
    pub async fn create_scim_token(
        &self,
        actor: &Actor,
        provider: &str,
    ) -> Result<String, StoreError> {
        let token = format!("{SCIM_TOKEN_PREFIX}{}", random_hex::<TOKEN_BYTES>()?);
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "insert into scim_tokens (provider, token_hash) values ($1, $2) \
             on conflict (provider) do update set \
                 token_hash = excluded.token_hash, created_at = now(), last_used_at = null",
        )
        .bind(provider)
        .bind(hash_secret(&token))
        .execute(&mut *tx)
        .await?;
        audit(
            &mut tx,
            actor,
            "scim.token.create",
            &format!("scim:{provider}"),
            json!({ "provider": provider }),
        )
        .await?;
        tx.commit().await?;
        Ok(token)
    }

    /// Deletes the provider's SCIM token. `false` when there was none.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_scim_token(
        &self,
        actor: &Actor,
        provider: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let deleted = sqlx::query("delete from scim_tokens where provider = $1")
            .bind(provider)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
        if !deleted {
            return Ok(false);
        }
        audit(
            &mut tx,
            actor,
            "scim.token.delete",
            &format!("scim:{provider}"),
            json!({ "provider": provider }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Whether `token` is the provider's current SCIM token (compared in
    /// constant time). Notes the use, at most once per touch interval.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn check_scim_token(&self, provider: &str, token: &str) -> Result<bool, StoreError> {
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("select token_hash from scim_tokens where provider = $1")
                .bind(provider)
                .fetch_optional(&self.pool)
                .await?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        let matches: bool = stored
            .as_slice()
            .ct_eq(hash_secret(token).as_slice())
            .into();
        if matches {
            sqlx::query(
                "update scim_tokens set last_used_at = now() \
                 where provider = $1 \
                   and (last_used_at is null or last_used_at < now() - make_interval(secs => $2))",
            )
            .bind(provider)
            .bind(TOKEN_TOUCH_INTERVAL.as_secs_f64())
            .execute(&self.pool)
            .await?;
        }
        Ok(matches)
    }

    /// Each of `providers` with its token's dates and its SCIM user and group
    /// counts, in the order given.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn scim_overview(
        &self,
        providers: &[String],
    ) -> Result<Vec<ScimProviderState>, StoreError> {
        Ok(sqlx::query_as(
            "select p.provider, \
                    t.created_at as token_created_at, t.last_used_at as token_last_used_at, \
                    (select count(*) from scim_users u where u.provider = p.provider) as users, \
                    (select count(*) from scim_groups g where g.provider = p.provider) as groups \
             from unnest($1::text[]) with ordinality as p(provider, ord) \
             left join scim_tokens t on t.provider = p.provider \
             order by p.ord",
        )
        .bind(providers)
        .fetch_all(&self.pool)
        .await?)
    }

    // ---- users ----

    /// Creates a SCIM user and links it to its login when there is one.
    ///
    /// # Errors
    /// Conflict for a `userName` the provider already has; otherwise when the
    /// transaction fails.
    pub async fn create_scim_user(
        &self,
        provider: &str,
        rule: &LinkRule,
        attrs: &UserAttrs,
    ) -> Result<ScimUser, ScimStoreError> {
        let mut tx = self.pool.begin().await?;
        let user: ScimUser = sqlx::query_as(concat!(
            "insert into scim_users (provider, user_name, external_id, display_name, \
                 given_name, family_name, name_formatted, emails, active) \
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9) returning ",
            user_columns!()
        ))
        .bind(provider)
        .bind(&attrs.user_name)
        .bind(&attrs.external_id)
        .bind(&attrs.display_name)
        .bind(&attrs.given_name)
        .bind(&attrs.family_name)
        .bind(&attrs.name_formatted)
        .bind(emails_value(&attrs.emails))
        .bind(attrs.active)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| conflict_or(error, user_name_taken(&attrs.user_name)))?;
        let user = finish_user(&mut tx, rule, user, "scim.user.create", &[]).await?;
        tx.commit().await?;
        Ok(user)
    }

    /// Replaces every writable attribute of a SCIM user (PUT, and PATCH after
    /// the patch is applied to the current attributes).
    ///
    /// # Errors
    /// Not found for an unknown id, conflict for a `userName` another user of
    /// the provider has; otherwise when the transaction fails.
    pub async fn replace_scim_user(
        &self,
        provider: &str,
        rule: &LinkRule,
        id: Uuid,
        attrs: &UserAttrs,
    ) -> Result<ScimUser, ScimStoreError> {
        let mut tx = self.pool.begin().await?;
        let user = write_user(&mut tx, provider, rule, id, attrs).await?;
        tx.commit().await?;
        Ok(user)
    }

    /// Applies `apply` to the current attributes of a SCIM user and stores the
    /// result (PATCH). The row is locked first, so concurrent patches of one
    /// user run one after the other and none loses its change.
    ///
    /// # Errors
    /// Not found for an unknown id, the patch error when `apply` fails,
    /// conflict for a `userName` another user of the provider has; otherwise
    /// when the transaction fails.
    pub async fn patch_scim_user(
        &self,
        provider: &str,
        rule: &LinkRule,
        id: Uuid,
        apply: impl FnOnce(&mut UserAttrs) -> Result<(), ScimError>,
    ) -> Result<ScimUser, ScimStoreError> {
        let mut tx = self.pool.begin().await?;
        let current: Option<ScimUser> = sqlx::query_as(concat!(
            "select ",
            user_columns!(),
            " from scim_users where provider = $1 and id = $2 for no key update"
        ))
        .bind(provider)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            return Err(ScimStoreError::NotFound);
        };
        let mut attrs = current.attrs();
        apply(&mut attrs).map_err(ScimStoreError::Patch)?;
        let user = write_user(&mut tx, provider, rule, id, &attrs).await?;
        tx.commit().await?;
        Ok(user)
    }

    /// One SCIM user of the provider.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn get_scim_user(
        &self,
        provider: &str,
        id: Uuid,
    ) -> Result<Option<ScimUser>, StoreError> {
        Ok(sqlx::query_as(concat!(
            "select ",
            user_columns!(),
            " from scim_users where provider = $1 and id = $2"
        ))
        .bind(provider)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// A page of the provider's SCIM users (`start_index` counts from 1) and
    /// how many match in all.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn list_scim_users(
        &self,
        provider: &str,
        lookup: Option<Lookup<'_>>,
        start_index: i64,
        count: i64,
    ) -> Result<(Vec<ScimUser>, i64), StoreError> {
        let key = lookup.map(|lookup| lookup.key.as_str());
        let value = lookup.map(|lookup| lookup.value);
        let total: i64 = sqlx::query_scalar(concat!(
            "select count(*) from scim_users where provider = $1 and ",
            lookup_condition!("user_name")
        ))
        .bind(provider)
        .bind(key)
        .bind(value)
        .fetch_one(&self.pool)
        .await?;
        let users = sqlx::query_as(concat!(
            "select ",
            user_columns!(),
            " from scim_users where provider = $1 and ",
            lookup_condition!("user_name"),
            " order by lower(user_name), id offset $4 limit $5"
        ))
        .bind(provider)
        .bind(key)
        .bind(value)
        .bind((start_index - 1).max(0))
        .bind(count.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok((users, total))
    }

    /// Deletes a SCIM user. A linked login is disabled and goes back to
    /// groups from its claims. `false` for an unknown id.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_scim_user(&self, provider: &str, id: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, Option<Uuid>)> = sqlx::query_as(
            "select user_name, user_id from scim_users where provider = $1 and id = $2 for no key update",
        )
        .bind(provider)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((user_name, login_id)) = row else {
            return Ok(false);
        };
        if let Some(login_id) = login_id {
            set_user_disabled_in(&mut tx, &scim_actor(provider), login_id, true).await?;
            sqlx::query("update users set groups_source = 'claims' where id = $1")
                .bind(login_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("delete from scim_users where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        audit_scim(
            &mut tx,
            provider,
            "scim.user.delete",
            &format!("scim-user:{user_name}"),
            json!({ "id": id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Links the login `user_id` of a provider to the SCIM user that stands
    /// for it, when it has none yet: the unlinked user whose `externalId` is
    /// `scim_key`, else whose `userName` is `email` (case-insensitive). Then
    /// the login gets the SCIM groups, and is disabled when the SCIM user is
    /// inactive. `true` when it linked.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn link_scim_user_on_login(
        &self,
        provider: &str,
        user_id: Uuid,
        email: Option<&str>,
        scim_key: Option<&str>,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let linked: bool = sqlx::query_scalar(
            "select exists (select 1 from scim_users where provider = $1 and user_id = $2)",
        )
        .bind(provider)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        if linked {
            return Ok(false);
        }

        let mut found = None;
        if let Some(key) = scim_key {
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "select id from scim_users \
                 where provider = $1 and user_id is null and external_id = $2 limit 2 for update",
            )
            .bind(provider)
            .bind(key)
            .fetch_all(&mut *tx)
            .await?;
            found = unambiguous(&ids).map(|id| (id, "external_id"));
        }
        if found.is_none()
            && let Some(email) = email.map(str::trim).filter(|email| !email.is_empty())
        {
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "select id from scim_users \
                 where provider = $1 and user_id is null and lower(user_name) = lower($2) \
                 limit 2 for update",
            )
            .bind(provider)
            .bind(email)
            .fetch_all(&mut *tx)
            .await?;
            found = unambiguous(&ids).map(|id| (id, "email"));
        }
        let Some((scim_user_id, how)) = found else {
            return Ok(false);
        };

        let user_name: String = sqlx::query_scalar(
            "update scim_users set user_id = $2, linked_by = $3 where id = $1 returning user_name",
        )
        .bind(scim_user_id)
        .bind(user_id)
        .bind(how)
        .fetch_one(&mut *tx)
        .await?;
        refresh_groups(&mut tx, &[scim_user_id]).await?;
        sync_active(&mut tx, provider, scim_user_id).await?;
        audit_scim(
            &mut tx,
            provider,
            "scim.user.link",
            &format!("scim-user:{user_name}"),
            json!({ "id": scim_user_id, "user_id": user_id, "by": how }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    // ---- groups ----

    /// Creates a SCIM group with its members (ids of the provider's SCIM
    /// users).
    ///
    /// # Errors
    /// Conflict for a `displayName` the provider already has, invalid for a
    /// member that is no SCIM user of it; otherwise when the transaction fails.
    pub async fn create_scim_group(
        &self,
        provider: &str,
        display_name: &str,
        external_id: Option<&str>,
        members: &[Uuid],
    ) -> Result<ScimGroup, ScimStoreError> {
        let mut tx = self.pool.begin().await?;
        let group: ScimGroup = sqlx::query_as(concat!(
            "insert into scim_groups (provider, display_name, external_id) \
             values ($1, $2, $3) returning ",
            group_columns!()
        ))
        .bind(provider)
        .bind(display_name)
        .bind(external_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| conflict_or(error, format!("group {display_name} already exists")))?;
        check_members(&mut tx, provider, members).await?;
        insert_members(&mut tx, group.id, members).await?;
        refresh_groups(&mut tx, members).await?;
        audit_scim(
            &mut tx,
            provider,
            "scim.group.create",
            &format!("scim-group:{display_name}"),
            json!({ "id": group.id, "members": members.len() }),
        )
        .await?;
        tx.commit().await?;
        Ok(group)
    }

    /// Replaces a group's name, `externalId` and members (PUT).
    ///
    /// # Errors
    /// As [`Store::patch_scim_group`].
    pub async fn replace_scim_group(
        &self,
        provider: &str,
        id: Uuid,
        display_name: &str,
        external_id: Option<&str>,
        members: &[Uuid],
    ) -> Result<ScimGroup, ScimStoreError> {
        self.patch_scim_group(
            provider,
            id,
            &[
                GroupChange::SetDisplayName(display_name.to_owned()),
                GroupChange::SetExternalId(external_id.map(str::to_owned)),
                GroupChange::ReplaceMembers(members.to_vec()),
            ],
        )
        .await
    }

    /// Applies `changes` to a group, in order.
    ///
    /// # Errors
    /// Not found for an unknown id, conflict for a `displayName` another group
    /// of the provider has, invalid for a member that is no SCIM user of it;
    /// otherwise when the transaction fails.
    pub async fn patch_scim_group(
        &self,
        provider: &str,
        id: Uuid,
        changes: &[GroupChange],
    ) -> Result<ScimGroup, ScimStoreError> {
        let mut tx = self.pool.begin().await?;
        let group = apply_group_changes(&mut tx, provider, id, changes).await?;
        tx.commit().await?;
        Ok(group)
    }

    /// Deletes a SCIM group; its members lose the groups it gave them.
    /// `false` for an unknown id.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_scim_group(&self, provider: &str, id: Uuid) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let name: Option<String> = sqlx::query_scalar(
            "select display_name from scim_groups where provider = $1 and id = $2 for update",
        )
        .bind(provider)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(name) = name else {
            return Ok(false);
        };
        let members: Vec<Uuid> = members_of(&mut tx, id).await?.into_iter().collect();
        sqlx::query("delete from scim_groups where id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        refresh_groups(&mut tx, &members).await?;
        audit_scim(
            &mut tx,
            provider,
            "scim.group.delete",
            &format!("scim-group:{name}"),
            json!({ "id": id }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// One SCIM group of the provider, without its members.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn get_scim_group(
        &self,
        provider: &str,
        id: Uuid,
    ) -> Result<Option<ScimGroup>, StoreError> {
        Ok(sqlx::query_as(concat!(
            "select ",
            group_columns!(),
            " from scim_groups where provider = $1 and id = $2"
        ))
        .bind(provider)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// A page of the provider's SCIM groups (`start_index` counts from 1) and
    /// how many match in all.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn list_scim_groups(
        &self,
        provider: &str,
        lookup: Option<Lookup<'_>>,
        start_index: i64,
        count: i64,
    ) -> Result<(Vec<ScimGroup>, i64), StoreError> {
        let key = lookup.map(|lookup| lookup.key.as_str());
        let value = lookup.map(|lookup| lookup.value);
        let total: i64 = sqlx::query_scalar(concat!(
            "select count(*) from scim_groups where provider = $1 and ",
            lookup_condition!("display_name")
        ))
        .bind(provider)
        .bind(key)
        .bind(value)
        .fetch_one(&self.pool)
        .await?;
        let groups = sqlx::query_as(concat!(
            "select ",
            group_columns!(),
            " from scim_groups where provider = $1 and ",
            lookup_condition!("display_name"),
            " order by lower(display_name), id offset $4 limit $5"
        ))
        .bind(provider)
        .bind(key)
        .bind(value)
        .bind((start_index - 1).max(0))
        .bind(count.max(0))
        .fetch_all(&self.pool)
        .await?;
        Ok((groups, total))
    }

    /// The members of these groups, ordered by `userName`.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn scim_group_members(
        &self,
        group_ids: &[Uuid],
    ) -> Result<Vec<ScimMember>, StoreError> {
        Ok(sqlx::query_as(
            "select m.group_id, m.scim_user_id as user_id, u.user_name \
             from scim_group_members m join scim_users u on u.id = m.scim_user_id \
             where m.group_id = any($1) order by lower(u.user_name), u.id",
        )
        .bind(group_ids)
        .fetch_all(&self.pool)
        .await?)
    }
}

fn user_name_taken(user_name: &str) -> String {
    format!("userName {user_name} is already in use")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_single_match_links() {
        let one = Uuid::new_v4();
        assert_eq!(unambiguous(&[one]), Some(one));
        assert_eq!(unambiguous(&[]), None);
        assert_eq!(unambiguous(&[one, Uuid::new_v4()]), None);
    }

    #[test]
    fn emails_round_trip_with_the_scim_names() {
        let emails = vec![ScimEmail {
            value: "a@example.com".to_owned(),
            kind: Some("work".to_owned()),
            primary: Some(true),
        }];
        let value = emails_value(&emails);
        assert_eq!(
            value,
            json!([{ "value": "a@example.com", "type": "work", "primary": true }])
        );
        assert_eq!(
            serde_json::from_value::<Vec<ScimEmail>>(value).unwrap(),
            emails
        );
    }
}
