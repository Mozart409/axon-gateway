//! Bindings of `IdP` subjects to service accounts, for resource-server JWTs
//!
//! A JWT access token from a configured provider resolves to a service account
//! when its `(issuer, subject)` is bound to one, else to the human user with
//! that issuer and subject (who has logged in before).

use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::FromRow;
use thiserror::Error;
use uuid::Uuid;

use super::auth::User;
use super::rbac::{Actor, audit};
use super::tokens::INACTIVE_OWNER_SUSPEND;
use super::{Store, StoreError};

/// Errors from binding a subject to a service account
#[derive(Debug, Error)]
pub enum JwtBindingError {
    #[error("the service account does not exist")]
    UnknownServiceAccount,

    #[error("that issuer and subject are already bound")]
    AlreadyBound,

    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
}

/// An `IdP` subject bound to a service account
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct JwtBinding {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

/// Who a JWT's `(issuer, subject)` acts as
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtSubject {
    /// A service account the subject is bound to
    ServiceAccount(User),
    /// The human user with that issuer and subject
    User(User),
}

#[derive(FromRow)]
struct BoundAccountRow {
    #[sqlx(flatten)]
    user: User,
    disabled: bool,
}

const BINDING_COLUMNS: &str = "id, service_account_id, issuer, subject, created_at, created_by";

impl Store {
    /// Binds an `IdP` subject to a service account, audited as `actor`.
    ///
    /// # Errors
    /// [`JwtBindingError::UnknownServiceAccount`] when `service_account_id` is
    /// not a service account, [`JwtBindingError::AlreadyBound`] when the
    /// subject is bound already, or a failed transaction.
    pub async fn create_jwt_binding(
        &self,
        actor: &Actor,
        service_account_id: Uuid,
        issuer: &str,
        subject: &str,
    ) -> Result<JwtBinding, JwtBindingError> {
        let mut tx = self.pool.begin().await?;
        let name: Option<String> = sqlx::query_scalar(
            "select subject from users where id = $1 and kind = 'service' for share",
        )
        .bind(service_account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(name) = name else {
            return Err(JwtBindingError::UnknownServiceAccount);
        };
        let binding: Option<JwtBinding> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "insert into jwt_bindings (service_account_id, issuer, subject, created_by) \
             values ($1, $2, $3, $4) on conflict (issuer, subject) do nothing \
             returning {BINDING_COLUMNS}"
        )))
        .bind(service_account_id)
        .bind(issuer)
        .bind(subject)
        .bind(actor.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(binding) = binding else {
            return Err(JwtBindingError::AlreadyBound);
        };
        audit(
            &mut tx,
            actor,
            "service_account.jwt_binding.create",
            &format!("service_account:{name}"),
            json!({ "issuer": issuer, "subject": subject }),
        )
        .await?;
        tx.commit().await?;
        Ok(binding)
    }

    /// The bindings of a service account, oldest first.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn list_jwt_bindings(
        &self,
        service_account_id: Uuid,
    ) -> Result<Vec<JwtBinding>, StoreError> {
        Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "select {BINDING_COLUMNS} from jwt_bindings \
             where service_account_id = $1 order by created_at, id"
        )))
        .bind(service_account_id)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Removes a binding of the service account, audited as `actor`. `false`
    /// when it does not exist.
    ///
    /// # Errors
    /// Fails when the transaction fails.
    pub async fn delete_jwt_binding(
        &self,
        actor: &Actor,
        service_account_id: Uuid,
        binding_id: Uuid,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let deleted: Option<(String, String, String)> = sqlx::query_as(
            "delete from jwt_bindings b using users u \
             where b.id = $2 and b.service_account_id = $1 and u.id = b.service_account_id \
             returning u.subject, b.issuer, b.subject",
        )
        .bind(service_account_id)
        .bind(binding_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((name, issuer, subject)) = deleted else {
            return Ok(false);
        };
        audit(
            &mut tx,
            actor,
            "service_account.jwt_binding.delete",
            &format!("service_account:{name}"),
            json!({ "issuer": issuer, "subject": subject }),
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Resolves the `(issuer, subject)` of a verified JWT: a binding first,
    /// else the user with that issuer and subject. `None` when neither
    /// exists, the service account is disabled, or the user is disabled or has
    /// not logged in for [`INACTIVE_OWNER_SUSPEND`]. A bound subject never
    /// falls back to a user.
    ///
    /// # Errors
    /// Fails when a query fails.
    pub async fn resolve_jwt_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<JwtSubject>, StoreError> {
        let bound: Option<BoundAccountRow> = sqlx::query_as(
            "select u.id, u.issuer, u.subject, u.email, u.display_name, u.groups, u.is_admin, \
                    u.disabled_at is not null as disabled \
             from jwt_bindings b join users u on u.id = b.service_account_id \
             where b.issuer = $1 and b.subject = $2 and u.kind = 'service'",
        )
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = bound {
            return Ok((!row.disabled).then_some(JwtSubject::ServiceAccount(row.user)));
        }
        let user: Option<User> = sqlx::query_as(
            "select id, issuer, subject, email, display_name, groups, is_admin from users \
             where kind = 'user' and issuer = $1 and subject = $2 \
               and disabled_at is null \
               and last_login_at > now() - make_interval(secs => $3)",
        )
        .bind(issuer)
        .bind(subject)
        .bind(INACTIVE_OWNER_SUSPEND.as_secs_f64())
        .fetch_optional(&self.pool)
        .await?;
        Ok(user.map(JwtSubject::User))
    }
}

#[cfg(test)]
mod tests {
    use super::super::LoginUser;
    use super::super::test_support::{database_url, isolated_url};
    use super::*;

    const ISSUER: &str = "https://idp.example";

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

    async fn login(store: &Store, subject: &str) -> User {
        let login = LoginUser {
            issuer: ISSUER,
            subject,
            email: None,
            display_name: None,
            groups: &[],
            is_admin: false,
        };
        store.upsert_user_on_login(&login).await.unwrap()
    }

    async fn service_account(store: &Store, name: &str) -> Uuid {
        store
            .create_service_account(&cli(), name, None)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn a_binding_is_created_listed_and_deleted() {
        let Some(store) = test_store("axon_store_jwt_bindings_crud").await else {
            return;
        };
        let account = service_account(&store, "ci").await;
        let binding = store
            .create_jwt_binding(&cli(), account, ISSUER, "client-1")
            .await
            .unwrap();
        assert_eq!(binding.service_account_id, account);
        assert_eq!(
            store.list_jwt_bindings(account).await.unwrap(),
            vec![binding.clone()]
        );

        let again = store
            .create_jwt_binding(&cli(), account, ISSUER, "client-1")
            .await;
        assert!(matches!(again, Err(JwtBindingError::AlreadyBound)));

        let other = service_account(&store, "other").await;
        assert!(
            !store
                .delete_jwt_binding(&cli(), other, binding.id)
                .await
                .unwrap()
        );
        assert!(
            store
                .delete_jwt_binding(&cli(), account, binding.id)
                .await
                .unwrap()
        );
        assert_eq!(store.list_jwt_bindings(account).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn only_a_service_account_can_be_bound() {
        let Some(store) = test_store("axon_store_jwt_bindings_kind").await else {
            return;
        };
        let user = login(&store, "alice").await;
        let result = store
            .create_jwt_binding(&cli(), user.id, ISSUER, "client-1")
            .await;
        assert!(matches!(
            result,
            Err(JwtBindingError::UnknownServiceAccount)
        ));
        let result = store
            .create_jwt_binding(&cli(), Uuid::new_v4(), ISSUER, "client-1")
            .await;
        assert!(matches!(
            result,
            Err(JwtBindingError::UnknownServiceAccount)
        ));
    }

    #[tokio::test]
    async fn a_subject_resolves_to_its_binding_before_a_user() {
        let Some(store) = test_store("axon_store_jwt_bindings_resolve").await else {
            return;
        };
        let alice = login(&store, "alice").await;
        assert_eq!(
            store.resolve_jwt_subject(ISSUER, "alice").await.unwrap(),
            Some(JwtSubject::User(alice))
        );
        assert_eq!(
            store.resolve_jwt_subject(ISSUER, "nobody").await.unwrap(),
            None
        );

        let account = service_account(&store, "ci").await;
        store
            .create_jwt_binding(&cli(), account, ISSUER, "alice")
            .await
            .unwrap();
        let Some(JwtSubject::ServiceAccount(resolved)) =
            store.resolve_jwt_subject(ISSUER, "alice").await.unwrap()
        else {
            panic!("the binding must win over the user");
        };
        assert_eq!(resolved.id, account);

        // another issuer with the same subject is a different subject
        assert_eq!(
            store
                .resolve_jwt_subject("https://other.example", "alice")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn disabled_and_inactive_subjects_do_not_resolve() {
        let Some(store) = test_store("axon_store_jwt_bindings_disabled").await else {
            return;
        };
        let account = service_account(&store, "ci").await;
        store
            .create_jwt_binding(&cli(), account, ISSUER, "client-1")
            .await
            .unwrap();
        assert!(
            store
                .set_service_account_disabled(&cli(), account, true)
                .await
                .unwrap()
        );
        assert_eq!(
            store.resolve_jwt_subject(ISSUER, "client-1").await.unwrap(),
            None
        );

        let bob = login(&store, "bob").await;
        sqlx::query("update users set last_login_at = now() - interval '91 days' where id = $1")
            .bind(bob.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.resolve_jwt_subject(ISSUER, "bob").await.unwrap(),
            None
        );
        sqlx::query("update users set last_login_at = now(), disabled_at = now() where id = $1")
            .bind(bob.id)
            .execute(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            store.resolve_jwt_subject(ISSUER, "bob").await.unwrap(),
            None
        );
    }
}
