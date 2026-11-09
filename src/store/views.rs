//! Per-user tool opt-outs: the tools a user hides from their own tool list
//!
//! This is a view preference, not an access control. Hiding a tool does not
//! stop calls to it.

use uuid::Uuid;

use super::{Store, StoreError};

/// One opt-out: a whole backend (`tool` is `None`) or one tool of a backend
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptOut {
    pub backend: String,
    /// The tool's original name; `None` hides the whole backend
    pub tool: Option<String>,
}

impl Store {
    /// The user's opt-outs, sorted by backend then tool, whole backend first
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn opt_outs(&self, user_id: Uuid) -> Result<Vec<OptOut>, StoreError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "select backend, tool from tool_opt_outs where user_id = $1 order by backend, tool",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(backend, tool)| OptOut {
                backend,
                tool: (!tool.is_empty()).then_some(tool),
            })
            .collect())
    }

    /// Hides the backend (`tool` is `None`) or one tool of it, or shows it
    /// again when `hidden` is false. `Some("")` means the whole backend.
    /// Returns whether a row was inserted or removed.
    ///
    /// # Errors
    /// Fails when the query fails, e.g. for a user that does not exist.
    pub async fn set_opt_out(
        &self,
        user_id: Uuid,
        backend: &str,
        tool: Option<&str>,
        hidden: bool,
    ) -> Result<bool, StoreError> {
        let tool = tool.unwrap_or_default();
        let result = if hidden {
            sqlx::query(
                "insert into tool_opt_outs (user_id, backend, tool) values ($1, $2, $3) \
                 on conflict do nothing",
            )
            .bind(user_id)
            .bind(backend)
            .bind(tool)
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query(
                "delete from tool_opt_outs where user_id = $1 and backend = $2 and tool = $3",
            )
            .bind(user_id)
            .bind(backend)
            .bind(tool)
            .execute(&self.pool)
            .await?
        };
        Ok(result.rows_affected() > 0)
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

    fn opt_out(backend: &str, tool: Option<&str>) -> OptOut {
        OptOut {
            backend: backend.to_string(),
            tool: tool.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn new_user_has_no_opt_outs() {
        let Some(store) = test_store("axon_store_views_empty").await else {
            return;
        };
        let user = test_user(&store, "alice").await;

        assert_eq!(store.opt_outs(user).await.unwrap(), Vec::<OptOut>::new());
    }

    #[tokio::test]
    async fn whole_backend_is_listed_before_its_tools() {
        let Some(store) = test_store("axon_store_views_order").await else {
            return;
        };
        let user = test_user(&store, "alice").await;

        assert!(
            store
                .set_opt_out(user, "github", Some("create_issue"), true)
                .await
                .unwrap()
        );
        assert!(store.set_opt_out(user, "github", None, true).await.unwrap());

        assert_eq!(
            store.opt_outs(user).await.unwrap(),
            [
                opt_out("github", None),
                opt_out("github", Some("create_issue")),
            ]
        );
    }

    #[tokio::test]
    async fn hiding_twice_reports_no_change_the_second_time() {
        let Some(store) = test_store("axon_store_views_twice").await else {
            return;
        };
        let user = test_user(&store, "alice").await;

        assert!(store.set_opt_out(user, "github", None, true).await.unwrap());
        assert!(!store.set_opt_out(user, "github", None, true).await.unwrap());
        // `Some("")` is the whole backend, so it is the same row again.
        assert!(
            !store
                .set_opt_out(user, "github", Some(""), true)
                .await
                .unwrap()
        );

        assert_eq!(
            store.opt_outs(user).await.unwrap(),
            [opt_out("github", None)]
        );
    }

    #[tokio::test]
    async fn unhiding_removes_the_opt_out_and_reports_the_change() {
        let Some(store) = test_store("axon_store_views_unhide").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        assert!(
            store
                .set_opt_out(user, "github", Some("create_issue"), true)
                .await
                .unwrap()
        );

        assert!(
            store
                .set_opt_out(user, "github", Some("create_issue"), false)
                .await
                .unwrap()
        );
        assert!(
            !store
                .set_opt_out(user, "github", Some("create_issue"), false)
                .await
                .unwrap()
        );

        assert_eq!(store.opt_outs(user).await.unwrap(), Vec::<OptOut>::new());
    }

    #[tokio::test]
    async fn opt_outs_belong_to_their_user() {
        let Some(store) = test_store("axon_store_views_users").await else {
            return;
        };
        let alice = test_user(&store, "alice").await;
        let bob = test_user(&store, "bob").await;

        assert!(
            store
                .set_opt_out(alice, "github", None, true)
                .await
                .unwrap()
        );
        assert!(
            store
                .set_opt_out(bob, "github", Some("create_issue"), true)
                .await
                .unwrap()
        );
        assert_eq!(
            store.opt_outs(alice).await.unwrap(),
            [opt_out("github", None)]
        );
        assert_eq!(
            store.opt_outs(bob).await.unwrap(),
            [opt_out("github", Some("create_issue"))]
        );

        // Showing the backend again for bob has nothing to remove and leaves
        // alice's row alone.
        assert!(!store.set_opt_out(bob, "github", None, false).await.unwrap());
        assert_eq!(
            store.opt_outs(alice).await.unwrap(),
            [opt_out("github", None)]
        );
    }

    #[tokio::test]
    async fn deleting_a_user_cascades_to_their_opt_outs() {
        let Some(store) = test_store("axon_store_views_cascade").await else {
            return;
        };
        let user = test_user(&store, "alice").await;
        assert!(store.set_opt_out(user, "github", None, true).await.unwrap());

        sqlx::query("delete from users where id = $1")
            .bind(user)
            .execute(&store.pool)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("select count(*) from tool_opt_outs")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
