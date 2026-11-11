//! The `/ui/admin` pages and their htmx actions end to end: the real gateway
//! binary, a real Postgres schema, the mock identity provider and a mock MCP
//! backend.
//!
//! The tests that need a database skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const FORM: &str = "application/x-www-form-urlencoded";

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// `ops` comes from the imported file and is an ordinary group.
const RBAC: &str = r#"
[[rbac.groups]]
name = "ops"
description = "Operations"
"#;

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// A multi-user gateway in front of a `files` backend, in its own schema.
/// Users whose groups claim holds `admins` are admins.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
    _backend: MockBackend,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let backend = MockBackend::start(&["read_file", "delete_file"]).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .http_backend("files", &backend.url())
            .database(DATABASE_ENV)
            .oidc_provider(
                "mock",
                idp.issuer(),
                "axon-test",
                "admin_groups = [\"admins\"]",
            )
            .rbac(RBAC)
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

        Some(Self {
            gateway,
            client: no_redirect_client(),
            idp,
            _backend: backend,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    /// Form-encodes `fields` as the htmx forms do.
    fn encode(fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(name, value)| format!("{}={}", percent(name), percent(value)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// `GET path` with the session cookie; returns the response.
    async fn get(&self, path: &str, session: &Session) -> Response {
        self.client
            .get(self.url(path))
            .header(COOKIE, &session.cookie)
            .send()
            .await
            .unwrap()
    }

    /// An action POST with the session cookie and, unless `csrf` is false,
    /// the session's CSRF token.
    fn action(&self, path: &str, session: &Session, fields: &[(&str, &str)]) -> RequestBuilder {
        self.client
            .request(Method::POST, self.url(path))
            .header(COOKIE, &session.cookie)
            .header("x-csrf-token", &session.csrf)
            .header(CONTENT_TYPE, FORM)
            .body(Self::encode(fields))
    }

    /// Sends an action; returns the response.
    async fn post(&self, path: &str, session: &Session, fields: &[(&str, &str)]) -> Response {
        self.action(path, session, fields).send().await.unwrap()
    }

    /// The text of a page, which must answer `status`.
    async fn page(&self, path: &str, session: &Session, status: StatusCode) -> String {
        let resp = self.get(path, session).await;
        assert_eq!(resp.status(), status, "{path}");
        resp.text().await.unwrap()
    }

    /// A complete login as the user the mock provider is set to.
    async fn login_as(&self, subject: &str, email: &str, groups: &[&str]) -> Session {
        self.idp.set_user(json!({
            "sub": subject,
            "email": email,
            "name": subject,
            "groups": groups,
        }));
        let resp = self
            .client
            .get(self.url("/auth/login"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let login_url = self.url(&location(&resp));

        let resp = self.client.get(login_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let login_cookie = cookie_pair(&resp, LOGIN_COOKIE).expect("a login cookie");
        let provider_url = location(&resp);

        // The mock approves on the spot and sends the browser back.
        let resp = self.client.get(provider_url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let callback = location(&resp);

        let resp = self
            .client
            .get(callback)
            .header(COOKIE, login_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let cookie = cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie");

        let page = self
            .client
            .get(self.url("/ui/tools"))
            .header(COOKIE, &cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        Session {
            cookie,
            csrf: csrf_token(&page),
        }
    }

    /// The My tools page of the session.
    async fn tools_page(&self, session: &Session) -> String {
        let resp = self
            .client
            .get(self.url("/ui/tools"))
            .header(COOKIE, &session.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.text().await.unwrap()
    }
}

/// Recreate `schema` and return a URL whose `search_path` points at it.
async fn isolated_url(base: &str, schema: &str) -> String {
    let pool = sqlx::PgPool::connect(base)
        .await
        .expect("the test database must be reachable");
    for statement in [
        format!("drop schema if exists {schema} cascade"),
        format!("create schema {schema}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .expect("the test database must allow recreating the test schema");
    }
    pool.close().await;

    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client should build")
}

fn location(resp: &Response) -> String {
    resp.headers()
        .get(LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// `name=value` of the cookie `name`, ready for a `Cookie` header.
fn cookie_pair(resp: &Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|header| header.split(';').next().map(str::to_string))
}

/// The CSRF token a dashboard page carries for htmx.
fn csrf_token(page: &str) -> String {
    let marker = "name=\"csrf-token\" content=\"";
    let start = page.find(marker).expect("a csrf-token meta tag") + marker.len();
    let len = page[start..].find('"').expect("a closed attribute");
    page[start..start + len].to_string()
}

fn percent(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// The id of the user with this email, from `GET /api/v1/users`.
async fn user_id(h: &Harness, admin: &Session, email: &str) -> String {
    let resp = h.get("/api/v1/users", admin).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    body["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["email"] == email)
        .unwrap_or_else(|| panic!("no user {email} in {body}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A response's header as text.
fn header(resp: &Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
        .to_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn an_admin_manages_groups_mappings_grants_and_members_through_the_ui() {
    let Some(h) = Harness::start("axon_admin_ui_flow").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let _bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    let page = h.page("/ui/admin", &admin, StatusCode::OK).await;
    assert!(page.contains("ops"));
    assert!(page.contains("Create group"));

    // A group: the answer is the groups section.
    let resp = h
        .post(
            "/ui/actions/admin/groups",
            &admin,
            &[("name", "devs"), ("description", "Developers")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = resp.text().await.unwrap();
    assert!(html.contains("id=\"admin-groups\""));
    assert!(html.contains("/ui/admin/groups/devs"));
    assert!(html.contains("Developers"));

    // An IdP mapping and a hand-added member, on the group page.
    let resp = h
        .post(
            "/ui/actions/admin/groups/devs/idp-mappings/add",
            &admin,
            &[("provider", "mock"), ("value", "bob-claim")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("bob-claim"));
    let bob_id = user_id(&h, &admin, "bob@example.com").await;
    let resp = h
        .post(
            "/ui/actions/admin/groups/devs/members/add",
            &admin,
            &[("user_id", bob_id.as_str())],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("bob@example.com"));

    // A grant with a comma separated include list.
    let resp = h
        .post(
            "/ui/actions/admin/grants",
            &admin,
            &[
                ("group", "devs"),
                ("backend", "files"),
                ("include", "read_*, list_*"),
                ("exclude", ""),
                ("read_only", "true"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let html = resp.text().await.unwrap();
    assert!(html.contains("id=\"admin-grants\""));
    assert!(html.contains("read_*, list_*"));

    // A role binding for the group.
    let resp = h
        .post(
            "/ui/actions/admin/role-bindings",
            &admin,
            &[("role", "auditor"), ("group", "devs"), ("user_id", "")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("auditor"));

    // The pages show all of it.
    let page = h.page("/ui/admin", &admin, StatusCode::OK).await;
    assert!(page.contains("devs"));
    assert!(page.contains("read_*, list_*"));
    assert!(page.contains("auditor"));
    let page = h
        .page("/ui/admin/groups/devs", &admin, StatusCode::OK)
        .await;
    assert!(page.contains("bob-claim"));
    assert!(page.contains("bob@example.com"));

    // Deleting a grant re-renders the grants section.
    let grant_id = page_delete_id(&h.page("/ui/admin", &admin, StatusCode::OK).await, "grants");
    let resp = h
        .post(
            &format!("/ui/actions/admin/grants/{grant_id}/delete"),
            &admin,
            &[],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.text().await.unwrap().contains("read_*, list_*"));

    // Removing the mapping and the member.
    let resp = h
        .post(
            "/ui/actions/admin/groups/devs/idp-mappings/remove",
            &admin,
            &[("provider", "mock"), ("value", "bob-claim")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.text().await.unwrap().contains("bob-claim"));
    let resp = h
        .post(
            "/ui/actions/admin/groups/devs/members/remove",
            &admin,
            &[("user_id", bob_id.as_str())],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The description can be changed.
    let resp = h
        .post(
            "/ui/actions/admin/groups/devs/update",
            &admin,
            &[("description", "Engineers")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("Engineers"));

    // Deleting the group sends the browser back to the overview.
    let resp = h
        .post("/ui/actions/admin/groups/devs/delete", &admin, &[])
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header(&resp, "hx-redirect"), "/ui/admin");
    let page = h.page("/ui/admin", &admin, StatusCode::OK).await;
    assert!(!page.contains("/ui/admin/groups/devs"));
}

/// The id in the first `/ui/actions/admin/<kind>/{id}/delete` of a page.
fn page_delete_id(page: &str, kind: &str) -> String {
    let marker = format!("/ui/actions/admin/{kind}/");
    let start = page.find(&marker).expect("a delete button") + marker.len();
    let len = page[start..].find('/').expect("an id");
    page[start..start + len].to_string()
}

#[tokio::test]
async fn a_member_gets_403_on_the_pages_and_on_actions() {
    let Some(h) = Harness::start("axon_admin_ui_member").await else {
        return;
    };
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    for path in ["/ui/admin", "/ui/admin/groups/ops", "/ui/admin/audit"] {
        let page = h.page(path, &bob, StatusCode::FORBIDDEN).await;
        assert!(page.contains("Not allowed"), "{path}");
    }

    // The error is the flash fragment, aimed at the flash area.
    let resp = h
        .post("/ui/actions/admin/groups", &bob, &[("name", "mine")])
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(header(&resp, "hx-retarget"), "#admin-flash");
    assert_eq!(header(&resp, "hx-reswap"), "innerHTML");
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("you are not allowed to do that")
    );
}

#[tokio::test]
async fn an_action_without_the_csrf_token_is_forbidden() {
    let Some(h) = Harness::start("axon_admin_ui_csrf").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    let resp = h
        .client
        .post(h.url("/ui/actions/admin/groups"))
        .header(COOKIE, &admin.cookie)
        .header(CONTENT_TYPE, FORM)
        .body("name=sneaky")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let page = h.page("/ui/admin", &admin, StatusCode::OK).await;
    assert!(!page.contains("sneaky"));
}

#[tokio::test]
async fn a_group_from_the_imported_file_has_forms_and_can_be_deleted() {
    let Some(h) = Harness::start("axon_admin_ui_config").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // The imported group is an ordinary one, with its forms.
    let page = h.page("/ui/admin/groups/ops", &admin, StatusCode::OK).await;
    assert!(page.contains("/ui/actions/admin/groups/ops/"));
    assert!(!page.contains("read-only"));

    let resp = h
        .post("/ui/actions/admin/groups/ops/delete", &admin, &[])
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(header(&resp, "hx-redirect"), "/ui/admin");
    let page = h.page("/ui/admin", &admin, StatusCode::OK).await;
    assert!(!page.contains("/ui/admin/groups/ops"));

    let resp = h
        .post(
            "/ui/actions/admin/groups",
            &admin,
            &[("name", "Not Valid!")],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = h
        .post("/ui/actions/admin/groups/nope/delete", &admin, &[])
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_audit_page_lists_the_ui_actions() {
    let Some(h) = Harness::start("axon_admin_ui_audit").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    for name in ["one", "two"] {
        let resp = h
            .post("/ui/actions/admin/groups", &admin, &[("name", name)])
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = h
        .post("/ui/actions/admin/groups/one/delete", &admin, &[])
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let page = h.page("/ui/admin/audit", &admin, StatusCode::OK).await;
    assert!(page.contains("group.create"));
    assert!(page.contains("group.delete"));
    assert!(page.contains("root@example.com"));
    assert!(page.contains("group:one"));
    assert!(page.contains("group:two"));
    assert!(!page.contains("Older"));

    // An unknown `before` shows nothing older.
    let page = h
        .page("/ui/admin/audit?before=1", &admin, StatusCode::OK)
        .await;
    assert!(!page.contains("group:two"));
    assert!(page.contains("Newest"));
}

#[tokio::test]
async fn the_admin_link_shows_for_admins_only() {
    let Some(h) = Harness::start("axon_admin_ui_link").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    assert!(h.tools_page(&admin).await.contains("href=\"/ui/admin\""));
    assert!(!h.tools_page(&bob).await.contains("/ui/admin"));
}

#[tokio::test]
async fn the_admin_pages_are_not_found_in_standalone_mode() {
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind).render();
    let gateway = Gateway::start(&config, &format!("http://{bind}")).await;
    let client = no_redirect_client();

    for path in ["/ui/admin", "/ui/admin/groups/ops", "/ui/admin/audit"] {
        let resp = client
            .get(format!("{}{path}", gateway.base))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let resp = client
        .post(format!("{}/ui/actions/admin/groups", gateway.base))
        .header(CONTENT_TYPE, FORM)
        .body("name=devs")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
