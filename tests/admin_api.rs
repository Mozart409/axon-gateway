//! The `/api/v1` admin API end to end: the real gateway binary, a real
//! Postgres schema, the mock identity provider and a mock MCP backend.
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

use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, poll_until};

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

    /// A request with the session cookie; writes carry the CSRF token.
    fn api(&self, method: Method, path: &str, session: &Session) -> RequestBuilder {
        let request = self
            .client
            .request(method.clone(), self.url(path))
            .header(COOKIE, &session.cookie);
        if method == Method::GET {
            request
        } else {
            request.header("x-csrf-token", &session.csrf)
        }
    }

    /// Like [`Harness::api`] with a JSON body; returns status and body.
    async fn send(
        &self,
        method: Method,
        path: &str,
        session: &Session,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.api(method, path, session);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let resp = request.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, body)
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

/// The id of the user with this email, from `GET /api/v1/users`.
async fn user_id(h: &Harness, admin: &Session, email: &str) -> String {
    let (status, body) = h.send(Method::GET, "/api/v1/users", admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn an_admin_grants_a_tool_to_a_group_and_its_members_see_it() {
    let Some(h) = Harness::start("axon_admin_api_flow").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    // `me` reports roles and permissions.
    let (status, me) = h.send(Method::GET, "/api/v1/me", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["user"]["email"], "root@example.com");
    assert!(me["roles"].as_array().unwrap().contains(&json!("admin")));
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("groups.manage"))
    );
    let (_, me) = h.send(Method::GET, "/api/v1/me", &bob, None).await;
    assert_eq!(me["roles"], json!(["member"]));
    assert_eq!(me["groups"], json!(["authenticated"]));

    // Nothing is granted yet.
    assert!(!h.tools_page(&bob).await.contains(">on<"));

    // A group, mapped to bob's claim, with a grant on `files`.
    let (status, group) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "devs", "description": "Developers" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    assert_eq!(group["source"], "local");
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups/devs/idp-mappings",
            &admin,
            Some(json!({ "provider": "mock", "value": "bob-claim" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, grant) = h
        .send(
            Method::POST,
            "/api/v1/grants",
            &admin,
            Some(json!({ "group": "devs", "backend": "files", "include": ["read_*"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let grant_id = grant["id"].as_i64().unwrap();

    // The tool is allowed for bob once the backend's tools have connected.
    let page = poll_until(50, Duration::from_millis(100), || async {
        let page = h.tools_page(&bob).await;
        page.contains(">on<").then_some(page)
    })
    .await
    .expect("bob should see files_read_file as allowed");
    assert!(page.contains("files_read_file"));
    let (_, me) = h.send(Method::GET, "/api/v1/me", &bob, None).await;
    assert_eq!(me["groups"], json!(["authenticated", "devs"]));

    // The listings show the group and the grant.
    let (_, groups) = h.send(Method::GET, "/api/v1/groups", &admin, None).await;
    let mut names: Vec<&str> = groups["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["devs", "ops"]);
    let (_, group) = h
        .send(Method::GET, "/api/v1/groups/devs", &admin, None)
        .await;
    assert_eq!(
        group["idp_mappings"],
        json!([{ "provider": "mock", "value": "bob-claim" }])
    );
    let (_, grants) = h.send(Method::GET, "/api/v1/grants", &admin, None).await;
    assert_eq!(grants["grants"][0]["id"], grant_id);
    assert_eq!(grants["grants"][0]["source"], "local");

    // Removing the grant takes the tool away again.
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/grants/{grant_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!h.tools_page(&bob).await.contains(">on<"));

    // Membership by user id and role bindings.
    let bob_id = user_id(&h, &admin, "bob@example.com").await;
    let (status, _) = h
        .send(
            Method::PUT,
            &format!("/api/v1/groups/devs/members/{bob_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h
        .send(
            Method::PUT,
            &format!("/api/v1/groups/devs/members/{bob_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, binding) = h
        .send(
            Method::POST,
            "/api/v1/role-bindings",
            &admin,
            Some(json!({ "role": "auditor", "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{binding}");
    let (status, audit) = h.send(Method::GET, "/api/v1/audit", &bob, None).await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/role-bindings/{}", binding["id"]),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.send(Method::GET, "/api/v1/audit", &bob, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_admins_cannot_write_or_list() {
    let Some(h) = Harness::start("axon_admin_api_forbidden").await else {
        return;
    };
    let bob = h.login_as("bob", "bob@example.com", &[]).await;

    for (method, path, body) in [
        (
            Method::POST,
            "/api/v1/groups",
            Some(json!({ "name": "devs" })),
        ),
        (
            Method::POST,
            "/api/v1/grants",
            Some(json!({ "group": "authenticated", "backend": "files" })),
        ),
        (
            Method::POST,
            "/api/v1/role-bindings",
            Some(json!({ "role": "admin", "group": "authenticated" })),
        ),
        (Method::GET, "/api/v1/groups", None),
        (Method::GET, "/api/v1/grants", None),
        (Method::GET, "/api/v1/role-bindings", None),
        (Method::GET, "/api/v1/users", None),
        (Method::GET, "/api/v1/audit", None),
    ] {
        let (status, body) = h.send(method, path, &bob, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(body["error"].is_string());
    }
}

#[tokio::test]
async fn groups_from_the_imported_file_are_ordinary_groups() {
    let Some(h) = Harness::start("axon_admin_api_config").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    let (_, group) = h
        .send(Method::GET, "/api/v1/groups/ops", &admin, None)
        .await;
    assert_eq!(group["source"], "local");
    assert_eq!(group["description"], "Operations");

    let (status, body) = h
        .send(
            Method::PATCH,
            "/api/v1/groups/ops",
            &admin,
            Some(json!({ "description": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/groups/ops/idp-mappings",
            &admin,
            Some(json!({ "provider": "mock", "value": "ops" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (_, group) = h
        .send(Method::GET, "/api/v1/groups/ops", &admin, None)
        .await;
    assert_eq!(group["description"], "x");

    // The name is taken, as for any group.
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "ops" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = h
        .send(Method::DELETE, "/api/v1/groups/ops", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = h
        .send(Method::GET, "/api/v1/groups/ops", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Bad input and unknown things.
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "Not Valid" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .send(Method::POST, "/api/v1/groups", &admin, Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/grants",
            &admin,
            Some(json!({ "group": "ops", "backend": "nowhere" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = h
        .send(Method::DELETE, "/api/v1/groups/missing", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .send(Method::DELETE, "/api/v1/grants/999999", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn writes_need_the_csrf_token_and_a_same_site_request() {
    let Some(h) = Harness::start("axon_admin_api_csrf").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let body = json!({ "name": "devs" });

    let resp = h
        .client
        .post(h.url("/api/v1/groups"))
        .header(COOKIE, &admin.cookie)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = h
        .client
        .post(h.url("/api/v1/groups"))
        .header(COOKIE, &admin.cookie)
        .header("x-csrf-token", "wrong")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = h
        .api(Method::POST, "/api/v1/groups", &admin)
        .header("sec-fetch-site", "cross-site")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // None of that created the group.
    let (status, _) = h
        .send(Method::GET, "/api/v1/groups/devs", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A broken body is a 400 with a JSON error.
    let resp = h
        .api(Method::POST, "/api/v1/groups", &admin)
        .header(CONTENT_TYPE, "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let error: Value = resp.json().await.unwrap();
    assert!(error["error"].is_string());
}

#[tokio::test]
async fn the_api_needs_a_session() {
    let Some(h) = Harness::start("axon_admin_api_unauthenticated").await else {
        return;
    };

    let resp = h.client.get(h.url("/api/v1/me")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({ "error": "not signed in" }));

    let resp = h
        .client
        .post(h.url("/api/v1/groups"))
        .json(&json!({ "name": "devs" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_audit_log_lists_the_writes_with_their_actor() {
    let Some(h) = Harness::start("axon_admin_api_audit").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    for name in ["one", "two"] {
        let (status, _) = h
            .send(
                Method::POST,
                "/api/v1/groups",
                &admin,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    let (status, _) = h
        .send(Method::DELETE, "/api/v1/groups/one", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, audit) = h.send(Method::GET, "/api/v1/audit", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let entries = audit["entries"].as_array().unwrap();
    let actions: Vec<&str> = entries
        .iter()
        .map(|entry| entry["action"].as_str().unwrap())
        .collect();
    // the oldest entry is the harness's import of the config file
    assert_eq!(
        actions,
        [
            "group.delete",
            "group.create",
            "group.create",
            "config.import"
        ]
    );
    assert_eq!(entries[0]["actor"], "root@example.com");
    assert_eq!(entries[0]["target"], "group:one");
    assert!(entries[0]["actor_user_id"].is_string());

    // Paging: `before` an id and `limit` bound the list.
    let newest = entries[0]["id"].as_i64().unwrap();
    let (_, page) = h
        .send(
            Method::GET,
            &format!("/api/v1/audit?limit=1&before={newest}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(page["entries"].as_array().unwrap().len(), 1);
    assert_eq!(page["entries"][0]["action"], "group.create");
}

#[tokio::test]
async fn the_api_is_not_found_in_standalone_mode() {
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind).render();
    let gateway = Gateway::start(&config, &format!("http://{bind}")).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("{}/api/v1/me", gateway.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());

    let resp = client
        .post(format!("{}/api/v1/groups", gateway.base))
        .json(&json!({ "name": "devs" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
