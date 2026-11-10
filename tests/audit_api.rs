//! The `/api/v1` audit settings and capture rule routes end to end: the real
//! gateway binary, a real Postgres schema, the mock identity provider and a
//! mock MCP backend. Tool call listings are covered with the `/mcp` hook.
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

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

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
        .expect("the user should be listed")["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The `action` of every admin audit entry, newest first.
async fn audit_actions(h: &Harness, admin: &Session) -> Vec<String> {
    let (status, body) = h.send(Method::GET, "/api/v1/audit", admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["action"].as_str().unwrap().to_string())
        .collect()
}

/// The status of a dashboard page.
async fn page_status(h: &Harness, session: &Session, path: &str) -> (StatusCode, String) {
    let resp = h
        .client
        .get(h.url(path))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    (status, resp.text().await.unwrap())
}

#[tokio::test]
async fn an_admin_manages_the_retention_settings() {
    let Some(h) = Harness::start("axon_audit_api_crud").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // The defaults.
    let (status, settings) = h
        .send(Method::GET, "/api/v1/audit/settings", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(
        settings,
        json!({ "arguments_retention_days": 30, "metadata_retention_days": 365 })
    );

    // Changing them.
    let (status, settings) = h
        .send(
            Method::PUT,
            "/api/v1/audit/settings",
            &admin,
            Some(json!({ "arguments_retention_days": 7, "metadata_retention_days": 90 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["arguments_retention_days"], 7);
    let (_, settings) = h
        .send(Method::GET, "/api/v1/audit/settings", &admin, None)
        .await;
    assert_eq!(
        settings,
        json!({ "arguments_retention_days": 7, "metadata_retention_days": 90 })
    );

    // Bad retentions and bodies change nothing.
    for body in [
        json!({ "arguments_retention_days": 0, "metadata_retention_days": 90 }),
        json!({ "arguments_retention_days": 7, "metadata_retention_days": -1 }),
        json!({ "arguments_retention_days": 7, "metadata_retention_days": 100_000 }),
        json!({ "arguments_retention_days": 7 }),
        json!({ "arguments_retention_days": "seven", "metadata_retention_days": 90 }),
    ] {
        let (status, error) = h
            .send(Method::PUT, "/api/v1/audit/settings", &admin, Some(body))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert!(error["error"].is_string());
    }
    let (_, settings) = h
        .send(Method::GET, "/api/v1/audit/settings", &admin, None)
        .await;
    assert_eq!(settings["metadata_retention_days"], 90);

    // The change is in the admin audit log.
    assert_eq!(
        audit_actions(&h, &admin).await[..1],
        ["audit.settings_update"]
    );
}

#[tokio::test]
async fn an_admin_manages_capture_rules() {
    let Some(h) = Harness::start("axon_audit_api_rules").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // No rules yet.
    let (status, rules) = h
        .send(Method::GET, "/api/v1/audit/capture-rules", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rules, json!({ "rules": [] }));

    // Creating one.
    let (status, rule) = h
        .send(
            Method::POST,
            "/api/v1/audit/capture-rules",
            &admin,
            Some(json!({
                "backend": "files",
                "tool_pattern": "read_*",
                "mode": "full",
                "drop_keys": ["content", " body ", "content"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{rule}");
    assert_eq!(rule["backend"], "files");
    assert_eq!(rule["tool_pattern"], "read_*");
    assert_eq!(rule["mode"], "full");
    assert_eq!(rule["drop_keys"], json!(["content", "body"]));
    let id = rule["id"].as_i64().unwrap();
    // drop_keys is optional.
    let (status, plain) = h
        .send(
            Method::POST,
            "/api/v1/audit/capture-rules",
            &admin,
            Some(json!({ "backend": "*", "tool_pattern": "*", "mode": "none" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{plain}");
    assert_eq!(plain["drop_keys"], json!([]));

    // Bad rules are refused.
    for body in [
        json!({ "backend": "files", "tool_pattern": "read_*", "mode": "everything" }),
        json!({ "backend": "files", "tool_pattern": "a*b", "mode": "none" }),
        json!({ "backend": "fi*", "tool_pattern": "x", "mode": "none" }),
        json!({ "backend": "", "tool_pattern": "x", "mode": "none" }),
        json!({ "backend": "files", "tool_pattern": "", "mode": "none" }),
        json!({ "backend": "files", "tool_pattern": "x" }),
    ] {
        let (status, error) = h
            .send(
                Method::POST,
                "/api/v1/audit/capture-rules",
                &admin,
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
    }

    let (_, rules) = h
        .send(Method::GET, "/api/v1/audit/capture-rules", &admin, None)
        .await;
    let listed: Vec<i64> = rules["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["id"].as_i64().unwrap())
        .collect();
    assert_eq!(listed, vec![id, plain["id"].as_i64().unwrap()]);

    // Deleting one, twice.
    let path = format!("/api/v1/audit/capture-rules/{id}");
    let (status, _) = h.send(Method::DELETE, &path, &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.send(Method::DELETE, &path, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .send(
            Method::DELETE,
            "/api/v1/audit/capture-rules/not-a-number",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Every change is in the admin audit log, newest first.
    assert_eq!(
        audit_actions(&h, &admin).await[..3],
        [
            "audit.rule_delete",
            "audit.rule_create",
            "audit.rule_create"
        ]
    );
}

#[tokio::test]
async fn plain_users_are_forbidden_everywhere() {
    let Some(h) = Harness::start("axon_audit_api_forbidden").await else {
        return;
    };
    let _admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    for (method, path, body) in [
        (Method::GET, "/api/v1/tool-calls", None),
        (Method::GET, "/api/v1/tool-calls/1", None),
        (Method::POST, "/api/v1/tool-calls/1/arguments", None),
        (Method::GET, "/api/v1/audit/settings", None),
        (
            Method::PUT,
            "/api/v1/audit/settings",
            Some(json!({ "arguments_retention_days": 1, "metadata_retention_days": 1 })),
        ),
        (Method::GET, "/api/v1/audit/capture-rules", None),
        (
            Method::POST,
            "/api/v1/audit/capture-rules",
            Some(json!({ "backend": "*", "tool_pattern": "*", "mode": "full" })),
        ),
        (Method::DELETE, "/api/v1/audit/capture-rules/1", None),
    ] {
        let (status, error) = h.send(method, path, &bob, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
        assert!(error["error"].is_string());
    }

    // The pages answer 403 too.
    for path in ["/ui/admin/tool-calls", "/ui/admin/audit-settings"] {
        let (status, _) = page_status(&h, &bob, path).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
}

#[tokio::test]
async fn an_auditor_reads_but_neither_manages_nor_sees_arguments() {
    let Some(h) = Harness::start("axon_audit_api_auditor").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;
    let bob_id = user_id(&h, &admin, "bob@example.com").await;
    let (status, binding) = h
        .send(
            Method::POST,
            "/api/v1/role-bindings",
            &admin,
            Some(json!({ "role": "auditor", "user_id": bob_id })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{binding}");

    for path in [
        "/api/v1/tool-calls",
        "/api/v1/audit/settings",
        "/api/v1/audit/capture-rules",
    ] {
        let (status, body) = h.send(Method::GET, path, &bob, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
    // An unknown call is not found for someone who may look.
    let (status, _) = h
        .send(Method::GET, "/api/v1/tool-calls/999", &bob, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Arguments need `audit.read_sensitive`, which the auditor lacks.
    let (status, _) = h
        .send(Method::POST, "/api/v1/tool-calls/999/arguments", &bob, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Managing needs `gateway.admin`.
    let (status, _) = h
        .send(
            Method::PUT,
            "/api/v1/audit/settings",
            &bob,
            Some(json!({ "arguments_retention_days": 1, "metadata_retention_days": 1 })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/audit/capture-rules",
            &bob,
            Some(json!({ "backend": "*", "tool_pattern": "*", "mode": "full" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The pages render, without the forms.
    let (status, page) = page_status(&h, &bob, "/ui/admin/audit-settings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Capture rules"));
    assert!(!page.contains("Add rule"));
}

#[tokio::test]
async fn the_tool_call_routes_answer_for_an_admin() {
    let Some(h) = Harness::start("axon_audit_api_calls").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    let (status, calls) = h
        .send(Method::GET, "/api/v1/tool-calls", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{calls}");
    assert_eq!(calls, json!({ "calls": [], "next_before": null }));
    let (status, _) = h
        .send(
            Method::GET,
            "/api/v1/tool-calls?backend=files&tool=read_file&outcome=ok&before=10&limit=5",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    for query in ["outcome=denied", "user=alice", "limit=many"] {
        let (status, _) = h
            .send(
                Method::GET,
                &format!("/api/v1/tool-calls?{query}"),
                &admin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let (status, _) = h
        .send(Method::GET, "/api/v1/tool-calls/999", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/tool-calls/999/arguments",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The pages render for an admin.
    let (status, page) = page_status(&h, &admin, "/ui/admin/tool-calls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Tool calls"));
    let (status, page) = page_status(&h, &admin, "/ui/admin/audit-settings").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("BetrVG"));
    assert!(page.contains("Add rule"));
    let (status, _) = page_status(&h, &admin, "/ui/admin/tool-calls/999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, overview) = page_status(&h, &admin, "/ui/admin").await;
    assert!(overview.contains("/ui/admin/tool-calls"));
    assert!(overview.contains("/ui/admin/audit-settings"));
}

#[tokio::test]
async fn the_audit_routes_need_a_session_and_a_csrf_token() {
    let Some(h) = Harness::start("axon_audit_api_guards").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // No session: 401.
    for path in ["/api/v1/tool-calls", "/api/v1/audit/settings"] {
        let resp = h.client.get(h.url(path)).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
    }

    // A session without the CSRF token cannot write or read arguments.
    for (method, path) in [
        (Method::PUT, "/api/v1/audit/settings"),
        (Method::POST, "/api/v1/audit/capture-rules"),
        (Method::DELETE, "/api/v1/audit/capture-rules/1"),
        (Method::POST, "/api/v1/tool-calls/1/arguments"),
    ] {
        let resp = h
            .client
            .request(method, h.url(path))
            .header(COOKIE, &admin.cookie)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
    }
}
