//! Disabling and re-enabling human users end to end: the real gateway binary,
//! a real Postgres schema and the mock identity provider. An admin disables a
//! user through the JSON API; their session ends, their tokens stop working
//! and they cannot log in again until they are re-enabled.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, rpc};

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
        let backend = MockBackend::start(&["read_file"]).await;
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
        let is_get = method == Method::GET;
        let request = self
            .client
            .request(method, self.url(path))
            .header(COOKIE, &session.cookie);
        if is_get {
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

    /// The login up to the gateway's callback, as the user the mock provider
    /// is set to; returns the callback's answer.
    async fn login_callback(&self, subject: &str, email: &str, groups: &[&str]) -> Response {
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

        self.client
            .get(callback)
            .header(COOKIE, login_cookie)
            .send()
            .await
            .unwrap()
    }

    /// A complete login as the user the mock provider is set to.
    async fn login_as(&self, subject: &str, email: &str, groups: &[&str]) -> Session {
        let resp = self.login_callback(subject, email, groups).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let cookie = cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie");

        let page = self
            .client
            .get(self.url("/ui/tokens"))
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

    /// A user's own token through the API; returns its plaintext.
    async fn create_pat(&self, session: &Session) -> String {
        let (status, token) = self
            .send(
                Method::POST,
                "/api/v1/tokens",
                session,
                Some(json!({ "name": "laptop" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{token}");
        token["plaintext"]
            .as_str()
            .expect("a plaintext")
            .to_string()
    }

    /// The status of `tools/list` with this bearer token.
    async fn mcp_status(&self, bearer: &str) -> StatusCode {
        mcp_post(
            &self.client,
            &self.url("/mcp"),
            Some(bearer),
            &rpc("tools/list"),
        )
        .await
        .0
    }

    /// The id of the user with this email, as the admin API lists it.
    async fn user_id(&self, admin: &Session, email: &str) -> String {
        let (status, body) = self.send(Method::GET, "/api/v1/users", admin, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["users"]
            .as_array()
            .expect("a users array")
            .iter()
            .find(|user| user["email"] == email)
            .unwrap_or_else(|| panic!("no user {email} in {body}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// `PATCH /api/v1/users/{id}` with `{"disabled": ...}`.
    async fn set_disabled(
        &self,
        session: &Session,
        id: &str,
        disabled: bool,
    ) -> (StatusCode, Value) {
        self.send(
            Method::PATCH,
            &format!("/api/v1/users/{id}"),
            session,
            Some(json!({ "disabled": disabled })),
        )
        .await
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

#[tokio::test]
async fn an_admin_disables_and_re_enables_a_user() {
    let Some(h) = Harness::start("axon_users_disable").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h.login_as("alice", "alice@example.com", &[]).await;
    let alice_pat = h.create_pat(&alice).await;
    let alice_id = h.user_id(&admin, "alice@example.com").await;

    assert_eq!(h.mcp_status(&alice_pat).await, StatusCode::OK);
    let (status, _) = h.send(Method::GET, "/api/v1/me", &alice, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = h.set_disabled(&admin, &alice_id, true).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["disabled"], true);
    assert_eq!(body["email"], "alice@example.com");

    // The listing shows it, the audit log records it.
    let (_, users) = h.send(Method::GET, "/api/v1/users", &admin, None).await;
    let listed = users["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["id"] == alice_id.as_str())
        .unwrap();
    assert_eq!(listed["disabled"], true);
    let (_, audit) = h.send(Method::GET, "/api/v1/audit", &admin, None).await;
    let entry = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "user.disable")
        .unwrap_or_else(|| panic!("no user.disable entry in {audit}"));
    assert_eq!(entry["target"], "user:alice@example.com");
    assert_eq!(entry["actor"], "root@example.com");

    // Her session is gone, her token stops working and she cannot log in.
    let (status, _) = h.send(Method::GET, "/api/v1/me", &alice, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.mcp_status(&alice_pat).await, StatusCode::UNAUTHORIZED);
    let resp = h.login_callback("alice", "alice@example.com", &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());

    // Disabling again changes nothing and writes no second audit row.
    let (status, _) = h.set_disabled(&admin, &alice_id, true).await;
    assert_eq!(status, StatusCode::OK);

    // Re-enabled: the token works again, a new login works, the old session
    // stays gone.
    let (status, body) = h.set_disabled(&admin, &alice_id, false).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["disabled"], false);
    assert_eq!(h.mcp_status(&alice_pat).await, StatusCode::OK);
    let (status, _) = h.send(Method::GET, "/api/v1/me", &alice, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let again = h.login_as("alice", "alice@example.com", &[]).await;
    let (status, _) = h.send(Method::GET, "/api/v1/me", &again, None).await;
    assert_eq!(status, StatusCode::OK);

    let (_, audit) = h.send(Method::GET, "/api/v1/audit", &admin, None).await;
    let actions: Vec<&str> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .filter(|action| action.starts_with("user."))
        .collect();
    assert_eq!(actions, ["user.enable", "user.disable"]);
}

#[tokio::test]
async fn only_admins_disable_and_never_themselves() {
    let Some(h) = Harness::start("axon_users_guards").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h.login_as("alice", "alice@example.com", &[]).await;
    let alice_id = h.user_id(&admin, "alice@example.com").await;
    let root_id = h.user_id(&admin, "root@example.com").await;

    // A user without users.manage cannot disable anyone, not even themselves.
    for id in [&alice_id, &root_id] {
        let (status, body) = h.set_disabled(&alice, id, true).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    let (status, body) = h.set_disabled(&admin, &root_id, true).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, _) = h.send(Method::GET, "/api/v1/me", &admin, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = h
        .set_disabled(&admin, "00000000-0000-0000-0000-000000000001", true)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Nothing was disabled, so nothing was audited.
    let (_, audit) = h.send(Method::GET, "/api/v1/audit", &admin, None).await;
    assert!(
        audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| !entry["action"].as_str().unwrap().starts_with("user."))
    );
}
