//! Resource-server mode end to end: the real gateway binary, a real Postgres
//! schema, the mock identity provider and a mock MCP backend. A JWT access
//! token the provider issued is a bearer token that acts as the user with that
//! subject, or as the service account bound to it.
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

use std::time::Duration;

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// `it` and `sales` come from claim values of the `mock` provider and are
/// granted different tools of `files`.
const RBAC: &str = r#"
[[rbac.groups]]
name = "it"
idp = [{ provider = "mock", value = "it-claim" }]

[[rbac.groups]]
name = "sales"
idp = [{ provider = "mock", value = "sales-claim" }]

[[rbac.grants]]
group = "it"
backend = "files"
include = ["read_file", "list_files"]

[[rbac.grants]]
group = "sales"
backend = "files"
include = ["delete_file"]
"#;

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// A multi-user gateway in front of a `files` backend whose provider accepts
/// access tokens, in its own schema. Users whose groups claim holds `admins`
/// are admins.
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
        let backend = MockBackend::start(&["read_file", "list_files", "delete_file"]).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .http_backend("files", &backend.url())
            .database(DATABASE_ENV)
            .oidc_provider(
                "mock",
                idp.issuer(),
                "axon-test",
                "admin_groups = [\"admins\"]\naccept_access_tokens = true",
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
    fn api(&self, method: &Method, path: &str, session: &Session) -> RequestBuilder {
        let request = self
            .client
            .request(method.clone(), self.url(path))
            .header(COOKIE, &session.cookie);
        if *method == Method::GET {
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
        let mut request = self.api(&method, path, session);
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

    /// A JSON-RPC call to `/mcp` with a bearer token.
    async fn mcp(&self, bearer: &str, body: &Value) -> (StatusCode, Value) {
        mcp_post(&self.client, &self.url("/mcp"), Some(bearer), body).await
    }

    /// The status of `tools/list` with this bearer token.
    async fn mcp_status(&self, bearer: &str) -> StatusCode {
        self.mcp(bearer, &rpc("tools/list")).await.0
    }

    /// The tool names `tools/list` returns for a token, sorted, once the
    /// backend's tools have connected (the token must be allowed some tool).
    async fn connected_tool_names(&self, token: &str) -> Vec<String> {
        poll_until(50, Duration::from_millis(100), || async {
            let (status, body) = self.mcp(token, &rpc("tools/list")).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let mut names: Vec<String> = body["result"]["tools"]
                .as_array()
                .unwrap_or_else(|| panic!("no tools in {body}"))
                .iter()
                .map(|tool| tool["name"].as_str().unwrap().to_string())
                .collect();
            names.sort();
            Some(names).filter(|names| !names.is_empty())
        })
        .await
        .expect("the files backend should connect")
    }

    /// A service account in a group that may read files; returns its id.
    async fn reader_account(&self, admin: &Session, name: &str) -> String {
        let (status, account) = self
            .send(
                Method::POST,
                "/api/v1/service-accounts",
                admin,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{account}");
        let id = account["id"].as_str().unwrap().to_string();

        let (status, _) = self
            .send(
                Method::POST,
                "/api/v1/groups",
                admin,
                Some(json!({ "name": "agents" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED);
        let (status, grant) = self
            .send(
                Method::POST,
                "/api/v1/grants",
                admin,
                Some(json!({ "group": "agents", "backend": "files", "include": ["read_file"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{grant}");
        let (status, _) = self
            .send(
                Method::PUT,
                &format!("/api/v1/groups/agents/members/{id}"),
                admin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        id
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
async fn a_jwt_acts_as_the_user_who_logged_in_with_that_subject() {
    let Some(h) = Harness::start("axon_jwt_user").await else {
        return;
    };
    h.login_as("alice", "alice@example.com", &["it-claim"])
        .await;

    // No groups in the token: the groups of the last login apply.
    let token = h.idp.mint_access_token(&json!({ "sub": "alice" }));
    assert_eq!(
        h.connected_tool_names(&token).await,
        ["files_list_files", "files_read_file"]
    );
    let (status, body) = h.mcp(&token, &rpc_call("files_read_file", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");

    // Groups in the token replace them.
    let token = h
        .idp
        .mint_access_token(&json!({ "sub": "alice", "groups": ["sales-claim"] }));
    assert_eq!(h.connected_tool_names(&token).await, ["files_delete_file"]);
}

#[tokio::test]
async fn a_jwt_of_an_unknown_subject_or_a_bad_token_is_refused() {
    let Some(h) = Harness::start("axon_jwt_refused").await else {
        return;
    };
    h.login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let good = h.idp.mint_access_token(&json!({ "sub": "alice" }));
    h.connected_tool_names(&good).await;

    // Nobody with this subject has logged in, and none is bound to it.
    let stranger = h.idp.mint_access_token(&json!({ "sub": "mallory" }));
    assert_eq!(h.mcp_status(&stranger).await, StatusCode::UNAUTHORIZED);

    // Another audience, an expired token and another issuer.
    for changes in [
        json!({ "sub": "alice", "aud": "someone-else" }),
        json!({ "sub": "alice", "exp": 1_000, "iat": 900 }),
        json!({ "sub": "alice", "iss": "http://127.0.0.1:1" }),
        json!({ "sub": "alice", "nonce": "n" }),
        json!({ "sub": "alice", "typ": "ID" }),
    ] {
        let token = h.idp.mint_access_token(&changes);
        assert_eq!(
            h.mcp_status(&token).await,
            StatusCode::UNAUTHORIZED,
            "{changes}"
        );
    }

    // The ID token of the login is not an access token.
    let id_token = h.idp.last_id_token().expect("a login issued an ID token");
    assert_eq!(h.mcp_status(&id_token).await, StatusCode::UNAUTHORIZED);

    // And the good one still works.
    assert_eq!(h.mcp_status(&good).await, StatusCode::OK);
}

#[tokio::test]
async fn a_jwt_acts_as_the_service_account_bound_to_its_subject() {
    let Some(h) = Harness::start("axon_jwt_service_account").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let id = h.reader_account(&admin, "ci-bot").await;
    let path = format!("/api/v1/service-accounts/{id}/jwt-bindings");

    let client_token = h
        .idp
        .mint_access_token(&json!({ "sub": "client-123", "groups": ["sales-claim"] }));
    assert_eq!(h.mcp_status(&client_token).await, StatusCode::UNAUTHORIZED);

    // Only the issuer of a provider that accepts access tokens can be bound.
    let (status, body) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({ "issuer": "https://other.example", "subject": "client-123" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body.to_string().contains("accept_access_tokens"),
        "a clear message: {body}"
    );

    let (status, binding) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({ "issuer": h.idp.issuer(), "subject": "client-123" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{binding}");
    assert_eq!(binding["subject"], "client-123");
    let binding_id = binding["id"].as_str().unwrap().to_string();

    let (status, _) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({ "issuer": h.idp.issuer(), "subject": "client-123" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, listed) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["jwt_bindings"].as_array().unwrap().len(), 1);

    // The account's groups apply, not the token's.
    assert_eq!(
        h.connected_tool_names(&client_token).await,
        ["files_read_file"]
    );

    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("{path}/{binding_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(h.mcp_status(&client_token).await, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("{path}/{binding_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_an_admin_manages_bindings() {
    let Some(h) = Harness::start("axon_jwt_bindings_admin").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let id = h.reader_account(&admin, "ci-bot").await;
    let path = format!("/api/v1/service-accounts/{id}/jwt-bindings");

    let member = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (status, _) = h.send(Method::GET, &path, &member, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .send(
            Method::POST,
            &path,
            &member,
            Some(json!({ "issuer": h.idp.issuer(), "subject": "client-123" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
