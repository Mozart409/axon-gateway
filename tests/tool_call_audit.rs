//! Tool-call audit end to end: a principal's `tools/call` on `/mcp` lands in
//! `GET /api/v1/tool-calls` with the capture policy applied. The real gateway
//! binary, a real Postgres schema, the mock identity provider and a mock MCP
//! backend.
//!
//! The writer batches every second, so the tests poll for up to 5 s.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

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

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::{MockBackend, MockBackendBuilder};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// `it` may read and list files; nobody is granted `delete_file`.
const RBAC: &str = r#"
[[rbac.groups]]
name = "it"
idp = [{ provider = "mock", value = "it-claim" }]

[[rbac.grants]]
group = "it"
backend = "files"
include = ["read_file", "list_files", "get_info"]
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
        let backend = MockBackendBuilder::new()
            .tool("read_file")
            .tool("list_files")
            .tool("delete_file")
            .read_only_tool("get_info")
            .build()
            .await;
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

    /// A user's own token through the API; returns its id and plaintext.
    async fn create_pat(&self, session: &Session, name: &str) -> (String, String) {
        let (status, token) = self
            .send(
                Method::POST,
                "/api/v1/tokens",
                session,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{token}");
        let plaintext = token["plaintext"]
            .as_str()
            .expect("a plaintext")
            .to_string();
        (token["id"].as_str().unwrap().to_string(), plaintext)
    }

    /// A JSON-RPC call to `/mcp` with a bearer token; status and body.
    async fn mcp(&self, bearer: &str, body: &Value) -> (StatusCode, Value) {
        mcp_post(&self.client, &self.url("/mcp"), Some(bearer), body).await
    }

    /// Waits until the `files` backend has connected, as seen by this token.
    async fn wait_connected(&self, token: &str) {
        poll_until(50, Duration::from_millis(100), || async {
            let (_, body) = self.mcp(token, &rpc("tools/list")).await;
            body["result"]["tools"]
                .as_array()
                .filter(|tools| !tools.is_empty())
                .map(|_| ())
        })
        .await
        .expect("the files backend should connect");
    }

    /// `tools/call` with a token; the whole JSON-RPC answer. A hidden tool's
    /// "method not found" (-32601) comes with HTTP 404.
    async fn call(&self, token: &str, tool: &str, arguments: Value) -> Value {
        let (status, body) = self.mcp(token, &rpc_call(tool, arguments)).await;
        let expected = if body["error"]["code"] == -32601 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::OK
        };
        assert_eq!(status, expected, "{body}");
        body
    }

    /// The audited calls of the original tool name `tool`, newest first.
    async fn calls_of(&self, admin: &Session, tool: &str) -> Vec<Value> {
        let (status, body) = self
            .send(
                Method::GET,
                &format!("/api/v1/tool-calls?tool={tool}"),
                admin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["calls"].as_array().unwrap().clone()
    }

    /// Polls up to 5 s (the writer batches every second) until `count` calls
    /// of `tool` are listed.
    async fn wait_for_calls(&self, admin: &Session, tool: &str, count: usize) -> Vec<Value> {
        poll_until(50, Duration::from_millis(100), || async {
            Some(self.calls_of(admin, tool).await).filter(|calls| calls.len() >= count)
        })
        .await
        .unwrap_or_else(|| panic!("{count} audited call(s) of {tool} should show up within 5 s"))
    }

    /// The stored arguments of an audited call, as the admin reads them.
    async fn arguments_of(&self, admin: &Session, call_id: i64) -> Value {
        let (status, body) = self
            .send(
                Method::POST,
                &format!("/api/v1/tool-calls/{call_id}/arguments"),
                admin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
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

#[tokio::test]
async fn a_pat_call_is_audited_and_its_arguments_are_redacted() {
    let Some(h) = Harness::start("axon_tool_call_audit_pat").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let alice_id = user_id(&h, &admin, "alice@example.com").await;
    let (token_id, pat) = h.create_pat(&alice, "alice laptop").await;
    h.wait_connected(&pat).await;

    // An unannotated tool counts as potentially destructive: arguments are
    // captured, redacted.
    let answer = h
        .call(
            &pat,
            "files_read_file",
            json!({ "password": "x", "q": "y" }),
        )
        .await;
    assert_eq!(answer["error"], Value::Null, "{answer}");

    let calls = h.wait_for_calls(&admin, "read_file", 1).await;
    let call = &calls[0];
    assert_eq!(call["user_id"], alice_id.as_str());
    assert_eq!(call["token_id"], token_id.as_str());
    assert_eq!(call["auth_method"], "pat");
    assert_eq!(call["backend"], "files");
    assert_eq!(call["tool"], "read_file");
    assert_eq!(call["outcome"], "ok");
    assert_eq!(call["client_ip"], "127.0.0.1");
    assert_eq!(call["arguments_capture"], "redacted");

    // Only a reader with `audit.read_sensitive` sees the arguments, and that
    // read is itself audited.
    let stored = h.arguments_of(&admin, call["id"].as_i64().unwrap()).await;
    assert_eq!(stored["capture"], "redacted");
    assert_eq!(stored["arguments"]["q"], "y");
    assert_ne!(stored["arguments"]["password"], "x");
    assert_eq!(stored["arguments"]["password"], "[redacted]");
    assert!(
        audit_actions(&h, &admin)
            .await
            .contains(&"audit.arguments_read".to_string())
    );
}

#[tokio::test]
async fn a_capture_rule_changes_what_the_next_call_stores() {
    let Some(h) = Harness::start("axon_tool_call_audit_rules").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (_, pat) = h.create_pat(&alice, "alice laptop").await;
    h.wait_connected(&pat).await;
    let arguments = json!({ "password": "x", "q": "y" });

    h.call(&pat, "files_list_files", arguments.clone()).await;
    let calls = h.wait_for_calls(&admin, "list_files", 1).await;
    assert_eq!(calls[0]["arguments_capture"], "redacted");

    // The rule needs no 30 s wait: the writer reloads the rules before its
    // next batch.
    let (status, rule) = h
        .send(
            Method::POST,
            "/api/v1/audit/capture-rules",
            &admin,
            Some(json!({ "backend": "files", "tool_pattern": "list_files", "mode": "full" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{rule}");

    h.call(&pat, "files_list_files", arguments.clone()).await;
    let calls = h.wait_for_calls(&admin, "list_files", 2).await;
    // Newest first.
    assert_eq!(calls[0]["arguments_capture"], "full");
    let stored = h
        .arguments_of(&admin, calls[0]["id"].as_i64().unwrap())
        .await;
    assert_eq!(stored["capture"], "full");
    assert_eq!(stored["arguments"], arguments);

    // Deleting the rule brings the default back.
    let rule_id = rule["id"].as_i64().unwrap();
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/audit/capture-rules/{rule_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    h.call(&pat, "files_list_files", arguments).await;
    let calls = h.wait_for_calls(&admin, "list_files", 3).await;
    assert_eq!(calls[0]["arguments_capture"], "redacted");
}

#[tokio::test]
async fn a_read_only_tool_stores_no_arguments() {
    let Some(h) = Harness::start("axon_tool_call_audit_read_only").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (_, pat) = h.create_pat(&alice, "alice laptop").await;
    h.wait_connected(&pat).await;

    h.call(&pat, "files_get_info", json!({ "q": "y" })).await;
    let calls = h.wait_for_calls(&admin, "get_info", 1).await;
    let call = &calls[0];
    assert_eq!(call["outcome"], "ok");
    assert!(
        call["arguments_capture"].is_null() || call["arguments_capture"] == "none",
        "{call}"
    );
    let (status, _) = h
        .send(
            Method::POST,
            &format!("/api/v1/tool-calls/{}/arguments", call["id"]),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_hidden_tool_is_recorded_with_its_error() {
    let Some(h) = Harness::start("axon_tool_call_audit_hidden").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (_, pat) = h.create_pat(&alice, "alice laptop").await;
    h.wait_connected(&pat).await;

    // Granted to nobody: answered like an unknown tool, and recorded.
    let answer = h.call(&pat, "files_delete_file", json!({})).await;
    assert_eq!(answer["error"]["code"], -32601, "{answer}");

    let calls = h.wait_for_calls(&admin, "delete_file", 1).await;
    let call = &calls[0];
    assert_eq!(call["backend"], "files");
    assert_eq!(call["outcome"], "error");
    assert_eq!(call["error_code"], -32601);
}

#[tokio::test]
async fn reading_the_tool_calls_needs_audit_read() {
    let Some(h) = Harness::start("axon_tool_call_audit_forbidden").await else {
        return;
    };
    let _admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["bob-claim"]).await;

    let (status, _) = h.send(Method::GET, "/api/v1/tool-calls", &bob, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
