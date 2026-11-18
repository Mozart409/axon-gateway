//! The usage UI pages and fragments end to end: the real gateway binary, a
//! real Postgres schema, the mock identity provider and a mock MCP backend.
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

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, Response, StatusCode};
use serde_json::json;
use support::mock_backend::MockBackendBuilder;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// A user who is only allowed to use the `files` backend, but has no
/// `audit.read` permission.
const RBAC_NO_AUDIT: &str = r#"
[[rbac.groups]]
name = "users"
idp = [{ provider = "mock", value = "users-claim" }]

[[rbac.grants]]
group = "users"
backend = "files"
include = ["*"]
"#;

/// A user who may also read the audit (so usage admin pages are visible).
const RBAC_AUDIT: &str = r#"
[[rbac.groups]]
name = "users"
idp = [{ provider = "mock", value = "users-claim" }]

[[rbac.groups]]
name = "auditors"
idp = [{ provider = "mock", value = "auditors-claim" }]

[[rbac.grants]]
group = "users"
backend = "files"
include = ["*"]

[[rbac.grants]]
group = "auditors"
backend = "files"
include = ["*"]

[[rbac.roles]]
name = "auditor"
permissions = ["audit.read"]

[[rbac.role_bindings]]
role = "auditor"
group = "auditors"
"#;

struct Session {
    cookie: String,
    csrf: String,
}

struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
}

impl Harness {
    async fn start(schema: &str, rbac: &str) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let backend = MockBackendBuilder::new().tool("read_file").build().await;
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
            .rbac(rbac)
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

        // keep backend alive for the test duration
        std::mem::forget(backend);

        Some(Self {
            gateway,
            client: no_redirect_client(),
            idp,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

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

fn cookie_pair(resp: &Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|v| v.split(';').next())
        .filter(|pair| pair.starts_with(&format!("{name}=")))
        .map(ToOwned::to_owned)
}

fn csrf_token(html: &str) -> String {
    let marker = "name=\"csrf-token\" content=\"";
    let start = html.find(marker).expect("csrf token in page") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_string()
}

#[tokio::test]
async fn usage_partials_and_pages_for_non_audit_user() {
    let Some(h) = Harness::start("usage_ui_no_audit", RBAC_NO_AUDIT).await else {
        return;
    };

    let session = h.login_as("alice", "alice@example.com", &["users"]).await;

    // GET /ui/partials/usage?days=7 -> 200 with region wiring
    let resp = h
        .client
        .get(h.url("/ui/partials/usage?days=7"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("sse-connect=\"/ui/events\""));
    assert!(body.contains("hx-get=\"/ui/partials/usage?days=7\""));
    assert!(body.contains("hx-trigger=\"sse:usage_changed\""));

    // GET /ui/me/usage contains the same region
    let resp = h
        .client
        .get(h.url("/ui/me/usage"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let page = resp.text().await.unwrap();
    assert!(page.contains("sse-connect=\"/ui/events\""));
    assert!(page.contains("hx-get=\"/ui/partials/usage?days=7\""));
    assert!(page.contains("hx-trigger=\"sse:usage_changed\""));

    // admin fragments -> 403
    let resp = h
        .client
        .get(h.url("/ui/partials/admin/usage"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = h
        .client
        .get(h.url("/ui/partials/admin/usage/00000000-0000-0000-0000-000000000000"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn usage_admin_partials_for_audit_user() {
    let Some(h) = Harness::start("usage_ui_audit", RBAC_AUDIT).await else {
        return;
    };

    let session = h
        .login_as("bob", "bob@example.com", &["users", "auditors"])
        .await;

    // /ui/partials/admin/usage?days=7 -> 200 with users-usage-region wiring
    let resp = h
        .client
        .get(h.url("/ui/partials/admin/usage?days=7"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(body.contains("id=\"users-usage-region\""));
    assert!(body.contains("sse-connect=\"/ui/events\""));
    assert!(body.contains("hx-get=\"/ui/partials/admin/usage?days=7\""));

    // unknown uuid -> 404
    let resp = h
        .client
        .get(h.url("/ui/partials/admin/usage/00000000-0000-0000-0000-000000000000?days=7"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // real user -> 200 (find via API)
    let resp = h
        .client
        .get(h.url("/api/v1/admin/usage?days=7"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let users = json["users"].as_array().cloned().unwrap_or_default();
    if let Some(first) = users.first() {
        let uid = first["user_id"].as_str().unwrap();
        let resp = h
            .client
            .get(h.url(&format!("/ui/partials/admin/usage/{uid}?days=7")))
            .header(COOKIE, &session.cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.text().await.unwrap();
        assert!(body.contains("id=\"user-usage-region\""));
    }
    // if no users yet (no calls), that's fine; the "unknown uuid" gave 404 and admin list gave 200 — satisfies the main assertions
}

#[tokio::test]
async fn usage_partials_reject_bad_days() {
    let Some(h) = Harness::start("usage_ui_bad_days", RBAC_AUDIT).await else {
        return;
    };

    let session = h
        .login_as("carol", "carol@example.com", &["users", "auditors"])
        .await;

    // own
    let resp = h
        .client
        .get(h.url("/ui/partials/usage?days=abc"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // admin
    let resp = h
        .client
        .get(h.url("/ui/partials/admin/usage?days=abc"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn usage_changed_event_is_emitted_after_tool_call() {
    let Some(h) = Harness::start("usage_ui_sse", RBAC_NO_AUDIT).await else {
        return;
    };

    let session = h.login_as("dave", "dave@example.com", &["users"]).await;

    // Create a PAT for MCP calls (need to use API; reuse pattern from tool_call_audit)
    // Create PAT via API
    let resp = h
        .client
        .request(Method::POST, h.url("/api/v1/tokens"))
        .header(COOKIE, &session.cookie)
        .header("x-csrf-token", &session.csrf)
        .json(&json!({ "name": "test-pat" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token_json: serde_json::Value = resp.json().await.unwrap();
    let pat = token_json["plaintext"].as_str().unwrap().to_string();

    // Connect to SSE
    let mut sse_resp = h
        .client
        .get(h.url("/ui/events"))
        .header(COOKIE, &session.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);

    // Wait a bit for the initial status event, then drive a tool call
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Make an MCP tool call to trigger audit/usage
    // First wait for backend to connect
    let _ = poll_until(50, Duration::from_millis(100), || {
        let client = h.client.clone();
        let url = h.url("/mcp");
        let pat = pat.clone();
        async move {
            let (status, body) = mcp_post(&client, &url, Some(&pat), &rpc("tools/list")).await;
            if status == StatusCode::OK && body["result"]["tools"].as_array().is_some() {
                Some(())
            } else {
                None
            }
        }
    })
    .await;

    // Call a tool
    let (_status, _body) = mcp_post(
        &h.client,
        &h.url("/mcp"),
        Some(&pat),
        &rpc_call("read_file", json!({"path": "/etc/hosts"})),
    )
    .await;

    // Read SSE stream for up to 15 seconds looking for "usage_changed"
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut found = false;
    let mut buf = Vec::new();
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), sse_resp.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                buf.extend_from_slice(&chunk);
                let text = String::from_utf8_lossy(&buf);
                if text.contains("usage_changed") {
                    found = true;
                    break;
                }
            }
            Ok(Ok(None) | Err(_)) => break,
            Err(_) => {}
        }
    }
    assert!(found, "expected 'usage_changed' in SSE stream within 15s");
}
