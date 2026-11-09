//! The "My tools" dashboard page end to end: the real gateway binary, a real
//! Postgres schema, the mock identity provider and a mock MCP backend.
//!
//! The tests that need a database skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use std::time::Duration;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{RequestBuilder, Response, StatusCode};
use serde_json::json;
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, poll_until};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const FORM: &str = "application/x-www-form-urlencoded";

/// Group `it` comes from the `it-claim` value of the `mock` provider. Everyone
/// gets `audit_log` (mandatory); `it` gets the rest of `files` but `delete_*`.
const RBAC: &str = r#"
[[rbac.groups]]
name = "it"
description = "IT staff"
idp = [{ provider = "mock", value = "it-claim" }]

[[rbac.grants]]
group = "authenticated"
backend = "files"
include = ["audit_log"]
mandatory = true

[[rbac.grants]]
group = "it"
backend = "files"
exclude = ["delete_*"]
"#;

/// A multi-user gateway in front of a `files` backend, in its own schema.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    _idp: MockOidc,
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
        idp.set_user(json!({
            "sub": "alice",
            "email": "alice@example.com",
            "name": "Alice",
            "groups": ["it-claim"],
        }));
        let backend = MockBackend::start(&["read_file", "delete_file", "audit_log"]).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .http_backend("files", &backend.url())
            .database(DATABASE_ENV)
            .oidc_provider("mock", idp.issuer(), "axon-test", "")
            .rbac(RBAC)
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

        Some(Self {
            gateway,
            client: no_redirect_client(),
            _idp: idp,
            _backend: backend,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    fn get(&self, path: &str, session: &str) -> RequestBuilder {
        self.client.get(self.url(path)).header(COOKIE, session)
    }

    /// The opt-out action, with the CSRF token unless `token` is `None`.
    fn opt_out(&self, session: &str, token: Option<&str>, body: &str) -> RequestBuilder {
        let request = self
            .client
            .post(self.url("/ui/actions/tools/opt-out"))
            .header(COOKIE, session)
            .header(CONTENT_TYPE, FORM)
            .body(body.to_string());
        match token {
            Some(token) => request.header("x-csrf-token", token),
            None => request,
        }
    }

    /// A complete login. Returns the `name=value` session cookie.
    async fn login(&self) -> String {
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
        cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie")
    }

    /// The My tools page, once the backend's tools have connected.
    async fn tools_page(&self, session: &str) -> String {
        poll_until(50, Duration::from_millis(100), || async {
            let resp = self.get("/ui/tools", session).send().await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let page = resp.text().await.unwrap();
            page.contains("files_read_file").then_some(page)
        })
        .await
        .expect("the files backend should connect")
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
async fn my_tools_shows_groups_states_and_reasons() {
    let Some(h) = Harness::start("axon_my_tools_view").await else {
        return;
    };
    let session = h.login().await;
    let page = h.tools_page(&session).await;

    // Groups, with the built-in one marked.
    assert!(page.contains("IT staff"), "{page}");
    assert!(page.contains("authenticated"));
    assert!(page.contains("built in"));

    // Allowed, mandatory and not granted (with the reason).
    assert!(page.contains("files_read_file"));
    assert!(page.contains(">on<"));
    assert!(page.contains("files_audit_log"));
    assert!(page.contains(">mandatory<"));
    assert!(page.contains("required by your admin"));
    assert!(page.contains("files_delete_file"));
    assert!(page.contains(">not granted<"));
    assert!(page.contains("excluded by the grant of group it"));
    assert!(!page.contains("hidden by you"));

    // The header links here.
    assert!(page.contains("href=\"/ui/tools\""));
}

#[tokio::test]
async fn hiding_a_tool_persists_and_the_rules_are_enforced() {
    let Some(h) = Harness::start("axon_my_tools_opt_out").await else {
        return;
    };
    let session = h.login().await;
    let token = csrf_token(&h.tools_page(&session).await);

    // No token, no change.
    let resp = h
        .opt_out(&session, None, "backend=files&tool=read_file&hidden=true")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Hiding a tool answers with the re-rendered backend section.
    let resp = h
        .opt_out(
            &session,
            Some(&token),
            "backend=files&tool=read_file&hidden=true",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let fragment = resp.text().await.unwrap();
    assert!(fragment.starts_with("<section"), "{fragment}");
    assert!(fragment.contains("hidden by you"));
    assert!(fragment.contains("name=\"hidden\" value=\"false\""));

    // It is still hidden after a reload.
    let page = h.tools_page(&session).await;
    assert!(page.contains("hidden by you"));

    // Showing it again.
    let resp = h
        .opt_out(
            &session,
            Some(&token),
            "backend=files&tool=read_file&hidden=false",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!h.tools_page(&session).await.contains("hidden by you"));

    // A mandatory tool, a tool that is not granted and an unknown backend or
    // tool cannot be hidden.
    for body in [
        "backend=files&tool=audit_log&hidden=true",
        "backend=files&tool=delete_file&hidden=true",
        "backend=files&tool=missing&hidden=true",
        "backend=missing&hidden=true",
    ] {
        let resp = h
            .opt_out(&session, Some(&token), body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
    }

    // Hiding the whole backend leaves the mandatory tool visible.
    let resp = h
        .opt_out(&session, Some(&token), "backend=files&hidden=true")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let fragment = resp.text().await.unwrap();
    assert!(fragment.contains("Show backend"));
    assert!(fragment.contains("Its mandatory tools stay visible"));
    assert!(fragment.contains(">mandatory<"));
    assert!(fragment.contains("hidden by you"));
}

#[tokio::test]
async fn my_tools_is_not_found_in_standalone_mode() {
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind).render();
    let gateway = Gateway::start(&config, &format!("http://{bind}")).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("{}/ui/tools", gateway.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = client
        .post(format!("{}/ui/actions/tools/opt-out", gateway.base))
        .header(CONTENT_TYPE, FORM)
        .body("backend=files&hidden=true")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
