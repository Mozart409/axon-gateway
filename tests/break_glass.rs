//! Break-glass admin login end to end: the real gateway binary and a real
//! Postgres schema. The code comes from `axon-gateway admin login-link`, the
//! way an operator would get it.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use std::process::Command;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Response, StatusCode};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const BIN: &str = env!("CARGO_BIN_EXE_axon-gateway");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const SESSION_COOKIE: &str = "__Host-axon_session";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// A multi-user gateway in its own schema, plus what the CLI needs.
struct Harness {
    gateway: Gateway,
    /// Keeps the mock provider up
    _idp: MockOidc,
    client: reqwest::Client,
    database_url: String,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let database_url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .database(DATABASE_ENV)
            .oidc_provider("mock", idp.issuer(), "axon-test", "")
            .render();
        let gateway = Gateway::start_with_env(
            &config,
            &format!("http://{bind}"),
            &[(DATABASE_ENV, &database_url)],
        )
        .await;

        Some(Self {
            gateway,
            _idp: idp,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client should build"),
            database_url,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    /// Runs `axon-gateway admin login-link` and returns its stdout, split in
    /// the link and the code.
    fn login_link(&self) -> (String, String) {
        let output = Command::new(BIN)
            .args(["admin", "login-link"])
            .env("AXON_DATABASE_URL", &self.database_url)
            .env("AXON_BASE_URL", &self.gateway.base)
            .env("RUST_LOG", "warn")
            .current_dir(MANIFEST_DIR)
            .output()
            .expect("the CLI should run");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut lines = stdout.lines();
        let link = lines.next().expect("a link line").to_owned();
        assert!(
            lines
                .next()
                .is_some_and(|line| line.contains("15 minutes") && line.contains("once")),
            "{stdout}"
        );
        let code = link
            .split_once("/auth/break-glass?code=")
            .expect("a break-glass link")
            .1
            .to_owned();
        assert!(link.starts_with(&self.gateway.base), "{link}");
        (link, code)
    }

    async fn confirm(&self, code: &str) -> Response {
        self.client
            .post(self.url("/auth/break-glass"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(format!("code={code}"))
            .send()
            .await
            .unwrap()
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

/// The whole `Set-Cookie` header for `name`.
fn set_cookie(resp: &Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(str::to_string)
}

#[tokio::test]
async fn a_login_link_opens_an_admin_session_once() {
    let Some(h) = Harness::start("axon_break_glass_login").await else {
        return;
    };
    let (link, code) = h.login_link();

    // The link only asks for confirmation, however often it is opened.
    for _ in 0..2 {
        let resp = h.client.get(&link).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = resp.text().await.unwrap();
        assert!(page.contains("Sign in as break-glass admin"), "{page}");
        assert!(page.contains("name=\"code\""), "{page}");
        assert!(page.contains(&format!("value=\"{code}\"")), "{page}");
        assert!(page.contains("method=\"post\""), "{page}");
    }

    // A page on another site cannot confirm for the user, and does not burn it.
    let resp = h
        .client
        .post(h.url("/auth/break-glass"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("sec-fetch-site", "cross-site")
        .body(format!("code={code}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = h.confirm(&code).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()[LOCATION], "/ui/admin");
    let attributes = set_cookie(&resp, SESSION_COOKIE).expect("a session cookie");
    for attribute in [
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=3600",
    ] {
        assert!(attributes.contains(attribute), "{attributes}");
    }
    let session = attributes.split(';').next().unwrap().to_owned();

    let resp = h
        .client
        .get(h.url("/ui/admin"))
        .header(COOKIE, &session)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the cookie opens the admin UI"
    );

    // Single use.
    let resp = h.confirm(&code).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie(&resp, SESSION_COOKIE).is_none());
    let page = resp.text().await.unwrap();
    assert!(page.contains("Link expired"), "{page}");

    // Both steps are in the audit log, after the import.
    let pool = sqlx::PgPool::connect(&h.database_url).await.unwrap();
    let rows: Vec<(String, String)> =
        sqlx::query_as("select action, actor from audit_log order by id")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    assert_eq!(
        rows,
        [
            // the harness imports the config file first
            ("config.import".to_owned(), "cli".to_owned()),
            ("break_glass.link_created".to_owned(), "cli".to_owned()),
            ("break_glass.login".to_owned(), "break-glass".to_owned()),
        ]
    );
}

#[tokio::test]
async fn an_unknown_code_is_refused() {
    let Some(h) = Harness::start("axon_break_glass_unknown").await else {
        return;
    };
    let resp = h.confirm("not-a-code").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(set_cookie(&resp, SESSION_COOKIE).is_none());
}

#[test]
fn the_admin_command_needs_a_subcommand() {
    let output = Command::new(BIN)
        .arg("admin")
        .current_dir(MANIFEST_DIR)
        .output()
        .expect("the CLI should run");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage: axon-gateway admin"));
}
