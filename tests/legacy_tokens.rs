//! Legacy `[[tokens]]` in multi-user mode: they are config service accounts under
//! strict RBAC (the groups that list them in `service_accounts`), and the shared
//! `gateway.auth_token` is refused. Database service accounts can be listed by name
//! in a config group too, and a token's use records the client address.
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
use reqwest::{Method, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, poll_until, rpc};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const SHARED_TOKEN: &str = "shared-secret-token";

/// `ops` lists one legacy token and one database service account; `[[tokens]]`
/// entries come after the rbac tables.
const CONFIG_TAIL: &str = r#"
[[rbac.groups]]
name = "ops"
service_accounts = ["legacy-ops", "legacy-narrow", "db-bot"]

[[rbac.grants]]
group = "ops"
backend = "files"
include = ["read_file", "list_files"]

[[tokens]]
name = "legacy-ops"
token = "legacy-ops-secret"

[[tokens]]
name = "legacy-narrow"
token = "legacy-narrow-secret"
allowed_tools = ["files_read_*"]

[[tokens]]
name = "legacy-orphan"
token = "legacy-orphan-secret"
"#;

struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
    db_url: String,
    // Kept alive for the gateway's sake
    _backend: MockBackend,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let db_url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let backend =
            MockBackend::start(&["read_file", "list_files", "delete_file", "audit_log"]).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .auth_token(SHARED_TOKEN)
            .http_backend("files", &backend.url())
            .database(DATABASE_ENV)
            .oidc_provider(
                "mock",
                idp.issuer(),
                "axon-test",
                "admin_groups = [\"admins\"]",
            )
            .rbac(CONFIG_TAIL)
            .render();
        let gateway = Gateway::start_with_env(
            &config,
            &format!("http://{bind}"),
            &[(DATABASE_ENV, &db_url)],
        )
        .await;

        Some(Self {
            gateway,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client should build"),
            idp,
            db_url,
            _backend: backend,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    /// A complete login as an admin; returns the session cookie and CSRF token.
    async fn login_admin(&self) -> (String, String) {
        self.idp.set_user(json!({
            "sub": "root",
            "email": "root@example.com",
            "name": "root",
            "groups": ["admins"],
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
            .get(self.url("/ui/tokens"))
            .header(COOKIE, &cookie)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        (cookie, csrf_token(&page))
    }

    fn api(&self, method: Method, path: &str, session: &(String, String)) -> RequestBuilder {
        let is_get = method == Method::GET;
        let request = self
            .client
            .request(method, self.url(path))
            .header(COOKIE, &session.0);
        if is_get {
            request
        } else {
            request.header("x-csrf-token", &session.1)
        }
    }

    /// An API call with a JSON body; returns status and body.
    async fn send(
        &self,
        method: Method,
        path: &str,
        session: &(String, String),
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self.api(method, path, session);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let resp = request.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// `tools/list` with a bearer token and extra headers; status and body.
    async fn list(&self, bearer: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut request = self
            .client
            .post(self.url("/mcp"))
            .bearer_auth(bearer)
            .json(&rpc("tools/list"));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let resp = request.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// The tool names `tools/list` returns for a token, sorted.
    async fn tool_names(&self, token: &str) -> Vec<String> {
        let (status, body) = self.list(token, &[]).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("no tools in {body}"))
            .iter()
            .map(|tool| tool["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        names
    }

    /// Like [`Harness::tool_names`], once the backend's tools have connected
    /// (the token must be allowed some tool).
    async fn connected_tool_names(&self, token: &str) -> Vec<String> {
        poll_until(50, Duration::from_millis(100), || async {
            Some(self.tool_names(token).await).filter(|names| !names.is_empty())
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

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get(LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// `name=value` of the cookie `name`, ready for a `Cookie` header.
fn cookie_pair(resp: &reqwest::Response, name: &str) -> Option<String> {
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
async fn the_shared_token_is_refused_in_multi_user_mode() {
    let Some(h) = Harness::start("axon_legacy_shared").await else {
        return;
    };
    let (status, _) = h.list(SHARED_TOKEN, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.list("not-a-token", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn legacy_tokens_see_what_their_config_groups_grant() {
    let Some(h) = Harness::start("axon_legacy_tokens").await else {
        return;
    };

    // In a group with a grant: the group's tools
    assert_eq!(
        h.connected_tool_names("legacy-ops-secret").await,
        ["files_list_files", "files_read_file"]
    );
    // Narrowed by its own allowed_tools
    assert_eq!(
        h.tool_names("legacy-narrow-secret").await,
        ["files_read_file"]
    );
    // In no group: strict RBAC, nothing (the backend is connected by now)
    assert_eq!(
        h.tool_names("legacy-orphan-secret").await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn a_database_service_account_is_a_member_of_config_groups_by_name() {
    let Some(h) = Harness::start("axon_legacy_db_account").await else {
        return;
    };
    let admin = h.login_admin().await;

    let (status, account) = h
        .send(
            Method::POST,
            "/api/v1/service-accounts",
            &admin,
            Some(json!({ "name": "db-bot" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let account_id = account["id"].as_str().unwrap().to_string();
    let (status, token) = h
        .send(
            Method::POST,
            &format!("/api/v1/service-accounts/{account_id}/tokens"),
            &admin,
            Some(json!({ "name": "ci", "expires_in_days": 30 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    let plaintext = token["plaintext"].as_str().unwrap().to_string();
    let token_id = token["id"].as_str().unwrap().to_string();

    // No database membership: the group comes from the `service_accounts` list alone.
    // The first use carries a forwarded address, which a loopback peer (the test
    // client) is believed to have been set by our own proxy.
    let (status, body) = h
        .list(&plaintext, &[("x-forwarded-for", "198.51.100.9")])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        h.connected_tool_names(&plaintext).await,
        ["files_list_files", "files_read_file"]
    );

    let pool = sqlx::PgPool::connect(&h.db_url).await.unwrap();
    let ip: Option<String> =
        sqlx::query_scalar("select last_used_ip from api_tokens where id::text = $1")
            .bind(&token_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    assert_eq!(ip.as_deref(), Some("198.51.100.9"));
}
