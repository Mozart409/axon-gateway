//! Personal MCP servers, the per-user catalog and their guard rails end to end:
//! the real gateway binary, a real Postgres schema, the mock identity provider
//! and mock MCP backends. Users add their own servers and store catalog
//! credentials through the JSON API, then call `/mcp` with a personal access
//! token.
//!
//! The tests that need a database skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
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

/// The tools of the mock a personal backend or catalog entry points at.
const REMOTE_TOOLS: &[&str] = &["echo", "other"];

/// Allows the loopback mocks as personal backends.
const ALLOW_LOOPBACK: &str = "egress_allow = [\"127.0.0.1/32\"]";

/// Everybody may use the shared `files` backend; `it` is a group of the
/// `it-claim` value of the `mock` provider.
const RBAC: &str = r#"
[[rbac.groups]]
name = "it"
idp = [{ provider = "mock", value = "it-claim" }]

[[rbac.grants]]
group = "authenticated"
backend = "files"
"#;

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// A multi-user gateway with a shared `files` backend, in its own schema, and a
/// second mock (`remote`) for the personal backends and catalog entries to
/// point at. Users whose groups claim holds `admins` are admins.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
    files: MockBackend,
    remote: MockBackend,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`. `tweak`
    /// adjusts the config; it gets the `remote` mock to point entries at.
    async fn start(
        schema: &str,
        tweak: impl FnOnce(ConfigBuilder, &MockBackend) -> ConfigBuilder,
    ) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let files = MockBackend::start(&["ping"]).await;
        let remote = MockBackend::start(REMOTE_TOOLS).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let builder = ConfigBuilder::new(&bind)
            .http_backend("files", &files.url())
            .database(DATABASE_ENV)
            .oidc_provider(
                "mock",
                idp.issuer(),
                "axon-test",
                "admin_groups = [\"admins\"]",
            )
            .rbac(RBAC);
        let config = tweak(builder, &remote).render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

        Some(Self {
            gateway,
            client: no_redirect_client(),
            idp,
            files,
            remote,
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

    /// Like [`Harness::api`] with a JSON body; returns status and body (a
    /// body that is not JSON comes back as a string).
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
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
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

    /// The default test user: a plain member of no group.
    async fn login_user(&self) -> Session {
        self.login_as("alice", "alice@example.com", &[]).await
    }

    /// An admin (they may manage the catalog and everybody's personal backends).
    async fn login_admin(&self) -> Session {
        self.login_as("root", "root@example.com", &["admins"]).await
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

    /// `POST /api/v1/me/backends`; returns status and body.
    async fn create_personal(
        &self,
        session: &Session,
        prefix: &str,
        url: &str,
        headers: Value,
    ) -> (StatusCode, Value) {
        self.send(
            Method::POST,
            "/api/v1/me/backends",
            session,
            Some(json!({ "prefix": prefix, "url": url, "headers": headers })),
        )
        .await
    }

    /// The tool names `tools/list` returns for a token, sorted.
    async fn tool_names(&self, token: &str) -> Vec<String> {
        let (status, body) = mcp_post(
            &self.client,
            &self.url("/mcp"),
            Some(token),
            &rpc("tools/list"),
        )
        .await;
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

    /// Polls `tools/list` until `tool` is in it (a personal backend connects
    /// on demand) or is gone, whichever `present` asks for.
    async fn wait_for_tool(&self, token: &str, tool: &str, present: bool) -> bool {
        poll_until(50, Duration::from_millis(100), || async {
            let names = self.tool_names(token).await;
            (names.iter().any(|name| name == tool) == present).then_some(())
        })
        .await
        .is_some()
    }

    /// `tools/call` with a token and `{}`-less arguments; the JSON-RPC answer.
    async fn call(&self, token: &str, tool: &str, arguments: Value) -> Value {
        let (_, body) = mcp_post(
            &self.client,
            &self.url("/mcp"),
            Some(token),
            &rpc_call(tool, arguments),
        )
        .await;
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

/// A call that went through: a result and no error.
fn assert_called(body: &Value) {
    assert!(body.get("error").is_none(), "{body}");
    assert!(body["result"].is_object(), "{body}");
}

/// The names in `GET /catalog`, sorted.
fn catalog_names(body: &Value) -> Vec<String> {
    let mut names: Vec<String> = body["catalog"]
        .as_array()
        .unwrap_or_else(|| panic!("no catalog in {body}"))
        .iter()
        .map(|entry| entry["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// The text of a call result's first content block.
fn result_text(body: &Value) -> String {
    body["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {body}"))
        .to_string()
}

#[tokio::test]
async fn a_personal_backend_is_proxied_with_its_sealed_headers() {
    let Some(h) = Harness::start("axon_personal_happy", |builder, _| {
        builder.personal_backends(ALLOW_LOOPBACK)
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;
    let pat = h.create_pat(&alice).await;

    let (status, body) = h
        .create_personal(
            &alice,
            "mine",
            &h.remote.url(),
            json!({ "x-api-key": "secret1" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["prefix"], "mine");
    assert_eq!(body["test"]["ok"], true, "{body}");
    assert_eq!(body["test"]["tools"], REMOTE_TOOLS.len(), "{body}");
    assert!(!body.to_string().contains("secret1"), "{body}");

    // No RBAC grant needed: the tools are the user's own.
    assert!(h.wait_for_tool(&pat, "mine_echo", true).await);
    let names = h.tool_names(&pat).await;
    assert!(names.contains(&"mine_other".to_string()), "{names:?}");
    assert!(names.contains(&"files_ping".to_string()), "{names:?}");

    let answer = h.call(&pat, "mine_echo", json!({ "a": 1 })).await;
    assert_called(&answer);
    assert_eq!(result_text(&answer), "echo:{\"a\":1}");
    assert_eq!(h.remote.call_count("echo"), 1);
    assert!(
        h.remote
            .header_values("x-api-key")
            .iter()
            .any(|value| value == "secret1"),
        "the backend should have got the header"
    );

    // The header values never come back, only their names.
    let (status, list) = h
        .send(Method::GET, "/api/v1/me/backends", &alice, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(!list.to_string().contains("secret1"), "{list}");
    assert_eq!(list["backends"][0]["prefix"], "mine");
    assert_eq!(list["backends"][0]["header_names"], json!(["x-api-key"]));
}

#[tokio::test]
async fn the_egress_guard_refuses_internal_and_non_http_urls() {
    let Some(h) = Harness::start("axon_personal_egress", |builder, _| builder).await else {
        return;
    };
    let alice = h.login_user().await;
    let port = h.remote.url();
    let port = port
        .rsplit(':')
        .next()
        .and_then(|rest| rest.split('/').next())
        .unwrap()
        .to_string();

    for url in [
        format!("http://127.0.0.1:{port}/mcp"),
        format!("http://localhost:{port}/mcp"),
        "http://169.254.169.254/".to_string(),
    ] {
        let (status, body) = h.create_personal(&alice, "mine", &url, json!({})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{url}: {body}");
        assert!(
            body.to_string().to_lowercase().contains("egress"),
            "{url}: {body}"
        );
    }

    let (status, body) = h
        .create_personal(&alice, "mine", "ftp://example.com/mcp", json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Nothing was saved.
    let (_, list) = h
        .send(Method::GET, "/api/v1/me/backends", &alice, None)
        .await;
    assert_eq!(list["backends"], json!([]), "{list}");
}

#[tokio::test]
async fn bad_and_taken_prefixes_are_refused() {
    let Some(h) = Harness::start("axon_personal_prefix", |builder, _| {
        builder.personal_backends(ALLOW_LOOPBACK)
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;

    // Reserved, upper case, an underscore (the namespace separator) and the
    // name of a shared backend.
    for prefix in ["admin", "Ab", "a_b", "files"] {
        let (status, body) = h
            .create_personal(&alice, prefix, &h.remote.url(), json!({}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{prefix}: {body}");
    }

    let (status, body) = h
        .create_personal(&alice, "fine", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn catalog_credentials_are_per_user_and_need_a_grant() {
    let Some(h) = Harness::start("axon_personal_catalog", |builder, remote| {
        let entry = format!(
            "[[backends]]\nname = \"cfgsvc\"\ntransport = \"http\"\nurl = \"{}\"\n\
             credential_mode = \"per_user\"\n\n\
             [[backends.credential_fields]]\nname = \"token\"\nlabel = \"API token\"\n\
             header = \"authorization\"\nprefix = \"Bearer \"\n",
            remote.url()
        );
        let rbac = format!("{RBAC}\n[[rbac.grants]]\ngroup = \"it\"\nbackend = \"cfgsvc\"\n");
        builder
            .personal_backends(ALLOW_LOOPBACK)
            .raw_backend(&entry)
            .rbac(&rbac)
    })
    .await
    else {
        return;
    };
    let admin = h.login_admin().await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let bob = h.login_as("bob", "bob@example.com", &[]).await;

    // An admin adds an entry to the catalog; it comes from the database, the
    // one of the config file from the config.
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/catalog",
            &admin,
            Some(json!({
                "name": "dbsvc",
                "description": "an entry of the database",
                "url": h.remote.url(),
                "credential_fields": [{
                    "name": "token",
                    "label": "API token",
                    "header": "authorization",
                    "prefix": "Bearer ",
                }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["source"], "database");

    // A catalog manager sees every entry, with its url.
    let (status, body) = h.send(Method::GET, "/api/v1/catalog", &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(catalog_names(&body), ["cfgsvc", "dbsvc"]);
    let sources: Vec<(&str, &str)> = body["catalog"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().unwrap(),
                entry["source"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(sources.contains(&("cfgsvc", "config")), "{body}");
    assert!(sources.contains(&("dbsvc", "database")), "{body}");

    // The others see the entries their groups have a grant for.
    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &alice, None).await;
    assert_eq!(catalog_names(&body), ["cfgsvc"], "{body}");
    assert_eq!(body["catalog"][0]["credential"]["set"], false);
    assert_eq!(body["catalog"][0]["credential_fields"][0]["name"], "token");
    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &bob, None).await;
    assert_eq!(catalog_names(&body), Vec::<String>::new(), "{body}");

    // Without a grant there is nothing to store a credential for.
    let (status, body) = h
        .send(
            Method::PUT,
            "/api/v1/me/credentials/cfgsvc",
            &bob,
            Some(json!({ "values": { "token": "bobs" } })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    // Alice stores hers; her token then lists and reaches the entry's tools
    // with the credential in the header.
    let pat = h.create_pat(&alice).await;
    let (status, body) = h
        .send(
            Method::PUT,
            "/api/v1/me/credentials/cfgsvc",
            &alice,
            Some(json!({ "values": { "token": "t0k" } })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(h.wait_for_tool(&pat, "cfgsvc_echo", true).await);
    let answer = h.call(&pat, "cfgsvc_echo", json!({})).await;
    assert_called(&answer);
    assert!(
        h.remote
            .header_values("authorization")
            .iter()
            .any(|value| value == "Bearer t0k"),
        "the backend should have got the credential"
    );

    // Bob has no credential and no grant: nothing of the entry for him.
    let bob_pat = h.create_pat(&bob).await;
    let names = h.tool_names(&bob_pat).await;
    assert!(!names.iter().any(|name| name.starts_with("cfgsvc_")));

    // The credential's state shows, its value does not.
    let (_, body) = h
        .send(Method::GET, "/api/v1/me/credentials", &alice, None)
        .await;
    assert_eq!(body["credentials"][0]["backend"], "cfgsvc", "{body}");
    assert!(!body.to_string().contains("t0k"), "{body}");
    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &alice, None).await;
    assert_eq!(body["catalog"][0]["credential"]["set"], true, "{body}");
    assert!(!body.to_string().contains("t0k"), "{body}");

    // An entry of the config file cannot be changed through the API; one of
    // the database can.
    let (status, body) = h
        .send(
            Method::PATCH,
            "/api/v1/catalog/cfgsvc",
            &admin,
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = h
        .send(
            Method::PATCH,
            "/api/v1/catalog/dbsvc",
            &admin,
            Some(json!({ "description": "changed" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = h
        .send(Method::DELETE, "/api/v1/catalog/dbsvc", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn a_user_may_only_have_so_many_backends() {
    let Some(h) = Harness::start("axon_personal_max_per_user", |builder, _| {
        builder.personal_backends(&format!("{ALLOW_LOOPBACK}\nmax_per_user = 1"))
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;

    let (status, body) = h
        .create_personal(&alice, "one", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h
        .create_personal(&alice, "two", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Deleting one makes room again.
    let (status, _) = h
        .send(Method::DELETE, "/api/v1/me/backends/one", &alice, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = h
        .create_personal(&alice, "two", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[tokio::test]
async fn personal_tool_calls_are_limited_per_minute_but_shared_ones_are_not() {
    let Some(h) = Harness::start("axon_personal_call_quota", |builder, _| {
        builder.personal_backends(&format!("{ALLOW_LOOPBACK}\nmax_calls_per_minute = 1"))
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;
    let pat = h.create_pat(&alice).await;
    let (status, body) = h
        .create_personal(&alice, "mine", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(h.wait_for_tool(&pat, "mine_echo", true).await);

    assert_called(&h.call(&pat, "mine_echo", json!({})).await);
    let second = h.call(&pat, "mine_echo", json!({})).await;
    let message = second["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error, got {second}"));
    assert!(message.contains("quota"), "{second}");
    assert_eq!(h.remote.call_count("echo"), 1);

    // Shared tools do not count.
    for _ in 0..3 {
        assert_called(&h.call(&pat, "files_ping", json!({})).await);
    }
    assert_eq!(h.files.call_count("ping"), 3);
}

#[tokio::test]
async fn an_idle_personal_connection_is_reopened_on_demand() {
    let Some(h) = Harness::start("axon_personal_idle", |builder, _| {
        builder
            .idle_timeout_secs(1)
            .personal_backends(ALLOW_LOOPBACK)
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;
    let pat = h.create_pat(&alice).await;
    let (status, body) = h
        .create_personal(&alice, "mine", &h.remote.url(), json!({}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(h.wait_for_tool(&pat, "mine_echo", true).await);

    assert_called(&h.call(&pat, "mine_echo", json!({ "n": 1 })).await);

    // Long enough for the connection to be closed as idle.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let answer = h.call(&pat, "mine_echo", json!({ "n": 2 })).await;
    assert_called(&answer);
    assert_eq!(result_text(&answer), "echo:{\"n\":2}");
    assert_eq!(h.remote.call_count("echo"), 2);
}

#[tokio::test]
async fn personal_backends_need_a_key_unless_they_are_switched_off() {
    let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
        eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
        return;
    };
    let idp = MockOidc::start("axon-test").await;
    let no_key = ["AXON_KEK", "AXON_KEK_FILE"];

    // A database and no key: the gateway refuses to start.
    let url = isolated_url(&base, "axon_personal_kek_missing").await;
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind)
        .database(DATABASE_ENV)
        .oidc_provider("mock", idp.issuer(), "axon-test", "")
        .render();
    let (status, stderr) = Gateway::run_to_exit_env(
        &config,
        Duration::from_secs(20),
        &[(DATABASE_ENV, &url)],
        &no_key,
    )
    .expect("the gateway should refuse to start");
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("AXON_KEK"), "{stderr}");

    // Switched off, it needs none.
    let url = isolated_url(&base, "axon_personal_kek_off").await;
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind)
        .database(DATABASE_ENV)
        .personal_backends("enabled = false")
        .oidc_provider("mock", idp.issuer(), "axon-test", "")
        .render();
    let _gateway = Gateway::start_without_env(
        &config,
        &format!("http://{bind}"),
        &[(DATABASE_ENV, &url)],
        &no_key,
    )
    .await;
}

#[tokio::test]
async fn an_admin_sees_and_switches_off_the_personal_backends_of_users() {
    let Some(h) = Harness::start("axon_personal_admin", |builder, _| {
        builder.personal_backends(ALLOW_LOOPBACK)
    })
    .await
    else {
        return;
    };
    let alice = h.login_user().await;
    let pat = h.create_pat(&alice).await;
    let (status, body) = h
        .create_personal(
            &alice,
            "mine",
            &h.remote.url(),
            json!({ "x-api-key": "secret1" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(h.wait_for_tool(&pat, "mine_echo", true).await);

    // A plain user cannot look at everybody's backends.
    let (status, _) = h
        .send(Method::GET, "/api/v1/admin/personal-backends", &alice, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let admin = h.login_admin().await;
    let (status, body) = h
        .send(Method::GET, "/api/v1/admin/personal-backends", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body.to_string().contains("secret1"), "{body}");
    let backend = body["backends"]
        .as_array()
        .unwrap()
        .iter()
        .find(|backend| backend["prefix"] == "mine")
        .unwrap_or_else(|| panic!("no backend of alice in {body}"));
    assert_eq!(backend["owner"]["email"], "alice@example.com");
    assert_eq!(backend["header_names"], json!(["x-api-key"]));
    let owner = backend["owner"]["id"].as_str().unwrap().to_string();

    // Switched off, the tools go (a change reaches the open session soon).
    let (status, body) = h
        .send(
            Method::PATCH,
            &format!("/api/v1/admin/personal-backends/{owner}/mine"),
            &admin,
            Some(json!({ "enabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(
        h.wait_for_tool(&pat, "mine_echo", false).await,
        "the tools of a disabled backend should leave the list"
    );
    let (_, body) = h
        .send(Method::GET, "/api/v1/me/backends", &alice, None)
        .await;
    assert_eq!(body["backends"][0]["enabled"], false, "{body}");
}

#[tokio::test]
async fn a_database_catalog_entry_can_be_granted_and_used() {
    let Some(h) = Harness::start("axon_personal_db_catalog", |builder, _| {
        builder.personal_backends(ALLOW_LOOPBACK)
    })
    .await
    else {
        return;
    };
    let admin = h.login_admin().await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let bob = h.login_as("bob", "bob@example.com", &[]).await;

    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/catalog",
            &admin,
            Some(json!({
                "name": "dbsvc",
                "url": h.remote.url(),
                "credential_fields": [{
                    "name": "token",
                    "label": "API token",
                    "header": "authorization",
                    "prefix": "Bearer ",
                }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Not granted yet: nobody but a catalog manager sees it.
    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &alice, None).await;
    assert_eq!(catalog_names(&body), Vec::<String>::new(), "{body}");

    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/grants",
            &admin,
            Some(json!({ "group": "it", "backend": "dbsvc" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &alice, None).await;
    assert_eq!(catalog_names(&body), ["dbsvc"], "{body}");
    assert_eq!(body["catalog"][0]["source"], "database");
    let (_, body) = h.send(Method::GET, "/api/v1/catalog", &bob, None).await;
    assert_eq!(catalog_names(&body), Vec::<String>::new(), "{body}");

    let pat = h.create_pat(&alice).await;
    let (status, body) = h
        .send(
            Method::PUT,
            "/api/v1/me/credentials/dbsvc",
            &alice,
            Some(json!({ "values": { "token": "t0k" } })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(h.wait_for_tool(&pat, "dbsvc_echo", true).await);
    assert_called(&h.call(&pat, "dbsvc_echo", json!({})).await);
    assert!(
        h.remote
            .header_values("authorization")
            .iter()
            .any(|value| value == "Bearer t0k"),
        "the backend should have got the credential"
    );
}
