//! Two gateway replicas on one database: a policy or per-user change made
//! through one reaches the clients of the other as `list_changed`, a session
//! opened on one is restored by the other and stays bound to its principal, and
//! the per-token rate limit is shared.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`); each uses its own schema.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, Response, StatusCode};
use rmcp::ServiceExt;
use rmcp::handler::client::ClientHandler;
use rmcp::service::{NotificationContext, RoleClient, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, raw_post, rpc};

const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";

/// `it-claim` is granted two tools of `files`.
const RBAC: &str = r#"
[[rbac.groups]]
name = "it"
idp = [{ provider = "mock", value = "it-claim" }]

[[rbac.grants]]
group = "it"
backend = "files"
include = ["read_file", "list_files"]
"#;

/// Two gateways on one database, in front of one mock identity provider and
/// one `files` backend. Users whose groups claim holds `admins` are admins.
struct Fleet {
    a: Gateway,
    b: Gateway,
    idp: MockOidc,
    _backend: MockBackend,
    http: reqwest::Client,
}

impl Fleet {
    /// Start A, then B, on the schema `schema`; `configure` adds to both
    /// configs. `None` (skip) without a database.
    async fn start(
        schema: &str,
        configure: impl Fn(ConfigBuilder) -> ConfigBuilder,
    ) -> Option<Self> {
        let Ok(db) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&db, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let backend = MockBackend::start(&["read_file", "list_files", "delete_file"]).await;
        let mut gateways = Vec::new();
        for _ in 0..2 {
            let bind = format!("127.0.0.1:{}", free_port());
            let config = configure(
                ConfigBuilder::new(&bind)
                    .http_backend("files", &backend.url())
                    .database(DATABASE_ENV)
                    .oidc_provider(
                        "mock",
                        idp.issuer(),
                        "axon-test",
                        "admin_groups = [\"admins\"]",
                    ),
            )
            .render();
            gateways.push(
                Gateway::start_with_env(
                    &config,
                    &format!("http://{bind}"),
                    &[(DATABASE_ENV, &url)],
                )
                .await,
            );
        }
        let b = gateways.pop().expect("replica B");
        let a = gateways.pop().expect("replica A");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client should build");
        Some(Self {
            a,
            b,
            idp,
            _backend: backend,
            http,
        })
    }

    /// A login on replica A as `subject`.
    async fn login(&self, subject: &str, groups: &[&str]) -> Session {
        login_as(&self.http, &self.a.base, &self.idp, subject, groups).await
    }

    /// A JSON API call on replica A as `session`.
    async fn api(
        &self,
        session: &Session,
        method: Method,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        api(&self.http, &self.a.base, session, method, path, body).await
    }

    /// A personal access token of `session`'s user, created through A.
    async fn pat(&self, session: &Session, body: Value) -> String {
        let (status, token) = self
            .api(session, Method::POST, "/api/v1/tokens", body)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{token}");
        token["plaintext"]
            .as_str()
            .expect("a plaintext")
            .to_string()
    }
}

/// What a connected client has been told by the gateway.
#[derive(Clone, Default)]
struct Recorder {
    list_changed: Arc<AtomicUsize>,
}

impl Recorder {
    fn list_changed(&self) -> usize {
        self.list_changed.load(Ordering::SeqCst)
    }
}

impl ClientHandler for Recorder {
    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.list_changed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Connect an rmcp client (initialize, session, standalone event stream) to
/// `url` with `token` as the bearer token.
async fn connect(
    url: &str,
    token: &str,
    recorder: &Recorder,
) -> RunningService<RoleClient, Recorder> {
    let config = StreamableHttpClientTransportConfig::with_uri(url).auth_header(token.to_string());
    let transport = StreamableHttpClientTransport::from_config(config);
    recorder
        .clone()
        .serve(transport)
        .await
        .expect("the client should connect")
}

/// Let the client's standalone event stream come up before the test changes
/// anything the gateway announces.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// The sorted tool names `client` lists.
async fn tool_names(client: &RunningService<RoleClient, Recorder>) -> Option<Vec<String>> {
    let tools = client.list_all_tools().await.ok()?;
    let mut names = tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<Vec<_>>();
    names.sort();
    Some(names)
}

/// Wait for `recorder` to be told the tool list changed since `seen`. The
/// change has to cross the database, so it gets a few seconds (the gateways'
/// own 30 s poll is only a backstop).
async fn expect_list_changed(recorder: &Recorder, seen: usize) {
    poll_until(60, Duration::from_millis(100), || async {
        (recorder.list_changed() > seen).then_some(())
    })
    .await
    .expect("the client on the other replica should be told the tool list changed");
}

#[tokio::test]
async fn a_grant_made_on_one_replica_reaches_a_client_on_the_other() {
    let Some(fleet) = Fleet::start("axon_replicas_grants", |config| config).await else {
        return;
    };
    let admin = fleet.login("root", &["admins"]).await;
    let alice = fleet.login("alice", &["alice-claim"]).await;
    let pat = fleet.pat(&alice, json!({ "name": "mcp" })).await;

    // Alice's client is connected to B; nothing is granted yet.
    let recorder = Recorder::default();
    let client = connect(&format!("{}/mcp", fleet.b.base), &pat, &recorder).await;
    settle().await;
    assert_eq!(client.list_all_tools().await.expect("tools"), Vec::new());
    let seen = recorder.list_changed();

    // An admin grants her group a tool of `files`, through A.
    for (path, body) in [
        (
            "/api/v1/groups",
            json!({ "name": "devs", "description": "Developers" }),
        ),
        (
            "/api/v1/groups/devs/idp-mappings",
            json!({ "provider": "mock", "value": "alice-claim" }),
        ),
        (
            "/api/v1/grants",
            json!({ "group": "devs", "backend": "files", "include": ["read_*"] }),
        ),
    ] {
        let (status, body) = fleet.api(&admin, Method::POST, path, body).await;
        assert_eq!(status, StatusCode::CREATED, "{path}: {body}");
    }

    expect_list_changed(&recorder, seen).await;
    let names = poll_until(50, Duration::from_millis(100), || async {
        tool_names(&client).await.filter(|names| !names.is_empty())
    })
    .await
    .expect("the granted tool should be listed on B");
    assert_eq!(names, ["files_read_file"]);
}

#[tokio::test]
async fn a_toolset_change_made_on_one_replica_reaches_the_users_client_on_the_other() {
    let Some(fleet) = Fleet::start("axon_replicas_toolsets", |config| config.rbac(RBAC)).await
    else {
        return;
    };
    let alice = fleet.login("alice", &["it-claim"]).await;
    let (status, toolset) = fleet
        .api(
            &alice,
            Method::POST,
            "/api/v1/toolsets",
            json!({ "name": "mine", "tools": ["files_*"] }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{toolset}");
    let id = toolset["id"].as_str().expect("an id").to_string();
    let pat = fleet
        .pat(&alice, json!({ "name": "pinned", "toolset_id": id }))
        .await;

    // Alice's client on B sees what the toolset keeps of her two tools.
    let recorder = Recorder::default();
    let client = connect(&format!("{}/mcp", fleet.b.base), &pat, &recorder).await;
    settle().await;
    assert_eq!(
        tool_names(&client).await.expect("tools"),
        ["files_list_files", "files_read_file"]
    );
    let seen = recorder.list_changed();

    // She narrows the toolset through A.
    let (status, body) = fleet
        .api(
            &alice,
            Method::PATCH,
            &format!("/api/v1/toolsets/{id}"),
            json!({ "tools": ["files_read_*"] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    expect_list_changed(&recorder, seen).await;
    let names = poll_until(50, Duration::from_millis(100), || async {
        tool_names(&client).await.filter(|names| names.len() == 1)
    })
    .await
    .expect("the narrowed toolset should apply on B");
    assert_eq!(names, ["files_read_file"]);
}

#[tokio::test]
async fn a_session_opened_on_one_replica_is_restored_by_the_other() {
    let Some(fleet) = Fleet::start("axon_replicas_sessions", |config| config.rbac(RBAC)).await
    else {
        return;
    };
    let alice = fleet.login("alice", &["it-claim"]).await;
    let bob = fleet.login("bob", &["it-claim"]).await;
    let alice_pat = fleet.pat(&alice, json!({ "name": "mcp" })).await;
    let bob_pat = fleet.pat(&bob, json!({ "name": "mcp" })).await;
    let mcp_a = format!("{}/mcp", fleet.a.base);
    let mcp_b = format!("{}/mcp", fleet.b.base);
    let client = reqwest::Client::new();

    let accept = ("Accept", "application/json, text/event-stream");
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "replica-tests", "version": "0.0.0" },
        },
    });
    let (status, headers, init) =
        raw_post(&client, &mcp_a, Some(&alice_pat), &initialize, &[accept]).await;
    assert_eq!(status, StatusCode::OK, "{init}");
    let session = headers
        .get("mcp-session-id")
        .expect("an Mcp-Session-Id header")
        .to_str()
        .unwrap()
        .to_string();

    let session_headers = [
        accept,
        ("Mcp-Session-Id", session.as_str()),
        ("MCP-Protocol-Version", "2025-11-25"),
    ];
    let initialized = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let (status, _, _) = raw_post(
        &client,
        &mcp_a,
        Some(&alice_pat),
        &initialized,
        &session_headers,
    )
    .await;
    assert!(status.is_success(), "initialized notification got {status}");

    // B never saw this session; it restores it from the database.
    let (status, _, listed) = raw_post(
        &client,
        &mcp_b,
        Some(&alice_pat),
        &rpc("tools/list"),
        &session_headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let mut names = listed["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["files_list_files", "files_read_file"]);

    // The session belongs to alice: bob presenting its id is told it is unknown.
    let (status, _, body) = raw_post(
        &client,
        &mcp_b,
        Some(&bob_pat),
        &rpc("tools/list"),
        &session_headers,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn the_rate_limit_is_counted_across_replicas() {
    let Some(fleet) = Fleet::start("axon_replicas_rate_limit", |config| {
        config.rate_limit_per_minute(3)
    })
    .await
    else {
        return;
    };
    let alice = fleet.login("alice", &["alice-claim"]).await;
    let pat = fleet.pat(&alice, json!({ "name": "mcp" })).await;
    let client = reqwest::Client::new();
    let mcp_a = format!("{}/mcp", fleet.a.base);
    let mcp_b = format!("{}/mcp", fleet.b.base);

    // The window is the wall-clock minute: do not straddle a rollover.
    let into_minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs()
        % 60;
    if into_minute >= 45 {
        tokio::time::sleep(Duration::from_secs(60 - into_minute + 1)).await;
    }

    for (replica, mcp) in [("A", &mcp_a), ("A", &mcp_a), ("B", &mcp_b)] {
        let (status, body) = mcp_post(&client, mcp, Some(&pat), &rpc("tools/list")).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "within the limit on {replica}: {body}"
        );
    }
    let (status, body) = mcp_post(&client, &mcp_b, Some(&pat), &rpc("tools/list")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the fourth request of the minute should be limited: {body}"
    );
}

// Dashboard login and the JSON API, as in `transport.rs`: the tests need users
// and personal access tokens, which only exist through the identity provider.

/// A logged-in dashboard user: the session cookie and its CSRF token.
struct Session {
    cookie: String,
    csrf: String,
}

/// A user's session through the mock provider's login flow.
async fn login_as(
    client: &reqwest::Client,
    base: &str,
    idp: &MockOidc,
    subject: &str,
    groups: &[&str],
) -> Session {
    idp.set_user(json!({
        "sub": subject,
        "email": format!("{subject}@example.com"),
        "name": subject,
        "groups": groups,
    }));
    let resp = client
        .get(format!("{base}/auth/login"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let login_url = format!("{base}{}", location(&resp));

    let resp = client.get(login_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let login_cookie = cookie_pair(&resp, LOGIN_COOKIE).expect("a login cookie");
    let provider_url = location(&resp);

    // The mock approves on the spot and sends the browser back.
    let resp = client.get(provider_url).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let callback = location(&resp);

    let resp = client
        .get(callback)
        .header(COOKIE, login_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie");

    let page = client
        .get(format!("{base}/ui/tokens"))
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

/// A JSON API call as `session`; writes carry the CSRF token.
async fn api(
    client: &reqwest::Client,
    base: &str,
    session: &Session,
    method: Method,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = client
        .request(method, format!("{base}{path}"))
        .header(COOKIE, &session.cookie)
        .header("x-csrf-token", &session.csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
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
