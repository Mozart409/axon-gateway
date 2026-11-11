//! MCP transport end to end: the real gateway binary behind the spec-compliant
//! streamable HTTP endpoints. Covers the stateless 2026-07-28 protocol, the
//! session based versions, the `Host` header check, the `allow_stdio` gate and
//! the notifications the gateway relays (`list_changed`, progress, cancel).
//!
//! The test that needs a database skips itself unless `AXON_TEST_DATABASE_URL`
//! is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, Response, StatusCode};
use rmcp::ServiceExt;
use rmcp::handler::client::ClientHandler;
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, ClientRequest, ProgressNotificationParam,
};
use rmcp::service::{NotificationContext, PeerRequestOptions, RoleClient, RunningService};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use serde_json::{Value, json};
use support::mock_backend::{MockBackend, MockBackendBuilder};
use support::mock_oidc::MockOidc;
use support::{
    ConfigBuilder, Gateway, free_port, mcp_post, mcp_request, poll_until, raw_post, rpc, rpc_call,
};

const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";

/// A gateway bound to a free port; returns it with its address.
async fn start_gateway(config: impl FnOnce(&str) -> String) -> (Gateway, String) {
    let bind = format!("127.0.0.1:{}", free_port());
    let base = format!("http://{bind}");
    let gateway = Gateway::start(&config(&bind), &base).await;
    (gateway, base)
}

/// Poll the stateless `tools/list` until the gateway lists `n` tools.
async fn wait_for_tools(client: &reqwest::Client, mcp: &str, bearer: Option<&str>, n: usize) {
    poll_until(50, Duration::from_millis(100), || async {
        let (_, body) = mcp_post(client, mcp, bearer, &rpc("tools/list")).await;
        body["result"]["tools"]
            .as_array()
            .filter(|tools| tools.len() >= n)
            .map(|_| ())
    })
    .await
    .expect("the gateway should list the backend tools");
}

/// What a connected client has been told by the gateway.
#[derive(Clone, Default)]
struct Recorder {
    list_changed: Arc<AtomicUsize>,
    progress: Arc<Mutex<Vec<ProgressNotificationParam>>>,
}

impl Recorder {
    fn list_changed(&self) -> usize {
        self.list_changed.load(Ordering::SeqCst)
    }

    fn progress(&self) -> Vec<ProgressNotificationParam> {
        self.progress.lock().unwrap().clone()
    }
}

impl ClientHandler for Recorder {
    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress.lock().unwrap().push(params);
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.list_changed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Connect an rmcp client (initialize, session, standalone event stream) to
/// `url`, with `token` as the bearer token when given.
async fn connect(
    url: &str,
    token: Option<&str>,
    recorder: &Recorder,
) -> RunningService<RoleClient, Recorder> {
    let mut config = StreamableHttpClientTransportConfig::with_uri(url);
    if let Some(token) = token {
        config = config.auth_header(token.to_string());
    }
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

fn call_request(tool: &str) -> ClientRequest {
    ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
        tool.to_string(),
    )))
}

#[tokio::test]
async fn stateless_requests_work_without_initialize() {
    let backend = MockBackend::start(&["echo"]).await;
    let (server, _) = start_gateway(|bind| {
        ConfigBuilder::new(bind)
            .http_backend("mock", &backend.url())
            .render()
    })
    .await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    wait_for_tools(&client, &mcp, None, 1).await;
    let (status, listed) = mcp_post(&client, &mcp, None, &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["result"]["tools"][0]["name"], "mock_echo");

    let (status, called) = mcp_post(
        &client,
        &mcp,
        None,
        &rpc_call("mock_echo", json!({ "value": 7 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{called}");
    assert_ne!(called["result"]["isError"], true, "{called}");
    let text = called["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("echo:"), "got {text}");
    assert_eq!(backend.call_count("echo"), 1);
}

#[tokio::test]
async fn stateless_requests_carry_the_bearer_token() {
    let backend = MockBackend::start(&["echo"]).await;
    let (server, _) = start_gateway(|bind| {
        ConfigBuilder::new(bind)
            .auth_token("transport-secret")
            .http_backend("mock", &backend.url())
            .render()
    })
    .await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    // Auth failures stay HTTP 401, whatever the protocol version.
    let (status, _) = mcp_post(&client, &mcp, None, &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = mcp_post(&client, &mcp, Some("wrong"), &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    wait_for_tools(&client, &mcp, Some("transport-secret"), 1).await;
}

#[tokio::test]
async fn a_bare_json_post_is_rejected() {
    let (server, _) = start_gateway(|bind| ConfigBuilder::new(bind).render()).await;
    let client = reqwest::Client::new();

    // No Accept, no protocol version, no 2026-07-28 metadata.
    let resp = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc("tools/list"))
        .send()
        .await
        .expect("bare request");
    assert!(
        resp.status().is_client_error(),
        "a bare POST should be a 4xx, got {}",
        resp.status()
    );

    // The old SSE endpoint is gone.
    let resp = client
        .get(format!("{}/mcp/sse", server.base))
        .send()
        .await
        .expect("sse request");
    assert!(
        resp.status().is_client_error(),
        "/mcp/sse should be gone, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn a_2025_11_25_client_initializes_and_uses_a_session() {
    let backend = MockBackend::start(&["echo"]).await;
    let (server, _) = start_gateway(|bind| {
        ConfigBuilder::new(bind)
            .http_backend("mock", &backend.url())
            .render()
    })
    .await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);
    wait_for_tools(&client, &mcp, None, 1).await;

    let accept = ("Accept", "application/json, text/event-stream");
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "transport-tests", "version": "0.0.0" },
        },
    });
    let (status, headers, init) = raw_post(&client, &mcp, None, &initialize, &[accept]).await;
    assert_eq!(status, StatusCode::OK, "{init}");
    assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
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
    let (status, _, _) = raw_post(&client, &mcp, None, &initialized, &session_headers).await;
    assert!(status.is_success(), "initialized notification got {status}");

    let (status, _, listed) =
        raw_post(&client, &mcp, None, &rpc("tools/list"), &session_headers).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["result"]["tools"][0]["name"], "mock_echo");
}

#[tokio::test]
async fn a_2024_11_05_initialize_is_not_negotiated() {
    let (server, _) = start_gateway(|bind| ConfigBuilder::new(bind).render()).await;
    let client = reqwest::Client::new();

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "transport-tests", "version": "0.0.0" },
        },
    });
    let (status, _, body) = raw_post(
        &client,
        &format!("{}/mcp", server.base),
        None,
        &initialize,
        &[("Accept", "application/json, text/event-stream")],
    )
    .await;
    // Either refused, or answered with a version the server does support.
    if status.is_success() {
        let version = body["result"]["protocolVersion"].as_str().unwrap_or("");
        assert_ne!(version, "2024-11-05", "{body}");
        assert!(!version.is_empty(), "{body}");
    } else {
        assert!(status.is_client_error(), "got {status}: {body}");
    }
}

#[tokio::test]
async fn a_wrong_host_header_is_rejected() {
    let (server, _) = start_gateway(|bind| ConfigBuilder::new(bind).render()).await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    let (status, body) = mcp_request(
        &client,
        &mcp,
        None,
        &rpc("tools/list"),
        &[("Host", "evil.example")],
    )
    .await;
    assert!(status.is_client_error(), "got {status}: {body}");

    // Loopback (the client's own Host header) and base_url's host pass.
    let (status, body) = mcp_post(&client, &mcp, None, &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn an_allowed_hosts_entry_is_accepted() {
    let (server, _) = start_gateway(|bind| {
        ConfigBuilder::new(bind)
            .allowed_hosts(&["gateway.example"])
            .render()
    })
    .await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    let (status, body) = mcp_request(
        &client,
        &mcp,
        None,
        &rpc("tools/list"),
        &[("Host", "gateway.example")],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A host that is not listed is still refused.
    let (status, body) = mcp_request(
        &client,
        &mcp,
        None,
        &rpc("tools/list"),
        &[("Host", "other.example")],
    )
    .await;
    assert!(status.is_client_error(), "got {status}: {body}");
}

#[tokio::test]
async fn a_stdio_backend_needs_allow_stdio() {
    let config = ConfigBuilder::new(&format!("127.0.0.1:{}", free_port()))
        .stdio_backend("local", "/nonexistent/axon-test-mcp")
        .render();
    let status = Gateway::run_to_exit(&config, Duration::from_secs(10))
        .expect("the gateway should refuse to start, not keep running");
    assert!(!status.success(), "expected a non-zero exit, got {status}");

    // With the switch on, the same config starts (the backend is just down).
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind)
        .allow_stdio(true)
        .stdio_backend("local", "/nonexistent/axon-test-mcp")
        .render();
    let _server = Gateway::start(&config, &format!("http://{bind}")).await;
}

#[tokio::test]
async fn adding_a_backend_by_config_reload_sends_list_changed() {
    let one = MockBackend::start(&["alpha"]).await;
    let two = MockBackend::start(&["beta"]).await;
    let bind = format!("127.0.0.1:{}", free_port());
    let base = format!("http://{bind}");
    let before = ConfigBuilder::new(&bind)
        .http_backend("one", &one.url())
        .render();
    let mut server = Gateway::start(&before, &base).await;

    let recorder = Recorder::default();
    let client = connect(&format!("{base}/mcp"), None, &recorder).await;
    let tools = poll_until(50, Duration::from_millis(100), || async {
        let tools = client.list_all_tools().await.ok()?;
        (!tools.is_empty()).then_some(tools)
    })
    .await
    .expect("the first backend's tool should be listed");
    assert_eq!(tools[0].name, "one_alpha");
    settle().await;
    let seen = recorder.list_changed();

    let after = ConfigBuilder::new(&bind)
        .http_backend("one", &one.url())
        .http_backend("two", &two.url())
        .render();
    server.replace_config_atomically(&after);

    poll_until(100, Duration::from_millis(100), || async {
        (recorder.list_changed() > seen).then_some(())
    })
    .await
    .expect("the client should be told the tool list changed");
    let tools = client.list_all_tools().await.expect("tools after reload");
    assert!(
        tools.iter().any(|tool| tool.name == "two_beta"),
        "expected the new backend's tool, got {tools:?}"
    );
}

#[tokio::test]
async fn progress_reaches_the_client_with_its_own_token() {
    let backend = MockBackendBuilder::new()
        .progress_tool("work", 3)
        .build()
        .await;
    let bind = format!("127.0.0.1:{}", free_port());
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let _server = Gateway::start(&config, &base).await;

    let recorder = Recorder::default();
    let client = connect(&format!("{base}/mcp"), None, &recorder).await;
    poll_until(50, Duration::from_millis(100), || async {
        let tools = client.list_all_tools().await.ok()?;
        (!tools.is_empty()).then_some(())
    })
    .await
    .expect("the backend's tool should be listed");

    let handle = client
        .send_cancellable_request(call_request("mock_work"), PeerRequestOptions::no_options())
        .await
        .expect("send the call");
    let token = handle.progress_token.clone();
    handle
        .await_response()
        .await
        .expect("the call should succeed");

    let received = poll_until(50, Duration::from_millis(100), || async {
        let progress = recorder.progress();
        (!progress.is_empty()).then_some(progress)
    })
    .await
    .expect("progress notifications should reach the client");
    for notification in &received {
        assert_eq!(notification.progress_token, token);
    }
}

#[tokio::test]
async fn cancelling_a_call_cancels_the_backend_call() {
    let backend = MockBackendBuilder::new()
        .wait_for_cancel_tool("hang")
        .build()
        .await;
    let bind = format!("127.0.0.1:{}", free_port());
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let _server = Gateway::start(&config, &base).await;

    let recorder = Recorder::default();
    let client = connect(&format!("{base}/mcp"), None, &recorder).await;
    poll_until(50, Duration::from_millis(100), || async {
        let tools = client.list_all_tools().await.ok()?;
        (!tools.is_empty()).then_some(())
    })
    .await
    .expect("the backend's tool should be listed");

    let handle = client
        .send_cancellable_request(call_request("mock_hang"), PeerRequestOptions::no_options())
        .await
        .expect("send the call");
    poll_until(100, Duration::from_millis(50), || async {
        (backend.call_count("hang") == 1).then_some(())
    })
    .await
    .expect("the call should reach the backend");
    assert!(!backend.was_cancelled("hang"));

    handle
        .cancel(Some("test is done waiting".to_string()))
        .await
        .expect("cancel the call");
    poll_until(100, Duration::from_millis(50), || async {
        backend.was_cancelled("hang").then_some(())
    })
    .await
    .expect("the backend call should be cancelled");
}

// The remaining test needs a database: a real Postgres schema, the mock
// identity provider and the admin API.

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

#[tokio::test]
async fn an_admin_grant_change_sends_list_changed_to_the_principal() {
    let Ok(db) = std::env::var("AXON_TEST_DATABASE_URL") else {
        eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
        return;
    };
    let url = isolated_url(&db, "axon_transport_grants").await;

    let idp = MockOidc::start("axon-test").await;
    let backend = MockBackend::start(&["read_file", "delete_file"]).await;
    let bind = format!("127.0.0.1:{}", free_port());
    let base = format!("http://{bind}");
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
    let _server = Gateway::start_with_env(&config, &base, &[(DATABASE_ENV, &url)]).await;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client should build");

    let admin = login_as(&http, &base, &idp, "root", &["admins"]).await;
    let alice = login_as(&http, &base, &idp, "alice", &["alice-claim"]).await;
    let (status, token) = api(
        &http,
        &base,
        &alice,
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "mcp" }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    let pat = token["plaintext"]
        .as_str()
        .expect("a plaintext")
        .to_string();

    // Alice's client is connected and subscribed; nothing is granted yet.
    let recorder = Recorder::default();
    let client = connect(&format!("{base}/mcp"), Some(&pat), &recorder).await;
    settle().await;
    assert_eq!(client.list_all_tools().await.expect("tools"), Vec::new());
    let seen = recorder.list_changed();

    // An admin grants her group a tool of `files`.
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
        let (status, body) = api(&http, &base, &admin, Method::POST, path, body).await;
        assert_eq!(status, StatusCode::CREATED, "{path}: {body}");
    }

    poll_until(100, Duration::from_millis(100), || async {
        (recorder.list_changed() > seen).then_some(())
    })
    .await
    .expect("the principal should be told the tool list changed");
    let names = poll_until(50, Duration::from_millis(100), || async {
        let tools = client.list_all_tools().await.ok()?;
        (!tools.is_empty()).then(|| {
            tools
                .iter()
                .map(|tool| tool.name.to_string())
                .collect::<Vec<_>>()
        })
    })
    .await
    .expect("the granted tool should be listed");
    assert_eq!(names, ["files_read_file"]);
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
