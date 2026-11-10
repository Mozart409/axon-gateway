//! User toolsets end to end: the real gateway binary, a real Postgres schema, the mock
//! identity provider and a mock MCP backend. Users create toolsets through the JSON API
//! and the dashboard, pin personal access tokens to them and see `tools/list` and
//! `tools/call` follow the toolset live.
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

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, poll_until, rpc, rpc_call};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const FORM: &str = "application/x-www-form-urlencoded";

/// Length of `axon_pat_<16 hex>_<64 hex>`
const PAT_LEN: usize = 9 + 16 + 1 + 64;

/// `it` and `sales` come from claim values of the `mock` provider and are
/// granted different tools of `files`; nobody is granted `audit_log`.
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
        let backend =
            MockBackend::start(&["read_file", "list_files", "delete_file", "audit_log"]).await;
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

    /// A dashboard action (form post) with the session's CSRF token; returns
    /// status and body text.
    async fn action(&self, path: &str, session: &Session, body: &str) -> (StatusCode, String) {
        let resp = self
            .client
            .post(self.url(path))
            .header(COOKIE, &session.cookie)
            .header("x-csrf-token", &session.csrf)
            .header(CONTENT_TYPE, FORM)
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.text().await.unwrap())
    }

    /// A dashboard page; returns status and body text.
    async fn page(&self, path: &str, session: &Session) -> (StatusCode, String) {
        let resp = self
            .client
            .get(self.url(path))
            .header(COOKIE, &session.cookie)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.text().await.unwrap())
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

    /// A user's own token through the API; returns its id and plaintext.
    async fn create_pat(&self, session: &Session, body: Value) -> (String, String) {
        let (status, token) = self
            .send(Method::POST, "/api/v1/tokens", session, Some(body))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{token}");
        let plaintext = token["plaintext"]
            .as_str()
            .expect("a plaintext")
            .to_string();
        assert!(plaintext.starts_with("axon_pat_"));
        assert_eq!(plaintext.len(), PAT_LEN);
        (token["id"].as_str().unwrap().to_string(), plaintext)
    }

    /// A JSON-RPC call to `path`, with a bearer token unless `bearer` is `None`.
    async fn mcp_at(&self, path: &str, bearer: Option<&str>, body: &Value) -> (StatusCode, Value) {
        let mut request = self.client.post(self.url(path)).json(body);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let resp = request.send().await.unwrap();
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// The tool names `tools/list` returns on `path` for a token, sorted.
    async fn tool_names_at(&self, path: &str, token: &str) -> Vec<String> {
        let (status, body) = self.mcp_at(path, Some(token), &rpc("tools/list")).await;
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

    /// The tool names `tools/list` returns on `/mcp` for a token, sorted.
    async fn tool_names(&self, token: &str) -> Vec<String> {
        self.tool_names_at("/mcp", token).await
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

    /// `tools/call` on `path` with a token; the whole JSON-RPC answer.
    async fn call_at(&self, path: &str, token: &str, tool: &str) -> Value {
        let (status, body) = self
            .mcp_at(path, Some(token), &rpc_call(tool, json!({})))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// `tools/call` on `/mcp` with a token; the whole JSON-RPC answer.
    async fn call(&self, token: &str, tool: &str) -> Value {
        self.call_at("/mcp", token, tool).await
    }

    /// Creates a toolset through the API; returns its id.
    async fn create_toolset(&self, session: &Session, body: Value) -> String {
        let (status, toolset) = self
            .send(Method::POST, "/api/v1/toolsets", session, Some(body))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{toolset}");
        toolset["id"].as_str().expect("an id").to_string()
    }

    /// Changes a toolset through the API.
    async fn patch_toolset(&self, session: &Session, id: &str, body: Value) {
        let (status, toolset) = self
            .send(
                Method::PATCH,
                &format!("/api/v1/toolsets/{id}"),
                session,
                Some(body),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{toolset}");
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

/// The first complete token plaintext in `text`; the `axon_pat_<id>_…` prefix
/// the lists show is too short to match.
fn find_plaintext(text: &str) -> Option<String> {
    text.match_indices("axon_pat_")
        .map(|(start, _)| {
            text[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .find(|candidate| candidate.len() == PAT_LEN)
}

/// The code and message of a JSON-RPC error, with the tool's name blanked so
/// that errors about different tools compare.
fn error_shape(body: &Value, tool: &str) -> (i64, String) {
    let error = &body["error"];
    assert!(error.is_object(), "expected a JSON-RPC error, got {body}");
    (
        error["code"].as_i64().unwrap(),
        error["message"].as_str().unwrap().replace(tool, "<tool>"),
    )
}

/// A call that went through: a result and no error.
fn assert_called(body: &Value) {
    assert!(body.get("error").is_none(), "{body}");
    assert!(body["result"].is_object(), "{body}");
}

#[tokio::test]
async fn a_pinned_token_follows_its_toolset_live() {
    let Some(h) = Harness::start("axon_toolsets_pinned").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let id = h
        .create_toolset(
            &alice,
            json!({
                "name": "reader",
                "description": "read only",
                "tools": ["files_read_*"],
            }),
        )
        .await;
    let (status, listed) = h.send(Method::GET, "/api/v1/toolsets", &alice, None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["toolsets"][0]["name"], "reader");
    assert_eq!(listed["toolsets"][0]["tools"], json!(["files_read_*"]));

    let (_, free_pat) = h.create_pat(&alice, json!({ "name": "free" })).await;
    let (status, pinned) = h
        .send(
            Method::POST,
            "/api/v1/tokens",
            &alice,
            Some(json!({ "name": "pinned", "toolset_id": id })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{pinned}");
    assert_eq!(pinned["toolset_id"], id.as_str());
    assert_eq!(pinned["toolset_name"], "reader");
    let pinned_pat = pinned["plaintext"].as_str().unwrap().to_string();

    // Policy is the owner's two tools; the toolset leaves one of them.
    assert_eq!(
        h.connected_tool_names(&free_pat).await,
        ["files_list_files", "files_read_file"]
    );
    assert_eq!(h.tool_names(&pinned_pat).await, ["files_read_file"]);

    // A tool outside the toolset is unknown, like one that does not exist.
    let nothing = error_shape(&h.call(&pinned_pat, "files_nothing").await, "files_nothing");
    let outside = h.call(&pinned_pat, "files_list_files").await;
    assert_eq!(error_shape(&outside, "files_list_files"), nothing);
    assert_called(&h.call(&pinned_pat, "files_read_file").await);

    // Editing the toolset changes the same token on its next request.
    h.patch_toolset(&alice, &id, json!({ "tools": ["files_list_*"] }))
        .await;
    assert_eq!(h.tool_names(&pinned_pat).await, ["files_list_files"]);
    h.patch_toolset(&alice, &id, json!({ "tools": [] })).await;
    assert_eq!(
        h.tool_names(&pinned_pat).await,
        ["files_list_files", "files_read_file"]
    );
    // A toolset backend the owner is not granted leaves nothing, it never adds.
    h.patch_toolset(&alice, &id, json!({ "backends": ["elsewhere"] }))
        .await;
    assert_eq!(h.tool_names(&pinned_pat).await, Vec::<String>::new());
    h.patch_toolset(&alice, &id, json!({ "backends": ["files"] }))
        .await;
    assert_eq!(
        h.tool_names(&pinned_pat).await,
        ["files_list_files", "files_read_file"]
    );

    // The token scope and the toolset both have to allow a tool.
    h.patch_toolset(
        &alice,
        &id,
        json!({ "tools": ["files_list_*", "files_read_*"] }),
    )
    .await;
    let (_, both) = h
        .create_pat(
            &alice,
            json!({ "name": "both", "toolset_id": id, "scope_tools": ["files_list_*"] }),
        )
        .await;
    assert_eq!(h.tool_names(&both).await, ["files_list_files"]);
}

#[tokio::test]
async fn the_toolset_endpoint_applies_the_callers_own_toolset() {
    let Some(h) = Harness::start("axon_toolsets_endpoint").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    h.create_toolset(
        &alice,
        json!({ "name": "reader", "tools": ["files_read_*"] }),
    )
    .await;
    let (_, pat) = h.create_pat(&alice, json!({ "name": "free" })).await;
    let path = "/mcp/toolset/reader";

    assert_eq!(
        h.connected_tool_names(&pat).await,
        ["files_list_files", "files_read_file"]
    );
    assert_eq!(h.tool_names_at(path, &pat).await, ["files_read_file"]);

    // Calls are limited too, not only the list.
    let nothing = error_shape(
        &h.call_at(path, &pat, "files_nothing").await,
        "files_nothing",
    );
    let outside = h.call_at(path, &pat, "files_list_files").await;
    assert_eq!(error_shape(&outside, "files_list_files"), nothing);
    assert_called(&h.call_at(path, &pat, "files_read_file").await);
    // /mcp itself is not narrowed by a toolset the token is not pinned to.
    assert_called(&h.call(&pat, "files_list_files").await);
}

#[tokio::test]
async fn a_pinned_toolset_cannot_be_deleted_until_the_token_is_revoked() {
    let Some(h) = Harness::start("axon_toolsets_delete").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let id = h
        .create_toolset(&alice, json!({ "name": "ops", "tools": ["files_read_*"] }))
        .await;
    let (token_id, _) = h
        .create_pat(&alice, json!({ "name": "pinned", "toolset_id": id }))
        .await;
    let path = format!("/api/v1/toolsets/{id}");

    let (status, body) = h.send(Method::DELETE, &path, &alice, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, _) = h.send(Method::GET, &path, &alice, None).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/tokens/{token_id}"),
            &alice,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = h.send(Method::DELETE, &path, &alice, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, _) = h.send(Method::GET, &path, &alice, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The revoked token stays in the list, no longer pinned.
    let (_, tokens) = h.send(Method::GET, "/api/v1/tokens", &alice, None).await;
    assert_eq!(tokens["tokens"][0]["toolset_id"], Value::Null);
}

#[tokio::test]
async fn toolsets_are_private_and_validated() {
    let Some(h) = Harness::start("axon_toolsets_isolation").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let bob = h.login_as("bob", "bob@example.com", &["sales-claim"]).await;
    let id = h
        .create_toolset(&alice, json!({ "name": "ops", "tools": ["files_read_*"] }))
        .await;
    let path = format!("/api/v1/toolsets/{id}");

    // Bob sees nothing of Alice's, and cannot touch or pin it.
    let (status, listed) = h.send(Method::GET, "/api/v1/toolsets", &bob, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["toolsets"], json!([]));
    let (status, _) = h.send(Method::GET, &path, &bob, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h
        .send(Method::PATCH, &path, &bob, Some(json!({ "tools": [] })))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.send(Method::DELETE, &path, &bob, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/tokens",
            &bob,
            Some(json!({ "name": "stolen", "toolset_id": id })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let (_, tokens) = h.send(Method::GET, "/api/v1/tokens", &bob, None).await;
    assert_eq!(tokens["tokens"], json!([]));
    // Alice's is untouched, and the name is free for Bob.
    let (status, body) = h.send(Method::GET, &path, &alice, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["tools"], json!(["files_read_*"]));
    h.create_toolset(&bob, json!({ "name": "ops" })).await;

    // Bad names and a taken name.
    for name in ["Bad Name", "", "authenticated"] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/toolsets",
                &alice,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name:?}: {body}");
    }
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/toolsets",
            &alice,
            Some(json!({ "name": "ops" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/toolsets",
            &alice,
            Some(json!({ "name": "blank", "tools": [" "] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_dashboard_manages_toolsets_and_pins_tokens() {
    let Some(h) = Harness::start("axon_toolsets_ui").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;

    let (status, page) = h.page("/ui/toolsets", &alice).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("No toolsets yet."));

    let (status, html) = h
        .action(
            "/ui/actions/toolsets",
            &alice,
            "name=uiset&description=from+the+page&tools=files_read_%2A%0D%0A&backends=files",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("uiset"));
    let (_, listed) = h.send(Method::GET, "/api/v1/toolsets", &alice, None).await;
    assert_eq!(listed["toolsets"][0]["tools"], json!(["files_read_*"]));
    assert_eq!(listed["toolsets"][0]["backends"], json!(["files"]));
    let id = listed["toolsets"][0]["id"].as_str().unwrap().to_string();

    // The token form offers it, and the token it issues is pinned.
    let (_, tokens_page) = h.page("/ui/tokens", &alice).await;
    assert!(tokens_page.contains(&format!("value=\"{id}\"")));
    let (status, html) = h
        .action(
            "/ui/actions/tokens",
            &alice,
            &format!("name=pinned&toolset_id={id}"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{html}");
    assert!(html.contains("toolset: "));
    let pat = find_plaintext(&html).expect("the new token's secret");
    assert_eq!(h.connected_tool_names(&pat).await, ["files_read_file"]);

    // Editing through the page reaches the token, and a pinned delete is a 409.
    let (status, _) = h
        .action(
            &format!("/ui/actions/toolsets/{id}"),
            &alice,
            "name=uiset&tools=files_list_%2A&backends=files",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.tool_names(&pat).await, ["files_list_files"]);
    let (status, _) = h
        .action(&format!("/ui/actions/toolsets/{id}/delete"), &alice, "")
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
