//! Personal access tokens and service accounts end to end: the real gateway
//! binary, a real Postgres schema, the mock identity provider and a mock MCP
//! backend. Users create tokens through the JSON API and the dashboard, then
//! call `/mcp` with them and see exactly what their policy allows.
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
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

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
    backend: MockBackend,
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
            backend,
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

    /// A JSON-RPC call to `/mcp`, with a bearer token unless `bearer` is `None`.
    async fn mcp(&self, bearer: Option<&str>, body: &Value) -> (StatusCode, Value) {
        mcp_post(&self.client, &self.url("/mcp"), bearer, body).await
    }

    /// The tool names `tools/list` returns for a token, sorted.
    async fn tool_names(&self, token: &str) -> Vec<String> {
        let (status, body) = self.mcp(Some(token), &rpc("tools/list")).await;
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

    /// `tools/call` with a token; the whole JSON-RPC answer. The stateless
    /// transport answers "method not found" (-32601, an unknown or hidden
    /// tool) with HTTP 404 and the JSON-RPC error as the body.
    async fn call(&self, token: &str, tool: &str) -> Value {
        let (status, body) = self.mcp(Some(token), &rpc_call(tool, json!({}))).await;
        let expected = if body["error"]["code"] == -32601 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::OK
        };
        assert_eq!(status, expected, "{body}");
        body
    }

    /// The status of `tools/list` with this bearer token (or none).
    async fn mcp_status(&self, bearer: Option<&str>) -> StatusCode {
        self.mcp(bearer, &rpc("tools/list")).await.0
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
async fn tokens_enforce_each_principals_policy_end_to_end() {
    let Some(h) = Harness::start("axon_tokens_enforcement").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let bob = h.login_as("bob", "bob@example.com", &["sales-claim"]).await;
    let (_, alice_pat) = h
        .create_pat(&alice, json!({ "name": "alice laptop" }))
        .await;
    let (_, bob_pat) = h.create_pat(&bob, json!({ "name": "bob laptop" })).await;

    // The lists differ as the groups' grants do.
    assert_eq!(
        h.connected_tool_names(&alice_pat).await,
        ["files_list_files", "files_read_file"]
    );
    assert_eq!(h.tool_names(&bob_pat).await, ["files_delete_file"]);

    // Each can call its own tool.
    assert_called(&h.call(&alice_pat, "files_read_file").await);
    assert_called(&h.call(&bob_pat, "files_delete_file").await);
    assert_eq!(h.backend.call_count("read_file"), 1);
    assert_eq!(h.backend.call_count("delete_file"), 1);

    // The other's tool, and a tool that is granted to nobody, answer exactly
    // like a tool that does not exist, and never reach the backend.
    let nothing = h.call(&alice_pat, "files_nothing").await;
    let nothing = error_shape(&nothing, "files_nothing");
    assert_eq!(nothing.0, -32601, "{nothing:?}");
    for (pat, tool) in [
        (&alice_pat, "files_delete_file"),
        (&alice_pat, "files_audit_log"),
        (&bob_pat, "files_read_file"),
        (&bob_pat, "files_list_files"),
    ] {
        let hidden = h.call(pat, tool).await;
        assert_eq!(error_shape(&hidden, tool), nothing, "{tool}");
    }
    assert_eq!(h.backend.call_count("delete_file"), 1);
    assert_eq!(h.backend.call_count("read_file"), 1);
    assert_eq!(h.backend.call_count("audit_log"), 0);
}

#[tokio::test]
async fn scope_opt_outs_revocation_and_bad_tokens() {
    let Some(h) = Harness::start("axon_tokens_scope").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (_, full) = h.create_pat(&alice, json!({ "name": "full" })).await;
    let (_, narrow) = h
        .create_pat(
            &alice,
            json!({ "name": "narrow", "scope_tools": ["files_read_*"] }),
        )
        .await;
    let (_, nowhere) = h
        .create_pat(
            &alice,
            json!({ "name": "nowhere", "scope_backends": ["elsewhere"] }),
        )
        .await;
    assert_eq!(
        h.connected_tool_names(&full).await,
        ["files_list_files", "files_read_file"]
    );

    // A scope only narrows.
    assert_eq!(h.tool_names(&narrow).await, ["files_read_file"]);
    assert_eq!(h.tool_names(&nowhere).await, Vec::<String>::new());
    let nothing = h.call(&full, "files_nothing").await;
    let nothing = error_shape(&nothing, "files_nothing");
    let out_of_scope = h.call(&narrow, "files_list_files").await;
    assert_eq!(error_shape(&out_of_scope, "files_list_files"), nothing);
    assert_called(&h.call(&narrow, "files_read_file").await);

    // A tool the owner opted out of is gone for every token of theirs.
    let (status, _) = h
        .action(
            "/ui/actions/tools/opt-out",
            &alice,
            "backend=files&tool=list_files&hidden=true",
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.tool_names(&full).await, ["files_read_file"]);
    let opted_out = h.call(&full, "files_list_files").await;
    assert_eq!(error_shape(&opted_out, "files_list_files"), nothing);
    assert_eq!(h.backend.call_count("list_files"), 0);

    // A revoked token is refused, and so is revoking it twice.
    let (id, doomed) = h.create_pat(&alice, json!({ "name": "doomed" })).await;
    assert_eq!(h.mcp_status(Some(doomed.as_str())).await, StatusCode::OK);
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/tokens/{id}"),
            &alice,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.mcp_status(Some(doomed.as_str())).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("/api/v1/tokens/{id}"),
            &alice,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Garbage and no token at all are refused in multi-user mode.
    let unknown = format!("axon_pat_0123456789abcdef_{}", "ab".repeat(32));
    for bearer in [
        Some(unknown.as_str()),
        Some("axon_pat_garbage"),
        Some("axon_pat_"),
        Some("not-a-token"),
        None,
    ] {
        assert_eq!(
            h.mcp_status(bearer).await,
            StatusCode::UNAUTHORIZED,
            "{bearer:?}"
        );
    }
    // The secret of a real token under another token's id is refused too.
    let wrong_secret = format!("{}{}", &full[..26], "0".repeat(64));
    assert_eq!(
        h.mcp_status(Some(wrong_secret.as_str())).await,
        StatusCode::UNAUTHORIZED
    );
    // The live tokens are unaffected.
    assert_eq!(h.mcp_status(Some(full.as_str())).await, StatusCode::OK);
}

#[tokio::test]
async fn a_service_account_token_follows_its_groups_and_its_state() {
    let Some(h) = Harness::start("axon_tokens_service_account").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    let (status, account) = h
        .send(
            Method::POST,
            "/api/v1/service-accounts",
            &admin,
            Some(json!({ "name": "ci-bot", "description": "CI agent" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    assert_eq!(account["name"], "ci-bot");
    assert_eq!(account["disabled"], false);
    let id = account["id"].as_str().unwrap().to_string();

    // Names follow the group name rules, and are unique.
    for (name, expected) in [
        ("CI Bot", StatusCode::BAD_REQUEST),
        ("ci-bot", StatusCode::CONFLICT),
    ] {
        let (status, _) = h
            .send(
                Method::POST,
                "/api/v1/service-accounts",
                &admin,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, expected, "{name}");
    }

    // The account joins a group of its own, with one grant.
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "agents" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, grant) = h
        .send(
            Method::POST,
            "/api/v1/grants",
            &admin,
            Some(json!({ "group": "agents", "backend": "files", "include": ["read_file"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let (status, _) = h
        .send(
            Method::PUT,
            &format!("/api/v1/groups/agents/members/{id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The lifetime is capped at 365 days for an account.
    let tokens_path = format!("/api/v1/service-accounts/{id}/tokens");
    for days in [0, 366] {
        let (status, _) = h
            .send(
                Method::POST,
                &tokens_path,
                &admin,
                Some(json!({ "name": "ci", "expires_in_days": days })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{days}");
    }
    let (status, token) = h
        .send(
            Method::POST,
            &tokens_path,
            &admin,
            Some(json!({ "name": "ci", "expires_in_days": 365 })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    let plaintext = token["plaintext"].as_str().unwrap().to_string();
    let token_id = token["id"].as_str().unwrap().to_string();

    // The token sees what the account's groups grant.
    assert_eq!(
        h.connected_tool_names(&plaintext).await,
        ["files_read_file"]
    );
    assert_called(&h.call(&plaintext, "files_read_file").await);
    let denied = h.call(&plaintext, "files_delete_file").await;
    let nothing = h.call(&plaintext, "files_nothing").await;
    assert_eq!(
        error_shape(&denied, "files_delete_file"),
        error_shape(&nothing, "files_nothing")
    );

    // The listing has the token without its secret.
    let (status, listed) = h.send(Method::GET, &tokens_path, &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["tokens"][0]["name"], "ci");
    assert_eq!(listed["tokens"][0]["state"], "active");
    assert!(!listed.to_string().contains(&plaintext[26..]));

    // Disabling the account stops its token, enabling it again restores it.
    let account_path = format!("/api/v1/service-accounts/{id}");
    let (status, patched) = h
        .send(
            Method::PATCH,
            &account_path,
            &admin,
            Some(json!({ "disabled": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    assert_eq!(patched["disabled"], true);
    assert_eq!(
        h.mcp_status(Some(plaintext.as_str())).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = h
        .send(
            Method::PATCH,
            &account_path,
            &admin,
            Some(json!({ "disabled": false })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.mcp_status(Some(plaintext.as_str())).await, StatusCode::OK);

    // Revoking the token stops it; the account is still there.
    let (status, _) = h
        .send(
            Method::DELETE,
            &format!("{tokens_path}/{token_id}"),
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.mcp_status(Some(plaintext.as_str())).await,
        StatusCode::UNAUTHORIZED
    );

    // A token of an account that is deleted stops too, and its endpoints go.
    let (_, second) = h
        .send(
            Method::POST,
            &tokens_path,
            &admin,
            Some(json!({ "name": "second" })),
        )
        .await;
    let second = second["plaintext"].as_str().unwrap().to_string();
    assert_eq!(h.mcp_status(Some(second.as_str())).await, StatusCode::OK);
    let (status, _) = h.send(Method::DELETE, &account_path, &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        h.mcp_status(Some(second.as_str())).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = h.send(Method::GET, &tokens_path, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A user's id is not a service account: no tokens for people.
    let (status, me) = h.send(Method::GET, "/api/v1/me", &admin, None).await;
    assert_eq!(status, StatusCode::OK);
    let own_id = me["user"]["id"].as_str().unwrap();
    let (status, _) = h
        .send(
            Method::POST,
            &format!("/api/v1/service-accounts/{own_id}/tokens"),
            &admin,
            Some(json!({ "name": "sneaky" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn permissions_and_the_one_time_secret() {
    let Some(h) = Harness::start("axon_tokens_secret").await else {
        return;
    };
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let bob = h.login_as("bob", "bob@example.com", &["sales-claim"]).await;
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let some_id = "00000000-0000-0000-0000-000000000001";

    // Service accounts are for admins.
    for (method, path, body) in [
        (Method::GET, "/api/v1/service-accounts".to_string(), None),
        (
            Method::POST,
            "/api/v1/service-accounts".to_string(),
            Some(json!({ "name": "mine" })),
        ),
        (
            Method::PATCH,
            format!("/api/v1/service-accounts/{some_id}"),
            Some(json!({ "disabled": true })),
        ),
        (
            Method::DELETE,
            format!("/api/v1/service-accounts/{some_id}"),
            None,
        ),
        (
            Method::GET,
            format!("/api/v1/service-accounts/{some_id}/tokens"),
            None,
        ),
        (
            Method::POST,
            format!("/api/v1/service-accounts/{some_id}/tokens"),
            Some(json!({ "name": "mine" })),
        ),
        (
            Method::DELETE,
            format!("/api/v1/service-accounts/{some_id}/tokens/{some_id}"),
            None,
        ),
    ] {
        let (status, _) = h.send(method.clone(), &path, &alice, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }
    let (status, _) = h.page("/ui/admin/service-accounts", &alice).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Bad requests are refused.
    for body in [
        json!({ "name": "" }),
        json!({ "name": "x", "expires_in_days": 0 }),
        json!({ "name": "x", "expires_in_days": 91 }),
        json!({ "name": "x", "scope_tools": [" "] }),
        json!({ "expires_in_days": 5 }),
    ] {
        let (status, error) = h
            .send(Method::POST, "/api/v1/tokens", &alice, Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {error}");
        assert!(error["error"].is_string());
    }

    // The create response is the only place with the secret.
    let (status, created) = h
        .send(
            Method::POST,
            "/api/v1/tokens",
            &alice,
            Some(json!({ "name": "laptop", "scope_backends": ["files"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let plaintext = created["plaintext"].as_str().unwrap().to_string();
    let secret = &plaintext[26..];
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["state"], "active");
    assert_eq!(created["scope_backends"], json!(["files"]));
    assert!(created["prefix"].as_str().unwrap().starts_with("axon_pat_"));

    let (status, listed) = h.send(Method::GET, "/api/v1/tokens", &alice, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["tokens"][0]["id"], id.as_str());
    assert!(listed["tokens"][0].get("plaintext").is_none());
    assert!(!listed.to_string().contains(secret));
    let (status, page) = h.page("/ui/tokens", &alice).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("laptop"));
    assert!(page.contains(&created["prefix"].as_str().unwrap().to_string()));
    assert!(page.contains("href=\"/ui/tokens\""));
    assert!(!page.contains(secret));

    // Nobody else sees or revokes it.
    let (status, theirs) = h.send(Method::GET, "/api/v1/tokens", &bob, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(theirs["tokens"], json!([]));
    let (status, _) = h
        .send(Method::DELETE, &format!("/api/v1/tokens/{id}"), &bob, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(h.mcp_status(Some(plaintext.as_str())).await, StatusCode::OK);

    // The dashboard creates one too, and shows its secret once.
    let (status, fragment) = h
        .action(
            "/ui/actions/tokens",
            &alice,
            "name=from+the+page&expires_in_days=7&scope_backends=files&scope_tools=files_read_*%2C+files_list_*",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fragment}");
    let shown = find_plaintext(&fragment).expect("the new token in the fragment");
    assert!(fragment.contains("will not be shown again"));
    assert!(fragment.contains("from the page"));
    assert_ne!(shown, plaintext);
    let (_, page) = h.page("/ui/tokens", &alice).await;
    assert!(page.contains("from the page"));
    assert!(page.contains("files_read_*, files_list_*"));
    assert!(find_plaintext(&page).is_none());
    assert_eq!(
        h.connected_tool_names(&shown).await,
        ["files_list_files", "files_read_file"]
    );

    // And revokes it.
    let (_, listed) = h.send(Method::GET, "/api/v1/tokens", &alice, None).await;
    let shown_id = listed["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|token| token["name"] == "from the page")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, fragment) = h
        .action(&format!("/ui/actions/tokens/{shown_id}/revoke"), &alice, "")
        .await;
    assert_eq!(status, StatusCode::OK, "{fragment}");
    assert!(fragment.contains(">revoked<"));
    assert_eq!(
        h.mcp_status(Some(shown.as_str())).await,
        StatusCode::UNAUTHORIZED
    );
    let (status, _) = h
        .action(&format!("/ui/actions/tokens/{shown_id}/revoke"), &alice, "")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The admin page creates an account and a token, with the secret once.
    let (status, fragment) = h
        .action(
            "/ui/actions/admin/service-accounts",
            &admin,
            "name=ui-bot&description=made+in+the+page",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fragment}");
    assert!(fragment.contains("ui-bot"));
    let (_, accounts) = h
        .send(Method::GET, "/api/v1/service-accounts", &admin, None)
        .await;
    let account_id = accounts["service_accounts"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, fragment) = h
        .action(
            &format!("/ui/actions/admin/service-accounts/{account_id}/tokens"),
            &admin,
            "name=ui+token&expires_in_days=30",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fragment}");
    let account_token = find_plaintext(&fragment).expect("the new token in the fragment");
    assert!(fragment.contains("will not be shown again"));
    let (status, page) = h.page("/ui/admin/service-accounts", &admin).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("ui-bot"));
    assert!(page.contains("ui token"));
    assert!(find_plaintext(&page).is_none());
    // The account has no groups yet, so its token sees nothing.
    assert_eq!(
        h.mcp_status(Some(account_token.as_str())).await,
        StatusCode::OK
    );
    assert_eq!(h.tool_names(&account_token).await, Vec::<String>::new());

    // The group page offers the account as a member.
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "agents" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, group_page) = h.page("/ui/admin/groups/agents", &admin).await;
    assert!(group_page.contains("ui-bot (service account)"));
    let (status, fragment) = h
        .action(
            "/ui/actions/admin/groups/agents/members/add",
            &admin,
            &format!("user_id={account_id}"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{fragment}");
    assert!(fragment.contains("ui-bot (service account)"));
    let (_, admin_page) = h.page("/ui/admin", &admin).await;
    assert!(admin_page.contains("href=\"/ui/admin/service-accounts\""));
}

#[tokio::test]
async fn tokens_are_not_found_in_standalone_mode() {
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind).render();
    let gateway = Gateway::start(&config, &format!("http://{bind}")).await;
    let client = no_redirect_client();

    for path in [
        "/ui/tokens",
        "/ui/admin/service-accounts",
        "/api/v1/tokens",
        "/api/v1/service-accounts",
    ] {
        let resp = client
            .get(format!("{}{path}", gateway.base))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn status_endpoints_need_gateway_admin_in_database_mode() {
    let Some(h) = Harness::start("axon_tokens_status").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let alice = h
        .login_as("alice", "alice@example.com", &["it-claim"])
        .await;
    let (_, admin_pat) = h.create_pat(&admin, json!({ "name": "admin" })).await;
    let (_, alice_pat) = h.create_pat(&alice, json!({ "name": "alice" })).await;

    let get = |path: &'static str, bearer: Option<&str>| {
        let request = h.client.get(h.url(path));
        let request = match bearer {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        async move { request.send().await.unwrap() }
    };

    for path in [
        "/status",
        "/status/detailed",
        "/status/toolsets",
        "/status/groups",
    ] {
        let resp = get(path, None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(resp.headers()["www-authenticate"], "Bearer", "{path}");
        let resp = get(path, Some("axon_pat_garbage")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
        let resp = get(path, Some(&alice_pat)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "{path}");
        let resp = get(path, Some(&admin_pat)).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
    let detailed: Value = get("/status/detailed", Some(&admin_pat))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(detailed["backends"][0]["name"], "files");

    // A dashboard session works the same way
    for (session, expected) in [(&admin, StatusCode::OK), (&alice, StatusCode::FORBIDDEN)] {
        let resp = h
            .api(Method::GET, "/status/detailed", session)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), expected);
    }

    // Probes and metrics stay open
    for path in ["/health", "/livez", "/readyz", "/build", "/metrics"] {
        let resp = get(path, None).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
    }
}
