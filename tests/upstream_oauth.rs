//! A user's own account at a catalog backend (upstream `OAuth`, "Connect") and
//! identity passthrough (RFC 8693 token exchange, Entra on-behalf-of) end to
//! end: the real gateway binary, a real Postgres schema, the mock identity
//! provider, a mock authorization server and OAuth-protected mock MCP backends.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

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
use reqwest::{Method, RequestBuilder, Response, StatusCode, Url};
use serde_json::{Value, json};
use support::mock_backend::{MockBackend, MockBackendBuilder};
use support::mock_oidc::MockOidc;
use support::mock_upstream::MockUpstream;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const FORM: &str = "application/x-www-form-urlencoded";

/// Allows the loopback mocks as backends.
const ALLOW_LOOPBACK: &str = "egress_allow = [\"127.0.0.1/32\"]";

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Where the backends of the passthrough tests say their authorization server
/// is; nothing is ever fetched from it.
const NO_ISSUER: &str = "http://127.0.0.1:1";

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// A multi-user gateway with the catalog entries a test gives it, in its own
/// schema, and a mock identity provider for the logins.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    /// `provider_extra` goes into the `[[auth.oidc]]` table of the `mock`
    /// provider, `env` into the environment of the gateway, and `tweak` adds
    /// the catalog entries and their grants to the config.
    async fn start(
        schema: &str,
        provider_extra: &str,
        env: &[(&str, &str)],
        tweak: impl FnOnce(ConfigBuilder) -> ConfigBuilder,
    ) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let bind = format!("127.0.0.1:{}", free_port());
        let builder = ConfigBuilder::new(&bind)
            .database(DATABASE_ENV)
            .personal_backends(ALLOW_LOOPBACK)
            .oidc_provider("mock", idp.issuer(), "axon-test", provider_extra);
        let config = tweak(builder).render();
        let mut env = env.to_vec();
        env.push((DATABASE_ENV, &url));
        let gateway = Gateway::start_with_env(&config, &format!("http://{bind}"), &env).await;

        Some(Self {
            gateway,
            client: no_redirect_client(),
            idp,
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

    /// Like [`Harness::api`] with an optional JSON body; returns status and
    /// body (a body that is not JSON comes back as a string).
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
    async fn login_as(&self, subject: &str, email: &str) -> Session {
        self.idp.set_user(json!({
            "sub": subject,
            "email": email,
            "name": subject,
            "groups": [],
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

    /// A dashboard form post with the session's CSRF token as a field.
    async fn post_action(&self, session: &Session, path: &str) -> Response {
        self.client
            .post(self.url(path))
            .header(COOKIE, &session.cookie)
            .header(CONTENT_TYPE, FORM)
            .body(form(&[("csrf_token", &session.csrf)]))
            .send()
            .await
            .unwrap()
    }

    /// Presses Connect on catalog entry `backend`; returns the URL the browser
    /// is sent to (the upstream authorization request).
    async fn start_connect(&self, session: &Session, backend: &str) -> String {
        let resp = self
            .post_action(session, &format!("/ui/actions/catalog/{backend}/connect"))
            .await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        location(&resp)
    }

    /// What the browser does at the authorization server: no cookies of the
    /// gateway go there, and the mock approves on the spot. Returns the URL the
    /// server sends the browser back to.
    async fn approve(&self, authorize_url: &str) -> String {
        let resp = self.client.get(authorize_url).send().await.unwrap();
        if resp.status() != StatusCode::FOUND {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            panic!("the authorization server answered {status}: {body}");
        }
        location(&resp)
    }

    /// The browser coming back to the gateway with the user's session.
    async fn callback(&self, session: &Session, callback_url: &str) -> Response {
        self.client
            .get(callback_url)
            .header(COOKIE, &session.cookie)
            .send()
            .await
            .unwrap()
    }

    /// The whole Connect flow of a user: returns the authorization URL.
    async fn connect(&self, session: &Session, backend: &str) -> String {
        let authorize_url = self.start_connect(session, backend).await;
        let callback_url = self.approve(&authorize_url).await;
        assert!(
            callback_url.starts_with(&self.url("/oauth/upstream/callback?")),
            "{callback_url}"
        );
        let resp = self.callback(session, &callback_url).await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), "/ui/catalog");
        authorize_url
    }

    /// `GET /api/v1/me/connections`.
    async fn connections(&self, session: &Session) -> Vec<Value> {
        let (status, body) = self
            .send(Method::GET, "/api/v1/me/connections", session, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["connections"]
            .as_array()
            .unwrap_or_else(|| panic!("no connections in {body}"))
            .clone()
    }

    /// The tool names `tools/list` returns for a bearer token, sorted.
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

    /// Polls `tools/list` until `tool` is in it (a backend connects on demand)
    /// or is gone, whichever `present` asks for.
    async fn wait_for_tool(&self, token: &str, tool: &str, present: bool) -> bool {
        poll_until(50, Duration::from_millis(100), || async {
            let names = self.tool_names(token).await;
            (names.iter().any(|name| name == tool) == present).then_some(())
        })
        .await
        .is_some()
    }

    /// `tools/call` with a bearer token; the JSON-RPC answer.
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

/// An `application/x-www-form-urlencoded` body
fn form(fields: &[(&str, &str)]) -> String {
    let mut url = Url::parse("http://form.invalid/").unwrap();
    url.query_pairs_mut().extend_pairs(fields);
    url.query().unwrap_or_default().to_string()
}

/// The value of query parameter `name` of `url`.
fn query_param(url: &str, name: &str) -> Option<String> {
    Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// `url` with query parameter `name` set to `value`.
fn with_query_param(url: &str, name: &str, value: &str) -> String {
    let mut url = Url::parse(url).unwrap();
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .filter(|(key, _)| key != name)
        .collect();
    url.query_pairs_mut()
        .clear()
        .extend_pairs(pairs)
        .append_pair(name, value);
    url.to_string()
}

/// A `[[backends]]` catalog entry; `extra` holds the credential mode and its
/// tables as TOML.
fn catalog_entry(name: &str, url: &str, extra: &str) -> String {
    format!("[[backends]]\nname = \"{name}\"\ntransport = \"http\"\nurl = \"{url}\"\n{extra}\n")
}

/// An entry connected through the backend's own authorization server (no
/// static client).
fn oauth_entry(name: &str, url: &str) -> String {
    catalog_entry(name, url, "credential_mode = \"oauth\"")
}

/// An entry with a static OAuth client.
fn static_client_entry(name: &str, url: &str, client_id: &str) -> String {
    catalog_entry(
        name,
        url,
        &format!("credential_mode = \"oauth\"\n\n[backends.oauth]\nclient_id = \"{client_id}\"\n"),
    )
}

/// An entry whose token is traded for the user's identity; `table` is the
/// body of `[backends.passthrough]`.
fn passthrough_entry(name: &str, url: &str, table: &str) -> String {
    catalog_entry(
        name,
        url,
        &format!("credential_mode = \"passthrough\"\n\n[backends.passthrough]\n{table}\n"),
    )
}

/// Everybody may use the entries `names`.
fn grants(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("[[rbac.grants]]\ngroup = \"authenticated\"\nbackend = \"{name}\"\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A mock MCP backend that only takes the access tokens of `upstream`.
async fn protected_backend(upstream: &MockUpstream) -> MockBackend {
    MockBackendBuilder::new()
        .tool("echo")
        .tool("other")
        .require_bearer(upstream.issuer(), |token| token.starts_with("up_at_"))
        .build()
        .await
}

/// A mock MCP backend that only takes the tokens a passthrough yields.
async fn exchange_backend() -> MockBackend {
    MockBackendBuilder::new()
        .tool("echo")
        .require_bearer(NO_ISSUER, |token| token.starts_with("exchanged_"))
        .build()
        .await
}

/// A call that went through: a result and no error.
fn assert_called(body: &Value) {
    assert!(body.get("error").is_none(), "{body}");
    assert!(body["result"].is_object(), "{body}");
}

#[tokio::test]
async fn connecting_through_dynamic_registration_gives_the_user_their_tools() {
    let upstream = MockUpstream::start().await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_dcr", "", &[], |builder| {
        builder
            .raw_backend(&oauth_entry("wiki", &backend.url()))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let bob = h.login_as("bob", "bob@example.com").await;
    let alice_pat = h.create_pat(&alice).await;
    let bob_pat = h.create_pat(&bob).await;

    // Nothing is connected yet.
    assert_eq!(h.connections(&alice).await, [] as [serde_json::Value; 0]);
    assert!(
        !h.tool_names(&alice_pat)
            .await
            .iter()
            .any(|name| name.starts_with("wiki_"))
    );

    let authorize_url = h.connect(&alice, "wiki").await;

    // The gateway registered itself once, and asked for what the spec says.
    assert!(
        authorize_url.starts_with(&format!("{}/authorize?", upstream.issuer())),
        "{authorize_url}"
    );
    let registrations = upstream.registrations();
    assert_eq!(registrations.len(), 1, "{registrations:?}");
    assert_eq!(
        registrations[0]["redirect_uris"],
        json!([h.url("/oauth/upstream/callback")])
    );
    let authorizations = upstream.authorize_requests();
    assert_eq!(authorizations.len(), 1);
    assert!(authorizations[0]["client_id"].starts_with("dcr-client-"));
    assert_eq!(authorizations[0]["resource"], backend.url());
    assert_eq!(authorizations[0]["code_challenge_method"], "S256");
    let exchanges = upstream.token_requests_for("authorization_code");
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].field("resource"), backend.url());
    assert_eq!(
        exchanges[0].field("redirect_uri"),
        h.url("/oauth/upstream/callback")
    );
    assert_ne!(exchanges[0].field("code_verifier"), "");

    // The connection lists.
    let connections = h.connections(&alice).await;
    assert_eq!(connections.len(), 1, "{connections:?}");
    assert_eq!(connections[0]["backend"], "wiki");
    assert_eq!(connections[0]["issuer"], upstream.issuer());
    assert!(connections[0]["last_error"].is_null(), "{connections:?}");

    // Alice's tools include the backend's, prefixed, and calls reach it with
    // her upstream access token.
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);
    assert_called(&h.call(&alice_pat, "wiki_echo", json!({})).await);
    let issued = upstream.issued_access_tokens();
    assert!(issued[0].starts_with("up_at_"), "{issued:?}");
    assert!(
        backend.bearer_tokens().contains(&issued[0]),
        "{:?} should hold {}",
        backend.bearer_tokens(),
        issued[0]
    );
    assert!(backend.call_count("echo") >= 1);

    // Bob did not connect: nothing of the entry for him.
    assert_eq!(h.connections(&bob).await, [] as [serde_json::Value; 0]);
    assert!(
        !h.tool_names(&bob_pat)
            .await
            .iter()
            .any(|name| name.starts_with("wiki_"))
    );
}

#[tokio::test]
async fn a_client_id_metadata_document_identifies_the_gateway() {
    let upstream = MockUpstream::builder().dcr(false).cimd(true).start().await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_cimd", "", &[], |builder| {
        builder
            .raw_backend(&oauth_entry("wiki", &backend.url()))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    // The mock server fetches the document while approving, so a connection
    // that completes also proves the document says the right redirect URI.
    h.connect(&alice, "wiki").await;
    let client_id = h.url("/oauth/upstream/client.json");
    let authorizations = upstream.authorize_requests();
    assert_eq!(authorizations.len(), 1);
    assert_eq!(authorizations[0]["client_id"], client_id);
    assert_eq!(upstream.registrations(), [] as [serde_json::Value; 0]);
    assert_eq!(
        upstream.token_requests_for("authorization_code")[0].field("client_id"),
        client_id
    );

    let resp = h.client.get(&client_id).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let document: Value = resp.json().await.unwrap();
    assert_eq!(document["client_id"], client_id);
    assert_eq!(
        document["redirect_uris"],
        json!([h.url("/oauth/upstream/callback")])
    );

    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);
}

#[tokio::test]
async fn a_static_client_needs_no_registration() {
    let upstream = MockUpstream::builder()
        .known_client("static-client")
        .start()
        .await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_static", "", &[], |builder| {
        builder
            .raw_backend(&static_client_entry(
                "wiki",
                &backend.url(),
                "static-client",
            ))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    h.connect(&alice, "wiki").await;

    // The server offers registration, but the configured client wins.
    assert_eq!(upstream.registrations(), [] as [serde_json::Value; 0]);
    let authorizations = upstream.authorize_requests();
    assert_eq!(authorizations.len(), 1);
    assert_eq!(authorizations[0]["client_id"], "static-client");
    let exchanges = upstream.token_requests_for("authorization_code");
    assert_eq!(exchanges.len(), 1);
    assert_eq!(exchanges[0].field("client_id"), "static-client");
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);
}

#[tokio::test]
async fn an_expiring_token_is_refreshed_when_the_users_backends_are_built() {
    let upstream = MockUpstream::builder().expires_in(60).start().await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_refresh", "", &[], |builder| {
        builder
            .raw_backend(&oauth_entry("wiki", &backend.url()))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    h.connect(&alice, "wiki").await;
    // It lives 60 seconds, less than the 2 minutes the gateway refreshes ahead.
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);

    let first = upstream.issued_access_tokens()[0].clone();
    let refreshes = poll_until(50, Duration::from_millis(100), || async {
        let refreshes = upstream.token_requests_for("refresh_token");
        (!refreshes.is_empty()).then_some(refreshes)
    })
    .await
    .expect("the gateway should have refreshed the token");
    // The refresh token of the first access token (`up_at_<n>` / `up_rt_<n>`).
    assert_eq!(
        refreshes[0].field("refresh_token"),
        first.replace("up_at_", "up_rt_")
    );
    let refreshed_access = refreshes[0]
        .access_token
        .clone()
        .expect("the refresh should have been granted");
    assert_ne!(refreshed_access, first);

    // The backend only ever saw the refreshed token.
    let seen = backend.bearer_tokens();
    assert!(
        seen.contains(&refreshed_access),
        "{seen:?} should hold {refreshed_access}"
    );
    assert!(!seen.contains(&first), "{seen:?} should not hold {first}");
}

#[tokio::test]
async fn the_callback_refuses_foreign_unknown_and_mismatched_requests() {
    let upstream = MockUpstream::builder().iss_parameter(true).start().await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_guards", "", &[], |builder| {
        builder
            .raw_backend(&oauth_entry("wiki", &backend.url()))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let bob = h.login_as("bob", "bob@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    // Alice's request, finished with Bob's session.
    let authorize_url = h.start_connect(&alice, "wiki").await;
    let callback_url = h.approve(&authorize_url).await;
    assert!(
        callback_url.contains("iss="),
        "the server returns iss: {callback_url}"
    );
    let resp = h.callback(&bob, &callback_url).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A state nobody started.
    let unknown = h.url("/oauth/upstream/callback?code=whatever&state=unknown");
    let resp = h.callback(&alice, &unknown).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A callback of another issuer: the server announces the iss parameter,
    // so the wrong one (and a missing one) is refused.
    let authorize_url = h.start_connect(&alice, "wiki").await;
    let callback_url = h.approve(&authorize_url).await;
    let forged = with_query_param(&callback_url, "iss", "http://evil.example");
    let resp = h.callback(&alice, &forged).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let authorize_url = h.start_connect(&alice, "wiki").await;
    let callback_url = h.approve(&authorize_url).await;
    let state = query_param(&callback_url, "state").expect("a state");
    let code = query_param(&callback_url, "code").expect("a code");
    let without_iss = h.url(&format!(
        "/oauth/upstream/callback?{}",
        form(&[("code", &code), ("state", &state)])
    ));
    let resp = h.callback(&alice, &without_iss).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // None of it got as far as the token endpoint, nothing connected.
    assert!(upstream.token_requests().is_empty());
    assert_eq!(h.connections(&alice).await, [] as [serde_json::Value; 0]);
    assert_eq!(h.connections(&bob).await, [] as [serde_json::Value; 0]);

    // The same flow with the right parameters works.
    h.connect(&alice, "wiki").await;
    assert_eq!(h.connections(&alice).await.len(), 1);
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);
}

#[tokio::test]
async fn disconnecting_removes_the_tools_and_the_connection() {
    let upstream = MockUpstream::start().await;
    let backend = protected_backend(&upstream).await;
    let Some(h) = Harness::start("axon_upstream_disconnect", "", &[], |builder| {
        builder
            .raw_backend(&oauth_entry("wiki", &backend.url()))
            .rbac(&grants(&["wiki"]))
    })
    .await
    else {
        return;
    };
    let alice = h.login_as("alice", "alice@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    // Through the dashboard.
    h.connect(&alice, "wiki").await;
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);
    let resp = h
        .post_action(&alice, "/ui/actions/catalog/wiki/disconnect")
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", false).await);
    assert_eq!(h.connections(&alice).await, [] as [serde_json::Value; 0]);

    // And through the API: connect again, then DELETE.
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/me/connections/wiki",
            &alice,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let authorize_url = body["authorize_url"]
        .as_str()
        .unwrap_or_else(|| panic!("no authorize_url in {body}"))
        .to_string();
    let callback_url = h.approve(&authorize_url).await;
    let resp = h.callback(&alice, &callback_url).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(h.connections(&alice).await.len(), 1);
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", true).await);

    let (status, body) = h
        .send(Method::DELETE, "/api/v1/me/connections/wiki", &alice, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(h.wait_for_tool(&alice_pat, "wiki_echo", false).await);
    assert_eq!(h.connections(&alice).await, [] as [serde_json::Value; 0]);

    // Nothing left to remove.
    let (status, body) = h
        .send(Method::DELETE, "/api/v1/me/connections/wiki", &alice, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn a_jwt_is_exchanged_for_a_backend_token_by_rfc_8693() {
    let backend = exchange_backend().await;
    let Some(h) = Harness::start(
        "axon_upstream_exchange",
        "accept_access_tokens = true",
        &[],
        |builder| {
            builder
                .raw_backend(&passthrough_entry(
                    "papi",
                    &backend.url(),
                    "grant = \"token_exchange\"\nprovider = \"mock\"\naudience = \"backend-api\"",
                ))
                .rbac(&grants(&["papi"]))
        },
    )
    .await
    else {
        return;
    };
    h.idp.set_token_exchange(true);
    // A JWT acts as the user who logged in with its subject.
    h.login_as("alice", "alice@example.com").await;

    let jwt = h.idp.mint_access_token(&json!({ "sub": "alice" }));
    assert!(h.wait_for_tool(&jwt, "papi_echo", true).await);
    assert_called(&h.call(&jwt, "papi_echo", json!({})).await);

    let forms = h.idp.token_forms_for(GRANT_TOKEN_EXCHANGE);
    assert!(!forms.is_empty(), "{:?}", h.idp.token_forms());
    let form = &forms[0];
    assert_eq!(form["subject_token"], jwt);
    assert_eq!(form["subject_token_type"], TOKEN_TYPE_ACCESS);
    assert_eq!(form["audience"], "backend-api");
    assert_eq!(form["client_id"], "axon-test");

    let seen = backend.bearer_tokens();
    assert!(
        seen.iter().any(|token| token.starts_with("exchanged_")),
        "{seen:?}"
    );
    assert!(!seen.contains(&jwt), "the user's own token must not leak");
}

#[tokio::test]
async fn entra_on_behalf_of_uses_the_refresh_token_kept_at_login() {
    let backend = exchange_backend().await;
    let Some(h) = Harness::start(
        "axon_upstream_obo",
        "client_secret_env = \"AXON_TEST_ENTRA_SECRET\"",
        &[("AXON_TEST_ENTRA_SECRET", "entra-secret-value")],
        |builder| {
            builder
                .raw_backend(&passthrough_entry(
                    "papi",
                    &backend.url(),
                    "grant = \"entra_obo\"\nprovider = \"mock\"\nscope = \"api://backend/.default\"",
                ))
                .rbac(&grants(&["papi"]))
        },
    )
    .await
    else {
        return;
    };
    // The login must hand the gateway a refresh token to keep.
    h.idp.set_refresh_tokens(true);
    h.idp.set_token_exchange(true);
    let alice = h.login_as("alice", "alice@example.com").await;
    let alice_pat = h.create_pat(&alice).await;

    // A personal access token carries no identity provider token: the gateway
    // refreshes one from the refresh token it kept, and trades that.
    assert!(h.wait_for_tool(&alice_pat, "papi_echo", true).await);
    assert_called(&h.call(&alice_pat, "papi_echo", json!({})).await);

    let forms = h.idp.token_forms();
    let refresh = forms
        .iter()
        .position(|form| form["grant_type"] == "refresh_token")
        .expect("a refresh_token grant");
    let obo = forms
        .iter()
        .position(|form| form["grant_type"] == GRANT_JWT_BEARER)
        .expect("a jwt-bearer grant");
    assert!(refresh < obo, "{forms:?}");
    assert!(forms[refresh]["refresh_token"].starts_with("refresh_"));

    let form = &forms[obo];
    assert_eq!(form["requested_token_use"], "on_behalf_of");
    assert!(form["assertion"].starts_with("idp_at_"), "{form:?}");
    assert_eq!(form["scope"], "api://backend/.default");
    assert_eq!(form["client_id"], "axon-test");
    assert_eq!(form["client_secret"], "entra-secret-value");

    let seen = backend.bearer_tokens();
    assert!(
        seen.iter().any(|token| token.starts_with("exchanged_")),
        "{seen:?}"
    );
}
