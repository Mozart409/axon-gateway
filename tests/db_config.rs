//! The gateway's configuration in the database, through the
//! `/api/v1/admin/config` API: backends, gateway toolsets, OIDC providers and
//! the settings, with their permissions, the secret handling and the live
//! effect of a write.
//!
//! The gateway starts in database mode (the harness imports the config file
//! first, then starts the binary from the environment alone). The tests skip
//! themselves unless `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

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
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

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

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// How the gateway of a test starts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// The provider `mock` and the `it` group come from the imported file.
    Plain,
    /// `AXON_ALLOW_STDIO=true`, otherwise like `Plain`.
    Stdio,
    /// The only provider is the environment's, `envsso`; no file RBAC.
    EnvProvider,
}

/// A gateway in database mode in front of a `files` backend, in its own
/// schema, and a second backend (`extra`: `ping`, `pong`) to add through the
/// API. Users whose groups claim holds `admins` are admins.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
    _files: MockBackend,
    extra: MockBackend,
    provider: &'static str,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str, variant: Variant) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let files = MockBackend::start(&["read_file", "list_files", "delete_file"]).await;
        let extra = MockBackend::start(&["ping", "pong"]).await;
        let bind = format!("127.0.0.1:{}", free_port());
        let mut config = ConfigBuilder::new(&bind)
            .http_backend("files", &files.url())
            .database(DATABASE_ENV);
        let mut env = vec![(DATABASE_ENV, url.as_str())];
        match variant {
            Variant::Plain | Variant::Stdio => {
                config = config
                    .oidc_provider(
                        "mock",
                        idp.issuer(),
                        "axon-test",
                        "admin_groups = [\"admins\"]",
                    )
                    .rbac(RBAC);
            }
            Variant::EnvProvider => {
                env.extend([
                    ("AXON_OIDC_ISSUER", idp.issuer()),
                    ("AXON_OIDC_CLIENT_ID", "axon-test"),
                    ("AXON_OIDC_ADMIN_GROUPS", "admins"),
                    ("AXON_OIDC_ID", "envsso"),
                ]);
            }
        }
        if variant == Variant::Stdio {
            config = config.allow_stdio(true);
        }
        let gateway =
            Gateway::start_with_env(&config.render(), &format!("http://{bind}"), &env).await;

        Some(Self {
            gateway,
            client: no_redirect_client(),
            idp,
            _files: files,
            extra,
            provider: if variant == Variant::EnvProvider {
                "envsso"
            } else {
                "mock"
            },
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    /// A request with the session cookie; writes carry the CSRF token.
    fn api(&self, method: Method, path: &str, session: &Session) -> RequestBuilder {
        let read = method == Method::GET;
        let request = self
            .client
            .request(method, self.url(path))
            .header(COOKIE, &session.cookie);
        if read {
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

    /// A complete login through the provider `provider` as the given user.
    async fn login_as(&self, subject: &str, groups: &[&str]) -> Session {
        self.idp.set_user(json!({
            "sub": subject,
            "email": format!("{subject}@example.com"),
            "name": subject,
            "groups": groups,
        }));
        let resp = self
            .client
            .get(self.url(&format!("/auth/login/{}", self.provider)))
            .send()
            .await
            .unwrap();
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

    /// A personal access token of the session's user.
    async fn pat(&self, session: &Session) -> String {
        let (status, token) = self
            .send(
                Method::POST,
                "/api/v1/tokens",
                session,
                Some(json!({ "name": "mcp" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{token}");
        token["plaintext"].as_str().unwrap().to_string()
    }

    /// The sorted tool names `tools/list` returns on `path` (`/mcp` or a
    /// toolset's); `None` unless the request succeeds.
    async fn tool_names(&self, pat: &str, path: &str) -> Option<Vec<String>> {
        let (status, body) =
            mcp_post(&self.client, &self.url(path), Some(pat), &rpc("tools/list")).await;
        if status != StatusCode::OK {
            return None;
        }
        let mut names: Vec<String> = body["result"]["tools"]
            .as_array()?
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect();
        names.sort();
        Some(names)
    }

    /// Waits until `/mcp` lists exactly `expected` for `pat` (a write reaches
    /// the gateway through the database notification).
    async fn expect_tools(&self, pat: &str, path: &str, expected: &[&str]) {
        let found = poll_until(150, Duration::from_millis(200), || async {
            self.tool_names(pat, path)
                .await
                .filter(|names| names == expected)
        })
        .await;
        assert!(
            found.is_some(),
            "{path} never listed exactly {expected:?}, last {:?}",
            self.tool_names(pat, path).await
        );
    }

    /// `/api/v1/admin/config/<path>`
    fn config_path(path: &str) -> String {
        format!("/api/v1/admin/config/{path}")
    }

    /// The `extra` backend as a request body.
    fn extra_body(&self) -> Value {
        json!({ "name": "extra", "url": self.extra.url(), "transport": "http" })
    }

    /// Grants the group `it` the tools of the backend `extra`. The backend has
    /// to be running on the gateway first, so this retries a while.
    async fn grant_extra(&self, admin: &Session) {
        let created = poll_until(100, Duration::from_millis(200), || async {
            let (status, body) = self
                .send(
                    Method::POST,
                    "/api/v1/grants",
                    admin,
                    Some(json!({ "group": "it", "backend": "extra", "include": ["ping", "pong"] })),
                )
                .await;
            (status == StatusCode::CREATED).then_some(body)
        })
        .await;
        assert!(created.is_some(), "the grant on `extra` was never accepted");
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

/// The entry named `key` = `value` of the array `body[list]`.
fn find<'a>(body: &'a Value, list: &str, key: &str, value: &str) -> Option<&'a Value> {
    body[list]
        .as_array()?
        .iter()
        .find(|entry| entry[key] == value)
}

#[tokio::test]
async fn a_backend_created_through_the_api_serves_its_tools_and_keeps_its_secrets() {
    let Some(h) = Harness::start("axon_dbconfig_backend", Variant::Plain).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;
    let alice = h.login_as("alice", &["it-claim"]).await;
    let pat = h.pat(&alice).await;
    h.expect_tools(&pat, "/mcp", &["files_list_files", "files_read_file"])
        .await;

    // Create it with an auth token and a secret header; the answer holds no value.
    let path = Harness::config_path("backends");
    let mut body = h.extra_body();
    body["auth_token"] = json!("token-one");
    body["headers"] = json!({ "x-api-key": "secret-one" });
    let (status, created) = h
        .send(Method::POST, &path, &admin, Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["name"], "extra");
    assert_eq!(created["auth_token_set"], true);
    assert_eq!(created["headers"], json!({ "x-api-key": "set" }));
    assert!(created.get("auth_token").is_none(), "{created}");
    let text = created.to_string();
    assert!(!text.contains("secret-one") && !text.contains("token-one"));

    // The name is taken.
    let (status, body) = h
        .send(Method::POST, &path, &admin, Some(h.extra_body()))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // It runs, and a grant makes its tools visible; the secrets reach it.
    h.grant_extra(&admin).await;
    h.expect_tools(
        &pat,
        "/mcp",
        &[
            "extra_ping",
            "extra_pong",
            "files_list_files",
            "files_read_file",
        ],
    )
    .await;
    assert!(
        h.extra
            .header_values("x-api-key")
            .contains(&"secret-one".to_string())
    );
    assert!(
        h.extra
            .header_values("authorization")
            .contains(&"Bearer token-one".to_string())
    );

    // Reads show which secrets are set, never a value.
    let item = format!("{path}/extra");
    let (status, one) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["auth_token_set"], true);
    assert_eq!(one["headers"], json!({ "x-api-key": "set" }));
    let (status, list) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert!(find(&list, "backends", "name", "files").is_some(), "{list}");
    assert!(find(&list, "backends", "name", "extra").is_some(), "{list}");
    let text = list.to_string();
    assert!(!text.contains("secret-one") && !text.contains("token-one"));

    // Keep: the secrets are absent or null, the rest changes (only `ping` now).
    let mut keep = h.extra_body();
    keep["allowed_tools"] = json!(["ping"]);
    keep["headers"] = json!({ "x-api-key": null });
    let (status, kept) = h.send(Method::PUT, &item, &admin, Some(keep)).await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert_eq!(kept["auth_token_set"], true);
    assert_eq!(kept["headers"], json!({ "x-api-key": "set" }));
    h.expect_tools(
        &pat,
        "/mcp",
        &["extra_ping", "files_list_files", "files_read_file"],
    )
    .await;
    assert!(
        h.extra
            .header_values("x-api-key")
            .iter()
            .all(|value| value == "secret-one"),
        "{:?}",
        h.extra.header_values("x-api-key")
    );

    // Set: a value replaces the stored one, and the backend sees the new one.
    let mut set = h.extra_body();
    set["headers"] = json!({ "x-api-key": "secret-two" });
    let (status, body) = h.send(Method::PUT, &item, &admin, Some(set)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["auth_token_set"], true, "the token was left out: keep");
    let seen = poll_until(150, Duration::from_millis(200), || async {
        (h.extra
            .header_values("x-api-key")
            .last()
            .map(String::as_str)
            == Some("secret-two"))
        .then_some(())
    })
    .await;
    assert!(seen.is_some(), "the backend never saw the new header value");
    h.expect_tools(
        &pat,
        "/mcp",
        &[
            "extra_ping",
            "extra_pong",
            "files_list_files",
            "files_read_file",
        ],
    )
    .await;

    // Clear: an empty token clears it, a header left out is removed.
    let mut clear = h.extra_body();
    clear["auth_token"] = json!("");
    clear["headers"] = json!({});
    let (status, cleared) = h.send(Method::PUT, &item, &admin, Some(clear)).await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["auth_token_set"], false);
    assert_eq!(cleared["headers"], json!({}));
    let (_, one) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(one["auth_token_set"], false);
    assert_eq!(one["headers"], json!({}));

    // Delete: the tools go, the backend is gone.
    let (status, _) = h.send(Method::DELETE, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    h.expect_tools(&pat, "/mcp", &["files_list_files", "files_read_file"])
        .await;
    let (status, _) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = h.send(Method::DELETE, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn backend_writes_are_validated() {
    let Some(h) = Harness::start("axon_dbconfig_validate", Variant::Plain).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;
    let path = Harness::config_path("backends");

    for (what, body) in [
        (
            "an unknown transport",
            json!({ "name": "x", "transport": "carrier-pigeon" }),
        ),
        (
            "an http backend without a url",
            json!({ "name": "x", "transport": "http" }),
        ),
        ("not an object", json!(["x"])),
    ] {
        let (status, body) = h.send(Method::POST, &path, &admin, Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
        assert!(body["error"].is_string(), "{what}: {body}");
    }
    let (status, _) = h
        .send(
            Method::PUT,
            &format!("{path}/nowhere"),
            &admin,
            Some(json!({ "name": "nowhere", "url": h.extra.url(), "transport": "http" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Nothing was stored.
    let (_, list) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(list["backends"].as_array().unwrap().len(), 1, "{list}");
}

#[tokio::test]
async fn a_stdio_backend_needs_axon_allow_stdio() {
    let Some(off) = Harness::start("axon_dbconfig_stdio_off", Variant::Plain).await else {
        return;
    };
    let admin = off.login_as("root", &["admins"]).await;
    let path = Harness::config_path("backends");
    let stdio = json!({
        "name": "local",
        "command": "/nonexistent/axon-test-mcp",
        "transport": "stdio",
    });
    let (status, body) = off
        .send(Method::POST, &path, &admin, Some(stdio.clone()))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("AXON_ALLOW_STDIO"),
        "{body}"
    );
    let (status, _) = off
        .send(Method::GET, &format!("{path}/local"), &admin, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    drop(off);

    // With the switch on, the same backend is accepted (it is just down).
    let Some(on) = Harness::start("axon_dbconfig_stdio_on", Variant::Stdio).await else {
        return;
    };
    let admin = on.login_as("root", &["admins"]).await;
    let (status, body) = on.send(Method::POST, &path, &admin, Some(stdio)).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["transport"], "stdio");
    let (status, _) = on
        .send(Method::GET, &format!("{path}/local"), &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn gateway_toolsets_are_managed_through_the_api_and_served_live() {
    let Some(h) = Harness::start("axon_dbconfig_toolsets", Variant::Plain).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;
    let alice = h.login_as("alice", &["it-claim"]).await;
    let pat = h.pat(&alice).await;
    let path = Harness::config_path("toolsets");
    let item = format!("{path}/readers");

    let (status, created) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({
                "name": "readers",
                "tools": ["files_read_*"],
                "description": "Read only",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["tools"], json!(["files_read_*"]));
    let (status, body) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({ "name": "readers" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // The endpoint of the toolset serves only the matching tools.
    h.expect_tools(&pat, "/mcp/toolset/readers", &["files_read_file"])
        .await;
    h.expect_tools(&pat, "/mcp", &["files_list_files", "files_read_file"])
        .await;

    let (_, one) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(one["description"], "Read only");
    let (_, list) = h.send(Method::GET, &path, &admin, None).await;
    assert!(
        find(&list, "toolsets", "name", "readers").is_some(),
        "{list}"
    );

    // An update takes effect without a restart.
    let (status, updated) = h
        .send(
            Method::PUT,
            &item,
            &admin,
            Some(json!({ "name": "readers", "tools": ["files_list_*"] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["tools"], json!(["files_list_*"]));
    h.expect_tools(&pat, "/mcp/toolset/readers", &["files_list_files"])
        .await;

    let (status, _) = h.send(Method::DELETE, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let gone = poll_until(150, Duration::from_millis(200), || async {
        h.tool_names(&pat, "/mcp/toolset/readers")
            .await
            .map_or(Some(()), |names| (names.is_empty()).then_some(()))
    })
    .await;
    assert!(gone.is_some(), "the deleted toolset still serves tools");
}

#[tokio::test]
async fn the_settings_apply_live() {
    let Some(h) = Harness::start("axon_dbconfig_settings", Variant::Plain).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;
    let alice = h.login_as("alice", &["it-claim"]).await;
    let pat = h.pat(&alice).await;
    let path = Harness::config_path("settings");

    let (status, settings) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{settings}");
    assert_eq!(settings["rate_limit_per_minute"], 0, "{settings}");

    let (status, body) = h
        .send(
            Method::PUT,
            &path,
            &admin,
            Some(json!({ "rate_limit_per_minute": "many" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, saved) = h
        .send(
            Method::PUT,
            &path,
            &admin,
            Some(json!({ "rate_limit_per_minute": 2 })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["rate_limit_per_minute"], 2);
    let (_, settings) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(settings["rate_limit_per_minute"], 2);

    // The per-token limit now applies, without a restart.
    let client = reqwest::Client::new();
    let mcp = h.url("/mcp");
    let limited = poll_until(150, Duration::from_millis(200), || async {
        let (status, _) = mcp_post(&client, &mcp, Some(&pat), &rpc("tools/list")).await;
        (status == StatusCode::TOO_MANY_REQUESTS).then_some(())
    })
    .await;
    assert!(limited.is_some(), "the saved rate limit never applied");
}

#[tokio::test]
async fn permissions_split_viewing_backends_managing_them_and_the_gateway() {
    let Some(h) = Harness::start("axon_dbconfig_permissions", Variant::Plain).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;

    // Two custom roles on two groups, mapped to claims.
    for (role, permission, group, claim) in [
        ("backend-viewer", "backends.view", "viewers", "view-claim"),
        (
            "backend-manager",
            "backends.manage",
            "managers",
            "manage-claim",
        ),
    ] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/admin/roles",
                &admin,
                Some(json!({ "name": role, "permissions": [permission] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        for (path, body) in [
            ("/api/v1/groups", json!({ "name": group })),
            (
                format!("/api/v1/groups/{group}/idp-mappings").as_str(),
                json!({ "provider": "mock", "value": claim }),
            ),
            (
                "/api/v1/role-bindings",
                json!({ "role": role, "group": group }),
            ),
        ] {
            let (status, body) = h.send(Method::POST, path, &admin, Some(body)).await;
            assert_eq!(status, StatusCode::CREATED, "{path}: {body}");
        }
    }
    let viewer = h.login_as("viewer", &["view-claim"]).await;
    let manager = h.login_as("manager", &["manage-claim"]).await;
    let nobody = h.login_as("nobody", &[]).await;

    let backends = Harness::config_path("backends");
    let toolsets = Harness::config_path("toolsets");
    let providers = Harness::config_path("oidc-providers");
    let settings = Harness::config_path("settings");
    let files_body = json!({ "name": "files", "url": h.extra.url(), "transport": "http" });
    let provider = json!({
        "id": "second",
        "issuer": h.idp.issuer(),
        "client_id": "axon-test",
    });

    // Without a permission nothing is readable.
    for path in [&backends, &toolsets, &providers, &settings] {
        let (status, _) = h.send(Method::GET, path, &nobody, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "nobody reads {path}");
    }

    // backends.view reads backends and toolsets, writes nothing, and has no
    // business with providers or settings.
    for path in [&backends, &toolsets] {
        let (status, body) = h.send(Method::GET, path, &viewer, None).await;
        assert_eq!(status, StatusCode::OK, "viewer reads {path}: {body}");
    }
    for (method, path, body) in [
        (Method::POST, &backends, Some(h.extra_body())),
        (Method::PUT, &format!("{backends}/files"), Some(files_body)),
        (Method::DELETE, &format!("{backends}/files"), None),
        (Method::POST, &toolsets, Some(json!({ "name": "t" }))),
        (Method::GET, &providers, None),
        (Method::POST, &providers, Some(provider.clone())),
        (Method::GET, &settings, None),
        (Method::PUT, &settings, Some(json!({}))),
    ] {
        let (status, body) = h.send(method.clone(), path, &viewer, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "viewer {method} {path}: {body}"
        );
    }

    // backends.manage writes backends and toolsets, but not the gateway's
    // providers and settings.
    let (status, body) = h
        .send(Method::POST, &backends, &manager, Some(h.extra_body()))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h
        .send(
            Method::POST,
            &toolsets,
            &manager,
            Some(json!({ "name": "t", "tools": ["extra_*"] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    for (method, path, body) in [
        (Method::GET, &providers, None),
        (Method::POST, &providers, Some(provider.clone())),
        (Method::GET, &settings, None),
        (
            Method::PUT,
            &settings,
            Some(json!({ "rate_limit_per_minute": 1 })),
        ),
    ] {
        let (status, body) = h.send(method.clone(), path, &manager, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "manager {method} {path}: {body}"
        );
    }
    let (status, _) = h
        .send(Method::DELETE, &format!("{backends}/extra"), &manager, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The admin holds everything.
    let (status, body) = h
        .send(Method::POST, &providers, &admin, Some(provider))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, _) = h.send(Method::GET, &settings, &admin, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn oidc_providers_are_managed_and_the_environment_one_is_read_only() {
    let Some(h) = Harness::start("axon_dbconfig_providers", Variant::EnvProvider).await else {
        return;
    };
    let admin = h.login_as("root", &["admins"]).await;
    let path = Harness::config_path("oidc-providers");

    // The provider of the environment is listed, first, with its source.
    let (status, list) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["providers"][0]["id"], "envsso", "{list}");
    assert_eq!(list["providers"][0]["source"], "env", "{list}");

    // It cannot be written.
    let env_item = format!("{path}/envsso");
    let (status, body) = h
        .send(
            Method::PUT,
            &env_item,
            &admin,
            Some(json!({ "id": "envsso", "issuer": h.idp.issuer(), "client_id": "other" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = h.send(Method::DELETE, &env_item, &admin, None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, one) = h.send(Method::GET, &env_item, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["client_id"], "axon-test");

    // A provider of the database: the answer never holds the secret.
    let (status, created) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({
                "id": "second",
                "display_name": "Second",
                "issuer": h.idp.issuer(),
                "client_id": "axon-test",
                "client_secret": "provider-secret-one",
                "admin_groups": ["ops"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["source"], "database");
    assert_eq!(created["client_secret_set"], true);
    assert!(created.get("client_secret").is_none(), "{created}");
    assert!(!created.to_string().contains("provider-secret-one"));
    let (status, body) = h
        .send(
            Method::POST,
            &path,
            &admin,
            Some(json!({ "id": "second", "issuer": h.idp.issuer(), "client_id": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (_, list) = h.send(Method::GET, &path, &admin, None).await;
    assert_eq!(list["providers"][0]["id"], "envsso", "{list}");
    assert_eq!(
        find(&list, "providers", "id", "second").unwrap()["source"],
        "database"
    );
    assert!(!list.to_string().contains("provider-secret-one"));

    // Absent secret: kept. Empty: cleared.
    let item = format!("{path}/second");
    let (status, kept) = h
        .send(
            Method::PUT,
            &item,
            &admin,
            Some(json!({
                "id": "second",
                "display_name": "Second SSO",
                "issuer": h.idp.issuer(),
                "client_id": "axon-test",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{kept}");
    assert_eq!(kept["display_name"], "Second SSO");
    assert_eq!(kept["client_secret_set"], true);
    let (status, cleared) = h
        .send(
            Method::PUT,
            &item,
            &admin,
            Some(json!({
                "id": "second",
                "issuer": h.idp.issuer(),
                "client_id": "axon-test",
                "client_secret": "",
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["client_secret_set"], false);

    let (status, _) = h.send(Method::DELETE, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.send(Method::GET, &item, &admin, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
