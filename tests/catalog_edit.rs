//! The edit form of the catalog admin (`POST /ui/actions/catalog/{name}/update`)
//! end to end: the real gateway binary, a real Postgres schema and the mock
//! identity provider. The form always sends the credential field rows and the
//! OAuth inputs; the gateway applies the half that matches its Sign-in choice.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode, Url};
use serde_json::{Value, json};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const FORM: &str = "application/x-www-form-urlencoded";

/// Allows the loopback address the entries point at.
const ALLOW_LOOPBACK: &str = "egress_allow = [\"127.0.0.1/32\"]";

/// Nothing connects to the entries of these tests.
const ENTRY_URL: &str = "http://127.0.0.1:1/mcp";

/// A user that logged in: the session cookie and the CSRF token of the session.
struct Session {
    cookie: String,
    csrf: String,
}

/// A multi-user gateway in its own schema. Users whose groups claim holds
/// `admins` are admins.
struct Harness {
    gateway: Gateway,
    client: reqwest::Client,
    idp: MockOidc,
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
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .database(DATABASE_ENV)
            .personal_backends(ALLOW_LOOPBACK)
            .oidc_provider(
                "mock",
                idp.issuer(),
                "axon-test",
                "admin_groups = [\"admins\"]",
            )
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

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

    /// A complete login as the admin the mock provider is set to.
    async fn login_admin(&self) -> Session {
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

    /// Adds an entry through the JSON API and asserts it worked.
    async fn create_entry(&self, session: &Session, body: Value) {
        let (status, body) = self
            .send(Method::POST, "/api/v1/catalog", session, Some(body))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// Posts the edit form of entry `name` with `fields`, in order.
    async fn edit(&self, session: &Session, name: &str, fields: &[(&str, &str)]) -> Response {
        self.client
            .post(self.url(&format!("/ui/actions/catalog/{name}/update")))
            .header(COOKIE, &session.cookie)
            .header("x-csrf-token", &session.csrf)
            .header(CONTENT_TYPE, FORM)
            .body(form(fields))
            .send()
            .await
            .unwrap()
    }

    /// The entry `name` as the admin sees it in `GET /api/v1/catalog`.
    async fn entry(&self, session: &Session, name: &str) -> Value {
        let (status, body) = self
            .send(Method::GET, "/api/v1/catalog", session, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["catalog"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap_or_else(|| panic!("no entry {name} in {body}"))
            .clone()
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

/// The names of the credential fields of an entry, in order.
fn field_names(entry: &Value) -> Vec<&str> {
    entry["credential_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn switching_an_oauth_entry_to_fields_takes_the_field_rows() {
    let Some(h) = Harness::start("catalog_edit_to_fields").await else {
        return;
    };
    let admin = h.login_admin().await;
    h.create_entry(
        &admin,
        json!({
            "name": "wiki",
            "url": ENTRY_URL,
            "auth": "oauth",
            "oauth_client_id": "axon",
            "oauth_scopes": ["read"],
        }),
    )
    .await;
    assert_eq!(h.entry(&admin, "wiki").await["auth"], "oauth");

    // What the edit form sends: the OAuth inputs prefilled with the stored
    // settings, and the field rows (one filled, two empty).
    let resp = h
        .edit(
            &admin,
            "wiki",
            &[
                ("description", ""),
                ("url", ENTRY_URL),
                ("enabled", "true"),
                ("field_name", "token"),
                ("field_label", "API token"),
                ("field_header", "Authorization"),
                ("field_prefix", "Bearer "),
                ("field_name", ""),
                ("field_label", ""),
                ("field_header", ""),
                ("field_prefix", ""),
                ("field_name", ""),
                ("field_label", ""),
                ("field_header", ""),
                ("field_prefix", ""),
                ("auth", "fields"),
                ("oauth_client_id", "axon"),
                ("oauth_scopes", "read"),
                ("oauth_client_secret", ""),
            ],
        )
        .await;
    let status = resp.status();
    let page = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{page}");

    let entry = h.entry(&admin, "wiki").await;
    assert_eq!(entry["auth"], "fields", "{entry}");
    assert_eq!(field_names(&entry), ["token"], "{entry}");
    assert_eq!(entry["credential_fields"][0]["label"], "API token");
    assert_eq!(entry["credential_fields"][0]["header"], "Authorization");
    assert_eq!(entry["credential_fields"][0]["prefix"], "Bearer ");
}

#[tokio::test]
async fn editing_a_fields_entry_changes_its_credential_fields() {
    let Some(h) = Harness::start("catalog_edit_fields").await else {
        return;
    };
    let admin = h.login_admin().await;
    h.create_entry(
        &admin,
        json!({
            "name": "wiki",
            "url": ENTRY_URL,
            "credential_fields": [{
                "name": "token",
                "label": "API token",
                "header": "Authorization",
                "prefix": "Bearer ",
            }],
        }),
    )
    .await;

    // The form prefilled with the stored field, plus a second one typed in.
    let resp = h
        .edit(
            &admin,
            "wiki",
            &[
                ("description", "changed"),
                ("url", ENTRY_URL),
                ("enabled", "true"),
                ("field_name", "token"),
                ("field_label", "API token"),
                ("field_header", "Authorization"),
                ("field_prefix", "Bearer "),
                ("field_name", "org"),
                ("field_label", "Organisation"),
                ("field_header", "X-Org"),
                ("field_prefix", ""),
                ("field_name", ""),
                ("field_label", ""),
                ("field_header", ""),
                ("field_prefix", ""),
                ("auth", "fields"),
                ("oauth_client_id", ""),
                ("oauth_scopes", ""),
                ("oauth_client_secret", ""),
            ],
        )
        .await;
    let status = resp.status();
    let page = resp.text().await.unwrap();
    assert_eq!(status, StatusCode::OK, "{page}");

    let entry = h.entry(&admin, "wiki").await;
    assert_eq!(entry["auth"], "fields", "{entry}");
    assert_eq!(entry["description"], "changed");
    assert_eq!(field_names(&entry), ["token", "org"], "{entry}");
    assert_eq!(entry["credential_fields"][1]["header"], "X-Org");

    // The edit form of the page shows the stored fields prefilled.
    assert!(page.contains("value=\"Organisation\""), "{page}");
    assert!(page.contains("value=\"X-Org\""), "{page}");

    // Dropping a row removes the field.
    let resp = h
        .edit(
            &admin,
            "wiki",
            &[
                ("url", ENTRY_URL),
                ("field_name", "org"),
                ("field_label", "Organisation"),
                ("field_header", "X-Org"),
                ("field_prefix", ""),
                ("field_name", ""),
                ("field_label", ""),
                ("field_header", ""),
                ("field_prefix", ""),
                ("auth", "fields"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(field_names(&h.entry(&admin, "wiki").await), ["org"]);
}

#[tokio::test]
async fn an_oauth_entry_keeps_taking_its_oauth_inputs() {
    let Some(h) = Harness::start("catalog_edit_oauth").await else {
        return;
    };
    let admin = h.login_admin().await;
    h.create_entry(
        &admin,
        json!({ "name": "wiki", "url": ENTRY_URL, "auth": "oauth" }),
    )
    .await;

    // The empty field rows of the form are ignored for OAuth.
    let resp = h
        .edit(
            &admin,
            "wiki",
            &[
                ("url", ENTRY_URL),
                ("field_name", ""),
                ("field_label", ""),
                ("field_header", ""),
                ("field_prefix", ""),
                ("auth", "oauth"),
                ("oauth_client_id", "axon"),
                ("oauth_scopes", "read write"),
            ],
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let entry = h.entry(&admin, "wiki").await;
    assert_eq!(entry["auth"], "oauth", "{entry}");
    assert!(field_names(&entry).is_empty(), "{entry}");
}
