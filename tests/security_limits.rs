//! Rate limits on the login routes and the rotation of a session on re-login:
//! the real gateway binary, a real Postgres schema and the mock identity
//! provider. The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{RequestBuilder, Response, StatusCode};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// A gateway with OIDC login against a mock provider, in its own schema.
struct Harness {
    gateway: Gateway,
    idp: MockOidc,
    client: reqwest::Client,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str, provider_extra: &str) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        let bind = format!("127.0.0.1:{}", free_port());
        let config = ConfigBuilder::new(&bind)
            .database(DATABASE_ENV)
            .oidc_provider("mock", idp.issuer(), "axon-test", provider_extra)
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;

        Some(Self {
            gateway,
            idp,
            client: no_redirect_client(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

    /// Resolve a `Location` that may be relative to the gateway.
    fn resolve(&self, location: &str) -> String {
        if location.starts_with('/') {
            self.url(location)
        } else {
            location.to_string()
        }
    }

    fn get(&self, url: &str, cookies: &[&str]) -> RequestBuilder {
        with_cookies(self.client.get(url), cookies)
    }

    fn post(&self, url: &str, cookies: &[&str]) -> RequestBuilder {
        with_cookies(self.client.post(url), cookies)
    }

    /// `/auth/login` through the provider's authorization endpoint, up to the
    /// gateway's callback URL. Returns the login cookie and that URL.
    async fn begin_login(&self) -> (String, String) {
        let resp = self
            .get(&self.url("/auth/login"), &[])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let next = location(&resp);
        assert!(
            next.starts_with("/auth/login/mock?return_to="),
            "a single provider skips the picker: {next}"
        );

        let resp = self.get(&self.resolve(&next), &[]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let login_cookie = cookie_pair(&resp, LOGIN_COOKIE).expect("a login cookie");
        let provider_url = location(&resp);
        assert!(
            provider_url.starts_with(self.idp.issuer()),
            "redirects to the provider: {provider_url}"
        );
        let attributes = set_cookie(&resp, LOGIN_COOKIE).expect("a login cookie");
        for attribute in [
            "Secure",
            "HttpOnly",
            "SameSite=Lax",
            "Path=/",
            "Max-Age=600",
        ] {
            assert!(attributes.contains(attribute), "{attributes}");
        }

        // The mock approves on the spot and sends the browser back.
        let resp = self.get(&provider_url, &[]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let callback = location(&resp);
        assert!(callback.contains("/auth/callback?code="), "{callback}");
        (login_cookie, callback)
    }

    /// A complete login. Returns the `name=value` session cookie.
    async fn login(&self) -> String {
        let (login_cookie, callback) = self.begin_login().await;
        let resp = self.get(&callback, &[&login_cookie]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie")
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

fn with_cookies(request: RequestBuilder, cookies: &[&str]) -> RequestBuilder {
    if cookies.is_empty() {
        request
    } else {
        request.header(COOKIE, cookies.join("; "))
    }
}

fn location(resp: &Response) -> String {
    resp.headers()
        .get(LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_string()
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

/// `name=value` of the cookie `name`, ready for a `Cookie` header.
fn cookie_pair(resp: &Response, name: &str) -> Option<String> {
    set_cookie(resp, name).and_then(|header| header.split(';').next().map(str::to_string))
}

#[tokio::test]
async fn starting_logins_is_limited_per_client() {
    let Some(h) = Harness::start("axon_limits_login", "").await else {
        return;
    };

    for attempt in 1..=20 {
        let resp = h.get(&h.url("/auth/login/mock"), &[]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "attempt {attempt}");
    }
    let resp = h.get(&h.url("/auth/login/mock"), &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers()["retry-after"], "60");
}

#[tokio::test]
async fn callbacks_are_limited_per_client() {
    let Some(h) = Harness::start("axon_limits_callback", "").await else {
        return;
    };

    for attempt in 1..=20 {
        let resp = h.get(&h.url("/auth/callback"), &[]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "attempt {attempt}");
    }
    let resp = h.get(&h.url("/auth/callback"), &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn break_glass_is_limited_per_client() {
    let Some(h) = Harness::start("axon_limits_break_glass", "").await else {
        return;
    };

    for attempt in 1..=10 {
        let resp = h
            .get(&h.url("/auth/break-glass?code=nope"), &[])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}");
    }
    let resp = h
        .get(&h.url("/auth/break-glass?code=nope"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let resp = h
        .post(&h.url("/auth/break-glass"), &[])
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("code=nope")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_second_login_ends_the_first_session() {
    let Some(h) = Harness::start("axon_limits_rotation", "").await else {
        return;
    };

    let old = h.login().await;
    let resp = h.get(&h.url("/ui"), &[&old]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The browser still holds the old session when it logs in again
    let (login_cookie, callback) = h.begin_login().await;
    let resp = h
        .get(&callback, &[&login_cookie, &old])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let new = cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie");
    assert_ne!(new, old);

    let resp = h.get(&h.url("/ui"), &[&old]).send().await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "the old session is gone"
    );
    let resp = h.get(&h.url("/ui"), &[&new]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
