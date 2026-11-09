//! Dashboard login end to end: the real gateway binary, a real Postgres schema
//! and the mock identity provider.
//!
//! Cookies are handled by hand (read `Set-Cookie`, send `Cookie`) with a client
//! that does not follow redirects, so every hop is asserted. The session
//! cookies are `Secure`, which is fine because nothing here is a browser.
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set.

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
use serde_json::json;
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

/// The CSRF token a dashboard page carries for htmx.
fn csrf_token(page: &str) -> String {
    let marker = "name=\"csrf-token\" content=\"";
    let start = page.find(marker).expect("a csrf-token meta tag") + marker.len();
    let len = page[start..].find('"').expect("a closed attribute");
    page[start..start + len].to_string()
}

#[tokio::test]
async fn login_opens_a_session_for_the_dashboard() {
    let Some(h) = Harness::start("axon_oidc_login", "").await else {
        return;
    };

    // Without a session a page redirects to the login, htmx is told to go
    // there, and everything else is a plain 401.
    let resp = h.get(&h.url("/ui"), &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/auth/login?return_to=%2Fui");

    let resp = h
        .get(&h.url("/ui/partials/backends"), &[])
        .header("hx-request", "true")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()["hx-redirect"], "/auth/login");

    let resp = h
        .post(&h.url("/ui/actions/reload"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The whole login, hop by hop.
    let (login_cookie, callback) = h.begin_login().await;
    let resp = h.get(&callback, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/ui");
    let attributes = set_cookie(&resp, SESSION_COOKIE).expect("a session cookie");
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(attributes.contains(attribute), "{attributes}");
    }
    let expired = set_cookie(&resp, LOGIN_COOKIE).expect("the login cookie is cleared");
    assert!(expired.contains("Max-Age=0"), "{expired}");
    let session = cookie_pair(&resp, SESSION_COOKIE).unwrap();

    let resp = h.get(&h.url("/ui"), &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let page = resp.text().await.unwrap();
    assert!(page.contains("Alice"), "the page names the user");
}

#[tokio::test]
async fn actions_need_the_csrf_token() {
    let Some(h) = Harness::start("axon_oidc_csrf", "").await else {
        return;
    };
    let session = h.login().await;
    let page = h
        .get(&h.url("/ui"), &[&session])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = csrf_token(&page);
    assert!(
        page.contains("hx-headers") && page.contains(&token),
        "htmx sends the token on every request"
    );

    let reload = h.url("/ui/actions/reload");
    let resp = h.post(&reload, &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "no token");

    let resp = h
        .post(&reload, &[&session])
        .header("x-csrf-token", "not-the-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "wrong token");

    let resp = h
        .post(&reload, &[&session])
        .header("x-csrf-token", &token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status() != StatusCode::UNAUTHORIZED && resp.status() != StatusCode::FORBIDDEN,
        "the right token gets through: {}",
        resp.status()
    );
}

#[tokio::test]
async fn callback_needs_the_browsers_state_and_works_once() {
    let Some(h) = Harness::start("axon_oidc_callback", "").await else {
        return;
    };
    let (login_cookie, callback) = h.begin_login().await;

    // Another browser's (or no) login cookie: refused, and the flow survives.
    let resp = h
        .get(&callback, &[&format!("{LOGIN_COOKIE}=something-else")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = h.get(&callback, &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = h.get(&callback, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(cookie_pair(&resp, SESSION_COOKIE).is_some());

    // Replaying it: the flow is spent.
    let resp = h.get(&callback, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());

    // An error from the provider is a refusal, not a session.
    let error = h.url("/auth/callback?error=access_denied");
    let resp = h.get(&error, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_ends_the_session_and_signs_out_at_the_provider() {
    let Some(h) = Harness::start("axon_oidc_logout", "").await else {
        return;
    };
    let session = h.login().await;
    let page = h
        .get(&h.url("/ui"), &[&session])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let token = csrf_token(&page);

    // No token, no logout: a cross-site form must not be able to end it.
    let logout = h.url("/auth/logout");
    let resp = h.post(&logout, &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = h.get(&h.url("/ui"), &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "still logged in");

    // A plain form post carries the token as a field.
    let resp = h
        .post(&logout, &[&session])
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("csrf_token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cleared = set_cookie(&resp, SESSION_COOKIE).expect("the session cookie is cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    let sign_out = location(&resp);
    assert!(
        sign_out.starts_with(&format!("{}/logout?", h.idp.issuer())),
        "{sign_out}"
    );
    assert!(sign_out.contains("id_token_hint="), "{sign_out}");

    // Following it is what the browser does; the provider saw the hint.
    h.get(&sign_out, &[]).send().await.unwrap();
    let logout_query = h.idp.last_logout().expect("the provider was signed out");
    assert!(logout_query.contains_key("id_token_hint"));
    assert_eq!(
        logout_query
            .get("post_logout_redirect_uri")
            .map(String::as_str),
        Some(format!("{}/", h.gateway.base).as_str())
    );

    // The old cookie is dead server side.
    let resp = h.get(&h.url("/ui"), &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/auth/login?return_to="));
}

#[tokio::test]
async fn logout_without_a_session_goes_home() {
    let Some(h) = Harness::start("axon_oidc_logout_anon", "").await else {
        return;
    };
    let resp = h.post(&h.url("/auth/logout"), &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/");
}

#[tokio::test]
async fn a_disallowed_email_domain_is_refused() {
    let Some(h) = Harness::start(
        "axon_oidc_domain",
        "allowed_email_domains = [\"corp.example\"]",
    )
    .await
    else {
        return;
    };
    h.idp.set_user(json!({
        "sub": "alice",
        "email": "alice@example.com",
        "name": "Alice",
        "groups": ["staff"],
    }));

    let (login_cookie, callback) = h.begin_login().await;
    let resp = h.get(&callback, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(cookie_pair(&resp, SESSION_COOKIE).is_none());
    let page = resp.text().await.unwrap();
    assert!(page.contains("not allowed to use this gateway"), "{page}");

    // The right domain on an address nobody verified is refused too.
    h.idp.set_user(json!({
        "sub": "mallory",
        "email": "mallory@corp.example",
        "name": "Mallory",
        "groups": [],
    }));
    let (login_cookie, callback) = h.begin_login().await;
    let resp = h.get(&callback, &[&login_cookie]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // A verified address at an allowed domain gets in.
    h.idp.set_user(json!({
        "sub": "bob",
        "email": "bob@corp.example",
        "email_verified": true,
        "name": "Bob",
        "groups": [],
    }));
    let session = h.login().await;
    let resp = h.get(&h.url("/ui"), &[&session]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn without_oidc_the_dashboard_stays_open() {
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind).render();
    let gateway = Gateway::start(&config, &format!("http://{bind}")).await;
    let client = no_redirect_client();

    let resp = client
        .get(format!("{}/ui", gateway.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(SET_COOKIE).is_none());

    for path in ["/auth/login", "/auth/login/mock", "/auth/callback"] {
        let resp = client
            .get(format!("{}{path}", gateway.base))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let resp = client
        .post(format!("{}/ui/actions/reload", gateway.base))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}
