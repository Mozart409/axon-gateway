//! Entra groups overage end to end: the real gateway binary, a real Postgres
//! schema and the mock identity provider, which also plays Microsoft Graph. A
//! login whose ID token reports an overage (no `groups` claim, an
//! `_claim_names` entry instead) gets its groups from Graph when the provider
//! has `graph_overage = true`, with the app's own client credentials.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Response, StatusCode};
use serde_json::{Value, json};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const SECRET_ENV: &str = "AXON_TEST_GRAPH_IDP_SECRET";
const GROUPS: [&str; 3] = ["grp-1", "grp-2", "grp-3"];

/// A gateway with OIDC login against a mock provider (which is also its
/// Graph), in its own schema. Users whose groups claim holds `admins` are
/// admins, so one can list the users and see their groups.
struct Harness {
    gateway: Gateway,
    idp: MockOidc,
    client: reqwest::Client,
}

impl Harness {
    /// `None` (after saying why) without `AXON_TEST_DATABASE_URL`.
    async fn start(schema: &str, graph_overage: bool) -> Option<Self> {
        let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
            eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
            return None;
        };
        let url = isolated_url(&base, schema).await;

        let idp = MockOidc::start("axon-test").await;
        idp.set_graph(&GROUPS);
        let bind = format!("127.0.0.1:{}", free_port());
        let extra = format!(
            "client_secret_env = \"{SECRET_ENV}\"\nadmin_groups = [\"admins\"]\ngraph_overage = {graph_overage}\ngraph_url = \"{}\"\n",
            idp.issuer()
        );
        let config = ConfigBuilder::new(&bind)
            .database(DATABASE_ENV)
            .oidc_provider("mock", idp.issuer(), "axon-test", &extra)
            .render();
        let gateway = Gateway::start_with_env(
            &config,
            &format!("http://{bind}"),
            &[(DATABASE_ENV, &url), (SECRET_ENV, "idp-client-secret")],
        )
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

    /// The login up to the gateway's callback, as the user the mock provider
    /// is set to; returns the callback's answer.
    async fn login_callback(&self) -> Response {
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

        self.client
            .get(callback)
            .header(COOKIE, login_cookie)
            .send()
            .await
            .unwrap()
    }

    /// A complete login as the user the mock provider is set to; returns the
    /// session cookie.
    async fn login(&self) -> String {
        let resp = self.login_callback().await;
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie")
    }

    /// An admin logged in through a groups claim, no overage involved.
    async fn admin(&self) -> String {
        self.idp.set_user(json!({
            "sub": "root",
            "email": "root@example.com",
            "name": "root",
            "groups": ["admins"],
        }));
        self.login().await
    }

    /// The groups of the user with this email, as the admin API lists them.
    async fn groups_of(&self, admin: &str, email: &str) -> Vec<String> {
        let resp = self
            .client
            .get(self.url("/api/v1/users"))
            .header(COOKIE, admin)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = resp.json().await.unwrap();
        let mut groups: Vec<String> = body["users"]
            .as_array()
            .expect("a users array")
            .iter()
            .find(|user| user["email"] == email)
            .unwrap_or_else(|| panic!("no user {email} in {body}"))["groups"]
            .as_array()
            .expect("a groups array")
            .iter()
            .map(|group| group.as_str().unwrap().to_string())
            .collect();
        groups.sort();
        groups
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

#[tokio::test]
async fn an_overage_login_gets_its_groups_from_graph() {
    let Some(h) = Harness::start("axon_graph_overage", true).await else {
        return;
    };
    let admin = h.admin().await;

    h.idp.set_overage("carol", "carol@example.com", "oid-carol");
    h.login().await;
    assert_eq!(h.groups_of(&admin, "carol@example.com").await, GROUPS);

    // Two pages, each with the app token in the bearer header.
    let requests = h.idp.graph_requests();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[0].starts_with("/v1.0/users/oid-carol/transitiveMemberOf/microsoft.graph.group?"),
        "{requests:?}"
    );
    assert!(requests[1].contains("page=1"), "{requests:?}");

    // The app token is asked for once, with the client credentials in the form.
    let grants = h.idp.token_forms_for("client_credentials");
    assert_eq!(grants.len(), 1, "{grants:?}");
    assert_eq!(grants[0]["client_id"], "axon-test");
    assert_eq!(grants[0]["client_secret"], "idp-client-secret");
    assert_eq!(grants[0]["scope"], format!("{}/.default", h.idp.issuer()));

    // A second login reuses it.
    h.idp.set_overage("dave", "dave@example.com", "oid-dave");
    h.login().await;
    assert_eq!(h.groups_of(&admin, "dave@example.com").await, GROUPS);
    assert_eq!(h.idp.graph_requests().len(), 4);
    assert_eq!(h.idp.token_forms_for("client_credentials").len(), 1);
}

#[tokio::test]
async fn a_graph_failure_still_logs_the_user_in() {
    let Some(h) = Harness::start("axon_graph_failure", true).await else {
        return;
    };
    let admin = h.admin().await;

    h.idp.set_graph_failing(true);
    h.idp.set_overage("erin", "erin@example.com", "oid-erin");
    h.login().await;
    assert_eq!(
        h.groups_of(&admin, "erin@example.com").await,
        [] as [std::string::String; 0]
    );
    assert_eq!(h.idp.graph_requests().len(), 1);

    // Graph back: the next login has the groups again.
    h.idp.set_graph_failing(false);
    h.login().await;
    assert_eq!(h.groups_of(&admin, "erin@example.com").await, GROUPS);
}

#[tokio::test]
async fn without_graph_overage_graph_is_not_called() {
    let Some(h) = Harness::start("axon_graph_off", false).await else {
        return;
    };
    let admin = h.admin().await;

    h.idp.set_overage("frank", "frank@example.com", "oid-frank");
    h.login().await;
    assert_eq!(
        h.groups_of(&admin, "frank@example.com").await,
        [] as [std::string::String; 0]
    );
    assert_eq!(h.idp.graph_requests(), [] as [std::string::String; 0]);
    assert_eq!(
        h.idp.token_forms_for("client_credentials"),
        [] as [std::collections::HashMap<std::string::String, std::string::String>; 0]
    );
}
