//! SCIM 2.0 provisioning end to end: the real gateway binary, a real Postgres
//! schema and the mock identity provider. An admin creates the provider's
//! SCIM token, the "identity provider" (this test) pushes users and groups
//! with it, and the users' logins, sessions and tokens follow.
//!
//! The tests skip themselves unless `AXON_TEST_DATABASE_URL` is set (see
//! `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_backend::MockBackend;
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, rpc};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

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
        let backend = MockBackend::start(&["read_file"]).await;
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
        let is_get = method == Method::GET;
        let request = self
            .client
            .request(method, self.url(path))
            .header(COOKIE, &session.cookie);
        if is_get {
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

    /// A SCIM request under `/scim/v2/mock` with `token` (none: no header);
    /// returns the whole response.
    async fn scim_raw(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Response {
        let mut request = self
            .client
            .request(method, self.url(&format!("/scim/v2/mock{path}")));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request
                .header(CONTENT_TYPE, "application/scim+json")
                .body(body.to_string());
        }
        request.send().await.unwrap()
    }

    /// Like [`Harness::scim_raw`]; returns status and JSON body.
    async fn scim(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let resp = self.scim_raw(method, path, Some(token), body).await;
        let status = resp.status();
        let text = resp.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    /// The login up to the gateway's callback, as the user the mock provider
    /// is set to; returns the callback's answer.
    async fn login_callback(&self, subject: &str, email: &str, groups: &[&str]) -> Response {
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

        self.client
            .get(callback)
            .header(COOKIE, login_cookie)
            .send()
            .await
            .unwrap()
    }

    /// A complete login as the user the mock provider is set to.
    async fn login_as(&self, subject: &str, email: &str, groups: &[&str]) -> Session {
        let resp = self.login_callback(subject, email, groups).await;
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

    /// The status of `tools/list` with this bearer token.
    async fn mcp_status(&self, bearer: &str) -> StatusCode {
        mcp_post(
            &self.client,
            &self.url("/mcp"),
            Some(bearer),
            &rpc("tools/list"),
        )
        .await
        .0
    }

    /// Creates or rotates the SCIM token of the `mock` provider.
    async fn scim_token(&self, admin: &Session) -> String {
        let (status, body) = self
            .send(Method::POST, "/api/v1/admin/scim/mock/token", admin, None)
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let token = body["token"].as_str().expect("a token").to_string();
        assert!(token.starts_with("axon_scim_"), "{token}");
        assert!(
            body["base_url"]
                .as_str()
                .unwrap()
                .ends_with("/scim/v2/mock"),
            "{body}"
        );
        token
    }

    /// The id of the user with this email, as the admin API lists it.
    async fn user_id(&self, admin: &Session, email: &str) -> String {
        let (status, body) = self.send(Method::GET, "/api/v1/users", admin, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["users"]
            .as_array()
            .expect("a users array")
            .iter()
            .find(|user| user["email"] == email)
            .unwrap_or_else(|| panic!("no user {email} in {body}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// The effective groups of a logged-in user.
    async fn groups_of(&self, session: &Session) -> Vec<String> {
        let (status, me) = self.send(Method::GET, "/api/v1/me", session, None).await;
        assert_eq!(status, StatusCode::OK, "{me}");
        me["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .map(|group| group.as_str().unwrap().to_string())
            .collect()
    }

    /// A SCIM user; returns its id.
    async fn scim_user(&self, token: &str, user: Value) -> String {
        let (status, body) = self.scim(Method::POST, "/Users", token, Some(user)).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        body["id"].as_str().expect("an id").to_string()
    }

    /// A SCIM `active` patch the way Entra ID sends it; returns the answer.
    async fn scim_active(&self, token: &str, id: &str, value: &str) -> (StatusCode, Value) {
        self.scim(
            Method::PATCH,
            &format!("/Users/{id}"),
            token,
            Some(json!({
                "schemas": [PATCH_OP],
                "Operations": [{ "op": "Replace", "path": "active", "value": value }],
            })),
        )
        .await
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

#[tokio::test]
async fn an_admin_creates_a_token_and_the_discovery_endpoints_answer() {
    let Some(h) = Harness::start("axon_scim_discovery").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // No token yet: the overview says so and the endpoint refuses.
    let (status, overview) = h
        .send(Method::GET, "/api/v1/admin/scim", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    let provider = &overview["providers"][0];
    assert_eq!(provider["provider"], "mock");
    assert_eq!(provider["has_token"], false);
    assert_eq!(provider["users"], 0);
    let resp = h
        .scim_raw(Method::GET, "/ServiceProviderConfig", None, None)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let token = h.scim_token(&admin).await;

    let resp = h
        .scim_raw(Method::GET, "/ServiceProviderConfig", Some(&token), None)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE).unwrap(),
        "application/scim+json"
    );
    let config: Value = resp.json().await.unwrap();
    assert_eq!(config["patch"]["supported"], true);
    assert_eq!(config["filter"]["supported"], true);
    assert_eq!(config["filter"]["maxResults"], 200);
    assert_eq!(config["bulk"]["supported"], false);
    assert_eq!(
        config["authenticationSchemes"][0]["type"],
        "oauthbearertoken"
    );

    let (status, types) = h.scim(Method::GET, "/ResourceTypes", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{types}");
    assert_eq!(types["totalResults"], 2);
    let (status, schemas) = h.scim(Method::GET, "/Schemas", &token, None).await;
    assert_eq!(status, StatusCode::OK, "{schemas}");
    assert_eq!(schemas["Resources"].as_array().unwrap().len(), 2);

    // An unknown provider has no SCIM endpoint at all.
    let resp = h
        .client
        .get(h.url("/scim/v2/nope/Users"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let (_, overview) = h
        .send(Method::GET, "/api/v1/admin/scim", &admin, None)
        .await;
    assert_eq!(overview["providers"][0]["has_token"], true);
    assert!(overview["providers"][0]["created_at"].is_string());

    // A user without users.manage cannot manage the token.
    let bob = h.login_as("bob", "bob@example.com", &[]).await;
    let (status, _) = h
        .send(Method::POST, "/api/v1/admin/scim/mock/token", &bob, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Deleting the token ends the access; a second delete finds nothing.
    let (status, _) = h
        .send(
            Method::DELETE,
            "/api/v1/admin/scim/mock/token",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = h.scim(Method::GET, "/Users", &token, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .send(
            Method::DELETE,
            "/api/v1/admin/scim/mock/token",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_wrong_token_is_a_401_and_a_rotated_token_replaces_the_old_one() {
    let Some(h) = Harness::start("axon_scim_tokens").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let first = h.scim_token(&admin).await;

    let resp = h
        .scim_raw(Method::GET, "/Users", Some("axon_scim_wrong"), None)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(CONTENT_TYPE).unwrap(),
        "application/scim+json"
    );
    let error: Value = resp.json().await.unwrap();
    assert_eq!(
        error["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:Error"])
    );
    assert_eq!(error["status"], "401");
    let (status, _) = h.scim(Method::GET, "/Users", "", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = h.scim(Method::GET, "/Users", &first, None).await;
    assert_eq!(status, StatusCode::OK);

    let second = h.scim_token(&admin).await;
    assert_ne!(first, second);
    let (status, _) = h.scim(Method::GET, "/Users", &first, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old token is gone");
    let (status, _) = h.scim(Method::GET, "/Users", &second, None).await;
    assert_eq!(status, StatusCode::OK);

    // The audit log names both creations.
    let actions = audit_actions(&h, &admin).await;
    assert_eq!(
        actions
            .iter()
            .filter(|(action, _)| action == "scim.token.create")
            .count(),
        2,
        "{actions:?}"
    );
}

#[tokio::test]
async fn users_and_groups_pushed_before_the_login_give_the_user_their_groups() {
    let Some(h) = Harness::start("axon_scim_groups").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;

    // Two gateway groups mapped to values SCIM will provide: a displayName
    // and an externalId.
    for (name, value) in [("devs", "Developers"), ("ops", "grp-ops-1")] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/groups",
                &admin,
                Some(json!({ "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = h
            .send(
                Method::POST,
                &format!("/api/v1/groups/{name}/idp-mappings"),
                &admin,
                Some(json!({ "provider": "mock", "value": value })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    let carol = h
        .scim_user(
            &token,
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "carol@example.com",
                "externalId": "carol-sub",
                "displayName": "Carol",
                "name": { "givenName": "Carol", "familyName": "C" },
                "emails": [{ "value": "carol@example.com", "type": "work", "primary": true }],
                "active": true,
            }),
        )
        .await;
    let (status, group) = h
        .scim(
            Method::POST,
            "/Groups",
            &token,
            Some(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "displayName": "Developers",
                "externalId": "grp-ops-1",
                "members": [{ "value": carol }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    assert_eq!(group["displayName"], "Developers");
    assert_eq!(group["members"][0]["value"], carol);
    assert_eq!(group["members"][0]["display"], "carol@example.com");
    assert_eq!(group["meta"]["resourceType"], "Group");
    let group_id = group["id"].as_str().unwrap().to_string();

    // Carol logs in for the first time; the IdP's own claims say nothing
    // useful, the SCIM groups decide.
    let carol_session = h
        .login_as("carol-sub", "carol@example.com", &["unrelated-claim"])
        .await;
    assert_eq!(
        h.groups_of(&carol_session).await,
        ["authenticated", "devs", "ops"]
    );

    // A later login does not overwrite them from the ID token.
    let carol_session = h
        .login_as("carol-sub", "carol@example.com", &["admins"])
        .await;
    assert_eq!(
        h.groups_of(&carol_session).await,
        ["authenticated", "devs", "ops"]
    );

    // Removing her from the group takes the groups away without a new login.
    let (status, body) = h
        .scim(
            Method::PATCH,
            &format!("/Groups/{group_id}"),
            &token,
            Some(json!({
                "schemas": [PATCH_OP],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{carol}\"]"),
                }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["members"], json!([]));
    assert_eq!(h.groups_of(&carol_session).await, ["authenticated"]);

    // Adding her back (Entra style) brings them back.
    let (status, _) = h
        .scim(
            Method::PATCH,
            &format!("/Groups/{group_id}"),
            &token,
            Some(json!({
                "Operations": [{ "op": "Add", "path": "members", "value": [{ "value": carol }] }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.groups_of(&carol_session).await,
        ["authenticated", "devs", "ops"]
    );

    // Renaming the group changes the values she carries.
    let (status, _) = h
        .scim(
            Method::PATCH,
            &format!("/Groups/{group_id}"),
            &token,
            Some(json!({
                "Operations": [{ "op": "Replace", "path": "displayName", "value": "Engineers" }],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.groups_of(&carol_session).await, ["authenticated", "ops"]);

    // Deleting the group takes the rest.
    let (status, _) = h
        .scim(Method::DELETE, &format!("/Groups/{group_id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(h.groups_of(&carol_session).await, ["authenticated"]);
    let (status, _) = h
        .scim(Method::GET, &format!("/Groups/{group_id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The pushes are in the audit log under the provider's name.
    let actions = audit_actions(&h, &admin).await;
    for action in [
        "scim.user.create",
        "scim.group.create",
        "scim.group.update",
        "scim.group.delete",
        "scim.user.link",
    ] {
        assert!(
            actions.contains(&(action.to_string(), "scim:mock".to_string())),
            "{action} in {actions:?}"
        );
    }
}

#[tokio::test]
async fn a_scim_user_that_is_pushed_after_the_login_links_to_it() {
    let Some(h) = Harness::start("axon_scim_link").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &admin,
            Some(json!({ "name": "devs" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups/devs/idp-mappings",
            &admin,
            Some(json!({ "provider": "mock", "value": "Developers" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // Dana logs in first, with no groups.
    let dana = h.login_as("dana-sub", "dana@example.com", &[]).await;
    assert_eq!(h.groups_of(&dana).await, ["authenticated"]);

    // Then the provider pushes her and her group; the userName is her email,
    // the externalId is something else.
    let user = h
        .scim_user(
            &token,
            json!({ "userName": "Dana@Example.com", "externalId": "other-id" }),
        )
        .await;
    let (status, _) = h
        .scim(
            Method::POST,
            "/Groups",
            &token,
            Some(json!({ "displayName": "Developers", "members": [{ "value": user }] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(h.groups_of(&dana).await, ["authenticated", "devs"]);
}

#[tokio::test]
async fn active_false_disables_the_user_and_active_true_enables_them_again() {
    let Some(h) = Harness::start("axon_scim_active").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;

    let erin = h.login_as("erin-sub", "erin@example.com", &[]).await;
    let erin_pat = h.create_pat(&erin).await;
    assert_eq!(h.mcp_status(&erin_pat).await, StatusCode::OK);
    let id = h
        .scim_user(
            &token,
            json!({ "userName": "erin@example.com", "externalId": "erin-sub" }),
        )
        .await;

    // Entra: a capitalised op and a string boolean.
    let (status, body) = h.scim_active(&token, &id, "False").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], false);
    assert_eq!(h.mcp_status(&erin_pat).await, StatusCode::UNAUTHORIZED);
    let (status, _) = h.send(Method::GET, "/api/v1/me", &erin, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "her session is gone");
    let resp = h.login_callback("erin-sub", "erin@example.com", &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let (status, body) = h.scim_active(&token, &id, "True").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active"], true);
    assert_eq!(h.mcp_status(&erin_pat).await, StatusCode::OK);
    let erin = h.login_as("erin-sub", "erin@example.com", &[]).await;
    assert_eq!(h.groups_of(&erin).await, ["authenticated"]);

    // DELETE deprovisions: 204, the user is disabled, SCIM forgets them.
    let (status, _) = h
        .scim(Method::DELETE, &format!("/Users/{id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(h.mcp_status(&erin_pat).await, StatusCode::UNAUTHORIZED);
    let (status, _) = h
        .scim(Method::GET, &format!("/Users/{id}"), &token, None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scim_never_enables_a_user_an_admin_disabled() {
    let Some(h) = Harness::start("axon_scim_admin_disabled").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;

    let frank = h.login_as("frank-sub", "frank@example.com", &[]).await;
    let frank_pat = h.create_pat(&frank).await;
    let frank_id = h.user_id(&admin, "frank@example.com").await;
    let id = h
        .scim_user(
            &token,
            json!({ "userName": "frank@example.com", "externalId": "frank-sub" }),
        )
        .await;

    let (status, body) = h
        .send(
            Method::PATCH,
            &format!("/api/v1/users/{frank_id}"),
            &admin,
            Some(json!({ "disabled": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.mcp_status(&frank_pat).await, StatusCode::UNAUTHORIZED);

    // SCIM deactivates and reactivates; the admin's decision stands.
    let (status, _) = h.scim_active(&token, &id, "False").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = h.scim_active(&token, &id, "True").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.mcp_status(&frank_pat).await, StatusCode::UNAUTHORIZED);
    let resp = h
        .login_callback("frank-sub", "frank@example.com", &[])
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_user_pushed_inactive_is_refused_at_the_first_login() {
    let Some(h) = Harness::start("axon_scim_inactive_login").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;

    let id = h
        .scim_user(
            &token,
            json!({
                "userName": "gina@example.com",
                "externalId": "gina-sub",
                "active": false,
            }),
        )
        .await;
    let resp = h.login_callback("gina-sub", "gina@example.com", &[]).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Activating her lets her in.
    let (status, _) = h.scim_active(&token, &id, "True").await;
    assert_eq!(status, StatusCode::OK);
    let gina = h.login_as("gina-sub", "gina@example.com", &[]).await;
    assert_eq!(h.groups_of(&gina).await, ["authenticated"]);
}

#[tokio::test]
async fn filters_list_and_uniqueness() {
    let Some(h) = Harness::start("axon_scim_filters").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let token = h.scim_token(&admin).await;

    let alice = h
        .scim_user(
            &token,
            json!({ "userName": "alice@example.com", "externalId": "a-1" }),
        )
        .await;
    h.scim_user(&token, json!({ "userName": "bob@example.com" }))
        .await;

    let list = |filter: &str| {
        let query = format!("/Users?filter={}", urlencode(filter));
        let token = token.clone();
        let h = &h;
        async move { h.scim(Method::GET, &query, &token, None).await }
    };
    let (status, body) = list(r#"userName eq "alice@example.com""#).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["id"], alice);
    assert_eq!(body["Resources"][0]["meta"]["resourceType"], "User");
    assert_eq!(
        body["schemas"],
        json!(["urn:ietf:params:scim:api:messages:2.0:ListResponse"])
    );
    let (_, body) = list(r#"USERNAME EQ "Alice@Example.com""#).await;
    assert_eq!(body["totalResults"], 1, "userName is case-insensitive");
    let (_, body) = list(r#"userName eq "nobody@example.com""#).await;
    assert_eq!(body["totalResults"], 0);
    assert_eq!(body["Resources"], json!([]));
    let (_, body) = list(r#"externalId eq "a-1""#).await;
    assert_eq!(body["totalResults"], 1);
    let (_, body) = list(&format!(r#"id eq "{alice}""#)).await;
    assert_eq!(body["totalResults"], 1);

    // Anything but eq is an invalidFilter.
    let (status, body) = list(r#"userName co "alice""#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["scimType"], "invalidFilter");
    assert_eq!(body["status"], "400");

    // Paging: everything, then one page of one.
    let (_, body) = h.scim(Method::GET, "/Users", &token, None).await;
    assert_eq!(body["totalResults"], 2);
    assert_eq!(body["itemsPerPage"], 2);
    let (_, body) = h
        .scim(Method::GET, "/Users?startIndex=2&count=1", &token, None)
        .await;
    assert_eq!(body["totalResults"], 2);
    assert_eq!(body["startIndex"], 2);
    assert_eq!(body["Resources"].as_array().unwrap().len(), 1);
    assert_eq!(body["Resources"][0]["userName"], "bob@example.com");

    // A duplicate userName is a 409 uniqueness, in any case.
    for name in ["alice@example.com", "ALICE@example.com"] {
        let (status, body) = h
            .scim(
                Method::POST,
                "/Users",
                &token,
                Some(json!({ "userName": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["scimType"], "uniqueness");
        assert_eq!(body["status"], "409");
    }
    // So is a PUT onto another user's name.
    let (status, body) = h
        .scim(
            Method::PUT,
            &format!("/Users/{alice}"),
            &token,
            Some(json!({ "userName": "bob@example.com" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A body that is no user is a 400.
    let (status, body) = h
        .scim(
            Method::POST,
            "/Users",
            &token,
            Some(json!({ "displayName": "x" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["scimType"], "invalidValue");
    let resp = h
        .client
        .post(h.url("/scim/v2/mock/Users"))
        .bearer_auth(&token)
        .body("{not json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // PUT replaces; application/json is accepted too.
    let resp = h
        .client
        .put(h.url(&format!("/scim/v2/mock/Users/{alice}")))
        .bearer_auth(&token)
        .json(&json!({
            "userName": "alice@example.com",
            "displayName": "Alice A",
            "name": { "givenName": "Alice" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["displayName"], "Alice A");
    assert!(body.get("externalId").is_none(), "PUT unsets what it omits");

    // Groups: a duplicate displayName, the filter and excludedAttributes.
    let (status, group) = h
        .scim(
            Method::POST,
            "/Groups",
            &token,
            Some(json!({ "displayName": "Ops", "members": [{ "value": alice }] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{group}");
    let group_id = group["id"].as_str().unwrap();
    let (status, body) = h
        .scim(
            Method::POST,
            "/Groups",
            &token,
            Some(json!({ "displayName": "Ops" })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["scimType"], "uniqueness");
    let (status, body) = h
        .scim(
            Method::POST,
            "/Groups",
            &token,
            Some(json!({ "displayName": "Dangling", "members": [{ "value": uuid_like() }] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (_, body) = h
        .scim(
            Method::GET,
            &format!("/Groups?filter={}", urlencode(r#"displayName eq "Ops""#)),
            &token,
            None,
        )
        .await;
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["members"].as_array().unwrap().len(), 1);
    let (status, body) = h
        .scim(
            Method::GET,
            &format!("/Groups/{group_id}?excludedAttributes=members"),
            &token,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("members").is_none(), "{body}");
    let (_, body) = h
        .scim(
            Method::GET,
            &format!(
                "/Groups?filter={}&excludedAttributes=members",
                urlencode(r#"displayName eq "Nope""#)
            ),
            &token,
            None,
        )
        .await;
    assert_eq!(body["totalResults"], 0);
}

/// The `(action, actor)` of the latest audit entries.
async fn audit_actions(h: &Harness, admin: &Session) -> Vec<(String, String)> {
    let (status, audit) = h
        .send(Method::GET, "/api/v1/audit?limit=200", admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    audit["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| {
            (
                entry["action"].as_str().unwrap().to_string(),
                entry["actor"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Percent-encodes a query value.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// A well-formed id no SCIM user has.
fn uuid_like() -> String {
    "00000000-0000-4000-8000-000000000001".to_string()
}
