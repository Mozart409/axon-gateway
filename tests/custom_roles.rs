//! Custom RBAC roles end to end: the real gateway binary, a real Postgres
//! schema and the mock identity provider. Roles are defined through
//! `/api/v1/admin/roles` and bound through `/api/v1/role-bindings` like the
//! built-in ones.
//!
//! The tests that need a database skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{COOKIE, LOCATION, SET_COOKIE};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde_json::{Value, json};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// `ops` and the role `config-reader` are declared in config and read-only
/// through the API.
const RBAC: &str = r#"
[[rbac.groups]]
name = "ops"
description = "Operations"

[[rbac.roles]]
name = "config-reader"
description = "Reads the audit log"
permissions = ["audit.read"]
"#;

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

    /// Creates a role as `session` and asserts it worked.
    async fn create_role(&self, session: &Session, name: &str, permissions: &[&str]) {
        let (status, body) = self
            .send(
                Method::POST,
                "/api/v1/admin/roles",
                session,
                Some(json!({ "name": name, "permissions": permissions })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// Binds `role` to a group or user (`subject` is the JSON field and its value).
    async fn bind(
        &self,
        session: &Session,
        role: &str,
        field: &str,
        subject: &str,
    ) -> (StatusCode, Value) {
        self.send(
            Method::POST,
            "/api/v1/role-bindings",
            session,
            Some(json!({ "role": role, field: subject })),
        )
        .await
    }

    /// The status of `GET /api/v1/audit` for the session.
    async fn audit_status(&self, session: &Session) -> StatusCode {
        self.send(Method::GET, "/api/v1/audit", session, None)
            .await
            .0
    }

    /// A group `devs` mapped to the claim `dev-claim`.
    async fn create_devs_group(&self, admin: &Session) {
        let (status, body) = self
            .send(
                Method::POST,
                "/api/v1/groups",
                admin,
                Some(json!({ "name": "devs" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = self
            .send(
                Method::POST,
                "/api/v1/groups/devs/idp-mappings",
                admin,
                Some(json!({ "provider": "mock", "value": "dev-claim" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
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

/// The id of the user with this email, from `GET /api/v1/users`.
async fn user_id(h: &Harness, admin: &Session, email: &str) -> String {
    let (status, body) = h.send(Method::GET, "/api/v1/users", admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["users"]
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["email"] == email)
        .unwrap_or_else(|| panic!("no user {email} in {body}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The role named `name` in `GET /api/v1/admin/roles`.
async fn listed_role(h: &Harness, session: &Session, name: &str) -> Option<Value> {
    let (status, body) = h
        .send(Method::GET, "/api/v1/admin/roles", session, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == name)
        .cloned()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_custom_role_bound_to_a_group_grants_exactly_its_permissions() {
    let Some(h) = Harness::start("axon_custom_roles_bind").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["dev-claim"]).await;
    h.create_devs_group(&admin).await;

    assert_eq!(h.audit_status(&bob).await, StatusCode::FORBIDDEN);

    let (status, role) = h
        .send(
            Method::POST,
            "/api/v1/admin/roles",
            &admin,
            Some(json!({
                "name": "log-reader",
                "description": "Reads the audit log",
                "permissions": ["audit.read"],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{role}");
    assert_eq!(role["source"], "local");
    assert_eq!(role["permissions"], json!(["audit.read"]));
    let (status, _) = h.bind(&admin, "log-reader", "group", "devs").await;
    assert_eq!(status, StatusCode::CREATED);

    // The role shows up in the listing with its binding.
    let listed = listed_role(&h, &admin, "log-reader").await.unwrap();
    assert_eq!(listed["description"], "Reads the audit log");
    assert_eq!(listed["bindings"], 1);
    let (_, bindings) = h
        .send(Method::GET, "/api/v1/role-bindings", &admin, None)
        .await;
    assert!(
        bindings["role_bindings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|binding| binding["role"] == "log-reader" && binding["group"] == "devs")
    );

    // Bob reads the audit log now, and can still not manage groups.
    assert_eq!(h.audit_status(&bob).await, StatusCode::OK);
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/groups",
            &bob,
            Some(json!({ "name": "mine" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, me) = h.send(Method::GET, "/api/v1/me", &bob, None).await;
    assert_eq!(me["roles"], json!(["log-reader", "member"]));
    assert!(
        me["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("audit.read"))
    );
    assert!(
        !me["permissions"]
            .as_array()
            .unwrap()
            .contains(&json!("groups.manage"))
    );

    // Editing the role changes what the binding grants.
    let (status, role) = h
        .send(
            Method::PUT,
            "/api/v1/admin/roles/log-reader",
            &admin,
            Some(json!({ "permissions": ["backends.view"] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{role}");
    assert_eq!(role["description"], Value::Null);
    assert_eq!(h.audit_status(&bob).await, StatusCode::FORBIDDEN);

    // The changes are in the audit log.
    let (_, audit) = h
        .send(Method::GET, "/api/v1/audit?limit=50", &admin, None)
        .await;
    let actions: Vec<&str> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .collect();
    for action in ["role.create", "role.update", "role_binding.create"] {
        assert!(actions.contains(&action), "{action} in {actions:?}");
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_roles_manager_cannot_hand_out_permissions_they_lack() {
    let Some(h) = Harness::start("axon_custom_roles_escalation").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let carol = h.login_as("carol", "carol@example.com", &[]).await;
    let carol_id = user_id(&h, &admin, "carol@example.com").await;

    // carol may manage roles, and nothing else.
    h.create_role(&admin, "role-admin", &["roles.manage"]).await;
    let (status, body) = h.bind(&admin, "role-admin", "user_id", &carol_id).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/admin/roles",
            &carol,
            Some(json!({ "name": "sneaky", "permissions": ["tokens.manage_all"] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(listed_role(&h, &carol, "sneaky").await.is_none());

    // A role of permissions carol holds is fine ...
    h.create_role(&carol, "mine", &["roles.manage"]).await;
    // ... but not once it grows beyond them.
    let (status, body) = h
        .send(
            Method::PUT,
            "/api/v1/admin/roles/mine",
            &carol,
            Some(json!({ "permissions": ["roles.manage", "tokens.manage_all"] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        listed_role(&h, &carol, "mine").await.unwrap()["permissions"],
        json!(["roles.manage"])
    );

    // Binding a role needs every one of its permissions too: the built-in admin
    // and auditor roles, and a custom role of an admin's making.
    h.create_role(&admin, "token-admin", &["tokens.manage_all"])
        .await;
    for role in ["admin", "auditor", "token-admin"] {
        let (status, body) = h.bind(&carol, role, "user_id", &carol_id).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {body}");
        let (status, body) = h.bind(&carol, role, "group", "ops").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{role}: {body}");
    }
    let (status, body) = h.bind(&carol, "mine", "group", "ops").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h.bind(&carol, "member", "group", "ops").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // A binding of an unknown role is refused.
    let (status, body) = h.bind(&admin, "nope", "group", "ops").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // Without roles.manage there is no way in at all.
    let dave = h.login_as("dave", "dave@example.com", &[]).await;
    let (status, _) = h
        .send(
            Method::POST,
            "/api/v1/admin/roles",
            &dave,
            Some(json!({ "name": "dave-role", "permissions": ["personal_backends.create"] })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = h
        .send(Method::GET, "/api/v1/admin/roles", &dave, None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn a_groups_manager_cannot_reach_permissions_through_a_group() {
    let Some(h) = Harness::start("axon_custom_roles_group_escalation").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let erin = h.login_as("erin", "erin@example.com", &[]).await;
    let erin_id = user_id(&h, &admin, "erin@example.com").await;

    // erin may manage groups, and nothing else.
    h.create_role(&admin, "group-admin", &["groups.manage"])
        .await;
    let (status, body) = h.bind(&admin, "group-admin", "user_id", &erin_id).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // `power` carries users.manage, `same` only what erin holds, `plain` nothing.
    h.create_role(&admin, "user-admin", &["users.manage"]).await;
    for group in ["power", "same", "plain"] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/groups",
                &admin,
                Some(json!({ "name": group })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let (status, body) = h.bind(&admin, "user-admin", "group", "power").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let (status, body) = h.bind(&admin, "group-admin", "group", "same").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // Joining the powerful group, directly or by a claim value, is refused.
    let (status, body) = h
        .send(
            Method::PUT,
            &format!("/api/v1/groups/power/members/{erin_id}"),
            &erin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = h
        .send(
            Method::POST,
            "/api/v1/groups/power/idp-mappings",
            &erin,
            Some(json!({ "provider": "mock", "value": "erin-claim" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // A group of permissions erin holds, or of none, is fine.
    for group in ["same", "plain"] {
        let (status, body) = h
            .send(
                Method::PUT,
                &format!("/api/v1/groups/{group}/members/{erin_id}"),
                &erin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{group}: {body}");
        let (status, body) = h
            .send(
                Method::POST,
                &format!("/api/v1/groups/{group}/idp-mappings"),
                &erin,
                Some(json!({ "provider": "mock", "value": format!("{group}-claim") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{group}: {body}");
    }
}

#[tokio::test]
async fn deleting_a_bound_role_needs_force_and_removes_the_access() {
    let Some(h) = Harness::start("axon_custom_roles_delete").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;
    let bob = h.login_as("bob", "bob@example.com", &["dev-claim"]).await;
    h.create_devs_group(&admin).await;
    h.create_role(&admin, "log-reader", &["audit.read"]).await;
    let (status, _) = h.bind(&admin, "log-reader", "group", "devs").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(h.audit_status(&bob).await, StatusCode::OK);

    let (status, body) = h
        .send(
            Method::DELETE,
            "/api/v1/admin/roles/log-reader",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["error"].as_str().unwrap().contains('1'), "{body}");
    assert!(listed_role(&h, &admin, "log-reader").await.is_some());
    assert_eq!(h.audit_status(&bob).await, StatusCode::OK);

    let (status, body) = h
        .send(
            Method::DELETE,
            "/api/v1/admin/roles/log-reader?force=true",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert!(listed_role(&h, &admin, "log-reader").await.is_none());
    assert_eq!(h.audit_status(&bob).await, StatusCode::FORBIDDEN);
    let (_, bindings) = h
        .send(Method::GET, "/api/v1/role-bindings", &admin, None)
        .await;
    assert!(
        bindings["role_bindings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|binding| binding["role"] != "log-reader")
    );

    let (status, _) = h
        .send(
            Method::DELETE,
            "/api/v1/admin/roles/log-reader",
            &admin,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // An unbound role needs no force.
    h.create_role(&admin, "spare", &["backends.view"]).await;
    let (status, _) = h
        .send(Method::DELETE, "/api/v1/admin/roles/spare", &admin, None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, audit) = h
        .send(Method::GET, "/api/v1/audit?limit=50", &admin, None)
        .await;
    assert!(
        audit["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["action"] == "role.delete" && entry["target"] == "role:log-reader")
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn built_in_and_config_roles_are_fixed_and_names_are_checked() {
    let Some(h) = Harness::start("axon_custom_roles_fixed").await else {
        return;
    };
    let admin = h.login_as("root", "root@example.com", &["admins"]).await;

    // The listing: built-ins first, then the config role.
    let admin_role = listed_role(&h, &admin, "admin").await.unwrap();
    assert_eq!(admin_role["source"], "builtin");
    assert_eq!(admin_role["permissions"].as_array().unwrap().len(), 12);
    let config_role = listed_role(&h, &admin, "config-reader").await.unwrap();
    assert_eq!(config_role["source"], "config");
    assert_eq!(config_role["permissions"], json!(["audit.read"]));

    for name in [
        "admin",
        "backend-admin",
        "auditor",
        "member",
        "config-reader",
    ] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/admin/roles",
                &admin,
                Some(json!({ "name": name, "permissions": ["audit.read"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "create {name}: {body}");
        let (status, body) = h
            .send(
                Method::PUT,
                &format!("/api/v1/admin/roles/{name}"),
                &admin,
                Some(json!({ "permissions": ["audit.read"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "update {name}: {body}");
        let (status, body) = h
            .send(
                Method::DELETE,
                &format!("/api/v1/admin/roles/{name}?force=true"),
                &admin,
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "delete {name}: {body}");
    }
    let (status, _) = h
        .send(
            Method::PUT,
            "/api/v1/admin/roles/missing",
            &admin,
            Some(json!({ "permissions": ["audit.read"] })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A config role binds like a built-in one.
    let (status, body) = h.bind(&admin, "config-reader", "group", "ops").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        listed_role(&h, &admin, "config-reader").await.unwrap()["bindings"],
        1
    );

    // Bad names and permission lists.
    for (name, permissions) in [
        ("Bad Name", json!(["audit.read"])),
        ("-leading", json!(["audit.read"])),
        ("", json!(["audit.read"])),
        ("empty", json!([])),
        ("unknown-permission", json!(["audit.write"])),
    ] {
        let (status, body) = h
            .send(
                Method::POST,
                "/api/v1/admin/roles",
                &admin,
                Some(json!({ "name": name, "permissions": permissions })),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name:?}: {body}");
    }

    // The permission catalogue names every permission with its text.
    let (status, body) = h
        .send(Method::GET, "/api/v1/admin/permissions", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let permissions = body["permissions"].as_array().unwrap();
    assert_eq!(permissions.len(), 12);
    let audit_read = permissions
        .iter()
        .find(|permission| permission["name"] == "audit.read")
        .unwrap();
    assert_ne!(audit_read["description"].as_str().unwrap(), "");
}
