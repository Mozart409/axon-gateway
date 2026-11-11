//! The MCP OAuth authorization server end to end: the real gateway binary, a real Postgres
//! schema and the mock identity provider.
//!
//! The browser is played by hand: a client that does not follow redirects, cookies read from
//! `Set-Cookie` and sent back, every hop asserted. The tests skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use reqwest::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde_json::{Value, json};
use support::mock_oidc::MockOidc;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, raw_post, rpc};

const SESSION_COOKIE: &str = "__Host-axon_session";
const LOGIN_COOKIE: &str = "__Host-axon_login";
const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";
const REDIRECT_URI: &str = "http://127.0.0.1:45871/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// A gateway with OIDC login against a mock provider, in its own schema.
struct Harness {
    gateway: Gateway,
    /// Kept running for the logins
    _idp: MockOidc,
    client: reqwest::Client,
}

/// What a finished authorization hands the client
struct Tokens {
    client_id: String,
    access: String,
    refresh: String,
    session: String,
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
            .oidc_provider("mock", idp.issuer(), "axon-test", "")
            .render();
        let gateway =
            Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)])
                .await;
        Some(Self {
            gateway,
            _idp: idp,
            client: no_redirect_client(),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.gateway.base)
    }

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

    fn post_form(&self, path: &str, cookies: &[&str], fields: &[(&str, &str)]) -> RequestBuilder {
        with_cookies(self.client.post(self.url(path)), cookies)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(fields))
    }

    /// Registers a client with the test redirect URI and returns its id.
    async fn register(&self, name: &str) -> String {
        let resp = self
            .client
            .post(self.url("/oauth/register"))
            .json(&json!({
                "redirect_uris": [REDIRECT_URI],
                "client_name": name,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: Value = resp.json().await.unwrap();
        body["client_id"].as_str().unwrap().to_string()
    }

    fn authorize_url(&self, client_id: &str, extra: &[(&str, &str)]) -> String {
        let mut fields = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT_URI),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "xyz"),
        ];
        fields.extend_from_slice(extra);
        self.url(&format!("/oauth/authorize?{}", form(&fields)))
    }

    /// Signs the browser in through the mock provider, starting at the login `Location`
    /// the session guard answered with. Returns the session cookie and where the login
    /// sends the browser back to.
    async fn login(&self, login_location: &str) -> (String, String) {
        let resp = self
            .get(&self.resolve(login_location), &[])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let next = location(&resp);
        assert!(next.starts_with("/auth/login/mock?return_to="), "{next}");

        let resp = self.get(&self.resolve(&next), &[]).send().await.unwrap();
        let login_cookie = cookie_pair(&resp, LOGIN_COOKIE).expect("a login cookie");
        let provider_url = location(&resp);
        let resp = self.get(&provider_url, &[]).send().await.unwrap();
        let callback = location(&resp);
        let resp = self.get(&callback, &[&login_cookie]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        (
            cookie_pair(&resp, SESSION_COOKIE).expect("a session cookie"),
            location(&resp),
        )
    }

    /// Authorizes `authorize_url` up to the consent page: the session, the page, the
    /// pending request's id and the CSRF token.
    async fn consent(&self, authorize_url: &str) -> (String, String, String, String) {
        let resp = self.get(authorize_url, &[]).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let continue_path = location(&resp);
        assert!(
            continue_path.starts_with("/oauth/authorize/continue?request="),
            "{continue_path}"
        );

        // Without a session the dashboard login comes first, and returns here
        let resp = self
            .get(&self.url(&continue_path), &[])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let login_location = location(&resp);
        assert!(login_location.starts_with("/auth/login?return_to="));
        let (session, back_to) = self.login(&login_location).await;
        assert_eq!(back_to, continue_path);

        let resp = self
            .get(&self.url(&back_to), &[&session])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["x-frame-options"], "DENY");
        let page = resp.text().await.unwrap();
        let request = field_value(&page, "request");
        let csrf = field_value(&page, "csrf_token");
        (session, page, request, csrf)
    }

    /// The whole flow with an approval; returns the tokens.
    async fn authorize(&self, extra: &[(&str, &str)]) -> Tokens {
        let client_id = self.register("Example client").await;
        let (session, _, request, csrf) =
            self.consent(&self.authorize_url(&client_id, extra)).await;
        let code = self.approve(&session, &request, &csrf).await;
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", client_id.as_str()),
            ("code_verifier", VERIFIER),
        ];
        let resource = extra.iter().find(|(name, _)| *name == "resource");
        if let Some((_, resource)) = resource {
            fields.push(("resource", *resource));
        }
        let resp = self.token(&fields).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = resp.json().await.unwrap();
        Tokens {
            client_id,
            access: body["access_token"].as_str().unwrap().to_string(),
            refresh: body["refresh_token"].as_str().unwrap().to_string(),
            session,
        }
    }

    /// Posts the decision and returns the code the browser is redirected back with
    async fn approve(&self, session: &str, request: &str, csrf: &str) -> String {
        let resp = self
            .post_form(
                "/oauth/authorize/decision",
                &[session],
                &[
                    ("csrf_token", csrf),
                    ("request", request),
                    ("decision", "approve"),
                ],
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let back = Url::parse(&location(&resp)).unwrap();
        assert!(back.as_str().starts_with(REDIRECT_URI));
        let params: Vec<(String, String)> = back.query_pairs().into_owned().collect();
        let param = |name: &str| {
            params
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(param("state").as_deref(), Some("xyz"));
        assert_eq!(param("iss").as_deref(), Some(self.gateway.base.as_str()));
        let code = param("code").expect("a code");
        assert_eq!(code.len(), 64);
        code
    }

    async fn token(&self, fields: &[(&str, &str)]) -> Response {
        self.post_form("/oauth/token", &[], fields)
            .send()
            .await
            .unwrap()
    }

    async fn refresh(&self, client_id: &str, refresh_token: &str) -> Response {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh_token),
        ])
        .await
    }

    async fn tools_list_status(&self, path: &str, bearer: &str) -> StatusCode {
        mcp_post(
            &self.client,
            &self.url(path),
            Some(bearer),
            &rpc("tools/list"),
        )
        .await
        .0
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

/// `name=value` of the cookie `name`, ready for a `Cookie` header.
fn cookie_pair(resp: &Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .and_then(|header| header.split(';').next().map(str::to_string))
}

/// An `application/x-www-form-urlencoded` body
fn form(fields: &[(&str, &str)]) -> String {
    let mut url = Url::parse("http://form.invalid/").unwrap();
    url.query_pairs_mut().extend_pairs(fields);
    url.query().unwrap_or_default().to_string()
}

/// The value of the hidden input `name` of the consent form
fn field_value(page: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = page.find(&marker).expect("a form field") + marker.len();
    let len = page[start..].find('"').expect("a closed attribute");
    page[start..start + len].to_string()
}

async fn json_of(resp: Response) -> Value {
    resp.json().await.unwrap()
}

#[tokio::test]
async fn metadata_documents_describe_the_server() {
    let Some(h) = Harness::start("oauth_metadata").await else {
        return;
    };
    let base = h.gateway.base.clone();

    let resp = h
        .get(&h.url("/.well-known/oauth-protected-resource/mcp"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        json_of(resp).await,
        json!({
            "resource": format!("{base}/mcp"),
            "authorization_servers": [base],
            "scopes_supported": ["mcp"],
            "bearer_methods_supported": ["header"],
        })
    );
    let resp = h
        .get(
            &h.url("/.well-known/oauth-protected-resource/mcp/toolset/ops"),
            &[],
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        json_of(resp).await["resource"],
        format!("{base}/mcp/toolset/ops")
    );
    let resp = h
        .get(&h.url("/.well-known/oauth-protected-resource"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(json_of(resp).await["resource"], format!("{base}/mcp"));
    let resp = h
        .get(&h.url("/.well-known/oauth-protected-resource/api/v1"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = h
        .get(&h.url("/.well-known/oauth-authorization-server"), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metadata = json_of(resp).await;
    assert_eq!(metadata["issuer"], base);
    assert_eq!(
        metadata["authorization_endpoint"],
        format!("{base}/oauth/authorize")
    );
    assert_eq!(metadata["token_endpoint"], format!("{base}/oauth/token"));
    assert_eq!(
        metadata["registration_endpoint"],
        format!("{base}/oauth/register")
    );
    assert_eq!(
        metadata["revocation_endpoint"],
        format!("{base}/oauth/revoke")
    );
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(metadata["client_id_metadata_document_supported"], true);
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );
}

#[tokio::test]
async fn registration_validates_client_metadata() {
    let Some(h) = Harness::start("oauth_registration").await else {
        return;
    };
    let register = |body: Value| {
        let request = h.client.post(h.url("/oauth/register")).json(&body);
        async move { request.send().await.unwrap() }
    };

    let resp = register(json!({
        "redirect_uris": ["https://app.example/cb", "http://localhost:3000/cb"],
        "client_name": "<b>Tool</b>",
    }))
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_of(resp).await;
    let client_id = body["client_id"].as_str().unwrap();
    let hex = client_id.strip_prefix("axon_client_").expect("a client id");
    assert_eq!(hex.len(), 32);
    assert!(hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(body["client_id_issued_at"].as_i64().unwrap() > 0);
    assert!(body.get("client_secret").is_none());
    assert_eq!(body["client_name"], "<b>Tool</b>");
    assert_eq!(body["token_endpoint_auth_method"], "none");

    for (bad, error) in [
        (json!({}), "invalid_redirect_uri"),
        (json!({ "redirect_uris": [] }), "invalid_redirect_uri"),
        (
            json!({ "redirect_uris": ["http://app.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["https://app.example/cb"], "token_endpoint_auth_method": "client_secret_basic" }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": ["https://app.example/cb"], "grant_types": ["password"] }),
            "invalid_client_metadata",
        ),
    ] {
        let resp = register(bad).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_of(resp).await["error"], error);
    }
}

#[tokio::test]
async fn full_flow_from_registration_to_revocation() {
    let Some(h) = Harness::start("oauth_full_flow").await else {
        return;
    };
    let client_id = h.register("<i>Example client</i>").await;
    let (session, page, request, csrf) = h
        .consent(&h.authorize_url(&client_id, &[("scope", "mcp")]))
        .await;

    // The consent page names the client (escaped), the redirect host, the user and the
    // resource
    assert!(page.contains("&lt;i&gt;Example client&lt;/i&gt;"));
    assert!(!page.contains("<i>Example client</i>"));
    assert!(page.contains("127.0.0.1:45871"));
    assert!(page.contains("alice@example.com"));
    assert!(page.contains(&format!("{}/mcp", h.gateway.base)));

    // A decision without the CSRF token is refused and does not spend the request
    let resp = h
        .post_form(
            "/oauth/authorize/decision",
            &[&session],
            &[("request", &request), ("decision", "approve")],
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let code = h.approve(&session, &request, &csrf).await;

    // The code works once, with the right verifier
    let resp = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", VERIFIER),
        ])
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let tokens = json_of(resp).await;
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);
    assert_eq!(tokens["scope"], "mcp");
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    assert!(access.starts_with("axon_oat_"));
    assert!(refresh.starts_with("axon_ort_"));

    // The access token calls the MCP endpoint
    let (status, body) =
        mcp_post(&h.client, &h.url("/mcp"), Some(&access), &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("result").is_some(), "{body}");

    // The grant is listed on the apps page and in the API
    let resp = h
        .get(&h.url("/ui/me/apps"), &[&session])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.text()
            .await
            .unwrap()
            .contains("&lt;i&gt;Example client")
    );
    let resp = h
        .get(&h.url("/api/v1/me/oauth-grants"), &[&session])
        .send()
        .await
        .unwrap();
    let grants = json_of(resp).await;
    assert_eq!(grants["grants"].as_array().unwrap().len(), 1);
    assert_eq!(grants["grants"][0]["client_id"], client_id);

    // Using the code again fails, and kills the grant made from it
    let replay = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", VERIFIER),
        ])
        .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(replay).await["error"], "invalid_grant");
    assert_eq!(
        h.tools_list_status("/mcp", &access).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes_the_grant() {
    let Some(h) = Harness::start("oauth_refresh").await else {
        return;
    };
    let tokens = h.authorize(&[]).await;

    let resp = h.refresh(&tokens.client_id, &tokens.refresh).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let second = json_of(resp).await;
    let new_access = second["access_token"].as_str().unwrap().to_string();
    let new_refresh = second["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, tokens.refresh);
    assert_eq!(
        h.tools_list_status("/mcp", &new_access).await,
        StatusCode::OK
    );
    // The old access token still works until it expires
    assert_eq!(
        h.tools_list_status("/mcp", &tokens.access).await,
        StatusCode::OK
    );

    // The spent refresh token is replayed: invalid_grant, and the whole grant is revoked
    let resp = h.refresh(&tokens.client_id, &tokens.refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_grant");
    for access in [&tokens.access, &new_access] {
        assert_eq!(
            h.tools_list_status("/mcp", access).await,
            StatusCode::UNAUTHORIZED
        );
    }
    let resp = h.refresh(&tokens.client_id, &new_refresh).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = h
        .get(&h.url("/api/v1/me/oauth-grants"), &[&tokens.session])
        .send()
        .await
        .unwrap();
    assert_eq!(json_of(resp).await["grants"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn revocation_by_endpoint_and_by_the_user_ends_the_grant() {
    let Some(h) = Harness::start("oauth_revocation").await else {
        return;
    };
    let tokens = h.authorize(&[]).await;

    // RFC 7009: always 200, even for garbage; the refresh token revokes the grant
    let resp = h
        .post_form("/oauth/revoke", &[], &[("token", "garbage")])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h.tools_list_status("/mcp", &tokens.access).await,
        StatusCode::OK
    );
    let resp = h
        .post_form(
            "/oauth/revoke",
            &[],
            &[
                ("token", &tokens.refresh),
                ("token_type_hint", "refresh_token"),
            ],
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        h.tools_list_status("/mcp", &tokens.access).await,
        StatusCode::UNAUTHORIZED
    );

    // The user ends another grant from the API
    let second = h.authorize(&[]).await;
    let resp = h
        .get(&h.url("/api/v1/me/oauth-grants"), &[&second.session])
        .send()
        .await
        .unwrap();
    let id = json_of(resp).await["grants"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let page = h
        .get(&h.url("/ui/me/apps"), &[&second.session])
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = meta_csrf(&page);
    let resp = with_cookies(
        h.client
            .delete(h.url(&format!("/api/v1/me/oauth-grants/{id}")))
            .header("x-csrf-token", csrf),
        &[&second.session],
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h.tools_list_status("/mcp", &second.access).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_wrong_pkce_verifier_fails_and_the_code_survives() {
    let Some(h) = Harness::start("oauth_pkce").await else {
        return;
    };
    let client_id = h.register("Example client").await;
    let (session, _, request, csrf) = h.consent(&h.authorize_url(&client_id, &[])).await;
    let code = h.approve(&session, &request, &csrf).await;

    let wrong = "x".repeat(43);
    let resp = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", &wrong),
        ])
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_grant");

    let resp = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("client_id", &client_id),
            ("code_verifier", "too-short"),
        ])
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_of(resp).await["error"], "invalid_request");

    let resp = h.token(&[("grant_type", "password")]).await;
    assert_eq!(json_of(resp).await["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn authorization_requests_are_validated() {
    let Some(h) = Harness::start("oauth_authorize").await else {
        return;
    };
    let client_id = h.register("Example client").await;

    // A redirect URI that is not registered: an error page, never a redirect
    let other = "http://127.0.0.1:45871/elsewhere";
    let url = h.authorize_url(&client_id, &[]).replace(
        &form(&[("redirect_uri", REDIRECT_URI)]),
        &form(&[("redirect_uri", other)]),
    );
    let resp = h.get(&url, &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get(LOCATION).is_none());
    let page = resp.text().await.unwrap();
    assert!(page.contains("redirect URI"), "{page}");

    // An unknown client likewise
    let resp = h
        .get(&h.authorize_url("axon_client_unknown", &[]), &[])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(resp.headers().get(LOCATION).is_none());

    // A loopback redirect URI may use another port
    let moved = form(&[("redirect_uri", "http://127.0.0.1:1234/callback")]);
    let url = h
        .authorize_url(&client_id, &[])
        .replace(&form(&[("redirect_uri", REDIRECT_URI)]), &moved);
    let resp = h.get(&url, &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert!(location(&resp).starts_with("/oauth/authorize/continue?request="));

    // Other errors go back to the client with state and iss
    let url = h.authorize_url(&client_id, &[]).replace("S256", "plain");
    let resp = h.get(&url, &[]).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let back = Url::parse(&location(&resp)).unwrap();
    assert!(back.as_str().starts_with(REDIRECT_URI));
    let query: Vec<(String, String)> = back.query_pairs().into_owned().collect();
    let has = |name: &str, value: &str| query.iter().any(|(k, v)| k == name && v == value);
    assert!(has("error", "invalid_request"));
    assert!(has("state", "xyz"));
    assert!(has("iss", &h.gateway.base));

    for (extra, error) in [
        (("scope", "admin"), "invalid_scope"),
        (
            ("resource", "https://elsewhere.example/mcp"),
            "invalid_target",
        ),
    ] {
        let resp = h
            .get(&h.authorize_url(&client_id, &[extra]), &[])
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let back = Url::parse(&location(&resp)).unwrap();
        assert!(back.query_pairs().any(|(k, v)| k == "error" && v == error));
    }

    // Deny goes back with access_denied
    let (session, _, request, csrf) = h.consent(&h.authorize_url(&client_id, &[])).await;
    let resp = h
        .post_form(
            "/oauth/authorize/decision",
            &[&session],
            &[
                ("csrf_token", &csrf),
                ("request", &request),
                ("decision", "deny"),
            ],
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let back = Url::parse(&location(&resp)).unwrap();
    assert!(
        back.query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
}

#[tokio::test]
async fn a_token_is_bound_to_its_resource_and_refused_outside_mcp() {
    let Some(h) = Harness::start("oauth_audience").await else {
        return;
    };
    let resource = format!("{}/mcp/toolset/ops", h.gateway.base);
    let tokens = h.authorize(&[("resource", &resource)]).await;

    // Not on /mcp, not on another toolset: 401 invalid_token with the metadata pointer
    let (status, headers, _) = raw_post(
        &h.client,
        &h.url("/mcp/toolset/other"),
        Some(&tokens.access),
        &rpc("tools/list"),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers["www-authenticate"].to_str().unwrap();
    assert!(challenge.contains("error=\"invalid_token\""), "{challenge}");
    assert!(challenge.contains(&format!(
        "resource_metadata=\"{}/.well-known/oauth-protected-resource/mcp/toolset/other\"",
        h.gateway.base
    )));
    assert_eq!(
        h.tools_list_status("/mcp", &tokens.access).await,
        StatusCode::UNAUTHORIZED
    );
    // On its own toolset it authenticates (the toolset itself does not exist: not a 401)
    assert_ne!(
        h.tools_list_status("/mcp/toolset/ops", &tokens.access)
            .await,
        StatusCode::UNAUTHORIZED
    );

    // A token for /mcp works on every MCP endpoint
    let general = h.authorize(&[]).await;
    assert_ne!(
        h.tools_list_status("/mcp/toolset/other", &general.access)
            .await,
        StatusCode::UNAUTHORIZED
    );

    // And no access token opens the JSON API
    for path in ["/api/v1/me/oauth-grants", "/api/v1/tokens"] {
        let resp = h
            .client
            .get(h.url(path))
            .bearer_auth(&general.access)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn the_mcp_401_points_at_the_resource_metadata() {
    let Some(h) = Harness::start("oauth_challenge").await else {
        return;
    };
    for (path, anonymous) in [("/mcp", true), ("/mcp/toolset/ops", true), ("/mcp", false)] {
        let bearer = (!anonymous).then_some("axon_oat_0000000000000000_not-a-real-token");
        let (status, headers, _) =
            raw_post(&h.client, &h.url(path), bearer, &rpc("tools/list"), &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            headers["www-authenticate"].to_str().unwrap(),
            format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource{path}\"",
                h.gateway.base
            )
        );
    }
}

/// The session's CSRF token from a dashboard page's `csrf-token` meta tag.
fn meta_csrf(page: &str) -> String {
    let marker = "name=\"csrf-token\" content=\"";
    let start = page.find(marker).expect("a csrf-token meta tag") + marker.len();
    let len = page[start..].find('"').expect("a closed attribute");
    page[start..start + len].to_string()
}
