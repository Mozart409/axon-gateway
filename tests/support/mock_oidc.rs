//! In-process mock `OpenID` Connect identity provider for integration tests.
//!
//! One axum server on an ephemeral loopback port serves discovery, the key
//! set, an authorization endpoint that approves every request on the spot (no
//! login form), the token endpoint and an end-session endpoint. ID tokens are
//! signed with a P-256 key generated per provider (ES256), and the code flow
//! enforces PKCE (S256), so the gateway runs a real login against it.
//!
//! Opt-in, for the Entra groups overage: [`MockOidc::set_overage`] makes the
//! next ID tokens report one, and [`MockOidc::set_graph`] adds the
//! `client_credentials` grant and a Microsoft Graph `transitiveMemberOf` on the
//! same server (point the provider's `graph_url` at the issuer).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use axum::extract::{Form, OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const KID: &str = "mock-oidc-key";
const TOKEN_LIFETIME: u64 = 300;
const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GRANT_CLIENT_CREDENTIALS: &str = "client_credentials";
/// Groups per page of the mock Graph answer.
const GRAPH_PAGE_SIZE: usize = 2;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Percent-encode a query component.
fn encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// What an issued authorization code is bound to.
struct Grant {
    redirect_uri: String,
    nonce: String,
    code_challenge: String,
}

// Opt-in switches of this test mock, each enabled by the tests that need it
#[allow(clippy::struct_excessive_bools)]
struct ProviderState {
    issuer: String,
    client_id: String,
    key: EcdsaKeyPair,
    user: Value,
    end_session: bool,
    codes: HashMap<String, Grant>,
    last_logout: Option<HashMap<String, String>>,
    last_id_token: Option<String>,
    /// Opt-in: the code exchange also returns a refresh token, and the
    /// `refresh_token` grant works.
    refresh_tokens: bool,
    /// Opt-in: the token exchange and `jwt-bearer` (on-behalf-of) grants work.
    token_exchange: bool,
    /// Counter behind the `refresh_<n>`, `idp_at_<n>` and `exchanged_<n>` tokens.
    issued: u64,
    refresh_valid: HashSet<String>,
    /// The form of every request the token endpoint got, oldest first.
    forms: Vec<HashMap<String, String>>,
    /// Opt-in: the `client_credentials` grant answers `graph_at_<n>` and the
    /// Graph route serves `graph_groups`.
    graph: bool,
    graph_groups: Vec<String>,
    /// The Graph route answers 500 (after checking the bearer token).
    graph_failing: bool,
    graph_tokens: HashSet<String>,
    /// The URI of every request the Graph route got, oldest first.
    graph_requests: Vec<String>,
}

type Shared = Arc<Mutex<ProviderState>>;

/// A running mock identity provider. The server stops on drop.
pub struct MockOidc {
    issuer: String,
    state: Shared,
    task: JoinHandle<()>,
}

impl Drop for MockOidc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockOidc {
    /// Start a provider on a free loopback port that accepts `client_id`.
    pub async fn start(client_id: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock oidc");
        let port = listener.local_addr().expect("local addr").port();
        let issuer = format!("http://127.0.0.1:{port}");

        let state = Arc::new(Mutex::new(ProviderState {
            issuer: issuer.clone(),
            client_id: client_id.to_string(),
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("generate key"),
            user: json!({
                "sub": "alice",
                "email": "alice@example.com",
                "name": "Alice",
                "groups": ["staff"],
            }),
            end_session: true,
            codes: HashMap::new(),
            last_logout: None,
            last_id_token: None,
            refresh_tokens: false,
            token_exchange: false,
            issued: 0,
            refresh_valid: HashSet::new(),
            forms: Vec::new(),
            graph: false,
            graph_groups: Vec::new(),
            graph_failing: false,
            graph_tokens: HashSet::new(),
            graph_requests: Vec::new(),
        }));

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/logout", get(logout))
            .route(
                "/v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group",
                get(graph_member_of),
            )
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock oidc");
        });

        Self {
            issuer,
            state,
            task,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Claims merged into the next ID tokens (sub, email, name, groups, ...).
    pub fn set_user(&self, claims: Value) {
        self.state.lock().unwrap().user = claims;
    }

    /// The next ID tokens report a groups overage as Entra does: no `groups`
    /// claim, but `_claim_names` and `_claim_sources`, and an `oid` claim.
    pub fn set_overage(&self, subject: &str, email: &str, oid: &str) {
        self.set_user(json!({
            "sub": subject,
            "email": email,
            "name": subject,
            "oid": oid,
            "_claim_names": {"groups": "src1"},
            "_claim_sources": {"src1": {"endpoint": "https://graph.example.invalid/getMemberObjects"}},
        }));
    }

    /// Turns on the `client_credentials` grant (it answers `graph_at_<n>`) and
    /// the Graph route `/v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group`,
    /// which needs such a token and lists `groups` for any user, two to a
    /// page, the next page behind `@odata.nextLink`.
    pub fn set_graph(&self, groups: &[&str]) {
        let mut state = self.state.lock().unwrap();
        state.graph = true;
        state.graph_groups = groups.iter().map(|group| (*group).to_string()).collect();
    }

    /// Whether the Graph route answers 500 instead of its groups.
    pub fn set_graph_failing(&self, failing: bool) {
        self.state.lock().unwrap().graph_failing = failing;
    }

    /// The URI (path and query) of every Graph request so far, oldest first.
    pub fn graph_requests(&self) -> Vec<String> {
        self.state.lock().unwrap().graph_requests.clone()
    }

    /// Whether discovery advertises `end_session_endpoint`.
    pub fn set_end_session(&self, enabled: bool) {
        self.state.lock().unwrap().end_session = enabled;
    }

    /// The query of the last `GET /logout` (`id_token_hint`,
    /// `post_logout_redirect_uri`, ...).
    pub fn last_logout(&self) -> Option<HashMap<String, String>> {
        self.state.lock().unwrap().last_logout.clone()
    }

    /// The ID token the token endpoint answered last.
    pub fn last_id_token(&self) -> Option<String> {
        self.state.lock().unwrap().last_id_token.clone()
    }

    /// Whether the code exchange returns a refresh token (`refresh_<n>`) and
    /// the `refresh_token` grant is accepted (it answers `idp_at_<n>`).
    pub fn set_refresh_tokens(&self, enabled: bool) {
        self.state.lock().unwrap().refresh_tokens = enabled;
    }

    /// Whether the RFC 8693 token exchange and the `jwt-bearer` (Entra
    /// on-behalf-of) grants are accepted; both answer `exchanged_<n>`.
    pub fn set_token_exchange(&self, enabled: bool) {
        self.state.lock().unwrap().token_exchange = enabled;
    }

    /// The form of every token endpoint request so far, oldest first.
    pub fn token_forms(&self) -> Vec<HashMap<String, String>> {
        self.state.lock().unwrap().forms.clone()
    }

    /// The forms of the token endpoint requests with `grant_type`.
    pub fn token_forms_for(&self, grant_type: &str) -> Vec<HashMap<String, String>> {
        self.token_forms()
            .into_iter()
            .filter(|form| {
                form.get("grant_type")
                    .is_some_and(|grant| grant == grant_type)
            })
            .collect()
    }

    /// A JWT access token signed by this provider, for resource-server mode:
    /// `iss`, `aud` (the client id), `sub` (`alice`), `iat` and `exp` are set,
    /// then `claims` is merged on top (a `null` removes a claim).
    pub fn mint_access_token(&self, claims: &Value) -> String {
        let state = self.state.lock().unwrap();
        let now = unix_now();
        let mut token_claims = json!({
            "iss": state.issuer,
            "aud": state.client_id,
            "sub": "alice",
            "iat": now,
            "exp": now + TOKEN_LIFETIME,
        });
        for (name, value) in claims.as_object().expect("claims is an object") {
            if value.is_null() {
                token_claims.as_object_mut().unwrap().remove(name);
            } else {
                token_claims[name] = value.clone();
            }
        }
        sign(&state, &token_claims)
    }
}

async fn discovery(State(state): State<Shared>) -> Json<Value> {
    let state = state.lock().unwrap();
    let issuer = &state.issuer;
    let mut doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "id_token_signing_alg_values_supported": ["ES256"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "code_challenge_methods_supported": ["S256"],
    });
    if state.end_session {
        doc["end_session_endpoint"] = json!(format!("{issuer}/logout"));
    }
    Json(doc)
}

async fn jwks(State(state): State<Shared>) -> Json<Value> {
    let state = state.lock().unwrap();
    // The uncompressed point: 0x04, then x and y.
    let point = state.key.public_key().as_ref();
    Json(json!({"keys": [{
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": KID,
        "x": b64(&point[1..33]), "y": b64(&point[33..65]),
    }]}))
}

fn bad_request(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": error}))).into_response()
}

async fn authorize(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let get = |name: &str| query.get(name).cloned().unwrap_or_default();
    let mut state = state.lock().unwrap();
    if get("client_id") != state.client_id || get("code_challenge_method") != "S256" {
        return bad_request("invalid_request");
    }

    let mut raw = [0u8; 24];
    aws_lc_rs::rand::fill(&mut raw).expect("random code");
    let code = b64(&raw);
    state.codes.insert(
        code.clone(),
        Grant {
            redirect_uri: get("redirect_uri"),
            nonce: get("nonce"),
            code_challenge: get("code_challenge"),
        },
    );

    let redirect_uri = get("redirect_uri");
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!(
        "{redirect_uri}{separator}code={}&state={}",
        encode(&code),
        encode(&get("state"))
    );
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// A JWT of `claims` signed with the provider's key.
fn sign(state: &ProviderState, claims: &Value) -> String {
    let header = json!({"alg": "ES256", "kid": KID, "typ": "JWT"});
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let signature = state
        .key
        .sign(&SystemRandom::new(), input.as_bytes())
        .expect("sign token");
    format!("{input}.{}", b64(signature.as_ref()))
}

async fn token(State(state): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Response {
    let mut state = state.lock().unwrap();
    state.forms.push(form.clone());
    match form.get("grant_type").map_or("", String::as_str) {
        "authorization_code" => code_grant(&mut state, &form),
        "refresh_token" if state.refresh_tokens => refresh_grant(&mut state, &form),
        GRANT_TOKEN_EXCHANGE | GRANT_JWT_BEARER if state.token_exchange => {
            exchange_grant(&mut state, &form)
        }
        GRANT_CLIENT_CREDENTIALS if state.graph => graph_token_grant(&mut state, &form),
        _ => bad_request("unsupported_grant_type"),
    }
}

fn code_grant(state: &mut ProviderState, form: &HashMap<String, String>) -> Response {
    let get = |name: &str| form.get(name).map_or("", String::as_str);
    // One-time: the code is gone whether or not the rest checks out.
    let Some(grant) = state.codes.remove(get("code")) else {
        return bad_request("invalid_grant");
    };
    let challenge = b64(&Sha256::digest(get("code_verifier").as_bytes()));
    if challenge != grant.code_challenge || get("redirect_uri") != grant.redirect_uri {
        return bad_request("invalid_grant");
    }

    let now = unix_now();
    let mut claims = state.user.clone();
    claims["iss"] = json!(state.issuer);
    claims["aud"] = json!(state.client_id);
    claims["nonce"] = json!(grant.nonce);
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + TOKEN_LIFETIME);

    let id_token = sign(state, &claims);
    state.last_id_token = Some(id_token.clone());

    let mut response = json!({
        "access_token": b64(&Sha256::digest(id_token.as_bytes())),
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
        "id_token": id_token,
    });
    if state.refresh_tokens {
        state.issued += 1;
        let refresh_token = format!("refresh_{}", state.issued);
        state.refresh_valid.insert(refresh_token.clone());
        response["refresh_token"] = json!(refresh_token);
    }
    Json(response).into_response()
}

/// A refresh token that was issued (it is not rotated) gets a fresh access token.
fn refresh_grant(state: &mut ProviderState, form: &HashMap<String, String>) -> Response {
    let token = form.get("refresh_token").map_or("", String::as_str);
    if !state.refresh_valid.contains(token) {
        return bad_request("invalid_grant");
    }
    state.issued += 1;
    Json(json!({
        "access_token": format!("idp_at_{}", state.issued),
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
    }))
    .into_response()
}

/// RFC 8693 token exchange (`subject_token`) or on-behalf-of (`assertion`).
fn exchange_grant(state: &mut ProviderState, form: &HashMap<String, String>) -> Response {
    let get = |name: &str| form.get(name).map_or("", String::as_str);
    let valid = if get("grant_type") == GRANT_JWT_BEARER {
        !get("assertion").is_empty() && get("requested_token_use") == "on_behalf_of"
    } else {
        !get("subject_token").is_empty()
    };
    if !valid {
        return bad_request("invalid_request");
    }
    state.issued += 1;
    Json(json!({
        "access_token": format!("exchanged_{}", state.issued),
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
    }))
    .into_response()
}

/// The app's client credentials, in the form body, for the Graph `.default`
/// scope (the mock serves Graph itself, so that is `{issuer}/.default`).
fn graph_token_grant(state: &mut ProviderState, form: &HashMap<String, String>) -> Response {
    let get = |name: &str| form.get(name).map_or("", String::as_str);
    if get("client_id") != state.client_id || get("client_secret").is_empty() {
        return bad_request("invalid_client");
    }
    if get("scope") != format!("{}/.default", state.issuer) {
        return bad_request("invalid_scope");
    }
    state.issued += 1;
    let token = format!("graph_at_{}", state.issued);
    state.graph_tokens.insert(token.clone());
    Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
    }))
    .into_response()
}

/// Graph's `transitiveMemberOf/microsoft.graph.group`: a bearer token from the
/// `client_credentials` grant, `$select=id,displayName` and `page` (the
/// `@odata.nextLink` cursor, from 0) are required.
async fn graph_member_of(
    State(state): State<Shared>,
    Path(oid): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let mut state = state.lock().unwrap();
    state.graph_requests.push(uri_text(&uri));
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !state.graph || !state.graph_tokens.contains(bearer) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "InvalidAuthenticationToken"})),
        )
            .into_response();
    }
    if state.graph_failing {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if query.get("$select").map(String::as_str) != Some("id,displayName") {
        return bad_request("missing $select");
    }
    let page: usize = query
        .get("page")
        .and_then(|page| page.parse().ok())
        .unwrap_or(0);
    let groups: Vec<&String> = state
        .graph_groups
        .chunks(GRAPH_PAGE_SIZE)
        .nth(page)
        .map(|chunk| chunk.iter().collect())
        .unwrap_or_default();
    let value: Vec<Value> = groups
        .into_iter()
        .map(|group| {
            json!({"@odata.type": "#microsoft.graph.group", "id": group, "displayName": group})
        })
        .collect();
    let mut body = json!({"value": value});
    if (page + 1) * GRAPH_PAGE_SIZE < state.graph_groups.len() {
        body["@odata.nextLink"] = json!(format!(
            "{}/v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group?$select=id,displayName&page={}",
            state.issuer,
            page + 1
        ));
    }
    Json(body).into_response()
}

fn uri_text(uri: &Uri) -> String {
    uri.path_and_query()
        .map_or_else(|| uri.path().to_string(), ToString::to_string)
}

async fn logout(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> &'static str {
    state.lock().unwrap().last_logout = Some(query);
    "logged out"
}
