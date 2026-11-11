//! In-process mock `OAuth` authorization server for the gateway's upstream
//! `OAuth` (a user connecting a catalog backend with their own account).
//!
//! One axum server on an ephemeral loopback port serves RFC 8414 metadata with
//! switches for dynamic client registration, client ID metadata documents and
//! the RFC 9207 `iss` parameter, `POST /register`, an authorization endpoint
//! that approves every request on the spot (it checks what a real server would:
//! `response_type`, S256 PKCE, `resource` and the client and its redirect URI)
//! and a token endpoint for the authorization code and refresh token grants
//! (PKCE verified, refresh tokens rotated). Access tokens are opaque
//! (`up_at_<n>`) and every request is recorded for the tests to assert on.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// What an issued authorization code is bound to.
struct AuthCode {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    resource: String,
}

/// One request the token endpoint got, and what it answered.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    /// The form fields (`grant_type`, `code`, `refresh_token`, `resource`, ...).
    pub form: HashMap<String, String>,
    /// The `Authorization` header (client authentication), if any.
    pub authorization: Option<String>,
    /// The access token issued; `None` when the request was refused.
    pub access_token: Option<String>,
}

impl TokenRequest {
    /// The form field `name`, or `""`.
    pub fn field(&self, name: &str) -> &str {
        self.form.get(name).map_or("", String::as_str)
    }
}

struct UpstreamState {
    issuer: String,
    dcr: bool,
    cimd: bool,
    iss_parameter: bool,
    expires_in: u64,
    /// Clients configured out of band (a static client of the gateway config).
    known_clients: HashSet<String>,
    /// Registered client id to its redirect URIs.
    registered: HashMap<String, Vec<String>>,
    registrations: Vec<Value>,
    authorizations: Vec<HashMap<String, String>>,
    codes: HashMap<String, AuthCode>,
    /// Refresh token to the client it belongs to.
    refresh_tokens: HashMap<String, String>,
    /// Counter behind client ids, codes and tokens.
    seq: u64,
    token_requests: Vec<TokenRequest>,
}

type Shared = Arc<Mutex<UpstreamState>>;

/// A running mock authorization server. The server stops on drop.
pub struct MockUpstream {
    issuer: String,
    state: Shared,
    task: JoinHandle<()>,
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Builder for a [`MockUpstream`]; by default it supports dynamic client
/// registration only and issues tokens that live an hour.
pub struct MockUpstreamBuilder {
    dcr: bool,
    cimd: bool,
    iss_parameter: bool,
    expires_in: u64,
    known_clients: HashSet<String>,
}

impl MockUpstreamBuilder {
    /// Whether the metadata advertises `registration_endpoint`.
    pub fn dcr(mut self, enabled: bool) -> Self {
        self.dcr = enabled;
        self
    }

    /// Whether the metadata says `client_id_metadata_document_supported`.
    pub fn cimd(mut self, enabled: bool) -> Self {
        self.cimd = enabled;
        self
    }

    /// Whether the metadata says `authorization_response_iss_parameter_supported`
    /// (and the authorization response then carries `iss`).
    pub fn iss_parameter(mut self, enabled: bool) -> Self {
        self.iss_parameter = enabled;
        self
    }

    /// The `expires_in` of every access token, in seconds.
    pub fn expires_in(mut self, seconds: u64) -> Self {
        self.expires_in = seconds;
        self
    }

    /// A client the server knows without registration (a static client).
    pub fn known_client(mut self, client_id: &str) -> Self {
        self.known_clients.insert(client_id.to_string());
        self
    }

    pub async fn start(self) -> MockUpstream {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock upstream");
        let port = listener.local_addr().expect("local addr").port();
        let issuer = format!("http://127.0.0.1:{port}");

        let state = Arc::new(Mutex::new(UpstreamState {
            issuer: issuer.clone(),
            dcr: self.dcr,
            cimd: self.cimd,
            iss_parameter: self.iss_parameter,
            expires_in: self.expires_in,
            known_clients: self.known_clients,
            registered: HashMap::new(),
            registrations: Vec::new(),
            authorizations: Vec::new(),
            codes: HashMap::new(),
            refresh_tokens: HashMap::new(),
            seq: 0,
            token_requests: Vec::new(),
        }));

        let app = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(auth_server_metadata),
            )
            .route("/register", post(register))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock upstream");
        });

        MockUpstream {
            issuer,
            state,
            task,
        }
    }
}

impl MockUpstream {
    /// A builder: registration only, tokens valid for an hour.
    pub fn builder() -> MockUpstreamBuilder {
        MockUpstreamBuilder {
            dcr: true,
            cimd: false,
            iss_parameter: false,
            expires_in: 3600,
            known_clients: HashSet::new(),
        }
    }

    /// A server with the defaults of [`MockUpstream::builder`].
    pub async fn start() -> Self {
        Self::builder().start().await
    }

    /// The issuer, which is also the origin of every endpoint.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The JSON body of every `POST /register`, oldest first.
    pub fn registrations(&self) -> Vec<Value> {
        self.state.lock().unwrap().registrations.clone()
    }

    /// The query of every `GET /authorize`, oldest first.
    pub fn authorize_requests(&self) -> Vec<HashMap<String, String>> {
        self.state.lock().unwrap().authorizations.clone()
    }

    /// Every token endpoint request, oldest first.
    pub fn token_requests(&self) -> Vec<TokenRequest> {
        self.state.lock().unwrap().token_requests.clone()
    }

    /// The token endpoint requests with `grant_type`, oldest first.
    pub fn token_requests_for(&self, grant_type: &str) -> Vec<TokenRequest> {
        self.token_requests()
            .into_iter()
            .filter(|request| request.field("grant_type") == grant_type)
            .collect()
    }

    /// Every access token issued so far, oldest first.
    pub fn issued_access_tokens(&self) -> Vec<String> {
        self.token_requests()
            .into_iter()
            .filter_map(|request| request.access_token)
            .collect()
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(json!({"error": error, "error_description": description})),
    )
        .into_response()
}

fn bad_request(error: &str, description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, error, description)
}

async fn auth_server_metadata(State(state): State<Shared>) -> Json<Value> {
    let state = state.lock().unwrap();
    let issuer = &state.issuer;
    let mut doc = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    });
    if state.dcr {
        doc["registration_endpoint"] = json!(format!("{issuer}/register"));
    }
    if state.cimd {
        doc["client_id_metadata_document_supported"] = json!(true);
    }
    if state.iss_parameter {
        doc["authorization_response_iss_parameter_supported"] = json!(true);
    }
    Json(doc)
}

async fn register(State(state): State<Shared>, Json(body): Json<Value>) -> Response {
    let redirect_uris: Vec<String> = body["redirect_uris"]
        .as_array()
        .map(|uris| {
            uris.iter()
                .filter_map(|uri| uri.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if redirect_uris.is_empty() {
        return bad_request("invalid_redirect_uri", "no redirect_uris");
    }
    let mut state = state.lock().unwrap();
    state.registrations.push(body);
    state.seq += 1;
    let client_id = format!("dcr-client-{}", state.seq);
    state
        .registered
        .insert(client_id.clone(), redirect_uris.clone());
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
        })),
    )
        .into_response()
}

/// How the client of an authorization request is known.
enum ClientKind {
    Registered(Vec<String>),
    Known,
    /// A client ID metadata document at the client id URL.
    Document,
    Unknown,
}

async fn authorize(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let get = |name: &str| query.get(name).map_or("", String::as_str);
    let kind = {
        let mut state = state.lock().unwrap();
        state.authorizations.push(query.clone());
        let client_id = get("client_id");
        if let Some(uris) = state.registered.get(client_id) {
            ClientKind::Registered(uris.clone())
        } else if state.known_clients.contains(client_id) {
            ClientKind::Known
        } else if state.cimd && client_id.starts_with("http") {
            ClientKind::Document
        } else {
            ClientKind::Unknown
        }
    };

    if get("response_type") != "code" {
        return bad_request("unsupported_response_type", "response_type must be code");
    }
    if get("code_challenge").is_empty() || get("code_challenge_method") != "S256" {
        return bad_request("invalid_request", "an S256 code_challenge is required");
    }
    if get("resource").is_empty() {
        return bad_request("invalid_target", "resource is required");
    }
    let redirect_uri = get("redirect_uri");
    let redirect_ok = match kind {
        ClientKind::Registered(uris) => uris.iter().any(|uri| uri == redirect_uri),
        ClientKind::Known => redirect_uri.ends_with("/oauth/upstream/callback"),
        ClientKind::Document => {
            // What a real server does: fetch the document the client id names
            // and take the redirect URI from it.
            let document: Value = match reqwest::get(get("client_id")).await {
                Ok(response) if response.status().is_success() => {
                    response.json().await.unwrap_or(Value::Null)
                }
                _ => Value::Null,
            };
            document["client_id"] == get("client_id")
                && document["redirect_uris"]
                    .as_array()
                    .is_some_and(|uris| uris.iter().any(|uri| uri == redirect_uri))
        }
        ClientKind::Unknown => {
            return bad_request("invalid_client", "unknown client_id");
        }
    };
    if !redirect_ok {
        return bad_request("invalid_request", "redirect_uri is not registered");
    }

    let mut state = state.lock().unwrap();
    state.seq += 1;
    let code = format!("upcode-{}", state.seq);
    state.codes.insert(
        code.clone(),
        AuthCode {
            client_id: get("client_id").to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: get("code_challenge").to_string(),
            resource: get("resource").to_string(),
        },
    );

    let Ok(mut location) = Url::parse(redirect_uri) else {
        return bad_request("invalid_request", "redirect_uri is not a URL");
    };
    {
        let mut pairs = location.query_pairs_mut();
        pairs.append_pair("code", &code);
        if !get("state").is_empty() {
            pairs.append_pair("state", get("state"));
        }
        if state.iss_parameter {
            pairs.append_pair("iss", &state.issuer);
        }
    }
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// The client id the request authenticates as: the `client_id` field, or the
/// user of a `Basic` header.
fn requesting_client(form: &HashMap<String, String>, authorization: Option<&str>) -> String {
    if let Some(id) = form.get("client_id") {
        return id.clone();
    }
    authorization
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|pair| pair.split_once(':').map(|(user, _)| user.to_string()))
        .unwrap_or_default()
}

/// A fresh access and refresh token for `client_id`, as a token response.
fn issue(state: &mut UpstreamState, client_id: &str) -> Value {
    state.seq += 1;
    let refresh_token = format!("up_rt_{}", state.seq);
    state
        .refresh_tokens
        .insert(refresh_token.clone(), client_id.to_string());
    json!({
        "access_token": format!("up_at_{}", state.seq),
        "token_type": "Bearer",
        "expires_in": state.expires_in,
        "refresh_token": refresh_token,
    })
}

/// Runs the grant of `form`: the token response, or the OAuth error code.
fn grant(
    state: &mut UpstreamState,
    form: &HashMap<String, String>,
    client_id: &str,
) -> Result<Value, &'static str> {
    let get = |name: &str| form.get(name).map_or("", String::as_str);
    match get("grant_type") {
        "authorization_code" => {
            // One-time: the code is gone whether or not the rest checks out.
            let code = state.codes.remove(get("code")).ok_or("invalid_grant")?;
            let challenge = b64(&Sha256::digest(get("code_verifier").as_bytes()));
            if code.client_id != client_id
                || challenge != code.code_challenge
                || get("redirect_uri") != code.redirect_uri
            {
                return Err("invalid_grant");
            }
            if get("resource") != code.resource {
                return Err("invalid_target");
            }
            Ok(issue(state, client_id))
        }
        "refresh_token" => {
            // Rotation: the old refresh token is used up.
            let owner = state
                .refresh_tokens
                .remove(get("refresh_token"))
                .ok_or("invalid_grant")?;
            if owner != client_id {
                return Err("invalid_grant");
            }
            Ok(issue(state, client_id))
        }
        _ => Err("unsupported_grant_type"),
    }
}

async fn token(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let client_id = requesting_client(&form, authorization.as_deref());
    let mut state = state.lock().unwrap();
    let result = grant(&mut state, &form, &client_id);
    let access_token = result
        .as_ref()
        .ok()
        .and_then(|response| response["access_token"].as_str().map(str::to_string));
    state.token_requests.push(TokenRequest {
        form,
        authorization,
        access_token,
    });
    match result {
        Ok(response) => Json(response).into_response(),
        Err(error) => bad_request(error, "the mock authorization server refused the grant"),
    }
}
