//! In-process mock `OpenID` Connect identity provider for integration tests.
//!
//! One axum server on an ephemeral loopback port serves discovery, the key
//! set, an authorization endpoint that approves every request on the spot (no
//! login form), the token endpoint and an end-session endpoint. ID tokens are
//! signed with a P-256 key generated per provider (ES256), and the code flow
//! enforces PKCE (S256), so the gateway runs a real login against it.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use axum::extract::{Form, Query, State};
use axum::http::{StatusCode, header};
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

struct ProviderState {
    issuer: String,
    client_id: String,
    key: EcdsaKeyPair,
    user: Value,
    end_session: bool,
    codes: HashMap<String, Grant>,
    last_logout: Option<HashMap<String, String>>,
    last_id_token: Option<String>,
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
        }));

        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/logout", get(logout))
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
    let get = |name: &str| form.get(name).map_or("", String::as_str);
    let mut state = state.lock().unwrap();
    if get("grant_type") != "authorization_code" {
        return bad_request("unsupported_grant_type");
    }
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

    let id_token = sign(&state, &claims);
    state.last_id_token = Some(id_token.clone());

    Json(json!({
        "access_token": b64(&Sha256::digest(id_token.as_bytes())),
        "token_type": "Bearer",
        "expires_in": TOKEN_LIFETIME,
        "id_token": id_token,
    }))
    .into_response()
}

async fn logout(
    State(state): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> &'static str {
    state.lock().unwrap().last_logout = Some(query);
    "logged out"
}
