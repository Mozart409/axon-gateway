//! The MCP OAuth authorization server (OAuth 2.1 for MCP clients).
//!
//! Only in multi-user mode (`[database]` and `[auth.oidc]`): [`routes`] registers nothing
//! otherwise. The issuer is `[gateway] base_url`. Clients register themselves (RFC 7591,
//! open, rate limited) or are named by the URL of a metadata document the gateway fetches
//! through the egress guard. The user logs in with the dashboard login and approves on the
//! consent page ([`super::oauth_ui`]); the token endpoint then issues opaque, hashed,
//! rotating tokens ([`crate::store`]). An access token authenticates the MCP endpoints
//! only, and only the endpoint it was issued for (`resource`, RFC 8707).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oauth2::url::form_urlencoded;
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Value, json};

use super::AppState;
use super::auth::ClientIp;
use super::oauth_views::render_error_page;
use crate::egress::EgressPolicy;
use crate::gateway::Caller;
use crate::policy::OptOuts;
use crate::principal::{PrincipalPolicy, TokenScope};
use crate::store::{
    ACCESS_TOKEN_TTL, AccessLookup, AuthRequest, CodeRedemption, IssuedOauthTokens, NewAuthRequest,
    NewOauthClient, OauthClient, Store, StoreError,
};

/// The one scope
const MCP_SCOPE: &str = "mcp";
/// Longest `client_name` a registration may carry, in characters
const MAX_CLIENT_NAME_CHARS: usize = 200;
/// Most redirect URIs a client may register
const MAX_REDIRECT_URIS: usize = 10;
/// Longest redirect URI, in bytes
const MAX_REDIRECT_URI_LEN: usize = 2048;
/// Longest `state` the authorization endpoint echoes, in bytes
const MAX_STATE_LEN: usize = 512;
/// Per client IP and minute: registrations
const REGISTER_LIMIT: u32 = 10;
/// Per client IP and minute: token and revocation requests
const TOKEN_LIMIT: u32 = 60;
/// Per client IP and minute: authorization requests
const AUTHORIZE_LIMIT: u32 = 60;
/// Largest client metadata document accepted
const CIMD_MAX_BYTES: usize = 64 * 1024;
/// How long fetching a client metadata document may take
const CIMD_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a fetched document is reused, per replica
const CIMD_TTL: Duration = Duration::from_mins(10);
/// Most documents kept in memory
const CIMD_CACHE_MAX: usize = 256;

/// The public routes: metadata, registration, authorization start, token and revocation.
/// Empty outside multi-user mode.
pub(super) fn routes(state: &AppState) -> Router<AppState> {
    if state.multi_user().is_none() {
        return Router::new();
    }
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_default),
        )
        .route(
            "/.well-known/oauth-protected-resource/{*path}",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server),
        )
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
}

/// The issuer and base of every URL we hand out: `base_url` without a trailing slash
pub(super) fn base(state: &AppState) -> &str {
    state.base_url.trim_end_matches('/')
}

/// A client as the authorization endpoint needs it
#[derive(Debug, Clone)]
struct ClientInfo {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

enum ClientError {
    /// The client cannot be used; the message is safe to show
    Invalid(String),
    Store(StoreError),
}

/// The metadata document documents' in-memory cache, per replica
static CIMD_CACHE: LazyLock<Mutex<HashMap<String, (Instant, ClientInfo)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---- metadata -------------------------------------------------------------------------

/// `GET /.well-known/oauth-protected-resource` (RFC 9728): the resource is `/mcp`
async fn protected_resource_default(State(state): State<AppState>) -> Response {
    Json(resource_metadata(base(&state), "mcp")).into_response()
}

/// `GET /.well-known/oauth-protected-resource/{path}`: for the MCP endpoint at `/{path}`
async fn protected_resource(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    let is_mcp = path == "mcp" || path.starts_with("mcp/");
    if !is_mcp || !path.bytes().all(|b| b.is_ascii_graphic()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(resource_metadata(base(&state), &path)).into_response()
}

fn resource_metadata(base: &str, path: &str) -> Value {
    json!({
        "resource": format!("{base}/{path}"),
        "authorization_servers": [base],
        "scopes_supported": [MCP_SCOPE],
        "bearer_methods_supported": ["header"],
    })
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414)
async fn authorization_server(State(state): State<AppState>) -> Response {
    let base = base(&state);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "revocation_endpoint": format!("{base}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": [MCP_SCOPE],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
    }))
    .into_response()
}

// ---- the 401 challenge and the audience -----------------------------------------------

/// The MCP endpoint's resource URL for a request path (`/mcp/group/` is the old spelling of
/// `/mcp/toolset/`)
fn endpoint_resource(base: &str, path: &str) -> String {
    let path = path.trim_end_matches('/');
    match path.strip_prefix("/mcp/group/") {
        Some(name) => format!("{base}/mcp/toolset/{name}"),
        None => format!("{base}{path}"),
    }
}

fn challenge(base: &str, path: &str, invalid_token: bool) -> String {
    let metadata =
        format!("resource_metadata=\"{base}/.well-known/oauth-protected-resource{path}\"");
    if invalid_token {
        format!("Bearer error=\"invalid_token\", {metadata}")
    } else {
        format!("Bearer {metadata}")
    }
}

fn set_challenge(response: &mut Response, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
}

/// A refused MCP request in multi-user mode: its 401 points the client at the protected
/// resource metadata. Anything else is returned as it is.
pub(super) fn with_challenge(mut response: Response, state: &AppState, path: &str) -> Response {
    if state.multi_user().is_some() && response.status() == StatusCode::UNAUTHORIZED {
        set_challenge(&mut response, &challenge(base(state), path, false));
    }
    response
}

/// The 401 for a caller whose OAuth access token is for another MCP endpoint, or `None`
/// when the caller may use the endpoint at `path`.
pub(super) fn refuse_wrong_audience(
    caller: &Caller,
    state: &AppState,
    path: &str,
) -> Option<Response> {
    let Caller::Principal(principal) = caller else {
        return None;
    };
    let resource = principal.resource()?;
    let base = base(state);
    if resource == endpoint_resource(base, path) || resource == format!("{base}/mcp") {
        return None;
    }
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    set_challenge(&mut response, &challenge(base, path, true));
    Some(response)
}

// ---- clients --------------------------------------------------------------------------

fn is_loopback_host(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// A redirect URI a client may register: `https`, or `http` to a loopback host; no
/// fragment, no credentials.
fn valid_redirect_uri(raw: &str) -> bool {
    if raw.len() > MAX_REDIRECT_URI_LEN || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return false;
    }
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some_and(|host| !host.is_empty()),
        "http" => is_loopback_host(&url),
        _ => false,
    }
}

/// Whether a redirect URI of an authorization request is one the client registered: exact,
/// except that a loopback URI may use another port (RFC 8252 section 7.3).
fn redirect_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(registered), Ok(requested)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    registered.scheme() == "http"
        && requested.scheme() == "http"
        && is_loopback_host(&registered)
        && registered.host_str() == requested.host_str()
        && registered.path() == requested.path()
        && registered.query() == requested.query()
}

/// The redirect URIs of a registration or metadata document, or why they are refused
fn validate_redirect_uris(uris: &[String]) -> Result<(), String> {
    if uris.is_empty() {
        return Err(String::from("redirect_uris is required"));
    }
    if uris.len() > MAX_REDIRECT_URIS {
        return Err(format!("at most {MAX_REDIRECT_URIS} redirect_uris"));
    }
    if let Some(bad) = uris.iter().find(|uri| !valid_redirect_uri(uri)) {
        return Err(format!(
            "redirect URI {bad:?} must be https, or http to 127.0.0.1, [::1] or localhost"
        ));
    }
    Ok(())
}

/// The host of a client id that is a metadata document URL, `None` for a registered client
pub(super) fn cimd_host(client_id: &str) -> Option<String> {
    cimd_url(client_id)?.host_str().map(str::to_owned)
}

/// A client id that is an `https://` URL with a path names a metadata document
fn cimd_url(client_id: &str) -> Option<Url> {
    let url = Url::parse(client_id).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.path().len() > 1
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none())
    .then_some(url)
}

/// The metadata document's fields that matter
#[derive(Deserialize)]
struct ClientDocument {
    client_id: String,
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
}

fn parse_client_document(client_id: &str, body: &[u8]) -> Result<ClientInfo, String> {
    let document: ClientDocument = serde_json::from_slice(body)
        .map_err(|_| String::from("the client metadata document is not valid JSON"))?;
    if document.client_id != client_id {
        return Err(String::from(
            "the client_id in the metadata document is not its URL",
        ));
    }
    if document
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method != "none")
    {
        return Err(String::from(
            "the client metadata document must not ask for client authentication",
        ));
    }
    validate_redirect_uris(&document.redirect_uris)?;
    Ok(ClientInfo {
        client_name: document
            .client_name
            .map(|name| name.chars().take(MAX_CLIENT_NAME_CHARS).collect()),
        redirect_uris: document.redirect_uris,
    })
}

/// Fetches a client metadata document: GET, JSON, at most 64 KiB, 5 seconds, no redirects,
/// through the egress guard with its default rules (no private or loopback addresses; the
/// personal backends' allow list does not apply to strangers' documents).
async fn fetch_client_document(client_id: &str) -> Result<ClientInfo, String> {
    let policy = EgressPolicy::new(&[], &[]).map_err(|error| error.to_string())?;
    let target = policy
        .check_url(client_id)
        .await
        .map_err(|error| format!("the client metadata URL is refused: {error}"))?;
    let client = target
        .client(CIMD_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let unreachable = |_| String::from("the client metadata document could not be fetched");
    let mut response = client
        .get(client_id)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(unreachable)?;
    if !response.status().is_success() {
        return Err(format!(
            "the client metadata document answered {}",
            response.status()
        ));
    }
    let too_large = || String::from("the client metadata document is too large");
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).is_ok_and(|length| length > CIMD_MAX_BYTES))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(unreachable)? {
        if body.len() + chunk.len() > CIMD_MAX_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    parse_client_document(client_id, &body)
}

fn cached_client_document(client_id: &str) -> Option<ClientInfo> {
    let cache = CIMD_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    cache
        .get(client_id)
        .filter(|(fetched, _)| fetched.elapsed() < CIMD_TTL)
        .map(|(_, info)| info.clone())
}

fn cache_client_document(client_id: &str, info: &ClientInfo) {
    let mut cache = CIMD_CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if cache.len() >= CIMD_CACHE_MAX {
        cache.retain(|_, (fetched, _)| fetched.elapsed() < CIMD_TTL);
    }
    if cache.len() < CIMD_CACHE_MAX {
        cache.insert(client_id.to_owned(), (Instant::now(), info.clone()));
    }
}

fn registered_client(client: OauthClient) -> ClientInfo {
    ClientInfo {
        client_name: client.client_name,
        redirect_uris: client.redirect_uris,
    }
}

/// The client behind a `client_id`: a metadata document (cached) or a registration.
/// `None` when there is no such registration.
async fn resolve_client(store: &Store, client_id: &str) -> Result<Option<ClientInfo>, ClientError> {
    if cimd_url(client_id).is_some() {
        if let Some(info) = cached_client_document(client_id) {
            return Ok(Some(info));
        }
        let info = fetch_client_document(client_id)
            .await
            .map_err(ClientError::Invalid)?;
        cache_client_document(client_id, &info);
        return Ok(Some(info));
    }
    let client = store
        .oauth_client(client_id)
        .await
        .map_err(ClientError::Store)?;
    Ok(client.map(registered_client))
}

// ---- responses ------------------------------------------------------------------------

/// An OAuth JSON error (RFC 6749 section 5.2, RFC 7591 section 3.2.2)
fn json_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn bad_request(error: &str, description: &str) -> Response {
    json_error(StatusCode::BAD_REQUEST, error, description)
}

fn too_many_requests() -> Response {
    json_error(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "too many requests, try again in a minute",
    )
}

fn server_error(error: &StoreError) -> Response {
    tracing::error!(%error, "An OAuth request failed in the database");
    json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_error",
        "the database is unavailable",
    )
}

/// The HTML page of an authorization request that must not redirect
pub(super) fn error_page(
    state: &AppState,
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    (
        status,
        [(header::X_FRAME_OPTIONS, "DENY")],
        Html(render_error_page(state, title, message).into_string()),
    )
        .into_response()
}

/// Counts a request per client IP in the shared Postgres window: `false` when the limit is
/// used up. A store error lets the request through, as for the token limits.
async fn within_limit(store: &Store, scope: &str, client_ip: Option<&str>, limit: u32) -> bool {
    let key = format!("oauth_{scope}:{}", client_ip.unwrap_or("unknown"));
    match store.hit_rate_limit(&key, limit).await {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(%error, key, "Rate limit check failed, letting the request through");
            true
        }
    }
}

/// Redirects the browser to the client's redirect URI with `params`, the client's `state`
/// and the issuer (RFC 9207). `redirect_uri` has been matched against the client's
/// registration.
pub(super) fn redirect_to_client(
    state: &AppState,
    redirect_uri: &str,
    client_state: Option<&str>,
    params: &[(&str, &str)],
) -> Response {
    let Ok(mut url) = Url::parse(redirect_uri) else {
        return error_page(
            state,
            StatusCode::BAD_REQUEST,
            "Invalid redirect",
            "The redirect URI of this request is not valid.",
        );
    };
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in params {
            query.append_pair(name, value);
        }
        if let Some(client_state) = client_state {
            query.append_pair("state", client_state);
        }
        query.append_pair("iss", base(state));
    }
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Redirect::to(url.as_str()),
    )
        .into_response()
}

fn redirect_error(
    state: &AppState,
    redirect_uri: &str,
    client_state: Option<&str>,
    error: &str,
    description: &str,
) -> Response {
    redirect_to_client(
        state,
        redirect_uri,
        client_state,
        &[("error", error), ("error_description", description)],
    )
}

// ---- dynamic client registration ------------------------------------------------------

/// The fields of a registration request that matter; others are ignored
#[derive(Deserialize)]
struct Registration {
    #[serde(default)]
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    client_name: Option<String>,
}

/// A registration that passed validation, defaults filled in
#[derive(Debug, PartialEq, Eq)]
struct ValidRegistration {
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    response_types: Vec<String>,
}

/// An RFC 7591 error code and its description
type RegistrationError = (&'static str, String);

fn subset_or_default(
    given: Option<Vec<String>>,
    allowed: &[&str],
    default: &str,
    field: &str,
) -> Result<Vec<String>, RegistrationError> {
    let given = given.filter(|values| !values.is_empty());
    let Some(given) = given else {
        return Ok(vec![default.to_owned()]);
    };
    if let Some(bad) = given
        .iter()
        .find(|value| !allowed.contains(&value.as_str()))
    {
        return Err((
            "invalid_client_metadata",
            format!("unsupported {field} {bad:?}"),
        ));
    }
    Ok(given)
}

fn validate_registration(body: &[u8]) -> Result<ValidRegistration, RegistrationError> {
    let registration: Registration = serde_json::from_slice(body).map_err(|_| {
        (
            "invalid_client_metadata",
            String::from("the body is not a JSON client metadata object"),
        )
    })?;
    validate_redirect_uris(&registration.redirect_uris)
        .map_err(|message| ("invalid_redirect_uri", message))?;
    if registration
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method != "none")
    {
        return Err((
            "invalid_client_metadata",
            String::from("only token_endpoint_auth_method none is supported"),
        ));
    }
    let grant_types = subset_or_default(
        registration.grant_types,
        &["authorization_code", "refresh_token"],
        "authorization_code",
        "grant_types",
    )?;
    let response_types = subset_or_default(
        registration.response_types,
        &["code"],
        "code",
        "response_types",
    )?;
    let client_name = registration.client_name.filter(|name| !name.is_empty());
    if client_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > MAX_CLIENT_NAME_CHARS)
    {
        return Err((
            "invalid_client_metadata",
            format!("client_name is at most {MAX_CLIENT_NAME_CHARS} characters"),
        ));
    }
    Ok(ValidRegistration {
        client_name,
        redirect_uris: registration.redirect_uris,
        grant_types,
        response_types,
    })
}

/// `POST /oauth/register` (RFC 7591): open registration of a public client
async fn register(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    body: Bytes,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !within_limit(store, "register", client_ip.as_deref(), REGISTER_LIMIT).await {
        return too_many_requests();
    }
    let registration = match validate_registration(&body) {
        Ok(registration) => registration,
        Err((error, description)) => return bad_request(error, &description),
    };
    let client = match store
        .create_oauth_client(&NewOauthClient {
            client_name: registration.client_name.as_deref(),
            redirect_uris: &registration.redirect_uris,
            grant_types: &registration.grant_types,
            response_types: &registration.response_types,
        })
        .await
    {
        Ok(client) => client,
        Err(error) => return server_error(&error),
    };

    let mut metadata = json!({
        "client_id": client.client_id,
        "client_id_issued_at": client.created_at.timestamp(),
        "redirect_uris": client.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": client.grant_types,
        "response_types": client.response_types,
    });
    if let (Some(name), Some(object)) = (client.client_name, metadata.as_object_mut()) {
        object.insert(String::from("client_name"), Value::String(name));
    }
    (
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(metadata),
    )
        .into_response()
}

// ---- authorization endpoint -----------------------------------------------------------

/// `GET /oauth/authorize` parameters; a missing one is checked by the handler
#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
}

/// Whether `resource` is an MCP endpoint of this gateway
fn valid_resource(base: &str, resource: &str) -> bool {
    let Some(rest) = resource
        .strip_prefix(base)
        .and_then(|rest| rest.strip_prefix("/mcp"))
    else {
        return false;
    };
    rest.is_empty()
        || rest.strip_prefix("/toolset/").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        })
}

/// A PKCE challenge is the base64url of a SHA-256: 43 characters
fn valid_code_challenge(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// The PKCE challenge and resource of an authorization request that passed the checks that
/// come after the redirect URI is trusted, or the error to redirect with
fn validate_authorize<'a>(
    base: &str,
    query: &'a AuthorizeQuery,
) -> Result<(&'a str, String), (&'static str, &'static str)> {
    if query
        .state
        .as_deref()
        .is_some_and(|value| value.len() > MAX_STATE_LEN)
    {
        return Err(("invalid_request", "state is too long"));
    }
    if query.response_type.as_deref() != Some("code") {
        return Err((
            "unsupported_response_type",
            "only response_type code is supported",
        ));
    }
    let Some(code_challenge) = query.code_challenge.as_deref() else {
        return Err(("invalid_request", "code_challenge is required"));
    };
    if query.code_challenge_method.as_deref() != Some("S256") {
        return Err((
            "invalid_request",
            "code_challenge_method must be S256; plain is not supported",
        ));
    }
    if !valid_code_challenge(code_challenge) {
        return Err(("invalid_request", "code_challenge is not an S256 challenge"));
    }
    if let Some(scope) = query.scope.as_deref()
        && !scope.split_whitespace().all(|scope| scope == MCP_SCOPE)
    {
        return Err(("invalid_scope", "the only scope is mcp"));
    }
    let resource = query
        .resource
        .clone()
        .unwrap_or_else(|| format!("{base}/mcp"));
    if !valid_resource(base, &resource) {
        return Err((
            "invalid_target",
            "resource must be an MCP endpoint of this gateway",
        ));
    }
    Ok((code_challenge, resource))
}

/// `GET /oauth/authorize`: validates the request, stores it and continues at
/// `/oauth/authorize/continue` (login and consent). A client or redirect URI that cannot be
/// trusted gets an error page, never a redirect.
async fn authorize(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Query(query)) = query else {
        return error_page(
            &state,
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "The authorization request could not be read.",
        );
    };
    if !within_limit(store, "authorize", client_ip.as_deref(), AUTHORIZE_LIMIT).await {
        return error_page(
            &state,
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "Try again in a minute.",
        );
    }

    let refuse =
        |title: &str, message: &str| error_page(&state, StatusCode::BAD_REQUEST, title, message);
    let Some(requested_client) = query.client_id.as_deref().filter(|id| !id.is_empty()) else {
        return refuse("Invalid request", "The request names no client.");
    };
    let client = match resolve_client(store, requested_client).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return refuse(
                "Unknown app",
                "This app is not registered with the gateway.",
            );
        }
        Err(ClientError::Invalid(message)) => return refuse("Unusable app", &message),
        Err(ClientError::Store(error)) => {
            tracing::error!(%error, "Could not look up an OAuth client");
            return error_page(
                &state,
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                "The database did not answer. Try again in a moment.",
            );
        }
    };
    let Some(redirect_uri) = query.redirect_uri.as_deref() else {
        return refuse("Invalid request", "The request names no redirect URI.");
    };
    if !client
        .redirect_uris
        .iter()
        .any(|registered| redirect_matches(registered, redirect_uri))
    {
        return refuse(
            "Invalid redirect URI",
            "The redirect URI is not one this app registered.",
        );
    }

    // From here on the redirect URI is trusted: errors go back to the client
    let client_state = query.state.as_deref();
    let (code_challenge, resource) = match validate_authorize(base(&state), &query) {
        Ok(validated) => validated,
        Err((error, description)) => {
            return redirect_error(&state, redirect_uri, client_state, error, description);
        }
    };
    let fail = |error: &str, description: &str| {
        redirect_error(&state, redirect_uri, client_state, error, description)
    };
    let id = match store
        .create_auth_request(&NewAuthRequest {
            client_id: requested_client,
            client_name: client.client_name.as_deref(),
            redirect_uri,
            code_challenge,
            state: client_state,
            scope: MCP_SCOPE,
            resource: &resource,
        })
        .await
    {
        Ok(id) => id,
        Err(error) => {
            tracing::error!(%error, "Could not store an OAuth authorization request");
            return fail("server_error", "the database is unavailable");
        }
    };
    if let Err(error) = store.touch_oauth_client(requested_client).await {
        tracing::warn!(%error, "Could not note the use of an OAuth client");
    }
    Redirect::to(&format!("/oauth/authorize/continue?request={id}")).into_response()
}

/// Where the pending request's client came from, for the consent page: the host of its
/// metadata document URL
pub(super) fn consent_client_host(request: &AuthRequest) -> Option<String> {
    cimd_host(&request.client_id)
}

// ---- token endpoint -------------------------------------------------------------------

/// The form's fields; `None` when a field repeats (RFC 6749 section 3.2)
fn parse_form(body: &[u8]) -> Option<HashMap<String, String>> {
    let mut fields = HashMap::new();
    for (name, value) in form_urlencoded::parse(body) {
        if fields
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(fields)
}

fn token_response(issued: &IssuedOauthTokens) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL.as_secs(),
            "refresh_token": issued.refresh_token,
            "scope": issued.scope,
        })),
    )
        .into_response()
}

/// `POST /oauth/token`: authorization code with PKCE, or refresh token; public clients
async fn token(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    body: Bytes,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !within_limit(store, "token", client_ip.as_deref(), TOKEN_LIMIT).await {
        return too_many_requests();
    }
    let Some(fields) = parse_form(&body) else {
        return bad_request("invalid_request", "a parameter is repeated");
    };
    let field = |name: &str| {
        fields
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    };

    match field("grant_type") {
        Some("authorization_code") => {
            let (Some(code), Some(redirect_uri), Some(requested_client), Some(code_verifier)) = (
                field("code"),
                field("redirect_uri"),
                field("client_id"),
                field("code_verifier"),
            ) else {
                return bad_request(
                    "invalid_request",
                    "code, redirect_uri, client_id and code_verifier are required",
                );
            };
            if !(43..=128).contains(&code_verifier.len()) {
                return bad_request(
                    "invalid_request",
                    "code_verifier must be 43 to 128 characters",
                );
            }
            if cimd_url(requested_client).is_none() {
                match store.oauth_client(requested_client).await {
                    Ok(Some(_)) => {}
                    Ok(None) => return bad_request("invalid_client", "unknown client_id"),
                    Err(error) => return server_error(&error),
                }
            }
            let redemption = CodeRedemption {
                code,
                client_id: requested_client,
                redirect_uri,
                code_verifier,
                resource: field("resource"),
            };
            match store.redeem_oauth_code(&redemption).await {
                Ok(Some(issued)) => token_response(&issued),
                Ok(None) => bad_request(
                    "invalid_grant",
                    "the code is invalid, expired, already used or does not match this request",
                ),
                Err(error) => server_error(&error),
            }
        }
        Some("refresh_token") => {
            let (Some(refresh_token), Some(requested_client)) =
                (field("refresh_token"), field("client_id"))
            else {
                return bad_request(
                    "invalid_request",
                    "refresh_token and client_id are required",
                );
            };
            match store
                .refresh_oauth_token(refresh_token, requested_client)
                .await
            {
                Ok(Some(issued)) => token_response(&issued),
                Ok(None) => bad_request(
                    "invalid_grant",
                    "the refresh token is invalid, expired or already used",
                ),
                Err(error) => server_error(&error),
            }
        }
        Some(_) => bad_request(
            "unsupported_grant_type",
            "grant_type must be authorization_code or refresh_token",
        ),
        None => bad_request("invalid_request", "grant_type is required"),
    }
}

/// `POST /oauth/revoke` (RFC 7009): revoking either token ends the grant. Always 200.
async fn revoke(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    body: Bytes,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !within_limit(store, "token", client_ip.as_deref(), TOKEN_LIMIT).await {
        return too_many_requests();
    }
    let plaintext = form_urlencoded::parse(&body)
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value.into_owned());
    if let Some(plaintext) = plaintext
        && let Err(error) = store.revoke_oauth_token(&plaintext).await
    {
        tracing::warn!(%error, "Could not revoke an OAuth token");
    }
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

// ---- authenticating an access token ---------------------------------------------------

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

/// 503 for a lookup that failed: the caller cannot be authenticated, which is not the
/// same as being refused.
fn unavailable(error: &StoreError) -> Response {
    tracing::error!(%error, "OAuth token authentication failed");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

/// Authenticates an OAuth access token (`axon_oat_...`) as a [`Caller::Principal`]: the
/// grant's user under their own groups and opt-outs, no narrowing by scope, bound to the
/// MCP endpoint (`resource`) the token was issued for. The error is boxed: a `Response` is
/// large for an error type.
pub(super) async fn authenticate_oauth_token(
    token: &str,
    state: &AppState,
    _client_ip: Option<&str>,
) -> Result<Caller, Box<Response>> {
    let Some((store, oidc)) = state.multi_user() else {
        return Err(Box::new(unauthorized()));
    };
    let principal = match store.authenticate_oauth_access(token).await {
        Ok(AccessLookup::Valid(principal)) => *principal,
        Ok(AccessLookup::Expired) => {
            crate::metrics::record_authn("oauth", "expired");
            return Err(Box::new(unauthorized()));
        }
        Ok(AccessLookup::Invalid) => {
            crate::metrics::record_authn("oauth", "invalid");
            return Err(Box::new(unauthorized()));
        }
        Err(error) => return Err(Box::new(unavailable(&error))),
    };

    let limit = state.auth_manager.load().effective_limit(0);
    if limit > 0 {
        let key = format!("oauth:{}", principal.grant_id);
        match store.hit_rate_limit(&key, limit).await {
            Ok(true) => {}
            Ok(false) => {
                crate::metrics::record_authn("oauth", "rate_limited");
                crate::metrics::record_authz_denied("rate_limit");
                return Err(Box::new(StatusCode::TOO_MANY_REQUESTS.into_response()));
            }
            Err(error) => {
                tracing::warn!(%error, key, "Rate limit check failed, letting the request through");
            }
        }
    }
    crate::metrics::record_authn("oauth", "ok");

    let owner = &principal.owner;
    let policy = state.policy.current();
    // No configured provider for the issuer: no IdP mapping applies
    let provider_id = oidc.id_for_issuer(&owner.issuer).unwrap_or("");
    let groups = policy.groups_for(owner.id, provider_id, &owner.groups);
    let opt_outs = store
        .opt_outs(owner.id)
        .await
        .map(|rows| OptOuts::new(rows.into_iter().map(|row| (row.backend, row.tool))))
        .map_err(|error| Box::new(unavailable(&error)))?;

    let owner_label = owner
        .email
        .clone()
        .or_else(|| owner.display_name.clone())
        .unwrap_or_else(|| owner.id.to_string());
    let app = principal
        .client_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&principal.client_id);
    let caller = PrincipalPolicy::new(
        format!("{owner_label} / {app}"),
        policy.effective(&groups),
        opt_outs,
        TokenScope::default(),
    )
    .with_identity(Some(owner.id), None)
    .with_resource(principal.resource);
    Ok(Caller::Principal(caller))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_are_https_or_loopback_http() {
        for good in [
            "https://app.example/callback",
            "https://app.example:8443/a/b?x=1",
            "http://127.0.0.1:33418/callback",
            "http://localhost/cb",
            "http://[::1]:5000/cb",
        ] {
            assert!(valid_redirect_uri(good), "{good}");
        }
        for bad in [
            "http://app.example/callback",
            "http://127.0.0.1.example/cb",
            "myapp://callback",
            "https://app.example/cb#frag",
            "https://user:pw@app.example/cb",
            "javascript:alert(1)",
            "https://app.example/c b",
            "/relative",
            "",
        ] {
            assert!(!valid_redirect_uri(bad), "{bad}");
        }
    }

    #[test]
    fn redirect_matching_is_exact_except_for_the_loopback_port() {
        assert!(redirect_matches(
            "https://app.example/cb",
            "https://app.example/cb"
        ));
        assert!(!redirect_matches(
            "https://app.example:1/cb",
            "https://app.example:2/cb"
        ));
        assert!(!redirect_matches(
            "https://app.example/cb",
            "https://app.example/cb2"
        ));
        assert!(redirect_matches(
            "http://127.0.0.1:1000/cb",
            "http://127.0.0.1:2000/cb"
        ));
        assert!(redirect_matches(
            "http://localhost/cb",
            "http://localhost:4567/cb"
        ));
        assert!(!redirect_matches(
            "http://127.0.0.1:1000/cb",
            "http://127.0.0.1:1000/other"
        ));
        assert!(!redirect_matches(
            "http://127.0.0.1:1000/cb",
            "http://localhost:1000/cb"
        ));
    }

    #[test]
    fn resources_are_the_gateways_mcp_endpoints() {
        let base = "https://gw.example";
        assert!(valid_resource(base, "https://gw.example/mcp"));
        assert!(valid_resource(base, "https://gw.example/mcp/toolset/ops-1"));
        assert!(!valid_resource(base, "https://gw.example/mcp/"));
        assert!(!valid_resource(base, "https://gw.example/mcp/toolset/"));
        assert!(!valid_resource(base, "https://gw.example/mcp/toolset/a/b"));
        assert!(!valid_resource(base, "https://gw.example/mcpx"));
        assert!(!valid_resource(base, "https://other.example/mcp"));
        assert!(!valid_resource(base, "https://gw.example/api/v1/tokens"));
    }

    #[test]
    fn metadata_document_urls_need_https_and_a_path() {
        assert_eq!(
            cimd_host("https://app.example/oauth/client.json").as_deref(),
            Some("app.example")
        );
        for not_cimd in [
            "axon_client_0123",
            "https://app.example",
            "https://app.example/",
            "http://app.example/client.json",
            "https://app.example/c.json#x",
            "https://u:p@app.example/c.json",
        ] {
            assert!(cimd_url(not_cimd).is_none(), "{not_cimd}");
        }
    }

    #[test]
    fn a_metadata_document_must_name_itself_and_have_good_redirects() {
        let url = "https://app.example/client.json";
        let good = json!({
            "client_id": url,
            "client_name": "App",
            "redirect_uris": ["http://127.0.0.1:1/cb"],
            "token_endpoint_auth_method": "none",
        });
        let info = parse_client_document(url, good.to_string().as_bytes()).unwrap();
        assert_eq!(info.client_name.as_deref(), Some("App"));

        let other = json!({ "client_id": "https://evil.example/c.json", "redirect_uris": ["https://a.example/cb"] });
        assert!(parse_client_document(url, other.to_string().as_bytes()).is_err());
        let secret = json!({ "client_id": url, "redirect_uris": ["https://a.example/cb"], "token_endpoint_auth_method": "client_secret_basic" });
        assert!(parse_client_document(url, secret.to_string().as_bytes()).is_err());
        let no_redirects = json!({ "client_id": url });
        assert!(parse_client_document(url, no_redirects.to_string().as_bytes()).is_err());
        let bad_redirect = json!({ "client_id": url, "redirect_uris": ["http://evil.example/cb"] });
        assert!(parse_client_document(url, bad_redirect.to_string().as_bytes()).is_err());
        assert!(parse_client_document(url, b"not json").is_err());
    }

    #[test]
    fn registration_validates_and_fills_defaults() {
        let ok = validate_registration(
            br#"{"redirect_uris": ["http://localhost:8080/cb"], "client_name": "Tool"}"#,
        )
        .unwrap();
        assert_eq!(ok.grant_types, ["authorization_code"]);
        assert_eq!(ok.response_types, ["code"]);
        assert_eq!(ok.client_name.as_deref(), Some("Tool"));

        let both = validate_registration(
            br#"{"redirect_uris": ["https://a.example/cb"], "grant_types": ["authorization_code", "refresh_token"], "token_endpoint_auth_method": "none"}"#,
        )
        .unwrap();
        assert_eq!(both.grant_types.len(), 2);

        let code = |body: &str| validate_registration(body.as_bytes()).unwrap_err().0;
        assert_eq!(code("{}"), "invalid_redirect_uri");
        assert_eq!(
            code(r#"{"redirect_uris": ["http://a.example/cb"]}"#),
            "invalid_redirect_uri"
        );
        assert_eq!(
            code(
                r#"{"redirect_uris": ["https://a.example/cb"], "token_endpoint_auth_method": "client_secret_post"}"#
            ),
            "invalid_client_metadata"
        );
        assert_eq!(
            code(r#"{"redirect_uris": ["https://a.example/cb"], "grant_types": ["password"]}"#),
            "invalid_client_metadata"
        );
        assert_eq!(
            code(r#"{"redirect_uris": ["https://a.example/cb"], "response_types": ["token"]}"#),
            "invalid_client_metadata"
        );
        assert_eq!(code("[1]"), "invalid_client_metadata");
        let long = format!(
            r#"{{"redirect_uris": ["https://a.example/cb"], "client_name": "{}"}}"#,
            "x".repeat(201)
        );
        assert_eq!(code(&long), "invalid_client_metadata");
    }

    #[test]
    fn the_challenge_points_at_the_resource_metadata() {
        assert_eq!(
            challenge("https://gw.example", "/mcp", false),
            "Bearer resource_metadata=\"https://gw.example/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(
            challenge("https://gw.example", "/mcp/toolset/x", true),
            "Bearer error=\"invalid_token\", resource_metadata=\"https://gw.example/.well-known/oauth-protected-resource/mcp/toolset/x\""
        );
    }

    #[test]
    fn endpoint_resources_follow_the_request_path() {
        let base = "https://gw.example";
        assert_eq!(endpoint_resource(base, "/mcp"), "https://gw.example/mcp");
        assert_eq!(endpoint_resource(base, "/mcp/"), "https://gw.example/mcp");
        assert_eq!(
            endpoint_resource(base, "/mcp/group/ops"),
            "https://gw.example/mcp/toolset/ops"
        );
    }

    #[test]
    fn challenge_codes_and_pkce_shapes() {
        assert!(valid_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!valid_code_challenge("short"));
        assert!(!valid_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"
        ));
    }

    #[test]
    fn repeated_form_fields_are_refused() {
        assert!(parse_form(b"a=1&b=2").is_some());
        assert!(parse_form(b"a=1&a=2").is_none());
    }
}
