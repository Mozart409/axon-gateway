//! OAuth client for backends that run their own authorization server
//!
//! Discovery (RFC 9728 protected resource metadata, RFC 8414 server metadata),
//! client selection (static, client ID metadata document or RFC 7591
//! registration), the authorization code flow with PKCE, refresh, and the two
//! passthrough grants (RFC 8693 token exchange and Entra on-behalf-of). Storage
//! is in `store::upstream_oauth`; sealing is here, with an AAD that binds each
//! secret to its row.
//!
//! Every request goes through [`Fetcher`]: a URL on the backend's own origin is
//! trusted, any other (the issuer and endpoints the backend names) is checked by
//! the [`EgressPolicy`] and DNS-pinned, or refused without one. No redirects,
//! 10 s, response bodies capped at 64 KiB. Errors carry the server's `error` and
//! a truncated `error_description`, never other body content or a token.

use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use chrono::{DateTime, Utc};
use oauth2::PkceCodeChallenge;
use reqwest::{StatusCode, Url, header};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{CryptoError, Keyring, Sealed};
use crate::egress::{EgressError, EgressPolicy};
use crate::store::SealedColumns;

/// Time limit of every request to a backend or its authorization server
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response body read
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Lifetime assumed when a token response has no `expires_in`
const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;
/// Longest `expires_in` believed, so a huge value cannot overflow a date
const MAX_EXPIRES_IN_SECS: u64 = 10 * 365 * 24 * 3600;
/// Longest error description kept
const MAX_DESCRIPTION_CHARS: usize = 200;
/// Random bytes in a `state`
const STATE_BYTES: usize = 32;
/// Name the gateway registers and publishes itself under
const CLIENT_NAME: &str = "axon-gateway";

const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";

/// What can go wrong talking to a backend's authorization server
#[derive(Debug, Error)]
pub enum UpstreamOauthError {
    #[error("invalid url: {0}")]
    Url(String),
    #[error(transparent)]
    Egress(#[from] EgressError),
    #[error("request failed: {0}")]
    Http(String),
    /// Discovery or a metadata document did not give what the flow needs
    #[error("{0}")]
    Metadata(String),
    #[error("the authorization server's issuer is {got}, expected {expected}")]
    IssuerMismatch { expected: String, got: String },
    #[error("the authorization server does not support PKCE with S256")]
    NoS256,
    #[error("the backend's authorization server needs a client id; set one on the catalog entry")]
    NeedsClientId,
    /// The authorization server answered with an OAuth error or a failure status;
    /// `code` is the OAuth `error` (empty when the answer had none)
    #[error("the authorization server answered {status}: {message}")]
    Refused {
        status: u16,
        code: String,
        message: String,
    },
    #[error("the authorization server's answer is not usable: {0}")]
    BadResponse(String),
    #[error("the callback's issuer is {got}, expected {expected}")]
    CallbackIssuer { expected: String, got: String },
    #[error("{0}")]
    Invalid(String),
    #[error("cannot gather randomness: {0}")]
    Random(String),
}

impl UpstreamOauthError {
    /// Whether the server said the grant (a refresh token, an assertion) is no
    /// longer valid, so retrying is pointless and the user has to sign in again
    #[must_use]
    pub fn is_invalid_grant(&self) -> bool {
        matches!(self, Self::Refused { code, .. } if code == "invalid_grant")
    }
}

/// A client id and the secret of a confidential client
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
}

impl fmt::Debug for ClientCredentials {
    // By hand, so the client secret can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCredentials")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The tokens kept sealed for one user and backend
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTokens {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl fmt::Debug for StoredTokens {
    // By hand, so the tokens can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredTokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A successful answer of a token endpoint
#[derive(Clone, PartialEq, Eq)]
pub struct TokenResponse {
    pub tokens: StoredTokens,
    pub expires_at: DateTime<Utc>,
    /// The granted scope, when the server said
    pub scope: Option<String>,
}

impl fmt::Debug for TokenResponse {
    // By hand, so the tokens can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("tokens", &self.tokens)
            .field("expires_at", &self.expires_at)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Which URLs a [`Fetcher`] may reach
#[derive(Debug, Clone)]
enum Scope<'a> {
    /// Every http(s) URL; for endpoints that come from admin configuration
    Unrestricted,
    /// URLs on the backend's origin; any other origin goes through the policy
    Backend {
        origin: String,
        policy: Option<&'a EgressPolicy>,
    },
}

/// Sends requests to backends and their authorization servers
#[derive(Debug, Clone)]
pub struct Fetcher<'a> {
    scope: Scope<'a>,
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl<'a> Fetcher<'a> {
    /// For the upstream OAuth flow of a catalog backend. The URLs it discovers
    /// (issuer, metadata, token and registration endpoints) are named by the
    /// backend, so only the backend's own origin (scheme, host and port) is
    /// trusted. Any other origin is checked by `policy` and the connection
    /// pinned to the checked address; without a policy it is refused.
    ///
    /// # Errors
    /// [`UpstreamOauthError::Url`] when `backend_url` is not an http(s) URL.
    pub fn for_backend(
        backend_url: &str,
        policy: Option<&'a EgressPolicy>,
    ) -> Result<Self, UpstreamOauthError> {
        let backend = parse_http_url(backend_url)?;
        Ok(Self {
            scope: Scope::Backend {
                origin: origin_of(&backend),
                policy,
            },
        })
    }

    /// No egress restriction, no redirects. Only for the configured
    /// `[[auth.oidc]]` provider's endpoints: they come from admin config, not
    /// from a backend.
    #[must_use]
    pub fn trusted() -> Self {
        Self {
            scope: Scope::Unrestricted,
        }
    }

    async fn client(&self, url: &str) -> Result<reqwest::Client, UpstreamOauthError> {
        let parsed = parse_http_url(url)?;
        let foreign = match &self.scope {
            Scope::Unrestricted => None,
            Scope::Backend { origin, policy } => (origin_of(&parsed) != *origin).then_some(*policy),
        };
        if let Some(policy) = foreign {
            let Some(policy) = policy else {
                return Err(UpstreamOauthError::Metadata(format!(
                    "the authorization server at {} is not on the backend's host and no egress policy allows it",
                    origin_of(&parsed)
                )));
            };
            return Ok(policy.check_url(url).await?.client(HTTP_TIMEOUT)?);
        }
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| UpstreamOauthError::Http(e.without_url().to_string()))
    }

    async fn get(&self, url: &str) -> Result<Reply, UpstreamOauthError> {
        let client = self.client(url).await?;
        execute(client.get(url).header(header::ACCEPT, "application/json")).await
    }

    async fn post_form(
        &self,
        url: &str,
        body: String,
        basic: Option<&(String, String)>,
    ) -> Result<Reply, UpstreamOauthError> {
        let client = self.client(url).await?;
        let mut request = client
            .post(url)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body);
        if let Some((user, password)) = basic {
            request = request.basic_auth(user, Some(password));
        }
        execute(request).await
    }

    async fn post_json(&self, url: &str, body: &Value) -> Result<Reply, UpstreamOauthError> {
        let client = self.client(url).await?;
        let body = serde_json::to_vec(body)
            .map_err(|e| UpstreamOauthError::Invalid(format!("cannot encode the request: {e}")))?;
        execute(
            client
                .post(url)
                .header(header::ACCEPT, "application/json")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await
    }
}

/// Sends the request and reads at most 64 KiB of the answer
async fn execute(request: reqwest::RequestBuilder) -> Result<Reply, UpstreamOauthError> {
    let http = |e: reqwest::Error| UpstreamOauthError::Http(e.without_url().to_string());
    let too_large = || UpstreamOauthError::Http(String::from("the response is too large"));
    let mut response = request.send().await.map_err(http)?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).is_ok_and(|length| length > MAX_BODY_BYTES))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http)? {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply { status, body })
}

fn parse_http_url(url: &str) -> Result<Url, UpstreamOauthError> {
    let parsed = Url::parse(url).map_err(|e| UpstreamOauthError::Url(format!("{url}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(UpstreamOauthError::Url(format!(
            "{url}: only http and https urls are allowed"
        )));
    }
    Ok(parsed)
}

/// `scheme://host[:port]` of a parsed URL
fn origin_of(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// The path of a URL for a well-known suffix: empty for the root
fn well_known_path(url: &Url) -> &str {
    match url.path() {
        "/" => "",
        path => path,
    }
}

/// The RFC 9728 metadata URLs to try for a backend URL, in order: the one with
/// the backend's path inserted, then the origin's.
///
/// # Errors
/// [`UpstreamOauthError::Url`] when `backend_url` is not an http(s) URL.
pub fn protected_resource_metadata_urls(
    backend_url: &str,
) -> Result<Vec<String>, UpstreamOauthError> {
    let url = parse_http_url(backend_url)?;
    let origin = origin_of(&url);
    let path = well_known_path(&url);
    let mut urls = Vec::new();
    if !path.is_empty() {
        urls.push(format!(
            "{origin}/.well-known/oauth-protected-resource{path}"
        ));
    }
    urls.push(format!("{origin}/.well-known/oauth-protected-resource"));
    Ok(urls)
}

/// The metadata URLs to try for an issuer, in order: RFC 8414, then `OpenID`
/// Connect discovery.
///
/// # Errors
/// [`UpstreamOauthError::Url`] when `issuer` is not an http(s) URL.
pub fn auth_server_metadata_urls(issuer: &str) -> Result<Vec<String>, UpstreamOauthError> {
    let url = parse_http_url(issuer)?;
    let origin = origin_of(&url);
    let path = well_known_path(&url);
    Ok(vec![
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ),
    ])
}

/// The `resource_metadata` URL of a `WWW-Authenticate` header, if it has one
// Nothing probes a backend for a 401 yet; discovery uses the well-known URLs.
#[allow(dead_code)]
#[must_use]
pub fn resource_metadata_from_challenge(header_value: &str) -> Option<String> {
    const KEY: &str = "resource_metadata";
    // ASCII lowercasing keeps byte offsets
    let lower = header_value.to_ascii_lowercase();
    let mut from = 0;
    while let Some(found) = lower.get(from..).and_then(|rest| rest.find(KEY)) {
        let start = from + found;
        let end = start + KEY.len();
        from = end;
        let at_boundary = header_value
            .get(..start)
            .and_then(|before| before.chars().next_back())
            .is_none_or(|c| matches!(c, ' ' | ',' | '\t'));
        let Some(rest) = header_value
            .get(end..)
            .and_then(|rest| rest.trim_start().strip_prefix('='))
        else {
            continue;
        };
        if !at_boundary {
            continue;
        }
        let rest = rest.trim_start();
        let value = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next(),
            None => rest.split([',', ' ', '\t']).next(),
        }
        .unwrap_or_default();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

/// RFC 9728 protected resource metadata, the parts used
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProtectedResourceMetadata {
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// RFC 8414 authorization server metadata, the parts used
#[derive(Debug, Clone, Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
}

/// What discovery found for a backend
#[derive(Debug, Clone)]
pub struct Discovery {
    pub issuer: String,
    pub metadata: AuthServerMetadata,
    /// `scopes_supported` of the protected resource metadata
    pub scopes_supported: Vec<String>,
}

enum Fetched<T> {
    Found(T),
    /// The server answered with this non-success status
    Status(u16),
}

async fn get_document<T: DeserializeOwned>(
    http: &Fetcher<'_>,
    url: &str,
    what: &str,
) -> Result<Fetched<T>, UpstreamOauthError> {
    let reply = http.get(url).await?;
    if !reply.status.is_success() {
        return Ok(Fetched::Status(reply.status.as_u16()));
    }
    serde_json::from_slice(&reply.body)
        .map(Fetched::Found)
        // No `{e}`: a serde error can quote values of the body.
        .map_err(|_| UpstreamOauthError::Metadata(format!("invalid {what} at {}", clip(url))))
}

/// Checks a metadata document against the issuer it was asked for: the issuer
/// must be the same, and S256 must be offered when the server lists methods.
///
/// # Errors
/// [`UpstreamOauthError::IssuerMismatch`] or [`UpstreamOauthError::NoS256`].
pub fn check_metadata(
    issuer: &str,
    metadata: &AuthServerMetadata,
) -> Result<(), UpstreamOauthError> {
    if metadata.issuer != issuer {
        return Err(UpstreamOauthError::IssuerMismatch {
            expected: clip(issuer),
            got: clip(&metadata.issuer),
        });
    }
    if metadata
        .code_challenge_methods_supported
        .as_ref()
        .is_some_and(|methods| !methods.iter().any(|m| m == "S256"))
    {
        return Err(UpstreamOauthError::NoS256);
    }
    Ok(())
}

/// The authorization endpoint is only handed to the user's browser, never
/// requested by the gateway, so it needs no egress check: any `http` or
/// `https` URL with a host will do, nothing else (no `javascript:` or `data:`).
///
/// # Errors
/// [`UpstreamOauthError::Metadata`] for any other scheme or an unparsable URL.
pub fn check_authorization_endpoint(endpoint: &str) -> Result<(), UpstreamOauthError> {
    let url = Url::parse(endpoint).ok().filter(|url| {
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| !h.is_empty())
    });
    url.map(|_| ()).ok_or_else(|| {
        UpstreamOauthError::Metadata(String::from(
            "the authorization endpoint must be an http or https URL",
        ))
    })
}

/// Finds the authorization server of a backend. `resource_metadata_url` is the
/// URL from a 401 `WWW-Authenticate` header; it wins over the well-known ones.
/// Without any protected resource metadata the backend's origin is the issuer.
///
/// # Errors
/// Fails when a request fails, a document is invalid, no authorization server
/// metadata is found, or the metadata fails [`check_metadata`].
pub async fn discover(
    http: &Fetcher<'_>,
    backend_url: &str,
    resource_metadata_url: Option<&str>,
) -> Result<Discovery, UpstreamOauthError> {
    const PRM: &str = "protected resource metadata";
    let backend = parse_http_url(backend_url)?;
    let prm: Option<ProtectedResourceMetadata> = if let Some(url) = resource_metadata_url {
        match get_document(http, url, PRM).await? {
            Fetched::Found(document) => Some(document),
            Fetched::Status(status) => {
                return Err(UpstreamOauthError::Metadata(format!(
                    "the {PRM} at {url} answered {status}"
                )));
            }
        }
    } else {
        let mut found = None;
        for url in protected_resource_metadata_urls(backend_url)? {
            if let Fetched::Found(document) = get_document(http, &url, PRM).await? {
                found = Some(document);
                break;
            }
        }
        found
    };
    let (issuer, scopes_supported) = match prm {
        Some(prm) => {
            let issuer = prm
                .authorization_servers
                .into_iter()
                .next()
                .ok_or_else(|| {
                    UpstreamOauthError::Metadata(String::from(
                        "the protected resource metadata lists no authorization server",
                    ))
                })?;
            (issuer, prm.scopes_supported)
        }
        None => (origin_of(&backend), Vec::new()),
    };
    let mut metadata = None;
    for url in auth_server_metadata_urls(&issuer)? {
        if let Fetched::Found(document) =
            get_document::<AuthServerMetadata>(http, &url, "authorization server metadata").await?
        {
            metadata = Some(document);
            break;
        }
    }
    let metadata = metadata.ok_or_else(|| {
        UpstreamOauthError::Metadata(format!(
            "no authorization server metadata found for {}",
            clip(&issuer)
        ))
    })?;
    check_metadata(&issuer, &metadata)?;
    check_authorization_endpoint(&metadata.authorization_endpoint)?;
    Ok(Discovery {
        issuer,
        metadata,
        scopes_supported,
    })
}

/// The client id URL of the gateway's client ID metadata document
#[must_use]
pub fn client_id_url(base_url: &str) -> String {
    format!(
        "{}/oauth/upstream/client.json",
        base_url.trim_end_matches('/')
    )
}

/// The redirect URI the gateway registers and sends in authorization requests
#[must_use]
pub fn redirect_uri(base_url: &str) -> String {
    format!("{}/oauth/upstream/callback", base_url.trim_end_matches('/'))
}

/// The gateway's client ID metadata document, served at [`client_id_url`]
#[must_use]
pub fn client_metadata_document(base_url: &str) -> Value {
    json!({
        "client_id": client_id_url(base_url),
        "client_name": CLIENT_NAME,
        "redirect_uris": [redirect_uri(base_url)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
}

/// How the gateway identifies itself to an authorization server
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientChoice {
    /// The client the catalog entry names
    Static(ClientCredentials),
    /// The gateway's client ID metadata document
    Cimd(ClientCredentials),
    /// Register at this endpoint (see [`register_client`]); the result is shared
    /// by every user, so look it up in the store first
    Register { endpoint: String },
}

/// Picks how to identify: a static client wins, then a client ID metadata
/// document, then registration.
///
/// # Errors
/// [`UpstreamOauthError::NeedsClientId`] when none of them is possible.
pub fn choose_client(
    metadata: &AuthServerMetadata,
    static_client: Option<ClientCredentials>,
    base_url: &str,
) -> Result<ClientChoice, UpstreamOauthError> {
    if let Some(client) = static_client {
        return Ok(ClientChoice::Static(client));
    }
    if metadata.client_id_metadata_document_supported {
        return Ok(ClientChoice::Cimd(ClientCredentials {
            client_id: client_id_url(base_url),
            client_secret: None,
        }));
    }
    match &metadata.registration_endpoint {
        Some(endpoint) => Ok(ClientChoice::Register {
            endpoint: endpoint.clone(),
        }),
        None => Err(UpstreamOauthError::NeedsClientId),
    }
}

/// Registers the gateway as a public client (RFC 7591). A server that answers
/// with a `client_secret` anyway gives a confidential client.
///
/// # Errors
/// Fails when the request fails or the answer has no `client_id`.
pub async fn register_client(
    http: &Fetcher<'_>,
    registration_endpoint: &str,
    base_url: &str,
) -> Result<ClientCredentials, UpstreamOauthError> {
    #[derive(Deserialize)]
    struct Registration {
        client_id: String,
        #[serde(default)]
        client_secret: Option<String>,
    }
    let body = json!({
        "client_name": CLIENT_NAME,
        "redirect_uris": [redirect_uri(base_url)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    let reply = http.post_json(registration_endpoint, &body).await?;
    if !reply.status.is_success() {
        return Err(refused(&reply));
    }
    let registration: Registration = serde_json::from_slice(&reply.body)
        .map_err(|_| UpstreamOauthError::BadResponse(String::from("registration: not a client")))?;
    if registration.client_id.is_empty() {
        return Err(UpstreamOauthError::BadResponse(String::from(
            "registration: no client_id",
        )));
    }
    Ok(ClientCredentials {
        client_id: registration.client_id,
        client_secret: registration
            .client_secret
            .filter(|secret| !secret.is_empty()),
    })
}

/// The scope to ask for: the static client's, else the resource's, else none
#[must_use]
pub fn select_scope(static_scopes: &[String], resource_scopes: &[String]) -> Option<String> {
    let scopes = if static_scopes.is_empty() {
        resource_scopes
    } else {
        static_scopes
    };
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

/// A built authorization request: where to send the browser, and what to keep
/// until it comes back
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub url: String,
    pub state: String,
    pub pkce_verifier: String,
}

impl fmt::Debug for AuthorizationRequest {
    // By hand, so the state and the verifier can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("url", &"<redacted>")
            .field("state", &"<redacted>")
            .field("pkce_verifier", &"<redacted>")
            .finish()
    }
}

/// Builds the authorization request: PKCE S256, a random 256-bit `state`, and
/// `resource` (RFC 8707) set to the backend URL.
///
/// # Errors
/// Fails when the authorization endpoint is not an http(s) URL or no randomness
/// is available.
pub fn build_authorization_request(
    metadata: &AuthServerMetadata,
    client_id: &str,
    redirect_uri: &str,
    resource: &str,
    scope: Option<&str>,
) -> Result<AuthorizationRequest, UpstreamOauthError> {
    let mut url = parse_http_url(&metadata.authorization_endpoint)?;
    let mut raw = [0_u8; STATE_BYTES];
    getrandom::fill(&mut raw).map_err(|e| UpstreamOauthError::Random(e.to_string()))?;
    let state = hex::encode(raw);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", &state)
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256")
            .append_pair("resource", resource);
        if let Some(scope) = scope {
            query.append_pair("scope", scope);
        }
    }
    Ok(AuthorizationRequest {
        url: url.into(),
        state,
        pkce_verifier: verifier.secret().clone(),
    })
}

/// Checks the RFC 9207 `iss` of a callback: when the server's metadata says it
/// returns the parameter, a missing or different `iss` is refused (a server that
/// does not announce it is not held to it, but a returned `iss` is not checked
/// then either).
///
/// # Errors
/// [`UpstreamOauthError::CallbackIssuer`] on a mismatch or a missing `iss`.
pub fn check_callback_issuer(
    issuer: &str,
    iss_parameter_supported: bool,
    returned: Option<&str>,
) -> Result<(), UpstreamOauthError> {
    if !iss_parameter_supported {
        return Ok(());
    }
    match returned {
        Some(got) if got == issuer => Ok(()),
        _ => Err(UpstreamOauthError::CallbackIssuer {
            expected: issuer.to_owned(),
            got: returned.unwrap_or("nothing").to_owned(),
        }),
    }
}

/// A token endpoint and the client authentication methods its server lists
#[derive(Debug, Clone, Copy)]
pub struct TokenEndpoint<'a> {
    pub url: &'a str,
    /// `token_endpoint_auth_methods_supported`; `None` when the server lists none
    pub auth_methods: Option<&'a [String]>,
}

type Form = Vec<(&'static str, String)>;

/// Percent-encodes for `application/x-www-form-urlencoded`
fn form_urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn form_body(form: &Form) -> String {
    form.iter()
        .map(|(key, value)| format!("{key}={}", form_urlencode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// How a client authenticates at a token endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuthMethod {
    /// A public client: only its id is sent
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenAuthMethod {
    /// The name used in server metadata and in the database
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }

    /// The method named `text`, as [`TokenAuthMethod::as_str`] writes it
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [Self::None, Self::ClientSecretBasic, Self::ClientSecretPost]
            .into_iter()
            .find(|method| method.as_str() == text)
    }

    /// A public client sends its id only; a confidential one uses
    /// `client_secret_basic` when the server lists it (or lists nothing), else
    /// `client_secret_post`.
    #[must_use]
    pub fn choose(client: &ClientCredentials, listed: Option<&[String]>) -> Self {
        if client.client_secret.is_none() {
            Self::None
        } else if listed.is_none_or(|methods| methods.iter().any(|m| m == "client_secret_basic")) {
            Self::ClientSecretBasic
        } else {
            Self::ClientSecretPost
        }
    }
}

/// Adds client authentication to `form` the way `method` says. Returns the
/// Basic credentials, if used. A client without a secret sends its id only,
/// whatever the method.
fn authenticate(
    form: &mut Form,
    client: &ClientCredentials,
    method: TokenAuthMethod,
) -> Option<(String, String)> {
    match (method, &client.client_secret) {
        (TokenAuthMethod::ClientSecretBasic, Some(secret)) => {
            Some((form_urlencode(&client.client_id), form_urlencode(secret)))
        }
        (TokenAuthMethod::ClientSecretPost, Some(secret)) => {
            form.push(("client_id", client.client_id.clone()));
            form.push(("client_secret", secret.clone()));
            None
        }
        _ => {
            form.push(("client_id", client.client_id.clone()));
            None
        }
    }
}

/// The form of the authorization code exchange, without client authentication
fn code_form(code: &str, redirect_uri: &str, pkce_verifier: &str, resource: &str) -> Form {
    vec![
        ("grant_type", String::from("authorization_code")),
        ("code", code.to_owned()),
        ("redirect_uri", redirect_uri.to_owned()),
        ("code_verifier", pkce_verifier.to_owned()),
        ("resource", resource.to_owned()),
    ]
}

/// The form of a refresh, without client authentication
fn refresh_form(refresh_token: &str, scope: Option<&str>, resource: Option<&str>) -> Form {
    let mut form = vec![
        ("grant_type", String::from("refresh_token")),
        ("refresh_token", refresh_token.to_owned()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope.to_owned()));
    }
    if let Some(resource) = resource {
        form.push(("resource", resource.to_owned()));
    }
    form
}

/// What to exchange in an RFC 8693 token exchange
#[derive(Clone, Copy)]
pub struct TokenExchangeRequest<'a> {
    pub subject_token: &'a str,
    pub audience: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub resource: Option<&'a str>,
}

impl fmt::Debug for TokenExchangeRequest<'_> {
    // By hand, so the subject token can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenExchangeRequest")
            .field("subject_token", &"<redacted>")
            .field("audience", &self.audience)
            .field("scope", &self.scope)
            .field("resource", &self.resource)
            .finish()
    }
}

/// The form of an RFC 8693 token exchange, without client authentication
fn token_exchange_form(request: &TokenExchangeRequest<'_>) -> Form {
    let mut form = vec![
        ("grant_type", String::from(GRANT_TOKEN_EXCHANGE)),
        ("subject_token", request.subject_token.to_owned()),
        ("subject_token_type", String::from(TOKEN_TYPE_ACCESS)),
        ("requested_token_type", String::from(TOKEN_TYPE_ACCESS)),
    ];
    for (key, value) in [
        ("audience", request.audience),
        ("scope", request.scope),
        ("resource", request.resource),
    ] {
        if let Some(value) = value {
            form.push((key, value.to_owned()));
        }
    }
    form
}

/// The form of an Entra on-behalf-of request, client credentials included
fn on_behalf_of_form(client_id: &str, client_secret: &str, assertion: &str, scope: &str) -> Form {
    vec![
        ("grant_type", String::from(GRANT_JWT_BEARER)),
        ("client_id", client_id.to_owned()),
        ("client_secret", client_secret.to_owned()),
        ("assertion", assertion.to_owned()),
        ("requested_token_use", String::from("on_behalf_of")),
        ("scope", scope.to_owned()),
    ]
}

/// At most [`MAX_DESCRIPTION_CHARS`] characters of text a server supplied, for
/// an error message
fn clip(text: &str) -> String {
    text.chars().take(MAX_DESCRIPTION_CHARS).collect()
}

/// An OAuth error answer, or a plain failure status
fn refused(reply: &Reply) -> UpstreamOauthError {
    #[derive(Deserialize)]
    struct OauthError {
        #[serde(default)]
        error: String,
        #[serde(default)]
        error_description: Option<String>,
    }
    let status = reply.status.as_u16();
    match serde_json::from_slice::<OauthError>(&reply.body) {
        Ok(OauthError {
            error,
            error_description,
        }) if !error.is_empty() => {
            let error = clip(&error);
            let description = clip(&error_description.unwrap_or_default());
            let message = if description.is_empty() {
                error.clone()
            } else {
                format!("{error} ({description})")
            };
            UpstreamOauthError::Refused {
                status,
                code: error,
                message,
            }
        }
        _ => UpstreamOauthError::Refused {
            status,
            code: String::new(),
            message: String::from("no error given"),
        },
    }
}

/// Reads the answer of a token endpoint. A response without a refresh token
/// keeps `previous_refresh_token` (rotation is optional); one without
/// `expires_in` lasts an hour from `now`.
///
/// # Errors
/// [`UpstreamOauthError::BadResponse`] when the body is not a token response.
pub fn parse_token_response(
    body: &[u8],
    previous_refresh_token: Option<&str>,
    now: DateTime<Utc>,
) -> Result<TokenResponse, UpstreamOauthError> {
    #[derive(Deserialize)]
    struct Raw {
        access_token: String,
        #[serde(default)]
        refresh_token: Option<String>,
        #[serde(default)]
        expires_in: Option<Value>,
        #[serde(default)]
        scope: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(body).map_err(|_| {
        UpstreamOauthError::BadResponse(String::from("token response: not a token"))
    })?;
    if raw.access_token.is_empty() {
        return Err(UpstreamOauthError::BadResponse(String::from(
            "token response: empty access_token",
        )));
    }
    let lifetime = match raw.expires_in {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
    .unwrap_or(DEFAULT_EXPIRES_IN_SECS)
    .min(MAX_EXPIRES_IN_SECS);
    let expires_at = i64::try_from(lifetime)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .and_then(|lifetime| now.checked_add_signed(lifetime))
        .unwrap_or(now);
    Ok(TokenResponse {
        tokens: StoredTokens {
            access_token: raw.access_token,
            refresh_token: raw
                .refresh_token
                .filter(|token| !token.is_empty())
                .or_else(|| previous_refresh_token.map(str::to_owned)),
        },
        expires_at,
        scope: raw.scope.filter(|scope| !scope.is_empty()),
    })
}

/// Posts a form to a token endpoint and reads the answer
async fn token_request(
    http: &Fetcher<'_>,
    url: &str,
    form: &Form,
    basic: Option<&(String, String)>,
    previous_refresh_token: Option<&str>,
) -> Result<TokenResponse, UpstreamOauthError> {
    let reply = http.post_form(url, form_body(form), basic).await?;
    if !reply.status.is_success() {
        return Err(refused(&reply));
    }
    parse_token_response(&reply.body, previous_refresh_token, Utc::now())
}

/// What the redirect gave back, to trade for tokens
#[derive(Clone, Copy)]
pub struct CodeGrant<'a> {
    pub code: &'a str,
    /// The redirect URI of the authorization request
    pub redirect_uri: &'a str,
    pub pkce_verifier: &'a str,
    /// The backend URL (RFC 8707)
    pub resource: &'a str,
}

impl fmt::Debug for CodeGrant<'_> {
    // By hand, so the code and the verifier can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodeGrant")
            .field("code", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("pkce_verifier", &"<redacted>")
            .field("resource", &self.resource)
            .finish()
    }
}

/// Exchanges an authorization code for tokens, authenticating the way `method`
/// says.
///
/// # Errors
/// Fails when the request fails, the server refuses or the answer is not a token
/// response.
pub async fn exchange_code(
    http: &Fetcher<'_>,
    token_endpoint: &str,
    method: TokenAuthMethod,
    client: &ClientCredentials,
    grant: &CodeGrant<'_>,
) -> Result<TokenResponse, UpstreamOauthError> {
    let mut form = code_form(
        grant.code,
        grant.redirect_uri,
        grant.pkce_verifier,
        grant.resource,
    );
    let basic = authenticate(&mut form, client, method);
    token_request(http, token_endpoint, &form, basic.as_ref(), None).await
}

/// Refreshes an access token, authenticating the way `method` says. The
/// response keeps `refresh_token` when the server rotates none. Check
/// [`UpstreamOauthError::is_invalid_grant`] on failure.
///
/// # Errors
/// Fails when the request fails, the server refuses or the answer is not a token
/// response.
pub async fn refresh_tokens(
    http: &Fetcher<'_>,
    token_endpoint: &str,
    method: TokenAuthMethod,
    client: &ClientCredentials,
    refresh_token: &str,
    scope: Option<&str>,
    resource: Option<&str>,
) -> Result<TokenResponse, UpstreamOauthError> {
    let mut form = refresh_form(refresh_token, scope, resource);
    let basic = authenticate(&mut form, client, method);
    token_request(
        http,
        token_endpoint,
        &form,
        basic.as_ref(),
        Some(refresh_token),
    )
    .await
}

/// Refreshes the identity provider's access token from the refresh token stored
/// at login, to use it as a subject token. The app's own client credentials
/// authenticate the way the endpoint's listed methods say; `scope` is optional.
///
/// # Errors
/// As [`refresh_tokens`].
pub async fn refresh_idp_token(
    http: &Fetcher<'_>,
    endpoint: &TokenEndpoint<'_>,
    app: &ClientCredentials,
    refresh_token: &str,
    scope: Option<&str>,
) -> Result<TokenResponse, UpstreamOauthError> {
    let method = TokenAuthMethod::choose(app, endpoint.auth_methods);
    refresh_tokens(http, endpoint.url, method, app, refresh_token, scope, None).await
}

/// RFC 8693 token exchange of `request.subject_token` for a token for the
/// backend, authenticated as the app.
///
/// # Errors
/// Fails when the request fails, the server refuses or the answer is not a token
/// response.
pub async fn token_exchange(
    http: &Fetcher<'_>,
    endpoint: &TokenEndpoint<'_>,
    app: &ClientCredentials,
    request: &TokenExchangeRequest<'_>,
) -> Result<TokenResponse, UpstreamOauthError> {
    let mut form = token_exchange_form(request);
    let method = TokenAuthMethod::choose(app, endpoint.auth_methods);
    let basic = authenticate(&mut form, app, method);
    token_request(http, endpoint.url, &form, basic.as_ref(), None).await
}

/// Entra on-behalf-of: trades the user's token (`assertion`) for one with `scope`.
/// The app's client id and secret go in the form body.
///
/// # Errors
/// [`UpstreamOauthError::Invalid`] when the app has no client secret; otherwise
/// as [`token_exchange`].
pub async fn on_behalf_of(
    http: &Fetcher<'_>,
    token_endpoint: &str,
    app: &ClientCredentials,
    assertion: &str,
    scope: &str,
) -> Result<TokenResponse, UpstreamOauthError> {
    let secret = app.client_secret.as_deref().ok_or_else(|| {
        UpstreamOauthError::Invalid(String::from("on-behalf-of needs a client secret"))
    })?;
    let form = on_behalf_of_form(&app.client_id, secret, assertion, scope);
    token_request(http, token_endpoint, &form, None, None).await
}

fn tokens_aad(user: Uuid, backend: &str) -> String {
    format!("upstream-oauth:{user}:{backend}")
}

fn idp_refresh_aad(user: Uuid, provider: &str) -> String {
    format!("idp-refresh:{user}:{provider}")
}

fn client_secret_aad(backend: &str, issuer: &str) -> String {
    format!("upstream-client:{backend}:{issuer}")
}

pub(crate) fn seal_text(
    keyring: &Keyring,
    plaintext: &[u8],
    aad: &str,
) -> Result<SealedColumns, CryptoError> {
    keyring
        .seal(plaintext, aad.as_bytes())
        .map(SealedColumns::from)
}

/// Opens a sealed text; the error is safe to store and show
pub(crate) fn open_text(
    keyring: &Keyring,
    sealed: &SealedColumns,
    aad: &str,
) -> Result<String, String> {
    let plaintext = keyring
        .open(&Sealed::from(sealed), aad.as_bytes())
        .map_err(|error| error.to_string())?;
    String::from_utf8(plaintext).map_err(|_| String::from("the stored secret is not text"))
}

/// Seals a user's tokens for a backend.
///
/// # Errors
/// Fails when sealing fails.
pub fn seal_tokens(
    keyring: &Keyring,
    user: Uuid,
    backend: &str,
    tokens: &StoredTokens,
) -> Result<SealedColumns, CryptoError> {
    let payload = serde_json::to_vec(tokens).map_err(|_| CryptoError::Encrypt)?;
    seal_text(keyring, &payload, &tokens_aad(user, backend))
}

/// Opens a user's tokens for a backend; the error is safe to store and show.
///
/// # Errors
/// Fails when the key is unknown, the data was tampered with or moved, or the
/// plaintext is not the expected JSON.
pub fn open_tokens(
    keyring: &Keyring,
    user: Uuid,
    backend: &str,
    sealed: &SealedColumns,
) -> Result<StoredTokens, String> {
    let payload = keyring
        .open(&Sealed::from(sealed), tokens_aad(user, backend).as_bytes())
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&payload)
        .map_err(|_| String::from("the stored tokens are not the expected JSON"))
}

/// Seals the refresh token an identity provider gave a user at login.
///
/// # Errors
/// Fails when sealing fails.
pub fn seal_idp_refresh_token(
    keyring: &Keyring,
    user: Uuid,
    provider: &str,
    refresh_token: &str,
) -> Result<SealedColumns, CryptoError> {
    seal_text(
        keyring,
        refresh_token.as_bytes(),
        &idp_refresh_aad(user, provider),
    )
}

/// Opens an identity provider refresh token; the error is safe to store and show.
///
/// # Errors
/// Fails when the key is unknown or the data was tampered with or moved.
pub fn open_idp_refresh_token(
    keyring: &Keyring,
    user: Uuid,
    provider: &str,
    sealed: &SealedColumns,
) -> Result<String, String> {
    open_text(keyring, sealed, &idp_refresh_aad(user, provider))
}

/// Seals the client secret of a registration at `issuer` for `backend`.
///
/// # Errors
/// Fails when sealing fails.
pub fn seal_client_secret(
    keyring: &Keyring,
    backend: &str,
    issuer: &str,
    secret: &str,
) -> Result<SealedColumns, CryptoError> {
    seal_text(
        keyring,
        secret.as_bytes(),
        &client_secret_aad(backend, issuer),
    )
}

/// Opens the client secret of a registration; the error is safe to store and show.
///
/// # Errors
/// Fails when the key is unknown or the data was tampered with or moved.
pub fn open_client_secret(
    keyring: &Keyring,
    backend: &str,
    issuer: &str,
    sealed: &SealedColumns,
) -> Result<String, String> {
    open_text(keyring, sealed, &client_secret_aad(backend, issuer))
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    use super::*;

    fn metadata() -> AuthServerMetadata {
        AuthServerMetadata {
            issuer: String::from("https://as.example.com"),
            authorization_endpoint: String::from("https://as.example.com/authorize"),
            token_endpoint: String::from("https://as.example.com/token"),
            registration_endpoint: None,
            code_challenge_methods_supported: None,
            token_endpoint_auth_methods_supported: None,
            client_id_metadata_document_supported: false,
            authorization_response_iss_parameter_supported: false,
        }
    }

    fn keyring() -> Keyring {
        Keyring::from_text("k1:0123456789abcdef0123456789abcdef-secret").unwrap()
    }

    fn client(secret: Option<&str>) -> ClientCredentials {
        ClientCredentials {
            client_id: String::from("axon"),
            client_secret: secret.map(str::to_owned),
        }
    }

    fn field<'a>(form: &'a Form, key: &str) -> Option<&'a str> {
        form.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn protected_resource_urls_with_and_without_a_path() {
        assert_eq!(
            protected_resource_metadata_urls("https://mcp.example.com/mcp?x=1#f").unwrap(),
            [
                "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
                "https://mcp.example.com/.well-known/oauth-protected-resource",
            ]
        );
        for root in ["https://mcp.example.com", "https://mcp.example.com/"] {
            assert_eq!(
                protected_resource_metadata_urls(root).unwrap(),
                ["https://mcp.example.com/.well-known/oauth-protected-resource"]
            );
        }
        assert_eq!(
            protected_resource_metadata_urls("http://mcp.example.com:8080/a/b/").unwrap()[0],
            "http://mcp.example.com:8080/.well-known/oauth-protected-resource/a/b/"
        );
        assert!(protected_resource_metadata_urls("ftp://x/").is_err());
    }

    #[test]
    fn server_metadata_urls_with_and_without_a_path() {
        assert_eq!(
            auth_server_metadata_urls("https://as.example.com").unwrap(),
            [
                "https://as.example.com/.well-known/oauth-authorization-server",
                "https://as.example.com/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            auth_server_metadata_urls("https://as.example.com/").unwrap(),
            [
                "https://as.example.com/.well-known/oauth-authorization-server",
                "https://as.example.com/.well-known/openid-configuration",
            ]
        );
        assert_eq!(
            auth_server_metadata_urls("https://as.example.com/tenant/v2").unwrap(),
            [
                "https://as.example.com/.well-known/oauth-authorization-server/tenant/v2",
                "https://as.example.com/tenant/v2/.well-known/openid-configuration",
            ]
        );
    }

    #[test]
    fn resource_metadata_is_read_from_a_challenge() {
        let url = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
        assert_eq!(
            resource_metadata_from_challenge(&format!(
                "Bearer realm=\"mcp\", resource_metadata=\"{url}\", error=\"invalid_token\""
            ))
            .as_deref(),
            Some(url)
        );
        assert_eq!(
            resource_metadata_from_challenge(&format!("Bearer Resource_Metadata={url}, a=b"))
                .as_deref(),
            Some(url)
        );
        assert_eq!(resource_metadata_from_challenge("Bearer realm=\"x\""), None);
        assert_eq!(
            resource_metadata_from_challenge("Bearer my_resource_metadata=\"x\""),
            None
        );
        assert_eq!(
            resource_metadata_from_challenge("Bearer resource_metadata=\"\""),
            None
        );
    }

    #[test]
    fn an_issuer_mismatch_is_rejected() {
        let mut document = metadata();
        document.issuer = String::from("https://evil.example.com");
        let error = check_metadata("https://as.example.com", &document).unwrap_err();
        assert!(matches!(error, UpstreamOauthError::IssuerMismatch { .. }));
        assert!(check_metadata("https://as.example.com", &metadata()).is_ok());
    }

    #[test]
    fn s256_is_required_when_methods_are_listed() {
        let mut document = metadata();
        document.code_challenge_methods_supported = Some(vec![String::from("plain")]);
        assert!(matches!(
            check_metadata("https://as.example.com", &document),
            Err(UpstreamOauthError::NoS256)
        ));
        document.code_challenge_methods_supported =
            Some(vec![String::from("plain"), String::from("S256")]);
        assert!(check_metadata("https://as.example.com", &document).is_ok());
        document.code_challenge_methods_supported = None;
        assert!(check_metadata("https://as.example.com", &document).is_ok());
    }

    #[test]
    fn client_choice_prefers_static_then_cimd_then_registration() {
        let base = "https://axon.example.com/";
        let mut document = metadata();
        assert!(matches!(
            choose_client(&document, None, base),
            Err(UpstreamOauthError::NeedsClientId)
        ));
        document.registration_endpoint = Some(String::from("https://as.example.com/register"));
        assert_eq!(
            choose_client(&document, None, base).unwrap(),
            ClientChoice::Register {
                endpoint: String::from("https://as.example.com/register")
            }
        );
        document.client_id_metadata_document_supported = true;
        assert_eq!(
            choose_client(&document, None, base).unwrap(),
            ClientChoice::Cimd(ClientCredentials {
                client_id: String::from("https://axon.example.com/oauth/upstream/client.json"),
                client_secret: None,
            })
        );
        assert_eq!(
            choose_client(&document, Some(client(Some("s"))), base).unwrap(),
            ClientChoice::Static(client(Some("s")))
        );
    }

    #[test]
    fn the_client_metadata_document_names_the_gateway() {
        let document = client_metadata_document("https://axon.example.com/");
        assert_eq!(
            document["client_id"],
            "https://axon.example.com/oauth/upstream/client.json"
        );
        assert_eq!(document["client_name"], "axon-gateway");
        assert_eq!(
            document["redirect_uris"],
            json!(["https://axon.example.com/oauth/upstream/callback"])
        );
        assert_eq!(
            document["grant_types"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(document["response_types"], json!(["code"]));
        assert_eq!(document["token_endpoint_auth_method"], "none");
    }

    #[test]
    fn scope_comes_from_the_client_then_the_resource() {
        let own = |s: &[&str]| s.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            select_scope(&own(&["a", "b"]), &own(&["c"])).as_deref(),
            Some("a b")
        );
        assert_eq!(select_scope(&[], &own(&["c", "d"])).as_deref(), Some("c d"));
        assert_eq!(select_scope(&[], &[]), None);
    }

    #[test]
    fn the_authorization_request_uses_pkce_s256_and_a_resource() {
        let mut document = metadata();
        document.authorization_endpoint = String::from("https://as.example.com/authorize?tenant=1");
        let request = build_authorization_request(
            &document,
            "axon",
            "https://axon.example.com/oauth/upstream/callback",
            "https://mcp.example.com/mcp",
            Some("read write"),
        )
        .unwrap();
        let url = Url::parse(&request.url).unwrap();
        let query = |key: &str| {
            url.query_pairs()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.into_owned())
        };
        assert_eq!(query("tenant").as_deref(), Some("1"));
        assert_eq!(query("response_type").as_deref(), Some("code"));
        assert_eq!(query("client_id").as_deref(), Some("axon"));
        assert_eq!(query("code_challenge_method").as_deref(), Some("S256"));
        assert_eq!(
            query("resource").as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        assert_eq!(query("scope").as_deref(), Some("read write"));
        assert_eq!(query("state").as_deref(), Some(request.state.as_str()));
        assert_eq!(request.state.len(), 64, "256 bits, hex");
        assert!(request.pkce_verifier.len() >= 43);
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(request.pkce_verifier.as_bytes()));
        assert_eq!(query("code_challenge").as_deref(), Some(expected.as_str()));

        let again =
            build_authorization_request(&document, "axon", "r", "https://x/", None).unwrap();
        assert_ne!(again.state, request.state);
        assert!(
            Url::parse(&again.url)
                .unwrap()
                .query_pairs()
                .all(|(k, _)| k != "scope")
        );
    }

    #[test]
    fn the_callback_issuer_is_required_and_checked_when_supported() {
        let issuer = "https://as.example.com";
        assert!(check_callback_issuer(issuer, true, Some(issuer)).is_ok());
        assert!(check_callback_issuer(issuer, true, Some("https://evil")).is_err());
        assert!(
            check_callback_issuer(issuer, true, None).is_err(),
            "RFC 9207: required"
        );
        assert!(check_callback_issuer(issuer, false, Some("https://other")).is_ok());
        assert!(check_callback_issuer(issuer, false, None).is_ok());
    }

    #[test]
    fn a_token_response_without_a_refresh_token_keeps_the_old_one() {
        let now = Utc::now();
        let body = br#"{"access_token":"a2","token_type":"Bearer","expires_in":60,"scope":"x"}"#;
        let parsed = parse_token_response(body, Some("old"), now).unwrap();
        assert_eq!(parsed.tokens.access_token, "a2");
        assert_eq!(parsed.tokens.refresh_token.as_deref(), Some("old"));
        assert_eq!(parsed.expires_at, now + chrono::Duration::seconds(60));
        assert_eq!(parsed.scope.as_deref(), Some("x"));

        let body = br#"{"access_token":"a3","refresh_token":"new"}"#;
        let parsed = parse_token_response(body, Some("old"), now).unwrap();
        assert_eq!(parsed.tokens.refresh_token.as_deref(), Some("new"));
        assert_eq!(
            parsed.expires_at,
            now + chrono::Duration::hours(1),
            "default 1 h"
        );
        assert_eq!(parse_token_response(body, None, now).unwrap().scope, None);

        let body = br#"{"access_token":"a","expires_in":"120"}"#;
        assert_eq!(
            parse_token_response(body, None, now).unwrap().expires_at,
            now + chrono::Duration::seconds(120)
        );
        assert!(parse_token_response(br#"{"access_token":""}"#, None, now).is_err());
        assert!(parse_token_response(b"{}", None, now).is_err());
    }

    #[test]
    fn an_oauth_error_is_reported_without_tokens() {
        let reply = Reply {
            status: StatusCode::BAD_REQUEST,
            body: br#"{"error":"invalid_grant","error_description":"expired"}"#.to_vec(),
        };
        let error = refused(&reply);
        assert!(error.is_invalid_grant());
        assert_eq!(
            error.to_string(),
            "the authorization server answered 400: invalid_grant (expired)"
        );
        let reply = Reply {
            status: StatusCode::BAD_GATEWAY,
            body: b"<html>".to_vec(),
        };
        let error = refused(&reply);
        assert!(!error.is_invalid_grant());
        assert!(error.to_string().contains("502"));
    }

    #[test]
    fn the_token_exchange_form_follows_rfc_8693() {
        let form = token_exchange_form(&TokenExchangeRequest {
            subject_token: "subj",
            audience: Some("api://backend"),
            scope: None,
            resource: Some("https://mcp.example.com/mcp"),
        });
        assert_eq!(
            form,
            vec![
                (
                    "grant_type",
                    String::from("urn:ietf:params:oauth:grant-type:token-exchange")
                ),
                ("subject_token", String::from("subj")),
                (
                    "subject_token_type",
                    String::from("urn:ietf:params:oauth:token-type:access_token")
                ),
                (
                    "requested_token_type",
                    String::from("urn:ietf:params:oauth:token-type:access_token")
                ),
                ("audience", String::from("api://backend")),
                ("resource", String::from("https://mcp.example.com/mcp")),
            ]
        );
    }

    #[test]
    fn the_on_behalf_of_form_carries_the_client_credentials() {
        let form = on_behalf_of_form("app", "s3cret", "user-token", "api://x/.default");
        assert_eq!(
            field(&form, "grant_type"),
            Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
        );
        assert_eq!(field(&form, "assertion"), Some("user-token"));
        assert_eq!(field(&form, "requested_token_use"), Some("on_behalf_of"));
        assert_eq!(field(&form, "scope"), Some("api://x/.default"));
        assert_eq!(field(&form, "client_id"), Some("app"));
        assert_eq!(field(&form, "client_secret"), Some("s3cret"));
    }

    #[test]
    fn code_and_refresh_forms_send_the_resource() {
        let form = code_form("c", "https://r/cb", "v", "https://mcp/mcp");
        assert_eq!(field(&form, "grant_type"), Some("authorization_code"));
        assert_eq!(field(&form, "code_verifier"), Some("v"));
        assert_eq!(field(&form, "resource"), Some("https://mcp/mcp"));
        let form = refresh_form("rt", None, Some("https://mcp/mcp"));
        assert_eq!(field(&form, "grant_type"), Some("refresh_token"));
        assert_eq!(field(&form, "refresh_token"), Some("rt"));
        assert_eq!(field(&form, "resource"), Some("https://mcp/mcp"));
        assert_eq!(field(&form, "scope"), None);
    }

    #[test]
    fn client_authentication_follows_the_listed_methods() {
        let own = |s: &[&str]| s.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>();
        let pick = |client: &ClientCredentials, listed: Option<&[String]>| {
            let mut form = Form::new();
            let method = TokenAuthMethod::choose(client, listed);
            let basic = authenticate(&mut form, client, method);
            (method, basic, form)
        };

        let (method, basic, form) = pick(&client(None), None);
        assert_eq!((method, basic), (TokenAuthMethod::None, None));
        assert_eq!(field(&form, "client_id"), Some("axon"));
        assert_eq!(field(&form, "client_secret"), None);

        let (method, basic, form) = pick(&client(Some("p w")), None);
        assert_eq!(method, TokenAuthMethod::ClientSecretBasic);
        assert_eq!(basic, Some((String::from("axon"), String::from("p+w"))));
        assert_eq!(form, [] as [(&str, String); 0]);

        let methods = own(&["client_secret_post"]);
        let (method, basic, form) = pick(&client(Some("s")), Some(&methods));
        assert_eq!((method, basic), (TokenAuthMethod::ClientSecretPost, None));
        assert_eq!(field(&form, "client_id"), Some("axon"));
        assert_eq!(field(&form, "client_secret"), Some("s"));

        let methods = own(&["client_secret_post", "client_secret_basic"]);
        let (method, basic, _) = pick(&client(Some("s")), Some(&methods));
        assert_eq!(method, TokenAuthMethod::ClientSecretBasic);
        assert!(basic.is_some());

        // A stored method outlives a secret that is gone: the id is still sent
        let mut form = Form::new();
        assert_eq!(
            authenticate(&mut form, &client(None), TokenAuthMethod::ClientSecretBasic),
            None
        );
        assert_eq!(field(&form, "client_id"), Some("axon"));
    }

    #[test]
    fn token_auth_methods_round_trip_their_names() {
        for method in [
            TokenAuthMethod::None,
            TokenAuthMethod::ClientSecretBasic,
            TokenAuthMethod::ClientSecretPost,
        ] {
            assert_eq!(TokenAuthMethod::parse(method.as_str()), Some(method));
        }
        assert_eq!(TokenAuthMethod::parse("private_key_jwt"), None);
    }

    #[test]
    fn form_bodies_are_percent_encoded() {
        let form: Form = vec![("a", String::from("x y&z=é")), ("b", String::from("1"))];
        assert_eq!(form_body(&form), "a=x+y%26z%3D%C3%A9&b=1");
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let creds = format!("{:?}", client(Some("hunter2")));
        assert!(creds.contains("axon") && !creds.contains("hunter2"));
        let tokens = StoredTokens {
            access_token: String::from("at-secret"),
            refresh_token: Some(String::from("rt-secret")),
        };
        let shown = format!("{tokens:?}");
        assert!(!shown.contains("at-secret") && !shown.contains("rt-secret"));
        let response = TokenResponse {
            tokens,
            expires_at: Utc::now(),
            scope: None,
        };
        let shown = format!("{response:?}");
        assert!(!shown.contains("at-secret") && !shown.contains("rt-secret"));
        let request = AuthorizationRequest {
            url: String::from("https://as/authorize?state=st-secret"),
            state: String::from("st-secret"),
            pkce_verifier: String::from("ver-secret"),
        };
        let shown = format!("{request:?}");
        assert!(!shown.contains("st-secret") && !shown.contains("ver-secret"));
        let shown = format!(
            "{:?}",
            TokenExchangeRequest {
                subject_token: "subj-secret",
                audience: None,
                scope: None,
                resource: None,
            }
        );
        assert!(!shown.contains("subj-secret"));
    }

    #[test]
    fn sealed_values_round_trip_and_are_bound_to_their_row() {
        let keyring = keyring();
        let user = Uuid::new_v4();
        let tokens = StoredTokens {
            access_token: String::from("at"),
            refresh_token: Some(String::from("rt")),
        };
        let sealed = seal_tokens(&keyring, user, "wiki", &tokens).unwrap();
        assert_eq!(
            open_tokens(&keyring, user, "wiki", &sealed).unwrap(),
            tokens
        );
        assert!(open_tokens(&keyring, user, "other", &sealed).is_err());
        assert!(open_tokens(&keyring, Uuid::new_v4(), "wiki", &sealed).is_err());

        let sealed = seal_idp_refresh_token(&keyring, user, "entra", "idp-rt").unwrap();
        assert_eq!(
            open_idp_refresh_token(&keyring, user, "entra", &sealed).unwrap(),
            "idp-rt"
        );
        assert!(open_idp_refresh_token(&keyring, user, "other", &sealed).is_err());

        let sealed = seal_client_secret(&keyring, "wiki", "https://as", "shh").unwrap();
        assert_eq!(
            open_client_secret(&keyring, "wiki", "https://as", &sealed).unwrap(),
            "shh"
        );
        assert!(open_client_secret(&keyring, "wiki", "https://other", &sealed).is_err());
    }

    const BACKEND: &str = "https://mcp.example.com/mcp";

    #[tokio::test]
    async fn same_origin_needs_no_policy() {
        let fetcher = Fetcher::for_backend(BACKEND, None).unwrap();
        for url in [
            "https://mcp.example.com/token",
            "https://mcp.example.com:443/register",
        ] {
            assert!(fetcher.client(url).await.is_ok(), "{url}");
        }
    }

    #[tokio::test]
    async fn other_origin_without_a_policy_is_refused() {
        let fetcher = Fetcher::for_backend(BACKEND, None).unwrap();
        for url in [
            "https://as.example.com/token",
            "http://mcp.example.com/token",
            "https://mcp.example.com:8443/token",
        ] {
            let error = fetcher.client(url).await.unwrap_err();
            assert!(
                matches!(&error, UpstreamOauthError::Metadata(m) if m.contains("no egress policy")),
                "{url}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn other_origin_goes_through_the_policy() {
        let deny = EgressPolicy::new(&[], &[]).unwrap();
        let fetcher = Fetcher::for_backend(BACKEND, Some(&deny)).unwrap();
        for url in ["http://127.0.0.1:9/token", "http://169.254.169.254/latest"] {
            let error = fetcher.client(url).await.unwrap_err();
            assert!(
                matches!(
                    error,
                    UpstreamOauthError::Egress(EgressError::Denied { .. })
                ),
                "{url}: {error}"
            );
        }
        let allow = EgressPolicy::new(&[String::from("127.0.0.1/32")], &[]).unwrap();
        let fetcher = Fetcher::for_backend(BACKEND, Some(&allow)).unwrap();
        assert!(fetcher.client("http://127.0.0.1:9/token").await.is_ok());
        assert!(fetcher.client("http://169.254.169.254/").await.is_err());
    }

    #[tokio::test]
    async fn trusted_fetcher_reaches_any_origin() {
        assert!(
            Fetcher::trusted()
                .client("http://127.0.0.1:9/token")
                .await
                .is_ok()
        );
    }

    #[test]
    fn authorization_endpoint_is_an_http_url() {
        for ok in [
            "https://as.example.com/authorize",
            "http://localhost:8080/authorize",
            "http://other-host/authorize",
        ] {
            check_authorization_endpoint(ok).unwrap();
        }
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "/authorize",
        ] {
            assert!(check_authorization_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refused_keeps_only_the_error_and_a_clipped_description() {
        let long = "x".repeat(500);
        let reply = Reply {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::to_vec(
                &json!({"error": "invalid_grant", "error_description": long, "secret": "hunter2"}),
            )
            .unwrap(),
        };
        let UpstreamOauthError::Refused { code, message, .. } = refused(&reply) else {
            panic!("not refused");
        };
        assert_eq!(code, "invalid_grant");
        assert!(!message.contains("hunter2"));
        assert_eq!(message.chars().count(), "invalid_grant ()".len() + 200);
        let reply = Reply {
            status: StatusCode::BAD_GATEWAY,
            body: b"<html>internal page</html>".to_vec(),
        };
        let error = refused(&reply).to_string();
        assert!(!error.contains("internal page"), "{error}");
    }
}
