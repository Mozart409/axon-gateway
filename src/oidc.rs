//! The `OpenID Connect` relying party: discovery, the authorization URL, the
//! code exchange and ID token verification, for several providers at once.
//!
//! Ported from `rust/lanternd`. The flow is the authorization-code flow with
//! PKCE, a `state` and a nonce. The OAuth 2.0 side (authorization URL, PKCE,
//! code exchange) is `oauth2`; discovery, the signing keys and the ID token
//! checks of OIDC Core 3.1.3.7 are done here, with `jsonwebtoken` (on aws-lc,
//! so without the `rsa` crate) checking the signature. Three things matter:
//!
//! * **Discovery is lazy and refreshed.** A gateway whose identity provider is
//!   down at boot must still start. The provider metadata and its signing keys
//!   are fetched on the first login and again after [`METADATA_TTL`]. Until
//!   discovery works that provider's login fails closed, not open.
//! * **A rotated key is picked up at once.** A token naming a key id the
//!   cached key set lacks makes the keys be fetched again, at most once per
//!   [`JWKS_REFETCH_INTERVAL`], so made-up key ids cannot make the gateway
//!   hammer the provider.
//! * **The client secret is optional.** Without one a provider is a public
//!   PKCE client.
//!
//! On top of that a verified ID token is mapped to a login: the groups are
//! read from the configured claim, `admin_groups` decide `is_admin`, and
//! `allowed_email_domains` can refuse a user whose email is elsewhere.
//!
//! All provider traffic goes through one reqwest client per provider with
//! redirects disabled (a token endpoint that redirects is an SSRF vector, not
//! a feature) and a timeout.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use oauth2::basic::{
    BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
    BasicTokenType,
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointNotSet, EndpointSet,
    ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardRevocableToken, StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};

use crate::config::OidcProviderConfig;
use crate::upstream_oauth::ClientCredentials;

/// How long discovered provider metadata is trusted before it is fetched again.
pub const METADATA_TTL: Duration = Duration::from_secs(3_600);

/// The signing keys are fetched again for an unknown key id at most this often.
pub const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// A Graph app token is fetched again this long before it expires.
const GRAPH_TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// At most this many pages of groups are read from Graph for one login.
const GRAPH_MAX_PAGES: usize = 50;

/// Clock skew allowed between the gateway and the provider for `exp`, `iat`
/// and `nbf`, in seconds.
const LEEWAY_SECS: u64 = 60;

/// The ID token signature algorithms accepted at all: asymmetric only, so
/// never `none` or an HMAC keyed with the (shared) client secret.
const ASYMMETRIC_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Why a login with an OIDC provider failed.
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    /// `client_secret_env` names a variable that is unset or empty.
    #[error("OIDC provider '{provider}': client secret variable {var} is not set or empty")]
    MissingSecret {
        /// The provider's `id`.
        provider: String,
        /// The environment variable.
        var: String,
    },
    /// Discovery, the key set or the token endpoint failed.
    #[error("OIDC provider '{provider}': {message}")]
    Provider {
        /// The provider's `id`.
        provider: String,
        /// What went wrong.
        message: String,
    },
    /// The ID token did not verify.
    #[error("the ID token was refused: {0}")]
    Rejected(String),
    /// The user's email is not in `allowed_email_domains`.
    #[error("email domain is not allowed to log in")]
    EmailDomainNotAllowed,
    /// The access token verified except that it has expired.
    #[error("the access token has expired")]
    Expired,
}

/// What an access token is: its issuer, subject and who it identifies.
pub struct AccessTokenClaims {
    /// The provider's issuer, as configured.
    pub issuer: String,
    /// The `sub` claim.
    pub subject: String,
    /// The groups in the provider's `groups_claim`; `None` when the token has none.
    pub groups: Option<Vec<String>>,
    /// The `email` claim, if any.
    pub email: Option<String>,
    /// The token as presented, for forwarding in a token exchange.
    pub token: String,
    /// The `exp` claim, in seconds since the epoch.
    pub expires_at: u64,
}

impl fmt::Debug for AccessTokenClaims {
    // By hand, so the bearer token can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessTokenClaims")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("groups", &self.groups)
            .field("email", &self.email)
            .field("expires_at", &self.expires_at)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// What the browser is sent to the provider with, and what must be kept until
/// it comes back.
pub struct LoginRedirect {
    /// The provider's authorization URL.
    pub url: String,
    /// The `state` parameter: the CSRF token and the key of the stored flow.
    pub state: String,
    /// The nonce the ID token must echo: 128 random bits, base64url.
    pub nonce: String,
    /// The PKCE verifier for the token request.
    pub pkce_verifier: String,
}

impl fmt::Debug for LoginRedirect {
    // By hand, so the flow secrets can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRedirect")
            .field("url", &self.url)
            .field("state", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("pkce_verifier", &"<redacted>")
            .finish()
    }
}

/// Who the provider says logged in, after every check passed.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedLogin {
    /// The `iss` claim.
    pub issuer: String,
    /// The `sub` claim.
    pub subject: String,
    /// The `name` claim.
    pub name: Option<String>,
    /// The `email` claim.
    pub email: Option<String>,
    /// The groups read from the provider's `groups_claim`.
    pub groups: Vec<String>,
    /// Whether any of `groups` is in the provider's `admin_groups`.
    pub is_admin: bool,
    /// The raw ID token, for `id_token_hint` at logout.
    pub id_token: String,
    /// The refresh token of the code exchange, when the provider gave one
    /// (`offline_access`); kept for the passthrough grants.
    pub refresh_token: Option<String>,
    /// The string value of the provider's `scim_match_claim` in the ID token
    /// (a number is stringified); what a SCIM `externalId` is matched against.
    /// `None` when the claim is missing, or an array or an object.
    pub scim_key: Option<String>,
}

impl fmt::Debug for VerifiedLogin {
    // By hand, so the ID token can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedLogin")
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("name", &self.name)
            .field("email", &self.email)
            .field("groups", &self.groups)
            .field("is_admin", &self.is_admin)
            .field("id_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("scim_key", &self.scim_key)
            .finish()
    }
}

/// The extra field OIDC adds to the OAuth 2.0 token response.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct IdTokenFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

impl ExtraTokenFields for IdTokenFields {}

/// An OAuth 2.0 client with the authorization and token endpoints set, whose
/// token response carries the ID token.
type OidcClient = oauth2::Client<
    BasicErrorResponse,
    StandardTokenResponse<IdTokenFields, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

/// The parts of the provider's discovery document that are used.
#[derive(Deserialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    end_session_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
}

/// An app token for Microsoft Graph, and when to get a new one.
struct GraphToken {
    token: String,
    refresh_at: Instant,
}

/// The parts of a client-credentials token response that are used.
#[derive(Deserialize)]
struct GraphTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// One page of `transitiveMemberOf`.
#[derive(Deserialize)]
struct GraphPage {
    #[serde(default)]
    value: Vec<GraphGroup>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// A group in a Graph answer (`$select=id,displayName`); only the object id is kept.
#[derive(Deserialize)]
struct GraphGroup {
    #[serde(default)]
    id: Option<String>,
}

/// The provider's signing keys, and when they were fetched.
struct Keys {
    set: JwkSet,
    fetched: Instant,
}

/// What discovery found: the endpoints (as an `oauth2` client), the accepted
/// algorithms and the signing keys.
struct Discovery {
    discovered: Instant,
    client: OidcClient,
    /// The ID token algorithms the provider advertises and we accept.
    algorithms: Vec<Algorithm>,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
    /// The token endpoint and the client authentication methods it lists
    token_endpoint: String,
    token_auth_methods: Option<Vec<String>>,
    keys: RwLock<Keys>,
}

impl Discovery {
    /// Fetches the signing keys again, unless that was tried within the
    /// last [`JWKS_REFETCH_INTERVAL`]. The write lock is held across the
    /// fetch, so concurrent logins wait for one fetch instead of each running
    /// their own, and a failed fetch counts as a try, so a provider whose keys
    /// endpoint is down is not asked again on every login.
    async fn refresh_keys(&self, provider: &str, http: &reqwest::Client) -> Result<(), String> {
        let mut keys = self.keys.write().await;
        if keys.fetched.elapsed() < JWKS_REFETCH_INTERVAL {
            return Ok(());
        }
        keys.fetched = Instant::now();
        let set = observed(provider, "jwks", get_json(http, &self.jwks_uri))
            .await
            .map_err(|error| format!("could not fetch the signing keys again: {error}"))?;
        keys.set = set;
        drop(keys);
        Ok(())
    }
}

/// The configured providers, in config order. Cheap to clone.
#[derive(Clone, Debug)]
pub struct OidcProviders {
    providers: Arc<Vec<Provider>>,
}

impl OidcProviders {
    /// Builds the providers from config. Reads each client secret from its
    /// environment variable now, but does not talk to any provider.
    /// `redirect_url` is `{base_url}/auth/callback`, shared by all of them.
    ///
    /// # Errors
    /// Fails on an unset or empty client secret variable, an unparseable
    /// redirect URL or an HTTP client that cannot be built: config mistakes,
    /// which should stop the gateway at startup.
    pub fn new(configs: &[OidcProviderConfig], redirect_url: &str) -> Result<Self, OidcError> {
        let providers = configs
            .iter()
            .map(|config| Provider::new(config, redirect_url))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            providers: Arc::new(providers),
        })
    }

    /// The provider with this `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|provider| provider.id == id)
    }

    /// The `id` of the provider with this issuer.
    #[must_use]
    pub fn id_for_issuer(&self, issuer: &str) -> Option<&str> {
        self.providers
            .iter()
            .find(|provider| provider.issuer == issuer)
            .map(|provider| provider.id.as_str())
    }

    /// The provider that issued `token` (by its unverified `iss`) when it
    /// accepts access tokens. Only picks who must verify the token: nothing
    /// here is trusted until [`Provider::verify_access_token`] has run.
    #[must_use]
    pub fn access_token_provider(&self, token: &str) -> Option<&Provider> {
        #[derive(Deserialize)]
        struct Unverified {
            iss: String,
        }
        let Unverified { iss } = jsonwebtoken::dangerous::insecure_decode_claims(token).ok()?;
        self.providers
            .iter()
            .find(|provider| provider.accept_access_tokens && provider.issuer == iss)
    }

    /// The providers in config order.
    pub fn iter(&self) -> impl Iterator<Item = &Provider> {
        self.providers.iter()
    }
}

/// One configured provider.
pub struct Provider {
    id: String,
    display_name: String,
    issuer: String,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    redirect_url: RedirectUrl,
    scopes: Vec<Scope>,
    groups_claim: String,
    allowed_email_domains: Vec<String>,
    admin_groups: Vec<String>,
    accept_access_tokens: bool,
    access_token_audience: String,
    graph_overage: bool,
    /// The Graph base URL, without a trailing slash.
    graph_url: String,
    scim_match_claim: String,
    /// The cached Graph app token. The lock is held across the token request,
    /// so concurrent logins wait for one request instead of each running their own.
    graph_token: Mutex<Option<GraphToken>>,
    http: reqwest::Client,
    discovery: RwLock<Option<Arc<Discovery>>>,
}

impl fmt::Debug for Provider {
    // By hand, so the client secret can never end up in a log line.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Provider")
            .field("id", &self.id)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id.as_str())
            .field("redirect_url", &self.redirect_url.as_str())
            .field("confidential", &self.client_secret.is_some())
            .finish_non_exhaustive()
    }
}

impl Provider {
    fn new(config: &OidcProviderConfig, redirect_url: &str) -> Result<Self, OidcError> {
        let error = |message: String| OidcError::Provider {
            provider: config.id.clone(),
            message,
        };
        let client_secret = match &config.client_secret_env {
            Some(var) => match std::env::var(var) {
                Ok(secret) if !secret.is_empty() => Some(ClientSecret::new(secret)),
                _ => {
                    return Err(OidcError::MissingSecret {
                        provider: config.id.clone(),
                        var: var.clone(),
                    });
                }
            },
            None => None,
        };
        let redirect_url = RedirectUrl::new(redirect_url.to_owned())
            .map_err(|source| error(format!("redirect URL: {source}")))?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|source| error(format!("could not build the HTTP client: {source}")))?;
        Ok(Self {
            id: config.id.clone(),
            display_name: config.display_name().to_owned(),
            issuer: config.issuer.clone(),
            client_id: ClientId::new(config.client_id.clone()),
            client_secret,
            redirect_url,
            // `openid` is always sent first, see `authorize`.
            scopes: config
                .scopes
                .iter()
                .filter(|scope| scope.as_str() != "openid")
                .map(|scope| Scope::new(scope.clone()))
                .collect(),
            groups_claim: config.groups_claim.clone(),
            allowed_email_domains: config.allowed_email_domains.clone(),
            admin_groups: config.admin_groups.clone(),
            accept_access_tokens: config.accept_access_tokens,
            access_token_audience: config.access_token_audience().to_owned(),
            graph_overage: config.graph_overage,
            graph_url: config.graph_url().to_owned(),
            scim_match_claim: config.scim_match_claim().to_owned(),
            graph_token: Mutex::new(None),
            http,
            discovery: RwLock::new(None),
        })
    }

    /// The provider's `id`, as used in login URLs.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The name shown on the login button.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The issuer, as configured.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Whether JWT access tokens of this provider are accepted as bearer tokens.
    #[must_use]
    pub fn accepts_access_tokens(&self) -> bool {
        self.accept_access_tokens
    }

    /// Verifies a JWT access token this provider issued for this gateway (as
    /// [`verify_access_jwt`] says) against the cached keys, fetched again once
    /// for a key the cache does not know yet, like [`Self::verify`].
    ///
    /// # Errors
    /// [`OidcError::Expired`] for a token that only fails on `exp`,
    /// [`OidcError::Rejected`] for any other refusal and
    /// [`OidcError::Provider`] when discovery or the key fetch fails.
    pub async fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, OidcError> {
        let discovery = self.discovery().await?;
        let expected = AccessExpected {
            issuer: &self.issuer,
            audience: &self.access_token_audience,
            algorithms: &discovery.algorithms,
        };
        let now = unix_now();
        let first = verify_access_jwt(token, &discovery.keys.read().await.set, &expected, now);
        let result = if matches!(first, Err(Rejection::UnknownKey)) {
            discovery
                .refresh_keys(&self.id, &self.http)
                .await
                .map_err(|error| self.error(error))?;
            verify_access_jwt(token, &discovery.keys.read().await.set, &expected, now)
        } else {
            first
        };
        let verified = result.map_err(|error| match error {
            Rejection::Expired => OidcError::Expired,
            other => OidcError::Rejected(other.to_string()),
        })?;
        Ok(AccessTokenClaims {
            issuer: verified.iss,
            subject: verified.sub,
            groups: claim_at(&verified.extra, &self.groups_claim)
                .is_some()
                .then(|| groups_from(&verified.extra, &self.groups_claim)),
            email: verified.email,
            token: token.to_owned(),
            expires_at: verified.exp,
        })
    }

    fn error(&self, message: String) -> OidcError {
        OidcError::Provider {
            provider: self.id.clone(),
            message,
        }
    }

    /// The provider's discovery, fetched on first use and again after
    /// [`METADATA_TTL`].
    async fn discovery(&self) -> Result<Arc<Discovery>, OidcError> {
        if let Some(discovery) = &*self.discovery.read().await
            && discovery.discovered.elapsed() < METADATA_TTL
        {
            return Ok(Arc::clone(discovery));
        }
        let mut slot = self.discovery.write().await;
        // Another request may have refreshed it while this one waited.
        if let Some(discovery) = &*slot
            && discovery.discovered.elapsed() < METADATA_TTL
        {
            return Ok(Arc::clone(discovery));
        }
        let discovery = Arc::new(self.discover().await.map_err(|error| {
            self.error(format!("discovery at {} failed: {error}", self.issuer))
        })?);
        // The write lock is held across discovery on purpose: concurrent
        // logins wait for one discovery instead of each running their own.
        *slot = Some(Arc::clone(&discovery));
        drop(slot);
        Ok(discovery)
    }

    /// Reads `{issuer}/.well-known/openid-configuration` and the key set it
    /// points to.
    async fn discover(&self) -> Result<Discovery, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let metadata: ProviderMetadata =
            observed(&self.id, "discovery", get_json(&self.http, &url)).await?;
        // The provider must name itself exactly as configured (OIDC Discovery
        // 4.3); its ID tokens carry the same string in `iss`.
        if metadata.issuer != self.issuer {
            return Err(format!(
                "the provider's issuer is {:?}, not the configured {:?}",
                metadata.issuer, self.issuer
            ));
        }
        let algorithms = accepted_algorithms(&metadata.id_token_signing_alg_values_supported);
        if algorithms.is_empty() {
            return Err(format!(
                "the provider signs ID tokens with none of the accepted algorithms: {:?}",
                metadata.id_token_signing_alg_values_supported
            ));
        }
        let set = observed(&self.id, "jwks", get_json(&self.http, &metadata.jwks_uri)).await?;
        let token_endpoint = metadata.token_endpoint.clone();
        let mut client: OidcClient = oauth2::Client::new(self.client_id.clone())
            .set_auth_uri(
                AuthUrl::new(metadata.authorization_endpoint)
                    .map_err(|error| format!("authorization_endpoint: {error}"))?,
            )
            .set_token_uri(
                TokenUrl::new(metadata.token_endpoint)
                    .map_err(|error| format!("token_endpoint: {error}"))?,
            )
            .set_redirect_uri(self.redirect_url.clone());
        if let Some(secret) = &self.client_secret {
            client = client.set_client_secret(secret.clone());
        }
        Ok(Discovery {
            discovered: Instant::now(),
            client,
            algorithms,
            jwks_uri: metadata.jwks_uri,
            end_session_endpoint: metadata.end_session_endpoint,
            token_endpoint,
            token_auth_methods: metadata.token_endpoint_auth_methods_supported,
            keys: RwLock::new(Keys {
                set,
                fetched: Instant::now(),
            }),
        })
    }

    /// Starts a login: a fresh `state`, nonce and PKCE pair, and the URL to
    /// send the browser to.
    ///
    /// # Errors
    /// Fails when the provider cannot be discovered.
    #[tracing::instrument(skip_all, fields(provider = %self.id()))]
    pub async fn authorize(&self) -> Result<LoginRedirect, OidcError> {
        let discovery = self.discovery().await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        // 128 random bits, base64url, as for the state.
        let nonce = CsrfToken::new_random().into_secret();
        let mut request = discovery
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_owned()))
            .add_extra_param("nonce", nonce.clone());
        for scope in &self.scopes {
            request = request.add_scope(scope.clone());
        }
        let (url, state) = request.set_pkce_challenge(challenge).url();
        Ok(LoginRedirect {
            url: url.to_string(),
            state: state.into_secret(),
            nonce,
            pkce_verifier: verifier.into_secret(),
        })
    }

    /// Exchanges the authorization code, verifies the ID token (signature,
    /// issuer, audience, expiry and nonce) and maps it to a login: groups,
    /// admin flag and the email domain check.
    ///
    /// # Errors
    /// Fails when the provider is unreachable or rejects the code, when the ID
    /// token does not verify, or when the email domain is not allowed.
    #[tracing::instrument(skip_all, fields(provider = %self.id()))]
    pub async fn exchange(
        &self,
        code: &str,
        pkce_verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedLogin, OidcError> {
        let discovery = self.discovery().await?;
        // The closure owns a clone of the client, so the future oauth2 builds
        // from it borrows nothing and stays `Send` for axum.
        let http = |request| send(self.http.clone(), request);
        let response = observed(
            &self.id,
            "token",
            discovery
                .client
                .exchange_code(AuthorizationCode::new(code.to_owned()))
                .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
                .request_async(&http),
        )
        .await
        .map_err(|error| self.error(format!("the code exchange failed: {error}")))?;
        let id_token = response
            .extra_fields()
            .id_token
            .as_deref()
            .ok_or_else(|| self.error("the provider returned no ID token".to_owned()))?;
        let claims = self.verify(&discovery, id_token, nonce).await?;
        let mut login = self.login(claims, id_token).await?;
        login.refresh_token = response
            .refresh_token()
            .map(|token| token.secret().clone())
            .filter(|token| !token.is_empty());
        Ok(login)
    }

    /// The provider's token endpoint and the client authentication methods it
    /// lists, from the cached discovery (fetched when there is none).
    ///
    /// # Errors
    /// Fails when the provider cannot be discovered.
    pub async fn token_endpoint(&self) -> Result<(String, Option<Vec<String>>), OidcError> {
        let discovery = self.discovery().await?;
        Ok((
            discovery.token_endpoint.clone(),
            discovery.token_auth_methods.clone(),
        ))
    }

    /// The gateway's own client at this provider, for the passthrough grants.
    #[must_use]
    pub fn app_credentials(&self) -> ClientCredentials {
        ClientCredentials {
            client_id: self.client_id.as_str().to_owned(),
            client_secret: self
                .client_secret
                .as_ref()
                .map(|secret| secret.secret().clone()),
        }
    }

    /// The configured scopes, without `openid`.
    #[must_use]
    pub fn scopes(&self) -> Vec<String> {
        self.scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect()
    }

    /// [`verify_id_token`] against the cached keys. A token signed with a key
    /// the cache does not know yet may follow a key rotation, so the keys are
    /// fetched again (at most every [`JWKS_REFETCH_INTERVAL`]) and the token
    /// checked once more.
    async fn verify(
        &self,
        discovery: &Discovery,
        token: &str,
        nonce: &str,
    ) -> Result<IdTokenClaims, OidcError> {
        let expected = Expected {
            issuer: &self.issuer,
            client_id: self.client_id.as_str(),
            nonce,
            algorithms: &discovery.algorithms,
        };
        let now = unix_now();
        let first = verify_id_token(token, &discovery.keys.read().await.set, &expected, now);
        if !matches!(first, Err(Rejection::UnknownKey)) {
            return first.map_err(|error| OidcError::Rejected(error.to_string()));
        }
        discovery
            .refresh_keys(&self.id, &self.http)
            .await
            .map_err(|error| self.error(error))?;
        verify_id_token(token, &discovery.keys.read().await.set, &expected, now)
            .map_err(|error| OidcError::Rejected(error.to_string()))
    }

    /// Maps verified claims to a login. Runs after the signature check, so
    /// nothing here trusts an unverified token.
    async fn login(
        &self,
        claims: IdTokenClaims,
        id_token: &str,
    ) -> Result<VerifiedLogin, OidcError> {
        // An unverified address proves nothing about its domain: anyone can
        // put `x@corp.example` in a profile at a provider that does not check.
        let email_verified = claim_is_true(claims.email_verified.as_ref())
            || claim_is_true(claims.xms_edov.as_ref());
        if !self.allowed_email_domains.is_empty() && !email_verified {
            return Err(OidcError::EmailDomainNotAllowed);
        }
        if !email_allowed(&self.allowed_email_domains, claims.email.as_deref()) {
            return Err(OidcError::EmailDomainNotAllowed);
        }
        let mut groups = groups_from(&claims.extra, &self.groups_claim);
        if has_group_overage(&claims.extra) {
            if self.graph_overage {
                groups = self.overage_groups(&claims.extra).await;
            } else {
                tracing::warn!(
                    provider = %self.id,
                    "the groups were not in the ID token (group overage); the user gets none"
                );
            }
        }
        let scim_key = scim_key(&claims, &self.scim_match_claim);
        let is_admin = groups.iter().any(|group| self.admin_groups.contains(group));
        Ok(VerifiedLogin {
            issuer: claims.iss,
            subject: claims.sub,
            name: claims.name,
            email: claims.email,
            groups,
            is_admin,
            id_token: id_token.to_owned(),
            refresh_token: None,
            scim_key,
        })
    }

    /// The user's groups from Microsoft Graph, for an ID token with a groups
    /// overage. A failure is logged and gives no groups: Graph being down must
    /// not lock everybody out.
    async fn overage_groups(&self, claims: &Map<String, Value>) -> Vec<String> {
        let Some(oid) = claim_at(claims, "oid").and_then(Value::as_str) else {
            tracing::warn!(
                provider = %self.id,
                "group overage but the ID token has no oid claim; the user gets no groups"
            );
            return Vec::new();
        };
        if !is_object_id(oid) {
            tracing::warn!(
                provider = %self.id,
                "group overage but the oid claim is not an object id; the user gets no groups"
            );
            return Vec::new();
        }
        match self.graph_groups(oid).await {
            Ok(groups) => groups,
            Err(error) => {
                tracing::warn!(
                    provider = %self.id,
                    %error,
                    "could not fetch the groups of a user with a group overage from Microsoft Graph; the user gets none"
                );
                Vec::new()
            }
        }
    }

    /// The object ids of the groups `oid` is a member of, directly or not,
    /// following `@odata.nextLink` for at most [`GRAPH_MAX_PAGES`] pages.
    async fn graph_groups(&self, oid: &str) -> Result<Vec<String>, String> {
        let token = self.graph_app_token().await?;
        let mut url = format!(
            "{}/v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group?$select=id,displayName",
            self.graph_url
        );
        let mut groups = Vec::new();
        for _ in 0..GRAPH_MAX_PAGES {
            let page: GraphPage = observed(
                &self.id,
                "graph_groups",
                get_json_bearer(&self.http, &url, &token),
            )
            .await?;
            groups.extend(page.value.into_iter().filter_map(|group| group.id));
            match page.next_link {
                None => return Ok(groups),
                Some(next) if graph_link_allowed(&self.graph_url, &next) => url = next,
                Some(next) => {
                    return Err(format!(
                        "refusing the next page link {next}: it is not under {}",
                        self.graph_url
                    ));
                }
            }
        }
        Err(format!(
            "more than {GRAPH_MAX_PAGES} pages of groups, giving up"
        ))
    }

    /// An app token for Graph by client credentials at the provider's token
    /// endpoint, cached until [`GRAPH_TOKEN_MARGIN`] before it expires.
    async fn graph_app_token(&self) -> Result<String, String> {
        let mut slot = self.graph_token.lock().await;
        if let Some(cached) = &*slot
            && Instant::now() < cached.refresh_at
        {
            return Ok(cached.token.clone());
        }
        let secret = self
            .client_secret
            .as_ref()
            .ok_or("no client secret for the client credentials grant")?;
        let discovery = self.discovery().await.map_err(|error| error.to_string())?;
        let scope = format!("{}/.default", self.graph_url);
        let body = form_body(&[
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", secret.secret()),
            ("scope", &scope),
        ])?;
        let started = Instant::now();
        let response: GraphTokenResponse = observed(
            &self.id,
            "graph_token",
            post_form_json(&self.http, &discovery.token_endpoint, body),
        )
        .await?;
        let lifetime = Duration::from_secs(response.expires_in.unwrap_or(0));
        *slot = Some(GraphToken {
            token: response.access_token.clone(),
            refresh_at: started + lifetime.saturating_sub(GRAPH_TOKEN_MARGIN),
        });
        drop(slot);
        Ok(response.access_token)
    }

    /// The RP-initiated logout URL (OIDC `RP-Initiated Logout`) from the
    /// provider's `end_session_endpoint`, with the `id_token_hint`, the
    /// `post_logout_redirect_uri` and the `client_id`. `None` when the provider
    /// does not advertise one or discovery fails.
    #[tracing::instrument(skip_all, fields(provider = %self.id()))]
    pub async fn end_session_url(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect: &str,
    ) -> Option<String> {
        let discovery = match self.discovery().await {
            Ok(discovery) => discovery,
            Err(error) => {
                tracing::warn!(%error, "no logout URL: discovery failed");
                return None;
            }
        };
        let mut url = reqwest::Url::parse(discovery.end_session_endpoint.as_deref()?).ok()?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(hint) = id_token_hint {
                query.append_pair("id_token_hint", hint);
            }
            query
                .append_pair("post_logout_redirect_uri", post_logout_redirect)
                .append_pair("client_id", self.client_id.as_str());
        }
        Some(url.into())
    }
}

/// Runs one request to the provider `provider` and records it in the OIDC
/// metrics under `op` (`discovery`, `token`, `userinfo` or `jwks`).
async fn observed<T, E>(
    provider: &str,
    op: &str,
    request: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let started = Instant::now();
    let result = request.await;
    crate::metrics::record_oidc_request(
        provider,
        op,
        result.is_ok(),
        started.elapsed().as_secs_f64(),
    );
    result
}

/// Encodes `fields` as an `application/x-www-form-urlencoded` body.
fn form_body(fields: &[(&str, &str)]) -> Result<String, String> {
    let mut url = reqwest::Url::parse("http://form.invalid/")
        .map_err(|error| format!("could not encode the request: {error}"))?;
    url.query_pairs_mut().extend_pairs(fields);
    Ok(url.query().unwrap_or_default().to_owned())
}

/// Sends one of oauth2's requests through `http`.
async fn send(
    http: reqwest::Client,
    request: oauth2::HttpRequest,
) -> Result<oauth2::HttpResponse, reqwest::Error> {
    let response = http.execute(request.try_into()?).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let mut answer = oauth2::http::Response::new(response.bytes().await?.to_vec());
    *answer.status_mut() = status;
    *answer.headers_mut() = headers;
    Ok(answer)
}

/// GETs `url` and parses its JSON answer; anything but a 2xx is an error.
async fn get_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    read_json(url, http.get(url)).await
}

/// Like [`get_json`], with `token` as the bearer token.
async fn get_json_bearer<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<T, String> {
    read_json(url, http.get(url).bearer_auth(token)).await
}

/// POSTs the form `body` to `url` and parses its JSON answer; anything but a
/// 2xx is an error. The answer's body is not quoted, as it may hold a token.
async fn post_form_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
    body: String,
) -> Result<T, String> {
    read_json(
        url,
        http.post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body),
    )
    .await
}

/// Sends `request` (to `url`, for the messages) and parses the JSON answer.
async fn read_json<T: serde::de::DeserializeOwned>(
    url: &str,
    request: reqwest::RequestBuilder,
) -> Result<T, String> {
    let response = request
        .send()
        .await
        .map_err(|error| format!("{url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("{url} answered {}", response.status()));
    }
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("{url}: {error}"))?;
    serde_json::from_slice(&body).map_err(|error| format!("{url}: {error}"))
}

/// The advertised ID token algorithms that are also in
/// [`ASYMMETRIC_ALGORITHMS`]; RS256, the OIDC default, when the provider
/// advertises none.
fn accepted_algorithms(advertised: &[String]) -> Vec<Algorithm> {
    if advertised.is_empty() {
        return vec![Algorithm::RS256];
    }
    advertised
        .iter()
        .filter_map(|alg| alg.parse::<Algorithm>().ok())
        .filter(|alg| ASYMMETRIC_ALGORITHMS.contains(alg))
        .collect()
}

/// What an ID token has to match besides its signature.
struct Expected<'a> {
    issuer: &'a str,
    client_id: &'a str,
    /// The nonce stored with the login flow.
    nonce: &'a str,
    algorithms: &'a [Algorithm],
}

/// The ID token claims that are checked or kept.
#[derive(Debug, PartialEq, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    /// A string or an array of strings; only counted here, as `decode`
    /// already checked that the client is in it.
    aud: Value,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    nonce: Option<String>,
    azp: Option<String>,
    name: Option<String>,
    email: Option<String>,
    /// A boolean, or the string `"true"` from some providers.
    email_verified: Option<Value>,
    /// Entra's optional "email domain owner verified" claim; Entra sends no
    /// `email_verified`.
    xms_edov: Option<Value>,
    /// Every other claim, for the groups.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Why an ID token was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum Rejection {
    /// It names a key the key set does not have (yet).
    #[error("signed with a key the provider does not publish")]
    UnknownKey,
    /// An access token past its `exp` (and the leeway).
    #[error("expired")]
    Expired,
    /// Anything else.
    #[error("{0}")]
    Invalid(String),
}

/// What an access token has to match besides its signature.
struct AccessExpected<'a> {
    issuer: &'a str,
    audience: &'a str,
    algorithms: &'a [Algorithm],
}

/// The access token claims that are checked or kept.
#[derive(Debug, Deserialize)]
struct AccessTokenJwt {
    iss: String,
    sub: String,
    exp: u64,
    iat: Option<u64>,
    nbf: Option<u64>,
    /// Only present in an ID token.
    nonce: Option<Value>,
    /// Keycloak marks its ID tokens `"ID"` here.
    typ: Option<Value>,
    email: Option<String>,
    /// Every other claim, for the groups.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Validates an ID token from the token endpoint as OIDC Core 3.1.3.7 asks:
/// an accepted asymmetric algorithm, a signature by one of the provider's
/// `keys`, the issuer and client in `iss` and `aud` (and `azp`), a `sub`, not
/// expired, not issued in the future and not before its `nbf` at `now` (Unix
/// seconds, give or take [`LEEWAY_SECS`]), and the nonce of this login.
fn verify_id_token(
    token: &str,
    keys: &JwkSet,
    expected: &Expected<'_>,
    now: u64,
) -> Result<IdTokenClaims, Rejection> {
    let (alg, key) = decoding_key(token, keys, expected.algorithms)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected.issuer]);
    validation.set_audience(&[expected.client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    // `exp`, `iat` and `nbf` are checked below against `now` rather than the
    // clock, so this function stays pure.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let claims = jsonwebtoken::decode::<IdTokenClaims>(token, &key, &validation)
        .map_err(|error| Rejection::Invalid(error.to_string()))?
        .claims;

    if claims.exp.saturating_add(LEEWAY_SECS) < now {
        return Err(Rejection::Invalid("expired".to_owned()));
    }
    if claims.iat > now.saturating_add(LEEWAY_SECS) {
        return Err(Rejection::Invalid("issued in the future".to_owned()));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(LEEWAY_SECS))
    {
        return Err(Rejection::Invalid("not valid yet (nbf)".to_owned()));
    }
    let several_audiences = claims.aud.as_array().is_some_and(|aud| aud.len() > 1);
    if (several_audiences || claims.azp.is_some())
        && claims.azp.as_deref() != Some(expected.client_id)
    {
        return Err(Rejection::Invalid(
            "the authorized party (azp) is not this client".to_owned(),
        ));
    }
    let nonce_matches = claims
        .nonce
        .as_deref()
        .is_some_and(|nonce| bool::from(nonce.as_bytes().ct_eq(expected.nonce.as_bytes())));
    if !nonce_matches {
        return Err(Rejection::Invalid(
            "the nonce does not match this login".to_owned(),
        ));
    }
    Ok(claims)
}

/// The algorithm of `token`, if one of `algorithms`, and the key of `keys` that
/// it names, which must be for that algorithm when it says so.
fn decoding_key(
    token: &str,
    keys: &JwkSet,
    algorithms: &[Algorithm],
) -> Result<(Algorithm, DecodingKey), Rejection> {
    let header = jsonwebtoken::decode_header(token)
        .map_err(|error| Rejection::Invalid(format!("malformed: {error}")))?;
    if !algorithms.contains(&header.alg) {
        return Err(Rejection::Invalid(format!(
            "algorithm {:?} is not accepted",
            header.alg
        )));
    }
    let jwk = signing_key(keys, header.kid.as_deref())?;
    if let Some(key_alg) = &jwk.common.key_algorithm
        && key_alg.to_string().parse::<Algorithm>().ok() != Some(header.alg)
    {
        return Err(Rejection::Invalid(format!(
            "the key is for {key_alg}, the token says {:?}",
            header.alg
        )));
    }
    let key = DecodingKey::from_jwk(jwk)
        .map_err(|error| Rejection::Invalid(format!("unusable key: {error}")))?;
    Ok((header.alg, key))
}

/// Validates a JWT access token the way RFC 9068 and RFC 8725 ask, with the
/// same algorithm rules as [`verify_id_token`]: an accepted asymmetric
/// algorithm, a signature by one of the provider's `keys`, the issuer in
/// `iss`, the configured audience in `aud` (a string or an array), a `sub`, an
/// `exp` that has not passed and an `iat` and `nbf` that are not in the future
/// at `now` (Unix seconds, give or take [`LEEWAY_SECS`]). A token that carries
/// a `nonce` or has the type `ID` is an ID token, which is refused.
fn verify_access_jwt(
    token: &str,
    keys: &JwkSet,
    expected: &AccessExpected<'_>,
    now: u64,
) -> Result<AccessTokenJwt, Rejection> {
    let (alg, key) = decoding_key(token, keys, expected.algorithms)?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[expected.issuer]);
    validation.set_audience(&[expected.audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    // Time claims are checked below against `now`, as for ID tokens.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    let claims = jsonwebtoken::decode::<AccessTokenJwt>(token, &key, &validation)
        .map_err(|error| Rejection::Invalid(error.to_string()))?
        .claims;

    if claims.exp.saturating_add(LEEWAY_SECS) < now {
        return Err(Rejection::Expired);
    }
    if claims
        .iat
        .is_some_and(|iat| iat > now.saturating_add(LEEWAY_SECS))
    {
        return Err(Rejection::Invalid("issued in the future".to_owned()));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(LEEWAY_SECS))
    {
        return Err(Rejection::Invalid("not valid yet (nbf)".to_owned()));
    }
    if claims.sub.is_empty() {
        return Err(Rejection::Invalid("the subject is empty".to_owned()));
    }
    let id_type = claims
        .typ
        .as_ref()
        .and_then(Value::as_str)
        .is_some_and(|typ| typ.eq_ignore_ascii_case("ID"));
    if claims.nonce.as_ref().is_some_and(|nonce| !nonce.is_null()) || id_type {
        return Err(Rejection::Invalid(
            "this is an ID token, not an access token".to_owned(),
        ));
    }
    Ok(claims)
}

/// The signing key `kid` names, or the only one when the token names none.
/// Keys published for encryption only are passed over.
fn signing_key<'k>(keys: &'k JwkSet, kid: Option<&str>) -> Result<&'k Jwk, Rejection> {
    let mut signing = keys.keys.iter().filter(|jwk| {
        jwk.common
            .public_key_use
            .as_ref()
            .is_none_or(|key_use| *key_use == PublicKeyUse::Signature)
    });
    match kid {
        Some(kid) => signing
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .ok_or(Rejection::UnknownKey),
        None => match (signing.next(), signing.next()) {
            (Some(only), None) => Ok(only),
            (None, _) => Err(Rejection::UnknownKey),
            (Some(_), Some(_)) => Err(Rejection::Invalid(
                "the token names no key and the provider has several".to_owned(),
            )),
        },
    }
}

/// The claim at the dotted `path`; a claim whose own name contains dots is
/// found as is before the path is split.
fn claim_at<'a>(claims: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    claims.get(path).or_else(|| {
        let mut parts = path.split('.');
        let mut current = claims.get(parts.next()?)?;
        for part in parts {
            current = current.as_object()?.get(part)?;
        }
        Some(current)
    })
}

/// The groups in the claim at the dotted `path` (`groups`,
/// `realm_access.roles`): an array of strings (anything else in it is
/// ignored) or a single string. Empty when the claim is missing or of another
/// type. A claim whose own name contains dots (a URL, say) is found as is
/// before the path is split.
fn groups_from(claims: &Map<String, Value>, path: &str) -> Vec<String> {
    match claim_at(claims, path) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(group)) => vec![group.clone()],
        _ => Vec::new(),
    }
}

/// Whether the claims say the groups were left out of the token, as Entra does
/// for a user in too many groups (`_claim_names.groups`).
fn has_group_overage(claims: &Map<String, Value>) -> bool {
    claims
        .get("_claim_names")
        .and_then(Value::as_object)
        .is_some_and(|names| names.contains_key("groups"))
}

/// Whether `oid` looks like an Entra object id (letters, digits and dashes),
/// so it can go into a Graph URL path as is.
fn is_object_id(oid: &str) -> bool {
    !oid.is_empty()
        && oid
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Whether a Graph `@odata.nextLink` is under `graph_url` (given without a
/// trailing slash): the same scheme, host and port, not just the same prefix
/// (`https://graph.example.com.evil.test` must not pass).
fn graph_link_allowed(graph_url: &str, link: &str) -> bool {
    link.strip_prefix(graph_url)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?']))
}

/// The value of the claim at `path` in the ID token, as a SCIM match key (see
/// [`scalar_claim`]). `sub`, `iss`, `email` and `name` are fields of
/// [`IdTokenClaims`], not in its `extra` claims.
fn scim_key(claims: &IdTokenClaims, path: &str) -> Option<String> {
    scalar_claim(&claims.extra, path).or_else(|| match path {
        "sub" => Some(claims.sub.clone()),
        "iss" => Some(claims.iss.clone()),
        "email" => claims.email.clone(),
        "name" => claims.name.clone(),
        _ => None,
    })
}

/// The claim at the dotted `path` as a string: a string as is, a number
/// stringified. `None` for anything else, an array or an object included.
fn scalar_claim(claims: &Map<String, Value>, path: &str) -> Option<String> {
    match claim_at(claims, path)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Whether a boolean claim is set: `true`, `"true"` or `1`.
fn claim_is_true(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => text.eq_ignore_ascii_case("true") || text == "1",
        Some(Value::Number(number)) => number.as_u64() == Some(1),
        _ => false,
    }
}

/// Whether `email` may log in: always when `allowed` is empty, otherwise only
/// when its domain (after the last `@`) is one of them, case-insensitively.
fn email_allowed(allowed: &[String], email: Option<&str>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    email
        .and_then(|email| email.rsplit_once('@'))
        .is_some_and(|(_, domain)| {
            allowed
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(domain))
        })
}

/// The current time in Unix seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// ID token validation against keys made up for the test: a token passes only
/// when everything OIDC Core 3.1.3.7 asks for holds. The last tests run the
/// whole client against a fake provider on loopback.
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeySize, PublicKeyComponents};
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RSA_PKCS1_SHA256, RsaKeyPair,
    };
    use axum::extract::State;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;

    use super::*;

    const ISSUER: &str = "https://idp.example.com";
    const CLIENT: &str = "axon";
    const NONCE: &str = "n-0S6_WzA2Mj";
    const NOW: u64 = 1_800_000_000;
    const ALGORITHMS: [Algorithm; 2] = [Algorithm::RS256, Algorithm::ES256];
    const REDIRECT: &str = "http://127.0.0.1:8080/auth/callback";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    enum Signer {
        Rsa(RsaKeyPair),
        Ec(EcdsaKeyPair),
    }

    /// A provider signing key, generated per test.
    struct Key {
        kid: &'static str,
        signer: Signer,
    }

    impl Key {
        fn rsa(kid: &'static str) -> Self {
            Self {
                kid,
                signer: Signer::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap()),
            }
        }

        fn ec(kid: &'static str) -> Self {
            Self {
                kid,
                signer: Signer::Ec(
                    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap(),
                ),
            }
        }

        const fn alg(&self) -> &'static str {
            match self.signer {
                Signer::Rsa(_) => "RS256",
                Signer::Ec(_) => "ES256",
            }
        }

        /// The public half, as the provider's key set lists it.
        fn jwk(&self) -> Value {
            match &self.signer {
                Signer::Rsa(pair) => {
                    let public = PublicKeyComponents::<Vec<u8>>::from(pair.public_key());
                    json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                           "n": b64(&public.n), "e": b64(&public.e)})
                }
                Signer::Ec(pair) => {
                    // The uncompressed point: 0x04, then x and y.
                    let point = pair.public_key().as_ref();
                    json!({"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256",
                           "kid": self.kid, "x": b64(&point[1..33]), "y": b64(&point[33..65])})
                }
            }
        }

        /// A JWT of `header` and `claims`, signed with this key.
        fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                b64(header.to_string().as_bytes()),
                b64(claims.to_string().as_bytes())
            );
            let rng = SystemRandom::new();
            let signature = match &self.signer {
                Signer::Rsa(pair) => {
                    let mut signature = vec![0; pair.public_modulus_len()];
                    pair.sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut signature)
                        .unwrap();
                    signature
                }
                Signer::Ec(pair) => pair.sign(&rng, input.as_bytes()).unwrap().as_ref().to_vec(),
            };
            format!("{input}.{}", b64(&signature))
        }

        /// A token with `claims`, as the provider would issue it.
        fn token(&self, claims: &Value) -> String {
            self.sign(
                &json!({"alg": self.alg(), "kid": self.kid, "typ": "JWT"}),
                claims,
            )
        }
    }

    fn jwks_json(keys: &[&Key]) -> Value {
        json!({"keys": keys.iter().map(|key| key.jwk()).collect::<Vec<_>>()})
    }

    fn jwks(keys: &[&Key]) -> JwkSet {
        serde_json::from_value(jwks_json(keys)).unwrap()
    }

    /// The claims of a good token.
    fn claims() -> Value {
        json!({"iss": ISSUER, "sub": "user-1", "aud": CLIENT, "exp": NOW + 300,
               "iat": NOW - 10, "nonce": NONCE, "email": "ada@example.com", "name": "Ada"})
    }

    /// [`claims`] with some replaced; a `null` removes the claim.
    fn claims_with(changes: &Value) -> Value {
        let mut claims = claims();
        let map = claims.as_object_mut().unwrap();
        for (name, value) in changes.as_object().unwrap() {
            if value.is_null() {
                map.remove(name);
            } else {
                map.insert(name.clone(), value.clone());
            }
        }
        claims
    }

    fn verify(token: &str, keys: &JwkSet) -> Result<IdTokenClaims, Rejection> {
        let expected = Expected {
            issuer: ISSUER,
            client_id: CLIENT,
            nonce: NONCE,
            algorithms: &ALGORITHMS,
        };
        verify_id_token(token, keys, &expected, NOW)
    }

    /// Why `token` is refused; fails the test if it is accepted.
    fn refusal(token: &str, keys: &JwkSet) -> String {
        match verify(token, keys) {
            Err(Rejection::Invalid(why)) => why,
            other => panic!("expected the token to be refused, got {other:?}"),
        }
    }

    fn object(value: &Value) -> &Map<String, Value> {
        value.as_object().unwrap()
    }

    #[test]
    fn a_good_rs256_token_gives_the_claims() {
        let key = Key::rsa("k1");
        let verified = verify(&key.token(&claims()), &jwks(&[&key])).unwrap();
        assert_eq!(verified.iss, ISSUER);
        assert_eq!(verified.sub, "user-1");
        assert_eq!(verified.name.as_deref(), Some("Ada"));
        assert_eq!(verified.email.as_deref(), Some("ada@example.com"));
    }

    #[test]
    fn a_good_es256_token_passes_and_the_key_is_picked_by_kid() {
        let (rsa, ec) = (Key::rsa("k1"), Key::ec("k2"));
        assert!(verify(&ec.token(&claims()), &jwks(&[&rsa, &ec])).is_ok());
    }

    #[test]
    fn a_token_signed_by_another_key_is_refused() {
        let (key, impostor) = (Key::rsa("k1"), Key::rsa("k1"));
        let why = refusal(&impostor.token(&claims()), &jwks(&[&key]));
        assert!(why.contains("Signature"), "{why}");
    }

    #[test]
    fn a_tampered_token_is_refused() {
        let key = Key::rsa("k1");
        let token = key.token(&claims());
        let forged = claims_with(&json!({"sub": "admin"}));
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        parts[1] = b64(forged.to_string().as_bytes());
        assert!(verify(&parts.join("."), &jwks(&[&key])).is_err());
    }

    #[test]
    fn an_unknown_kid_asks_for_fresh_keys() {
        let (known, rotated) = (Key::rsa("k1"), Key::rsa("k2"));
        assert_eq!(
            verify(&rotated.token(&claims()), &jwks(&[&known])),
            Err(Rejection::UnknownKey)
        );
    }

    #[test]
    fn without_a_kid_only_a_lone_key_is_used() {
        let (one, two) = (Key::rsa("k1"), Key::ec("k2"));
        let token = one.sign(&json!({"alg": "RS256"}), &claims());
        assert!(verify(&token, &jwks(&[&one])).is_ok());
        assert!(refusal(&token, &jwks(&[&one, &two])).contains("several"));
    }

    #[test]
    fn encryption_keys_are_never_used_to_verify() {
        let key = Key::rsa("k1");
        let mut jwk = key.jwk();
        jwk["use"] = json!("enc");
        let keys: JwkSet = serde_json::from_value(json!({"keys": [jwk]})).unwrap();
        assert_eq!(
            verify(&key.token(&claims()), &keys),
            Err(Rejection::UnknownKey)
        );
    }

    #[test]
    fn alg_none_and_hmac_are_refused() {
        let key = Key::rsa("k1");
        let body = b64(claims().to_string().as_bytes());
        let none = format!("{}.{body}.", b64(br#"{"alg":"none","kid":"k1"}"#));
        assert!(verify(&none, &jwks(&[&key])).is_err());

        // HS256 keyed with something the attacker knows, such as the public key.
        let hs256 = format!(
            "{}.{body}.{}",
            b64(br#"{"alg":"HS256","kid":"k1"}"#),
            b64(&[0; 32])
        );
        assert!(refusal(&hs256, &jwks(&[&key])).contains("not accepted"));
    }

    #[test]
    fn an_algorithm_the_provider_does_not_advertise_is_refused() {
        let key = Key::ec("k1");
        let expected = Expected {
            issuer: ISSUER,
            client_id: CLIENT,
            nonce: NONCE,
            algorithms: &[Algorithm::RS256],
        };
        let result = verify_id_token(&key.token(&claims()), &jwks(&[&key]), &expected, NOW);
        assert!(
            matches!(&result, Err(Rejection::Invalid(why)) if why.contains("not accepted")),
            "{result:?}"
        );
    }

    #[test]
    fn a_token_must_use_the_algorithm_of_its_key() {
        let (rsa, ec) = (Key::rsa("k1"), Key::ec("k1"));
        // Signed with the EC key but naming the RSA key's id.
        let why = refusal(&ec.token(&claims()), &jwks(&[&rsa]));
        assert!(why.contains("RS256"), "{why}");
    }

    #[test]
    fn only_asymmetric_advertised_algorithms_are_accepted() {
        let advertised = |algs: &[&str]| {
            accepted_algorithms(&algs.iter().map(ToString::to_string).collect::<Vec<_>>())
        };
        assert_eq!(advertised(&[]), [Algorithm::RS256], "the OIDC default");
        assert_eq!(
            advertised(&["none", "HS256", "RS256", "ES256", "XY999"]),
            [Algorithm::RS256, Algorithm::ES256]
        );
        assert_eq!(advertised(&["HS256"]), Vec::<Algorithm>::new());
    }

    #[test]
    fn issuer_audience_and_subject_must_be_ours_and_present() {
        let key = Key::rsa("k1");
        let keys = jwks(&[&key]);
        for changes in [
            json!({"iss": "https://evil.example.com"}),
            json!({"iss": "https://idp.example.com/"}),
            json!({"aud": "another-client"}),
            json!({"aud": ["another-client"]}),
            json!({"iss": null}),
            json!({"aud": null}),
            json!({"sub": null}),
        ] {
            assert!(
                verify(&key.token(&claims_with(&changes)), &keys).is_err(),
                "{changes}"
            );
        }
    }

    #[test]
    fn several_audiences_need_azp_naming_us() {
        let key = Key::rsa("k1");
        let keys = jwks(&[&key]);
        let token = |changes: Value| key.token(&claims_with(&changes));
        assert!(refusal(&token(json!({"aud": [CLIENT, "other"]})), &keys).contains("azp"));
        assert!(
            verify(
                &token(json!({"aud": [CLIENT, "other"], "azp": CLIENT})),
                &keys
            )
            .is_ok()
        );
        assert!(refusal(&token(json!({"azp": "other"})), &keys).contains("azp"));
        assert!(verify(&token(json!({"aud": [CLIENT]})), &keys).is_ok());
    }

    #[test]
    fn the_nonce_must_be_this_logins() {
        let key = Key::rsa("k1");
        let keys = jwks(&[&key]);
        for changes in [
            json!({"nonce": "another-login"}),
            json!({"nonce": "n-0S6_WzA2Mk"}),
            json!({"nonce": ""}),
            json!({"nonce": null}),
        ] {
            let why = refusal(&key.token(&claims_with(&changes)), &keys);
            assert!(why.contains("nonce"), "{changes}: {why}");
        }
    }

    #[test]
    fn expiry_issue_time_and_nbf_allow_a_minute_of_skew() {
        let key = Key::rsa("k1");
        let keys = jwks(&[&key]);
        let token = |changes: Value| key.token(&claims_with(&changes));
        assert!(refusal(&token(json!({"exp": NOW - 61})), &keys).contains("expired"));
        assert!(verify(&token(json!({"exp": NOW - 30})), &keys).is_ok());
        assert!(refusal(&token(json!({"iat": NOW + 120})), &keys).contains("future"));
        assert!(verify(&token(json!({"iat": NOW + 30})), &keys).is_ok());
        assert!(refusal(&token(json!({"nbf": NOW + 120})), &keys).contains("nbf"));
        assert!(verify(&token(json!({"nbf": NOW + 30})), &keys).is_ok());
        assert!(verify(&token(json!({"exp": null})), &keys).is_err());
        assert!(verify(&token(json!({"iat": null})), &keys).is_err());
    }

    #[test]
    fn groups_are_read_along_a_dotted_path() {
        let claims = json!({
            "groups": ["a", 7, "b", null],
            "realm_access": {"roles": ["admin", "user"]},
            "https://example.com/groups": ["url"],
        });
        let claims = object(&claims);
        assert_eq!(groups_from(claims, "groups"), ["a", "b"], "non-strings go");
        assert_eq!(groups_from(claims, "realm_access.roles"), ["admin", "user"]);
        assert_eq!(groups_from(claims, "https://example.com/groups"), ["url"]);
        assert_eq!(
            groups_from(claims, "realm_access.missing"),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            groups_from(claims, "groups.deeper"),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn a_single_string_group_is_one_group() {
        let claims = json!({"groups": "solo", "number": 3});
        assert_eq!(groups_from(object(&claims), "groups"), ["solo"]);
        assert_eq!(
            groups_from(object(&claims), "number"),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn a_missing_groups_claim_gives_no_groups() {
        assert_eq!(
            groups_from(object(&json!({})), "groups"),
            [] as [std::string::String; 0]
        );
        assert_eq!(
            groups_from(object(&json!({"groups": null})), "groups"),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn group_overage_is_recognised() {
        let overage = json!({"_claim_names": {"groups": "src1"}, "_claim_sources": {}});
        assert!(has_group_overage(object(&overage)));
        assert!(!has_group_overage(object(
            &json!({"_claim_names": {"other": "x"}})
        )));
        assert!(!has_group_overage(object(&json!({"groups": ["a"]}))));
    }

    #[test]
    fn verification_claims_accept_only_a_clear_yes() {
        for yes in [
            json!(true),
            json!("true"),
            json!("TRUE"),
            json!("1"),
            json!(1),
        ] {
            assert!(claim_is_true(Some(&yes)), "{yes}");
        }
        for no in [
            json!(false),
            json!("false"),
            json!("yes"),
            json!(0),
            json!(null),
        ] {
            assert!(!claim_is_true(Some(&no)), "{no}");
        }
        assert!(!claim_is_true(None));
    }

    #[test]
    fn email_domains_are_matched_after_the_last_at_without_case() {
        let allowed = vec!["Example.com".to_owned(), "corp.example.org".to_owned()];
        assert!(email_allowed(&allowed, Some("ada@example.com")));
        assert!(email_allowed(&allowed, Some("ADA@EXAMPLE.COM")));
        assert!(email_allowed(&allowed, Some("a@b@corp.example.org")));
        assert!(!email_allowed(&allowed, Some("ada@evil.com")));
        assert!(!email_allowed(&allowed, Some("ada@example.com.evil.com")));
        assert!(!email_allowed(&allowed, Some("ada@sub.example.com")));
        assert!(!email_allowed(&allowed, Some("no-at-sign")));
        assert!(!email_allowed(&allowed, None), "an email is required");
        assert!(email_allowed(&[], None), "no list allows everyone");
    }

    #[test]
    fn a_graph_next_link_must_be_under_the_graph_url() {
        let graph = "https://graph.microsoft.com";
        for link in [
            "https://graph.microsoft.com/v1.0/users/x/transitiveMemberOf?$skiptoken=1",
            "https://graph.microsoft.com?$skiptoken=1",
            "https://graph.microsoft.com",
        ] {
            assert!(graph_link_allowed(graph, link), "{link}");
        }
        for link in [
            "https://graph.microsoft.com.evil.test/v1.0/x",
            "https://graph.microsoft.com@evil.test/v1.0/x",
            "http://graph.microsoft.com/v1.0/x",
            "https://evil.test/https://graph.microsoft.com/v1.0/x",
            "",
        ] {
            assert!(!graph_link_allowed(graph, link), "{link}");
        }
    }

    #[test]
    fn graph_object_ids_are_checked_before_they_go_into_a_url() {
        assert!(is_object_id("00000000-1111-2222-3333-444444444444"));
        assert!(!is_object_id(""));
        assert!(!is_object_id("../me"));
        assert!(!is_object_id("a/b"));
        assert!(!is_object_id("a?b"));
    }

    #[test]
    fn a_graph_page_yields_the_group_object_ids() {
        let page: GraphPage = serde_json::from_value(json!({
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryObjects",
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/next",
            "value": [
                {"@odata.type": "#microsoft.graph.group", "id": "g-1", "displayName": "One"},
                {"displayName": "No id"},
                {"id": "g-2"},
            ],
        }))
        .unwrap();
        let ids: Vec<_> = page
            .value
            .into_iter()
            .filter_map(|group| group.id)
            .collect();
        assert_eq!(ids, ["g-1", "g-2"]);
        assert_eq!(
            page.next_link.as_deref(),
            Some("https://graph.microsoft.com/v1.0/next")
        );

        let last: GraphPage = serde_json::from_value(json!({"value": []})).unwrap();
        assert!(last.value.is_empty());
        assert!(last.next_link.is_none());
    }

    #[test]
    fn the_scim_key_is_a_string_or_a_number_claim() {
        let claims = json!({
            "sub": "user-1",
            "oid": "o-1",
            "employee": 4711,
            "tags": ["a"],
            "nested": {"upn": "a@example.com"},
            "flag": true,
        });
        let claims = claims.as_object().unwrap();
        assert_eq!(scalar_claim(claims, "sub").as_deref(), Some("user-1"));
        assert_eq!(scalar_claim(claims, "employee").as_deref(), Some("4711"));
        assert_eq!(
            scalar_claim(claims, "nested.upn").as_deref(),
            Some("a@example.com")
        );
        assert_eq!(scalar_claim(claims, "missing"), None);
        assert_eq!(scalar_claim(claims, "tags"), None);
        assert_eq!(scalar_claim(claims, "nested"), None);
        assert_eq!(scalar_claim(claims, "flag"), None);
    }

    #[test]
    fn form_bodies_are_percent_encoded() {
        let body = form_body(&[("scope", "https://g.example/.default"), ("a", "b c&d")]).unwrap();
        assert_eq!(body, "scope=https%3A%2F%2Fg.example%2F.default&a=b+c%26d");
    }

    #[test]
    fn debug_output_redacts_the_secrets() {
        let redirect = LoginRedirect {
            url: "https://idp.example.com/authorize".to_owned(),
            state: "state-secret".to_owned(),
            nonce: "nonce-secret".to_owned(),
            pkce_verifier: "verifier-secret".to_owned(),
        };
        let shown = format!("{redirect:?}");
        for secret in ["state-secret", "nonce-secret", "verifier-secret"] {
            assert!(!shown.contains(secret), "{shown}");
        }
        let login = VerifiedLogin {
            issuer: ISSUER.to_owned(),
            subject: "user-1".to_owned(),
            name: None,
            email: None,
            groups: Vec::new(),
            is_admin: false,
            id_token: "id-token-secret".to_owned(),
            refresh_token: Some("refresh-token-secret".to_owned()),
            scim_key: None,
        };
        let shown = format!("{login:?}");
        assert!(!shown.contains("id-token-secret"));
        assert!(!shown.contains("refresh-token-secret"));
    }

    /// What the fake provider serves, and what it was sent.
    #[derive(Clone, Default)]
    struct Fake {
        /// The `issuer` its discovery document claims.
        issuer: Arc<Mutex<String>>,
        /// The `end_session_endpoint` its discovery document advertises.
        end_session: Arc<Mutex<Option<String>>>,
        jwks: Arc<Mutex<Value>>,
        id_token: Arc<Mutex<String>>,
        /// The last token request's form body.
        token_request: Arc<Mutex<String>>,
    }

    /// Serves discovery, the key set and the token endpoint on loopback.
    /// Returns the issuer URL and the state to steer it with.
    async fn fake_provider(keys: &[&Key]) -> (String, Fake) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fake = Fake::default();
        (*fake.issuer.lock().unwrap()).clone_from(&base);
        *fake.jwks.lock().unwrap() = jwks_json(keys);
        let discovery = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        });
        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move |State(fake): State<Fake>| {
                    let mut document = discovery.clone();
                    document["issuer"] = json!(fake.issuer.lock().unwrap().clone());
                    if let Some(end_session) = fake.end_session.lock().unwrap().clone() {
                        document["end_session_endpoint"] = json!(end_session);
                    }
                    std::future::ready(Json(document))
                }),
            )
            .route(
                "/jwks",
                get(|State(fake): State<Fake>| {
                    std::future::ready(Json(fake.jwks.lock().unwrap().clone()))
                }),
            )
            .route(
                "/token",
                post(|State(fake): State<Fake>, body: String| {
                    *fake.token_request.lock().unwrap() = body;
                    std::future::ready(Json(json!({
                        "access_token": "at",
                        "token_type": "Bearer",
                        "expires_in": 60,
                        "id_token": fake.id_token.lock().unwrap().clone(),
                    })))
                }),
            )
            .with_state(fake.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (base, fake)
    }

    fn config_for(issuer: &str) -> OidcProviderConfig {
        OidcProviderConfig {
            id: "test".to_owned(),
            display_name: None,
            issuer: issuer.to_owned(),
            client_id: CLIENT.to_owned(),
            client_secret_env: None,
            scopes: vec!["profile".to_owned(), "email".to_owned()],
            groups_claim: "groups".to_owned(),
            allowed_email_domains: Vec::new(),
            admin_groups: Vec::new(),
            accept_access_tokens: false,
            access_token_audience: None,
            graph_overage: false,
            graph_url: None,
            scim_match_claim: None,
        }
    }

    fn providers_for(config: &OidcProviderConfig) -> OidcProviders {
        OidcProviders::new(std::slice::from_ref(config), REDIRECT).unwrap()
    }

    /// The claims of a good token from the fake provider.
    fn fake_claims(issuer: &str, nonce: &str) -> Value {
        let now = unix_now();
        claims_with(&json!({"iss": issuer, "nonce": nonce, "exp": now + 300, "iat": now}))
    }

    /// Runs a whole login at the fake provider with `changes` on top of the
    /// good claims.
    async fn login_with(
        config: &OidcProviderConfig,
        key: &Key,
        fake: &Fake,
        changes: Value,
    ) -> Result<VerifiedLogin, OidcError> {
        let providers = providers_for(config);
        let provider = providers.get("test").unwrap();
        let redirect = provider.authorize().await.unwrap();
        let mut claims = fake_claims(&config.issuer, &redirect.nonce);
        for (name, value) in changes.as_object().unwrap() {
            claims[name] = value.clone();
        }
        *fake.id_token.lock().unwrap() = key.token(&claims);
        provider
            .exchange("the-code", &redirect.pkce_verifier, &redirect.nonce)
            .await
    }

    #[tokio::test]
    async fn the_scim_key_comes_from_the_configured_claim() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        let login = login_with(&config_for(&issuer), &key, &fake, json!({}))
            .await
            .unwrap();
        assert_eq!(login.scim_key.as_deref(), Some("user-1"), "sub by default");

        let mut config = config_for(&issuer);
        config.scim_match_claim = Some("oid".to_owned());
        let login = login_with(&config, &key, &fake, json!({"oid": "o-1"}))
            .await
            .unwrap();
        assert_eq!(login.scim_key.as_deref(), Some("o-1"));
        let login = login_with(&config, &key, &fake, json!({})).await.unwrap();
        assert_eq!(login.scim_key, None);
    }

    #[tokio::test]
    async fn a_login_runs_end_to_end_against_the_provider() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        let providers = providers_for(&config_for(&issuer));
        assert!(providers.iter().next().is_some());
        let provider = providers.get("test").unwrap();
        assert_eq!(provider.id(), "test");
        assert_eq!(provider.display_name(), "test");
        assert_eq!(providers.iter().count(), 1);
        assert!(providers.get("other").is_none());

        let redirect = provider.authorize().await.unwrap();
        let url = reqwest::Url::parse(&redirect.url).unwrap();
        assert_eq!(url.path(), "/authorize");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT);
        assert_eq!(query["redirect_uri"], REDIRECT);
        assert_eq!(query["scope"], "openid profile email");
        assert_eq!(query["state"], redirect.state);
        assert_eq!(query["nonce"], redirect.nonce);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(redirect.nonce.len(), 22, "128 bits, base64url");

        let id_token = key.token(&fake_claims(&issuer, &redirect.nonce));
        *fake.id_token.lock().unwrap() = id_token.clone();
        let login = provider
            .exchange("the-code", &redirect.pkce_verifier, &redirect.nonce)
            .await
            .unwrap();
        assert_eq!(login.issuer, issuer);
        assert_eq!(login.subject, "user-1");
        assert_eq!(login.id_token, id_token);
        assert_eq!(login.groups, [] as [std::string::String; 0]);
        assert!(!login.is_admin);
        let form = fake.token_request.lock().unwrap().clone();
        assert!(form.contains("grant_type=authorization_code"), "{form}");
        assert!(form.contains("code=the-code"), "{form}");
        assert!(
            form.contains(&format!("code_verifier={}", redirect.pkce_verifier)),
            "{form}"
        );
        assert!(!form.contains("client_secret"), "a public client: {form}");

        // Another login's nonce does not do.
        let error = provider
            .exchange("the-code", &redirect.pkce_verifier, "another-login")
            .await
            .unwrap_err();
        assert!(matches!(error, OidcError::Rejected(_)), "{error}");
        assert!(error.to_string().contains("nonce"), "{error}");
    }

    #[tokio::test]
    async fn groups_and_the_admin_flag_come_from_the_verified_token() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        let mut config = config_for(&issuer);
        config.groups_claim = "realm_access.roles".to_owned();
        config.admin_groups = vec!["axon-admin".to_owned()];

        let roles = json!({"realm_access": {"roles": ["dev", "axon-admin"]}});
        let login = login_with(&config, &key, &fake, roles).await.unwrap();
        assert_eq!(login.groups, ["dev", "axon-admin"]);
        assert!(login.is_admin);

        let roles = json!({"realm_access": {"roles": ["dev", "AXON-ADMIN"]}});
        let login = login_with(&config, &key, &fake, roles).await.unwrap();
        assert!(!login.is_admin, "the match is exact");

        // Entra group overage: no groups, no admin, but the login stands.
        let overage = json!({"_claim_names": {"groups": "src1"}});
        let login = login_with(&config, &key, &fake, overage).await.unwrap();
        assert_eq!(login.groups, [] as [std::string::String; 0]);
        assert!(!login.is_admin);
    }

    #[tokio::test]
    async fn the_email_domain_is_checked_after_the_signature() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        let mut config = config_for(&issuer);
        config.allowed_email_domains = vec!["Example.COM".to_owned()];

        let verified = json!({"email_verified": true});
        let login = login_with(&config, &key, &fake, verified).await.unwrap();
        assert_eq!(login.email.as_deref(), Some("ada@example.com"));

        // Entra sends no `email_verified`, only the optional `xms_edov`.
        let entra = json!({"xms_edov": true});
        assert!(login_with(&config, &key, &fake, entra).await.is_ok());

        // Right domain, but nobody checked the address.
        for unverified in [json!({}), json!({"email_verified": false})] {
            let error = login_with(&config, &key, &fake, unverified)
                .await
                .unwrap_err();
            assert!(matches!(error, OidcError::EmailDomainNotAllowed), "{error}");
        }

        let other = json!({"email": "ada@evil.example", "email_verified": true});
        let error = login_with(&config, &key, &fake, other).await.unwrap_err();
        assert!(matches!(error, OidcError::EmailDomainNotAllowed), "{error}");

        let none = json!({"email": null, "email_verified": true});
        let error = login_with(&config, &key, &fake, none).await.unwrap_err();
        assert!(matches!(error, OidcError::EmailDomainNotAllowed), "{error}");

        // A forged token is refused as such, before the domain is looked at.
        let impostor = Key::rsa("k1");
        let error = login_with(&config, &impostor, &fake, json!({}))
            .await
            .unwrap_err();
        assert!(matches!(error, OidcError::Rejected(_)), "{error}");
    }

    #[tokio::test]
    async fn a_rotated_key_is_fetched_again_but_at_most_once_a_minute() {
        let (old, new) = (Key::rsa("k1"), Key::rsa("k2"));
        let (issuer, fake) = fake_provider(&[&old]).await;
        let providers = providers_for(&config_for(&issuer));
        let provider = providers.get("test").unwrap();
        let discovery = provider.discovery().await.unwrap();
        let token = new.token(&fake_claims(&issuer, NONCE));

        *fake.jwks.lock().unwrap() = jwks_json(&[&new]);
        // The keys were fetched a moment ago: no refetch yet.
        let error = provider
            .verify(&discovery, &token, NONCE)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("does not publish"), "{error}");

        discovery.keys.write().await.fetched = Instant::now()
            .checked_sub(JWKS_REFETCH_INTERVAL + Duration::from_secs(1))
            .unwrap();
        let verified = provider.verify(&discovery, &token, NONCE).await.unwrap();
        assert_eq!(verified.sub, "user-1");
        assert!(
            provider
                .verify(&discovery, &old.token(&fake_claims(&issuer, NONCE)), NONCE)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn discovery_refuses_a_provider_that_names_another_issuer() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        *fake.issuer.lock().unwrap() = format!("{issuer}/");
        let providers = providers_for(&config_for(&issuer));
        let provider = providers.get("test").unwrap();
        let Err(error) = provider.authorize().await else {
            panic!("discovery accepted a foreign issuer");
        };
        assert!(matches!(error, OidcError::Provider { .. }), "{error}");
        assert!(error.to_string().contains("issuer"), "{error}");
    }

    #[tokio::test]
    async fn the_end_session_url_needs_an_advertised_endpoint() {
        let key = Key::rsa("k1");
        let (issuer, _fake) = fake_provider(&[&key]).await;
        let providers = providers_for(&config_for(&issuer));
        let provider = providers.get("test").unwrap();
        let logged_out = "http://127.0.0.1:8080/";

        // Not advertised.
        assert_eq!(
            provider.end_session_url(Some("hint"), logged_out).await,
            None
        );
    }

    #[tokio::test]
    async fn the_end_session_url_carries_hint_redirect_and_client() {
        let key = Key::rsa("k1");
        let (issuer, fake) = fake_provider(&[&key]).await;
        *fake.end_session.lock().unwrap() = Some(format!("{issuer}/logout"));
        let providers = providers_for(&config_for(&issuer));
        let provider = providers.get("test").unwrap();
        let logged_out = "http://127.0.0.1:8080/";

        let url = provider
            .end_session_url(Some("the-hint"), logged_out)
            .await
            .unwrap();
        let url = reqwest::Url::parse(&url).unwrap();
        assert_eq!(url.path(), "/logout");
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["id_token_hint"], "the-hint");
        assert_eq!(query["post_logout_redirect_uri"], logged_out);
        assert_eq!(query["client_id"], CLIENT);

        let url = provider.end_session_url(None, logged_out).await.unwrap();
        assert!(!url.contains("id_token_hint"), "{url}");
    }

    #[tokio::test]
    async fn the_end_session_url_is_none_when_discovery_fails() {
        let providers = providers_for(&config_for("http://127.0.0.1:1"));
        let provider = providers.get("test").unwrap();
        assert_eq!(provider.end_session_url(None, "http://x/").await, None);
    }

    #[test]
    fn a_missing_client_secret_variable_stops_startup() {
        let mut config = config_for(ISSUER);
        config.client_secret_env = Some("AXON_TEST_OIDC_SECRET_THAT_IS_NEVER_SET_9F2C".to_owned());
        let Err(error) = OidcProviders::new(&[config], REDIRECT) else {
            panic!("a missing secret was accepted");
        };
        assert!(
            matches!(
                &error,
                OidcError::MissingSecret { provider, var }
                    if provider == "test" && var == "AXON_TEST_OIDC_SECRET_THAT_IS_NEVER_SET_9F2C"
            ),
            "{error}"
        );
    }

    /// The claims of a good access token: [`claims`] without the nonce.
    fn access_claims_with(changes: &Value) -> Value {
        let mut claims = claims_with(&json!({"nonce": null, "groups": ["ops"]}));
        let map = claims.as_object_mut().unwrap();
        for (name, value) in changes.as_object().unwrap() {
            if value.is_null() {
                map.remove(name);
            } else {
                map.insert(name.clone(), value.clone());
            }
        }
        claims
    }

    fn verify_access(token: &str, keys: &JwkSet) -> Result<AccessTokenJwt, Rejection> {
        let expected = AccessExpected {
            issuer: ISSUER,
            audience: CLIENT,
            algorithms: &ALGORITHMS,
        };
        verify_access_jwt(token, keys, &expected, NOW)
    }

    /// Why an access token is refused; fails the test if it is accepted.
    fn access_refusal(changes: &Value) -> Rejection {
        let key = Key::rsa("k1");
        let token = key.token(&access_claims_with(changes));
        verify_access(&token, &jwks(&[&key])).expect_err("the token should be refused")
    }

    #[test]
    fn a_good_access_token_gives_the_claims() {
        let key = Key::rsa("k1");
        let token = key.token(&access_claims_with(&json!({})));
        let verified = verify_access(&token, &jwks(&[&key])).unwrap();
        assert_eq!(verified.iss, ISSUER);
        assert_eq!(verified.sub, "user-1");
        assert_eq!(verified.email.as_deref(), Some("ada@example.com"));
        assert_eq!(groups_from(&verified.extra, "groups"), ["ops"]);
    }

    #[test]
    fn an_access_token_with_the_audience_in_an_array_passes() {
        let key = Key::ec("k1");
        let token = key.token(&access_claims_with(&json!({"aud": ["other", CLIENT]})));
        assert!(verify_access(&token, &jwks(&[&key])).is_ok());
    }

    #[test]
    fn an_access_token_for_another_audience_is_refused() {
        assert!(matches!(
            access_refusal(&json!({"aud": "someone-else"})),
            Rejection::Invalid(why) if why.contains("Audience")
        ));
        assert!(matches!(
            access_refusal(&json!({"aud": null})),
            Rejection::Invalid(_)
        ));
    }

    #[test]
    fn an_expired_access_token_is_refused_after_the_leeway() {
        assert_eq!(
            access_refusal(&json!({"exp": NOW - LEEWAY_SECS - 1})),
            Rejection::Expired
        );
        let key = Key::rsa("k1");
        let token = key.token(&access_claims_with(&json!({"exp": NOW - LEEWAY_SECS})));
        assert!(verify_access(&token, &jwks(&[&key])).is_ok());
        assert!(matches!(
            access_refusal(&json!({"exp": null})),
            Rejection::Invalid(_)
        ));
    }

    #[test]
    fn an_access_token_from_the_future_is_refused() {
        assert!(matches!(
            access_refusal(&json!({"nbf": NOW + LEEWAY_SECS + 1})),
            Rejection::Invalid(why) if why.contains("nbf")
        ));
        assert!(matches!(
            access_refusal(&json!({"iat": NOW + LEEWAY_SECS + 1})),
            Rejection::Invalid(why) if why.contains("future")
        ));
    }

    #[test]
    fn an_access_token_from_another_issuer_is_refused() {
        assert!(matches!(
            access_refusal(&json!({"iss": "https://evil.example.com"})),
            Rejection::Invalid(why) if why.contains("Issuer")
        ));
    }

    #[test]
    fn an_access_token_needs_a_subject() {
        assert!(matches!(
            access_refusal(&json!({"sub": null})),
            Rejection::Invalid(_)
        ));
    }

    #[test]
    fn an_id_token_is_not_an_access_token() {
        assert!(matches!(
            access_refusal(&json!({"nonce": NONCE})),
            Rejection::Invalid(why) if why.contains("ID token")
        ));
        for typ in ["ID", "id"] {
            assert!(
                matches!(
                    access_refusal(&json!({"typ": typ})),
                    Rejection::Invalid(why) if why.contains("ID token")
                ),
                "{typ}"
            );
        }
    }

    #[test]
    fn an_access_token_signed_with_an_unknown_key_asks_for_fresh_keys() {
        let (known, rotated) = (Key::rsa("k1"), Key::rsa("k2"));
        let token = rotated.token(&access_claims_with(&json!({})));
        assert_eq!(
            verify_access(&token, &jwks(&[&known])).unwrap_err(),
            Rejection::UnknownKey
        );
    }

    #[test]
    fn only_a_provider_that_accepts_access_tokens_and_issued_the_token_is_picked() {
        let key = Key::rsa("k1");
        let token = key.token(&access_claims_with(&json!({})));
        let mut config = config_for(ISSUER);

        assert!(
            providers_for(&config)
                .access_token_provider(&token)
                .is_none()
        );

        config.accept_access_tokens = true;
        let providers = providers_for(&config);
        assert_eq!(
            providers.access_token_provider(&token).map(Provider::id),
            Some("test")
        );

        // another issuer, and things that are not JWTs at all
        let foreign = key.token(&access_claims_with(
            &json!({"iss": "https://other.example"}),
        ));
        assert!(providers.access_token_provider(&foreign).is_none());
        for junk in ["", "axon_legacy_secret", "a.b.c", "e30.e30.e30"] {
            assert!(providers.access_token_provider(junk).is_none(), "{junk}");
        }
    }

    #[tokio::test]
    async fn an_access_token_is_verified_against_the_provider() {
        let key = Key::rsa("k1");
        let (issuer, _fake) = fake_provider(&[&key]).await;
        let mut config = config_for(&issuer);
        config.accept_access_tokens = true;
        let providers = providers_for(&config);
        let provider = providers.get("test").unwrap();
        assert_eq!(provider.issuer(), issuer);

        let now = unix_now();
        let fresh = json!({"iss": issuer, "exp": now + 300, "iat": now});
        let token = key.token(&access_claims_with(&fresh));
        let claims = provider.verify_access_token(&token).await.unwrap();
        assert_eq!(claims.issuer, issuer);
        assert_eq!(claims.subject, "user-1");
        assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
        assert_eq!(claims.groups, Some(vec!["ops".to_owned()]));
        assert_eq!(claims.token, token);
        assert!(!format!("{claims:?}").contains(&token));

        // no groups claim at all is not the same as an empty one
        let without = json!({"iss": issuer, "exp": now + 300, "iat": now, "groups": null});
        let token = key.token(&access_claims_with(&without));
        let claims = provider.verify_access_token(&token).await.unwrap();
        assert_eq!(claims.groups, None);

        let expired = json!({"iss": issuer, "exp": now - 600, "iat": now - 900});
        let token = key.token(&access_claims_with(&expired));
        assert!(matches!(
            provider.verify_access_token(&token).await,
            Err(OidcError::Expired)
        ));

        let wrong_audience = json!({"iss": issuer, "exp": now + 300, "aud": "other"});
        let token = key.token(&access_claims_with(&wrong_audience));
        assert!(matches!(
            provider.verify_access_token(&token).await,
            Err(OidcError::Rejected(_))
        ));
    }
}
