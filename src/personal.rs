//! Per-user backends: personal MCP servers and catalog credentials
//!
//! Every user with at least one personal backend, a stored credential for a
//! catalog entry, an OAuth connection or a passthrough token gets a
//! [`UserSlot`]: their own registry and one backend actor per entry, built
//! lazily on the first request and dropped again when the user's configuration
//! changes ([`PersonalHub::invalidate`]), when a token in it is about to expire
//! or when the per-replica instance cap makes room for someone else. Secrets are
//! opened only while a slot is built and live on in the backend actors' headers.
//!
//! A catalog entry authenticates in one of three ways ([`CatalogAuth`]): header
//! values the user entered, an OAuth sign-in at the backend's own authorization
//! server (`begin_connect`/`finish_connect`), or the user's identity provider
//! token traded for a backend token (RFC 8693 or Entra on-behalf-of).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use kameo::actor::{ActorRef, Spawn};
use kameo::mailbox;
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use uuid::Uuid;

use crate::backend::{BackendActor, BackendOptions, GetBackendInfo, OutcomeHook, http_transport};
use crate::changes::{ChangeBus, ChangeScope};
use crate::config::{
    BackendConfig, Config, CredentialField, CredentialMode, PassthroughConfig, PassthroughGrant,
    PersonalBackendsConfig, TransportType,
};
use crate::crypto::{CryptoError, Keyring, Sealed};
use crate::egress::EgressPolicy;
use crate::oidc::{OidcProviders, Provider};
use crate::registry::{RegisterBackend, RegistryActor};
use crate::store::{
    Actor, CatalogAuthMode, CatalogEntry, NewUpstreamRequest, NewUpstreamToken, PersonalBackend,
    SealedColumns, Store, StoreError, UpstreamToken, UserCredential,
};
use crate::types::BackendState;
use crate::upstream_oauth::{
    self, ClientChoice, ClientCredentials, CodeGrant, Fetcher, StoredTokens, TokenAuthMethod,
    TokenEndpoint, TokenExchangeRequest, TokenResponse,
};

/// A token that expires within this is refreshed before it is used, and a slot
/// holding one is rebuilt this long before it expires
const REFRESH_MARGIN_SECS: i64 = 120;
/// A slot is kept at least this long, however short its tokens live
const MIN_SLOT_LIFETIME: Duration = Duration::from_secs(30);
/// A slot that lacks a backend for a failure that may pass is rebuilt after this
const RETRY_AFTER: Duration = Duration::from_secs(60);
/// Most subject tokens kept in memory
const MAX_SUBJECT_TOKENS: usize = 10_000;
/// An authorization request older than this is refused (the store ages them
/// out as well)
const REQUEST_MAX_AGE_SECS: i64 = 10 * 60;

/// Prefixes nobody may take for a personal backend
const RESERVED_PREFIXES: &[&str] = &[
    "axon", "mcp", "admin", "api", "system", "gateway", "internal", "catalog",
];

impl From<&SealedColumns> for Sealed {
    fn from(columns: &SealedColumns) -> Self {
        Self {
            kek_id: columns.kek_id.clone(),
            wrapped_dek: columns.dek.clone(),
            ciphertext: columns.data.clone(),
        }
    }
}

impl From<Sealed> for SealedColumns {
    fn from(sealed: Sealed) -> Self {
        Self {
            kek_id: sealed.kek_id,
            dek: sealed.wrapped_dek,
            data: sealed.ciphertext,
        }
    }
}

/// Where a catalog entry is defined
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSource {
    /// A `per_user` `[[backends]]` entry of the config file
    Config,
    /// A catalog entry an admin added in the dashboard
    Database,
}

/// How the users of a catalog item authenticate to its backend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogAuth {
    /// The values of `credential_fields`, sent as headers
    Fields,
    /// Each user connects their own account at the backend's authorization server
    OAuth {
        /// The static client; without it the gateway uses a client ID metadata
        /// document or registers itself
        client: Option<ClientCredentials>,
        /// Scopes to ask for; empty uses the ones the backend advertises
        scopes: Vec<String>,
        /// The static client's secret was set but cannot be read, so nobody can
        /// connect until an admin sets it again
        client_unusable: bool,
    },
    /// The user's identity provider token is exchanged for a backend token
    Passthrough(PassthroughConfig),
}

/// One backend every user may bring a credential, a connection or an identity for
#[derive(Debug, Clone)]
pub struct CatalogItem {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    /// The values users enter; empty unless `auth` is [`CatalogAuth::Fields`]
    pub credential_fields: Vec<CredentialField>,
    pub auth: CatalogAuth,
    pub enabled: bool,
    pub source: CatalogSource,
    /// `None`: the connection stays open
    pub idle_timeout: Option<Duration>,
    pub timeout_secs: u64,
}

/// What a backend of a user's slot is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserBackendKind {
    /// The user's own MCP server
    Personal { id: Uuid },
    /// A catalog entry, with the user's credential
    Catalog,
}

/// One user's registry and backends
pub struct UserSlot {
    pub registry: ActorRef<RegistryActor>,
    /// Backend name (the prefix, or the catalog name) -> actor; copy-on-write
    /// like the gateway's map so request tasks can hold a snapshot
    pub backends: Arc<HashMap<String, ActorRef<BackendActor>>>,
    pub kinds: HashMap<String, UserBackendKind>,
}

struct SlotEntry {
    /// `None`: the user has no backends, remembered so every request does not
    /// ask the database again
    slot: Option<Arc<UserSlot>>,
    last_used: Instant,
    /// From here on the entry counts as missing: a token in the slot is about
    /// to expire, or a backend was left out for a failure that may pass
    refresh_at: Option<Instant>,
    /// Identity providers whose token a passthrough backend of the user lacks
    awaiting_subject: BTreeSet<String>,
}

impl SlotEntry {
    fn instances(&self) -> usize {
        self.slot.as_ref().map_or(0, |slot| slot.backends.len())
    }
}

#[derive(Default)]
struct CatalogState {
    items: Vec<CatalogItem>,
    /// Config backends that are not `per_user`
    shared: BTreeSet<String>,
}

impl CatalogState {
    /// Every name a personal prefix must not collide with
    fn taken_names(&self) -> BTreeSet<String> {
        self.shared
            .iter()
            .cloned()
            .chain(self.items.iter().map(|item| item.name.clone()))
            .collect()
    }
}

/// A backend about to be spawned in a slot
struct Spec {
    config: BackendConfig,
    options: BackendOptions,
    kind: UserBackendKind,
    /// When the token in the headers expires, if it does
    expires_at: Option<DateTime<Utc>>,
}

/// What building one catalog item gave
// Built once per catalog load, not per request, so the size gap costs nothing.
#[allow(clippy::large_enum_variant)]
enum SpecOutcome {
    Ready(Spec),
    /// Left out for good (until the user's setup changes)
    Skip,
    /// Left out for a failure that may pass; try again soon
    Retry,
    /// A passthrough backend with no token of the identity provider to start from
    NeedsSubject,
}

/// What [`PersonalHub::build`] made
struct Built {
    slot: Option<Arc<UserSlot>>,
    refresh_at: Option<Instant>,
    awaiting_subject: BTreeSet<String>,
}

/// Why connecting a service, or storing a token, failed. The text is safe to
/// show the user.
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("this service cannot be connected with OAuth")]
    NotConnectable,
    #[error("the administrator's OAuth client secret for this service cannot be read")]
    ClientUnusable,
    #[error("the service's authorization server cannot be used: {0}")]
    Upstream(String),
    #[error("the sign-in request is unknown, expired or already used")]
    UnknownRequest,
    #[error("the sign-in request was started by someone else")]
    WrongUser,
    #[error("the authorization server's answer cannot be trusted: {0}")]
    Callback(String),
    #[error("the authorization server refused the sign-in: {0}")]
    Exchange(String),
    #[error("the tokens cannot be stored")]
    Seal(#[from] CryptoError),
    #[error("the tokens cannot be stored")]
    Store(#[from] StoreError),
}

/// One OAuth connection of a user, for the "Connected services" view. No tokens.
#[derive(Debug, Clone)]
pub struct ConnectionStatus {
    pub backend: String,
    pub issuer: String,
    pub expires_at: DateTime<Utc>,
    /// Why the last refresh failed; the user has to connect again
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// The newest identity provider access token seen per user and provider, kept
/// in memory to start the passthrough grants from
struct SubjectTokens {
    cap: usize,
    tokens: HashMap<(Uuid, String), SubjectToken>,
}

struct SubjectToken {
    token: String,
    expires_at: DateTime<Utc>,
}

impl SubjectTokens {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            tokens: HashMap::new(),
        }
    }

    /// Keeps `token` unless it expired or a later-expiring one is known. When the
    /// map is full, expired entries go first, then the one closest to expiry.
    fn note(
        &mut self,
        user: Uuid,
        provider: &str,
        token: &str,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) {
        if expires_at <= now {
            return;
        }
        let key = (user, provider.to_owned());
        if let Some(known) = self.tokens.get_mut(&key) {
            if expires_at > known.expires_at || known.expires_at <= now {
                token.clone_into(&mut known.token);
                known.expires_at = expires_at;
            }
            return;
        }
        if self.tokens.len() >= self.cap {
            self.tokens.retain(|_, known| known.expires_at > now);
        }
        if self.tokens.len() >= self.cap {
            let soonest = self
                .tokens
                .iter()
                .min_by_key(|(_, known)| known.expires_at)
                .map(|(key, _)| key.clone());
            if let Some(soonest) = soonest {
                self.tokens.remove(&soonest);
            }
        }
        self.tokens.insert(
            key,
            SubjectToken {
                token: token.to_owned(),
                expires_at,
            },
        );
    }

    /// The token, when it lives longer than `margin` from `now`
    fn usable(
        &self,
        user: Uuid,
        provider: &str,
        now: DateTime<Utc>,
        margin: TimeDelta,
    ) -> Option<String> {
        self.tokens
            .get(&(user, provider.to_owned()))
            .filter(|known| known.expires_at - now > margin)
            .map(|known| known.token.clone())
    }
}

/// How long a token must still live to be used
fn margin() -> TimeDelta {
    TimeDelta::seconds(REFRESH_MARGIN_SECS)
}

/// Builds and keeps every user's own backends; shared as `Arc<PersonalHub>`
pub struct PersonalHub {
    store: Store,
    keyring: Arc<Keyring>,
    egress: Arc<EgressPolicy>,
    config: PersonalBackendsConfig,
    /// `[gateway] idle_timeout_secs`
    idle_default_secs: u64,
    changes: ChangeBus,
    /// The identity providers of the dashboard login, whose tokens the
    /// passthrough backends exchange
    oidc: Option<Arc<OidcProviders>>,
    catalog: RwLock<CatalogState>,
    slots: Mutex<HashMap<Uuid, SlotEntry>>,
    /// One lock per user so concurrent first requests build the slot once
    build_locks: Mutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>,
    subjects: Mutex<SubjectTokens>,
}

/// What the slot cache holds for a user
enum Cached {
    /// Never built, or invalidated since
    Missing,
    /// Built; `None` remembers a user with no backends
    Hit(Option<Arc<UserSlot>>),
}

impl PersonalHub {
    /// A hub whose catalog holds only the config entries; call
    /// [`PersonalHub::reload_catalog`] to add the database's.
    #[must_use]
    pub fn new(
        store: Store,
        keyring: Arc<Keyring>,
        egress: Arc<EgressPolicy>,
        config: &Config,
        changes: ChangeBus,
        oidc: Option<Arc<OidcProviders>>,
    ) -> Self {
        let idle_default_secs = config.gateway.idle_timeout_secs;
        let state = catalog_state(&keyring, config, idle_default_secs, Vec::new());
        Self {
            store,
            keyring,
            egress,
            config: config.personal_backends.clone(),
            idle_default_secs,
            changes,
            oidc,
            catalog: RwLock::new(state),
            slots: Mutex::new(HashMap::new()),
            build_locks: Mutex::new(HashMap::new()),
            subjects: Mutex::new(SubjectTokens::new(MAX_SUBJECT_TOKENS)),
        }
    }

    /// Recomputes the merged catalog and the shared names from `config` and
    /// the database. The client secrets of OAuth entries are opened here; one
    /// that cannot be opened leaves its entry's client unusable (and is logged),
    /// it does not fail the reload. Built slots are left alone; call
    /// [`PersonalHub::invalidate_all`] when they must pick the change up.
    ///
    /// # Errors
    /// Fails when the catalog query fails.
    pub async fn reload_catalog(&self, config: &Config) -> Result<(), StoreError> {
        let entries = self.store.list_catalog_entries().await?;
        let state = catalog_state(
            &self.keyring,
            config,
            config.gateway.idle_timeout_secs,
            entries,
        );
        *self.catalog.write().unwrap_or_else(PoisonError::into_inner) = state;
        Ok(())
    }

    /// The merged catalog, by name
    #[must_use]
    pub fn catalog(&self) -> Vec<CatalogItem> {
        self.catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .clone()
    }

    /// Names of the config backends every user shares
    #[must_use]
    pub fn shared_names(&self) -> Vec<String> {
        self.catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .shared
            .iter()
            .cloned()
            .collect()
    }

    /// Whether `prefix` may name a personal backend
    ///
    /// # Errors
    /// Returns the reason it may not.
    pub fn validate_prefix(&self, prefix: &str) -> Result<(), String> {
        let names = self
            .catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .taken_names();
        check_prefix(prefix, &names)
    }

    /// Seals the header values of a personal backend.
    ///
    /// # Errors
    /// Fails when sealing fails.
    pub fn seal_personal_headers(
        &self,
        id: Uuid,
        headers: &BTreeMap<String, String>,
    ) -> Result<SealedColumns, CryptoError> {
        seal_map(&self.keyring, headers, &personal_aad(id))
    }

    /// Seals the values a user entered for a catalog entry.
    ///
    /// # Errors
    /// Fails when sealing fails.
    pub fn seal_credential(
        &self,
        user: Uuid,
        backend: &str,
        values: &BTreeMap<String, String>,
    ) -> Result<SealedColumns, CryptoError> {
        seal_map(&self.keyring, values, &credential_aad(user, backend))
    }

    /// Seals the static OAuth client secret of the catalog entry `name`.
    ///
    /// # Errors
    /// Fails when sealing fails.
    pub fn seal_catalog_oauth_secret(
        &self,
        name: &str,
        secret: &str,
    ) -> Result<SealedColumns, CryptoError> {
        upstream_oauth::seal_text(&self.keyring, secret.as_bytes(), &catalog_oauth_aad(name))
    }

    /// Most personal backends plus catalog credentials one user may have
    #[must_use]
    pub fn max_per_user(&self) -> u32 {
        self.config.max_per_user
    }

    /// Checks `url` against the egress policy, the way a connection will.
    ///
    /// # Errors
    /// Returns the reason the URL may not be reached.
    pub async fn check_egress(&self, url: &str) -> Result<(), String> {
        self.egress
            .check_url(url)
            .await
            .map(|_| ())
            .map_err(|error| format!("egress refused: {error}"))
    }

    /// Opens the sealed headers of a personal backend; empty when it has none.
    ///
    /// # Errors
    /// Returns why the headers cannot be opened (safe to show).
    pub fn open_personal_headers(
        &self,
        backend: &PersonalBackend,
    ) -> Result<BTreeMap<String, String>, String> {
        match &backend.secret {
            Some(secret) => open_map(&self.keyring, secret, &personal_aad(backend.id)),
            None => Ok(BTreeMap::new()),
        }
    }

    /// Connects to an MCP server the way a personal backend would (egress
    /// pinning, the given headers), lists its tools and disconnects; the
    /// number of tools the first page held.
    ///
    /// # Errors
    /// Returns why the server could not be reached or listed. The text never
    /// holds a header value.
    pub async fn probe(
        &self,
        url: &str,
        headers: &BTreeMap<String, String>,
    ) -> Result<usize, String> {
        let connect_timeout = Duration::from_secs(BackendConfig::default().timeout_secs);
        let mut config = StreamableHttpClientTransportConfig::with_uri(url);
        if !headers.is_empty() {
            let custom_headers = headers
                .iter()
                .map(|(name, value)| {
                    let header = name
                        .parse::<http::HeaderName>()
                        .map_err(|_| format!("invalid header name {name:?}"))?;
                    let value = http::HeaderValue::from_str(value)
                        .map_err(|_| format!("invalid value for the header {name:?}"))?;
                    Ok((header, value))
                })
                .collect::<Result<HashMap<_, _>, String>>()?;
            config = config.custom_headers(custom_headers);
        }
        let transport = http_transport(url, config, Some(&self.egress), connect_timeout).await?;

        let listing = async {
            let client =
                ().serve(transport)
                    .await
                    .map_err(|error| format!("failed to connect: {error}"))?;
            let tools = client
                .peer()
                .list_tools(None)
                .await
                .map(|listing| listing.tools.len())
                .map_err(|error| format!("failed to list the tools: {error}"));
            if let Err(error) = client.cancel().await {
                tracing::debug!(%error, "probe connection did not close cleanly");
            }
            tools
        };
        timeout(connect_timeout, listing)
            .await
            .map_err(|_| format!("timed out after {}s", connect_timeout.as_secs()))?
    }

    /// The user's slot, built on first use; `None` when personal backends are
    /// off or the user has none.
    pub async fn slot(&self, user: Uuid) -> Option<Arc<UserSlot>> {
        if !self.config.enabled {
            return None;
        }
        if let Cached::Hit(slot) = self.cached(user) {
            return slot;
        }

        let build_lock = self.build_lock(user);
        let _building = build_lock.lock().await;
        // Another request may have built it while this one waited
        if let Cached::Hit(slot) = self.cached(user) {
            return slot;
        }

        let built = match self.build(user).await {
            Ok(built) => built,
            Err(error) => {
                tracing::warn!(%user, %error, "could not load the user's backends");
                return None;
            }
        };
        let slot = built.slot.clone();
        // The slot this one replaces (a refresh) is stopped like an evicted one
        let evicted = self.insert(user, built);
        for slot in &evicted {
            stop_slot(slot).await;
        }
        slot
    }

    /// Drops the user's slot (the next [`PersonalHub::slot`] rebuilds it) and
    /// tells their clients the tool list may have changed.
    pub async fn invalidate(&self, user: Uuid) {
        let build_lock = self.build_lock(user);
        let _building = build_lock.lock().await;
        let entry = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&user);
        if let Some(slot) = entry.and_then(|entry| entry.slot) {
            stop_slot(&slot).await;
        }
        self.changes.publish(ChangeScope::User(user));
    }

    /// The connection state of every backend this replica holds for users. A
    /// backend that does not answer is left out.
    pub async fn backend_states(&self) -> Vec<BackendState> {
        let slots: Vec<Arc<UserSlot>> = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter_map(|entry| entry.slot.clone())
            .collect();
        let mut states = Vec::new();
        for slot in slots {
            for backend in slot.backends.values() {
                if let Ok(info) = backend.ask(GetBackendInfo).await {
                    states.push(info.state);
                }
            }
        }
        states
    }

    /// Drops every slot and tells all clients once.
    pub async fn invalidate_all(&self) {
        let entries: Vec<SlotEntry> = self
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, entry)| entry)
            .collect();
        for slot in entries.into_iter().filter_map(|entry| entry.slot) {
            stop_slot(&slot).await;
        }
        self.changes.publish(ChangeScope::All);
    }

    /// Counts one call of the user's own or catalog backends against
    /// `max_calls_per_minute` (0 = unlimited) in the shared Postgres window;
    /// `false` when the quota is used up. A store error lets the call through:
    /// the quota protects the backends, it is not an access check.
    pub async fn admit_call(&self, user: Uuid) -> bool {
        let limit = self.config.max_calls_per_minute;
        if limit == 0 {
            return true;
        }
        match self
            .store
            .hit_rate_limit(&format!("user-calls:{user}"), limit)
            .await
        {
            Ok(within) => within,
            Err(error) => {
                tracing::warn!(%user, %error, "Call quota check failed, letting the call through");
                true
            }
        }
    }

    /// The enabled OAuth catalog item `backend`, with its static client and scopes
    fn oauth_item(&self, backend: &str) -> Result<(CatalogItem, Vec<String>), ConnectError> {
        let item = self
            .catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .iter()
            .find(|item| item.enabled && item.name == backend)
            .cloned()
            .ok_or(ConnectError::NotConnectable)?;
        match &item.auth {
            CatalogAuth::OAuth {
                client_unusable: true,
                ..
            } => Err(ConnectError::ClientUnusable),
            CatalogAuth::OAuth { scopes, .. } => {
                let scopes = scopes.clone();
                Ok((item, scopes))
            }
            CatalogAuth::Fields | CatalogAuth::Passthrough(_) => Err(ConnectError::NotConnectable),
        }
    }

    /// Starts connecting `user` to the OAuth backend `backend`: discovers its
    /// authorization server, picks the client (the static one, else the gateway's
    /// client ID metadata document, else a registration, made now when none is
    /// cached for this server), stores the request and returns the URL to send
    /// the browser to. `base_url` is the gateway's public URL.
    ///
    /// # Errors
    /// Fails when the backend is not an enabled OAuth catalog item, discovery or
    /// registration fails, or the request cannot be stored.
    pub async fn begin_connect(
        &self,
        user: Uuid,
        backend: &str,
        base_url: &str,
        return_to: Option<String>,
    ) -> Result<String, ConnectError> {
        let (item, scopes) = self.oauth_item(backend)?;
        let static_client = match &item.auth {
            CatalogAuth::OAuth { client, .. } => client.clone(),
            CatalogAuth::Fields | CatalogAuth::Passthrough(_) => None,
        };
        let upstream =
            |error: upstream_oauth::UpstreamOauthError| ConnectError::Upstream(error.to_string());
        // The backend URL is admin-defined, but the issuer and endpoints
        // discovered from it are not: off the backend's origin they need the
        // egress policy.
        let http = Fetcher::for_backend(&item.url, Some(self.egress.as_ref())).map_err(upstream)?;
        let discovery = upstream_oauth::discover(&http, &item.url, None)
            .await
            .map_err(upstream)?;
        let client =
            match upstream_oauth::choose_client(&discovery.metadata, static_client, base_url)
                .map_err(upstream)?
            {
                ClientChoice::Static(client) | ClientChoice::Cimd(client) => client,
                ClientChoice::Register { endpoint } => {
                    self.registered_client(
                        &http,
                        &item.name,
                        &discovery.issuer,
                        &endpoint,
                        base_url,
                    )
                    .await?
                }
            };
        let method = TokenAuthMethod::choose(
            &client,
            discovery
                .metadata
                .token_endpoint_auth_methods_supported
                .as_deref(),
        );
        let scope = upstream_oauth::select_scope(&scopes, &discovery.scopes_supported);
        let redirect_uri = upstream_oauth::redirect_uri(base_url);
        let request = upstream_oauth::build_authorization_request(
            &discovery.metadata,
            &client.client_id,
            &redirect_uri,
            &item.url,
            scope.as_deref(),
        )
        .map_err(upstream)?;
        self.store
            .create_upstream_request(&NewUpstreamRequest {
                state: request.state.clone(),
                user_id: user,
                backend: item.name.clone(),
                issuer: discovery.issuer.clone(),
                client_id: client.client_id,
                token_endpoint: discovery.metadata.token_endpoint.clone(),
                redirect_uri,
                pkce_verifier: request.pkce_verifier.clone(),
                return_to,
                token_auth_method: method.as_str().to_owned(),
                iss_supported: discovery
                    .metadata
                    .authorization_response_iss_parameter_supported,
            })
            .await?;
        Ok(request.url)
    }

    /// The client registered for `backend` at `issuer`: the cached registration,
    /// or one made now at `endpoint` and cached for every user
    async fn registered_client(
        &self,
        http: &Fetcher<'_>,
        backend: &str,
        issuer: &str,
        endpoint: &str,
        base_url: &str,
    ) -> Result<ClientCredentials, ConnectError> {
        if let Some(known) = self.store.get_upstream_client(backend, issuer).await? {
            match &known.secret {
                None => {
                    return Ok(ClientCredentials {
                        client_id: known.client_id,
                        client_secret: None,
                    });
                }
                Some(sealed) => {
                    match upstream_oauth::open_client_secret(&self.keyring, backend, issuer, sealed)
                    {
                        Ok(secret) => {
                            return Ok(ClientCredentials {
                                client_id: known.client_id,
                                client_secret: Some(secret),
                            });
                        }
                        Err(error) => {
                            tracing::warn!(%backend, %error, "the cached registration cannot be opened, registering again");
                        }
                    }
                }
            }
        }
        let client = upstream_oauth::register_client(http, endpoint, base_url)
            .await
            .map_err(|error| ConnectError::Upstream(error.to_string()))?;
        let sealed = client
            .client_secret
            .as_deref()
            .map(|secret| {
                upstream_oauth::seal_client_secret(&self.keyring, backend, issuer, secret)
            })
            .transpose()?;
        self.store
            .upsert_upstream_client(backend, issuer, &client.client_id, sealed.as_ref())
            .await?;
        Ok(client)
    }

    /// Finishes the connection `state` started for `user`: the request must
    /// exist, be younger than 10 minutes and be the user's (it is used up
    /// either way), `iss` must be the authorization server's when that server
    /// returns it, and the code is traded for tokens, which are stored sealed.
    /// The user's slot is rebuilt with the backend. Returns the backend and the
    /// `return_to` given to [`PersonalHub::begin_connect`].
    ///
    /// # Errors
    /// Fails when the request is unknown, expired or someone else's, the issuer
    /// check or the code exchange fails, or the tokens cannot be stored.
    pub async fn finish_connect(
        &self,
        actor: &Actor,
        user: Uuid,
        state: &str,
        code: &str,
        iss: Option<&str>,
    ) -> Result<(String, Option<String>), ConnectError> {
        let request = self
            .store
            .take_upstream_request(state)
            .await?
            .filter(|request| {
                Utc::now() - request.created_at < TimeDelta::seconds(REQUEST_MAX_AGE_SECS)
            })
            .ok_or(ConnectError::UnknownRequest)?;
        if request.user_id != user {
            return Err(ConnectError::WrongUser);
        }
        let (item, _) = self.oauth_item(&request.backend)?;
        upstream_oauth::check_callback_issuer(&request.issuer, request.iss_supported, iss)
            .map_err(|error| ConnectError::Callback(error.to_string()))?;

        let client = self
            .upstream_client(&item, &request.issuer, &request.client_id)
            .await;
        let method = TokenAuthMethod::parse(&request.token_auth_method)
            .unwrap_or_else(|| TokenAuthMethod::choose(&client, None));
        let http = Fetcher::for_backend(&item.url, Some(self.egress.as_ref()))
            .map_err(|error| ConnectError::Exchange(error.to_string()))?;
        let response = upstream_oauth::exchange_code(
            &http,
            &request.token_endpoint,
            method,
            &client,
            &CodeGrant {
                code,
                redirect_uri: &request.redirect_uri,
                pkce_verifier: &request.pkce_verifier,
                resource: &item.url,
            },
        )
        .await
        .map_err(|error| ConnectError::Exchange(error.to_string()))?;

        let secret =
            upstream_oauth::seal_tokens(&self.keyring, user, &item.name, &response.tokens)?;
        self.store
            .connect_upstream_token(
                actor,
                &NewUpstreamToken {
                    user_id: user,
                    backend: &item.name,
                    issuer: &request.issuer,
                    client_id: &request.client_id,
                    token_endpoint: &request.token_endpoint,
                    scope: response.scope.as_deref(),
                    token_auth_method: method.as_str(),
                    secret: &secret,
                    expires_at: response.expires_at,
                },
            )
            .await?;
        self.invalidate(user).await;
        Ok((request.backend, request.return_to))
    }

    /// Removes the user's tokens for `backend` and rebuilds their slot; `false`
    /// when there were none.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn disconnect(
        &self,
        actor: &Actor,
        user: Uuid,
        backend: &str,
    ) -> Result<bool, StoreError> {
        let removed = self
            .store
            .disconnect_upstream_token(actor, user, backend)
            .await?;
        self.invalidate(user).await;
        Ok(removed)
    }

    /// The user's OAuth connections, by backend. No token values.
    ///
    /// # Errors
    /// Fails when the query fails.
    pub async fn connections(&self, user: Uuid) -> Result<Vec<ConnectionStatus>, StoreError> {
        Ok(self
            .store
            .list_upstream_tokens(user)
            .await?
            .into_iter()
            .map(|token| ConnectionStatus {
                backend: token.backend,
                issuer: token.issuer,
                expires_at: token.expires_at,
                last_error: token.last_error,
                last_error_at: token.last_error_at,
                created_at: token.created_at,
            })
            .collect())
    }

    /// Whether any enabled passthrough backend takes its token from `provider`
    fn uses_provider(&self, provider: &str) -> bool {
        self.catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .items
            .iter()
            .any(|item| {
                item.enabled
                    && matches!(&item.auth, CatalogAuth::Passthrough(c) if c.provider == provider)
            })
    }

    /// Whether the user's slot was built without a token of `provider` that a
    /// passthrough backend needs
    fn awaits_subject(&self, user: Uuid, provider: &str) -> bool {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&user)
            .is_some_and(|entry| entry.awaiting_subject.contains(provider))
    }

    /// Notes the access token of `provider` a request of `user` came with (a
    /// resource-server JWT), to start the passthrough grants from. Keeps the
    /// newest per user and provider, and rebuilds the user's slot when it was
    /// built without one a passthrough backend needs. Does nothing when no
    /// passthrough backend uses `provider`.
    pub async fn note_subject_token(
        &self,
        user: Uuid,
        provider: &str,
        token: &str,
        expires_at: DateTime<Utc>,
    ) {
        if !self.uses_provider(provider) {
            return;
        }
        let now = Utc::now();
        self.subjects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .note(user, provider, token, expires_at, now);
        // A token about to expire would not be used, and the rebuild would loop
        if expires_at - now > margin() && self.awaits_subject(user, provider) {
            self.invalidate(user).await;
        }
    }

    /// Whether the dashboard login at `provider` should ask for a refresh token
    /// (`offline_access`) and hand it to [`PersonalHub::store_idp_refresh_token`]:
    /// a passthrough backend uses that provider.
    #[must_use]
    pub fn wants_idp_refresh_token(&self, provider: &str) -> bool {
        self.uses_provider(provider)
    }

    /// Stores the refresh token `provider` gave `user` at login, sealed, to get
    /// fresh tokens for the passthrough grants without a request that carries one.
    ///
    /// # Errors
    /// Fails when sealing or the query fails.
    pub async fn store_idp_refresh_token(
        &self,
        user: Uuid,
        provider: &str,
        refresh_token: &str,
    ) -> Result<(), ConnectError> {
        self.save_idp_refresh_token(user, provider, refresh_token)
            .await?;
        if self.awaits_subject(user, provider) {
            self.invalidate(user).await;
        }
        Ok(())
    }

    async fn save_idp_refresh_token(
        &self,
        user: Uuid,
        provider: &str,
        refresh_token: &str,
    ) -> Result<(), ConnectError> {
        let sealed =
            upstream_oauth::seal_idp_refresh_token(&self.keyring, user, provider, refresh_token)?;
        self.store
            .upsert_idp_refresh_token(user, provider, &sealed)
            .await?;
        Ok(())
    }

    /// The cached entry (bumping its last use); one past its `refresh_at` counts
    /// as missing, so the next build replaces it
    fn cached(&self, user: Uuid) -> Cached {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = slots.get_mut(&user) else {
            return Cached::Missing;
        };
        let now = Instant::now();
        if entry.refresh_at.is_some_and(|at| now >= at) {
            return Cached::Missing;
        }
        entry.last_used = now;
        Cached::Hit(entry.slot.clone())
    }

    fn build_lock(&self, user: Uuid) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .build_locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(locks.entry(user).or_default())
    }

    /// Stores the built slot and evicts the least recently used other slots
    /// until the instance cap holds again; returns the replaced slot and the
    /// evicted ones to stop.
    fn insert(&self, user: Uuid, built: Built) -> Vec<Arc<UserSlot>> {
        let max = usize::try_from(self.config.max_instances).unwrap_or(usize::MAX);
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let replaced = slots.insert(
            user,
            SlotEntry {
                slot: built.slot,
                last_used: Instant::now(),
                refresh_at: built.refresh_at,
                awaiting_subject: built.awaiting_subject,
            },
        );

        let mut evicted: Vec<Arc<UserSlot>> =
            replaced.and_then(|entry| entry.slot).into_iter().collect();
        while slots.values().map(SlotEntry::instances).sum::<usize>() > max {
            let victim = slots
                .iter()
                .filter(|(id, entry)| **id != user && entry.slot.is_some())
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| *id);
            let Some(victim) = victim else { break };
            if let Some(slot) = slots.remove(&victim).and_then(|entry| entry.slot) {
                tracing::info!(user = %victim, "evicting a user's backends to stay under max_instances");
                evicted.push(slot);
            }
        }
        evicted
    }

    /// Opens the user's secrets and spawns their backends
    // One linear sequence of steps, kept in one place so the order reads top to bottom.
    #[allow(clippy::too_many_lines)]
    async fn build(&self, user: Uuid) -> Result<Built, StoreError> {
        let (items, taken) = {
            let state = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
            (state.items.clone(), state.taken_names())
        };
        let credentials = self.store.list_user_credentials(user).await?;
        let personal = self.store.list_personal_backends(user).await?;
        let wants_tokens = items
            .iter()
            .any(|item| item.enabled && matches!(item.auth, CatalogAuth::OAuth { .. }));
        let tokens = if wants_tokens {
            self.store.list_upstream_tokens(user).await?
        } else {
            Vec::new()
        };

        let mut specs = Vec::new();
        let mut awaiting_subject = BTreeSet::new();
        let mut retry = false;
        for item in items.iter().filter(|item| item.enabled) {
            let outcome = match &item.auth {
                CatalogAuth::Fields => {
                    let Some(credential) = credentials.iter().find(|c| c.backend == item.name)
                    else {
                        continue;
                    };
                    match self.catalog_spec(user, item, credential).await {
                        Some(spec) => SpecOutcome::Ready(spec),
                        None => SpecOutcome::Skip,
                    }
                }
                CatalogAuth::OAuth { .. } => {
                    let Some(oauth_token) = tokens.iter().find(|t| t.backend == item.name) else {
                        continue;
                    };
                    self.oauth_spec(user, item, oauth_token).await
                }
                CatalogAuth::Passthrough(config) => {
                    let outcome = self.passthrough_spec(user, item, config).await;
                    if matches!(outcome, SpecOutcome::NeedsSubject) {
                        awaiting_subject.insert(config.provider.clone());
                    }
                    outcome
                }
            };
            match outcome {
                SpecOutcome::Ready(spec) => specs.push(spec),
                SpecOutcome::Retry => retry = true,
                SpecOutcome::Skip | SpecOutcome::NeedsSubject => {}
            }
        }
        for backend in personal.iter().filter(|backend| backend.enabled) {
            if prefix_clash(&backend.prefix, &taken) {
                tracing::warn!(
                    %user,
                    prefix = %backend.prefix,
                    "skipping a personal backend that clashes with a shared or catalog name"
                );
                continue;
            }
            if let Some(spec) = self.personal_spec(backend).await {
                specs.push(spec);
            }
        }

        let max = usize::try_from(self.config.max_instances).unwrap_or(usize::MAX);
        if specs.len() > max {
            tracing::warn!(
                %user,
                backends = specs.len(),
                max,
                "the user has more backends than max_instances allows, starting only some"
            );
            specs.truncate(max);
        }
        if specs.is_empty() {
            return Ok(Built {
                slot: None,
                refresh_at: retry.then(|| retry_deadline(Instant::now())),
                awaiting_subject,
            });
        }
        let started = Instant::now();
        let refresh_at = slot_refresh_at(
            specs.iter().filter_map(|spec| spec.expires_at),
            retry,
            started,
            Utc::now(),
        );

        let registry = RegistryActor::spawn_with_mailbox(
            RegistryActor::new()
                .with_change_bus(self.changes.clone())
                .with_change_scope(ChangeScope::User(user)),
            mailbox::unbounded(),
        );
        let mut backends = HashMap::new();
        let mut kinds = HashMap::new();
        for spec in specs {
            let name = spec.config.name.clone();
            if let Err(error) = registry.tell(RegisterBackend { name: name.clone() }).await {
                tracing::warn!(%user, backend = %name, %error, "could not register the backend");
                continue;
            }
            let actor = BackendActor::with_options(spec.config, registry.clone(), spec.options);
            let actor_ref = BackendActor::spawn_with_mailbox(actor, mailbox::unbounded());
            kinds.insert(name.clone(), spec.kind);
            backends.insert(name, actor_ref);
        }

        Ok(Built {
            slot: Some(Arc::new(UserSlot {
                registry,
                backends: Arc::new(backends),
                kinds,
            })),
            refresh_at,
            awaiting_subject,
        })
    }

    /// The backend of a catalog entry with the user's credential; `None` (and
    /// the outcome recorded) when the credential cannot be opened
    async fn catalog_spec(
        &self,
        user: Uuid,
        item: &CatalogItem,
        credential: &UserCredential,
    ) -> Option<Spec> {
        let aad = credential_aad(user, &item.name);
        let values = match open_map(&self.keyring, &credential.secret, &aad) {
            Ok(values) => values,
            Err(error) => {
                if let Err(store_error) = self
                    .store
                    .record_credential_outcome(user, &item.name, Some(&error))
                    .await
                {
                    tracing::warn!(%user, backend = %item.name, %store_error, "could not record the outcome");
                }
                return None;
            }
        };
        let store = self.store.clone();
        let backend = item.name.clone();
        let hook: OutcomeHook = Arc::new(move |error: Option<String>| {
            let store = store.clone();
            let backend = backend.clone();
            tokio::spawn(async move {
                if let Err(store_error) = store
                    .record_credential_outcome(user, &backend, error.as_deref())
                    .await
                {
                    tracing::debug!(%user, %backend, %store_error, "could not record the outcome");
                }
            });
        });
        Some(catalog_backend(
            item,
            credential_headers(&item.credential_fields, &values),
            Some(hook),
            None,
        ))
    }

    /// The backend of an OAuth catalog entry with the user's access token,
    /// refreshed first when it expires within [`REFRESH_MARGIN_SECS`]. A token
    /// that cannot be opened or refreshed is recorded on its row (the UI then
    /// asks to connect again) and the backend is left out.
    async fn oauth_spec(&self, user: Uuid, item: &CatalogItem, row: &UpstreamToken) -> SpecOutcome {
        let tokens = match upstream_oauth::open_tokens(&self.keyring, user, &item.name, &row.secret)
        {
            Ok(tokens) => tokens,
            Err(error) => {
                self.record_token_error(user, &item.name, &error).await;
                return SpecOutcome::Skip;
            }
        };
        let (access_token, expires_at) = if row.expires_at - Utc::now() > margin() {
            (tokens.access_token, row.expires_at)
        } else {
            match self.refresh_oauth(user, item, row, &tokens).await {
                Refreshed::Tokens(response) => (response.tokens.access_token, response.expires_at),
                Refreshed::Failed => return SpecOutcome::Skip,
                Refreshed::TryAgain => return SpecOutcome::Retry,
            }
        };
        let store = self.store.clone();
        let backend = item.name.clone();
        // A backend that rejects the token shows as a connection to renew
        let hook: OutcomeHook = Arc::new(move |error: Option<String>| {
            let Some(error) = error else { return };
            let store = store.clone();
            let backend = backend.clone();
            tokio::spawn(async move {
                if let Err(store_error) = store
                    .record_upstream_token_error(user, &backend, &error)
                    .await
                {
                    tracing::debug!(%user, %backend, %store_error, "could not record the outcome");
                }
            });
        });
        SpecOutcome::Ready(catalog_backend(
            item,
            bearer_header(&access_token),
            Some(hook),
            Some(expires_at),
        ))
    }

    /// Trades the refresh token for new tokens and stores them
    async fn refresh_oauth(
        &self,
        user: Uuid,
        item: &CatalogItem,
        row: &UpstreamToken,
        tokens: &StoredTokens,
    ) -> Refreshed {
        let Some(refresh_token) = tokens.refresh_token.as_deref() else {
            self.record_token_error(
                user,
                &item.name,
                "the access token expired and the service gave no refresh token",
            )
            .await;
            return Refreshed::Failed;
        };
        let client = self
            .upstream_client(item, &row.issuer, &row.client_id)
            .await;
        let method = TokenAuthMethod::parse(&row.token_auth_method)
            .unwrap_or_else(|| TokenAuthMethod::choose(&client, None));
        // The stored token endpoint came from the backend's metadata: it gets
        // the same origin-or-policy rule as at connect time.
        let refreshed = match Fetcher::for_backend(&item.url, Some(self.egress.as_ref())) {
            Ok(http) => {
                upstream_oauth::refresh_tokens(
                    &http,
                    &row.token_endpoint,
                    method,
                    &client,
                    refresh_token,
                    None,
                    Some(&item.url),
                )
                .await
            }
            Err(error) => Err(error),
        };
        match refreshed {
            Ok(response) => {
                let secret = match upstream_oauth::seal_tokens(
                    &self.keyring,
                    user,
                    &item.name,
                    &response.tokens,
                ) {
                    Ok(secret) => secret,
                    Err(error) => {
                        // The new tokens still work for this slot
                        tracing::warn!(%user, backend = %item.name, %error, "could not seal the refreshed tokens");
                        return Refreshed::Tokens(response);
                    }
                };
                let stored = self
                    .store
                    .upsert_upstream_token(&NewUpstreamToken {
                        user_id: user,
                        backend: &item.name,
                        issuer: &row.issuer,
                        client_id: &row.client_id,
                        token_endpoint: &row.token_endpoint,
                        scope: response.scope.as_deref().or(row.scope.as_deref()),
                        token_auth_method: &row.token_auth_method,
                        secret: &secret,
                        expires_at: response.expires_at,
                    })
                    .await;
                if let Err(error) = stored {
                    tracing::warn!(%user, backend = %item.name, %error, "could not store the refreshed tokens");
                }
                Refreshed::Tokens(response)
            }
            Err(error) => {
                // Another replica may have refreshed first; a rotated refresh
                // token only works once
                if let Some(response) = self.refreshed_elsewhere(user, item, row).await {
                    return Refreshed::Tokens(response);
                }
                tracing::warn!(%user, backend = %item.name, %error, "could not refresh the tokens");
                self.record_token_error(user, &item.name, &error.to_string())
                    .await;
                if error.is_invalid_grant() {
                    Refreshed::Failed
                } else {
                    Refreshed::TryAgain
                }
            }
        }
    }

    /// The tokens another replica stored after `row` was read, if they are fresh
    async fn refreshed_elsewhere(
        &self,
        user: Uuid,
        item: &CatalogItem,
        row: &UpstreamToken,
    ) -> Option<TokenResponse> {
        let latest = self
            .store
            .get_upstream_token(user, &item.name)
            .await
            .ok()
            .flatten()
            .filter(|latest| {
                latest.updated_at > row.updated_at && latest.expires_at - Utc::now() > margin()
            })?;
        let tokens =
            upstream_oauth::open_tokens(&self.keyring, user, &item.name, &latest.secret).ok()?;
        Some(TokenResponse {
            tokens,
            expires_at: latest.expires_at,
            scope: latest.scope,
        })
    }

    /// The client a token was issued to: the static one, the registration
    /// shared by every user, or else a public client with that id (a client ID
    /// metadata document)
    async fn upstream_client(
        &self,
        item: &CatalogItem,
        issuer: &str,
        client_id: &str,
    ) -> ClientCredentials {
        if let CatalogAuth::OAuth {
            client: Some(client),
            ..
        } = &item.auth
            && client.client_id == client_id
        {
            return client.clone();
        }
        match self.store.get_upstream_client(&item.name, issuer).await {
            Ok(Some(registered)) if registered.client_id == client_id => {
                let client_secret = registered.secret.as_ref().and_then(|sealed| {
                    upstream_oauth::open_client_secret(&self.keyring, &item.name, issuer, sealed)
                        .inspect_err(|error| {
                            tracing::warn!(backend = %item.name, %error, "could not open the registered client's secret");
                        })
                        .ok()
                });
                return ClientCredentials {
                    client_id: registered.client_id,
                    client_secret,
                };
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(backend = %item.name, %error, "could not read the registered client");
            }
        }
        ClientCredentials {
            client_id: client_id.to_owned(),
            client_secret: None,
        }
    }

    /// Records why a user's tokens for a backend cannot be used
    async fn record_token_error(&self, user: Uuid, backend: &str, error: &str) {
        if let Err(store_error) = self
            .store
            .record_upstream_token_error(user, backend, error)
            .await
        {
            tracing::warn!(%user, %backend, %store_error, "could not record the token error");
        }
    }

    /// The backend of a passthrough entry with a token exchanged from the
    /// user's identity provider token
    async fn passthrough_spec(
        &self,
        user: Uuid,
        item: &CatalogItem,
        config: &PassthroughConfig,
    ) -> SpecOutcome {
        let Some(provider) = self
            .oidc
            .as_ref()
            .and_then(|providers| providers.get(&config.provider))
        else {
            tracing::warn!(backend = %item.name, provider = %config.provider, "the passthrough provider is not configured");
            return SpecOutcome::Skip;
        };
        // OBO needs an assertion issued for the gateway's own API; a token for
        // the login scopes alone is Microsoft Graph's on Entra
        let assertion_scope = (config.grant == PassthroughGrant::EntraObo).then(|| {
            config.assertion_scope.clone().unwrap_or_else(|| {
                format!("api://{}/.default", provider.app_credentials().client_id)
            })
        });
        let subject = match self
            .subject_token(user, &provider, assertion_scope.as_deref())
            .await
        {
            Subject::Token(token) => token,
            Subject::Missing => return SpecOutcome::NeedsSubject,
            Subject::Failed => return SpecOutcome::Retry,
        };
        let (token_endpoint, auth_methods) = match provider.token_endpoint().await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::warn!(backend = %item.name, %error, "could not discover the passthrough provider");
                return SpecOutcome::Retry;
            }
        };
        let app = provider.app_credentials();
        // The token endpoint is the configured `[[auth.oidc]]` provider's, not a
        // backend's, so it is not egress-restricted
        let http = Fetcher::trusted();
        let exchanged = match config.grant {
            PassthroughGrant::TokenExchange => {
                upstream_oauth::token_exchange(
                    &http,
                    &TokenEndpoint {
                        url: &token_endpoint,
                        auth_methods: auth_methods.as_deref(),
                    },
                    &app,
                    &TokenExchangeRequest {
                        subject_token: &subject,
                        audience: config.audience.as_deref(),
                        scope: config.scope.as_deref(),
                        resource: config.resource.as_deref(),
                    },
                )
                .await
            }
            PassthroughGrant::EntraObo => {
                let Some(scope) = config.scope.as_deref() else {
                    return SpecOutcome::Skip;
                };
                upstream_oauth::on_behalf_of(&http, &token_endpoint, &app, &subject, scope).await
            }
        };
        match exchanged {
            Ok(response) => SpecOutcome::Ready(catalog_backend(
                item,
                bearer_header(&response.tokens.access_token),
                None,
                Some(response.expires_at),
            )),
            Err(error) => {
                tracing::warn!(%user, backend = %item.name, %error, "the token exchange failed");
                SpecOutcome::Retry
            }
        }
    }

    /// An access token of the identity provider to start a passthrough grant
    /// from: the newest JWT seen on a request, else one refreshed with the
    /// refresh token stored at login. `extra_scope` is requested on top of the
    /// login scopes (Entra on-behalf-of: the gateway's own API).
    async fn subject_token(
        &self,
        user: Uuid,
        provider: &Provider,
        extra_scope: Option<&str>,
    ) -> Subject {
        let known = self
            .subjects
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .usable(user, provider.id(), Utc::now(), margin());
        if let Some(token) = known {
            return Subject::Token(token);
        }
        let sealed = match self.store.get_idp_refresh_token(user, provider.id()).await {
            Ok(Some(sealed)) => sealed,
            Ok(None) => return Subject::Missing,
            Err(error) => {
                tracing::warn!(%user, provider = provider.id(), %error, "could not read the identity provider refresh token");
                return Subject::Failed;
            }
        };
        let refresh_token = match upstream_oauth::open_idp_refresh_token(
            &self.keyring,
            user,
            provider.id(),
            &sealed,
        ) {
            Ok(token) => token,
            Err(error) => {
                tracing::warn!(%user, provider = provider.id(), %error, "could not open the identity provider refresh token");
                return Subject::Missing;
            }
        };
        let (token_endpoint, auth_methods) = match provider.token_endpoint().await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                tracing::warn!(provider = provider.id(), %error, "could not discover the identity provider");
                return Subject::Failed;
            }
        };
        let mut scopes = provider.scopes();
        scopes.extend(extra_scope.map(str::to_owned));
        let scope = (!scopes.is_empty()).then(|| scopes.join(" "));
        let refreshed = upstream_oauth::refresh_idp_token(
            // The configured `[[auth.oidc]]` provider's endpoint, not a backend's
            &Fetcher::trusted(),
            &TokenEndpoint {
                url: &token_endpoint,
                auth_methods: auth_methods.as_deref(),
            },
            &provider.app_credentials(),
            &refresh_token,
            scope.as_deref(),
        )
        .await;
        match refreshed {
            Ok(response) => {
                if let Some(rotated) = response
                    .tokens
                    .refresh_token
                    .as_deref()
                    .filter(|rotated| *rotated != refresh_token)
                    && let Err(error) = self
                        .save_idp_refresh_token(user, provider.id(), rotated)
                        .await
                {
                    tracing::warn!(%user, provider = provider.id(), %error, "could not store the rotated refresh token");
                }
                self.subjects
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .note(
                        user,
                        provider.id(),
                        &response.tokens.access_token,
                        response.expires_at,
                        Utc::now(),
                    );
                Subject::Token(response.tokens.access_token)
            }
            Err(error) if error.is_invalid_grant() => {
                // The user has to log in again to get a new one
                if let Err(store_error) = self
                    .store
                    .delete_idp_refresh_token(user, provider.id())
                    .await
                {
                    tracing::warn!(%user, provider = provider.id(), %store_error, "could not delete the refresh token");
                }
                Subject::Missing
            }
            Err(error) => {
                tracing::warn!(%user, provider = provider.id(), %error, "could not refresh the identity provider token");
                Subject::Failed
            }
        }
    }

    /// The backend of a personal entry; `None` (and the outcome recorded) when
    /// its headers cannot be opened
    async fn personal_spec(&self, backend: &PersonalBackend) -> Option<Spec> {
        let headers = match &backend.secret {
            Some(secret) => match open_map(&self.keyring, secret, &personal_aad(backend.id)) {
                Ok(headers) => headers,
                Err(error) => {
                    if let Err(store_error) = self
                        .store
                        .record_personal_outcome(backend.id, Some(&error))
                        .await
                    {
                        tracing::warn!(id = %backend.id, %store_error, "could not record the outcome");
                    }
                    return None;
                }
            },
            None => BTreeMap::new(),
        };
        let config = BackendConfig {
            name: backend.prefix.clone(),
            url: Some(backend.url.clone()),
            transport: TransportType::Http,
            headers: headers.into_iter().collect(),
            ..BackendConfig::default()
        };
        let idle_timeout = config.idle_timeout(self.idle_default_secs);
        let store = self.store.clone();
        let id = backend.id;
        let hook: OutcomeHook = Arc::new(move |error: Option<String>| {
            let store = store.clone();
            tokio::spawn(async move {
                if let Err(store_error) = store.record_personal_outcome(id, error.as_deref()).await
                {
                    tracing::debug!(%id, %store_error, "could not record the outcome");
                }
            });
        });
        Some(Spec {
            config,
            options: BackendOptions {
                idle_timeout,
                egress: Some(Arc::clone(&self.egress)),
                passive_health: true,
                on_outcome: Some(hook),
            },
            kind: UserBackendKind::Personal { id },
            expires_at: None,
        })
    }
}

/// Stops a slot's backends and registry
async fn stop_slot(slot: &UserSlot) {
    for (name, backend) in slot.backends.iter() {
        if let Err(error) = backend.stop_gracefully().await {
            tracing::debug!(backend = %name, %error, "backend already stopped");
        }
    }
    if let Err(error) = slot.registry.stop_gracefully().await {
        tracing::debug!(%error, "registry already stopped");
    }
}

/// What refreshing an OAuth connection gave
enum Refreshed {
    Tokens(TokenResponse),
    /// The server refused for good; the user has to connect again
    Failed,
    /// A failure that may pass
    TryAgain,
}

/// What a passthrough grant can start from
enum Subject {
    Token(String),
    /// No token and no way to get one
    Missing,
    /// A failure that may pass
    Failed,
}

/// The backend of a catalog item with `headers`; `expires_at` is when the
/// token in them stops working
fn catalog_backend(
    item: &CatalogItem,
    headers: HashMap<String, String>,
    on_outcome: Option<OutcomeHook>,
    expires_at: Option<DateTime<Utc>>,
) -> Spec {
    Spec {
        config: BackendConfig {
            name: item.name.clone(),
            url: Some(item.url.clone()),
            transport: TransportType::Http,
            headers,
            timeout_secs: item.timeout_secs,
            ..BackendConfig::default()
        },
        options: BackendOptions {
            idle_timeout: item.idle_timeout,
            egress: None,
            passive_health: true,
            on_outcome,
        },
        kind: UserBackendKind::Catalog,
        expires_at,
    }
}

fn bearer_header(access_token: &str) -> HashMap<String, String> {
    HashMap::from([(
        String::from("Authorization"),
        format!("Bearer {access_token}"),
    )])
}

/// When a slot built at `started` must be built again: before its earliest token
/// expires, and soon when a backend was left out for a failure that may pass
fn slot_refresh_at(
    expiries: impl Iterator<Item = DateTime<Utc>>,
    retry: bool,
    started: Instant,
    now: DateTime<Utc>,
) -> Option<Instant> {
    let expiry = expiries
        .min()
        .map(|expires_at| refresh_deadline(started, now, expires_at));
    let retry = retry.then(|| retry_deadline(started));
    match (expiry, retry) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// [`REFRESH_MARGIN_SECS`] before `expires_at`, but not sooner than
/// [`MIN_SLOT_LIFETIME`] after `started`
fn refresh_deadline(started: Instant, now: DateTime<Utc>, expires_at: DateTime<Utc>) -> Instant {
    let left = (expires_at - now - margin())
        .to_std()
        .unwrap_or_default()
        .max(MIN_SLOT_LIFETIME);
    started.checked_add(left).unwrap_or(started)
}

fn retry_deadline(started: Instant) -> Instant {
    started.checked_add(RETRY_AFTER).unwrap_or(started)
}

fn catalog_oauth_aad(name: &str) -> String {
    format!("catalog-oauth:{name}")
}

fn personal_aad(id: Uuid) -> String {
    format!("personal-backend:{id}")
}

fn credential_aad(user: Uuid, backend: &str) -> String {
    format!("credential:{user}:{backend}")
}

/// Seals a JSON object of strings
fn seal_map(
    keyring: &Keyring,
    map: &BTreeMap<String, String>,
    aad: &str,
) -> Result<SealedColumns, CryptoError> {
    let payload = serde_json::to_vec(map).map_err(|_| CryptoError::Encrypt)?;
    keyring
        .seal(&payload, aad.as_bytes())
        .map(SealedColumns::from)
}

/// Opens a sealed JSON object of strings; the error is safe to store and show
fn open_map(
    keyring: &Keyring,
    sealed: &SealedColumns,
    aad: &str,
) -> Result<BTreeMap<String, String>, String> {
    let payload = keyring
        .open(&Sealed::from(sealed), aad.as_bytes())
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&payload)
        .map_err(|_| String::from("the stored secret is not a JSON object of strings"))
}

/// The headers for the values a user entered: each filled field becomes its
/// `header` with `prefix` in front; fields the user left empty are skipped
fn credential_headers(
    fields: &[CredentialField],
    values: &BTreeMap<String, String>,
) -> HashMap<String, String> {
    fields
        .iter()
        .filter_map(|field| {
            let value = values.get(&field.name).filter(|value| !value.is_empty())?;
            let prefix = field.prefix.as_deref().unwrap_or_default();
            Some((field.header.clone(), format!("{prefix}{value}")))
        })
        .collect()
}

/// Whether a personal backend named `prefix` would share tool names with a
/// shared or catalog backend (`name` itself, or `name_tool` with `name` under it)
fn prefix_clash(prefix: &str, names: &BTreeSet<String>) -> bool {
    let tool_prefix = format!("{prefix}_");
    names
        .iter()
        .any(|name| name == prefix || name.starts_with(&tool_prefix))
}

/// `^[a-z][a-z0-9-]{1,30}$`, not reserved, not clashing with `names`
fn check_prefix(prefix: &str, names: &BTreeSet<String>) -> Result<(), String> {
    let mut chars = prefix.chars();
    let well_formed = (2..=31).contains(&prefix.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !well_formed {
        return Err(String::from(
            "the prefix must be 2 to 31 characters: a lowercase letter, then lowercase letters, digits or dashes",
        ));
    }
    if RESERVED_PREFIXES.contains(&prefix) {
        return Err(format!("the prefix {prefix:?} is reserved"));
    }
    if prefix_clash(prefix, names) {
        return Err(format!(
            "the prefix {prefix:?} clashes with a shared or catalog backend"
        ));
    }
    Ok(())
}

/// The catalog and shared names from the config and the database's entries
fn catalog_state(
    keyring: &Keyring,
    config: &Config,
    gateway_idle_secs: u64,
    entries: Vec<CatalogEntry>,
) -> CatalogState {
    let shared = config
        .backends
        .iter()
        .filter(|backend| !backend.is_per_user())
        .map(|backend| backend.name.clone())
        .collect();
    CatalogState {
        items: merge_catalog(keyring, &config.backends, gateway_idle_secs, entries),
        shared,
    }
}

/// How the users of a config backend authenticate; `None` for a backend that
/// is not per-user or lacks the table its mode needs
fn config_auth(backend: &BackendConfig) -> Option<CatalogAuth> {
    match backend.credential_mode {
        CredentialMode::Shared => None,
        CredentialMode::PerUser => Some(CatalogAuth::Fields),
        CredentialMode::OAuth => {
            let oauth = backend.oauth.as_ref();
            Some(CatalogAuth::OAuth {
                client: oauth.map(|oauth| ClientCredentials {
                    client_id: oauth.client_id.clone(),
                    client_secret: oauth.client_secret.clone(),
                }),
                scopes: oauth.map(|oauth| oauth.scopes.clone()).unwrap_or_default(),
                // `Config::load` reads the secret, so a missing one is a config
                // that skipped it
                client_unusable: oauth.is_some_and(|oauth| {
                    oauth.client_secret_env.is_some() && oauth.client_secret.is_none()
                }),
            })
        }
        CredentialMode::Passthrough => backend.passthrough.clone().map(CatalogAuth::Passthrough),
    }
}

/// How the users of a database entry authenticate. A client secret that cannot
/// be opened is logged and makes the client unusable.
fn entry_auth(keyring: &Keyring, entry: &CatalogEntry) -> CatalogAuth {
    match entry.auth {
        CatalogAuthMode::Fields => CatalogAuth::Fields,
        CatalogAuthMode::OAuth => {
            let mut client_unusable = false;
            let client = entry.oauth_client_id.as_ref().map(|client_id| {
                let client_secret = entry.oauth_secret.as_ref().and_then(|sealed| {
                    upstream_oauth::open_text(keyring, sealed, &catalog_oauth_aad(&entry.name))
                        .inspect_err(|error| {
                            tracing::warn!(entry = %entry.name, %error, "the catalog entry's OAuth client secret cannot be opened, its client is unusable");
                            client_unusable = true;
                        })
                        .ok()
                });
                ClientCredentials {
                    client_id: client_id.clone(),
                    client_secret,
                }
            });
            CatalogAuth::OAuth {
                client,
                scopes: entry.oauth_scopes.clone(),
                client_unusable,
            }
        }
    }
}

/// The per-user config backends and the database's entries, by name; the
/// config wins when both define a name
fn merge_catalog(
    keyring: &Keyring,
    backends: &[BackendConfig],
    gateway_idle_secs: u64,
    entries: Vec<CatalogEntry>,
) -> Vec<CatalogItem> {
    let mut items: Vec<CatalogItem> = backends
        .iter()
        .filter(|backend| backend.is_per_user())
        .filter_map(|backend| {
            Some(CatalogItem {
                name: backend.name.clone(),
                description: None,
                url: backend.url.clone()?,
                credential_fields: backend.credential_fields.clone(),
                auth: config_auth(backend)?,
                enabled: backend.enabled,
                source: CatalogSource::Config,
                idle_timeout: backend.idle_timeout(gateway_idle_secs),
                timeout_secs: backend.timeout_secs,
            })
        })
        .collect();

    let default_timeout_secs = BackendConfig::default().timeout_secs;
    for entry in entries {
        if backends.iter().any(|backend| backend.name == entry.name) {
            continue;
        }
        let auth = entry_auth(keyring, &entry);
        items.push(CatalogItem {
            name: entry.name,
            description: entry.description,
            url: entry.url,
            credential_fields: entry.credential_fields,
            auth,
            enabled: entry.enabled,
            source: CatalogSource::Database,
            idle_timeout: (gateway_idle_secs > 0).then(|| Duration::from_secs(gateway_idle_secs)),
            timeout_secs: default_timeout_secs,
        });
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::config::{CredentialMode, UpstreamOAuthConfig};

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|name| (*name).to_string()).collect()
    }

    fn field(name: &str, header: &str, prefix: Option<&str>) -> CredentialField {
        CredentialField {
            name: name.to_string(),
            label: None,
            header: header.to_string(),
            prefix: prefix.map(str::to_string),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn per_user(name: &str, url: &str) -> BackendConfig {
        BackendConfig {
            name: name.to_string(),
            url: Some(url.to_string()),
            transport: TransportType::Http,
            credential_mode: CredentialMode::PerUser,
            idle_timeout_secs: Some(60),
            timeout_secs: 12,
            ..BackendConfig::default()
        }
    }

    fn entry(name: &str, url: &str) -> CatalogEntry {
        CatalogEntry {
            name: name.to_string(),
            description: Some(String::from("from the database")),
            url: url.to_string(),
            credential_fields: Vec::new(),
            enabled: true,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            auth: CatalogAuthMode::Fields,
            oauth_client_id: None,
            oauth_scopes: Vec::new(),
            oauth_secret: None,
        }
    }

    fn keyring() -> Keyring {
        Keyring::from_text("k1:0123456789abcdef0123456789abcdef-secret").unwrap()
    }

    fn oauth_entry(
        name: &str,
        client_id: Option<&str>,
        secret: Option<SealedColumns>,
    ) -> CatalogEntry {
        CatalogEntry {
            auth: CatalogAuthMode::OAuth,
            oauth_client_id: client_id.map(str::to_string),
            oauth_scopes: vec![String::from("read")],
            oauth_secret: secret,
            ..entry(name, "https://oauth.example/mcp")
        }
    }

    fn oauth_backend(name: &str, oauth: Option<UpstreamOAuthConfig>) -> BackendConfig {
        BackendConfig {
            credential_mode: CredentialMode::OAuth,
            oauth,
            ..per_user(name, "https://oauth.example/mcp")
        }
    }

    fn passthrough_config() -> PassthroughConfig {
        PassthroughConfig {
            grant: PassthroughGrant::TokenExchange,
            provider: String::from("entra"),
            audience: Some(String::from("api://wiki")),
            scope: None,
            resource: None,
            assertion_scope: None,
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::UNIX_EPOCH + TimeDelta::seconds(secs)
    }

    #[test]
    fn prefix_accepts_a_good_name() {
        let taken = names(&["github", "forgejo"]);
        assert_eq!(check_prefix("my-notes", &taken), Ok(()));
        assert_eq!(check_prefix("a1", &taken), Ok(()));
    }

    #[test]
    fn prefix_rejects_bad_shapes() {
        let taken = names(&[]);
        assert!(check_prefix("a", &taken).is_err());
        assert!(check_prefix("", &taken).is_err());
        assert!(check_prefix("Notes", &taken).is_err());
        assert!(check_prefix("my_notes", &taken).is_err());
        assert!(check_prefix("1notes", &taken).is_err());
        assert!(check_prefix("-notes", &taken).is_err());
        assert!(check_prefix(&"a".repeat(32), &taken).is_err());
        assert!(check_prefix(&"a".repeat(31), &taken).is_ok());
    }

    #[test]
    fn prefix_rejects_reserved_names() {
        let taken = names(&[]);
        for reserved in RESERVED_PREFIXES {
            assert!(check_prefix(reserved, &taken).is_err(), "{reserved}");
        }
    }

    #[test]
    fn prefix_rejects_clashes() {
        let taken = names(&["forgejo", "pg_main"]);
        assert!(check_prefix("forgejo", &taken).is_err());
        // `pg_main` would be a tool `main` of a personal backend `pg`
        assert!(check_prefix("pg", &taken).is_err());
        assert!(check_prefix("pgx", &taken).is_ok());
    }

    #[test]
    fn config_wins_a_catalog_name_clash() {
        let backends = vec![
            per_user("github", "https://config.example/mcp"),
            BackendConfig {
                name: String::from("shared"),
                url: Some(String::from("https://shared.example/mcp")),
                ..BackendConfig::default()
            },
        ];
        let entries = vec![
            entry("github", "https://database.example/mcp"),
            entry("linear", "https://linear.example/mcp"),
        ];
        let items = merge_catalog(&keyring(), &backends, 300, entries);

        assert_eq!(items.len(), 2);
        let github = items.iter().find(|i| i.name == "github");
        assert_eq!(
            github.map(|i| (i.url.as_str(), i.source)),
            Some(("https://config.example/mcp", CatalogSource::Config))
        );
        assert_eq!(
            github.map(|i| (i.idle_timeout, i.timeout_secs)),
            Some((Some(Duration::from_secs(60)), 12))
        );
        let linear = items.iter().find(|i| i.name == "linear");
        assert_eq!(linear.map(|i| i.source), Some(CatalogSource::Database));
        assert_eq!(
            linear.map(|i| i.idle_timeout),
            Some(Some(Duration::from_secs(300)))
        );
        assert_eq!(
            linear.map(|i| i.timeout_secs),
            Some(BackendConfig::default().timeout_secs)
        );
    }

    #[test]
    fn headers_use_the_prefix_and_skip_missing_fields() {
        let fields = vec![
            field("token", "Authorization", Some("Bearer ")),
            field("org", "X-Org", None),
            field("extra", "X-Extra", None),
        ];
        let headers = credential_headers(&fields, &values(&[("token", "abc"), ("extra", "")]));

        assert_eq!(headers.len(), 1);
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer abc")
        );
    }

    #[test]
    fn sealed_payload_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::from_text("k1:0123456789abcdef0123456789abcdef-secret")?;
        let id = Uuid::new_v4();
        let headers = values(&[("Authorization", "Bearer abc"), ("X-Key", "v")]);

        let sealed = seal_map(&keyring, &headers, &personal_aad(id))?;
        assert_eq!(open_map(&keyring, &sealed, &personal_aad(id)), Ok(headers));
        // The AAD binds the secret to its row
        assert!(open_map(&keyring, &sealed, &personal_aad(Uuid::new_v4())).is_err());
        Ok(())
    }

    #[test]
    fn credential_payload_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let keyring = Keyring::from_text("0123456789abcdef0123456789abcdef-secret")?;
        let user = Uuid::new_v4();
        let entered = values(&[("token", "abc")]);

        let sealed = seal_map(&keyring, &entered, &credential_aad(user, "github"))?;
        assert_eq!(
            open_map(&keyring, &sealed, &credential_aad(user, "github")),
            Ok(entered)
        );
        assert!(open_map(&keyring, &sealed, &credential_aad(user, "linear")).is_err());
        Ok(())
    }

    fn seal_secret(keyring: &Keyring, name: &str, secret: &str) -> SealedColumns {
        upstream_oauth::seal_text(keyring, secret.as_bytes(), &catalog_oauth_aad(name)).unwrap()
    }

    fn auth_of<'a>(items: &'a [CatalogItem], name: &str) -> Option<&'a CatalogAuth> {
        items.iter().find(|i| i.name == name).map(|i| &i.auth)
    }

    #[test]
    fn config_entries_carry_their_auth() {
        let backends = vec![
            per_user("fields", "https://fields.example/mcp"),
            oauth_backend(
                "static",
                Some(UpstreamOAuthConfig {
                    client_id: String::from("axon"),
                    client_secret_env: Some(String::from("STATIC_SECRET")),
                    client_secret: Some(String::from("s3cret")),
                    scopes: vec![String::from("a"), String::from("b")],
                }),
            ),
            oauth_backend("dynamic", None),
            oauth_backend(
                "unread",
                Some(UpstreamOAuthConfig {
                    client_id: String::from("axon"),
                    client_secret_env: Some(String::from("MISSING")),
                    client_secret: None,
                    scopes: Vec::new(),
                }),
            ),
            BackendConfig {
                credential_mode: CredentialMode::Passthrough,
                passthrough: Some(passthrough_config()),
                ..per_user("exchange", "https://exchange.example/mcp")
            },
            BackendConfig {
                credential_mode: CredentialMode::Passthrough,
                passthrough: None,
                ..per_user("broken", "https://broken.example/mcp")
            },
        ];
        let items = merge_catalog(&keyring(), &backends, 300, Vec::new());

        assert_eq!(
            items.len(),
            5,
            "a passthrough entry without its table is left out"
        );
        assert_eq!(auth_of(&items, "fields"), Some(&CatalogAuth::Fields));
        assert_eq!(
            auth_of(&items, "static"),
            Some(&CatalogAuth::OAuth {
                client: Some(ClientCredentials {
                    client_id: String::from("axon"),
                    client_secret: Some(String::from("s3cret")),
                }),
                scopes: vec![String::from("a"), String::from("b")],
                client_unusable: false,
            })
        );
        assert_eq!(
            auth_of(&items, "dynamic"),
            Some(&CatalogAuth::OAuth {
                client: None,
                scopes: Vec::new(),
                client_unusable: false,
            })
        );
        assert!(matches!(
            auth_of(&items, "unread"),
            Some(CatalogAuth::OAuth {
                client_unusable: true,
                ..
            })
        ));
        assert_eq!(
            auth_of(&items, "exchange"),
            Some(&CatalogAuth::Passthrough(passthrough_config()))
        );
        assert!(
            items
                .iter()
                .all(|item| item.source == CatalogSource::Config)
        );
    }

    #[test]
    fn database_entries_open_their_client_secret() {
        let keyring = keyring();
        let entries = vec![
            entry("plain", "https://plain.example/mcp"),
            oauth_entry(
                "static",
                Some("axon"),
                Some(seal_secret(&keyring, "static", "shh")),
            ),
            oauth_entry("public", Some("axon"), None),
            oauth_entry("dynamic", None, None),
            // Sealed for another entry: the AAD does not match
            oauth_entry(
                "moved",
                Some("axon"),
                Some(seal_secret(&keyring, "other", "shh")),
            ),
        ];
        let items = merge_catalog(&keyring, &[], 300, entries);

        assert_eq!(auth_of(&items, "plain"), Some(&CatalogAuth::Fields));
        assert_eq!(
            auth_of(&items, "static"),
            Some(&CatalogAuth::OAuth {
                client: Some(ClientCredentials {
                    client_id: String::from("axon"),
                    client_secret: Some(String::from("shh")),
                }),
                scopes: vec![String::from("read")],
                client_unusable: false,
            })
        );
        assert_eq!(
            auth_of(&items, "public"),
            Some(&CatalogAuth::OAuth {
                client: Some(ClientCredentials {
                    client_id: String::from("axon"),
                    client_secret: None,
                }),
                scopes: vec![String::from("read")],
                client_unusable: false,
            })
        );
        assert!(matches!(
            auth_of(&items, "dynamic"),
            Some(CatalogAuth::OAuth {
                client: None,
                client_unusable: false,
                ..
            })
        ));
        // The reload goes on; only that entry's client is unusable
        assert!(matches!(
            auth_of(&items, "moved"),
            Some(CatalogAuth::OAuth {
                client_unusable: true,
                ..
            })
        ));
        assert_eq!(items.len(), 5);
        assert!(
            items
                .iter()
                .all(|item| item.source == CatalogSource::Database)
        );
    }

    #[test]
    fn a_slot_is_rebuilt_before_its_first_token_expires() {
        let started = Instant::now();
        let now = at(1_000);

        assert_eq!(slot_refresh_at([].into_iter(), false, started, now), None);
        // Two minutes before the earliest expiry
        assert_eq!(
            slot_refresh_at([at(1_900), at(1_600)].into_iter(), false, started, now),
            Some(started + Duration::from_secs(480))
        );
        // A token that lives less than the margin does not make a slot that
        // is rebuilt on every request
        assert_eq!(
            slot_refresh_at([at(1_060)].into_iter(), false, started, now),
            Some(started + MIN_SLOT_LIFETIME)
        );
        assert_eq!(
            slot_refresh_at([at(1_000)].into_iter(), false, started, now),
            Some(started + MIN_SLOT_LIFETIME)
        );
        // A backend left out for a failure that may pass is tried again soon
        assert_eq!(
            slot_refresh_at([].into_iter(), true, started, now),
            Some(started + RETRY_AFTER)
        );
        assert_eq!(
            slot_refresh_at([at(1_150)].into_iter(), true, started, now),
            Some(started + MIN_SLOT_LIFETIME)
        );
        assert_eq!(
            slot_refresh_at([at(5_000)].into_iter(), true, started, now),
            Some(started + RETRY_AFTER)
        );
    }

    #[test]
    fn the_newest_subject_token_wins() {
        let user = Uuid::new_v4();
        let now = at(1_000);
        let mut tokens = SubjectTokens::new(10);

        tokens.note(user, "entra", "first", at(2_000), now);
        tokens.note(user, "entra", "older", at(1_500), now);
        assert_eq!(
            tokens.usable(user, "entra", now, margin()).as_deref(),
            Some("first")
        );
        tokens.note(user, "entra", "second", at(3_000), now);
        assert_eq!(
            tokens.usable(user, "entra", now, margin()).as_deref(),
            Some("second")
        );
        // Another provider or user has its own
        assert_eq!(tokens.usable(user, "other", now, margin()), None);
        assert_eq!(tokens.usable(Uuid::new_v4(), "entra", now, margin()), None);
    }

    #[test]
    fn a_subject_token_is_used_only_with_time_to_spare() {
        let user = Uuid::new_v4();
        let now = at(1_000);
        let mut tokens = SubjectTokens::new(10);

        tokens.note(user, "entra", "short", at(1_100), now);
        assert_eq!(tokens.usable(user, "entra", now, margin()), None);
        assert_eq!(
            tokens
                .usable(user, "entra", now, TimeDelta::seconds(60))
                .as_deref(),
            Some("short")
        );
        // An expired token is not kept
        tokens.note(user, "gone", "expired", at(999), now);
        assert_eq!(tokens.tokens.len(), 1);
    }

    #[test]
    fn the_subject_tokens_are_capped() {
        let now = at(1_000);
        let (a, b, c, d) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let mut tokens = SubjectTokens::new(2);

        tokens.note(a, "entra", "a", at(1_100), now);
        tokens.note(b, "entra", "b", at(1_200), now);
        // Full: nothing has expired, so the one closest to expiry goes
        tokens.note(c, "entra", "c", at(1_300), now);
        assert_eq!(tokens.tokens.len(), 2);
        assert_eq!(tokens.usable(a, "entra", now, TimeDelta::zero()), None);
        assert!(tokens.usable(b, "entra", now, TimeDelta::zero()).is_some());
        assert!(tokens.usable(c, "entra", now, TimeDelta::zero()).is_some());

        // Full again, and one has expired by now: it makes room, nothing else goes
        let later = at(1_250);
        tokens.note(d, "entra", "d", at(2_000), later);
        assert_eq!(tokens.tokens.len(), 2);
        assert!(
            tokens
                .usable(c, "entra", later, TimeDelta::zero())
                .is_some()
        );
        assert!(
            tokens
                .usable(d, "entra", later, TimeDelta::zero())
                .is_some()
        );
        assert_eq!(tokens.usable(b, "entra", later, TimeDelta::zero()), None);
    }

    #[test]
    fn catalog_secrets_are_bound_to_their_entry() {
        let keyring = keyring();
        let sealed = seal_secret(&keyring, "wiki", "shh");
        assert_eq!(
            upstream_oauth::open_text(&keyring, &sealed, &catalog_oauth_aad("wiki")),
            Ok(String::from("shh"))
        );
        assert!(upstream_oauth::open_text(&keyring, &sealed, &catalog_oauth_aad("other")).is_err());
    }
}
