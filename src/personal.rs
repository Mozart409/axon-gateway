//! Per-user backends: personal MCP servers and catalog credentials
//!
//! Every user with at least one personal backend, or a stored credential for a
//! catalog entry, gets a [`UserSlot`]: their own registry and one backend actor
//! per entry, built lazily on the first request and dropped again when the
//! user's configuration changes ([`PersonalHub::invalidate`]) or when the
//! per-replica instance cap makes room for someone else. Secrets are opened
//! only while a slot is built and live on in the backend actors' headers.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use kameo::actor::{ActorRef, Spawn};
use kameo::mailbox;
use rmcp::ServiceExt;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use uuid::Uuid;

use crate::backend::{BackendActor, BackendOptions, GetBackendInfo, OutcomeHook, http_transport};
use crate::changes::{ChangeBus, ChangeScope};
use crate::config::{
    BackendConfig, Config, CredentialField, PersonalBackendsConfig, TransportType,
};
use crate::crypto::{CryptoError, Keyring, Sealed};
use crate::egress::EgressPolicy;
use crate::registry::{RegisterBackend, RegistryActor};
use crate::store::{
    CatalogEntry, PersonalBackend, SealedColumns, Store, StoreError, UserCredential,
};
use crate::types::BackendState;

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

/// One backend every user may bring a credential for
#[derive(Debug, Clone)]
pub struct CatalogItem {
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub credential_fields: Vec<CredentialField>,
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
    catalog: RwLock<CatalogState>,
    slots: Mutex<HashMap<Uuid, SlotEntry>>,
    /// One lock per user so concurrent first requests build the slot once
    build_locks: Mutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>,
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
    ) -> Self {
        let idle_default_secs = config.gateway.idle_timeout_secs;
        let state = catalog_state(config, idle_default_secs, Vec::new());
        Self {
            store,
            keyring,
            egress,
            config: config.personal_backends.clone(),
            idle_default_secs,
            changes,
            catalog: RwLock::new(state),
            slots: Mutex::new(HashMap::new()),
            build_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Recomputes the merged catalog and the shared names from `config` and
    /// the database. Built slots are left alone; call
    /// [`PersonalHub::invalidate_all`] when they must pick the change up.
    ///
    /// # Errors
    /// Fails when the catalog query fails.
    pub async fn reload_catalog(&self, config: &Config) -> Result<(), StoreError> {
        let entries = self.store.list_catalog_entries().await?;
        let state = catalog_state(config, config.gateway.idle_timeout_secs, entries);
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
        let evicted = self.insert(user, built.clone());
        for slot in &evicted {
            stop_slot(slot).await;
        }
        built
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

    /// The cached entry (bumping its last use)
    fn cached(&self, user: Uuid) -> Cached {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = slots.get_mut(&user) else {
            return Cached::Missing;
        };
        entry.last_used = Instant::now();
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
    /// until the instance cap holds again; returns the evicted ones to stop.
    fn insert(&self, user: Uuid, slot: Option<Arc<UserSlot>>) -> Vec<Arc<UserSlot>> {
        let max = usize::try_from(self.config.max_instances).unwrap_or(usize::MAX);
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.insert(
            user,
            SlotEntry {
                slot,
                last_used: Instant::now(),
            },
        );

        let mut evicted = Vec::new();
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
    async fn build(&self, user: Uuid) -> Result<Option<Arc<UserSlot>>, StoreError> {
        let (items, taken) = {
            let state = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
            (state.items.clone(), state.taken_names())
        };
        let credentials = self.store.list_user_credentials(user).await?;
        let personal = self.store.list_personal_backends(user).await?;

        let mut specs = Vec::new();
        for item in items.iter().filter(|item| item.enabled) {
            let Some(credential) = credentials.iter().find(|c| c.backend == item.name) else {
                continue;
            };
            if let Some(spec) = self.catalog_spec(user, item, credential).await {
                specs.push(spec);
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
            return Ok(None);
        }

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

        Ok(Some(Arc::new(UserSlot {
            registry,
            backends: Arc::new(backends),
            kinds,
        })))
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
        let config = BackendConfig {
            name: item.name.clone(),
            url: Some(item.url.clone()),
            transport: TransportType::Http,
            headers: credential_headers(&item.credential_fields, &values),
            timeout_secs: item.timeout_secs,
            ..BackendConfig::default()
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
        Some(Spec {
            config,
            options: BackendOptions {
                idle_timeout: item.idle_timeout,
                egress: None,
                passive_health: true,
                on_outcome: Some(hook),
            },
            kind: UserBackendKind::Catalog,
        })
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
        items: merge_catalog(&config.backends, gateway_idle_secs, entries),
        shared,
    }
}

/// The `per_user` config backends and the database's entries, by name; the
/// config wins when both define a name
fn merge_catalog(
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
        items.push(CatalogItem {
            name: entry.name,
            description: entry.description,
            url: entry.url,
            credential_fields: entry.credential_fields,
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
    use crate::config::CredentialMode;

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
        }
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
        let items = merge_catalog(&backends, 300, entries);

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
}
