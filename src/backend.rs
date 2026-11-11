//! Backend Actor - Manages connection to a single MCP server
//!
//! Each backend server gets its own actor that:
//! - Maintains the connection (reconnects on failure with exponential backoff)
//! - Fetches tool, resource, and prompt lists on connect
//! - Forwards tool calls, resource reads, and prompt gets
//! - Performs periodic health checks (or none, when health is passive)
//! - Closes the connection after an idle timeout and reconnects on the next request
//! - Implements circuit breaker pattern for failing backends

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::error::BoxError;
use futures::StreamExt;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::message::{Context, Message};
use kameo::reply::DelegatedReply;
use rmcp::ServiceExt;
use rmcp::handler::client::ClientHandler;
use rmcp::handler::client::progress::{ProgressDispatcher, ProgressSubscriber};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, CancelledNotificationParam,
    ClientCapabilities, ClientConfig, ClientRequest, GetPromptRequestParams, Implementation,
    ProgressNotificationParam, ReadResourceRequestParams, RequestId, RequestParamsMeta,
    ServerResult,
};
use rmcp::service::{
    NotificationContext, Peer, PeerRequestOptions, RoleClient, RunningService, ServiceError,
};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::config::{BackendConfig, TransportType};
use crate::egress::EgressPolicy;
use crate::registry::{RegistryActor, UpdateBackend};
use crate::relay::CallRelay;
use crate::telemetry::TraceContext;
use crate::types::{BackendState, PromptDefinition, ResourceDefinition, ToolDefinition};

/// Maximum backoff duration for reconnection attempts
const MAX_BACKOFF_SECS: u64 = 300; // 5 minutes

/// Base backoff duration for reconnection attempts
const BASE_BACKOFF_SECS: u64 = 1;

/// Maximum number of requests in flight to one backend at a time
const MAX_INFLIGHT_CALLS_PER_BACKEND: usize = 32;

/// Called after every connect attempt: `None` when it succeeded, otherwise the error
pub type OutcomeHook = Arc<dyn Fn(Option<String>) + Send + Sync>;

/// How a backend actor differs from the plain always-connected shared backend
#[derive(Clone, Default)]
pub struct BackendOptions {
    /// Close the connection after this long without requests; `None` keeps it open
    pub idle_timeout: Option<Duration>,
    /// Check every connect against this policy and pin the connection to the checked address
    pub egress: Option<Arc<EgressPolicy>>,
    /// No periodic health check and no background reconnect: the next request retries
    pub passive_health: bool,
    /// Told the outcome of every connect attempt
    pub on_outcome: Option<OutcomeHook>,
}

impl std::fmt::Debug for BackendOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendOptions")
            .field("idle_timeout", &self.idle_timeout)
            .field("egress", &self.egress)
            .field("passive_health", &self.passive_health)
            .field("on_outcome", &self.on_outcome.as_ref().map(|_| "<hook>"))
            .finish()
    }
}

/// How long ago the backend was last used and how many requests are in flight,
/// for the idle timeout. Shared with the request tasks.
struct Activity {
    epoch: Instant,
    /// Milliseconds after `epoch` of the last request start or finish
    last_ms: AtomicU64,
    active: AtomicUsize,
}

impl Activity {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_ms: AtomicU64::new(0),
            active: AtomicUsize::new(0),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Note that the backend was just used
    fn touch(&self) {
        self.last_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = self.last_ms.load(Ordering::Relaxed);
        Duration::from_millis(self.elapsed_ms().saturating_sub(last))
    }

    fn is_busy(&self) -> bool {
        self.active.load(Ordering::Relaxed) > 0
    }

    /// Count a request as in flight until the returned guard is dropped
    fn begin(self: &Arc<Self>) -> ActiveCall {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.touch();
        ActiveCall(Arc::clone(self))
    }
}

/// A request in flight, for the idle timeout
struct ActiveCall(Arc<Activity>);

impl Drop for ActiveCall {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

/// How often the idle timeout is checked at most
const MAX_IDLE_CHECK_PERIOD: Duration = Duration::from_secs(30);

/// Timeout of the health check ping
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Reply of the request handlers, sent from the task that runs the request
type CallReply = DelegatedReply<Result<serde_json::Value, String>>;

/// Error message prefixes of a request kind
#[derive(Clone, Copy)]
struct CallLabels {
    failed: &'static str,
    timed_out: &'static str,
    serialize_failed: &'static str,
}

/// Wrapper enum for different MCP client types
///
/// Each transport type produces a different `RunningService` type, so we wrap them
/// in an enum to store in the actor.
enum McpClient {
    /// Client connected via streamable HTTP (used for both SSE and HTTP transports)
    Http(RunningService<RoleClient, BackendClient>),
    /// Client connected via child process stdio
    Stdio(RunningService<RoleClient, BackendClient>),
}

/// The client side of a backend connection
///
/// Routes the backend's progress notifications to the calls waiting on them and
/// refreshes the tool list when the backend announces a change.
#[derive(Clone)]
struct BackendClient {
    backend: String,
    progress: ProgressDispatcher,
    /// The backend actor, for the tool refresh; `None` before it has started
    actor: Option<WeakActorRef<BackendActor>>,
}

impl ClientHandler for BackendClient {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("axon-gateway", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress.handle_notification(params).await;
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let Some(actor_ref) = self.actor.as_ref().and_then(WeakActorRef::upgrade) else {
            return;
        };
        let backend = self.backend.clone();
        tracing::debug!("Backend '{backend}' announced a tool list change");

        // Spawned so this connection's message loop stays free: the refresh lists
        // tools over this very connection.
        tokio::spawn(async move {
            if let Err(e) = actor_ref.ask(RefreshTools).await {
                tracing::debug!("Tool refresh for backend '{backend}' failed: {e}");
            }
        });
    }
}

/// Why a request failed, as far as the circuit breaker is concerned
trait CallFault {
    /// The client cancelled the call; the backend is not at fault
    fn is_cancelled(&self) -> bool {
        false
    }
}

impl CallFault for ServiceError {}

/// Failure of a relayed tool call
#[derive(Debug)]
enum RelayError {
    /// The client cancelled the call
    Cancelled,
    /// The backend or the connection failed it
    Failed(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled by the client"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl CallFault for RelayError {
    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

/// Sends `notifications/cancelled` for a request when dropped while armed, so a
/// call that is abandoned (the backend timeout, a dropped task) does not keep
/// running on the backend
struct AbandonedCall {
    peer: Peer<RoleClient>,
    id: Option<RequestId>,
}

impl AbandonedCall {
    fn disarm(&mut self) {
        self.id.take();
    }
}

impl Drop for AbandonedCall {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let peer = self.peer.clone();
        tokio::spawn(async move {
            let param = CancelledNotificationParam::new(Some(id), Some("timed out".to_string()));
            let _ = peer.notify_cancelled(param).await;
        });
    }
}

/// The next progress notification of `subscriber`; never resolves without one
async fn next_progress(subscriber: &mut Option<ProgressSubscriber>) -> ProgressNotificationParam {
    if let Some(subscriber) = subscriber
        && let Some(notification) = subscriber.next().await
    {
        return notification;
    }
    std::future::pending().await
}

/// Put the gateway's trace context into the `_meta` of a request to a backend
/// (`traceparent`, and `tracestate` when there is one), so the backend's spans
/// join the gateway's trace. The gateway's context replaces one already in
/// `_meta`, the gateway's span being the child of the client's; the rest of
/// `_meta` is left alone.
fn inject_trace_context(params: &mut impl RequestParamsMeta, trace: Option<&TraceContext>) {
    let Some(trace) = trace else {
        return;
    };
    let meta = &mut params.meta_or_default().0;
    meta.set_traceparent(trace.traceparent.as_str());
    match &trace.tracestate {
        Some(state) => meta.set_tracestate(state.as_str()),
        None => {
            meta.0.remove("tracestate");
        }
    }
}

/// Call a tool on `peer` on behalf of a client: forward the backend's progress
/// to the relay and cancel the backend request when the client cancels.
async fn call_tool_relayed(
    peer: Peer<RoleClient>,
    dispatcher: ProgressDispatcher,
    params: CallToolRequestParams,
    relay: CallRelay,
) -> Result<CallToolResult, RelayError> {
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params));
    let mut handle = peer
        .send_cancellable_request(request, PeerRequestOptions::no_options())
        .await
        .map_err(|e| RelayError::Failed(e.to_string()))?;
    let mut abandoned = AbandonedCall {
        peer: peer.clone(),
        id: Some(handle.id.clone()),
    };

    // Dropping the subscriber unsubscribes it
    let mut subscriber = if relay.progress.is_some() {
        Some(dispatcher.subscribe(handle.progress_token.clone()).await)
    } else {
        None
    };

    let response = loop {
        tokio::select! {
            response = &mut handle.rx => break Some(response),
            () = relay.cancel.cancelled() => break None,
            notification = next_progress(&mut subscriber) => {
                if let Some(progress) = &relay.progress {
                    // Progress is advisory: drop it when the client is behind
                    let _ = progress.try_send(notification);
                }
            }
        }
    };
    drop(subscriber);
    abandoned.disarm();

    let failed = |e: ServiceError| RelayError::Failed(e.to_string());
    match response {
        Some(Ok(Ok(ServerResult::CallToolResult(result)))) => Ok(result),
        Some(Ok(Ok(_))) => Err(failed(ServiceError::UnexpectedResponse)),
        Some(Ok(Err(e))) => Err(failed(e)),
        Some(Err(_)) => Err(failed(ServiceError::TransportClosed)),
        None => {
            let _ = handle
                .cancel(Some("cancelled by the client".to_string()))
                .await;
            Err(RelayError::Cancelled)
        }
    }
}

impl McpClient {
    /// Get a reference to the peer for making requests
    fn peer(&self) -> &Peer<RoleClient> {
        match self {
            Self::Http(service) | Self::Stdio(service) => service.peer(),
        }
    }

    /// Cancel the client connection gracefully
    async fn cancel(self) {
        match self {
            Self::Http(service) | Self::Stdio(service) => {
                let _ = service.cancel().await;
            }
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone)]
struct CircuitBreaker {
    /// Number of consecutive failures
    consecutive_failures: u32,
    /// Maximum failures before opening the circuit
    max_failures: u32,
    /// When the circuit was opened (if open)
    opened_at: Option<Instant>,
    /// Cooldown period before attempting to close the circuit
    cooldown: Duration,
}

impl CircuitBreaker {
    fn new(max_failures: u32, cooldown_secs: u64) -> Self {
        Self {
            consecutive_failures: 0,
            max_failures,
            opened_at: None,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Record a successful call, resetting the failure count
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.opened_at = None;
    }

    /// Record a failed call, potentially opening the circuit
    fn record_failure(&mut self) -> bool {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.max_failures && self.opened_at.is_none() {
            self.opened_at = Some(Instant::now());
            true // Circuit just opened
        } else {
            false
        }
    }

    /// Check if the circuit is open
    fn is_open(&self) -> bool {
        self.opened_at.is_some()
    }

    /// Check if we should attempt to close the circuit (half-open state)
    fn should_attempt_close(&self) -> bool {
        if let Some(opened_at) = self.opened_at {
            opened_at.elapsed() >= self.cooldown
        } else {
            false
        }
    }

    /// Reset the circuit breaker
    fn reset(&mut self) {
        self.consecutive_failures = 0;
        self.opened_at = None;
    }
}

/// The streamable HTTP transport for `url`: through a client pinned to the
/// address the egress policy allowed, when there is a policy
pub(crate) async fn http_transport(
    url: &str,
    config: StreamableHttpClientTransportConfig,
    egress: Option<&EgressPolicy>,
    connect_timeout: Duration,
) -> Result<StreamableHttpClientTransport<reqwest::Client>, String> {
    let Some(egress) = egress else {
        return Ok(StreamableHttpClientTransport::from_config(config));
    };
    let target = egress
        .check_url(url)
        .await
        .map_err(|e| format!("egress refused: {e}"))?;
    let client = target
        .client(connect_timeout)
        .map_err(|e| format!("egress refused: {e}"))?;
    Ok(StreamableHttpClientTransport::with_client(client, config))
}

/// Actor managing a single backend MCP server connection
pub struct BackendActor {
    config: BackendConfig,
    registry: ActorRef<RegistryActor>,
    state: BackendState,
    client: Option<McpClient>,
    /// Current reconnection attempt count (for exponential backoff)
    reconnect_attempts: u32,
    /// Circuit breaker for handling repeated failures
    circuit_breaker: CircuitBreaker,
    /// Weak reference to self for scheduling delayed messages
    self_ref: Option<WeakActorRef<Self>>,
    /// Cancellation token for spawned background tasks
    cancel_token: CancellationToken,
    /// Limits the requests in flight to this backend
    inflight: Arc<Semaphore>,
    /// Routes the backend's progress notifications to the calls waiting on them
    progress: ProgressDispatcher,
    options: BackendOptions,
    /// Last use and requests in flight, for the idle timeout
    activity: Arc<Activity>,
    /// Whether a health check is already scheduled, so a reconnect adds no second chain
    health_check_scheduled: bool,
}

impl BackendActor {
    pub fn with_options(
        config: BackendConfig,
        registry: ActorRef<RegistryActor>,
        options: BackendOptions,
    ) -> Self {
        let circuit_breaker = CircuitBreaker::new(
            config.max_consecutive_failures,
            config.circuit_breaker_cooldown_secs,
        );
        Self {
            config,
            registry,
            state: BackendState::Disconnected,
            client: None,
            reconnect_attempts: 0,
            circuit_breaker,
            self_ref: None,
            cancel_token: CancellationToken::new(),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_CALLS_PER_BACKEND)),
            progress: ProgressDispatcher::new(),
            options,
            activity: Arc::new(Activity::new()),
            health_check_scheduled: false,
        }
    }

    /// The client handler for a new connection to the backend; a `probe` connection
    /// is not the actor's, so it does not refresh the tools
    fn client_handler(&self, probe: bool) -> BackendClient {
        BackendClient {
            backend: self.config.name.clone(),
            progress: self.progress.clone(),
            actor: if probe { None } else { self.self_ref.clone() },
        }
    }

    /// Connect to the backend MCP server and report the outcome
    async fn connect(&mut self) -> Result<(), BoxError> {
        let result = self.try_connect().await;
        crate::metrics::record_backend_up(&self.config.name, result.is_ok());
        if let Some(hook) = &self.options.on_outcome {
            hook(result.as_ref().err().map(ToString::to_string));
        }
        result
    }

    /// Open a connection to the backend MCP server
    async fn open_client(&self, probe: bool) -> Result<McpClient, BoxError> {
        let client = match self.config.transport {
            TransportType::Sse | TransportType::Http => {
                let url = self.config.url.as_ref().ok_or("Missing URL for backend")?;
                tracing::info!(
                    "Connecting via streamable HTTP to: {} (transport: {:?})",
                    url,
                    self.config.transport
                );

                let connect_timeout = Duration::from_secs(self.config.timeout_secs);

                // Build transport config with optional auth and custom headers
                let mut transport_config =
                    StreamableHttpClientTransportConfig::with_uri(url.as_str());
                if let Some(token) = &self.config.auth_token {
                    transport_config = transport_config.auth_header(token.clone());
                }
                if !self.config.headers.is_empty() {
                    let custom_headers = self
                        .config
                        .headers
                        .iter()
                        .filter_map(|(k, v)| {
                            let name = k.parse::<http::HeaderName>().ok()?;
                            let value = http::HeaderValue::from_str(v).ok()?;
                            Some((name, value))
                        })
                        .collect();
                    transport_config = transport_config.custom_headers(custom_headers);
                }
                let transport = http_transport(
                    url,
                    transport_config,
                    self.options.egress.as_deref(),
                    connect_timeout,
                )
                .await?;

                let service = timeout(connect_timeout, self.client_handler(probe).serve(transport))
                    .await
                    .map_err(|_| format!("Connection timeout after {}s", self.config.timeout_secs))?
                    .map_err(|e| format!("Failed to connect to {url}: {e}"))?;

                tracing::info!(
                    "Connected to backend '{}', server info: {:?}",
                    self.config.name,
                    service.peer().peer_info()
                );

                McpClient::Http(service)
            }
            TransportType::Stdio => {
                let cmd = self
                    .config
                    .command
                    .as_ref()
                    .ok_or("Missing command for stdio backend")?;
                let args = self.config.args.as_deref().unwrap_or(&[]);

                tracing::info!("Spawning stdio process: {} {:?}", cmd, args);

                let mut command = Command::new(cmd);
                command.args(args);

                // Set environment variables for stdio backends
                for (key, value) in &self.config.env {
                    command.env(key, value);
                }

                let transport = TokioChildProcess::new(command)
                    .map_err(|e| format!("Failed to spawn process {cmd}: {e}"))?;

                let connect_timeout = Duration::from_secs(self.config.timeout_secs);
                let service = timeout(connect_timeout, self.client_handler(probe).serve(transport))
                    .await
                    .map_err(|_| {
                        format!(
                            "Stdio initialization timeout after {}s",
                            self.config.timeout_secs
                        )
                    })?
                    .map_err(|e| format!("Failed to initialize MCP client for {cmd}: {e}"))?;

                tracing::info!(
                    "Connected to stdio backend '{}', server info: {:?}",
                    self.config.name,
                    service.peer().peer_info()
                );

                McpClient::Stdio(service)
            }
        };

        Ok(client)
    }

    /// Connect to the backend MCP server and publish its tools
    async fn try_connect(&mut self) -> Result<(), BoxError> {
        self.state = BackendState::Connecting;
        tracing::info!("Connecting to backend: {}", self.config.name);

        let client = self.open_client(false).await?;

        self.client = Some(client);
        self.activity.touch();
        self.state = BackendState::Connected;
        self.reconnect_attempts = 0;
        self.circuit_breaker.reset();

        // Record connected state in metrics
        crate::metrics::record_backend_state(&self.config.name, "connected");

        // Fetch tools from backend
        let tools = self.fetch_tools().await?;

        // Update registry
        self.registry
            .tell(UpdateBackend {
                name: self.config.name.clone(),
                state: BackendState::Connected,
                tools,
                error: None,
            })
            .await
            .map_err(|e| Box::new(e) as BoxError)?;

        // Schedule periodic health checks if configured
        self.schedule_health_check();

        Ok(())
    }

    /// Fetch tool list from the backend with timeout
    async fn fetch_tools(&self) -> Result<Vec<ToolDefinition>, BoxError> {
        let client = self
            .client
            .as_ref()
            .ok_or("No client connection available")?;

        let fetch_timeout = Duration::from_secs(self.config.timeout_secs);
        let tools = timeout(fetch_timeout, client.peer().list_all_tools())
            .await
            .map_err(|_| {
                format!(
                    "Tool list fetch timeout after {}s",
                    self.config.timeout_secs
                )
            })?
            .map_err(|e| format!("Failed to list tools: {e}"))?;

        let tool_defs: Vec<ToolDefinition> = tools.into_iter().map(ToolDefinition::from).collect();

        // Apply tool filtering if allowed_tools is configured
        let filtered_tools = self.filter_tools(tool_defs);

        tracing::info!(
            "Backend '{}' provides {} tools (after filtering)",
            self.config.name,
            filtered_tools.len()
        );

        for tool in &filtered_tools {
            tracing::debug!("  - {}: {:?}", tool.name, tool.description);
        }

        Ok(filtered_tools)
    }

    /// Filter tools based on `allowed_tools` configuration
    fn filter_tools(&self, tools: Vec<ToolDefinition>) -> Vec<ToolDefinition> {
        if self.config.allowed_tools.is_empty() {
            // No filtering - expose all tools
            return tools;
        }

        let allowed: std::collections::HashSet<&str> = self
            .config
            .allowed_tools
            .iter()
            .map(String::as_str)
            .collect();

        let (filtered, excluded): (Vec<_>, Vec<_>) = tools
            .into_iter()
            .partition(|t| allowed.contains(t.name.as_str()));

        if !excluded.is_empty() {
            tracing::debug!(
                "Backend '{}' filtered out {} tools: {:?}",
                self.config.name,
                excluded.len(),
                excluded.iter().map(|t| &t.name).collect::<Vec<_>>()
            );
        }

        filtered
    }

    /// Fetch resource list from the backend with timeout
    async fn fetch_resources(&self) -> Result<Vec<ResourceDefinition>, BoxError> {
        let client = self
            .client
            .as_ref()
            .ok_or("No client connection available")?;

        let fetch_timeout = Duration::from_secs(self.config.timeout_secs);
        let resources = timeout(fetch_timeout, client.peer().list_all_resources())
            .await
            .map_err(|_| {
                format!(
                    "Resource list fetch timeout after {}s",
                    self.config.timeout_secs
                )
            })?
            .map_err(|e| format!("Failed to list resources: {e}"))?;

        let resource_defs: Vec<ResourceDefinition> = resources
            .into_iter()
            .map(ResourceDefinition::from)
            .collect();

        tracing::info!(
            "Backend '{}' provides {} resources",
            self.config.name,
            resource_defs.len()
        );

        for resource in &resource_defs {
            tracing::debug!("  - {}: {:?}", resource.uri, resource.name);
        }

        Ok(resource_defs)
    }

    /// Fetch prompt list from the backend with timeout
    async fn fetch_prompts(&self) -> Result<Vec<PromptDefinition>, BoxError> {
        let client = self
            .client
            .as_ref()
            .ok_or("No client connection available")?;

        let fetch_timeout = Duration::from_secs(self.config.timeout_secs);
        let prompts = timeout(fetch_timeout, client.peer().list_all_prompts())
            .await
            .map_err(|_| {
                format!(
                    "Prompt list fetch timeout after {}s",
                    self.config.timeout_secs
                )
            })?
            .map_err(|e| format!("Failed to list prompts: {e}"))?;

        let prompt_defs: Vec<PromptDefinition> =
            prompts.into_iter().map(PromptDefinition::from).collect();

        tracing::info!(
            "Backend '{}' provides {} prompts",
            self.config.name,
            prompt_defs.len()
        );

        for prompt in &prompt_defs {
            tracing::debug!("  - {}: {:?}", prompt.name, prompt.description);
        }

        Ok(prompt_defs)
    }

    /// Check the state and circuit breaker for a new request and return the peer to send it on.
    ///
    /// A half-open circuit lets one request through as a probe, as before.
    fn admit_call(&self) -> Result<Peer<RoleClient>, String> {
        self.check_state()?;

        self.client
            .as_ref()
            .map(|client| client.peer().clone())
            .ok_or_else(|| "No client connection available".to_string())
    }

    /// The state and circuit breaker part of [`Self::admit_call`]; an idle backend is
    /// admitted, as the request wakes it first
    fn check_state(&self) -> Result<(), String> {
        match self.state {
            BackendState::Connected | BackendState::CircuitOpen | BackendState::Idle => {}
            BackendState::Reconnecting => {
                return Err(format!(
                    "Backend '{}' is reconnecting (attempt {})",
                    self.config.name, self.reconnect_attempts
                ));
            }
            _ => return Err(format!("Backend '{}' is not connected", self.config.name)),
        }

        if self.circuit_breaker.is_open() {
            if self.circuit_breaker.should_attempt_close() {
                tracing::info!(
                    "Backend '{}' circuit breaker attempting half-open state",
                    self.config.name
                );
            } else {
                return Err(format!(
                    "Backend '{}' circuit breaker is open",
                    self.config.name
                ));
            }
        } else if self.state == BackendState::CircuitOpen {
            return Err(format!(
                "Backend '{}' circuit breaker is open",
                self.config.name
            ));
        }

        Ok(())
    }

    /// Connect before a request when the backend is idle, or failed and probed only by
    /// requests (passive health). One actor message at a time, so concurrent requests
    /// during the wake wait here and share the connection.
    async fn wake(&mut self) -> Result<(), String> {
        let from_idle = self.state == BackendState::Idle;
        let wakeable = match self.state {
            BackendState::Idle => true,
            BackendState::Disconnected | BackendState::Failed | BackendState::CircuitOpen => {
                self.options.passive_health
            }
            _ => false,
        };
        if !wakeable {
            return Ok(());
        }

        if self.circuit_breaker.is_open() {
            if !self.circuit_breaker.should_attempt_close() {
                return Err(format!(
                    "Backend '{}' circuit breaker is open",
                    self.config.name
                ));
            }
            self.circuit_breaker.reset();
        }

        tracing::debug!("Backend '{}' connecting for a request", self.config.name);
        // Drops a stale connection
        self.disconnect().await;

        let Err(e) = self.connect().await else {
            return Ok(());
        };
        let error_msg = format!("Backend '{}' failed to connect: {e}", self.config.name);

        self.disconnect().await;
        if from_idle {
            // The tools stay cached; the next request tries again
            self.state = BackendState::Idle;
            crate::metrics::record_backend_state(&self.config.name, "idle");
        } else {
            self.state = BackendState::Failed;
            crate::metrics::record_backend_state(&self.config.name, "failed");
        }
        self.handle_call_failure(&error_msg).await;
        Err(error_msg)
    }

    /// Run a request against the backend in a spawned task, so the actor stays free to handle
    /// other messages (including more requests) while it is in flight.
    ///
    /// A backend that needs to connect first does so here, then the state and circuit breaker
    /// checks run. The task waits for a permit, runs `request` under the backend timeout,
    /// sends the reply and then reports the outcome back to the actor, which owns the circuit
    /// breaker.
    async fn spawn_call<T, E, Fut>(
        &mut self,
        ctx: &mut Context<Self, CallReply>,
        labels: CallLabels,
        request: impl FnOnce(Peer<RoleClient>) -> Fut + Send + 'static,
    ) -> CallReply
    where
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        T: serde::Serialize + Send,
        E: std::fmt::Display + CallFault + Send,
    {
        let (delegated, reply_tx) = ctx.reply_sender();

        let peer = match self.wake().await.and_then(|()| self.admit_call()) {
            Ok(peer) => peer,
            Err(e) => {
                if let Some(reply_tx) = reply_tx {
                    reply_tx.send(Err(e));
                }
                return delegated;
            }
        };
        let active = self.activity.begin();

        let backend = self.config.name.clone();
        let timeout_secs = self.config.timeout_secs;
        let semaphore = Arc::clone(&self.inflight);
        let self_ref = self.self_ref.clone();

        tokio::spawn(async move {
            let _active = active;
            let Ok(_permit) = semaphore.acquire().await else {
                if let Some(reply_tx) = reply_tx {
                    reply_tx.send(Err(format!("Backend '{backend}' call limiter is closed")));
                }
                return;
            };
            let _inflight = crate::metrics::InflightCallGuard::new(&backend);

            let result = timeout(Duration::from_secs(timeout_secs), request(peer)).await;

            // The outcome is what the actor counts against the circuit breaker: `Some(None)`
            // a success, `Some(Some(error))` a failure, `None` nothing (a client cancellation
            // says nothing about the backend). A result that cannot be serialized still
            // reached the backend, so it counts as a success.
            let (reply, outcome) = match result {
                Ok(Ok(value)) => (
                    serde_json::to_value(&value)
                        .map_err(|e| format!("{}: {e}", labels.serialize_failed)),
                    Some(None),
                ),
                Ok(Err(e)) if e.is_cancelled() => (Err(e.to_string()), None),
                Ok(Err(e)) => {
                    let error_msg = format!("{}: {e}", labels.failed);
                    (Err(error_msg.clone()), Some(Some(error_msg)))
                }
                Err(_) => {
                    let error_msg = format!("{} after {timeout_secs}s", labels.timed_out);
                    (Err(error_msg.clone()), Some(Some(error_msg)))
                }
            };

            if let Some(reply_tx) = reply_tx {
                reply_tx.send(reply);
            }

            if let Some(error) = outcome
                && let Some(actor_ref) = self_ref.and_then(|weak| weak.upgrade())
            {
                let _ = actor_ref.tell(CallOutcome { error }).await;
            }
        });

        delegated
    }

    /// Handle a call failure, potentially triggering reconnect or circuit breaker
    async fn handle_call_failure(&mut self, error_msg: &str) {
        tracing::warn!("Backend '{}' call failed: {}", self.config.name, error_msg);

        let circuit_opened = self.circuit_breaker.record_failure();
        if circuit_opened {
            tracing::warn!(
                "Backend '{}' circuit breaker opened after {} consecutive failures",
                self.config.name,
                self.circuit_breaker.consecutive_failures
            );
            self.state = BackendState::CircuitOpen;
            crate::metrics::record_backend_state(&self.config.name, "circuit_open");

            // Update registry with circuit open state
            let _ = self
                .registry
                .tell(UpdateBackend {
                    name: self.config.name.clone(),
                    state: BackendState::CircuitOpen,
                    tools: vec![],
                    error: Some(format!("Circuit breaker open: {error_msg}")),
                })
                .await;

            // Schedule reconnect after cooldown
            self.schedule_reconnect_with_cooldown();
        }
    }

    /// Disconnect from the backend
    async fn disconnect(&mut self) {
        if let Some(client) = self.client.take() {
            tracing::info!("Disconnecting from backend: {}", self.config.name);
            client.cancel().await;
        }
        self.state = BackendState::Disconnected;
    }

    /// Calculate exponential backoff duration
    fn calculate_backoff(&self) -> Duration {
        let backoff_secs =
            BASE_BACKOFF_SECS.saturating_mul(2u64.saturating_pow(self.reconnect_attempts));
        Duration::from_secs(backoff_secs.min(MAX_BACKOFF_SECS))
    }

    /// Schedule a reconnection attempt with exponential backoff
    async fn schedule_reconnect(&mut self) {
        if self.options.passive_health {
            return; // The next request reconnects
        }

        if let Some(self_ref) = &self.self_ref
            && let Some(actor_ref) = self_ref.upgrade()
        {
            let backoff = self.calculate_backoff();
            self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
            self.state = BackendState::Reconnecting;
            crate::metrics::record_backend_state(&self.config.name, "reconnecting");

            tracing::info!(
                "Backend '{}' scheduling reconnect in {:?} (attempt {})",
                self.config.name,
                backoff,
                self.reconnect_attempts
            );

            // Update registry with reconnecting state
            let _ = self
                .registry
                .tell(UpdateBackend {
                    name: self.config.name.clone(),
                    state: BackendState::Reconnecting,
                    tools: vec![],
                    error: Some(format!(
                        "Reconnecting (attempt {})",
                        self.reconnect_attempts
                    )),
                })
                .await;

            let name = self.config.name.clone();
            let token = self.cancel_token.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = token.cancelled() => {
                        tracing::debug!("Reconnect task cancelled for '{}'", name);
                    }
                    () = tokio::time::sleep(backoff) => {
                        if let Err(e) = actor_ref.tell(Reconnect).await {
                            tracing::debug!("Failed to send reconnect message to '{}': {}", name, e);
                        }
                    }
                }
            });
        }
    }

    /// Schedule a reconnection attempt after circuit breaker cooldown
    fn schedule_reconnect_with_cooldown(&mut self) {
        if self.options.passive_health {
            return; // The first request after the cooldown reconnects
        }

        if let Some(self_ref) = &self.self_ref
            && let Some(actor_ref) = self_ref.upgrade()
        {
            let cooldown = Duration::from_secs(self.config.circuit_breaker_cooldown_secs);

            tracing::info!(
                "Backend '{}' scheduling reconnect after circuit breaker cooldown ({:?})",
                self.config.name,
                cooldown
            );

            let name = self.config.name.clone();
            let token = self.cancel_token.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = token.cancelled() => {
                        tracing::debug!("Circuit breaker reconnect task cancelled for '{}'", name);
                    }
                    () = tokio::time::sleep(cooldown) => {
                        if let Err(e) = actor_ref.tell(Reconnect).await {
                            tracing::debug!("Failed to send reconnect message to '{}': {}", name, e);
                        }
                    }
                }
            });
        }
    }

    /// Schedule periodic health check
    fn schedule_health_check(&mut self) {
        if self.config.health_check_interval_secs == 0 || self.options.passive_health {
            return; // Health checks disabled
        }
        if self.health_check_scheduled {
            return; // The chain of checks is still running
        }

        if let Some(self_ref) = &self.self_ref
            && let Some(actor_ref) = self_ref.upgrade()
        {
            let interval = Duration::from_secs(self.config.health_check_interval_secs);
            let name = self.config.name.clone();
            let token = self.cancel_token.clone();
            self.health_check_scheduled = true;

            tokio::spawn(async move {
                tokio::select! {
                    () = token.cancelled() => {
                        tracing::debug!("Health check task cancelled for '{}'", name);
                    }
                    () = tokio::time::sleep(interval) => {
                        if let Err(e) = actor_ref.tell(PerformHealthCheck).await {
                            tracing::debug!("Failed to send health check message to '{}': {}", name, e);
                        }
                    }
                }
            });
        }
    }

    /// Check the idle timeout periodically
    fn schedule_idle_checks(&self) {
        let Some(idle_timeout) = self.options.idle_timeout else {
            return;
        };
        let Some(self_ref) = self.self_ref.clone() else {
            return;
        };

        let period = idle_timeout
            .min(MAX_IDLE_CHECK_PERIOD)
            .max(Duration::from_secs(1));
        let name = self.config.name.clone();
        let token = self.cancel_token.clone();

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // The first tick is immediate
            loop {
                tokio::select! {
                    () = token.cancelled() => {
                        tracing::debug!("Idle check task cancelled for '{}'", name);
                        break;
                    }
                    _ = ticker.tick() => {
                        // A weak reference, so this task does not keep the actor alive
                        let Some(actor_ref) = self_ref.upgrade() else {
                            break;
                        };
                        if actor_ref.tell(IdleCheck).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Check an idle backend with a short-lived connection of its own
    async fn probe_idle(&self) -> Result<(), String> {
        let client = self
            .open_client(true)
            .await
            .map_err(|e| format!("Health check failed: {e}"))?;

        let result = timeout(HEALTH_CHECK_TIMEOUT, client.peer().list_tools(None)).await;
        client.cancel().await;

        match result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("Health check failed: {e}")),
            Err(_) => Err("Health check timeout".to_string()),
        }
    }

    /// Perform health check by pinging the backend
    async fn perform_health_check(&mut self) -> Result<(), String> {
        if self.state != BackendState::Connected {
            return Ok(()); // Only check connected backends
        }

        let Some(client) = &self.client else {
            return Err("No client connection".to_string());
        };

        // Try to ping by listing tools (lightweight operation)
        let result = timeout(HEALTH_CHECK_TIMEOUT, client.peer().list_tools(None)).await;
        crate::metrics::record_backend_up(&self.config.name, matches!(result, Ok(Ok(_))));

        match result {
            Ok(Ok(_)) => {
                tracing::debug!("Backend '{}' health check passed", self.config.name);
                crate::metrics::record_health_check(&self.config.name, true);
                Ok(())
            }
            Ok(Err(e)) => {
                let error_msg = format!("Health check failed: {e}");
                tracing::warn!("Backend '{}' {}", self.config.name, error_msg);
                crate::metrics::record_health_check(&self.config.name, false);
                Err(error_msg)
            }
            Err(_) => {
                let error_msg = "Health check timeout".to_string();
                tracing::warn!("Backend '{}' {}", self.config.name, error_msg);
                crate::metrics::record_health_check(&self.config.name, false);
                Err(error_msg)
            }
        }
    }
}

impl Actor for BackendActor {
    type Args = Self;
    type Error = BoxError;

    async fn on_start(mut state: Self, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        tracing::info!("Backend actor started: {}", state.config.name);

        state.self_ref = Some(actor_ref.downgrade());
        state.schedule_idle_checks();

        if let Err(e) = state.connect().await {
            tracing::error!("Failed to connect to {}: {}", state.config.name, e);
            state.state = BackendState::Failed;
            state
                .registry
                .tell(UpdateBackend {
                    name: state.config.name.clone(),
                    state: BackendState::Failed,
                    tools: vec![],
                    error: Some(e.to_string()),
                })
                .await
                .map_err(|e| Box::new(e) as BoxError)?;

            state.schedule_reconnect().await;
        }

        Ok(state)
    }

    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: kameo::error::ActorStopReason,
    ) -> Result<(), Self::Error> {
        tracing::info!("Backend actor stopping: {}", self.config.name);
        self.cancel_token.cancel();
        self.disconnect().await;
        Ok(())
    }
}

// --- Messages ---

/// Execute a tool call on this backend
#[derive(Clone)]
pub struct CallTool {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    /// The client's progress and cancellation; `None` for calls without a client
    pub relay: Option<CallRelay>,
    /// The caller's trace context, taken where the client's request is handled: the
    /// backend actor runs outside the caller's span
    pub trace: Option<TraceContext>,
}

impl Message<CallTool> for BackendActor {
    type Reply = CallReply;

    async fn handle(&mut self, msg: CallTool, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let backend = self.config.name.clone();
        let labels = CallLabels {
            failed: "Tool call failed",
            timed_out: "Tool call timeout",
            serialize_failed: "Failed to serialize tool result",
        };
        let dispatcher = self.progress.clone();
        self.spawn_call(ctx, labels, move |peer| {
            tracing::info!(
                "Backend '{}' executing tool '{}' with args: {}",
                backend,
                msg.tool_name,
                msg.arguments
            );

            // Convert arguments to JsonObject if it's an object, otherwise use empty
            let mut params = CallToolRequestParams::new(msg.tool_name);
            if let Some(args) = msg.arguments.as_object().cloned() {
                params = params.with_arguments(args);
            }
            inject_trace_context(&mut params, msg.trace.as_ref());

            async move {
                match msg.relay {
                    Some(relay) => call_tool_relayed(peer, dispatcher, params, relay).await,
                    None => peer
                        .call_tool(params)
                        .await
                        .map_err(|e| RelayError::Failed(e.to_string())),
                }
            }
        })
        .await
    }
}

/// Read a resource from this backend
#[derive(Clone)]
pub struct ReadResource {
    pub uri: String,
    /// The caller's trace context, see [`CallTool::trace`]
    pub trace: Option<TraceContext>,
}

impl Message<ReadResource> for BackendActor {
    type Reply = CallReply;

    async fn handle(
        &mut self,
        msg: ReadResource,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let backend = self.config.name.clone();
        let labels = CallLabels {
            failed: "Resource read failed",
            timed_out: "Resource read timeout",
            serialize_failed: "Failed to serialize resource result",
        };
        self.spawn_call(ctx, labels, move |peer| {
            tracing::info!("Backend '{}' reading resource '{}'", backend, msg.uri);

            let mut params = ReadResourceRequestParams::new(msg.uri);
            inject_trace_context(&mut params, msg.trace.as_ref());

            async move { peer.read_resource(params).await }
        })
        .await
    }
}

/// Get a prompt from this backend
#[derive(Clone)]
pub struct GetPrompt {
    pub name: String,
    pub arguments: Option<std::collections::HashMap<String, String>>,
    /// The caller's trace context, see [`CallTool::trace`]
    pub trace: Option<TraceContext>,
}

impl Message<GetPrompt> for BackendActor {
    type Reply = CallReply;

    async fn handle(
        &mut self,
        msg: GetPrompt,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let backend = self.config.name.clone();
        let labels = CallLabels {
            failed: "Prompt get failed",
            timed_out: "Prompt get timeout",
            serialize_failed: "Failed to serialize prompt result",
        };
        self.spawn_call(ctx, labels, move |peer| {
            tracing::info!(
                "Backend '{}' getting prompt '{}' with args: {:?}",
                backend,
                msg.name,
                msg.arguments
            );

            // Convert HashMap<String, String> to serde_json::Map<String, Value>
            let args_map = msg.arguments.map(|args| {
                args.into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect()
            });

            let mut params = GetPromptRequestParams::new(msg.name);
            if let Some(args) = args_map {
                params = params.with_arguments(args);
            }
            inject_trace_context(&mut params, msg.trace.as_ref());

            async move { peer.get_prompt(params).await }
        })
        .await
    }
}

/// Outcome of a spawned request, reported back so the actor can update its circuit breaker
pub struct CallOutcome {
    /// `None` when the request reached the backend, otherwise the error that failed it
    pub error: Option<String>,
}

impl Message<CallOutcome> for BackendActor {
    type Reply = ();

    async fn handle(&mut self, msg: CallOutcome, _ctx: &mut Context<Self, Self::Reply>) {
        match msg.error {
            None => self.circuit_breaker.record_success(),
            Some(error_msg) => self.handle_call_failure(&error_msg).await,
        }
    }
}

/// List resources from this backend
pub struct ListResources;

impl Message<ListResources> for BackendActor {
    type Reply = Result<Vec<ResourceDefinition>, String>;

    async fn handle(
        &mut self,
        _msg: ListResources,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.wake().await?;
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }
        self.activity.touch();

        self.fetch_resources()
            .await
            .map_err(|e| format!("Failed to fetch resources: {e}"))
    }
}

/// List prompts from this backend
pub struct ListPrompts;

impl Message<ListPrompts> for BackendActor {
    type Reply = Result<Vec<PromptDefinition>, String>;

    async fn handle(
        &mut self,
        _msg: ListPrompts,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.wake().await?;
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }
        self.activity.touch();

        self.fetch_prompts()
            .await
            .map_err(|e| format!("Failed to fetch prompts: {e}"))
    }
}

/// Trigger reconnection
pub struct Reconnect;

impl Message<Reconnect> for BackendActor {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: Reconnect,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Only reconnect if not already connected (an idle backend connects on demand)
        if matches!(self.state, BackendState::Connected | BackendState::Idle) {
            return;
        }

        // Disconnect existing (possibly broken) connection
        self.disconnect().await;

        // Reset circuit breaker if we're attempting reconnect after cooldown
        if self.circuit_breaker.should_attempt_close() {
            self.circuit_breaker.reset();
        }

        if let Err(e) = self.connect().await {
            tracing::warn!(
                "Reconnect failed for '{}' (attempt {}): {}",
                self.config.name,
                self.reconnect_attempts,
                e
            );

            self.state = BackendState::Failed;
            let _ = self
                .registry
                .tell(UpdateBackend {
                    name: self.config.name.clone(),
                    state: BackendState::Failed,
                    tools: vec![],
                    error: Some(e.to_string()),
                })
                .await;

            // Schedule another reconnect with exponential backoff
            self.schedule_reconnect().await;
        }
    }
}

/// Health check message
pub struct HealthCheck;

impl Message<HealthCheck> for BackendActor {
    type Reply = BackendState;

    async fn handle(
        &mut self,
        _msg: HealthCheck,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.state
    }
}

/// Perform a health check ping
pub struct PerformHealthCheck;

impl Message<PerformHealthCheck> for BackendActor {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: PerformHealthCheck,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.health_check_scheduled = false;

        // An idle backend is probed over a connection of its own and stays idle
        if self.state == BackendState::Idle {
            let result = self.probe_idle().await;
            crate::metrics::record_backend_up(&self.config.name, result.is_ok());
            crate::metrics::record_health_check(&self.config.name, result.is_ok());
            match result {
                Ok(()) => {
                    tracing::debug!("Idle backend '{}' health check passed", self.config.name);
                }
                Err(e) => tracing::warn!("Idle backend '{}' {}", self.config.name, e),
            }
            self.schedule_health_check();
            return;
        }

        if let Err(e) = self.perform_health_check().await {
            // Health check failed, trigger circuit breaker
            self.handle_call_failure(&e).await;

            // If still "connected" but failing health checks, start reconnect
            if self.state == BackendState::Connected {
                tracing::warn!(
                    "Backend '{}' failed health check, initiating reconnect",
                    self.config.name
                );
                self.disconnect().await;
                self.state = BackendState::Failed;
                self.schedule_reconnect().await;
            }
        }

        // Schedule next health check if still connected
        if self.state == BackendState::Connected {
            self.schedule_health_check();
        }
    }
}

/// Close the connection when the backend has been unused for the idle timeout
struct IdleCheck;

impl Message<IdleCheck> for BackendActor {
    type Reply = ();

    async fn handle(&mut self, _msg: IdleCheck, _ctx: &mut Context<Self, Self::Reply>) {
        let Some(idle_timeout) = self.options.idle_timeout else {
            return;
        };
        if self.state != BackendState::Connected
            || self.activity.is_busy()
            || self.activity.idle_for() < idle_timeout
        {
            return;
        }

        tracing::debug!(
            "Backend '{}' idle for {:?}, closing the connection",
            self.config.name,
            self.activity.idle_for()
        );
        if let Some(client) = self.client.take() {
            client.cancel().await;
        }
        // The registry keeps the tools; they are served while the backend sleeps
        self.state = BackendState::Idle;
        crate::metrics::record_backend_state(&self.config.name, "idle");
        if let Err(error) = self
            .registry
            .tell(crate::registry::MarkIdle {
                name: self.config.name.clone(),
            })
            .await
        {
            tracing::debug!("Failed to mark '{}' idle: {error}", self.config.name);
        }
    }
}

/// Refresh tool list from backend
pub struct RefreshTools;

impl Message<RefreshTools> for BackendActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        _msg: RefreshTools,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }

        let tools = self
            .fetch_tools()
            .await
            .map_err(|e| format!("Failed to refresh tools: {e}"))?;

        self.registry
            .tell(UpdateBackend {
                name: self.config.name.clone(),
                state: BackendState::Connected,
                tools,
                error: None,
            })
            .await
            .map_err(|e| format!("Failed to update registry: {e}"))?;

        Ok(())
    }
}

/// Get detailed backend info
pub struct GetBackendInfo;

#[derive(Debug, Clone, serde::Serialize, kameo::Reply)]
pub struct BackendInfoResponse {
    pub name: String,
    pub state: BackendState,
    pub reconnect_attempts: u32,
    pub circuit_breaker_open: bool,
    pub circuit_breaker_failures: u32,
}

impl Message<GetBackendInfo> for BackendActor {
    type Reply = BackendInfoResponse;

    async fn handle(
        &mut self,
        _msg: GetBackendInfo,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        BackendInfoResponse {
            name: self.config.name.clone(),
            state: self.state,
            reconnect_attempts: self.reconnect_attempts,
            circuit_breaker_open: self.circuit_breaker.is_open(),
            circuit_breaker_failures: self.circuit_breaker.consecutive_failures,
        }
    }
}

/// Force reconnect (for admin API)
pub struct ForceReconnect;

impl Message<ForceReconnect> for BackendActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        _msg: ForceReconnect,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        tracing::info!("Force reconnect requested for '{}'", self.config.name);

        // Reset state
        self.disconnect().await;
        self.reconnect_attempts = 0;
        self.circuit_breaker.reset();

        // Attempt connection
        self.connect()
            .await
            .map_err(|e| format!("Force reconnect failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendConfig;

    mod circuit_breaker {
        use super::*;
        use rstest::rstest;

        /// The circuit opens on exactly the Nth consecutive failure, for a
        /// range of configured thresholds.
        #[rstest]
        #[case(1)]
        #[case(2)]
        #[case(3)]
        #[case(5)]
        fn circuit_opens_on_configured_threshold(#[case] threshold: u32) {
            let mut cb = CircuitBreaker::new(threshold, 60);
            for _ in 1..threshold {
                assert!(!cb.record_failure(), "should stay closed below threshold");
                assert!(!cb.is_open());
            }
            assert!(cb.record_failure(), "the threshold-th failure opens it");
            assert!(cb.is_open());
        }

        #[test]
        fn new_circuit_breaker_is_closed() {
            let cb = CircuitBreaker::new(3, 60);
            assert!(!cb.is_open());
            assert_eq!(cb.consecutive_failures, 0);
        }

        #[test]
        fn record_success_resets_failures() {
            let mut cb = CircuitBreaker::new(3, 60);
            cb.consecutive_failures = 2;
            cb.record_success();
            assert_eq!(cb.consecutive_failures, 0);
            assert!(!cb.is_open());
        }

        #[test]
        fn record_failure_increments_count() {
            let mut cb = CircuitBreaker::new(3, 60);
            let opened = cb.record_failure();
            assert!(!opened);
            assert_eq!(cb.consecutive_failures, 1);
            assert!(!cb.is_open());
        }

        #[test]
        fn circuit_opens_after_max_failures() {
            let mut cb = CircuitBreaker::new(3, 60);
            assert!(!cb.record_failure()); // 1
            assert!(!cb.record_failure()); // 2
            assert!(cb.record_failure()); // 3 - opens
            assert!(cb.is_open());
        }

        #[test]
        fn circuit_stays_open_on_additional_failures() {
            let mut cb = CircuitBreaker::new(2, 60);
            cb.record_failure();
            assert!(cb.record_failure()); // opens
            assert!(!cb.record_failure()); // already open, returns false
            assert!(cb.is_open());
        }

        #[test]
        fn should_attempt_close_returns_false_when_closed() {
            let cb = CircuitBreaker::new(3, 60);
            assert!(!cb.should_attempt_close());
        }

        #[test]
        fn should_attempt_close_returns_false_before_cooldown() {
            let mut cb = CircuitBreaker::new(1, 60);
            cb.record_failure();
            assert!(cb.is_open());
            assert!(!cb.should_attempt_close());
        }

        #[test]
        fn should_attempt_close_returns_true_after_cooldown() {
            let mut cb = CircuitBreaker::new(1, 0); // 0 second cooldown
            cb.record_failure();
            assert!(cb.is_open());
            // With 0 cooldown, should immediately be ready
            assert!(cb.should_attempt_close());
        }

        #[test]
        fn reset_clears_all_state() {
            let mut cb = CircuitBreaker::new(1, 60);
            cb.record_failure();
            assert!(cb.is_open());
            cb.reset();
            assert!(!cb.is_open());
            assert_eq!(cb.consecutive_failures, 0);
        }
    }

    mod idle {
        use super::*;
        use crate::registry::RegistryActor;
        use kameo::actor::Spawn;
        use kameo::mailbox;

        fn backend(options: BackendOptions) -> BackendActor {
            let registry =
                RegistryActor::spawn_with_mailbox(RegistryActor::new(), mailbox::unbounded());
            let config = BackendConfig {
                name: "test".to_string(),
                ..Default::default()
            };
            BackendActor::with_options(config, registry, options)
        }

        #[test]
        fn default_options_have_no_idle_timeout_or_egress() {
            let options = BackendOptions::default();
            assert_eq!(options.idle_timeout, None);
            assert!(options.egress.is_none());
            assert!(!options.passive_health);
            assert!(options.on_outcome.is_none());
        }

        #[test]
        fn metrics_state_list_contains_idle() {
            assert!(crate::metrics::BACKEND_STATES.contains(&"idle"));
        }

        #[tokio::test]
        async fn idle_backend_is_admitted() {
            let mut actor = backend(BackendOptions {
                idle_timeout: Some(Duration::from_secs(60)),
                ..Default::default()
            });
            actor.state = BackendState::Idle;
            assert_eq!(actor.check_state(), Ok(()));
        }

        #[tokio::test]
        async fn disconnected_backend_is_not_admitted() {
            let actor = backend(BackendOptions::default());
            assert!(actor.check_state().is_err());
        }

        #[test]
        fn activity_is_busy_while_a_call_is_in_flight() {
            let activity = Arc::new(Activity::new());
            assert!(!activity.is_busy());
            let call = activity.begin();
            assert!(activity.is_busy());
            drop(call);
            assert!(!activity.is_busy());
        }
    }

    mod calculate_backoff {
        use super::*;
        use rstest::rstest;

        fn backoff_for_attempts(attempts: u32) -> Duration {
            let backoff_secs = BASE_BACKOFF_SECS.saturating_mul(2u64.saturating_pow(attempts));
            Duration::from_secs(backoff_secs.min(MAX_BACKOFF_SECS))
        }

        #[test]
        fn first_attempt_uses_base_backoff() {
            let backoff = backoff_for_attempts(0);
            assert_eq!(backoff, Duration::from_secs(BASE_BACKOFF_SECS));
        }

        /// Backoff is `2^attempt` seconds while below the cap.
        #[rstest]
        #[case(0, 1)]
        #[case(1, 2)]
        #[case(2, 4)]
        #[case(3, 8)]
        #[case(4, 16)]
        #[case(8, 256)]
        fn backoff_doubles_each_attempt(#[case] attempts: u32, #[case] expected_secs: u64) {
            assert_eq!(
                backoff_for_attempts(attempts),
                Duration::from_secs(expected_secs)
            );
        }

        /// Once `2^attempt` exceeds the cap, backoff saturates at the maximum.
        #[rstest]
        #[case(9)]
        #[case(20)]
        #[case(63)]
        fn backoff_caps_at_max(#[case] attempts: u32) {
            assert_eq!(
                backoff_for_attempts(attempts),
                Duration::from_secs(MAX_BACKOFF_SECS)
            );
        }
    }

    mod filter_tools {
        use super::*;

        fn make_tool(name: &str) -> ToolDefinition {
            ToolDefinition {
                name: name.to_string(),
                description: None,
                input_schema: serde_json::json!({}),
                annotations: None,
            }
        }

        #[test]
        fn no_filter_returns_all_tools() {
            let config = BackendConfig {
                name: "test".to_string(),
                allowed_tools: vec![],
                ..Default::default()
            };
            let tools = [make_tool("a"), make_tool("b"), make_tool("c")];

            // Empty allowed_tools means no filtering - all tools returned
            assert_eq!(config.allowed_tools, Vec::<String>::new());
            assert_eq!(tools.len(), 3);
        }

        #[test]
        fn filter_keeps_only_allowed_tools() {
            let allowed_set: std::collections::HashSet<&str> =
                ["tool_a", "tool_c"].into_iter().collect();

            let tools = vec![
                make_tool("tool_a"),
                make_tool("tool_b"),
                make_tool("tool_c"),
            ];
            let filtered: Vec<_> = tools
                .into_iter()
                .filter(|t| allowed_set.contains(t.name.as_str()))
                .collect();

            assert_eq!(filtered.len(), 2);
            assert_eq!(filtered[0].name, "tool_a");
            assert_eq!(filtered[1].name, "tool_c");
        }

        #[test]
        fn filter_with_no_matches_returns_empty() {
            let allowed_set: std::collections::HashSet<&str> =
                ["nonexistent"].into_iter().collect();

            let tools = vec![make_tool("tool_a"), make_tool("tool_b")];
            let filtered: Vec<_> = tools
                .into_iter()
                .filter(|t| allowed_set.contains(t.name.as_str()))
                .collect();

            assert!(filtered.is_empty());
        }
    }

    mod trace_context {
        use super::*;

        const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0c3b4e8e-01";

        fn trace(tracestate: Option<&str>) -> TraceContext {
            TraceContext {
                traceparent: TRACEPARENT.to_string(),
                tracestate: tracestate.map(str::to_string),
            }
        }

        #[test]
        fn sets_traceparent_and_tracestate() {
            let mut params = ReadResourceRequestParams::new("file:///a");

            inject_trace_context(&mut params, Some(&trace(Some("vendor=value"))));

            assert_eq!(params.traceparent(), Some(TRACEPARENT));
            assert_eq!(params.tracestate(), Some("vendor=value"));
        }

        #[test]
        fn keeps_existing_meta_keys() {
            let mut params = CallToolRequestParams::new("tool");
            params
                .meta_or_default()
                .0
                .0
                .insert("custom".to_string(), serde_json::json!(7));

            inject_trace_context(&mut params, Some(&trace(None)));

            let meta = params.meta().unwrap();
            assert_eq!(meta.0.0.get("custom"), Some(&serde_json::json!(7)));
            assert_eq!(meta.get_traceparent(), Some(TRACEPARENT));
            assert_eq!(meta.get_tracestate(), None);
        }

        #[test]
        fn replaces_a_context_the_request_already_has() {
            let mut params = GetPromptRequestParams::new("prompt");
            params.set_traceparent("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00");
            params.set_tracestate("stale=1");

            inject_trace_context(&mut params, Some(&trace(None)));

            assert_eq!(params.traceparent(), Some(TRACEPARENT));
            assert_eq!(params.tracestate(), None);
        }

        #[test]
        fn without_a_context_the_request_is_unchanged() {
            let mut params = CallToolRequestParams::new("tool");

            inject_trace_context(&mut params, None);

            assert!(params.meta().is_none());
        }
    }
}
