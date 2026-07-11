//! Backend Actor - Manages connection to a single MCP server
//!
//! Each backend server gets its own actor that:
//! - Maintains the connection (reconnects on failure with exponential backoff)
//! - Fetches tool, resource, and prompt lists on connect
//! - Forwards tool calls, resource reads, and prompt gets
//! - Performs periodic health checks
//! - Implements circuit breaker pattern for failing backends

use std::time::{Duration, Instant};

use crate::error::BoxError;
use kameo::actor::{Actor, ActorRef, WeakActorRef};
use kameo::message::{Context, Message};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, GetPromptRequestParams, ReadResourceRequestParams};
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use tokio::process::Command;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::config::{BackendConfig, TransportType};
use crate::registry::{RegistryActor, UpdateBackend};
use crate::types::{BackendState, PromptDefinition, ResourceDefinition, ToolDefinition};

/// Maximum backoff duration for reconnection attempts
const MAX_BACKOFF_SECS: u64 = 300; // 5 minutes

/// Base backoff duration for reconnection attempts
const BASE_BACKOFF_SECS: u64 = 1;

/// Wrapper enum for different MCP client types
///
/// Each transport type produces a different `RunningService` type, so we wrap them
/// in an enum to store in the actor.
enum McpClient {
    /// Client connected via streamable HTTP (used for both SSE and HTTP transports)
    Http(RunningService<RoleClient, ()>),
    /// Client connected via child process stdio
    Stdio(RunningService<RoleClient, ()>),
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
}

impl BackendActor {
    pub fn new(config: BackendConfig, registry: ActorRef<RegistryActor>) -> Self {
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
        }
    }

    /// Connect to the backend MCP server
    async fn connect(&mut self) -> Result<(), BoxError> {
        self.state = BackendState::Connecting;
        tracing::info!("Connecting to backend: {}", self.config.name);

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
                let transport = StreamableHttpClientTransport::from_config(transport_config);

                let service = timeout(connect_timeout, ().serve(transport))
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
                let service = timeout(connect_timeout, ().serve(transport))
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

        self.client = Some(client);
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

    /// Forward a tool call to this backend with timeout and error handling
    async fn call_tool(
        &mut self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        // Check circuit breaker
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
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "No client connection available".to_string())?;

        tracing::info!(
            "Backend '{}' executing tool '{}' with args: {}",
            self.config.name,
            tool_name,
            arguments
        );

        // Convert arguments to JsonObject if it's an object, otherwise use empty
        let arguments_obj = arguments.as_object().cloned();

        let call_timeout = Duration::from_secs(self.config.timeout_secs);
        let mut params = CallToolRequestParams::new(tool_name.to_string());
        if let Some(args) = arguments_obj {
            params = params.with_arguments(args);
        }

        let result = timeout(call_timeout, client.peer().call_tool(params)).await;

        match result {
            Ok(Ok(call_result)) => {
                // Success - reset circuit breaker
                self.circuit_breaker.record_success();

                // Convert CallToolResult to JSON
                let response = serde_json::to_value(&call_result)
                    .map_err(|e| format!("Failed to serialize tool result: {e}"))?;
                Ok(response)
            }
            Ok(Err(e)) => {
                // Tool call error
                let error_msg = format!("Tool call failed: {e}");
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
            Err(_) => {
                // Timeout
                let error_msg = format!("Tool call timeout after {}s", self.config.timeout_secs);
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
        }
    }

    /// Read a resource from this backend
    async fn read_resource(&mut self, uri: &str) -> Result<serde_json::Value, String> {
        // Check circuit breaker
        if self.circuit_breaker.is_open() && !self.circuit_breaker.should_attempt_close() {
            return Err(format!(
                "Backend '{}' circuit breaker is open",
                self.config.name
            ));
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "No client connection available".to_string())?;

        tracing::info!("Backend '{}' reading resource '{}'", self.config.name, uri);

        let call_timeout = Duration::from_secs(self.config.timeout_secs);
        let result = timeout(
            call_timeout,
            client
                .peer()
                .read_resource(ReadResourceRequestParams::new(uri)),
        )
        .await;

        match result {
            Ok(Ok(read_result)) => {
                self.circuit_breaker.record_success();
                let response = serde_json::to_value(&read_result)
                    .map_err(|e| format!("Failed to serialize resource result: {e}"))?;
                Ok(response)
            }
            Ok(Err(e)) => {
                let error_msg = format!("Resource read failed: {e}");
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
            Err(_) => {
                let error_msg =
                    format!("Resource read timeout after {}s", self.config.timeout_secs);
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
        }
    }

    /// Get a prompt from this backend
    async fn get_prompt(
        &mut self,
        name: &str,
        arguments: Option<std::collections::HashMap<String, String>>,
    ) -> Result<serde_json::Value, String> {
        // Check circuit breaker
        if self.circuit_breaker.is_open() && !self.circuit_breaker.should_attempt_close() {
            return Err(format!(
                "Backend '{}' circuit breaker is open",
                self.config.name
            ));
        }

        let client = self
            .client
            .as_ref()
            .ok_or_else(|| "No client connection available".to_string())?;

        tracing::info!(
            "Backend '{}' getting prompt '{}' with args: {:?}",
            self.config.name,
            name,
            arguments
        );

        // Convert HashMap<String, String> to serde_json::Map<String, Value>
        let args_map = arguments.map(|args| {
            args.into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect()
        });

        let mut params = GetPromptRequestParams::new(name);
        if let Some(args) = args_map {
            params = params.with_arguments(args);
        }

        let call_timeout = Duration::from_secs(self.config.timeout_secs);
        let result = timeout(call_timeout, client.peer().get_prompt(params)).await;

        match result {
            Ok(Ok(prompt_result)) => {
                self.circuit_breaker.record_success();
                let response = serde_json::to_value(&prompt_result)
                    .map_err(|e| format!("Failed to serialize prompt result: {e}"))?;
                Ok(response)
            }
            Ok(Err(e)) => {
                let error_msg = format!("Prompt get failed: {e}");
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
            Err(_) => {
                let error_msg = format!("Prompt get timeout after {}s", self.config.timeout_secs);
                self.handle_call_failure(&error_msg).await;
                Err(error_msg)
            }
        }
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
    fn schedule_health_check(&self) {
        if self.config.health_check_interval_secs == 0 {
            return; // Health checks disabled
        }

        if let Some(self_ref) = &self.self_ref
            && let Some(actor_ref) = self_ref.upgrade()
        {
            let interval = Duration::from_secs(self.config.health_check_interval_secs);
            let name = self.config.name.clone();
            let token = self.cancel_token.clone();

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

    /// Perform health check by pinging the backend
    async fn perform_health_check(&mut self) -> Result<(), String> {
        if self.state != BackendState::Connected {
            return Ok(()); // Only check connected backends
        }

        let Some(client) = &self.client else {
            return Err("No client connection".to_string());
        };

        // Try to ping by listing tools (lightweight operation)
        let check_timeout = Duration::from_secs(10); // Short timeout for health checks
        let result = timeout(check_timeout, client.peer().list_tools(None)).await;

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
}

impl Message<CallTool> for BackendActor {
    type Reply = Result<serde_json::Value, String>;

    async fn handle(
        &mut self,
        msg: CallTool,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match self.state {
            BackendState::Connected => self.call_tool(&msg.tool_name, &msg.arguments).await,
            BackendState::CircuitOpen => {
                if self.circuit_breaker.should_attempt_close() {
                    // Allow a test request in half-open state
                    self.call_tool(&msg.tool_name, &msg.arguments).await
                } else {
                    Err(format!(
                        "Backend '{}' circuit breaker is open",
                        self.config.name
                    ))
                }
            }
            BackendState::Reconnecting => Err(format!(
                "Backend '{}' is reconnecting (attempt {})",
                self.config.name, self.reconnect_attempts
            )),
            _ => Err(format!("Backend '{}' is not connected", self.config.name)),
        }
    }
}

/// Read a resource from this backend
#[derive(Clone)]
pub struct ReadResource {
    pub uri: String,
}

impl Message<ReadResource> for BackendActor {
    type Reply = Result<serde_json::Value, String>;

    async fn handle(
        &mut self,
        msg: ReadResource,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match self.state {
            BackendState::Connected => self.read_resource(&msg.uri).await,
            BackendState::CircuitOpen => {
                if self.circuit_breaker.should_attempt_close() {
                    self.read_resource(&msg.uri).await
                } else {
                    Err(format!(
                        "Backend '{}' circuit breaker is open",
                        self.config.name
                    ))
                }
            }
            BackendState::Reconnecting => Err(format!(
                "Backend '{}' is reconnecting (attempt {})",
                self.config.name, self.reconnect_attempts
            )),
            _ => Err(format!("Backend '{}' is not connected", self.config.name)),
        }
    }
}

/// Get a prompt from this backend
#[derive(Clone)]
pub struct GetPrompt {
    pub name: String,
    pub arguments: Option<std::collections::HashMap<String, String>>,
}

impl Message<GetPrompt> for BackendActor {
    type Reply = Result<serde_json::Value, String>;

    async fn handle(
        &mut self,
        msg: GetPrompt,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        match self.state {
            BackendState::Connected => self.get_prompt(&msg.name, msg.arguments).await,
            BackendState::CircuitOpen => {
                if self.circuit_breaker.should_attempt_close() {
                    self.get_prompt(&msg.name, msg.arguments).await
                } else {
                    Err(format!(
                        "Backend '{}' circuit breaker is open",
                        self.config.name
                    ))
                }
            }
            BackendState::Reconnecting => Err(format!(
                "Backend '{}' is reconnecting (attempt {})",
                self.config.name, self.reconnect_attempts
            )),
            _ => Err(format!("Backend '{}' is not connected", self.config.name)),
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
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }

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
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }

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
        // Only reconnect if not already connected
        if self.state == BackendState::Connected {
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
            assert!(config.allowed_tools.is_empty());
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
}
