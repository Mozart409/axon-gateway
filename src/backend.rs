//! Backend Actor - Manages connection to a single MCP server
//!
//! Each backend server gets its own actor that:
//! - Maintains the connection (reconnects on failure)
//! - Fetches tool list on connect
//! - Forwards tool calls and returns results

use std::borrow::Cow;

use kameo::actor::{Actor, ActorRef};
use kameo::error::BoxError;
use kameo::message::{Context, Message};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::service::{Peer, RoleClient, RunningService};
use rmcp::transport::{StreamableHttpClientTransport, TokioChildProcess};
use tokio::process::Command;

use crate::config::{BackendConfig, TransportType};
use crate::registry::{RegistryActor, UpdateBackend};
use crate::types::{BackendState, ToolDefinition};

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

/// Actor managing a single backend MCP server connection
pub struct BackendActor {
    config: BackendConfig,
    registry: ActorRef<RegistryActor>,
    state: BackendState,
    client: Option<McpClient>,
}

impl BackendActor {
    pub fn new(config: BackendConfig, registry: ActorRef<RegistryActor>) -> Self {
        Self {
            config,
            registry,
            state: BackendState::Disconnected,
            client: None,
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

                let transport = StreamableHttpClientTransport::from_uri(url.as_str());
                let service =
                    ().serve(transport)
                        .await
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

                let transport = TokioChildProcess::new(command)
                    .map_err(|e| format!("Failed to spawn process {cmd}: {e}"))?;

                let service = ()
                    .serve(transport)
                    .await
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

        Ok(())
    }

    /// Fetch tool list from the backend
    async fn fetch_tools(&self) -> Result<Vec<ToolDefinition>, BoxError> {
        let client = self
            .client
            .as_ref()
            .ok_or("No client connection available")?;

        let tools = client
            .peer()
            .list_all_tools()
            .await
            .map_err(|e| format!("Failed to list tools: {e}"))?;

        let tool_defs: Vec<ToolDefinition> = tools.into_iter().map(ToolDefinition::from).collect();

        tracing::info!(
            "Backend '{}' provides {} tools",
            self.config.name,
            tool_defs.len()
        );

        for tool in &tool_defs {
            tracing::debug!("  - {}: {:?}", tool.name, tool.description);
        }

        Ok(tool_defs)
    }

    /// Forward a tool call to this backend
    async fn call_tool(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
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

        let result = client
            .peer()
            .call_tool(CallToolRequestParams {
                meta: None,
                name: Cow::Owned(tool_name.to_string()),
                arguments: arguments_obj,
                task: None,
            })
            .await
            .map_err(|e| format!("Tool call failed: {e}"))?;

        // Convert CallToolResult to JSON
        let response = serde_json::to_value(&result)
            .map_err(|e| format!("Failed to serialize tool result: {e}"))?;

        Ok(response)
    }

    /// Disconnect from the backend
    async fn disconnect(&mut self) {
        if let Some(client) = self.client.take() {
            tracing::info!("Disconnecting from backend: {}", self.config.name);
            client.cancel().await;
        }
        self.state = BackendState::Disconnected;
    }
}

impl Actor for BackendActor {
    type Mailbox = kameo::mailbox::unbounded::UnboundedMailbox<Self>;

    async fn on_start(&mut self, _actor_ref: ActorRef<Self>) -> Result<(), BoxError> {
        tracing::info!("Backend actor started: {}", self.config.name);

        // Initial connection
        if let Err(e) = self.connect().await {
            tracing::error!("Failed to connect to {}: {}", self.config.name, e);
            self.state = BackendState::Failed;
            self.registry
                .tell(UpdateBackend {
                    name: self.config.name.clone(),
                    state: BackendState::Failed,
                    tools: vec![],
                    error: Some(e.to_string()),
                })
                .await
                .map_err(|e| Box::new(e) as BoxError)?;

            // TODO: Schedule reconnect with exponential backoff
            // actor_ref.tell_delayed(Reconnect, Duration::from_secs(5)).await;
        }

        Ok(())
    }

    async fn on_stop(
        &mut self,
        _actor_ref: kameo::actor::WeakActorRef<Self>,
        _reason: kameo::error::ActorStopReason,
    ) -> Result<(), BoxError> {
        tracing::info!("Backend actor stopping: {}", self.config.name);
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

    async fn handle(&mut self, msg: CallTool, _ctx: Context<'_, Self, Self::Reply>) -> Self::Reply {
        if self.state != BackendState::Connected {
            return Err(format!("Backend '{}' is not connected", self.config.name));
        }

        self.call_tool(&msg.tool_name, &msg.arguments).await
    }
}

/// Trigger reconnection
pub struct Reconnect;

impl Message<Reconnect> for BackendActor {
    type Reply = ();

    async fn handle(
        &mut self,
        _msg: Reconnect,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        if self.state != BackendState::Connected {
            // Disconnect existing (possibly broken) connection
            self.disconnect().await;

            if let Err(e) = self.connect().await {
                tracing::warn!("Reconnect failed for {}: {}", self.config.name, e);
                // TODO: Schedule another reconnect with exponential backoff
            }
        }
    }
}

/// Health check
pub struct HealthCheck;

impl Message<HealthCheck> for BackendActor {
    type Reply = BackendState;

    async fn handle(
        &mut self,
        _msg: HealthCheck,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        self.state
    }
}

/// Refresh tool list from backend
pub struct RefreshTools;

impl Message<RefreshTools> for BackendActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        _msg: RefreshTools,
        _ctx: Context<'_, Self, Self::Reply>,
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
