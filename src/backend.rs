//! Backend Actor - Manages connection to a single MCP server
//!
//! Each backend server gets its own actor that:
//! - Maintains the connection (reconnects on failure)
//! - Fetches tool list on connect
//! - Forwards tool calls and returns results

use crate::config::{BackendConfig, TransportType};
use crate::registry::{RegistryActor, UpdateBackend};
use crate::types::{BackendState, ToolDefinition};
use kameo::actor::{Actor, ActorRef};
use kameo::error::BoxError;
use kameo::message::{Context, Message};

/// Actor managing a single backend MCP server connection
pub struct BackendActor {
    config: BackendConfig,
    registry: ActorRef<RegistryActor>,
    state: BackendState,
    // In real impl: actual MCP client connection
    // client: Option<McpClient>,
}

impl BackendActor {
    pub fn new(config: BackendConfig, registry: ActorRef<RegistryActor>) -> Self {
        Self {
            config,
            registry,
            state: BackendState::Disconnected,
        }
    }

    /// Connect to the backend MCP server
    async fn connect(&mut self) -> Result<(), BoxError> {
        self.state = BackendState::Connecting;
        tracing::info!("Connecting to backend: {}", self.config.name);

        // TODO: Replace with actual rmcp client connection
        // This is where you'd use rmcp's client transport
        match self.config.transport {
            TransportType::Sse => {
                let url = self.config.url.as_ref().unwrap();
                tracing::info!("Would connect via SSE to: {}", url);
                // let client = rmcp::client::SseClient::connect(url).await?;
            }
            TransportType::Http => {
                let url = self.config.url.as_ref().unwrap();
                tracing::info!("Would connect via HTTP to: {}", url);
                // let client = rmcp::client::HttpClient::connect(url).await?;
            }
            TransportType::Stdio => {
                let cmd = self.config.command.as_ref().unwrap();
                let args = self.config.args.as_deref().unwrap_or(&[]);
                tracing::info!("Would spawn stdio process: {} {:?}", cmd, args);
                // let client = rmcp::client::StdioClient::spawn(cmd, args).await?;
            }
        }

        // Simulate successful connection
        self.state = BackendState::Connected;

        // Fetch tools from backend
        let tools = self.fetch_tools();

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
    fn fetch_tools(&self) -> Vec<ToolDefinition> {
        // TODO: Replace with actual MCP tools/list call
        // let response = self.client.request("tools/list", json!({})).await?;

        // For PoC, return mock tools based on backend name
        let mock_tools = match self.config.name.as_str() {
            "homeassistant" => vec![
                ToolDefinition {
                    name: "turn_on".to_string(),
                    description: Some("Turn on a device".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "entity_id": { "type": "string" }
                        },
                        "required": ["entity_id"]
                    }),
                },
                ToolDefinition {
                    name: "turn_off".to_string(),
                    description: Some("Turn off a device".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "entity_id": { "type": "string" }
                        },
                        "required": ["entity_id"]
                    }),
                },
            ],
            "jellyfin" => vec![
                ToolDefinition {
                    name: "search_media".to_string(),
                    description: Some("Search for media".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "query": { "type": "string" }
                        },
                        "required": ["query"]
                    }),
                },
                ToolDefinition {
                    name: "play".to_string(),
                    description: Some("Play media on a device".to_string()),
                    input_schema: serde_json::json!({
                        "type": "object",
                        "properties": {
                            "media_id": { "type": "string" },
                            "device_id": { "type": "string" }
                        },
                        "required": ["media_id"]
                    }),
                },
            ],
            _ => vec![ToolDefinition {
                name: "ping".to_string(),
                description: Some("Ping the service".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            }],
        };

        tracing::info!(
            "Backend '{}' provides {} tools",
            self.config.name,
            mock_tools.len()
        );
        mock_tools
    }

    /// Forward a tool call to this backend
    fn call_tool(&self, tool_name: &str, arguments: &serde_json::Value) -> serde_json::Value {
        // TODO: Replace with actual MCP tools/call
        // let response = self.client.request("tools/call", json!({
        //     "name": tool_name,
        //     "arguments": arguments
        // })).await?;

        // Mock response
        tracing::info!(
            "Backend '{}' executing tool '{}' with args: {}",
            self.config.name,
            tool_name,
            arguments
        );

        serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!("Mock result from {}::{}", self.config.name, tool_name)
            }]
        })
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

            // Schedule reconnect
            // actor_ref.tell_delayed(Reconnect, Duration::from_secs(5)).await;
        }

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

        Ok(self.call_tool(&msg.tool_name, &msg.arguments))
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
        if self.state != BackendState::Connected
            && let Err(e) = self.connect().await
        {
            tracing::warn!("Reconnect failed for {}: {}", self.config.name, e);
            // Would schedule another reconnect here
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
