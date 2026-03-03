//! Gateway Actor - Main orchestrator
//!
//! Responsibilities:
//! - Spawn and manage backend actors
//! - Handle incoming MCP requests
//! - Route tool calls to appropriate backends
//! - Graceful error handling when backends fail

use crate::backend::{BackendActor, CallTool, ForceReconnect, GetBackendInfo};
use crate::config::Config;
use crate::registry::{
    GetBackendStatus, ListTools, RegisterBackend, RegistryActor, ResolveToolBackend, ToolRoute,
};
use crate::types::{BackendInfo, JsonRpcRequest, JsonRpcResponse};
use kameo::actor::{Actor, ActorRef};
use kameo::error::BoxError;
use kameo::message::{Context, Message};
use std::collections::HashMap;

/// The main gateway actor
pub struct GatewayActor {
    config: Config,
    registry: ActorRef<RegistryActor>,
    backends: HashMap<String, ActorRef<BackendActor>>,
}

impl GatewayActor {
    pub fn new(config: Config, registry: ActorRef<RegistryActor>) -> Self {
        Self {
            config,
            registry,
            backends: HashMap::new(),
        }
    }

    /// Initialize all backends from config
    async fn init_backends(&mut self) -> Result<(), BoxError> {
        for backend_config in &self.config.backends {
            if !backend_config.enabled {
                tracing::info!("Skipping disabled backend: {}", backend_config.name);
                continue;
            }

            // Register in registry
            self.registry
                .tell(RegisterBackend {
                    name: backend_config.name.clone(),
                })
                .await
                .map_err(|e| Box::new(e) as BoxError)?;

            // Spawn backend actor
            let backend_actor = BackendActor::new(backend_config.clone(), self.registry.clone());
            let actor_ref = kameo::spawn(backend_actor);

            self.backends.insert(backend_config.name.clone(), actor_ref);

            tracing::info!("Initialized backend: {}", backend_config.name);
        }

        Ok(())
    }
}

impl Actor for GatewayActor {
    type Mailbox = kameo::mailbox::unbounded::UnboundedMailbox<Self>;

    async fn on_start(&mut self, _actor_ref: ActorRef<Self>) -> Result<(), BoxError> {
        tracing::info!("Gateway actor starting...");
        self.init_backends().await?;
        tracing::info!("Gateway ready with {} backends", self.backends.len());
        Ok(())
    }
}

// --- Messages ---

/// Handle an incoming MCP JSON-RPC request
#[derive(Clone)]
pub struct HandleRequest {
    pub request: JsonRpcRequest,
}

impl Message<HandleRequest> for GatewayActor {
    type Reply = JsonRpcResponse;

    #[allow(clippy::too_many_lines)]
    async fn handle(
        &mut self,
        msg: HandleRequest,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let request = msg.request;

        tracing::debug!("Handling MCP request: {}", request.method);

        match request.method.as_str() {
            // Initialize handshake
            "initialize" => JsonRpcResponse::success(
                request.id,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "mcp-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }),
            ),

            // List all tools from all backends
            "tools/list" => match self.registry.ask(ListTools).await {
                Ok(tools) => JsonRpcResponse::success(
                    request.id,
                    serde_json::json!({
                        "tools": tools
                    }),
                ),
                Err(e) => {
                    JsonRpcResponse::error(request.id, -32000, format!("Failed to list tools: {e}"))
                }
            },

            // Execute a tool
            "tools/call" => {
                let params = request.params;
                let tool_name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::json!({}));

                // Resolve which backend handles this tool
                let route = match self
                    .registry
                    .ask(ResolveToolBackend {
                        namespaced_tool_name: tool_name.clone(),
                    })
                    .await
                {
                    Ok(route) => route,
                    Err(e) => {
                        return JsonRpcResponse::error(
                            request.id,
                            -32000,
                            format!("Failed to resolve tool: {e}"),
                        );
                    }
                };

                match route {
                    Some(ToolRoute {
                        backend_name,
                        original_tool_name,
                    }) => {
                        // Get the backend actor
                        if let Some(backend) = self.backends.get(&backend_name) {
                            // Forward the call
                            match backend
                                .ask(CallTool {
                                    tool_name: original_tool_name,
                                    arguments,
                                })
                                .await
                            {
                                Ok(content) => JsonRpcResponse::success(request.id, content),
                                Err(e) => JsonRpcResponse::error(
                                    request.id,
                                    -32000,
                                    format!("Failed to call backend: {e}"),
                                ),
                            }
                        } else {
                            JsonRpcResponse::error(
                                request.id,
                                -32000,
                                format!("Backend '{backend_name}' not available"),
                            )
                        }
                    }
                    None => JsonRpcResponse::error(
                        request.id,
                        -32601,
                        format!("Unknown tool: {tool_name}"),
                    ),
                }
            }

            // Notifications (no response needed, but we return success)
            "notifications/initialized" => {
                JsonRpcResponse::success(request.id, serde_json::json!({}))
            }

            // Unknown method
            _ => JsonRpcResponse::error(
                request.id,
                -32601,
                format!("Method not found: {}", request.method),
            ),
        }
    }
}

/// Get gateway status
pub struct GetStatus;

#[derive(Debug, Clone, serde::Serialize, kameo::Reply)]
pub struct GatewayStatus {
    pub backend_count: usize,
    pub backends: Vec<String>,
}

impl Message<GetStatus> for GatewayActor {
    type Reply = GatewayStatus;

    async fn handle(
        &mut self,
        _msg: GetStatus,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        GatewayStatus {
            backend_count: self.backends.len(),
            backends: self.backends.keys().cloned().collect(),
        }
    }
}

/// Get detailed status of all backends
pub struct GetDetailedStatus;

#[derive(Debug, Clone, serde::Serialize, kameo::Reply)]
pub struct DetailedGatewayStatus {
    pub backend_count: usize,
    pub backends: Vec<BackendInfo>,
}

impl Message<GetDetailedStatus> for GatewayActor {
    type Reply = DetailedGatewayStatus;

    async fn handle(
        &mut self,
        _msg: GetDetailedStatus,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let backends: Vec<BackendInfo> = self
            .registry
            .ask(GetBackendStatus)
            .await
            .unwrap_or_default();

        DetailedGatewayStatus {
            backend_count: self.backends.len(),
            backends,
        }
    }
}

/// Force reconnect a specific backend
pub struct ForceBackendReconnect {
    pub backend_name: String,
}

impl Message<ForceBackendReconnect> for GatewayActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: ForceBackendReconnect,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let backend = self
            .backends
            .get(&msg.backend_name)
            .ok_or_else(|| format!("Backend '{}' not found", msg.backend_name))?;

        // When Reply = Result<T, E>, ask().await returns Result<T, SendError<M, E>>
        // So ask().await returns Result<(), SendError<ForceReconnect, String>>
        backend
            .ask(ForceReconnect)
            .await
            .map_err(|e| format!("Failed to reconnect: {e:?}"))
    }
}

/// Get info for a specific backend
pub struct GetBackendInfoMsg {
    pub backend_name: String,
}

impl Message<GetBackendInfoMsg> for GatewayActor {
    type Reply = Result<crate::backend::BackendInfoResponse, String>;

    async fn handle(
        &mut self,
        msg: GetBackendInfoMsg,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let backend = self
            .backends
            .get(&msg.backend_name)
            .ok_or_else(|| format!("Backend '{}' not found", msg.backend_name))?;

        match backend.ask(GetBackendInfo).await {
            Ok(info) => Ok(info),
            Err(e) => Err(format!("Failed to get backend info: {e:?}")),
        }
    }
}
