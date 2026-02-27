//! Gateway Actor - Main orchestrator
//!
//! Responsibilities:
//! - Spawn and manage backend actors
//! - Handle incoming MCP requests
//! - Route tool calls to appropriate backends

use crate::backend::{BackendActor, CallTool};
use crate::config::Config;
use crate::registry::{ListTools, RegisterBackend, RegistryActor, ResolveToolBackend, ToolRoute};
use crate::types::{JsonRpcRequest, JsonRpcResponse, ToolDefinition};
use kameo::prelude::*;
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
    async fn init_backends(&mut self) -> anyhow::Result<()> {
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
                .await?;

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
    type Error = anyhow::Error;

    async fn on_start(&mut self, _actor_ref: ActorRef<Self>) -> Result<(), Self::Error> {
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

    async fn handle(
        &mut self,
        msg: HandleRequest,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        let request = msg.request;

        tracing::debug!("Handling MCP request: {}", request.method);

        let response = match request.method.as_str() {
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
            "tools/list" => {
                let tools: Vec<ToolDefinition> = self.registry.ask(ListTools).await?;

                JsonRpcResponse::success(
                    request.id,
                    serde_json::json!({
                        "tools": tools
                    }),
                )
            }

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
                let route = self
                    .registry
                    .ask(ResolveToolBackend {
                        namespaced_tool_name: tool_name.clone(),
                    })
                    .await?;

                match route {
                    Some(ToolRoute {
                        backend_name,
                        original_tool_name,
                    }) => {
                        // Get the backend actor
                        if let Some(backend) = self.backends.get(&backend_name) {
                            // Forward the call
                            let result = backend
                                .ask(CallTool {
                                    tool_name: original_tool_name,
                                    arguments,
                                })
                                .await?;

                            match result {
                                Ok(content) => JsonRpcResponse::success(request.id, content),
                                Err(e) => JsonRpcResponse::error(request.id, -32000, e),
                            }
                        } else {
                            JsonRpcResponse::error(
                                request.id,
                                -32000,
                                format!("Backend '{}' not available", backend_name),
                            )
                        }
                    }
                    None => JsonRpcResponse::error(
                        request.id,
                        -32601,
                        format!("Unknown tool: {}", tool_name),
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
        };

        Ok(response)
    }
}

/// Get gateway status
pub struct GetStatus;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GatewayStatus {
    pub backend_count: usize,
    pub backends: Vec<String>,
}

impl Message<GetStatus> for GatewayActor {
    type Reply = GatewayStatus;

    async fn handle(
        &mut self,
        _msg: GetStatus,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        Ok(GatewayStatus {
            backend_count: self.backends.len(),
            backends: self.backends.keys().cloned().collect(),
        })
    }
}
