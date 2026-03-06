//! Gateway Actor - Main orchestrator
//!
//! Responsibilities:
//! - Spawn and manage backend actors
//! - Handle incoming MCP requests
//! - Route tool calls, resource reads, and prompt gets to appropriate backends
//! - Graceful error handling when backends fail

use std::collections::HashMap;
use std::sync::Arc;

use kameo::actor::{Actor, ActorRef};
use kameo::error::BoxError;
use kameo::message::{Context, Message};

use crate::auth::{AuthManager, TokenIdentity};
use crate::backend::{
    BackendActor, CallTool, ForceReconnect, GetBackendInfo, GetPrompt, ListPrompts, ListResources,
    ReadResource,
};
use crate::config::{BackendConfig, Config};
use crate::registry::{
    GetBackendStatus, ListToolGroup, ListToolGroups, ListTools, RegisterBackend, RegistryActor,
    RemoveBackend, ResolveToolBackend, ToolRoute,
};
use crate::types::{
    BackendInfo, JsonRpcRequest, JsonRpcResponse, NamespacedPrompt, NamespacedResource,
    PromptDefinition, ResourceDefinition,
};

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
    /// Resolved token identity (None = shared token or no auth)
    pub identity: Option<Arc<TokenIdentity>>,
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
                        "name": "axon-gateway",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {}
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
                        // Check backend permission
                        if let Err(e) = AuthManager::check_backend_permission(
                            msg.identity.as_deref(),
                            &backend_name,
                        ) {
                            return JsonRpcResponse::error(
                                request.id,
                                -32000,
                                format!("Permission denied: {e}"),
                            );
                        }

                        // Get the backend actor
                        if let Some(backend) = self.backends.get(&backend_name) {
                            // Record metrics
                            crate::metrics::record_tool_call(&backend_name, &original_tool_name);
                            let start = std::time::Instant::now();

                            // Forward the call
                            match backend
                                .ask(CallTool {
                                    tool_name: original_tool_name.clone(),
                                    arguments,
                                })
                                .await
                            {
                                Ok(content) => {
                                    crate::metrics::record_tool_call_duration(
                                        &backend_name,
                                        &original_tool_name,
                                        start.elapsed().as_secs_f64(),
                                    );
                                    JsonRpcResponse::success(request.id, content)
                                }
                                Err(e) => {
                                    crate::metrics::record_tool_call_error(
                                        &backend_name,
                                        &original_tool_name,
                                    );
                                    crate::metrics::record_tool_call_duration(
                                        &backend_name,
                                        &original_tool_name,
                                        start.elapsed().as_secs_f64(),
                                    );
                                    JsonRpcResponse::error(
                                        request.id,
                                        -32000,
                                        format!("Failed to call backend: {e}"),
                                    )
                                }
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

            // List all resources from all backends
            "resources/list" => {
                let mut all_resources: Vec<ResourceDefinition> = Vec::new();

                for (backend_name, backend) in &self.backends {
                    // ask() returns Result<T, SendError<M, E>> when Reply = Result<T, E>
                    match backend.ask(ListResources).await {
                        Ok(resources) => {
                            // Namespace the resources
                            for resource in resources {
                                let namespaced = NamespacedResource::new(backend_name, resource);
                                all_resources.push(namespaced.definition);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to list resources from backend '{}': {:?}",
                                backend_name,
                                e
                            );
                        }
                    }
                }

                JsonRpcResponse::success(
                    request.id,
                    serde_json::json!({
                        "resources": all_resources
                    }),
                )
            }

            // Read a specific resource
            "resources/read" => {
                let params = request.params;
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                // Parse the namespaced URI to find backend and original URI
                // Format: "{backend}://{original_uri}"
                if let Some((backend_name, original_uri)) = uri.split_once("://") {
                    if let Some(backend) = self.backends.get(backend_name) {
                        crate::metrics::record_resource_read(backend_name);
                        match backend
                            .ask(ReadResource {
                                uri: original_uri.to_string(),
                            })
                            .await
                        {
                            Ok(result) => JsonRpcResponse::success(request.id, result),
                            Err(e) => JsonRpcResponse::error(
                                request.id,
                                -32000,
                                format!("Failed to read resource: {e:?}"),
                            ),
                        }
                    } else {
                        JsonRpcResponse::error(
                            request.id,
                            -32000,
                            format!("Backend '{backend_name}' not found"),
                        )
                    }
                } else {
                    JsonRpcResponse::error(
                        request.id,
                        -32602,
                        format!("Invalid resource URI format: {uri}"),
                    )
                }
            }

            // List all prompts from all backends
            "prompts/list" => {
                let mut all_prompts: Vec<PromptDefinition> = Vec::new();

                for (backend_name, backend) in &self.backends {
                    match backend.ask(ListPrompts).await {
                        Ok(prompts) => {
                            // Namespace the prompts
                            for prompt in prompts {
                                let namespaced = NamespacedPrompt::new(backend_name, prompt);
                                all_prompts.push(namespaced.definition);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to list prompts from backend '{}': {:?}",
                                backend_name,
                                e
                            );
                        }
                    }
                }

                JsonRpcResponse::success(
                    request.id,
                    serde_json::json!({
                        "prompts": all_prompts
                    }),
                )
            }

            // Get a specific prompt
            "prompts/get" => {
                let params = request.params;
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments: Option<HashMap<String, String>> = params
                    .get("arguments")
                    .and_then(|v| serde_json::from_value(v.clone()).ok());

                // Parse the namespaced name to find backend and original name
                // Format: "{backend}_{original_name}"
                if let Some((backend_name, original_name)) = name.split_once('_') {
                    if let Some(backend) = self.backends.get(backend_name) {
                        crate::metrics::record_prompt_get(backend_name);
                        match backend
                            .ask(GetPrompt {
                                name: original_name.to_string(),
                                arguments,
                            })
                            .await
                        {
                            Ok(result) => JsonRpcResponse::success(request.id, result),
                            Err(e) => JsonRpcResponse::error(
                                request.id,
                                -32000,
                                format!("Failed to get prompt: {e:?}"),
                            ),
                        }
                    } else {
                        JsonRpcResponse::error(
                            request.id,
                            -32000,
                            format!("Backend '{backend_name}' not found"),
                        )
                    }
                } else {
                    JsonRpcResponse::error(
                        request.id,
                        -32602,
                        format!("Invalid prompt name format (expected 'backend_name'): {name}"),
                    )
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

/// Handle a JSON-RPC request scoped to a tool group
///
/// For `tools/list`, returns only tools in the specified group.
/// Other methods are handled the same as regular requests.
#[derive(Clone)]
pub struct HandleGroupRequest {
    pub request: JsonRpcRequest,
    pub identity: Option<Arc<TokenIdentity>>,
    pub group_name: String,
}

impl Message<HandleGroupRequest> for GatewayActor {
    type Reply = JsonRpcResponse;

    async fn handle(
        &mut self,
        msg: HandleGroupRequest,
        ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let request = msg.request.clone();

        // For tools/list, return group-filtered tools
        if request.method == "tools/list" {
            return match self
                .registry
                .ask(ListToolGroup {
                    group_name: msg.group_name.clone(),
                })
                .await
            {
                Ok(tools) => {
                    JsonRpcResponse::success(request.id, serde_json::json!({ "tools": tools }))
                }
                Err(e) => JsonRpcResponse::error(
                    request.id,
                    -32000,
                    format!("Failed to list tools for group '{}': {e}", msg.group_name),
                ),
            };
        }

        // For all other methods, delegate to the normal handler
        self.handle(
            HandleRequest {
                request: msg.request,
                identity: msg.identity,
            },
            ctx,
        )
        .await
    }
}

/// Get available tool groups
pub struct GetToolGroups;

impl Message<GetToolGroups> for GatewayActor {
    type Reply = Vec<crate::registry::ToolGroupInfo>;

    async fn handle(
        &mut self,
        _msg: GetToolGroups,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        self.registry.ask(ListToolGroups).await.unwrap_or_default()
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

/// Add a new backend dynamically (for hot reload)
pub struct AddBackend {
    pub config: BackendConfig,
}

impl Message<AddBackend> for GatewayActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: AddBackend,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let name = msg.config.name.clone();

        if self.backends.contains_key(&name) {
            return Err(format!("Backend '{name}' already exists",));
        }

        if !msg.config.enabled {
            return Err(format!("Backend '{name}' is disabled",));
        }

        // Register in registry
        self.registry
            .tell(RegisterBackend { name: name.clone() })
            .await
            .map_err(|e| format!("Failed to register backend: {e:?}"))?;

        // Spawn backend actor
        let backend_actor = BackendActor::new(msg.config, self.registry.clone());
        let actor_ref = kameo::spawn(backend_actor);

        self.backends.insert(name.clone(), actor_ref);
        tracing::info!("Added backend: {name}",);

        Ok(())
    }
}

/// Remove a backend dynamically (for hot reload)
pub struct RemoveBackendMsg {
    pub name: String,
}

impl Message<RemoveBackendMsg> for GatewayActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: RemoveBackendMsg,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let actor_ref = self
            .backends
            .remove(&msg.name)
            .ok_or_else(|| format!("Backend '{}' not found", msg.name))?;

        // Stop the backend actor
        if let Err(e) = actor_ref.stop_gracefully().await {
            tracing::warn!("Failed to stop backend '{}' gracefully: {:?}", msg.name, e);
        }

        // Remove from registry
        self.registry
            .tell(RemoveBackend {
                name: msg.name.clone(),
            })
            .await
            .map_err(|e| format!("Failed to remove from registry: {e:?}"))?;

        tracing::info!("Removed backend: {}", msg.name);
        Ok(())
    }
}

/// Disable a backend (stop it but keep in config)
pub struct DisableBackendMsg {
    pub backend_name: String,
}

impl Message<DisableBackendMsg> for GatewayActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: DisableBackendMsg,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let actor_ref = self
            .backends
            .remove(&msg.backend_name)
            .ok_or_else(|| format!("Backend '{}' not found", msg.backend_name))?;

        // Stop the backend actor gracefully
        if let Err(e) = actor_ref.stop_gracefully().await {
            tracing::warn!(
                "Failed to stop backend '{}' gracefully: {:?}",
                msg.backend_name,
                e
            );
        }

        // Update registry to mark as disconnected (but don't remove)
        let _ = self
            .registry
            .tell(crate::registry::UpdateBackend {
                name: msg.backend_name.clone(),
                state: crate::types::BackendState::Disconnected,
                tools: vec![],
                error: Some("Disabled by admin".to_string()),
            })
            .await;

        crate::metrics::record_backend_state(&msg.backend_name, "disconnected");
        tracing::info!("Disabled backend: {}", msg.backend_name);
        Ok(())
    }
}

/// Enable a previously disabled backend
pub struct EnableBackendMsg {
    pub backend_name: String,
}

impl Message<EnableBackendMsg> for GatewayActor {
    type Reply = Result<(), String>;

    async fn handle(
        &mut self,
        msg: EnableBackendMsg,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        // Check if already running
        if self.backends.contains_key(&msg.backend_name) {
            return Err(format!("Backend '{}' is already enabled", msg.backend_name));
        }

        // Find the backend config
        let backend_config = self
            .config
            .backends
            .iter()
            .find(|b| b.name == msg.backend_name)
            .ok_or_else(|| format!("Backend '{}' not found in config", msg.backend_name))?
            .clone();

        // Register in registry
        self.registry
            .tell(RegisterBackend {
                name: msg.backend_name.clone(),
            })
            .await
            .map_err(|e| format!("Failed to register backend: {e:?}"))?;

        // Spawn backend actor
        let backend_actor = BackendActor::new(backend_config, self.registry.clone());
        let actor_ref = kameo::spawn(backend_actor);
        self.backends.insert(msg.backend_name.clone(), actor_ref);

        tracing::info!("Enabled backend: {}", msg.backend_name);
        Ok(())
    }
}

/// Reload configuration (for hot reload)
pub struct ReloadConfig {
    pub config: Config,
}

impl Message<ReloadConfig> for GatewayActor {
    type Reply = Result<ReloadResult, String>;

    async fn handle(
        &mut self,
        msg: ReloadConfig,
        _ctx: Context<'_, Self, Self::Reply>,
    ) -> Self::Reply {
        let new_config = msg.config;
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut errors = Vec::new();

        // Find backends to add (in new config but not current)
        let current_names: std::collections::HashSet<_> = self.backends.keys().cloned().collect();
        let new_names: std::collections::HashSet<_> = new_config
            .backends
            .iter()
            .filter(|b| b.enabled)
            .map(|b| b.name.clone())
            .collect();

        // Remove backends that are no longer in config
        for name in current_names.difference(&new_names) {
            if let Some(actor_ref) = self.backends.remove(name) {
                if let Err(e) = actor_ref.stop_gracefully().await {
                    errors.push(format!("Failed to stop '{name}': {e:?}",));
                }
                let _ = self
                    .registry
                    .tell(RemoveBackend { name: name.clone() })
                    .await;
                removed.push(name.clone());
            }
        }

        // Add new backends
        for backend_config in &new_config.backends {
            if !backend_config.enabled {
                continue;
            }
            if !current_names.contains(&backend_config.name) {
                // Register in registry
                if let Err(e) = self
                    .registry
                    .tell(RegisterBackend {
                        name: backend_config.name.clone(),
                    })
                    .await
                {
                    errors.push(format!(
                        "Failed to register '{}': {e:?}",
                        backend_config.name
                    ));
                    continue;
                }

                // Spawn backend actor
                let backend_actor =
                    BackendActor::new(backend_config.clone(), self.registry.clone());
                let actor_ref = kameo::spawn(backend_actor);
                self.backends.insert(backend_config.name.clone(), actor_ref);
                added.push(backend_config.name.clone());
            }
        }

        // Update internal config
        self.config = new_config;

        tracing::info!(
            "Config reloaded: {} added, {} removed, {} errors",
            added.len(),
            removed.len(),
            errors.len()
        );

        Ok(ReloadResult {
            added,
            removed,
            errors,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, kameo::Reply)]
pub struct ReloadResult {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub errors: Vec<String>,
}
