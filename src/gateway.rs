//! Gateway Actor - Main orchestrator
//!
//! Responsibilities:
//! - Spawn and manage backend actors
//! - Handle incoming MCP requests
//! - Route tool calls, resource reads, and prompt gets to appropriate backends
//! - Graceful error handling when backends fail

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error::BoxError;
use kameo::actor::{Actor, ActorRef, Spawn};
use kameo::mailbox;
use kameo::message::{Context, Message};
use kameo::reply::DelegatedReply;

use crate::auth::{AuthManager, TokenIdentity};
use crate::backend::{
    BackendActor, CallTool, ForceReconnect, GetBackendInfo, GetPrompt, ListPrompts, ListResources,
    ReadResource,
};
use crate::config::{BackendConfig, Config};
use crate::policy::ToolRef;
use crate::principal::PrincipalPolicy;
use crate::registry::{
    GetBackendStatus, ListTools, ListToolset, ListToolsets, RegisterBackend, RegistryActor,
    RemoveBackend, ResolveToolBackend, ToolRoute,
};
use crate::types::{
    BackendInfo, JsonRpcRequest, JsonRpcResponse, NamespacedPrompt, NamespacedResource,
    NamespacedTool, PromptDefinition, ResourceDefinition, ToolDefinition,
};

/// The main gateway actor
pub struct GatewayActor {
    config: Config,
    registry: ActorRef<RegistryActor>,
    /// Copy-on-write so request tasks can hold a snapshot while the actor
    /// adds or removes backends.
    backends: Arc<HashMap<String, ActorRef<BackendActor>>>,
}

impl GatewayActor {
    pub fn new(config: Config, registry: ActorRef<RegistryActor>) -> Self {
        Self {
            config,
            registry,
            backends: Arc::new(HashMap::new()),
        }
    }

    /// Mutable access to the backend map (clones it if a request task still
    /// holds the previous snapshot).
    fn backends_mut(&mut self) -> &mut HashMap<String, ActorRef<BackendActor>> {
        Arc::make_mut(&mut self.backends)
    }

    /// Snapshot of the routing state for serving a request outside the actor.
    fn router(&self) -> RequestRouter {
        RequestRouter {
            registry: self.registry.clone(),
            backends: Arc::clone(&self.backends),
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
            let actor_ref = BackendActor::spawn_with_mailbox(backend_actor, mailbox::unbounded());

            Arc::make_mut(&mut self.backends).insert(backend_config.name.clone(), actor_ref);

            tracing::info!("Initialized backend: {}", backend_config.name);
        }

        Ok(())
    }
}

impl Actor for GatewayActor {
    type Args = Self;
    type Error = BoxError;

    async fn on_start(mut state: Self, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        tracing::info!("Gateway actor starting...");
        state.init_backends().await?;
        tracing::info!("Gateway ready with {} backends", state.backends.len());
        Ok(state)
    }
}

// --- Messages ---

/// Handle an incoming MCP JSON-RPC request
#[derive(Clone)]
pub struct HandleRequest {
    pub request: JsonRpcRequest,
    /// Who is asking, and so what they may see and call
    pub caller: Arc<Caller>,
}

impl Message<HandleRequest> for GatewayActor {
    type Reply = DelegatedReply<JsonRpcResponse>;

    /// Only snapshots the routing state here; the backend round trip runs in a
    /// spawned task so a slow tool call never blocks the gateway's mailbox
    /// (status, UI, hot reload and every other client).
    async fn handle(
        &mut self,
        msg: HandleRequest,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let router = self.router();
        let (delegated, sender) = ctx.reply_sender();
        tokio::spawn(async move {
            let response = router.handle_request(msg.request, &msg.caller).await;
            if let Some(sender) = sender {
                sender.send(response);
            }
        });
        delegated
    }
}

/// A snapshot of the gateway's routing state, cheap to clone, used to serve one
/// request outside the actor.
#[derive(Clone)]
struct RequestRouter {
    registry: ActorRef<RegistryActor>,
    backends: Arc<HashMap<String, ActorRef<BackendActor>>>,
}

/// The authenticated caller of an MCP request.
#[derive(Debug, Clone)]
pub enum Caller {
    /// No authentication configured (standalone): everything is allowed.
    Open,
    /// A legacy `[[tokens]]` identity, checked against its own ACL.
    Token(TokenIdentity),
    /// A personal access token or service account, checked against RBAC.
    Principal(PrincipalPolicy),
}

impl Caller {
    /// Whether the caller may use the backend at all.
    fn backend_permitted(&self, backend_name: &str) -> bool {
        match self {
            Self::Open => true,
            Self::Token(identity) => {
                AuthManager::check_backend_permission(Some(identity), backend_name).is_ok()
            }
            Self::Principal(policy) => policy.backend_permitted(backend_name),
        }
    }

    /// The error message for a request that names a backend the caller may
    /// not use, `None` if it may. A principal gets the answer for a backend
    /// that does not exist, so a hidden backend looks absent.
    fn backend_denial(&self, backend_name: &str) -> Option<String> {
        match self {
            Self::Open => None,
            Self::Token(identity) => {
                AuthManager::check_backend_permission(Some(identity), backend_name)
                    .err()
                    .map(|e| format!("Permission denied: {e}"))
            }
            Self::Principal(policy) => (!policy.backend_permitted(backend_name))
                .then(|| format!("Backend '{backend_name}' not found")),
        }
    }

    /// Whether the caller may see and call this tool: for a legacy token both
    /// the backend ACL and the tool patterns must allow it, for a principal
    /// its policy and token scope.
    fn tool_permitted(&self, tool: &NamespacedTool) -> bool {
        match self {
            Self::Open => true,
            Self::Token(identity) => {
                AuthManager::check_backend_permission(Some(identity), &tool.backend_name).is_ok()
                    && AuthManager::check_tool_permission(Some(identity), &tool.namespaced_name)
                        .is_ok()
            }
            Self::Principal(policy) => policy.permits(
                ToolRef {
                    backend: &tool.backend_name,
                    name: &tool.original_name,
                    read_only_hint: tool.definition.read_only_hint(),
                },
                &tool.namespaced_name,
            ),
        }
    }

    /// Whether the caller is restricted at all (`Open` and a legacy token with
    /// empty lists are unrestricted).
    fn is_restricted(&self) -> bool {
        match self {
            Self::Open => false,
            Self::Token(id) => !id.allowed_backends.is_empty() || !id.allowed_tools.is_empty(),
            Self::Principal(_) => true,
        }
    }
}

/// The response for a tool name that does not resolve. A tool the caller may
/// not call gets this too, so hidden looks like absent.
fn unknown_tool(id: Option<serde_json::Value>, tool_name: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(id, -32601, format!("Unknown tool: {tool_name}"))
}

impl RequestRouter {
    /// Backends the caller may access.
    fn permitted_backends<'a>(
        &'a self,
        caller: &'a Caller,
    ) -> impl Iterator<Item = (&'a String, &'a ActorRef<BackendActor>)> + 'a {
        self.backends
            .iter()
            .filter(move |(name, _)| caller.backend_permitted(name))
    }

    /// Drop the tools the caller is not allowed to call.
    ///
    /// The owning backend comes from the registry's routing table rather than
    /// the name prefix, since backend names may themselves contain `_`.
    async fn filter_tools(
        &self,
        tools: Vec<ToolDefinition>,
        caller: &Caller,
    ) -> Vec<ToolDefinition> {
        if !caller.is_restricted() {
            return tools;
        }

        let backends = self
            .registry
            .ask(GetBackendStatus)
            .await
            .unwrap_or_default();
        let permitted: HashSet<&str> = backends
            .iter()
            .flat_map(|backend| backend.tools.iter())
            .filter(|tool| caller.tool_permitted(tool))
            .map(|tool| tool.namespaced_name.as_str())
            .collect();

        tools
            .into_iter()
            .filter(|tool| permitted.contains(tool.name.as_str()))
            .collect()
    }

    /// Whether the caller may call the tool `original_name` of `backend_name`,
    /// by the definition the registry holds for it. A tool the registry does
    /// not know is not callable.
    async fn tool_callable(
        &self,
        caller: &Caller,
        backend_name: &str,
        original_name: &str,
    ) -> bool {
        let backends = self
            .registry
            .ask(GetBackendStatus)
            .await
            .unwrap_or_default();
        backends
            .iter()
            .flat_map(|backend| backend.tools.iter())
            .find(|tool| tool.backend_name == backend_name && tool.original_name == original_name)
            .is_some_and(|tool| caller.tool_permitted(tool))
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_request(&self, request: JsonRpcRequest, caller: &Caller) -> JsonRpcResponse {
        tracing::debug!("Handling MCP request: {}", request.method);

        match request.method.as_str() {
            // Initialize handshake
            "initialize" => JsonRpcResponse::success(
                request.id.clone(),
                serde_json::json!({
                    "protocolVersion": "2025-11-25",
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

            // Liveness check used by MCP clients/inspectors
            "ping" => JsonRpcResponse::success(request.id.clone(), serde_json::json!({})),

            // List all tools from all backends
            "tools/list" => match self.registry.ask(ListTools).await {
                Ok(tools) => JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({
                        "tools": self.filter_tools(tools, caller).await
                    }),
                ),
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    -32000,
                    format!("Failed to list tools: {e}"),
                ),
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
                            request.id.clone(),
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
                        // A principal may only call a tool its policy shows
                        // it: anything else is answered like an unknown tool
                        if let Caller::Principal(_) = caller
                            && !self
                                .tool_callable(caller, &backend_name, &original_tool_name)
                                .await
                        {
                            return unknown_tool(request.id.clone(), &tool_name);
                        }

                        // Check backend permission
                        if let Some(message) = caller.backend_denial(&backend_name) {
                            return JsonRpcResponse::error(request.id.clone(), -32000, message);
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
                                    JsonRpcResponse::success(request.id.clone(), content)
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
                                        request.id.clone(),
                                        -32000,
                                        format!("Failed to call backend: {e}"),
                                    )
                                }
                            }
                        } else {
                            JsonRpcResponse::error(
                                request.id.clone(),
                                -32000,
                                format!("Backend '{backend_name}' not available"),
                            )
                        }
                    }
                    None => unknown_tool(request.id.clone(), &tool_name),
                }
            }

            // List all resources from all backends
            "resources/list" => {
                let mut all_resources: Vec<ResourceDefinition> = Vec::new();

                for (backend_name, backend) in self.permitted_backends(caller) {
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
                    request.id.clone(),
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
                    if let Some(message) = caller.backend_denial(backend_name) {
                        JsonRpcResponse::error(request.id.clone(), -32000, message)
                    } else if let Some(backend) = self.backends.get(backend_name) {
                        crate::metrics::record_resource_read(backend_name);
                        match backend
                            .ask(ReadResource {
                                uri: original_uri.to_string(),
                            })
                            .await
                        {
                            Ok(result) => JsonRpcResponse::success(request.id.clone(), result),
                            Err(e) => JsonRpcResponse::error(
                                request.id.clone(),
                                -32000,
                                format!("Failed to read resource: {e:?}"),
                            ),
                        }
                    } else {
                        JsonRpcResponse::error(
                            request.id.clone(),
                            -32000,
                            format!("Backend '{backend_name}' not found"),
                        )
                    }
                } else {
                    JsonRpcResponse::error(
                        request.id.clone(),
                        -32602,
                        format!("Invalid resource URI format: {uri}"),
                    )
                }
            }

            // List all prompts from all backends
            "prompts/list" => {
                let mut all_prompts: Vec<PromptDefinition> = Vec::new();

                for (backend_name, backend) in self.permitted_backends(caller) {
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
                    request.id.clone(),
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
                    if let Some(message) = caller.backend_denial(backend_name) {
                        JsonRpcResponse::error(request.id.clone(), -32000, message)
                    } else if let Some(backend) = self.backends.get(backend_name) {
                        crate::metrics::record_prompt_get(backend_name);
                        match backend
                            .ask(GetPrompt {
                                name: original_name.to_string(),
                                arguments,
                            })
                            .await
                        {
                            Ok(result) => JsonRpcResponse::success(request.id.clone(), result),
                            Err(e) => JsonRpcResponse::error(
                                request.id.clone(),
                                -32000,
                                format!("Failed to get prompt: {e:?}"),
                            ),
                        }
                    } else {
                        JsonRpcResponse::error(
                            request.id.clone(),
                            -32000,
                            format!("Backend '{backend_name}' not found"),
                        )
                    }
                } else {
                    JsonRpcResponse::error(
                        request.id.clone(),
                        -32602,
                        format!("Invalid prompt name format (expected 'backend_name'): {name}"),
                    )
                }
            }

            // Notifications (no response needed per JSON-RPC spec)
            "notifications/initialized" => {
                // Notifications don't require a response
                // Return success with the same id if present
                JsonRpcResponse::success(request.id.clone(), serde_json::json!({}))
            }

            // Unknown method
            _ => JsonRpcResponse::error(
                request.id.clone(),
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        GatewayStatus {
            backend_count: self.backends.len(),
            backends: self.backends.keys().cloned().collect(),
        }
    }
}

/// Handle a JSON-RPC request scoped to a toolset
///
/// For `tools/list`, returns only tools in the specified toolset.
/// Other methods are handled the same as regular requests.
#[derive(Clone)]
pub struct HandleToolsetRequest {
    pub request: JsonRpcRequest,
    pub caller: Arc<Caller>,
    pub toolset_name: String,
}

impl Message<HandleToolsetRequest> for GatewayActor {
    type Reply = DelegatedReply<JsonRpcResponse>;

    async fn handle(
        &mut self,
        msg: HandleToolsetRequest,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let router = self.router();
        let (delegated, sender) = ctx.reply_sender();
        tokio::spawn(async move {
            let response = router
                .handle_toolset_request(msg.request, &msg.caller, &msg.toolset_name)
                .await;
            if let Some(sender) = sender {
                sender.send(response);
            }
        });
        delegated
    }
}

impl RequestRouter {
    async fn handle_toolset_request(
        &self,
        request: JsonRpcRequest,
        caller: &Caller,
        toolset_name: &str,
    ) -> JsonRpcResponse {
        // For tools/list, return toolset-filtered tools
        if request.method == "tools/list" {
            return match self
                .registry
                .ask(ListToolset {
                    toolset_name: toolset_name.to_string(),
                })
                .await
            {
                Ok(tools) => JsonRpcResponse::success(
                    request.id.clone(),
                    serde_json::json!({ "tools": self.filter_tools(tools, caller).await }),
                ),
                Err(e) => JsonRpcResponse::error(
                    request.id.clone(),
                    -32000,
                    format!("Failed to list tools for toolset '{toolset_name}': {e}"),
                ),
            };
        }

        // For all other methods, delegate to the normal handler
        self.handle_request(request, caller).await
    }
}

/// Describe a namespaced tool for the tool-call audit: backend, original name
/// and annotations. `None` when no tool has that name.
pub struct DescribeTool {
    pub namespaced_name: String,
}

impl Message<DescribeTool> for GatewayActor {
    type Reply = DelegatedReply<Option<crate::registry::ToolDescription>>;

    async fn handle(
        &mut self,
        msg: DescribeTool,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let registry = self.registry.clone();
        let (delegated, sender) = ctx.reply_sender();
        tokio::spawn(async move {
            let description = registry
                .ask(crate::registry::DescribeTool {
                    namespaced_tool_name: msg.namespaced_name,
                })
                .await
                .ok()
                .flatten();
            if let Some(sender) = sender {
                sender.send(description);
            }
        });
        delegated
    }
}

/// Get available toolsets
pub struct GetToolsets;

impl Message<GetToolsets> for GatewayActor {
    type Reply = Vec<crate::registry::ToolsetInfo>;

    async fn handle(
        &mut self,
        _msg: GetToolsets,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.registry.ask(ListToolsets).await.unwrap_or_default()
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
        _ctx: &mut Context<Self, Self::Reply>,
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
        _ctx: &mut Context<Self, Self::Reply>,
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
        _ctx: &mut Context<Self, Self::Reply>,
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let name = msg.config.name.clone();

        if self.backends.contains_key(&name) {
            return Err(format!("Backend '{name}' already exists"));
        }

        if !msg.config.enabled {
            return Err(format!("Backend '{name}' is disabled"));
        }

        // Register in registry
        self.registry
            .tell(RegisterBackend { name: name.clone() })
            .await
            .map_err(|e| format!("Failed to register backend: {e:?}"))?;

        // Spawn backend actor
        let backend_actor = BackendActor::new(msg.config, self.registry.clone());
        let actor_ref = BackendActor::spawn_with_mailbox(backend_actor, mailbox::unbounded());

        self.backends_mut().insert(name.clone(), actor_ref);
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let actor_ref = self
            .backends_mut()
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let actor_ref = self
            .backends_mut()
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
        _ctx: &mut Context<Self, Self::Reply>,
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
        let actor_ref = BackendActor::spawn_with_mailbox(backend_actor, mailbox::unbounded());
        self.backends_mut()
            .insert(msg.backend_name.clone(), actor_ref);

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
        _ctx: &mut Context<Self, Self::Reply>,
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
            if let Some(actor_ref) = self.backends_mut().remove(name) {
                if let Err(e) = actor_ref.stop_gracefully().await {
                    errors.push(format!("Failed to stop '{name}': {e:?}"));
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
                let actor_ref =
                    BackendActor::spawn_with_mailbox(backend_actor, mailbox::unbounded());
                self.backends_mut()
                    .insert(backend_config.name.clone(), actor_ref);
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

#[cfg(test)]
mod tests {
    use super::*;

    mod resource_uri_parsing {
        #[test]
        fn parses_namespaced_uri() {
            let uri = "backend://http://localhost:8080/api";
            let (backend, original) = uri.split_once("://").unwrap();

            assert_eq!(backend, "backend");
            assert_eq!(original, "http://localhost:8080/api");
        }

        #[test]
        fn handles_simple_uri() {
            let uri = "mybackend://file.txt";
            let (backend, original) = uri.split_once("://").unwrap();

            assert_eq!(backend, "mybackend");
            assert_eq!(original, "file.txt");
        }

        #[test]
        fn invalid_uri_returns_none() {
            let uri = "no-separator-here";
            let result = uri.split_once("://");
            assert!(result.is_none());
        }

        #[test]
        fn empty_backend_parses() {
            let uri = "://path";
            let (backend, original) = uri.split_once("://").unwrap();

            assert_eq!(backend, "");
            assert_eq!(original, "path");
        }
    }

    mod prompt_name_parsing {
        #[test]
        fn parses_namespaced_prompt() {
            let name = "backend_prompt_name";
            let (backend, original) = name.split_once('_').unwrap();

            assert_eq!(backend, "backend");
            assert_eq!(original, "prompt_name");
        }

        #[test]
        fn handles_multiple_underscores() {
            let name = "be_prompt_with_underscores";
            let (backend, original) = name.split_once('_').unwrap();

            assert_eq!(backend, "be");
            assert_eq!(original, "prompt_with_underscores");
        }

        #[test]
        fn no_underscore_returns_none() {
            let name = "nounderscore";
            let result = name.split_once('_');
            assert!(result.is_none());
        }
    }

    mod json_rpc_request {
        use super::*;

        #[test]
        fn deserializes_tools_list() {
            let json = r#"{
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }"#;

            let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.method, "tools/list");
            assert_eq!(req.id, Some(serde_json::json!(1)));
        }

        #[test]
        fn deserializes_tool_call() {
            let json = r#"{
                "jsonrpc": "2.0",
                "id": "req-123",
                "method": "tools/call",
                "params": {
                    "name": "backend_my_tool",
                    "arguments": {"key": "value"}
                }
            }"#;

            let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.method, "tools/call");
            assert_eq!(req.id, Some(serde_json::json!("req-123")));
            assert_eq!(
                req.params.get("name").and_then(|v| v.as_str()),
                Some("backend_my_tool")
            );
            assert_eq!(
                req.params.get("arguments").and_then(|v| v.get("key")),
                Some(&serde_json::json!("value"))
            );
        }

        #[test]
        fn deserializes_resource_read() {
            let json = r#"{
                "jsonrpc": "2.0",
                "id": 2,
                "method": "resources/read",
                "params": {
                    "uri": "mybackend://path/to/resource"
                }
            }"#;

            let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.method, "resources/read");
            assert_eq!(
                req.params.get("uri").and_then(|v| v.as_str()),
                Some("mybackend://path/to/resource")
            );
        }

        #[test]
        fn handles_missing_params() {
            let json = r#"{
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            }"#;

            let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.method, "ping");
            assert_eq!(req.params, serde_json::Value::Null);
        }

        #[test]
        fn deserializes_notification_without_id() {
            let json = r#"{
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }"#;

            let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
            assert_eq!(req.method, "notifications/initialized");
            assert!(req.id.is_none());
        }
    }

    mod gateway_status {
        use super::*;

        #[test]
        fn serializes_correctly() {
            let status = GatewayStatus {
                backend_count: 3,
                backends: vec![
                    "backend1".to_string(),
                    "backend2".to_string(),
                    "backend3".to_string(),
                ],
            };

            let json = serde_json::to_value(&status).unwrap();
            assert_eq!(json["backend_count"], 3);
            assert_eq!(json["backends"].as_array().unwrap().len(), 3);
        }
    }

    mod reload_result {
        use super::*;

        #[test]
        fn serializes_correctly() {
            let result = ReloadResult {
                added: vec!["new1".to_string(), "new2".to_string()],
                removed: vec!["old1".to_string()],
                errors: vec![],
            };

            let json = serde_json::to_value(&result).unwrap();
            assert_eq!(json["added"].as_array().unwrap().len(), 2);
            assert_eq!(json["removed"].as_array().unwrap().len(), 1);
            assert_eq!(json["errors"], serde_json::json!([]));
        }

        #[test]
        fn handles_errors() {
            let result = ReloadResult {
                added: vec![],
                removed: vec![],
                errors: vec!["Failed to connect".to_string()],
            };

            let json = serde_json::to_value(&result).unwrap();
            assert_eq!(json["errors"][0], "Failed to connect");
        }
    }

    mod tool_routing_logic {
        #[test]
        fn extracts_backend_from_namespaced_tool() {
            let tool_name = "homeassistant_get_state";
            let parts: Vec<&str> = tool_name.splitn(2, '_').collect();

            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0], "homeassistant");
            assert_eq!(parts[1], "get_state");
        }

        #[test]
        fn tool_with_underscores_preserves_original_name() {
            let tool_name = "backend_tool_with_many_underscores";
            let parts: Vec<&str> = tool_name.splitn(2, '_').collect();

            assert_eq!(parts[0], "backend");
            assert_eq!(parts[1], "tool_with_many_underscores");
        }
    }

    mod token_acl {
        use kameo::mailbox;

        use super::*;
        use crate::config::GatewayConfig;
        use crate::principal::TokenScope;
        use crate::registry::UpdateBackend;
        use crate::types::BackendState;

        fn tool(name: &str) -> ToolDefinition {
            ToolDefinition {
                name: name.to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                annotations: None,
            }
        }

        fn identity(allowed_backends: &[&str], allowed_tools: &[&str]) -> Arc<Caller> {
            Arc::new(Caller::Token(TokenIdentity {
                name: String::from("agent"),
                allowed_tools: allowed_tools.iter().map(ToString::to_string).collect(),
                allowed_backends: allowed_backends.iter().map(ToString::to_string).collect(),
                rate_limit_per_minute: 0,
            }))
        }

        /// A gateway with no backend actors, whose registry knows the tools of
        /// `public`, `secret` and `public_extra` (a name that shares a prefix).
        async fn gateway() -> ActorRef<GatewayActor> {
            let registry =
                RegistryActor::spawn_with_mailbox(RegistryActor::new(), mailbox::unbounded());
            for (backend, tools) in [
                ("public", vec!["read", "write"]),
                ("secret", vec!["dump"]),
                ("public_extra", vec!["thing"]),
            ] {
                registry
                    .ask(UpdateBackend {
                        name: backend.to_string(),
                        state: BackendState::Connected,
                        tools: tools.into_iter().map(tool).collect(),
                        error: None,
                    })
                    .await
                    .unwrap();
            }
            let config = Config {
                gateway: GatewayConfig {
                    bind: String::from("127.0.0.1:0"),
                    base_url: String::from("http://127.0.0.1:0"),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                },
                backends: Vec::new(),
                tokens: Vec::new(),
                toolsets: Vec::new(),
                groups: Vec::new(),
                database: None,
                auth: crate::config::AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
            };
            GatewayActor::spawn_with_mailbox(
                GatewayActor::new(config, registry),
                mailbox::unbounded(),
            )
        }

        async fn call(
            gateway: &ActorRef<GatewayActor>,
            method: &str,
            params: serde_json::Value,
            caller: Arc<Caller>,
        ) -> JsonRpcResponse {
            gateway
                .ask(HandleRequest {
                    request: JsonRpcRequest {
                        jsonrpc: String::from("2.0"),
                        id: Some(serde_json::json!(1)),
                        method: method.to_string(),
                        params,
                    },
                    caller,
                })
                .await
                .unwrap()
        }

        fn tool_names(response: &JsonRpcResponse) -> Vec<String> {
            let mut names: Vec<String> = response.result.as_ref().unwrap()["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect();
            names.sort();
            names
        }

        #[tokio::test]
        async fn tools_list_is_unfiltered_without_restrictions() {
            let gateway = gateway().await;
            let all = call(
                &gateway,
                "tools/list",
                serde_json::json!({}),
                Arc::new(Caller::Open),
            )
            .await;
            assert_eq!(tool_names(&all).len(), 4);

            let open = identity(&[], &[]);
            let open = call(&gateway, "tools/list", serde_json::json!({}), open).await;
            assert_eq!(tool_names(&open).len(), 4);
        }

        #[tokio::test]
        async fn tools_list_hides_backends_outside_the_token_acl() {
            let gateway = gateway().await;
            let id = identity(&["public"], &[]);
            let response = call(&gateway, "tools/list", serde_json::json!({}), id).await;
            // `public_extra_thing` starts with `public_` but belongs to another
            // backend, so it must stay hidden.
            assert_eq!(tool_names(&response), ["public_read", "public_write"]);
        }

        #[tokio::test]
        async fn tools_list_applies_tool_patterns() {
            let gateway = gateway().await;
            let id = identity(&[], &["public_read", "secret_*"]);
            let response = call(&gateway, "tools/list", serde_json::json!({}), id).await;
            assert_eq!(tool_names(&response), ["public_read", "secret_dump"]);
        }

        #[tokio::test]
        async fn resources_read_rejects_backend_outside_the_token_acl() {
            let gateway = gateway().await;
            let id = identity(&["public"], &[]);
            let params = serde_json::json!({ "uri": "secret://file.txt" });
            let response = call(&gateway, "resources/read", params, id).await;
            let error = response.error.expect("must be denied");
            assert!(
                error.message.contains("Permission denied"),
                "{}",
                error.message
            );
        }

        #[tokio::test]
        async fn prompts_get_rejects_backend_outside_the_token_acl() {
            let gateway = gateway().await;
            let id = identity(&["public"], &[]);
            let params = serde_json::json!({ "name": "secret_prompt" });
            let response = call(&gateway, "prompts/get", params, id).await;
            let error = response.error.expect("must be denied");
            assert!(
                error.message.contains("Permission denied"),
                "{}",
                error.message
            );
        }

        #[tokio::test]
        async fn permitted_backend_is_not_denied() {
            let gateway = gateway().await;
            let id = identity(&["public"], &[]);
            let params = serde_json::json!({ "uri": "public://file.txt" });
            let response = call(&gateway, "resources/read", params, id).await;
            // No backend actor exists in this test, so it gets past the ACL and
            // fails on lookup instead.
            let error = response.error.expect("no backend actor");
            assert!(error.message.contains("not found"), "{}", error.message);
        }

        fn principal(
            groups: &[&str],
            opt_outs: &[(&str, Option<&str>)],
            scope: TokenScope,
        ) -> Arc<Caller> {
            use crate::policy::{GrantConfig, OptOuts, Policy, RbacConfig, RbacGroupConfig};

            let grant = |backend: &str, include: &[&str]| GrantConfig {
                group: String::from("dev"),
                backend: backend.to_string(),
                include: include.iter().map(ToString::to_string).collect(),
                exclude: Vec::new(),
                read_only: false,
                mandatory: false,
            };
            let config = RbacConfig {
                groups: vec![RbacGroupConfig {
                    name: String::from("dev"),
                    description: None,
                    idp: Vec::new(),
                    service_accounts: Vec::new(),
                }],
                grants: vec![grant("public", &["*"]), grant("secret", &["nothing"])],
                role_bindings: Vec::new(),
            };
            let groups: Vec<String> = groups.iter().map(ToString::to_string).collect();
            let effective = Policy::from_config(&config).effective(&groups);
            let opt_outs = OptOuts::new(
                opt_outs
                    .iter()
                    .map(|(backend, tool)| (backend.to_string(), tool.map(ToString::to_string))),
            );
            Arc::new(Caller::Principal(PrincipalPolicy::new(
                String::from("alice"),
                effective,
                opt_outs,
                scope,
            )))
        }

        async fn call_tool(
            gateway: &ActorRef<GatewayActor>,
            name: &str,
            caller: &Arc<Caller>,
        ) -> JsonRpcResponse {
            call(
                gateway,
                "tools/call",
                serde_json::json!({ "name": name }),
                Arc::clone(caller),
            )
            .await
        }

        /// The unknown-tool answer of a nonexistent name, with `name` swapped in.
        fn assert_looks_unknown(response: &JsonRpcResponse, name: &str) {
            let error = response.error.as_ref().expect("must be an error");
            assert_eq!(error.code, -32601);
            assert_eq!(error.message, format!("Unknown tool: {name}"));
        }

        #[tokio::test]
        async fn principal_lists_only_granted_tools() {
            let gateway = gateway().await;
            let caller = principal(&["dev"], &[], TokenScope::default());
            let response = call(&gateway, "tools/list", serde_json::json!({}), caller).await;
            assert_eq!(tool_names(&response), ["public_read", "public_write"]);
        }

        #[tokio::test]
        async fn principal_without_grants_sees_nothing() {
            let gateway = gateway().await;
            let caller = principal(&[], &[], TokenScope::default());
            let response = call(&gateway, "tools/list", serde_json::json!({}), caller).await;
            assert_eq!(tool_names(&response), Vec::<String>::new());
        }

        #[tokio::test]
        async fn principal_list_honours_opt_outs_and_scope() {
            let gateway = gateway().await;
            let opted_out = [("public", Some("write"))];
            let caller = principal(&["dev"], &opted_out, TokenScope::default());
            let response = call(&gateway, "tools/list", serde_json::json!({}), caller).await;
            assert_eq!(tool_names(&response), ["public_read"]);

            let scope = TokenScope {
                backends: Vec::new(),
                tools: vec![String::from("public_write")],
            };
            let caller = principal(&["dev"], &[], scope);
            let response = call(&gateway, "tools/list", serde_json::json!({}), caller).await;
            assert_eq!(tool_names(&response), ["public_write"]);
        }

        #[tokio::test]
        async fn principal_call_of_hidden_tool_looks_like_unknown_tool() {
            let gateway = gateway().await;
            let missing = call_tool(
                &gateway,
                "public_missing",
                &principal(&["dev"], &[], TokenScope::default()),
            )
            .await;
            assert_looks_unknown(&missing, "public_missing");

            // not granted: `secret` exists but only `nothing` is granted
            let caller = principal(&["dev"], &[], TokenScope::default());
            let denied = call_tool(&gateway, "secret_dump", &caller).await;
            assert_looks_unknown(&denied, "secret_dump");
            let (denied, missing) = (denied.error.unwrap(), missing.error.unwrap());
            assert_eq!(denied.code, missing.code);
            assert_eq!(denied.data, missing.data);

            // opted out
            let opted_out = [("public", Some("write"))];
            let caller = principal(&["dev"], &opted_out, TokenScope::default());
            let response = call_tool(&gateway, "public_write", &caller).await;
            assert_looks_unknown(&response, "public_write");

            // outside the token scope
            let scope = TokenScope {
                backends: vec![String::from("secret")],
                tools: Vec::new(),
            };
            let caller = principal(&["dev"], &[], scope);
            let response = call_tool(&gateway, "public_read", &caller).await;
            assert_looks_unknown(&response, "public_read");
        }

        #[tokio::test]
        async fn principal_call_of_visible_tool_reaches_the_backend() {
            let gateway = gateway().await;
            let caller = principal(&["dev"], &[], TokenScope::default());
            let response = call_tool(&gateway, "public_read", &caller).await;
            // No backend actor exists in this test, so it gets past RBAC and
            // fails on lookup instead.
            let error = response.error.expect("no backend actor");
            assert!(error.message.contains("not available"), "{}", error.message);
        }

        #[tokio::test]
        async fn principal_toolset_endpoint_only_narrows() {
            let gateway = gateway().await;
            let caller = principal(&["dev"], &[], TokenScope::default());
            let response = gateway
                .ask(HandleToolsetRequest {
                    request: JsonRpcRequest {
                        jsonrpc: String::from("2.0"),
                        id: Some(serde_json::json!(1)),
                        method: String::from("tools/call"),
                        params: serde_json::json!({ "name": "secret_dump" }),
                    },
                    caller,
                    toolset_name: String::from("any"),
                })
                .await
                .unwrap();
            assert_looks_unknown(&response, "secret_dump");
        }
    }
}
