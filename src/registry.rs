//! Registry Actor - Central registry of all backends and their tools
//!
//! Responsibilities:
//! - Track which backends are connected
//! - Maintain aggregated tool list with namespacing
//! - Route tool calls to correct backend

use crate::types::{BackendInfo, BackendState, NamespacedTool, ToolDefinition};
use dashmap::DashMap;
use kameo::prelude::*;
use std::sync::Arc;

/// The registry actor
pub struct RegistryActor {
    /// Backend name -> BackendInfo
    backends: Arc<DashMap<String, BackendInfo>>,
    /// Namespaced tool name -> backend name (for routing)
    tool_routing: Arc<DashMap<String, String>>,
}

impl RegistryActor {
    pub fn new() -> Self {
        Self {
            backends: Arc::new(DashMap::new()),
            tool_routing: Arc::new(DashMap::new()),
        }
    }
}

impl Actor for RegistryActor {
    type Error = anyhow::Error;

    async fn on_start(&mut self, _actor_ref: ActorRef<Self>) -> Result<(), Self::Error> {
        tracing::info!("Registry actor started");
        Ok(())
    }
}

// --- Messages ---

/// Register a new backend (doesn't connect yet)
#[derive(Clone)]
pub struct RegisterBackend {
    pub name: String,
}

impl Message<RegisterBackend> for RegistryActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: RegisterBackend,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        self.backends.insert(
            msg.name.clone(),
            BackendInfo {
                name: msg.name,
                state: BackendState::Disconnected,
                tools: Vec::new(),
                last_error: None,
            },
        );
        Ok(())
    }
}

/// Update backend state and tools
#[derive(Clone)]
pub struct UpdateBackend {
    pub name: String,
    pub state: BackendState,
    pub tools: Vec<ToolDefinition>,
    pub error: Option<String>,
}

impl Message<UpdateBackend> for RegistryActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: UpdateBackend,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        // Remove old tool routes for this backend
        self.tool_routing.retain(|_, backend| backend != &msg.name);

        // Create namespaced tools and update routing
        let namespaced_tools: Vec<NamespacedTool> = msg
            .tools
            .into_iter()
            .map(|t| {
                let ns_tool = NamespacedTool::new(&msg.name, t);
                self.tool_routing
                    .insert(ns_tool.namespaced_name.clone(), msg.name.clone());
                ns_tool
            })
            .collect();

        // Update backend info
        self.backends.insert(
            msg.name.clone(),
            BackendInfo {
                name: msg.name,
                state: msg.state,
                tools: namespaced_tools,
                last_error: msg.error,
            },
        );

        Ok(())
    }
}

/// Get all tools (aggregated from all backends)
pub struct ListTools;

impl Message<ListTools> for RegistryActor {
    type Reply = Vec<ToolDefinition>;

    async fn handle(
        &mut self,
        _msg: ListTools,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        let tools: Vec<ToolDefinition> = self
            .backends
            .iter()
            .filter(|b| b.state == BackendState::Connected)
            .flat_map(|b| b.tools.iter().map(|t| t.definition.clone()))
            .collect();

        tracing::debug!("Listing {} tools from all backends", tools.len());
        Ok(tools)
    }
}

/// Resolve which backend handles a namespaced tool
pub struct ResolveToolBackend {
    pub namespaced_tool_name: String,
}

#[derive(Debug, Clone)]
pub struct ToolRoute {
    pub backend_name: String,
    pub original_tool_name: String,
}

impl Message<ResolveToolBackend> for RegistryActor {
    type Reply = Option<ToolRoute>;

    async fn handle(
        &mut self,
        msg: ResolveToolBackend,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        // Find the backend for this tool
        if let Some(backend_name) = self.tool_routing.get(&msg.namespaced_tool_name) {
            // Find the original tool name
            if let Some(backend) = self.backends.get(backend_name.value()) {
                if let Some(tool) = backend
                    .tools
                    .iter()
                    .find(|t| t.namespaced_name == msg.namespaced_tool_name)
                {
                    return Ok(Some(ToolRoute {
                        backend_name: backend_name.clone(),
                        original_tool_name: tool.original_name.clone(),
                    }));
                }
            }
        }
        Ok(None)
    }
}

/// Get status of all backends
pub struct GetBackendStatus;

impl Message<GetBackendStatus> for RegistryActor {
    type Reply = Vec<BackendInfo>;

    async fn handle(
        &mut self,
        _msg: GetBackendStatus,
        _ctx: &mut Context<Self>,
    ) -> Result<Self::Reply, Self::Error> {
        Ok(self.backends.iter().map(|r| r.value().clone()).collect())
    }
}
