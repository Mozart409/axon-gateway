//! Registry Actor - Central registry of all backends and their tools
//!
//! Responsibilities:
//! - Track which backends are connected
//! - Maintain aggregated tool list with namespacing
//! - Route tool calls to correct backend
//! - Cache tool lists with automatic invalidation
//! - Support toolset filtering

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::BoxError;
use dashmap::DashMap;
use kameo::actor::{Actor, ActorRef};
use kameo::message::{Context, Message};

use crate::changes::{ChangeBus, ChangeScope};
use crate::config::ToolsetConfig;
use crate::types::{BackendInfo, BackendState, NamespacedTool, ToolDefinition};

/// Default cache TTL for tool lists (5 minutes)
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Cached tool list
struct ToolCache {
    /// Cached aggregated tool list
    tools: Vec<ToolDefinition>,
    /// When the cache was last populated
    cached_at: Instant,
    /// Cache TTL
    ttl: Duration,
}

impl ToolCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            tools: Vec::new(),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Check if the cache is still valid
    fn is_valid(&self) -> bool {
        !self.tools.is_empty() && self.cached_at.elapsed() < self.ttl
    }

    /// Invalidate the cache
    fn invalidate(&mut self) {
        self.tools.clear();
    }

    /// Update the cache with new tools
    fn update(&mut self, tools: Vec<ToolDefinition>) {
        self.tools = tools;
        self.cached_at = Instant::now();
    }
}

/// The registry actor
pub struct RegistryActor {
    /// Backend name -> `BackendInfo`
    backends: Arc<DashMap<String, BackendInfo>>,
    /// Namespaced tool name -> backend name (for routing)
    tool_routing: Arc<DashMap<String, String>>,
    /// Cached tool list to avoid recomputing on every `tools/list`
    tool_cache: ToolCache,
    /// Toolset definitions
    toolsets: Vec<ToolsetConfig>,
    /// Told when a backend's tools change; `None` publishes nothing
    changes: Option<ChangeBus>,
    /// Whose tool lists a change here concerns (everyone, or one user's slot)
    change_scope: ChangeScope,
}

impl RegistryActor {
    pub fn new() -> Self {
        Self {
            backends: Arc::new(DashMap::new()),
            tool_routing: Arc::new(DashMap::new()),
            tool_cache: ToolCache::new(DEFAULT_CACHE_TTL_SECS),
            toolsets: Vec::new(),
            changes: None,
            change_scope: ChangeScope::All,
        }
    }

    /// Create with toolset definitions
    pub fn with_toolsets(toolsets: Vec<ToolsetConfig>) -> Self {
        Self {
            backends: Arc::new(DashMap::new()),
            tool_routing: Arc::new(DashMap::new()),
            tool_cache: ToolCache::new(DEFAULT_CACHE_TTL_SECS),
            toolsets,
            changes: None,
            change_scope: ChangeScope::All,
        }
    }

    /// Publish tool-list changes on `bus`
    #[must_use]
    pub fn with_change_bus(mut self, bus: ChangeBus) -> Self {
        self.changes = Some(bus);
        self
    }

    /// Publish changes under `scope` instead of [`ChangeScope::All`], for a
    /// registry that holds one user's backends
    #[must_use]
    pub fn with_change_scope(mut self, scope: ChangeScope) -> Self {
        self.change_scope = scope;
        self
    }

    /// Tell the subscribers that some caller's tool list may have changed
    fn publish_tools_changed(&self) {
        if let Some(bus) = &self.changes {
            bus.publish(self.change_scope);
        }
    }

    /// Whether two tool lists hold the same namespaced names and definitions
    fn same_tools(old: &[NamespacedTool], new: &[NamespacedTool]) -> bool {
        old.len() == new.len()
            && old.iter().zip(new).all(|(old, new)| {
                old.namespaced_name == new.namespaced_name
                    && old.definition.name == new.definition.name
                    && old.definition.description == new.definition.description
                    && old.definition.input_schema == new.definition.input_schema
                    && old.definition.annotations == new.definition.annotations
            })
    }

    /// Build the aggregated tool list from all connected backends
    fn build_tool_list(&self) -> Vec<ToolDefinition> {
        self.backends
            .iter()
            .filter(|b| matches!(b.state, BackendState::Connected | BackendState::Idle))
            .flat_map(|b| {
                b.tools
                    .iter()
                    .map(|t| t.definition.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Filter tools for a specific toolset
    fn filter_tools_for_toolset(
        tools: &[ToolDefinition],
        toolset: &ToolsetConfig,
    ) -> Vec<ToolDefinition> {
        tools
            .iter()
            .filter(|tool| {
                // Check backend filter
                if !toolset.backends.is_empty() {
                    let matches_backend = toolset
                        .backends
                        .iter()
                        .any(|b| tool.name.starts_with(&format!("{b}_")));
                    if !matches_backend {
                        return false;
                    }
                }

                // Check tool pattern filter
                if toolset.tools.is_empty() {
                    return true; // No tool filter = include all
                }

                toolset
                    .tools
                    .iter()
                    .any(|pattern| crate::authz::tool_matches_pattern(&tool.name, pattern))
            })
            .cloned()
            .collect()
    }
}

impl Actor for RegistryActor {
    type Args = Self;
    type Error = BoxError;

    async fn on_start(state: Self, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        tracing::info!("Registry actor started");
        if !state.toolsets.is_empty() {
            tracing::info!(
                "Toolsets configured: {:?}",
                state.toolsets.iter().map(|g| &g.name).collect::<Vec<_>>()
            );
        }
        Ok(state)
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.backends.insert(
            msg.name.clone(),
            BackendInfo::new(msg.name, BackendState::Disconnected, Vec::new(), None),
        );
    }
}

/// Mark a backend idle: its connection is closed on purpose, its cached tools
/// stay listed and routable
pub struct MarkIdle {
    pub name: String,
}

impl Message<MarkIdle> for RegistryActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: MarkIdle,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if let Some(mut info) = self.backends.get_mut(&msg.name) {
            info.state = BackendState::Idle;
        }
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
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

        // The guard of `get` is gone by the end of the statement, before `insert`
        let unchanged = self
            .backends
            .get(&msg.name)
            .map_or(namespaced_tools.is_empty(), |previous| {
                Self::same_tools(&previous.tools, &namespaced_tools)
            });

        // Update backend info
        self.backends.insert(
            msg.name.clone(),
            BackendInfo::new(msg.name, msg.state, namespaced_tools, msg.error),
        );

        // Invalidate tool cache on any backend update
        self.tool_cache.invalidate();

        if !unchanged {
            self.publish_tools_changed();
        }
    }
}

/// Get all tools (aggregated from all backends), using cache when valid
pub struct ListTools;

impl Message<ListTools> for RegistryActor {
    type Reply = Vec<ToolDefinition>;

    async fn handle(
        &mut self,
        _msg: ListTools,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Return cached tools if available
        if self.tool_cache.is_valid() {
            tracing::debug!("Returning {} cached tools", self.tool_cache.tools.len());
            return self.tool_cache.tools.clone();
        }

        // Rebuild cache
        let tools = self.build_tool_list();
        tracing::debug!("Rebuilt tool cache with {} tools", tools.len());
        self.tool_cache.update(tools.clone());
        tools
    }
}

/// List tools for a specific toolset
pub struct ListToolset {
    pub toolset_name: String,
}

impl Message<ListToolset> for RegistryActor {
    type Reply = Result<Vec<ToolDefinition>, String>;

    async fn handle(
        &mut self,
        msg: ListToolset,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let toolset = self
            .toolsets
            .iter()
            .find(|g| g.name == msg.toolset_name)
            .ok_or_else(|| format!("Toolset '{}' not found", msg.toolset_name))?;

        // Get all tools (using cache)
        let all_tools = if self.tool_cache.is_valid() {
            self.tool_cache.tools.clone()
        } else {
            let tools = self.build_tool_list();
            self.tool_cache.update(tools.clone());
            tools
        };

        Ok(Self::filter_tools_for_toolset(&all_tools, toolset))
    }
}

/// Get available toolsets
pub struct ListToolsets;

#[derive(Debug, Clone, serde::Serialize, kameo::Reply)]
pub struct ToolsetInfo {
    pub name: String,
    pub description: Option<String>,
    pub tool_count: usize,
}

impl Message<ListToolsets> for RegistryActor {
    type Reply = Vec<ToolsetInfo>;

    async fn handle(
        &mut self,
        _msg: ListToolsets,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let all_tools = if self.tool_cache.is_valid() {
            self.tool_cache.tools.clone()
        } else {
            let tools = self.build_tool_list();
            self.tool_cache.update(tools.clone());
            tools
        };

        self.toolsets
            .iter()
            .map(|toolset| {
                let filtered = Self::filter_tools_for_toolset(&all_tools, toolset);
                ToolsetInfo {
                    name: toolset.name.clone(),
                    description: toolset.description.clone(),
                    tool_count: filtered.len(),
                }
            })
            .collect()
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
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Find the backend for this tool
        if let Some(backend_name) = self.tool_routing.get(&msg.namespaced_tool_name)
            && let Some(backend) = self.backends.get(backend_name.value())
            && let Some(tool) = backend
                .tools
                .iter()
                .find(|t| t.namespaced_name == msg.namespaced_tool_name)
        {
            return Some(ToolRoute {
                backend_name: backend_name.clone(),
                original_tool_name: tool.original_name.clone(),
            });
        }
        None
    }
}

/// Look up what the tool-call audit records about a namespaced tool.
pub struct DescribeTool {
    pub namespaced_tool_name: String,
}

/// The backend, original name and MCP annotations of a tool.
#[derive(Debug, Clone)]
pub struct ToolDescription {
    pub backend_name: String,
    pub original_tool_name: String,
    pub annotations: Option<serde_json::Value>,
}

impl Message<DescribeTool> for RegistryActor {
    type Reply = Option<ToolDescription>;

    async fn handle(
        &mut self,
        msg: DescribeTool,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let backend_name = self.tool_routing.get(&msg.namespaced_tool_name)?;
        let backend = self.backends.get(backend_name.value())?;
        let tool = backend
            .tools
            .iter()
            .find(|t| t.namespaced_name == msg.namespaced_tool_name)?;
        Some(ToolDescription {
            backend_name: backend_name.clone(),
            original_tool_name: tool.original_name.clone(),
            annotations: tool.definition.annotations.clone(),
        })
    }
}

/// Get status of all backends
pub struct GetBackendStatus;

impl Message<GetBackendStatus> for RegistryActor {
    type Reply = Vec<BackendInfo>;

    async fn handle(
        &mut self,
        _msg: GetBackendStatus,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.backends.iter().map(|r| r.value().clone()).collect()
    }
}

/// Replace the toolset definitions (config reload). Toolsets only filter the
/// cached tool list, so the cache stays valid; open MCP connections are told
/// because their toolset may have changed.
pub struct SetToolsets {
    pub toolsets: Vec<ToolsetConfig>,
}

impl Message<SetToolsets> for RegistryActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: SetToolsets,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.toolsets != msg.toolsets {
            self.toolsets = msg.toolsets;
            self.publish_tools_changed();
        }
    }
}

/// Remove a backend from the registry
#[derive(Clone)]
pub struct RemoveBackend {
    pub name: String,
}

impl Message<RemoveBackend> for RegistryActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: RemoveBackend,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // Remove tool routes for this backend
        self.tool_routing.retain(|_, backend| backend != &msg.name);
        // Remove the backend
        let had_tools = self
            .backends
            .remove(&msg.name)
            .is_some_and(|(_, backend)| !backend.tools.is_empty());
        // Invalidate cache
        self.tool_cache.invalidate();
        if had_tools {
            self.publish_tools_changed();
        }
        tracing::info!("Removed backend '{}' from registry", msg.name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: Some(format!("{name} description")),
            input_schema: serde_json::json!({"type": "object"}),
            annotations: None,
        }
    }

    mod tool_cache {
        use super::*;

        #[test]
        fn new_cache_is_invalid() {
            let cache = ToolCache::new(300);
            assert!(!cache.is_valid());
        }

        #[test]
        fn cache_becomes_valid_after_update() {
            let mut cache = ToolCache::new(300);
            cache.update(vec![make_tool("test")]);
            assert!(cache.is_valid());
        }

        #[test]
        fn invalidate_clears_cache() {
            let mut cache = ToolCache::new(300);
            cache.update(vec![make_tool("test")]);
            assert!(cache.is_valid());
            cache.invalidate();
            assert!(!cache.is_valid());
        }

        #[test]
        fn empty_cache_is_invalid_even_after_update() {
            let mut cache = ToolCache::new(300);
            cache.update(vec![]);
            assert!(!cache.is_valid());
        }

        #[test]
        fn cache_expires_after_ttl() {
            let mut cache = ToolCache::new(0); // 0 second TTL
            cache.update(vec![make_tool("test")]);
            // With 0 TTL, cache should be invalid immediately
            std::thread::sleep(std::time::Duration::from_millis(1));
            assert!(!cache.is_valid());
        }
    }

    mod filter_tools_for_toolset {
        use super::*;

        #[test]
        fn empty_filters_returns_all_tools() {
            let tools = vec![make_tool("backend1_tool_a"), make_tool("backend2_tool_b")];
            let toolset = ToolsetConfig {
                name: "all".to_string(),
                tools: vec![],
                backends: vec![],
                description: None,
            };

            let filtered = RegistryActor::filter_tools_for_toolset(&tools, &toolset);
            assert_eq!(filtered.len(), 2);
        }

        #[test]
        fn backend_filter_keeps_matching_tools() {
            let tools = vec![
                make_tool("backend1_tool_a"),
                make_tool("backend1_tool_b"),
                make_tool("backend2_tool_c"),
            ];
            let toolset = ToolsetConfig {
                name: "toolset1".to_string(),
                tools: vec![],
                backends: vec!["backend1".to_string()],
                description: None,
            };

            let filtered = RegistryActor::filter_tools_for_toolset(&tools, &toolset);
            assert_eq!(filtered.len(), 2);
            assert!(filtered.iter().all(|t| t.name.starts_with("backend1_")));
        }

        #[test]
        fn tool_pattern_filter_with_prefix_glob() {
            let tools = vec![
                make_tool("backend1_read"),
                make_tool("backend1_write"),
                make_tool("backend2_delete"),
            ];
            let toolset = ToolsetConfig {
                name: "backend1_tools".to_string(),
                tools: vec!["backend1_*".to_string()],
                backends: vec![],
                description: None,
            };

            let filtered = RegistryActor::filter_tools_for_toolset(&tools, &toolset);
            assert_eq!(filtered.len(), 2);
            assert!(filtered.iter().all(|t| t.name.starts_with("backend1_")));
        }

        #[test]
        fn tool_pattern_filter_with_exact_match() {
            let tools = vec![
                make_tool("backend1_read"),
                make_tool("backend1_write"),
                make_tool("backend1_delete"),
            ];
            let toolset = ToolsetConfig {
                name: "readonly".to_string(),
                tools: vec!["backend1_read".to_string()],
                backends: vec![],
                description: None,
            };

            let filtered = RegistryActor::filter_tools_for_toolset(&tools, &toolset);
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].name, "backend1_read");
        }

        #[test]
        fn combined_backend_and_tool_filter() {
            let tools = vec![
                make_tool("backend1_read"),
                make_tool("backend1_write"),
                make_tool("backend2_read"),
            ];
            let toolset = ToolsetConfig {
                name: "b1_read".to_string(),
                tools: vec!["backend1_read".to_string()],
                backends: vec!["backend1".to_string()],
                description: None,
            };

            let filtered = RegistryActor::filter_tools_for_toolset(&tools, &toolset);
            assert_eq!(filtered.len(), 1);
            assert_eq!(filtered[0].name, "backend1_read");
        }
    }

    mod registry_actor {
        use super::*;

        #[test]
        fn new_creates_empty_registry() {
            let registry = RegistryActor::new();
            assert!(registry.backends.is_empty());
            assert!(registry.tool_routing.is_empty());
        }

        #[test]
        fn with_toolsets_stores_toolsets() {
            let toolsets = vec![ToolsetConfig {
                name: "toolset1".to_string(),
                tools: vec![],
                backends: vec![],
                description: Some("Test toolset".to_string()),
            }];
            let registry = RegistryActor::with_toolsets(toolsets.clone());
            assert_eq!(registry.toolsets.len(), 1);
            assert_eq!(registry.toolsets[0].name, "toolset1");
        }

        #[test]
        fn build_tool_list_only_includes_connected_backends() {
            let registry = RegistryActor::new();

            // Add a connected backend
            let tool = make_tool("test_tool");
            let ns_tool = NamespacedTool::new("connected", tool);
            registry.backends.insert(
                "connected".to_string(),
                BackendInfo::new(
                    "connected".to_string(),
                    BackendState::Connected,
                    vec![ns_tool],
                    None,
                ),
            );

            // Add a disconnected backend
            let tool2 = make_tool("other_tool");
            let ns_tool2 = NamespacedTool::new("disconnected", tool2);
            registry.backends.insert(
                "disconnected".to_string(),
                BackendInfo::new(
                    "disconnected".to_string(),
                    BackendState::Disconnected,
                    vec![ns_tool2],
                    None,
                ),
            );

            let tool_list = registry.build_tool_list();
            assert_eq!(tool_list.len(), 1);
            assert_eq!(tool_list[0].name, "connected_test_tool");
        }
    }

    mod change_publishing {
        use super::*;
        use kameo::actor::Spawn;
        use kameo::mailbox;

        /// Waits long enough, on the paused clock, to see whether anything was published
        async fn published(subscription: &mut crate::changes::ChangeSubscription) -> bool {
            tokio::time::timeout(Duration::from_secs(5), subscription.changed_for(None))
                .await
                .is_ok()
        }

        fn update(name: &str, tools: &[&str]) -> UpdateBackend {
            UpdateBackend {
                name: name.to_string(),
                state: BackendState::Connected,
                tools: tools.iter().map(|tool| make_tool(tool)).collect(),
                error: None,
            }
        }

        #[tokio::test]
        async fn a_changed_tool_list_is_published_and_an_identical_one_is_not() {
            let bus = ChangeBus::new();
            let mut subscription = bus.subscribe();
            let registry = RegistryActor::spawn_with_mailbox(
                RegistryActor::new().with_change_bus(bus),
                mailbox::unbounded(),
            );

            registry.ask(update("b", &["one"])).await.unwrap();
            assert!(published(&mut subscription).await);

            registry.ask(update("b", &["one"])).await.unwrap();
            assert!(!published(&mut subscription).await);

            registry.ask(update("b", &["one", "two"])).await.unwrap();
            assert!(published(&mut subscription).await);
        }

        #[tokio::test]
        async fn removing_a_backend_publishes_only_when_it_had_tools() {
            let bus = ChangeBus::new();
            let mut subscription = bus.subscribe();
            let registry = RegistryActor::spawn_with_mailbox(
                RegistryActor::with_toolsets(Vec::new()).with_change_bus(bus),
                mailbox::unbounded(),
            );

            registry.ask(update("empty", &[])).await.unwrap();
            assert!(!published(&mut subscription).await);
            registry
                .ask(RemoveBackend {
                    name: "empty".to_string(),
                })
                .await
                .unwrap();
            assert!(!published(&mut subscription).await);

            registry.ask(update("full", &["one"])).await.unwrap();
            assert!(published(&mut subscription).await);
            registry
                .ask(RemoveBackend {
                    name: "full".to_string(),
                })
                .await
                .unwrap();
            assert!(published(&mut subscription).await);
        }
    }

    mod namespaced_tool {
        use super::*;

        #[test]
        fn creates_namespaced_name() {
            let tool = make_tool("my_tool");
            let ns = NamespacedTool::new("backend", tool);
            assert_eq!(ns.namespaced_name, "backend_my_tool");
            assert_eq!(ns.original_name, "my_tool");
            assert_eq!(ns.backend_name, "backend");
        }

        #[test]
        fn definition_has_namespaced_name() {
            let tool = make_tool("tool");
            let ns = NamespacedTool::new("prefix", tool);
            assert_eq!(ns.definition.name, "prefix_tool");
        }
    }
}
