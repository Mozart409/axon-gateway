//! In-process mock MCP backend for integration tests.
//!
//! Spins up a real streamable-HTTP MCP server (via `rmcp`) on an ephemeral
//! port, so the gateway — running as a separate spawned binary — connects to
//! it over actual TCP exactly as it would to a production backend. This lets
//! integration tests exercise the full proxy path: connect, aggregate/namespace
//! tools, and route `tools/call` to the right backend.
//!
//! The mock records every `tools/call` it receives so tests can assert the
//! gateway routed correctly, and individual tools can be configured to return
//! tool-level errors, to send progress notifications, or to wait until the
//! request is cancelled.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ProgressNotificationParam, ServerCapabilities,
    ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpServerConfig;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// A single recorded `tools/call` invocation.
#[derive(Debug, Clone)]
pub struct CallRecord {
    pub tool: String,
    pub arguments: Value,
}

/// Shared, interior-mutable state behind the mock handler.
struct MockState {
    tools: Vec<Tool>,
    failing: HashSet<String>,
    slow: HashMap<String, Duration>,
    /// Tools that send this many progress notifications before returning.
    progress: HashMap<String, u32>,
    /// Tools that wait until their request is cancelled.
    cancellable: HashSet<String>,
    /// Cancellable tools whose request was cancelled.
    cancelled: Mutex<HashSet<String>>,
    calls: Mutex<Vec<CallRecord>>,
}

#[derive(Clone)]
struct MockHandler {
    state: Arc<MockState>,
}

impl ServerHandler for MockHandler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("mock-backend", "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.state.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let arguments = request.arguments.clone().map_or(Value::Null, Value::Object);

        self.state.calls.lock().unwrap().push(CallRecord {
            tool: name.clone(),
            arguments: arguments.clone(),
        });

        if let Some(steps) = self.state.progress.get(&name)
            && let Some(token) = context.meta.get_progress_token()
        {
            for step in 1..=*steps {
                let _ = context
                    .peer
                    .notify_progress(
                        ProgressNotificationParam::new(token.clone(), f64::from(step))
                            .with_total(f64::from(*steps))
                            .with_message(format!("{name} step {step}")),
                    )
                    .await;
            }
        }

        if self.state.cancellable.contains(&name) {
            // Wait for the cancellation (a generous cap keeps a broken test
            // from leaving the request hanging forever).
            tokio::select! {
                () = context.ct.cancelled() => {
                    self.state.cancelled.lock().unwrap().insert(name.clone());
                }
                () = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "mock tool '{name}' was cancelled"
            ))])
            .into());
        }

        if let Some(delay) = self.state.slow.get(&name) {
            tokio::time::sleep(*delay).await;
        }

        if self.state.failing.contains(&name) {
            return Ok(CallToolResult::error(vec![ContentBlock::text(format!(
                "mock backend deliberately failed tool '{name}'"
            ))])
            .into());
        }

        // Echo the call back so tests can assert on routing and payload.
        Ok(CallToolResult::success(vec![ContentBlock::text(format!("{name}:{arguments}"))]).into())
    }
}

/// A running mock backend. The server is torn down when this is dropped.
pub struct MockBackend {
    base_url: String,
    state: Arc<MockState>,
    shutdown: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockBackend {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.handle.abort();
    }
}

impl MockBackend {
    /// Start a mock backend exposing `tools`, all of which succeed by echoing.
    pub async fn start(tools: &[&str]) -> Self {
        let mut builder = MockBackendBuilder::new();
        for tool in tools {
            builder = builder.tool(tool);
        }
        builder.build().await
    }

    /// The MCP endpoint URL to put in a gateway `[[backends]]` `url` field.
    pub fn url(&self) -> String {
        format!("{}/mcp", self.base_url)
    }

    /// How many times `tool` was called on this backend.
    pub fn call_count(&self, tool: &str) -> usize {
        self.state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.tool == tool)
            .count()
    }

    /// Whether a `wait_for_cancel` tool's request was cancelled.
    pub fn was_cancelled(&self, tool: &str) -> bool {
        self.state.cancelled.lock().unwrap().contains(tool)
    }

    /// A snapshot of every recorded call.
    pub fn calls(&self) -> Vec<CallRecord> {
        self.state.calls.lock().unwrap().clone()
    }
}

/// Builder for a [`MockBackend`] with per-tool behaviour.
pub struct MockBackendBuilder {
    tools: Vec<Tool>,
    failing: HashSet<String>,
    slow: HashMap<String, Duration>,
    progress: HashMap<String, u32>,
    cancellable: HashSet<String>,
}

impl MockBackendBuilder {
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            failing: HashSet::new(),
            slow: HashMap::new(),
            progress: HashMap::new(),
            cancellable: HashSet::new(),
        }
    }

    /// Add a tool that sends `steps` progress notifications (to the request's
    /// progress token, if it has one) and then succeeds.
    pub fn progress_tool(mut self, name: &str, steps: u32) -> Self {
        self.tools.push(make_tool(name));
        self.progress.insert(name.to_string(), steps);
        self
    }

    /// Add a tool that waits until its request is cancelled, recording that
    /// it was (see [`MockBackend::was_cancelled`]).
    pub fn wait_for_cancel_tool(mut self, name: &str) -> Self {
        self.tools.push(make_tool(name));
        self.cancellable.insert(name.to_string());
        self
    }

    /// Add a tool that succeeds, but only after sleeping for `delay`.
    pub fn slow_tool(mut self, name: &str, delay: Duration) -> Self {
        self.tools.push(make_tool(name));
        self.slow.insert(name.to_string(), delay);
        self
    }

    /// Add a tool that succeeds (echoes its arguments).
    pub fn tool(mut self, name: &str) -> Self {
        self.tools.push(make_tool(name));
        self
    }

    /// Add a tool that succeeds and is annotated `readOnlyHint: true`.
    pub fn read_only_tool(mut self, name: &str) -> Self {
        self.tools
            .push(make_tool(name).with_annotations(ToolAnnotations::new().read_only(true)));
        self
    }

    /// Add a tool that always returns a tool-level error.
    pub fn failing_tool(mut self, name: &str) -> Self {
        self.tools.push(make_tool(name));
        self.failing.insert(name.to_string());
        self
    }

    /// Bind an ephemeral port and start serving. Panics on bind failure.
    pub async fn build(self) -> MockBackend {
        let state = Arc::new(MockState {
            tools: self.tools,
            failing: self.failing,
            slow: self.slow,
            progress: self.progress,
            cancellable: self.cancellable,
            cancelled: Mutex::new(HashSet::new()),
            calls: Mutex::new(Vec::new()),
        });

        let handler = MockHandler {
            state: state.clone(),
        };
        let service = StreamableHttpService::new(
            move || Ok(handler.clone()),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

        let router = axum::Router::new().nest_service("/mcp", service);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock backend port");
        let addr = listener.local_addr().expect("mock backend local addr");
        let base_url = format!("http://{addr}");

        let shutdown = CancellationToken::new();
        let shutdown_child = shutdown.clone();
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown_child.cancelled().await })
                .await;
        });

        MockBackend {
            base_url,
            state,
            shutdown,
            handle,
        }
    }
}

impl Default for MockBackendBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A tool with a permissive `{ "type": "object" }` input schema.
fn make_tool(name: &str) -> Tool {
    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    Tool::new(
        name.to_string(),
        format!("mock tool {name}"),
        Arc::new(schema),
    )
}
