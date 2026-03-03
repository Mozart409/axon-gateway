//! Core types for the MCP Gateway

use kameo::Reply;
use std::borrow::Cow;

use rmcp::model::Tool;
use serde::{Deserialize, Serialize};

/// A tool definition as returned by MCP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

impl From<Tool> for ToolDefinition {
    fn from(tool: Tool) -> Self {
        Self {
            name: tool.name.into_owned(),
            description: tool.description.map(Cow::into_owned),
            input_schema: serde_json::to_value(&*tool.input_schema).unwrap_or_default(),
        }
    }
}

/// A namespaced tool with routing info
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NamespacedTool {
    /// Original tool name from backend
    pub original_name: String,
    /// Namespaced name: "{backend}_{original}"
    pub namespaced_name: String,
    /// Which backend owns this tool
    pub backend_name: String,
    /// The tool definition (with namespaced name)
    pub definition: ToolDefinition,
}

impl NamespacedTool {
    pub fn new(backend_name: &str, tool: ToolDefinition) -> Self {
        let namespaced_name = format!("{}_{}", backend_name, tool.name);
        let mut namespaced_def = tool.clone();
        namespaced_def.name.clone_from(&namespaced_name);

        Self {
            original_name: tool.name,
            namespaced_name,
            backend_name: backend_name.to_string(),
            definition: namespaced_def,
        }
    }
}

/// MCP JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// MCP JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize, Reply)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Backend connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Reply, Serialize)]
pub enum BackendState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
    /// Circuit breaker is open due to repeated failures
    CircuitOpen,
    /// Reconnecting after failure with exponential backoff
    Reconnecting,
}

/// Info about a connected backend
#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub name: String,
    pub state: BackendState,
    #[serde(skip_serializing)]
    pub tools: Vec<NamespacedTool>,
    /// Number of tools (serialized instead of full tool list)
    #[serde(rename = "tool_count")]
    pub tool_count: usize,
    pub last_error: Option<String>,
}

impl BackendInfo {
    /// Create a new `BackendInfo` with computed tool count
    pub fn new(
        name: String,
        state: BackendState,
        tools: Vec<NamespacedTool>,
        last_error: Option<String>,
    ) -> Self {
        let tool_count = tools.len();
        Self {
            name,
            state,
            tools,
            tool_count,
            last_error,
        }
    }
}
