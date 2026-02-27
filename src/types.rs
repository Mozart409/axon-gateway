//! Core types for the MCP Gateway

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A tool definition as returned by MCP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// A namespaced tool with routing info
#[derive(Debug, Clone)]
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
        namespaced_def.name = namespaced_name.clone();

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

/// Info about a connected backend
#[derive(Debug, Clone)]
pub struct BackendInfo {
    pub name: String,
    pub state: BackendState,
    pub tools: Vec<NamespacedTool>,
    pub last_error: Option<String>,
}
