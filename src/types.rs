//! Core types for the MCP Gateway

use std::borrow::Cow;

use kameo::Reply;
use rmcp::model::{Prompt, Resource, Tool};
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

/// A resource definition as returned by MCP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl From<Resource> for ResourceDefinition {
    fn from(resource: Resource) -> Self {
        Self {
            uri: resource.uri.clone(),
            name: Some(resource.name.clone()),
            description: resource.description.clone(),
            mime_type: resource.mime_type.clone(),
        }
    }
}

/// A namespaced resource with routing info
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NamespacedResource {
    /// Original URI from backend
    pub original_uri: String,
    /// Namespaced URI: `{backend}://{original_path}`
    pub namespaced_uri: String,
    /// Which backend owns this resource
    pub backend_name: String,
    /// The resource definition (with namespaced URI)
    pub definition: ResourceDefinition,
}

impl NamespacedResource {
    pub fn new(backend_name: &str, resource: ResourceDefinition) -> Self {
        // Namespace by prefixing with backend name
        let namespaced_uri = format!("{backend_name}://{}", resource.uri);
        let mut namespaced_def = resource.clone();
        namespaced_def.uri.clone_from(&namespaced_uri);
        namespaced_def.name = namespaced_def
            .name
            .map(|name| format!("{} {name}", display_backend_name(backend_name)));

        Self {
            original_uri: resource.uri,
            namespaced_uri,
            backend_name: backend_name.to_string(),
            definition: namespaced_def,
        }
    }
}

fn display_backend_name(backend_name: &str) -> String {
    backend_name
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(capitalize_first)
        .collect::<Vec<_>>()
        .join(" ")
}

fn capitalize_first(value: &str) -> String {
    let mut chars = value.chars();
    let first = chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_default();
    let rest = chars.as_str().to_lowercase();
    format!("{first}{rest}")
}

/// A prompt definition as returned by MCP servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDefinition {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

impl From<Prompt> for PromptDefinition {
    fn from(prompt: Prompt) -> Self {
        Self {
            name: prompt.name,
            description: prompt.description,
            arguments: prompt.arguments.map(|args| {
                args.into_iter()
                    .map(|arg| PromptArgument {
                        name: arg.name,
                        description: arg.description,
                        required: arg.required,
                    })
                    .collect()
            }),
        }
    }
}

/// A namespaced prompt with routing info
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NamespacedPrompt {
    /// Original prompt name from backend
    pub original_name: String,
    /// Namespaced name: "{backend}_{original}"
    pub namespaced_name: String,
    /// Which backend owns this prompt
    pub backend_name: String,
    /// The prompt definition (with namespaced name)
    pub definition: PromptDefinition,
}

impl NamespacedPrompt {
    pub fn new(backend_name: &str, prompt: PromptDefinition) -> Self {
        let namespaced_name = format!("{backend_name}_{}", prompt.name);
        let mut namespaced_def = prompt.clone();
        namespaced_def.name.clone_from(&namespaced_name);

        Self {
            original_name: prompt.name,
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

#[cfg(test)]
mod tests {
    use super::{NamespacedResource, ResourceDefinition};

    #[test]
    fn namespaced_resource_prefixes_display_name_with_backend() {
        let resource = ResourceDefinition {
            uri: String::from("http://localhost:20212/openapi.json"),
            name: Some(String::from("OpenApi Specification")),
            description: None,
            mime_type: None,
        };

        let namespaced = NamespacedResource::new("netalertx", resource);

        assert_eq!(
            namespaced.definition.name,
            Some(String::from("Netalertx OpenApi Specification"))
        );
        assert_eq!(
            namespaced.definition.uri,
            String::from("netalertx://http://localhost:20212/openapi.json")
        );
    }

    #[test]
    fn namespaced_resource_humanizes_backend_name_with_separators() {
        let resource = ResourceDefinition {
            uri: String::from("stdout.log"),
            name: Some(String::from("stdout.log")),
            description: None,
            mime_type: None,
        };

        let namespaced = NamespacedResource::new("home_assistant-api", resource);
        assert_eq!(
            namespaced.definition.name,
            Some(String::from("Home Assistant Api stdout.log"))
        );
    }
}
