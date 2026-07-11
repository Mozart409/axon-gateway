//! Proxy-path integration tests.
//!
//! These spin up one or more in-process mock MCP backends, point the real
//! gateway binary at them, and assert the gateway's core job: connect to a
//! backend, aggregate and namespace its tools, and route `tools/call` to the
//! backend that owns the tool.

mod support;

use std::time::Duration;

use support::mock_backend::MockBackend;
use support::{ConfigBuilder, Gateway, free_port, poll_until, rpc, rpc_call};

/// Fetch `tools/list` and return the namespaced tool names.
async fn list_tool_names(client: &reqwest::Client, base: &str) -> Vec<String> {
    let body: serde_json::Value = client
        .post(format!("{base}/mcp"))
        .json(&rpc("tools/list"))
        .send()
        .await
        .expect("tools/list request")
        .json()
        .await
        .expect("tools/list json");
    body["result"]["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Poll until the gateway reports at least `n` tools (backends connect async).
async fn wait_for_tools(client: &reqwest::Client, base: &str, n: usize) -> Vec<String> {
    poll_until(50, Duration::from_millis(100), || async {
        let names = list_tool_names(client, base).await;
        (names.len() >= n).then_some(names)
    })
    .await
    .unwrap_or_default()
}

#[tokio::test]
async fn aggregates_and_namespaces_backend_tools() {
    let backend = MockBackend::start(&["echo", "add"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    let names = wait_for_tools(&client, &server.base, 2).await;
    assert!(
        names.contains(&"mock_echo".to_string()),
        "expected namespaced 'mock_echo', got {names:?}"
    );
    assert!(
        names.contains(&"mock_add".to_string()),
        "expected namespaced 'mock_add', got {names:?}"
    );
}

#[tokio::test]
async fn routes_tool_call_to_owning_backend() {
    let backend = MockBackend::start(&["echo"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    wait_for_tools(&client, &server.base, 1).await;

    let resp: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc_call("mock_echo", serde_json::json!({ "value": 42 })))
        .send()
        .await
        .expect("tools/call request")
        .json()
        .await
        .expect("tools/call json");

    // The mock echoes "<tool>:<args>"; the gateway strips the namespace so the
    // backend sees the original name "echo".
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.starts_with("echo:"),
        "expected echoed original tool name, got {resp:?}"
    );
    assert!(
        text.contains("42"),
        "expected arguments forwarded, got {text}"
    );

    // The backend recorded exactly one call, under its un-namespaced name.
    assert_eq!(backend.call_count("echo"), 1);
    assert_eq!(backend.call_count("mock_echo"), 0);
}

#[tokio::test]
async fn per_backend_tool_filtering_is_applied() {
    let backend = MockBackend::start(&["allowed", "blocked"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend_filtered("mock", &backend.url(), &["allowed"])
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    let names = wait_for_tools(&client, &server.base, 1).await;
    assert!(
        names.contains(&"mock_allowed".to_string()),
        "allowed tool should be exposed, got {names:?}"
    );
    assert!(
        !names.contains(&"mock_blocked".to_string()),
        "filtered tool must not be exposed, got {names:?}"
    );
}

#[tokio::test]
async fn same_tool_name_on_two_backends_does_not_collide() {
    let backend_a = MockBackend::start(&["echo"]).await;
    let backend_b = MockBackend::start(&["echo"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("alpha", &backend_a.url())
        .http_backend("beta", &backend_b.url())
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    let names = wait_for_tools(&client, &server.base, 2).await;
    assert!(names.contains(&"alpha_echo".to_string()), "got {names:?}");
    assert!(names.contains(&"beta_echo".to_string()), "got {names:?}");

    // A call to alpha_echo must reach only backend A.
    let _: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc_call("alpha_echo", serde_json::json!({})))
        .send()
        .await
        .expect("call alpha")
        .json()
        .await
        .expect("alpha json");

    assert_eq!(backend_a.call_count("echo"), 1);
    assert_eq!(backend_b.call_count("echo"), 0);
}

#[tokio::test]
async fn tool_level_backend_error_propagates() {
    let backend = support::mock_backend::MockBackendBuilder::new()
        .failing_tool("boom")
        .build()
        .await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    wait_for_tools(&client, &server.base, 1).await;

    let resp: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc_call("mock_boom", serde_json::json!({})))
        .send()
        .await
        .expect("call failing tool")
        .json()
        .await
        .expect("failing json");

    // The backend returned a tool-level error (isError=true), which the gateway
    // forwards as a successful JSON-RPC response carrying the error content.
    let is_error = resp["result"]["isError"].as_bool().unwrap_or(false);
    assert!(
        is_error,
        "expected tool-level error to propagate, got {resp:?}"
    );
    assert_eq!(backend.call_count("boom"), 1);
}
