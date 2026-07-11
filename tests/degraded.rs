//! Degraded and error-path integration tests.
//!
//! Covers behaviour the happy-path tests don't: an unreachable backend, the
//! Prometheus `/metrics` scrape, malformed JSON-RPC input, and calls to tools
//! that don't exist. The theme is that none of these should take the gateway
//! down — it degrades, it reports, it returns errors.

mod support;

use std::time::Duration;

use support::mock_backend::MockBackend;
use support::{ConfigBuilder, Gateway, free_port, poll_until, rpc, rpc_call};

#[tokio::test]
async fn unreachable_backend_is_degraded_but_gateway_stays_healthy() {
    // A port with nothing listening on it.
    let dead_port = free_port();
    let dead_url = format!("http://127.0.0.1:{dead_port}/mcp");

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("dead", &dead_url)
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    // The gateway itself is healthy despite the broken backend.
    let health = client
        .get(format!("{}/health", server.base))
        .send()
        .await
        .expect("health request");
    assert!(health.status().is_success());

    // The backend is still counted (it's configured), just not connected.
    let status: serde_json::Value = client
        .get(format!("{}/status", server.base))
        .send()
        .await
        .expect("status request")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["backend_count"], 1);

    // Detailed status reports the backend in a non-connected state with no tools.
    let detailed: serde_json::Value = client
        .get(format!("{}/status/detailed", server.base))
        .send()
        .await
        .expect("detailed request")
        .json()
        .await
        .expect("detailed json");
    let backend = &detailed["backends"][0];
    assert_eq!(backend["name"], "dead");
    assert_ne!(
        backend["state"], "Connected",
        "unreachable backend must not report Connected, got {detailed:?}"
    );

    // No tools are exposed from a backend that never connected.
    let tools: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc("tools/list"))
        .send()
        .await
        .expect("tools/list request")
        .json()
        .await
        .expect("tools/list json");
    assert_eq!(tools["result"]["tools"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn metrics_endpoint_serves_prometheus_text() {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind).render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    // Generate some request activity so a counter is registered.
    for _ in 0..3 {
        let _ = client
            .get(format!("{}/status", server.base))
            .send()
            .await
            .expect("status request");
    }

    // The request-counting middleware records asynchronously; poll for it.
    let body = poll_until(30, Duration::from_millis(100), || async {
        let text = client
            .get(format!("{}/metrics", server.base))
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        text.contains("axon_requests_total").then_some(text)
    })
    .await;

    let body = body.expect("metrics should expose axon_requests_total");
    // Prometheus text exposition format includes HELP/TYPE comment lines.
    assert!(
        body.contains("# TYPE axon_requests_total"),
        "expected Prometheus exposition format, got:\n{body}"
    );
}

#[tokio::test]
async fn malformed_json_rpc_is_rejected_without_crashing() {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind).render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    // Body that isn't valid JSON at all.
    let not_json = client
        .post(&mcp)
        .header("content-type", "application/json")
        .body("this is not json")
        .send()
        .await
        .expect("garbage request");
    assert!(
        not_json.status().is_client_error(),
        "malformed body should be a 4xx, got {}",
        not_json.status()
    );

    // Valid JSON but missing the required JSON-RPC fields.
    let wrong_shape = client
        .post(&mcp)
        .json(&serde_json::json!({ "foo": "bar" }))
        .send()
        .await
        .expect("wrong-shape request");
    assert!(
        wrong_shape.status().is_client_error(),
        "wrong-shape body should be a 4xx, got {}",
        wrong_shape.status()
    );

    // The gateway is still alive and serving after bad input.
    let health = client
        .get(format!("{}/health", server.base))
        .send()
        .await
        .expect("post-garbage health");
    assert!(health.status().is_success());
}

#[tokio::test]
async fn calling_an_unknown_tool_returns_json_rpc_error() {
    let backend = MockBackend::start(&["echo"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    let resp: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc_call("mock_does_not_exist", serde_json::json!({})))
        .send()
        .await
        .expect("unknown tool request")
        .json()
        .await
        .expect("unknown tool json");

    // Method-not-found for an unroutable tool name.
    assert_eq!(
        resp["error"]["code"], -32601,
        "expected method-not-found error, got {resp:?}"
    );
    // The real tool was never invoked.
    assert_eq!(backend.call_count("does_not_exist"), 0);
}
