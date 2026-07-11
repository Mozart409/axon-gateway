//! End-to-end integration tests.
//!
//! Unlike the unit tests (which exercise the router in-process), these spawn
//! the **real compiled binary** with a generated config and drive it over HTTP.
//! That covers the actual wiring: config loading, actor startup, graceful
//! readiness, auth middleware, and the JSON-RPC surface.

mod support;

use support::{ConfigBuilder, Gateway, free_port, rpc};

#[tokio::test]
async fn serves_status_and_mcp_without_auth() {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind).render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();

    // Health.
    let health: serde_json::Value = client
        .get(format!("{}/health", server.base))
        .send()
        .await
        .expect("health request")
        .json()
        .await
        .expect("health json");
    assert_eq!(health["status"], "ok");

    // Status reports zero backends for an empty config.
    let status: serde_json::Value = client
        .get(format!("{}/status", server.base))
        .send()
        .await
        .expect("status request")
        .json()
        .await
        .expect("status json");
    assert_eq!(status["backend_count"], 0);

    // Build metadata is exposed.
    let build: serde_json::Value = client
        .get(format!("{}/build", server.base))
        .send()
        .await
        .expect("build request")
        .json()
        .await
        .expect("build json");
    assert!(build["version"].is_string());

    // MCP initialize handshake.
    let init: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc("initialize"))
        .send()
        .await
        .expect("initialize request")
        .json()
        .await
        .expect("initialize json");
    assert_eq!(init["result"]["serverInfo"]["name"], "axon-gateway");

    // tools/list returns an empty set when no backends are configured.
    let tools: serde_json::Value = client
        .post(format!("{}/mcp", server.base))
        .json(&rpc("tools/list"))
        .send()
        .await
        .expect("tools/list request")
        .json()
        .await
        .expect("tools/list json");
    assert_eq!(
        tools["result"]["tools"].as_array().map(Vec::len),
        Some(0),
        "expected no tools, got {tools:?}"
    );
}

#[tokio::test]
async fn enforces_bearer_auth_on_mcp() {
    let token = "s3cret-token";
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");
    let config = ConfigBuilder::new(&bind).auth_token(token).render();
    let server = Gateway::start(&config, &base).await;
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", server.base);

    // No Authorization header -> 401.
    let missing = client
        .post(&mcp)
        .json(&rpc("initialize"))
        .send()
        .await
        .expect("request without auth");
    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Wrong token -> 401.
    let wrong = client
        .post(&mcp)
        .bearer_auth("not-the-token")
        .json(&rpc("initialize"))
        .send()
        .await
        .expect("request with wrong token");
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Correct token -> 200 and a valid handshake.
    let ok = client
        .post(&mcp)
        .bearer_auth(token)
        .json(&rpc("initialize"))
        .send()
        .await
        .expect("request with correct token");
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = ok.json().await.expect("ok json");
    assert_eq!(body["result"]["serverInfo"]["name"], "axon-gateway");
}
