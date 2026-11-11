//! End-to-end integration tests.
//!
//! Unlike the unit tests (which exercise the router in-process), these spawn
//! the **real compiled binary** with a generated config and drive it over HTTP.
//! That covers the actual wiring: config loading, actor startup, graceful
//! readiness, auth middleware, and the JSON-RPC surface.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use support::{ConfigBuilder, Gateway, free_port, mcp_post, rpc};

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

    // Stateless server discovery: no initialize handshake is needed.
    let mcp = format!("{}/mcp", server.base);
    let (status, discover) = mcp_post(&client, &mcp, None, &rpc("server/discover")).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{discover}");
    assert!(
        discover["result"]["supportedVersions"]
            .as_array()
            .is_some_and(|v| v.iter().any(|v| v == "2026-07-28")),
        "{discover}"
    );

    // tools/list returns an empty set when no backends are configured.
    let (status, tools) = mcp_post(&client, &mcp, None, &rpc("tools/list")).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{tools}");
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
    let (status, _) = mcp_post(&client, &mcp, None, &rpc("tools/list")).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);

    // Wrong token -> 401.
    let (status, _) = mcp_post(&client, &mcp, Some("not-the-token"), &rpc("tools/list")).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);

    // Correct token -> 200 and a valid response.
    let (status, body) = mcp_post(&client, &mcp, Some(token), &rpc("server/discover")).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert!(body["result"]["supportedVersions"].is_array(), "{body}");
}
