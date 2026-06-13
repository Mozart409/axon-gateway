//! End-to-end integration tests.
//!
//! Unlike the unit tests (which exercise the router in-process), these spawn
//! the **real compiled binary** with a generated config and drive it over HTTP.
//! That covers the actual wiring: config loading, actor startup, graceful
//! readiness, auth middleware, and the JSON-RPC surface.

use std::process::{Child, Command};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_axon-gateway");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// A running gateway process bound to an ephemeral port. Killed on drop.
struct TestServer {
    child: Child,
    base: String,
    config_path: std::path::PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Grab a free TCP port by binding to :0 and releasing it. A small race window
/// exists before the gateway rebinds, which is acceptable for tests.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Spawn the gateway binary with a generated config and wait until it is ready.
async fn start_server(auth_token: Option<&str>) -> TestServer {
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    let auth_line = auth_token.map_or_else(String::new, |t| format!("auth_token = \"{t}\"\n"));
    // `backends` is a required root-level key, so it must appear before the
    // first `[table]` header.
    let config = format!(
        "backends = []\n\n[gateway]\nbind = \"{bind}\"\nbase_url = \"{base}\"\n{auth_line}"
    );

    let config_path =
        std::env::temp_dir().join(format!("axon-e2e-{}-{port}.toml", std::process::id()));
    std::fs::write(&config_path, config).expect("write config");

    let child = Command::new(BIN)
        .arg(&config_path)
        // ServeFile routes resolve assets relative to CWD.
        .current_dir(MANIFEST_DIR)
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("gateway binary should start");

    let server = TestServer {
        child,
        base: base.clone(),
        config_path,
    };

    // Poll /health (unauthenticated) until the server is accepting requests.
    let client = reqwest::Client::new();
    let health = format!("{base}/health");
    for _ in 0..100 {
        if let Ok(resp) = client.get(&health).send().await
            && resp.status().is_success()
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("gateway did not become ready within 10s");
}

fn rpc(method: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {}
    })
}

#[tokio::test]
async fn serves_status_and_mcp_without_auth() {
    let server = start_server(None).await;
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
    let server = start_server(Some(token)).await;
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
