//! Hot-reload integration tests.
//!
//! Exercises the config file watcher (`src/watcher.rs`) together with the
//! gateway's `ReloadConfig` handler: rewrite the on-disk config while the
//! gateway is running and assert that backends are added and removed live,
//! without a restart.

mod support;

use std::time::Duration;

use support::mock_backend::MockBackend;
use support::{ConfigBuilder, Gateway, free_port, poll_until, rpc};

/// Number of namespaced tools the gateway currently advertises.
async fn tool_count(client: &reqwest::Client, base: &str) -> usize {
    let body: serde_json::Value = client
        .post(format!("{base}/mcp"))
        .json(&rpc("tools/list"))
        .send()
        .await
        .expect("tools/list request")
        .json()
        .await
        .expect("tools/list json");
    body["result"]["tools"].as_array().map_or(0, Vec::len)
}

/// The gateway's reported backend count.
async fn backend_count(client: &reqwest::Client, base: &str) -> u64 {
    let body: serde_json::Value = client
        .get(format!("{base}/status"))
        .send()
        .await
        .expect("status request")
        .json()
        .await
        .expect("status json");
    body["backend_count"].as_u64().unwrap_or(0)
}

#[tokio::test]
async fn adding_a_backend_hot_reloads_new_tools() {
    let backend = MockBackend::start(&["echo", "add"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    // Start with no backends.
    let empty = ConfigBuilder::new(&bind).render();
    let server = Gateway::start(&empty, &base).await;
    let client = reqwest::Client::new();
    assert_eq!(tool_count(&client, &server.base).await, 0);

    // Rewrite the config to add the mock backend.
    let with_backend = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    server.rewrite_config(&with_backend);

    // The watcher debounces (~500ms) then reloads; poll generously.
    let count = poll_until(60, Duration::from_millis(250), || async {
        let n = tool_count(&client, &server.base).await;
        (n >= 2).then_some(n)
    })
    .await;
    assert_eq!(
        count,
        Some(2),
        "new backend tools should appear after reload"
    );
    assert_eq!(backend_count(&client, &server.base).await, 1);
}

#[tokio::test]
async fn atomic_replace_of_config_hot_reloads() {
    let backend = MockBackend::start(&["echo", "add"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    // Start with no backends.
    let empty = ConfigBuilder::new(&bind).render();
    let server = Gateway::start(&empty, &base).await;
    let client = reqwest::Client::new();
    assert_eq!(tool_count(&client, &server.base).await, 0);

    // Replace the config via rename(2) rather than an in-place write. A watcher
    // bound to the file's inode would miss this (the watch follows the old,
    // now-detached inode); the directory-level watch must still catch it.
    let with_backend = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    server.replace_config_atomically(&with_backend);

    let count = poll_until(60, Duration::from_millis(250), || async {
        let n = tool_count(&client, &server.base).await;
        (n >= 2).then_some(n)
    })
    .await;
    assert_eq!(
        count,
        Some(2),
        "atomically replaced config should still hot-reload"
    );
    assert_eq!(backend_count(&client, &server.base).await, 1);
}

#[tokio::test]
async fn removing_a_backend_hot_reloads_tools_away() {
    let backend = MockBackend::start(&["echo"]).await;
    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let base = format!("http://{bind}");

    // Start with one backend.
    let with_backend = ConfigBuilder::new(&bind)
        .http_backend("mock", &backend.url())
        .render();
    let server = Gateway::start(&with_backend, &base).await;
    let client = reqwest::Client::new();

    // Wait for the backend to connect and expose its tool.
    let present = poll_until(50, Duration::from_millis(100), || async {
        (tool_count(&client, &server.base).await >= 1).then_some(())
    })
    .await;
    assert_eq!(present, Some(()), "backend should connect on startup");

    // Rewrite the config to remove all backends.
    let empty = ConfigBuilder::new(&bind).render();
    server.rewrite_config(&empty);

    let gone = poll_until(60, Duration::from_millis(250), || async {
        (tool_count(&client, &server.base).await == 0).then_some(())
    })
    .await;
    assert_eq!(gone, Some(()), "tools should disappear after reload");
    assert_eq!(backend_count(&client, &server.base).await, 0);
}
