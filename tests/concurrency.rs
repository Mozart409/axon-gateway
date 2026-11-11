//! Concurrency integration tests.
//!
//! Calls to one backend must run in parallel rather than queue behind each
//! other in the backend actor.

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

mod support;

use std::time::{Duration, Instant};

use support::mock_backend::MockBackendBuilder;
use support::{ConfigBuilder, Gateway, free_port, mcp_post, poll_until, rpc, rpc_call};

const DELAY: Duration = Duration::from_millis(500);

/// Poll until the gateway lists at least one tool (backends connect async).
async fn wait_for_tools(client: &reqwest::Client, base: &str) {
    poll_until(50, Duration::from_millis(100), || async {
        let (_, body) = mcp_post(client, &format!("{base}/mcp"), None, &rpc("tools/list")).await;
        body["result"]["tools"]
            .as_array()
            .filter(|tools| !tools.is_empty())
            .map(|_| ())
    })
    .await
    .expect("gateway should list the backend tool");
}

#[tokio::test]
async fn slow_calls_to_one_backend_run_in_parallel() {
    let backend = MockBackendBuilder::new()
        .slow_tool("slow", DELAY)
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

    wait_for_tools(&client, &server.base).await;

    let call = || async {
        let (_, body) = mcp_post(
            &client,
            &format!("{}/mcp", server.base),
            None,
            &rpc_call("mock_slow", serde_json::json!({})),
        )
        .await;
        body
    };

    let started = Instant::now();
    let (first, second) = tokio::join!(call(), call());
    let elapsed = started.elapsed();

    for resp in [&first, &second] {
        assert!(
            resp["result"].is_object(),
            "expected a successful call, got {resp:?}"
        );
    }
    assert_eq!(backend.call_count("slow"), 2);
    assert!(
        elapsed < Duration::from_millis(900),
        "two {DELAY:?} calls took {elapsed:?}, they were serialized"
    );
}
