//! Shared integration-test helpers.
//!
//! Each integration test binary pulls this in with `mod support;`. Not every
//! test uses every helper, so dead-code warnings are expected and silenced.
#![allow(dead_code)]

pub mod mock_backend;

use std::process::{Child, Command};
use std::time::Duration;

use tempfile::NamedTempFile;

const BIN: &str = env!("CARGO_BIN_EXE_axon-gateway");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Grab a free TCP port by binding to :0 and releasing it. A small race window
/// exists before the gateway rebinds, which is acceptable for tests.
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Fluent builder for a gateway TOML config.
///
/// `backends` is a required root-level key, so it is always emitted before the
/// first `[table]` header.
pub struct ConfigBuilder {
    bind: String,
    base_url: String,
    auth_token: Option<String>,
    backends: Vec<String>,
}

impl ConfigBuilder {
    /// Start a config bound to `bind` (e.g. `127.0.0.1:8080`).
    pub fn new(bind: &str) -> Self {
        Self {
            bind: bind.to_string(),
            base_url: format!("http://{bind}"),
            auth_token: None,
            backends: Vec::new(),
        }
    }

    pub fn auth_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Add an HTTP-transport backend pointing at `url`.
    pub fn http_backend(mut self, name: &str, url: &str) -> Self {
        self.backends.push(format!(
            "[[backends]]\nname = \"{name}\"\nurl = \"{url}\"\ntransport = \"http\"\n"
        ));
        self
    }

    /// Add an HTTP-transport backend restricted to `allowed_tools`.
    pub fn http_backend_filtered(mut self, name: &str, url: &str, allowed_tools: &[&str]) -> Self {
        let allowed = allowed_tools
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ");
        self.backends.push(format!(
            "[[backends]]\nname = \"{name}\"\nurl = \"{url}\"\ntransport = \"http\"\nallowed_tools = [{allowed}]\n"
        ));
        self
    }

    /// Append a raw `[[backends]]` block (for exotic cases like unreachable URLs).
    pub fn raw_backend(mut self, block: &str) -> Self {
        self.backends.push(block.to_string());
        self
    }

    /// Render the TOML document.
    ///
    /// `backends` is a required root-level key. When there are no backend
    /// blocks we emit `backends = []` (before any table header, as required);
    /// otherwise the `[[backends]]` array-of-tables supplies the key and
    /// emitting the empty array too would be a TOML redefinition.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        if self.backends.is_empty() {
            out.push_str("backends = []\n\n");
        }
        let _ = write!(
            out,
            "[gateway]\nbind = \"{}\"\nbase_url = \"{}\"\n",
            self.bind, self.base_url
        );
        if let Some(token) = &self.auth_token {
            let _ = writeln!(out, "auth_token = \"{token}\"");
        }
        out.push('\n');
        for backend in &self.backends {
            out.push_str(backend);
            out.push('\n');
        }
        out
    }
}

/// A running gateway process bound to an ephemeral port. Killed on drop; the
/// config file is a `NamedTempFile` cleaned up automatically.
pub struct Gateway {
    child: Child,
    pub base: String,
    config: NamedTempFile,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// Spawn the gateway binary with `config` TOML and wait until it is ready.
    pub async fn start(config: &str, base: &str) -> Self {
        let mut file = NamedTempFile::new().expect("create temp config");
        std::io::Write::write_all(&mut file, config.as_bytes()).expect("write config");

        let child = Command::new(BIN)
            .arg(file.path())
            // ServeFile routes resolve assets relative to CWD.
            .current_dir(MANIFEST_DIR)
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("gateway binary should start");

        let gateway = Gateway {
            child,
            base: base.to_string(),
            config: file,
        };
        gateway.wait_ready().await;
        gateway
    }

    /// Overwrite the config file in place (to trigger the hot-reload watcher).
    pub fn rewrite_config(&self, config: &str) {
        std::fs::write(self.config.path(), config).expect("rewrite config");
    }

    /// Atomically replace the config file via `rename(2)` — the way editors and
    /// atomic config deploys (e.g. a symlink/store swap) mutate a file. This
    /// detaches any inotify watch bound to the *original* inode, so it exercises
    /// the watcher's directory-level watching rather than a file-inode watch.
    pub fn replace_config_atomically(&self, config: &str) {
        let dir = self
            .config
            .path()
            .parent()
            .expect("config has a parent dir");
        let mut tmp = NamedTempFile::new_in(dir).expect("create sibling temp config");
        std::io::Write::write_all(&mut tmp, config.as_bytes()).expect("write new config");
        tmp.persist(self.config.path())
            .expect("atomic rename over config");
    }

    /// Poll `/health` (unauthenticated) until the server accepts requests.
    async fn wait_ready(&self) {
        let client = reqwest::Client::new();
        let health = format!("{}/health", self.base);
        for _ in 0..100 {
            if let Ok(resp) = client.get(&health).send().await
                && resp.status().is_success()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("gateway did not become ready within 10s");
    }
}

/// Build a JSON-RPC request body with empty params.
pub fn rpc(method: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {}
    })
}

/// Build a `tools/call` JSON-RPC request. `arguments` is moved into `params`.
pub fn rpc_call(name: &str, arguments: serde_json::Value) -> serde_json::Value {
    let mut params = serde_json::Map::new();
    params.insert("name".to_string(), name.into());
    params.insert("arguments".to_string(), arguments);
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": params
    })
}

/// Poll `f` until it returns `Some`, up to `attempts` at `delay` intervals.
pub async fn poll_until<T, F, Fut>(attempts: u32, delay: Duration, mut f: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..attempts {
        if let Some(v) = f().await {
            return Some(v);
        }
        tokio::time::sleep(delay).await;
    }
    None
}
