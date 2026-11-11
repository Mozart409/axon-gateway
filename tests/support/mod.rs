//! Shared integration-test helpers.
//!
//! Each integration test binary pulls this in with `mod support;`. Not every
//! test uses every helper, so dead-code warnings are expected and silenced.
#![allow(dead_code)]

pub mod mock_backend;
pub mod mock_oidc;

use std::process::{Child, Command};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
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
    allow_stdio: bool,
    allowed_hosts: Vec<String>,
    backends: Vec<String>,
    database_url_env: Option<String>,
    oidc_providers: Vec<String>,
    rbac: Option<String>,
}

impl ConfigBuilder {
    /// Start a config bound to `bind` (e.g. `127.0.0.1:8080`).
    pub fn new(bind: &str) -> Self {
        Self {
            bind: bind.to_string(),
            base_url: format!("http://{bind}"),
            auth_token: None,
            allow_stdio: false,
            allowed_hosts: Vec::new(),
            backends: Vec::new(),
            database_url_env: None,
            oidc_providers: Vec::new(),
            rbac: None,
        }
    }

    pub fn auth_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Set `[gateway] allow_stdio`.
    pub fn allow_stdio(mut self, allow: bool) -> Self {
        self.allow_stdio = allow;
        self
    }

    /// Set `[gateway] allowed_hosts` (extra accepted MCP `Host` header values).
    pub fn allowed_hosts(mut self, hosts: &[&str]) -> Self {
        self.allowed_hosts = hosts.iter().map(|h| (*h).to_string()).collect();
        self
    }

    /// Add a stdio-transport backend running `command`. The gateway only
    /// starts with it when `allow_stdio` is set.
    pub fn stdio_backend(mut self, name: &str, command: &str) -> Self {
        self.backends.push(format!(
            "[[backends]]\nname = \"{name}\"\ncommand = \"{command}\"\ntransport = \"stdio\"\n"
        ));
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

    /// Add a `[database]` section whose URL is read from the `url_env`
    /// variable (pass it to the gateway with [`Gateway::start_with_env`]).
    pub fn database(mut self, url_env: &str) -> Self {
        self.database_url_env = Some(url_env.to_string());
        self
    }

    /// Add an `[[auth.oidc]]` provider. `extra_toml` is appended to the table
    /// as is (e.g. `allowed_email_domains = ["corp.example"]`).
    pub fn oidc_provider(
        mut self,
        id: &str,
        issuer: &str,
        client_id: &str,
        extra_toml: &str,
    ) -> Self {
        self.oidc_providers.push(format!(
            "[[auth.oidc]]\nid = \"{id}\"\nissuer = \"{issuer}\"\nclient_id = \"{client_id}\"\n{extra_toml}\n"
        ));
        self
    }

    /// Add `[rbac]` tables (`[[rbac.groups]]`, `[[rbac.grants]]`); `toml` is
    /// appended as is, after the `[[auth.oidc]]` providers.
    pub fn rbac(mut self, toml: &str) -> Self {
        self.rbac = Some(toml.to_string());
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
        if self.allow_stdio {
            out.push_str("allow_stdio = true\n");
        }
        if !self.allowed_hosts.is_empty() {
            let hosts = self
                .allowed_hosts
                .iter()
                .map(|h| format!("\"{h}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(out, "allowed_hosts = [{hosts}]");
        }
        out.push('\n');
        for backend in &self.backends {
            out.push_str(backend);
            out.push('\n');
        }
        if let Some(url_env) = &self.database_url_env {
            let _ = writeln!(out, "[database]\nurl_env = \"{url_env}\"\n");
        }
        for provider in &self.oidc_providers {
            out.push_str(provider);
            out.push('\n');
        }
        if let Some(rbac) = &self.rbac {
            out.push_str(rbac);
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
        Self::start_with_env(config, base, &[]).await
    }

    /// Like [`Gateway::start`], with extra environment variables for the
    /// gateway process.
    pub async fn start_with_env(config: &str, base: &str, env: &[(&str, &str)]) -> Self {
        let mut file = NamedTempFile::new().expect("create temp config");
        std::io::Write::write_all(&mut file, config.as_bytes()).expect("write config");

        let child = Command::new(BIN)
            .arg(file.path())
            // ServeFile routes resolve assets relative to CWD.
            .current_dir(MANIFEST_DIR)
            .env("RUST_LOG", "warn")
            .envs(env.iter().copied())
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

    /// Spawn the gateway binary with `config` and wait up to `timeout` for it
    /// to exit by itself. Returns its exit status, or `None` if it was still
    /// running (it is killed then). For startup-refusal tests.
    pub fn run_to_exit(config: &str, timeout: Duration) -> Option<std::process::ExitStatus> {
        let mut file = NamedTempFile::new().expect("create temp config");
        std::io::Write::write_all(&mut file, config.as_bytes()).expect("write config");
        let mut child = Command::new(BIN)
            .arg(file.path())
            .current_dir(MANIFEST_DIR)
            .env("RUST_LOG", "warn")
            .spawn()
            .expect("gateway binary should start");
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().expect("poll gateway") {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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

/// The stateless MCP protocol version the test helpers speak.
pub const MCP_STATELESS_VERSION: &str = "2026-07-28";

/// Add the 2026-07-28 per-request `_meta` keys to a request's `params`,
/// keeping every param (and `_meta` key) already present.
fn with_stateless_meta(body: &Value) -> Value {
    let mut body = body.clone();
    if body.get("id").is_none() {
        return body;
    }
    let Some(object) = body.as_object_mut() else {
        return body;
    };
    let params = object.entry("params").or_insert_with(|| json!({}));
    if !params.is_object() {
        *params = json!({});
    }
    let Some(params) = params.as_object_mut() else {
        return body;
    };
    let meta = params.entry("_meta").or_insert_with(|| json!({}));
    if !meta.is_object() {
        *meta = json!({});
    }
    if let Some(meta) = meta.as_object_mut() {
        for (key, value) in [
            (
                "io.modelcontextprotocol/protocolVersion",
                json!(MCP_STATELESS_VERSION),
            ),
            ("io.modelcontextprotocol/clientCapabilities", json!({})),
            (
                "io.modelcontextprotocol/clientInfo",
                json!({ "name": "axon-tests", "version": "0.0.0" }),
            ),
        ] {
            meta.entry(key).or_insert(value);
        }
    }
    body
}

/// Pick the JSON-RPC response with `id` out of a `text/event-stream` body
/// (the `data:` lines of every event).
fn response_from_sse(text: &str, id: &Value) -> Value {
    let mut last = Value::Null;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let Ok(message) = serde_json::from_str::<Value>(data.trim()) else {
            continue;
        };
        let is_response = message.get("result").is_some() || message.get("error").is_some();
        if is_response && (message.get("id") == Some(id) || id.is_null()) {
            return message;
        }
        if is_response {
            last = message;
        }
    }
    last
}

/// POST `body` as is, with exactly `headers` (plus the bearer token), and parse
/// the reply as [`mcp_request`] does. Returns the status, the response headers
/// and the JSON-RPC response (`Value::Null` for a body without an `id` or an
/// empty reply). For tests of other protocol versions and malformed requests.
pub async fn raw_post(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
    body: &Value,
    headers: &[(&str, &str)],
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let mut request = client.post(url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.json(body).send().await.expect("mcp request");
    let status = response.status();
    let response_headers = response.headers().clone();
    let is_sse = response_headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let text = response.text().await.expect("mcp response body");
    let Some(id) = body.get("id") else {
        return (status, response_headers, Value::Null);
    };
    if is_sse {
        return (status, response_headers, response_from_sse(&text, id));
    }
    if text.trim().is_empty() {
        return (status, response_headers, Value::Null);
    }
    let value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    (status, response_headers, value)
}

/// POST a JSON-RPC message to an MCP endpoint speaking the stateless
/// 2026-07-28 transport, with `extra_headers` added (e.g. a `Host` override).
///
/// Requests get the version, `Accept`, `Mcp-Method` and (for `tools/call`,
/// `prompts/get`, `resources/read`) `Mcp-Name` headers and the required
/// `_meta` keys merged into `params`. Both `application/json` and
/// `text/event-stream` replies are parsed. A notification (a body without an
/// `id`) returns the status with `Value::Null`. A body that is not JSON comes
/// back as a `Value::String`.
pub async fn mcp_request(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
    body: &Value,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let payload = with_stateless_meta(body);
    let mut headers = vec![
        ("MCP-Protocol-Version", MCP_STATELESS_VERSION),
        ("Accept", "application/json, text/event-stream"),
    ];
    let method = payload.get("method").and_then(Value::as_str);
    if let Some(method) = method {
        headers.push(("Mcp-Method", method));
        let key = match method {
            "tools/call" | "prompts/get" => Some("name"),
            "resources/read" => Some("uri"),
            _ => None,
        };
        if let Some(name) = key
            .and_then(|key| payload.pointer(&format!("/params/{key}")))
            .and_then(Value::as_str)
        {
            headers.push(("Mcp-Name", name));
        }
    }
    headers.extend_from_slice(extra_headers);
    let (status, _, value) = raw_post(client, url, bearer, &payload, &headers).await;
    (status, value)
}

/// [`mcp_request`] without extra headers.
pub async fn mcp_post(
    client: &reqwest::Client,
    url: &str,
    bearer: Option<&str>,
    body: &Value,
) -> (StatusCode, Value) {
    mcp_request(client, url, bearer, body, &[]).await
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
