//! Shared integration-test helpers.
//!
//! Each integration test binary pulls this in with `mod support;`. Not every
//! test uses every helper, so dead-code warnings are expected and silenced.
#![allow(dead_code)]

pub mod mock_backend;
pub mod mock_oidc;
pub mod mock_upstream;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const BIN: &str = env!("CARGO_BIN_EXE_axon-gateway");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// The key a gateway with a database needs for personal backends; a test key,
/// at least 32 characters.
const TEST_KEK: &str = "axon-integration-test-kek-0123456789abcdef";

/// A free TCP port for a gateway to bind. It comes from below the kernel's
/// ephemeral range (32768 and up on Linux), so the mocks' `:0` listeners never
/// take it before the gateway binds, and a port is handed out once per test
/// binary, so two tests never share one.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    // Each test binary starts at its own offset; the binaries run one after another
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let start = 20_000 + u16::try_from(std::process::id() % 1_000).unwrap() * 10;
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed) % 12_000;
        let port = 20_000 + (start - 20_000 + offset) % 12_000;
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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
    rate_limit_per_minute: Option<u32>,
    idle_timeout_secs: Option<u64>,
    personal_backends: Option<String>,
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
            rate_limit_per_minute: None,
            idle_timeout_secs: None,
            personal_backends: None,
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

    /// Set `[gateway] rate_limit_per_minute` (the per-PAT limit in multi-user mode).
    pub fn rate_limit_per_minute(mut self, limit: u32) -> Self {
        self.rate_limit_per_minute = Some(limit);
        self
    }

    /// Set `[gateway] idle_timeout_secs` (disconnect idle connections after this long).
    pub fn idle_timeout_secs(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = Some(secs);
        self
    }

    /// Add a `[personal_backends]` section; `toml` holds its keys as is
    /// (e.g. `egress_allow = ["127.0.0.1/32"]`).
    pub fn personal_backends(mut self, toml: &str) -> Self {
        self.personal_backends = Some(toml.to_string());
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
        if let Some(limit) = self.rate_limit_per_minute {
            let _ = writeln!(out, "rate_limit_per_minute = {limit}");
        }
        if let Some(secs) = self.idle_timeout_secs {
            let _ = writeln!(out, "idle_timeout_secs = {secs}");
        }
        out.push('\n');
        for backend in &self.backends {
            out.push_str(backend);
            out.push('\n');
        }
        if let Some(url_env) = &self.database_url_env {
            let _ = writeln!(out, "[database]\nurl_env = \"{url_env}\"\n");
        }
        if let Some(personal) = &self.personal_backends {
            let _ = writeln!(out, "[personal_backends]\n{personal}\n");
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

/// How a config with a `[database]` section runs: the configuration lives in
/// the database, so the file is imported once (`admin import-config`) and the
/// gateway then starts from the environment alone.
#[derive(Clone)]
struct DbMode {
    /// The value of the variable `[database] url_env` names.
    url: String,
    bind: String,
    base_url: String,
    allow_stdio: bool,
}

impl DbMode {
    /// `None` for a standalone config (no `[database]` section, or a file that
    /// is not TOML, which the gateway then refuses itself).
    fn detect(config: &str, base: &str, env: &[(String, String)]) -> Option<Self> {
        let table: toml::Table = toml::from_str(config).ok()?;
        let database = table.get("database")?.as_table()?;
        let url_env = database
            .get("url_env")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("[database] needs a url_env"));
        let url = env
            .iter()
            .find(|(name, _)| name == url_env)
            .map(|(_, value)| value.clone())
            .or_else(|| std::env::var(url_env).ok())
            .unwrap_or_else(|| panic!("the database URL variable {url_env} is not set"));
        let gateway = table.get("gateway").and_then(toml::Value::as_table);
        let text = |key: &str| {
            gateway
                .and_then(|gateway| gateway.get(key))
                .and_then(toml::Value::as_str)
                .map(str::to_string)
        };
        Some(Self {
            url,
            bind: text("bind").unwrap_or_else(|| panic!("[gateway] needs a bind")),
            base_url: text("base_url").unwrap_or_else(|| base.to_string()),
            allow_stdio: gateway
                .and_then(|gateway| gateway.get("allow_stdio"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
        })
    }
}

fn owned_env(env: &[(&str, &str)]) -> Vec<(String, String)> {
    env.iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

/// The gateway binary as a process: in database mode with the bootstrap
/// environment and no config path, otherwise on the config file at `path`.
fn gateway_command(path: &Path, db: Option<&DbMode>, env: &[(String, String)]) -> Command {
    let mut command = Command::new(BIN);
    command
        // ServeFile routes resolve assets relative to CWD.
        .current_dir(MANIFEST_DIR)
        .env("RUST_LOG", "warn")
        .env("AXON_KEK", TEST_KEK);
    match db {
        Some(db) => {
            command
                .env("AXON_DATABASE_URL", &db.url)
                .env("AXON_BIND", &db.bind)
                .env("AXON_BASE_URL", &db.base_url);
            if db.allow_stdio {
                command.env("AXON_ALLOW_STDIO", "true");
            }
        }
        None => {
            command.arg(path).env_remove("AXON_DATABASE_URL");
        }
    }
    command.envs(env.iter().map(|(name, value)| (name, value)));
    command
}

/// What a finished command line wrote.
pub struct CliOutput {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run the binary with `args` and `env` (plus the test key), wait up to
/// `timeout` and return what it wrote; `None` if it was still running (it is
/// killed then). Not a database-mode start: `AXON_DATABASE_URL` is only set
/// when `env` sets it.
pub fn run_cli(args: &[&str], env: &[(&str, &str)], timeout: Duration) -> Option<CliOutput> {
    use std::io::Read as _;

    let mut child = Command::new(BIN)
        .args(args)
        .current_dir(MANIFEST_DIR)
        .env("RUST_LOG", "warn")
        .env("AXON_KEK", TEST_KEK)
        .env_remove("AXON_DATABASE_URL")
        .env_remove("AXON_GATEWAY_CONFIG")
        .envs(env.iter().copied())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("gateway binary should start");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll gateway") {
            let mut stdout = String::new();
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stdout.take() {
                let _ = pipe.read_to_string(&mut stdout);
            }
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Some(CliOutput {
                status,
                stdout,
                stderr,
            });
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `axon-gateway admin import-config <file>` (plus `--dry-run` when asked)
/// against the database at `database_url`, with the test key.
pub fn import_config_cli(
    file: &Path,
    database_url: &str,
    dry_run: bool,
    env: &[(&str, &str)],
) -> CliOutput {
    let file = file.to_str().expect("utf-8 path");
    let mut args = vec!["admin", "import-config", file];
    if dry_run {
        args.push("--dry-run");
    }
    let mut env = env.to_vec();
    env.push(("AXON_DATABASE_URL", database_url));
    run_cli(&args, &env, Duration::from_secs(60)).expect("the import should finish")
}

/// `name<TAB>token` lines of the import's stdout.
fn parse_imported_tokens(stdout: &str) -> HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(name, token)| (name.to_string(), token.to_string()))
        .collect()
}

/// Import the config file at `path` the way the gateway would see the
/// environment; the new tokens it prints.
fn import_for(path: &Path, db: &DbMode, env: &[(String, String)]) -> HashMap<String, String> {
    let env: Vec<(&str, &str)> = env
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let output = import_config_cli(path, &db.url, false, &env);
    assert!(
        output.status.success(),
        "import-config failed: {}",
        output.stderr
    );
    parse_imported_tokens(&output.stdout)
}

/// A running gateway process bound to an ephemeral port. Killed on drop; the
/// config file is a `NamedTempFile` cleaned up automatically, unless the test
/// started the gateway on a path it owns ([`Gateway::start_at`]).
///
/// A config with a `[database]` section runs in database mode: the file is
/// imported with `admin import-config` first, and the gateway starts from the
/// environment alone (`AXON_DATABASE_URL`, `AXON_BIND`, `AXON_BASE_URL`, the
/// key, `AXON_ALLOW_STDIO`). Rewriting the config re-imports it.
pub struct Gateway {
    child: Child,
    pub base: String,
    config: Option<NamedTempFile>,
    config_path: PathBuf,
    db: Option<DbMode>,
    env: Vec<(String, String)>,
    /// The tokens the imports printed, by service account name.
    pub imported_tokens: HashMap<String, String>,
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

        let path = file.path().to_path_buf();
        Self::spawn(path, Some(file), base, env, &[]).await
    }

    /// Like [`Gateway::start_with_env`], with the environment variables in
    /// `env_remove` removed from the gateway process (e.g. `AXON_KEK`). The
    /// import of a database-mode config keeps them.
    pub async fn start_without_env(
        config: &str,
        base: &str,
        env: &[(&str, &str)],
        env_remove: &[&str],
    ) -> Self {
        let mut file = NamedTempFile::new().expect("create temp config");
        std::io::Write::write_all(&mut file, config.as_bytes()).expect("write config");

        let path = file.path().to_path_buf();
        Self::spawn(path, Some(file), base, env, env_remove).await
    }

    /// Spawn the gateway binary on the config file at `path`, which the test
    /// owns (it is neither written nor removed here), and wait until it is
    /// ready. For tests that lay the file out themselves, e.g. as symlinks.
    pub async fn start_at(path: &Path, base: &str, env: &[(&str, &str)]) -> Self {
        Self::spawn(path.to_path_buf(), None, base, env, &[]).await
    }

    async fn spawn(
        config_path: PathBuf,
        config: Option<NamedTempFile>,
        base: &str,
        env: &[(&str, &str)],
        env_remove: &[&str],
    ) -> Self {
        let env = owned_env(env);
        let text = std::fs::read_to_string(&config_path).expect("read config");
        let db = DbMode::detect(&text, base, &env);
        let imported_tokens = match &db {
            Some(db) => import_for(&config_path, db, &env),
            None => HashMap::new(),
        };
        let mut command = gateway_command(&config_path, db.as_ref(), &env);
        for name in env_remove {
            command.env_remove(name);
        }
        let child = command.spawn().expect("gateway binary should start");

        let gateway = Gateway {
            child,
            base: base.to_string(),
            config,
            config_path,
            db,
            env,
            imported_tokens,
        };
        gateway.wait_ready().await;
        gateway
    }

    /// The token the import printed for the service account `name`.
    pub fn token(&self, name: &str) -> &str {
        self.imported_tokens
            .get(name)
            .unwrap_or_else(|| panic!("the import printed no token for {name}"))
    }

    /// Spawn the gateway binary with `config` and wait up to `timeout` for it
    /// to exit by itself. Returns its exit status, or `None` if it was still
    /// running (it is killed then). For startup-refusal tests.
    pub fn run_to_exit(config: &str, timeout: Duration) -> Option<std::process::ExitStatus> {
        Self::run_to_exit_env(config, timeout, &[], &[]).map(|(status, _)| status)
    }

    /// Like [`Gateway::run_to_exit`], with extra environment variables, the
    /// ones in `env_remove` removed (from the gateway, not from the import of
    /// a database-mode config), and what the gateway wrote to stderr returned
    /// with its exit status.
    pub fn run_to_exit_env(
        config: &str,
        timeout: Duration,
        env: &[(&str, &str)],
        env_remove: &[&str],
    ) -> Option<(std::process::ExitStatus, String)> {
        use std::io::Read as _;

        let mut file = NamedTempFile::new().expect("create temp config");
        std::io::Write::write_all(&mut file, config.as_bytes()).expect("write config");
        let env = owned_env(env);
        let db = DbMode::detect(config, "http://127.0.0.1", &env);
        if let Some(db) = &db {
            import_for(file.path(), db, &env);
        }
        let mut command = gateway_command(file.path(), db.as_ref(), &env);
        command.stderr(std::process::Stdio::piped());
        for name in env_remove {
            command.env_remove(name);
        }
        let mut child = command.spawn().expect("gateway binary should start");
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().expect("poll gateway") {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                return Some((status, stderr));
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
    /// In database mode the file is imported again, and the gateway reloads
    /// through the change notification.
    pub fn rewrite_config(&mut self, config: &str) {
        std::fs::write(&self.config_path, config).expect("rewrite config");
        self.reimport();
    }

    /// Atomically replace the config file via `rename(2)` — the way editors and
    /// atomic config deploys (e.g. a symlink/store swap) mutate a file. This
    /// detaches any inotify watch bound to the *original* inode, so it exercises
    /// the watcher's directory-level watching rather than a file-inode watch.
    /// In database mode the file is imported again.
    pub fn replace_config_atomically(&mut self, config: &str) {
        let dir = self.config_path.parent().expect("config has a parent dir");
        let mut tmp = NamedTempFile::new_in(dir).expect("create sibling temp config");
        std::io::Write::write_all(&mut tmp, config.as_bytes()).expect("write new config");
        tmp.persist(&self.config_path)
            .expect("atomic rename over config");
        self.reimport();
    }

    fn reimport(&mut self) {
        if let Some(db) = &self.db {
            let tokens = import_for(&self.config_path, db, &self.env);
            self.imported_tokens.extend(tokens);
        }
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
