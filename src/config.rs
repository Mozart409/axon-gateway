//! Configuration types for the MCP Gateway
//!
//! Example config.toml:
//! ```toml
//! [gateway]
//! bind = "0.0.0.0:8080"
//! base_url = "http://localhost:8080"
//! auth_token = "your-secret-token"  # optional
//! allow_stdio = true  # needed for the stdio backend below
//!
//! [[backends]]
//! name = "homeassistant"
//! url = "http://localhost:3001/mcp"
//! transport = "sse"
//!
//! [[backends]]
//! name = "jellyfin"
//! url = "http://localhost:3002/mcp"
//! transport = "http"
//!
//! [[backends]]
//! name = "proxmox"
//! command = "/usr/local/bin/proxmox-mcp"
//! args = ["--config", "/etc/proxmox-mcp.toml"]
//! transport = "stdio"
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub gateway: GatewayConfig,
    pub backends: Vec<BackendConfig>,
    /// Named API tokens with permissions
    #[serde(default)]
    pub tokens: Vec<TokenConfig>,
    /// Toolsets: expose subsets of tools via different path prefixes
    #[serde(default)]
    pub toolsets: Vec<ToolsetConfig>,
    /// Deprecated name of `toolsets` (`[[groups]]`); [`Config::load`] moves the
    /// entries into `toolsets`, so this is empty after loading.
    #[serde(default)]
    pub groups: Vec<ToolsetConfig>,
    /// Optional Postgres store; without it the gateway runs standalone.
    /// Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub database: Option<crate::store::DatabaseConfig>,
    /// How people log in to the dashboard (OIDC providers).
    /// Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub auth: AuthConfig,
    /// RBAC groups and tool grants (multi-user mode). Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub rbac: crate::policy::RbacConfig,
    /// Per-user and personal backends (limits and egress rules).
    /// Not hot-reloadable: changes need a restart.
    #[serde(default)]
    pub personal_backends: PersonalBackendsConfig,
}

/// `[personal_backends]` section: limits for per-user catalog credentials and
/// the backends people add themselves. Not hot-reloadable: changes need a restart.
#[derive(Debug, Clone, Deserialize)]
pub struct PersonalBackendsConfig {
    /// Let people add personal backends and store catalog credentials
    #[serde(default = "default_personal_enabled")]
    pub enabled: bool,
    /// Max personal backends plus catalog credentials per user
    #[serde(default = "default_personal_max_per_user")]
    pub max_per_user: u32,
    /// Max tool calls per minute per user across all backends (0 = unlimited)
    #[serde(default)]
    pub max_calls_per_minute: u32,
    /// Max per-user and personal connections open at once per replica
    #[serde(default = "default_personal_max_instances")]
    pub max_instances: u32,
    /// Host patterns or CIDRs personal backends may reach (empty = any public host)
    #[serde(default)]
    pub egress_allow: Vec<String>,
    /// Host patterns or CIDRs personal backends may never reach
    #[serde(default)]
    pub egress_deny: Vec<String>,
}

const fn default_personal_enabled() -> bool {
    true
}

const fn default_personal_max_per_user() -> u32 {
    10
}

const fn default_personal_max_instances() -> u32 {
    500
}

impl Default for PersonalBackendsConfig {
    fn default() -> Self {
        Self {
            enabled: default_personal_enabled(),
            max_per_user: default_personal_max_per_user(),
            max_calls_per_minute: 0,
            max_instances: default_personal_max_instances(),
            egress_allow: Vec::new(),
            egress_deny: Vec::new(),
        }
    }
}

/// `[auth]` section: how people log in to the dashboard.
/// Not hot-reloadable: changes need a restart.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// OIDC providers offered on the login page, in this order
    #[serde(default)]
    pub oidc: Vec<OidcProviderConfig>,
}

/// A generic OIDC provider (Entra, Pocket ID, Keycloak, ...)
#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfig {
    /// Stable id used in URLs and stored with each session: `[a-z0-9-]+`
    pub id: String,
    /// Button label on the login page; defaults to the id
    #[serde(default)]
    pub display_name: Option<String>,
    /// Issuer URL; discovery is `{issuer}/.well-known/openid-configuration`
    pub issuer: String,
    pub client_id: String,
    /// Env var holding the client secret; unset for a public (PKCE-only) client
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: Vec<String>,
    /// ID-token claim with the user's groups; a dotted path reaches into
    /// objects (`realm_access.roles`)
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// When non-empty, only these email domains may log in (case-insensitive)
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    /// Members of any of these groups are gateway admins
    #[serde(default)]
    pub admin_groups: Vec<String>,
    /// Accept JWT access tokens this provider issued as bearer tokens
    /// (resource-server mode). The subject acts as the user with that issuer
    /// and subject, or as the service account bound to it. Needs the
    /// `[database]` every provider needs.
    #[serde(default)]
    pub accept_access_tokens: bool,
    /// The `aud` an accepted access token must carry; defaults to `client_id`
    #[serde(default)]
    pub access_token_audience: Option<String>,
    /// When an Entra ID token reports a groups overage (too many groups to
    /// list), fetch the user's groups from Microsoft Graph with the app's own
    /// client credentials. Needs `client_secret_env` and the application
    /// permission `GroupMember.Read.All` (or `Directory.Read.All`).
    #[serde(default)]
    pub graph_overage: bool,
    /// Base URL of Microsoft Graph, for sovereign clouds and tests; defaults to
    /// `https://graph.microsoft.com`
    #[serde(default)]
    pub graph_url: Option<String>,
    /// ID-token claim (a dotted path, like `groups_claim`) whose value a SCIM
    /// `externalId` is matched against; defaults to `sub`
    #[serde(default)]
    pub scim_match_claim: Option<String>,
}

impl OidcProviderConfig {
    /// The Graph base URL: `graph_url`, or the public cloud's, without a
    /// trailing slash
    pub fn graph_url(&self) -> &str {
        self.graph_url
            .as_deref()
            .unwrap_or("https://graph.microsoft.com")
            .trim_end_matches('/')
    }

    /// The claim a SCIM `externalId` is matched against: `scim_match_claim`, or `sub`
    pub fn scim_match_claim(&self) -> &str {
        self.scim_match_claim.as_deref().unwrap_or("sub")
    }

    /// The audience of accepted access tokens: `access_token_audience`, or the client id
    pub fn access_token_audience(&self) -> &str {
        self.access_token_audience
            .as_deref()
            .unwrap_or(&self.client_id)
    }

    /// Button label: `display_name`, or the id when unset
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.id)
    }
}

fn default_oidc_scopes() -> Vec<String> {
    ["openid", "profile", "email"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_groups_claim() -> String {
    String::from("groups")
}

/// Toolset configuration
///
/// Expose subsets of tools via different endpoints, e.g. `/mcp/toolset/coding`
/// only exposes tools matching the configured patterns.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolsetConfig {
    /// Toolset name used as path suffix: `/mcp/toolset/{name}`
    pub name: String,
    /// Tool name patterns to include (supports `"backend_*"` globs)
    #[serde(default)]
    pub tools: Vec<String>,
    /// Backends to include (empty = all)
    #[serde(default)]
    pub backends: Vec<String>,
    /// Optional description for this toolset
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub bind: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Simple shared auth token (for backward compat)
    pub auth_token: Option<String>,
    /// Rate limit: max requests per minute per token (0 = unlimited)
    #[serde(default)]
    pub rate_limit_per_minute: u32,
    /// Allow `transport = "stdio"` backends. They spawn processes inside the
    /// gateway, so this is off by default and a stdio backend fails the load.
    #[serde(default)]
    pub allow_stdio: bool,
    /// Extra `Host` names or `host:port` pairs the MCP endpoints accept, besides
    /// loopback and the host of `base_url`
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Seconds without a call before an HTTP/SSE backend connection is closed
    /// (0 = always connected). A backend's own `idle_timeout_secs` wins, and
    /// stdio backends stay connected unless they set one.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

/// Default value for `[gateway] idle_timeout_secs`
const fn default_idle_timeout_secs() -> u64 {
    300
}

/// `Host` values the MCP endpoints accept: loopback, the host (and `host:port`)
/// of `base_url`, then `[gateway] allowed_hosts`, without duplicates
pub fn mcp_allowed_hosts(gateway: &GatewayConfig) -> Vec<String> {
    let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
        .into_iter()
        .map(String::from)
        .collect();
    if let Ok(uri) = gateway.base_url.parse::<http::Uri>()
        && let Some(host) = uri.host()
    {
        // `Uri::host` keeps the brackets of an IPv6 literal
        let host = host.trim_start_matches('[').trim_end_matches(']');
        hosts.push(host.to_string());
        if let Some(port) = uri.port_u16() {
            hosts.push(format!("{host}:{port}"));
        }
    }
    hosts.extend(gateway.allowed_hosts.iter().cloned());

    let mut seen = std::collections::HashSet::new();
    hosts.retain(|host| seen.insert(host.clone()));
    hosts
}

fn default_base_url() -> String {
    String::from("http://localhost:8080")
}

/// Per-token configuration with permissions
#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    /// Display name for this token
    pub name: String,
    /// The secret token value
    pub token: String,
    /// Allowed tool patterns (empty = all tools allowed)
    /// Supports glob-like patterns: `"backend_*"` or specific `"backend_tool_name"`
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Allowed backends (empty = all backends allowed)
    #[serde(default)]
    pub allowed_backends: Vec<String>,
    /// Rate limit override for this token (0 = use global default)
    #[serde(default)]
    pub rate_limit_per_minute: u32,
    /// Custom metadata for this token (for future use)
    #[serde(default)]
    #[allow(dead_code)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    /// Unique name, used as namespace prefix for tools
    pub name: String,

    /// For SSE/HTTP transports
    pub url: Option<String>,

    /// For stdio transport
    pub command: Option<String>,
    pub args: Option<Vec<String>>,

    /// Transport type: "sse", "http", or "stdio"
    pub transport: TransportType,

    /// Optional: only expose specific tools (empty = all)
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Optional: disable this backend without removing from config
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Optional: timeout for tool calls in seconds (default: 30)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Optional: health check interval in seconds (default: 30, 0 = disabled)
    #[serde(default = "default_health_check_interval_secs")]
    pub health_check_interval_secs: u64,

    /// Optional: max consecutive failures before circuit breaker opens (default: 3)
    #[serde(default = "default_max_consecutive_failures")]
    pub max_consecutive_failures: u32,

    /// Optional: circuit breaker cooldown in seconds (default: 60)
    #[serde(default = "default_circuit_breaker_cooldown_secs")]
    pub circuit_breaker_cooldown_secs: u64,

    /// Optional: auth token to send to this backend (Bearer token)
    pub auth_token: Option<String>,

    /// Optional: custom headers to send to this backend
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Optional: environment variables to set for stdio backends
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Optional: seconds without a call before the connection is closed
    /// (0 = always connected). Unset: the gateway default for HTTP/SSE
    /// backends, always connected for stdio (restarting a process is slow).
    pub idle_timeout_secs: Option<u64>,

    /// `shared` (default): one connection with the backend's own credentials.
    /// `per_user`: no shared connection, each user stores their own credential
    /// (`credential_fields`) and gets their own connection. `oauth`: each user
    /// connects their own account through the backend's authorization server.
    /// `passthrough`: the user's identity is exchanged for a backend token.
    #[serde(default)]
    pub credential_mode: CredentialMode,

    /// For `per_user` backends: the values each user enters, and the headers
    /// they are sent in
    #[serde(default)]
    pub credential_fields: Vec<CredentialField>,

    /// For `oauth` backends: a static client; without it the gateway uses a
    /// client ID metadata document or registers itself
    #[serde(default)]
    pub oauth: Option<UpstreamOAuthConfig>,

    /// For `passthrough` backends: how the user's token is exchanged
    #[serde(default)]
    pub passthrough: Option<PassthroughConfig>,
}

/// Whose credentials a backend connection uses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// One shared connection with the backend's own `auth_token` and `headers`
    #[default]
    Shared,
    /// A connection per user, with the credential that user stored
    PerUser,
    /// A connection per user, with the tokens the backend's authorization
    /// server gave that user
    #[serde(rename = "oauth")]
    OAuth,
    /// A connection per user, with a token exchanged from the user's identity
    Passthrough,
}

/// `[backends.oauth]`: the static OAuth client of an `oauth` backend
#[derive(Clone, Deserialize)]
pub struct UpstreamOAuthConfig {
    pub client_id: String,
    /// Env var holding the client secret; unset for a public client
    #[serde(default)]
    pub client_secret_env: Option<String>,
    /// The secret read from `client_secret_env` when the config loads
    #[serde(skip)]
    pub client_secret: Option<String>,
    /// Scopes to ask for; empty uses the ones the backend advertises
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for UpstreamOAuthConfig {
    // By hand, so the client secret can never end up in a log line.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamOAuthConfig")
            .field("client_id", &self.client_id)
            .field("client_secret_env", &self.client_secret_env)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// How a `passthrough` backend gets its token
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PassthroughGrant {
    /// RFC 8693 token exchange
    TokenExchange,
    /// Entra on-behalf-of
    EntraObo,
}

/// `[backends.passthrough]`: trade the user's identity provider token for one
/// the backend accepts
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PassthroughConfig {
    pub grant: PassthroughGrant,
    /// Id of the `[[auth.oidc]]` provider that issued the user's token; its
    /// token endpoint and client credentials are used
    pub provider: String,
    /// Token exchange `audience`
    #[serde(default)]
    pub audience: Option<String>,
    /// Token exchange `scope`; the scope of an Entra on-behalf-of request
    #[serde(default)]
    pub scope: Option<String>,
    /// Token exchange `resource`
    #[serde(default)]
    pub resource: Option<String>,
    /// Entra on-behalf-of: the scope the assertion token is requested for.
    /// Defaults to `api://<provider client_id>/.default`, the gateway's own API
    /// under its default Application ID URI; set it for a custom URI.
    #[serde(default)]
    pub assertion_scope: Option<String>,
}

/// One credential a user enters for a `per_user` backend. The gateway sends
/// header `header` with the value `prefix` + what the user entered for `name`
/// (for example header `Authorization`, prefix `Bearer `).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialField {
    /// Key of the value, unique within the backend
    pub name: String,
    /// Label shown next to the input (defaults to `name`)
    #[serde(default)]
    pub label: Option<String>,
    /// HTTP header the value is sent in
    pub header: String,
    /// Text put in front of the value in the header
    #[serde(default)]
    pub prefix: Option<String>,
}

impl BackendConfig {
    /// How long the connection may sit idle before it is closed; `None` keeps
    /// it always connected. The backend's own value wins, then stdio stays
    /// connected, then `gateway_default_secs` applies. 0 means always connected.
    #[must_use]
    pub fn idle_timeout(&self, gateway_default_secs: u64) -> Option<Duration> {
        let secs = match self.idle_timeout_secs {
            Some(secs) => secs,
            None if self.transport == TransportType::Stdio => 0,
            None => gateway_default_secs,
        };
        (secs > 0).then(|| Duration::from_secs(secs))
    }

    /// Whether each user has their own connection (no shared one): a stored
    /// credential, an OAuth sign-in or a passthrough token
    #[must_use]
    pub fn is_per_user(&self) -> bool {
        self.credential_mode != CredentialMode::Shared
    }
}

/// Default value for the `enabled` field when omitted from config
const fn default_enabled() -> bool {
    true
}

/// Default value for the `timeout_secs` field
const fn default_timeout_secs() -> u64 {
    30
}

/// Default value for the `health_check_interval_secs` field
const fn default_health_check_interval_secs() -> u64 {
    30
}

/// Default value for the `max_consecutive_failures` field
const fn default_max_consecutive_failures() -> u32 {
    3
}

/// Default value for the `circuit_breaker_cooldown_secs` field
const fn default_circuit_breaker_cooldown_secs() -> u64 {
    60
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            url: None,
            command: None,
            args: None,
            transport: TransportType::Sse,
            allowed_tools: Vec::new(),
            enabled: true,
            timeout_secs: default_timeout_secs(),
            health_check_interval_secs: default_health_check_interval_secs(),
            max_consecutive_failures: default_max_consecutive_failures(),
            circuit_breaker_cooldown_secs: default_circuit_breaker_cooldown_secs(),
            auth_token: None,
            headers: HashMap::new(),
            env: HashMap::new(),
            idle_timeout_secs: None,
            credential_mode: CredentialMode::Shared,
            credential_fields: Vec::new(),
            oauth: None,
            passthrough: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Sse,
    Http,
    Stdio,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;
        config.migrate_deprecated_groups();

        let env_vars = load_env_vars(path)?;
        config.resolve_env_vars(&env_vars)?;

        config.validate()?;
        Ok(config)
    }

    /// [`Config::load`] for async contexts: the file and `.env` reads are
    /// blocking, so run them on the blocking pool instead of a runtime worker.
    pub async fn load_async(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        tokio::task::spawn_blocking(move || Self::load(path))
            .await
            .map_err(|e| ConfigError::ReadError(std::io::Error::other(e)))?
    }

    /// Move the deprecated `[[groups]]` entries into `toolsets`.
    fn migrate_deprecated_groups(&mut self) {
        if self.groups.is_empty() {
            return;
        }
        tracing::warn!("[[groups]] is deprecated, rename it to [[toolsets]]");
        self.toolsets.append(&mut self.groups);
    }

    fn resolve_env_vars(&mut self, env_vars: &HashMap<String, String>) -> Result<(), ConfigError> {
        self.gateway.bind = resolve_placeholders(&self.gateway.bind, "gateway.bind", env_vars)?;
        self.gateway.base_url =
            resolve_placeholders(&self.gateway.base_url, "gateway.base_url", env_vars)?;
        self.gateway.auth_token = resolve_option_placeholder(
            self.gateway.auth_token.take(),
            "gateway.auth_token",
            env_vars,
        )?;

        for (index, token) in self.tokens.iter_mut().enumerate() {
            token.name =
                resolve_placeholders(&token.name, &format!("tokens[{index}].name"), env_vars)?;
            token.token =
                resolve_placeholders(&token.token, &format!("tokens[{index}].token"), env_vars)?;
            resolve_vec_placeholders(
                &mut token.allowed_tools,
                &format!("tokens[{index}].allowed_tools"),
                env_vars,
            )?;
            resolve_vec_placeholders(
                &mut token.allowed_backends,
                &format!("tokens[{index}].allowed_backends"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut token.metadata,
                &format!("tokens[{index}].metadata"),
                env_vars,
            )?;
        }

        for (index, backend) in self.backends.iter_mut().enumerate() {
            backend.name =
                resolve_placeholders(&backend.name, &format!("backends[{index}].name"), env_vars)?;
            backend.url = resolve_option_placeholder(
                backend.url.take(),
                &format!("backends[{index}].url"),
                env_vars,
            )?;
            backend.command = resolve_option_placeholder(
                backend.command.take(),
                &format!("backends[{index}].command"),
                env_vars,
            )?;
            if let Some(args) = backend.args.as_mut() {
                resolve_vec_placeholders(args, &format!("backends[{index}].args"), env_vars)?;
            }
            resolve_vec_placeholders(
                &mut backend.allowed_tools,
                &format!("backends[{index}].allowed_tools"),
                env_vars,
            )?;
            backend.auth_token = resolve_option_placeholder(
                backend.auth_token.take(),
                &format!("backends[{index}].auth_token"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut backend.headers,
                &format!("backends[{index}].headers"),
                env_vars,
            )?;
            resolve_map_value_placeholders(
                &mut backend.env,
                &format!("backends[{index}].env"),
                env_vars,
            )?;
            if let Some(oauth) = backend.oauth.as_mut()
                && let Some(var) = &oauth.client_secret_env
            {
                let Some(secret) = env_vars.get(var).filter(|secret| !secret.is_empty()) else {
                    return Err(ConfigError::InvalidPerUserBackend {
                        name: backend.name.clone(),
                        reason: format!(
                            "oauth.client_secret_env names {var}, which is unset or empty"
                        ),
                    });
                };
                oauth.client_secret = Some(secret.clone());
            }
        }

        for (index, toolset) in self.toolsets.iter_mut().enumerate() {
            toolset.name =
                resolve_placeholders(&toolset.name, &format!("toolsets[{index}].name"), env_vars)?;
            resolve_vec_placeholders(
                &mut toolset.tools,
                &format!("toolsets[{index}].tools"),
                env_vars,
            )?;
            resolve_vec_placeholders(
                &mut toolset.backends,
                &format!("toolsets[{index}].backends"),
                env_vars,
            )?;
            toolset.description = resolve_option_placeholder(
                toolset.description.take(),
                &format!("toolsets[{index}].description"),
                env_vars,
            )?;
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        for backend in &self.backends {
            // Reject bad custom headers here instead of silently dropping them
            // when the backend connects.
            for (name, value) in &backend.headers {
                let invalid = |part| ConfigError::InvalidHeader {
                    backend: backend.name.clone(),
                    header: name.clone(),
                    part,
                };
                if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
                    return Err(invalid("name"));
                }
                if http::HeaderValue::from_str(value).is_err() {
                    return Err(invalid("value"));
                }
            }

            match backend.transport {
                TransportType::Sse | TransportType::Http => {
                    if backend.url.is_none() {
                        return Err(ConfigError::MissingUrl {
                            name: backend.name.clone(),
                            transport: backend.transport,
                        });
                    }
                }
                TransportType::Stdio => {
                    if backend.command.is_none() {
                        return Err(ConfigError::MissingCommand {
                            name: backend.name.clone(),
                        });
                    }
                }
            }
        }

        self.validate_per_user_backends()?;

        if !self.gateway.allow_stdio {
            let stdio: Vec<&str> = self
                .backends
                .iter()
                .filter(|b| b.transport == TransportType::Stdio)
                .map(|b| b.name.as_str())
                .collect();
            if !stdio.is_empty() {
                return Err(ConfigError::StdioNotAllowed {
                    names: stdio.join(", "),
                });
            }
        }

        let mut toolset_names = std::collections::HashSet::new();
        for toolset in &self.toolsets {
            if !toolset_names.insert(toolset.name.as_str()) {
                return Err(ConfigError::DuplicateToolset {
                    name: toolset.name.clone(),
                });
            }
        }

        self.validate_auth()?;
        self.validate_rbac()
    }

    /// Per-user backends (`per_user`, `oauth`, `passthrough`): a url, a
    /// database to store the connections in, and the settings of their mode.
    /// `per_user` is HTTP/SSE with well-formed credential fields; the others
    /// are HTTP only.
    fn validate_per_user_backends(&self) -> Result<(), ConfigError> {
        for backend in &self.backends {
            let name = &backend.name;
            let invalid = |reason: String| ConfigError::InvalidPerUserBackend {
                name: name.clone(),
                reason,
            };
            if !backend.is_per_user() {
                if backend.oauth.is_some() {
                    return Err(invalid(
                        "the oauth table needs credential_mode = \"oauth\"".into(),
                    ));
                }
                if backend.passthrough.is_some() {
                    return Err(invalid(
                        "the passthrough table needs credential_mode = \"passthrough\"".into(),
                    ));
                }
                continue;
            }
            let per_user = backend.credential_mode == CredentialMode::PerUser;
            if backend.transport == TransportType::Stdio {
                return Err(invalid(if per_user {
                    "stdio is not supported, use http or sse".into()
                } else {
                    "stdio is not supported, use http".into()
                }));
            }
            if !per_user && backend.transport != TransportType::Http {
                return Err(invalid("it needs transport = \"http\"".into()));
            }
            if backend.url.is_none() {
                return Err(invalid("it needs a url".into()));
            }
            match backend.credential_mode {
                CredentialMode::PerUser => {
                    if backend.oauth.is_some() {
                        return Err(invalid(
                            "the oauth table needs credential_mode = \"oauth\"".into(),
                        ));
                    }
                    if backend.passthrough.is_some() {
                        return Err(invalid(
                            "the passthrough table needs credential_mode = \"passthrough\"".into(),
                        ));
                    }
                    Self::validate_credential_fields(backend).map_err(invalid)?;
                }
                CredentialMode::OAuth => {
                    if !backend.credential_fields.is_empty() {
                        return Err(invalid("credential_fields must be empty".into()));
                    }
                    if backend.passthrough.is_some() {
                        return Err(invalid(
                            "the passthrough table needs credential_mode = \"passthrough\"".into(),
                        ));
                    }
                    if let Some(oauth) = &backend.oauth {
                        if oauth.client_id.is_empty() {
                            return Err(invalid("oauth.client_id must not be empty".into()));
                        }
                        if oauth.scopes.iter().any(String::is_empty) {
                            return Err(invalid(
                                "oauth.scopes must not hold an empty scope".into(),
                            ));
                        }
                    }
                }
                CredentialMode::Passthrough => {
                    if !backend.credential_fields.is_empty() {
                        return Err(invalid("credential_fields must be empty".into()));
                    }
                    if backend.oauth.is_some() {
                        return Err(invalid(
                            "the oauth table needs credential_mode = \"oauth\"".into(),
                        ));
                    }
                    self.validate_passthrough(backend).map_err(invalid)?;
                }
                CredentialMode::Shared => {}
            }
            if self.database.is_none() {
                return Err(ConfigError::PerUserRequiresDatabase { name: name.clone() });
            }
        }
        Ok(())
    }

    /// At least one well-formed credential field, each name used once
    fn validate_credential_fields(backend: &BackendConfig) -> Result<(), String> {
        if backend.credential_fields.is_empty() {
            return Err("it needs at least one credential_fields entry".into());
        }
        let mut seen = std::collections::HashSet::new();
        for field in &backend.credential_fields {
            if field.name.is_empty() {
                return Err("a credential field has an empty name".into());
            }
            if !seen.insert(field.name.as_str()) {
                return Err(format!("credential field '{}' is listed twice", field.name));
            }
            if http::HeaderName::from_bytes(field.header.as_bytes()).is_err() {
                return Err(format!(
                    "credential field '{}' has an invalid header name '{}'",
                    field.name, field.header
                ));
            }
        }
        Ok(())
    }

    /// The passthrough table: present, naming a configured provider, and
    /// complete for its grant
    fn validate_passthrough(&self, backend: &BackendConfig) -> Result<(), String> {
        let Some(passthrough) = &backend.passthrough else {
            return Err("it needs a passthrough table".into());
        };
        let Some(provider) = self
            .auth
            .oidc
            .iter()
            .find(|provider| provider.id == passthrough.provider)
        else {
            return Err(format!(
                "passthrough.provider '{}' is not an [[auth.oidc]] id",
                passthrough.provider
            ));
        };
        let blank = |value: Option<&str>| value.is_some_and(str::is_empty);
        if blank(passthrough.audience.as_deref())
            || blank(passthrough.scope.as_deref())
            || blank(passthrough.resource.as_deref())
        {
            return Err("passthrough.audience, scope and resource must not be empty".into());
        }
        if blank(passthrough.assertion_scope.as_deref()) {
            return Err("passthrough.assertion_scope must not be empty".into());
        }
        if passthrough.grant != PassthroughGrant::EntraObo && passthrough.assertion_scope.is_some()
        {
            return Err("passthrough.assertion_scope is only for the entra_obo grant".into());
        }
        if passthrough.grant == PassthroughGrant::EntraObo {
            if passthrough.scope.is_none() {
                return Err("the entra_obo grant needs passthrough.scope".into());
            }
            if provider.client_secret_env.is_none() {
                return Err(format!(
                    "the entra_obo grant needs a client secret: set client_secret_env on provider '{}'",
                    provider.id
                ));
            }
        }
        Ok(())
    }

    fn validate_rbac(&self) -> Result<(), ConfigError> {
        let backend_names: Vec<&str> = self.backends.iter().map(|b| b.name.as_str()).collect();
        let provider_ids: Vec<&str> = self.auth.oidc.iter().map(|p| p.id.as_str()).collect();
        self.rbac
            .validate(&backend_names, &provider_ids)
            .map_err(ConfigError::InvalidRbac)
    }

    fn validate_auth(&self) -> Result<(), ConfigError> {
        if self.auth.oidc.is_empty() {
            return Ok(());
        }
        if self.database.is_none() {
            return Err(ConfigError::OidcRequiresDatabase);
        }

        let mut seen = std::collections::HashSet::new();
        for provider in &self.auth.oidc {
            let invalid = |reason: &str| ConfigError::InvalidOidcProvider {
                id: provider.id.clone(),
                reason: reason.to_string(),
            };

            if provider.id.is_empty()
                || !provider
                    .id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(invalid("id must be non-empty and match [a-z0-9-]+"));
            }
            if !seen.insert(provider.id.as_str()) {
                return Err(invalid("duplicate id"));
            }
            if !provider.scopes.iter().any(|scope| scope == "openid") {
                return Err(invalid("scopes must include \"openid\""));
            }
            let Ok(issuer) = reqwest::Url::parse(&provider.issuer) else {
                return Err(invalid("issuer is not a valid URL"));
            };
            let loopback = matches!(issuer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
            if issuer.scheme() != "https" && !(issuer.scheme() == "http" && loopback) {
                return Err(invalid(
                    "issuer must use https (http is only allowed for localhost)",
                ));
            }
            if provider.client_id.is_empty() {
                return Err(invalid("client_id must not be empty"));
            }
            if provider.access_token_audience.as_deref() == Some("") {
                return Err(invalid("access_token_audience must not be empty"));
            }
            if provider.graph_overage && provider.client_secret_env.is_none() {
                return Err(invalid(
                    "graph_overage needs a client secret: set client_secret_env",
                ));
            }
            if provider.graph_url.is_some() {
                let Ok(graph) = reqwest::Url::parse(provider.graph_url()) else {
                    return Err(invalid("graph_url is not a valid URL"));
                };
                let loopback =
                    matches!(graph.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
                if graph.scheme() != "https" && !(graph.scheme() == "http" && loopback) {
                    return Err(invalid(
                        "graph_url must use https (http is only allowed for localhost)",
                    ));
                }
            }
            if provider.scim_match_claim.as_deref() == Some("") {
                return Err(invalid("scim_match_claim must not be empty"));
            }
        }
        Ok(())
    }
}

fn load_env_vars(config_path: &Path) -> Result<HashMap<String, String>, ConfigError> {
    let mut env_vars: HashMap<String, String> = std::env::vars().collect();
    let env_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".env");

    if env_path.exists() {
        let path_display = env_path.display().to_string();
        let iter =
            dotenvy::from_path_iter(&env_path).map_err(|source| ConfigError::EnvFileError {
                path: path_display.clone(),
                source,
            })?;

        for entry in iter {
            let (key, value) = entry.map_err(|source| ConfigError::EnvFileError {
                path: path_display.clone(),
                source,
            })?;
            env_vars.entry(key).or_insert(value);
        }
    }

    Ok(env_vars)
}

fn resolve_option_placeholder(
    value: Option<String>,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<Option<String>, ConfigError> {
    value
        .map(|v| resolve_placeholders(&v, field, env_vars))
        .transpose()
}

fn resolve_vec_placeholders(
    values: &mut [String],
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (index, value) in values.iter_mut().enumerate() {
        let resolved = resolve_placeholders(value, &format!("{field}[{index}]"), env_vars)?;
        value.clone_from(&resolved);
    }
    Ok(())
}

fn resolve_map_value_placeholders(
    values: &mut HashMap<String, String>,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    for (key, value) in values.iter_mut() {
        let resolved = resolve_placeholders(value, &format!("{field}.{key}"), env_vars)?;
        value.clone_from(&resolved);
    }
    Ok(())
}

fn resolve_placeholders(
    input: &str,
    field: &str,
    env_vars: &HashMap<String, String>,
) -> Result<String, ConfigError> {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;

    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 2..];

        let Some(end) = after_start.find('}') else {
            return Err(ConfigError::InvalidEnvPlaceholder {
                field: field.to_string(),
                value: input.to_string(),
            });
        };

        let var_name = &after_start[..end];
        if var_name.is_empty() {
            return Err(ConfigError::InvalidEnvPlaceholder {
                field: field.to_string(),
                value: input.to_string(),
            });
        }

        let var_value = env_vars
            .get(var_name)
            .ok_or_else(|| ConfigError::MissingEnvVar {
                var: var_name.to_string(),
                field: field.to_string(),
            })?;
        output.push_str(var_value);

        remaining = &after_start[end + 1..];
    }

    output.push_str(remaining);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::error::ConfigError;

    mod resolve_placeholders {
        use super::*;

        #[test]
        fn resolves_single_placeholder() {
            let env_vars = HashMap::from([(String::from("API_TOKEN"), String::from("abc123"))]);
            let resolved = resolve_placeholders("${API_TOKEN}", "gateway.auth_token", &env_vars)
                .expect("placeholder should resolve");
            assert_eq!(resolved, "abc123");
        }

        #[test]
        fn resolves_multiple_placeholders_in_one_value() {
            let env_vars = HashMap::from([
                (String::from("HOST"), String::from("localhost")),
                (String::from("PORT"), String::from("8080")),
            ]);
            let resolved =
                resolve_placeholders("http://${HOST}:${PORT}", "backends[0].url", &env_vars)
                    .expect("placeholders should resolve");
            assert_eq!(resolved, "http://localhost:8080");
        }

        #[test]
        fn errors_when_placeholder_is_missing() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${MISSING_TOKEN}", "tokens[0].token", &env_vars)
                .expect_err("missing placeholder should error");

            match error {
                ConfigError::MissingEnvVar { var, field } => {
                    assert_eq!(var, "MISSING_TOKEN");
                    assert_eq!(field, "tokens[0].token");
                }
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn returns_input_unchanged_without_placeholders() {
            let env_vars = HashMap::new();
            let result = resolve_placeholders("plain text", "field", &env_vars).unwrap();
            assert_eq!(result, "plain text");
        }

        #[test]
        fn errors_on_unclosed_placeholder() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${UNCLOSED", "field", &env_vars)
                .expect_err("unclosed placeholder should error");

            match error {
                ConfigError::InvalidEnvPlaceholder { field, value } => {
                    assert_eq!(field, "field");
                    assert_eq!(value, "${UNCLOSED");
                }
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn errors_on_empty_placeholder() {
            let env_vars = HashMap::new();
            let error = resolve_placeholders("${}", "field", &env_vars)
                .expect_err("empty placeholder should error");

            match error {
                ConfigError::InvalidEnvPlaceholder { .. } => {}
                other => panic!("unexpected error variant: {other:?}"),
            }
        }

        #[test]
        fn preserves_text_around_placeholder() {
            let env_vars = HashMap::from([("VAR".to_string(), "value".to_string())]);
            let result = resolve_placeholders("prefix_${VAR}_suffix", "field", &env_vars).unwrap();
            assert_eq!(result, "prefix_value_suffix");
        }
    }

    mod config_validation {
        use super::*;

        #[test]
        fn sse_transport_requires_url() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "test".to_string(),
                    transport: TransportType::Sse,
                    url: None,
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            let error = config.validate().expect_err("should require URL");
            match error {
                ConfigError::MissingUrl { name, transport } => {
                    assert_eq!(name, "test");
                    assert_eq!(transport, TransportType::Sse);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn http_transport_requires_url() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "http_backend".to_string(),
                    transport: TransportType::Http,
                    url: None,
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            let error = config.validate().expect_err("should require URL");
            match error {
                ConfigError::MissingUrl { name, .. } => assert_eq!(name, "http_backend"),
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn stdio_transport_requires_command() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: true,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "stdio_backend".to_string(),
                    transport: TransportType::Stdio,
                    command: None,
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            let error = config.validate().expect_err("should require command");
            match error {
                ConfigError::MissingCommand { name } => assert_eq!(name, "stdio_backend"),
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn stdio_backend_needs_allow_stdio() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![
                    BackendConfig {
                        name: "web".to_string(),
                        transport: TransportType::Http,
                        url: Some("http://localhost:3001/mcp".to_string()),
                        ..Default::default()
                    },
                    BackendConfig {
                        name: "files".to_string(),
                        transport: TransportType::Stdio,
                        command: Some("/usr/local/bin/mcp-files".to_string()),
                        ..Default::default()
                    },
                    BackendConfig {
                        name: "shell".to_string(),
                        transport: TransportType::Stdio,
                        command: Some("/usr/local/bin/mcp-shell".to_string()),
                        ..Default::default()
                    },
                ],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            let error = config.validate().expect_err("should refuse stdio");
            match error {
                ConfigError::StdioNotAllowed { names } => assert_eq!(names, "files, shell"),
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn valid_sse_config_passes() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "valid".to_string(),
                    transport: TransportType::Sse,
                    url: Some("http://localhost:3000".to_string()),
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            config.validate().expect("valid config should pass");
        }

        fn config_with_header(name: &str, value: &str) -> Config {
            Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: false,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "hdr".to_string(),
                    transport: TransportType::Http,
                    url: Some("http://localhost:3000".to_string()),
                    headers: HashMap::from([(name.to_string(), value.to_string())]),
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            }
        }

        #[test]
        fn valid_custom_header_passes() {
            config_with_header("X-Api-Key", "secret")
                .validate()
                .expect("valid header should pass");
        }

        #[test]
        fn invalid_header_name_is_rejected() {
            let error = config_with_header("Bad Header", "v")
                .validate()
                .expect_err("space in header name");
            match error {
                ConfigError::InvalidHeader {
                    backend,
                    header,
                    part,
                } => {
                    assert_eq!(backend, "hdr");
                    assert_eq!(header, "Bad Header");
                    assert_eq!(part, "name");
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn invalid_header_value_is_rejected_without_leaking_it() {
            let error = config_with_header("X-Api-Key", "line\nbreak-secret")
                .validate()
                .expect_err("newline in header value");
            assert!(matches!(
                error,
                ConfigError::InvalidHeader { part: "value", .. }
            ));
            assert!(!error.to_string().contains("secret"), "{error}");
        }

        #[test]
        fn valid_stdio_config_passes() {
            let config = Config {
                gateway: GatewayConfig {
                    bind: "0.0.0.0:8080".to_string(),
                    base_url: "http://localhost".to_string(),
                    auth_token: None,
                    rate_limit_per_minute: 0,
                    allow_stdio: true,
                    allowed_hosts: vec![],
                    idle_timeout_secs: 300,
                },
                backends: vec![BackendConfig {
                    name: "stdio".to_string(),
                    transport: TransportType::Stdio,
                    command: Some("/usr/bin/mcp-server".to_string()),
                    args: Some(vec!["--config".to_string(), "file.toml".to_string()]),
                    ..Default::default()
                }],
                tokens: vec![],
                toolsets: vec![],
                groups: vec![],
                database: None,
                auth: AuthConfig::default(),
                rbac: crate::policy::RbacConfig::default(),
                personal_backends: crate::config::PersonalBackendsConfig::default(),
            };

            config.validate().expect("valid config should pass");
        }
    }

    mod config_parsing {
        use super::*;

        #[test]
        fn parses_minimal_config() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"

                [[backends]]
                name = "test"
                url = "http://localhost:3000"
                transport = "sse"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.gateway.bind, "0.0.0.0:8080");
            assert_eq!(config.backends.len(), 1);
            assert_eq!(config.backends[0].name, "test");
            assert_eq!(config.backends[0].transport, TransportType::Sse);
        }

        #[test]
        fn parses_full_backend_config() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"
                auth_token = "secret"
                rate_limit_per_minute = 100

                [[backends]]
                name = "full"
                url = "http://localhost:3000"
                transport = "http"
                enabled = false
                timeout_secs = 60
                health_check_interval_secs = 120
                max_consecutive_failures = 5
                circuit_breaker_cooldown_secs = 300
                auth_token = "backend_token"
                allowed_tools = ["tool1", "tool2"]

                [backends.headers]
                X-Custom = "value"

                [backends.env]
                MY_VAR = "my_value"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            let backend = &config.backends[0];

            assert_eq!(backend.name, "full");
            assert!(!backend.enabled);
            assert_eq!(backend.timeout_secs, 60);
            assert_eq!(backend.health_check_interval_secs, 120);
            assert_eq!(backend.max_consecutive_failures, 5);
            assert_eq!(backend.circuit_breaker_cooldown_secs, 300);
            assert_eq!(backend.auth_token, Some("backend_token".to_string()));
            assert_eq!(backend.allowed_tools, vec!["tool1", "tool2"]);
            assert_eq!(backend.headers.get("X-Custom"), Some(&"value".to_string()));
            assert_eq!(backend.env.get("MY_VAR"), Some(&"my_value".to_string()));
        }

        #[test]
        fn parses_stdio_backend() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"

                [[backends]]
                name = "stdio_server"
                command = "/usr/local/bin/mcp-server"
                args = ["--verbose", "--config", "/etc/mcp.toml"]
                transport = "stdio"

                [backends.env]
                DEBUG = "1"
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            let backend = &config.backends[0];

            assert_eq!(backend.transport, TransportType::Stdio);
            assert_eq!(
                backend.command,
                Some("/usr/local/bin/mcp-server".to_string())
            );
            assert_eq!(
                backend.args,
                Some(vec![
                    "--verbose".to_string(),
                    "--config".to_string(),
                    "/etc/mcp.toml".to_string()
                ])
            );
            assert_eq!(backend.env.get("DEBUG"), Some(&"1".to_string()));
        }

        #[test]
        fn parses_tokens() {
            let toml = r#"
[gateway]
bind = "0.0.0.0:8080"

[[backends]]
name = "dummy"
url = "http://localhost"
transport = "http"

[[tokens]]
name = "admin"
token = "admin_secret"
allowed_tools = ["*"]
allowed_backends = ["backend1", "backend2"]
rate_limit_per_minute = 1000

[[tokens]]
name = "readonly"
token = "ro_token"
allowed_tools = ["*_read", "*_list"]
            "#;

            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.tokens.len(), 2);

            assert_eq!(config.tokens[0].name, "admin");
            assert_eq!(
                config.tokens[0].allowed_backends,
                vec!["backend1", "backend2"]
            );

            assert_eq!(config.tokens[1].name, "readonly");
            assert_eq!(config.tokens[1].allowed_tools, vec!["*_read", "*_list"]);
        }

        const TOOLSETS_BASE: &str = r#"
[gateway]
bind = "0.0.0.0:8080"

[[backends]]
name = "dummy"
url = "http://localhost"
transport = "http"
"#;

        #[test]
        fn parses_toolsets() {
            let toml = format!(
                r#"{TOOLSETS_BASE}
[[toolsets]]
name = "coding"
tools = ["*_read", "*_write"]
backends = ["vscode", "git"]
description = "Coding tools only"

[[toolsets]]
name = "readonly"
tools = ["*_read", "*_list", "*_get"]
"#
            );

            let config: Config = toml::from_str(&toml).expect("should parse");
            assert_eq!(config.toolsets.len(), 2);

            assert_eq!(config.toolsets[0].name, "coding");
            assert_eq!(config.toolsets[0].backends, vec!["vscode", "git"]);
            assert_eq!(
                config.toolsets[0].description,
                Some("Coding tools only".to_string())
            );

            assert_eq!(config.toolsets[1].name, "readonly");
            assert_eq!(config.toolsets[1].backends, Vec::<String>::new());
        }

        #[test]
        fn deprecated_groups_move_into_toolsets_on_load() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let toml = format!(
                r#"{TOOLSETS_BASE}
[[toolsets]]
name = "new"

[[groups]]
name = "old"
"#
            );
            std::fs::write(&path, toml).unwrap();

            let config = Config::load(&path).expect("should load");
            assert!(config.groups.is_empty());
            let names: Vec<_> = config.toolsets.iter().map(|t| t.name.as_str()).collect();
            assert_eq!(names, ["new", "old"]);
        }

        #[test]
        fn duplicate_toolset_names_are_rejected() {
            let toml = format!(
                r#"{TOOLSETS_BASE}
[[toolsets]]
name = "same"

[[toolsets]]
name = "same"
"#
            );
            let config: Config = toml::from_str(&toml).expect("should parse");

            let error = config.validate().expect_err("duplicate must fail");
            assert!(
                matches!(&error, ConfigError::DuplicateToolset { name } if name == "same"),
                "{error:?}"
            );
        }
    }

    mod load_async {
        use super::*;

        #[tokio::test]
        async fn loads_a_config_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            std::fs::write(&path, "backends = []\n[gateway]\nbind = \"127.0.0.1:0\"\n").unwrap();

            let config = Config::load_async(&path).await.unwrap();
            assert_eq!(config.gateway.bind, "127.0.0.1:0");
        }

        #[tokio::test]
        async fn missing_file_is_a_read_error() {
            let dir = tempfile::tempdir().unwrap();
            let error = Config::load_async(dir.path().join("absent.toml"))
                .await
                .expect_err("missing file must fail");
            assert!(matches!(error, ConfigError::ReadError(_)), "{error:?}");
        }
    }

    mod auth_config {
        use super::*;

        const BASE: &str = r#"
            [gateway]
            bind = "0.0.0.0:8080"

            [[backends]]
            name = "b"
            transport = "http"
            url = "http://localhost:9000"
        "#;

        fn parse(extra: &str) -> Config {
            toml::from_str(&format!("{BASE}\n{extra}")).expect("should parse")
        }

        fn with_db(extra: &str) -> Config {
            parse(&format!("[database]\n{extra}"))
        }

        fn provider(id: &str, issuer: &str) -> String {
            format!("[[auth.oidc]]\nid = \"{id}\"\nissuer = \"{issuer}\"\nclient_id = \"cid\"\n")
        }

        fn invalid_reason(config: &Config) -> String {
            match config.validate().expect_err("should be invalid") {
                ConfigError::InvalidOidcProvider { reason, .. } => reason,
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn absent_auth_is_empty() {
            let config = parse("");
            assert!(config.auth.oidc.is_empty());
            config.validate().expect("no providers is valid");
        }

        #[test]
        fn parses_two_providers_with_defaults() {
            let config = parse(
                r#"
                [database]

                [[auth.oidc]]
                id = "entra"
                display_name = "Microsoft"
                issuer = "https://login.microsoftonline.com/t/v2.0"
                client_id = "abc"
                client_secret_env = "AXON_OIDC_ENTRA_SECRET"
                admin_groups = ["g1"]

                [[auth.oidc]]
                id = "pocket-id"
                issuer = "https://id.homelab.internal"
                client_id = "def"
                scopes = ["openid", "groups"]
                groups_claim = "realm_access.roles"
                allowed_email_domains = ["example.com"]
                "#,
            );
            config.validate().expect("valid config should pass");

            let [entra, pocket] = config.auth.oidc.as_slice() else {
                panic!("expected two providers");
            };
            assert_eq!(entra.display_name(), "Microsoft");
            assert_eq!(entra.scopes, ["openid", "profile", "email"]);
            assert_eq!(entra.groups_claim, "groups");
            assert_eq!(
                entra.client_secret_env.as_deref(),
                Some("AXON_OIDC_ENTRA_SECRET")
            );
            assert_eq!(entra.admin_groups, ["g1"]);
            assert_eq!(pocket.display_name(), "pocket-id");
            assert_eq!(pocket.scopes, ["openid", "groups"]);
            assert_eq!(pocket.groups_claim, "realm_access.roles");
            assert!(pocket.client_secret_env.is_none());
            assert_eq!(pocket.allowed_email_domains, ["example.com"]);
        }

        #[test]
        fn oidc_requires_database() {
            let config = parse(&provider("a", "https://idp.example.com"));
            assert!(matches!(
                config.validate(),
                Err(ConfigError::OidcRequiresDatabase)
            ));
        }

        #[test]
        fn rejects_bad_ids() {
            for id in ["", "Upper", "under_score", "sp ace"] {
                let config = with_db(&provider(id, "https://idp.example.com"));
                assert!(invalid_reason(&config).contains("id"), "{id:?}");
            }
        }

        #[test]
        fn rejects_duplicate_ids() {
            let extra = format!(
                "{}{}",
                provider("a", "https://one.example.com"),
                provider("a", "https://two.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("duplicate"));
        }

        #[test]
        fn rejects_scopes_without_openid() {
            let extra = format!(
                "{}scopes = [\"profile\"]\n",
                provider("a", "https://idp.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("openid"));
        }

        #[test]
        fn rejects_bad_issuers() {
            for issuer in ["not a url", "http://idp.example.com", "ftp://localhost"] {
                let config = with_db(&provider("a", issuer));
                assert!(invalid_reason(&config).contains("issuer"), "{issuer:?}");
            }
        }

        #[test]
        fn allows_http_for_loopback_and_trailing_slash() {
            for issuer in [
                "http://localhost:8081/realms/x",
                "http://127.0.0.1:8081",
                "http://[::1]:8081",
                "https://idp.example.com/",
            ] {
                with_db(&provider("a", issuer))
                    .validate()
                    .unwrap_or_else(|e| panic!("{issuer}: {e}"));
            }
        }

        #[test]
        fn rejects_empty_client_id() {
            let extra = "[[auth.oidc]]\nid = \"a\"\nissuer = \"https://idp.example.com\"\nclient_id = \"\"\n";
            assert!(invalid_reason(&with_db(extra)).contains("client_id"));
        }

        #[test]
        fn access_tokens_default_to_off_and_the_client_id_audience() {
            let config = with_db(&provider("a", "https://idp.example.com"));
            config.validate().expect("valid");
            let [one] = config.auth.oidc.as_slice() else {
                panic!("one provider");
            };
            assert!(!one.accept_access_tokens);
            assert_eq!(one.access_token_audience(), "cid");

            let extra = format!(
                "{}accept_access_tokens = true\naccess_token_audience = \"api://axon\"\n",
                provider("a", "https://idp.example.com")
            );
            let config = with_db(&extra);
            config.validate().expect("valid");
            let [one] = config.auth.oidc.as_slice() else {
                panic!("one provider");
            };
            assert!(one.accept_access_tokens);
            assert_eq!(one.access_token_audience(), "api://axon");
        }

        #[test]
        fn rejects_an_empty_access_token_audience() {
            let extra = format!(
                "{}access_token_audience = \"\"\n",
                provider("a", "https://idp.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("access_token_audience"));
        }

        #[test]
        fn graph_overage_is_off_and_scim_matches_sub_by_default() {
            let config = with_db(&provider("a", "https://idp.example.com"));
            config.validate().expect("valid");
            let [one] = config.auth.oidc.as_slice() else {
                panic!("one provider");
            };
            assert!(!one.graph_overage);
            assert_eq!(one.graph_url(), "https://graph.microsoft.com");
            assert_eq!(one.scim_match_claim(), "sub");

            let extra = format!(
                "{}client_secret_env = \"S\"\ngraph_overage = true\ngraph_url = \"https://graph.microsoft.us/\"\nscim_match_claim = \"oid\"\n",
                provider("a", "https://idp.example.com")
            );
            let config = with_db(&extra);
            config.validate().expect("valid");
            let [one] = config.auth.oidc.as_slice() else {
                panic!("one provider");
            };
            assert!(one.graph_overage);
            assert_eq!(one.graph_url(), "https://graph.microsoft.us");
            assert_eq!(one.scim_match_claim(), "oid");
        }

        #[test]
        fn graph_overage_needs_a_client_secret() {
            let extra = format!(
                "{}graph_overage = true\n",
                provider("a", "https://idp.example.com")
            );
            assert!(invalid_reason(&with_db(&extra)).contains("client_secret_env"));
        }

        #[test]
        fn rejects_a_bad_graph_url_and_an_empty_scim_claim() {
            for (line, key) in [
                ("graph_url = \"not a url\"", "graph_url"),
                ("graph_url = \"http://graph.example.com\"", "graph_url"),
                ("scim_match_claim = \"\"", "scim_match_claim"),
            ] {
                let extra = format!("{}{line}\n", provider("a", "https://idp.example.com"));
                assert!(invalid_reason(&with_db(&extra)).contains(key), "{line}");
            }
            let extra = format!(
                "{}graph_url = \"http://127.0.0.1:9000\"\n",
                provider("a", "https://idp.example.com")
            );
            with_db(&extra).validate().expect("loopback http is fine");
        }
    }

    mod backend_config_defaults {
        use super::*;

        #[test]
        fn default_values_are_set() {
            let config = BackendConfig::default();

            assert!(config.enabled);
            assert_eq!(config.timeout_secs, 30);
            assert_eq!(config.health_check_interval_secs, 30);
            assert_eq!(config.max_consecutive_failures, 3);
            assert_eq!(config.circuit_breaker_cooldown_secs, 60);
            assert_eq!(config.allowed_tools, Vec::<String>::new());
            assert!(config.headers.is_empty());
            assert!(config.env.is_empty());
        }
    }

    mod allowed_hosts {
        use super::*;

        fn gateway(base_url: &str, allowed_hosts: &[&str]) -> GatewayConfig {
            GatewayConfig {
                bind: "0.0.0.0:8080".to_string(),
                base_url: base_url.to_string(),
                auth_token: None,
                rate_limit_per_minute: 0,
                allow_stdio: false,
                allowed_hosts: allowed_hosts.iter().map(|h| (*h).to_string()).collect(),
                idle_timeout_secs: 300,
            }
        }

        #[test]
        fn includes_loopback_and_base_url_host_with_port() {
            let hosts = mcp_allowed_hosts(&gateway("http://localhost:8080", &[]));
            assert_eq!(hosts, ["localhost", "127.0.0.1", "::1", "localhost:8080"]);
        }

        #[test]
        fn adds_public_host_and_extra_hosts_without_duplicates() {
            let hosts = mcp_allowed_hosts(&gateway(
                "https://axon.homelab.internal",
                &["axon.homelab.local", "localhost", "axon.homelab.internal"],
            ));
            assert_eq!(
                hosts,
                [
                    "localhost",
                    "127.0.0.1",
                    "::1",
                    "axon.homelab.internal",
                    "axon.homelab.local",
                ]
            );
        }

        #[test]
        fn unparsable_base_url_keeps_loopback_and_extras() {
            let hosts = mcp_allowed_hosts(&gateway("not a url", &["axon.example"]));
            assert_eq!(hosts, ["localhost", "127.0.0.1", "::1", "axon.example"]);
        }

        #[test]
        fn allowed_hosts_default_to_empty_and_stdio_to_off() {
            let toml = r#"
                [gateway]
                bind = "0.0.0.0:8080"
            "#;
            let value: toml::Table = toml::from_str(toml).expect("should parse");
            let gateway: GatewayConfig = value["gateway"]
                .clone()
                .try_into()
                .expect("should deserialize");
            assert!(!gateway.allow_stdio);
            assert_eq!(gateway.allowed_hosts, Vec::<String>::new());
        }
    }

    mod idle_timeout {
        use super::*;

        fn backend(transport: TransportType, idle: Option<u64>) -> BackendConfig {
            BackendConfig {
                transport,
                idle_timeout_secs: idle,
                ..Default::default()
            }
        }

        #[test]
        fn http_and_sse_use_the_gateway_default() {
            for transport in [TransportType::Http, TransportType::Sse] {
                assert_eq!(
                    backend(transport, None).idle_timeout(300),
                    Some(Duration::from_secs(300))
                );
            }
        }

        #[test]
        fn gateway_default_zero_means_always_connected() {
            assert_eq!(backend(TransportType::Http, None).idle_timeout(0), None);
        }

        #[test]
        fn stdio_defaults_to_always_connected() {
            assert_eq!(backend(TransportType::Stdio, None).idle_timeout(300), None);
        }

        #[test]
        fn backend_value_overrides_the_default() {
            assert_eq!(
                backend(TransportType::Http, Some(60)).idle_timeout(300),
                Some(Duration::from_secs(60))
            );
            assert_eq!(
                backend(TransportType::Stdio, Some(120)).idle_timeout(300),
                Some(Duration::from_secs(120))
            );
        }

        #[test]
        fn backend_zero_means_always_connected() {
            assert_eq!(
                backend(TransportType::Http, Some(0)).idle_timeout(300),
                None
            );
        }
    }

    mod per_user_and_personal {
        use super::*;

        const BASE: &str = r#"
            [gateway]
            bind = "0.0.0.0:8080"
        "#;

        const FIELD: &str = r#"
            credential_fields = [
                { name = "token", header = "Authorization", prefix = "Bearer " },
            ]
        "#;

        fn parse(backend: &str, extra: &str) -> Config {
            let toml = format!("{BASE}\n[[backends]]\nname = \"cat\"\n{backend}\n{extra}");
            toml::from_str(&toml).expect("should parse")
        }

        fn per_user(extra: &str) -> Config {
            parse(
                "transport = \"http\"\nurl = \"http://localhost:9000\"\ncredential_mode = \"per_user\"",
                extra,
            )
        }

        fn reason(config: &Config) -> String {
            match config.validate().expect_err("should be invalid") {
                ConfigError::InvalidPerUserBackend { reason, .. } => reason,
                other => panic!("unexpected error: {other:?}"),
            }
        }

        #[test]
        fn empty_config_has_the_defaults() {
            let config: Config =
                toml::from_str(&format!("backends = []\n{BASE}")).expect("should parse");
            assert_eq!(config.gateway.idle_timeout_secs, 300);

            let personal = config.personal_backends;
            assert!(personal.enabled);
            assert_eq!(personal.max_per_user, 10);
            assert_eq!(personal.max_calls_per_minute, 0);
            assert_eq!(personal.max_instances, 500);
            assert_eq!(personal.egress_allow, Vec::<String>::new());
            assert_eq!(personal.egress_deny, Vec::<String>::new());
        }

        #[test]
        fn parses_the_new_keys() {
            let toml = r#"
                backends = []

                [gateway]
                bind = "0.0.0.0:8080"
                idle_timeout_secs = 120

                [personal_backends]
                enabled = false
                max_per_user = 3
                max_calls_per_minute = 60
                max_instances = 50
                egress_allow = ["*.example.com"]
                egress_deny = ["10.0.0.0/8"]
            "#;
            let config: Config = toml::from_str(toml).expect("should parse");
            assert_eq!(config.gateway.idle_timeout_secs, 120);

            let personal = config.personal_backends;
            assert!(!personal.enabled);
            assert_eq!(personal.max_per_user, 3);
            assert_eq!(personal.max_calls_per_minute, 60);
            assert_eq!(personal.max_instances, 50);
            assert_eq!(personal.egress_allow, ["*.example.com"]);
            assert_eq!(personal.egress_deny, ["10.0.0.0/8"]);
        }

        #[test]
        fn parses_a_per_user_backend() {
            let config = per_user(&format!("idle_timeout_secs = 30\n{FIELD}\n[database]"));
            let backend = &config.backends[0];
            assert!(backend.is_per_user());
            assert_eq!(backend.idle_timeout_secs, Some(30));
            assert_eq!(
                backend.credential_fields,
                [CredentialField {
                    name: "token".into(),
                    label: None,
                    header: "Authorization".into(),
                    prefix: Some("Bearer ".into()),
                }]
            );
            config.validate().expect("should be valid");
        }

        #[test]
        fn backends_are_shared_by_default() {
            let config = parse("transport = \"http\"\nurl = \"http://x\"", "");
            assert_eq!(config.backends[0].credential_mode, CredentialMode::Shared);
            assert!(!config.backends[0].is_per_user());
            assert_eq!(config.backends[0].credential_fields.len(), 0);
            assert_eq!(config.backends[0].idle_timeout_secs, None);
        }

        #[test]
        fn credential_field_round_trips_through_json() {
            let field = CredentialField {
                name: "key".into(),
                label: Some("API key".into()),
                header: "X-Api-Key".into(),
                prefix: None,
            };
            let json = serde_json::to_string(&field).expect("should serialize");
            let back: CredentialField = serde_json::from_str(&json).expect("should parse");
            assert_eq!(back, field);
        }

        #[test]
        fn stdio_is_rejected() {
            let config = parse(
                "transport = \"stdio\"\ncommand = \"x\"\ncredential_mode = \"per_user\"",
                &format!("{FIELD}\n[database]"),
            );
            assert!(reason(&config).contains("stdio"));
        }

        #[test]
        fn url_is_required() {
            let config = parse(
                "transport = \"http\"\ncredential_mode = \"per_user\"",
                &format!("{FIELD}\n[database]"),
            );
            assert!(matches!(
                config.validate(),
                Err(ConfigError::MissingUrl { .. } | ConfigError::InvalidPerUserBackend { .. })
            ));
        }

        #[test]
        fn a_credential_field_is_required() {
            let config = per_user("[database]");
            assert!(reason(&config).contains("at least one"));
        }

        #[test]
        fn field_names_must_be_non_empty() {
            let config =
                per_user("credential_fields = [{ name = \"\", header = \"X-Key\" }]\n[database]");
            assert!(reason(&config).contains("empty name"));
        }

        #[test]
        fn field_names_must_be_unique() {
            let config = per_user(
                "credential_fields = [{ name = \"k\", header = \"X-A\" }, { name = \"k\", header = \"X-B\" }]\n[database]",
            );
            assert!(reason(&config).contains("twice"));
        }

        #[test]
        fn header_must_be_a_valid_name() {
            let config = per_user(
                "credential_fields = [{ name = \"k\", header = \"bad header\" }]\n[database]",
            );
            assert!(reason(&config).contains("invalid header name"));
        }

        #[test]
        fn a_database_is_required() {
            let config = per_user(FIELD);
            assert!(matches!(
                config.validate(),
                Err(ConfigError::PerUserRequiresDatabase { .. })
            ));
        }

        #[test]
        fn shared_backends_need_none_of_it() {
            let config = parse("transport = \"http\"\nurl = \"http://x\"", "");
            config.validate().expect("should be valid");
        }

        const HTTP: &str = "transport = \"http\"\nurl = \"http://localhost:9000\"";

        const OIDC: &str = r#"
            [[auth.oidc]]
            id = "entra"
            issuer = "https://login.example.com/v2.0"
            client_id = "app"
            client_secret_env = "ENTRA_SECRET"
        "#;

        const OIDC_PUBLIC: &str = r#"
            [[auth.oidc]]
            id = "entra"
            issuer = "https://login.example.com/v2.0"
            client_id = "app"
        "#;

        fn with_mode(mode: &str, extra: &str) -> Config {
            parse(&format!("{HTTP}\ncredential_mode = \"{mode}\""), extra)
        }

        fn passthrough(table: &str, oidc: &str) -> Config {
            with_mode(
                "passthrough",
                &format!("[backends.passthrough]\n{table}\n[database]\n{oidc}"),
            )
        }

        #[test]
        fn parses_an_oauth_backend() {
            let config = with_mode(
                "oauth",
                "[backends.oauth]\nclient_id = \"c\"\nclient_secret_env = \"WIKI_SECRET\"\nscopes = [\"read\", \"write\"]\n[database]",
            );
            let backend = &config.backends[0];
            assert_eq!(backend.credential_mode, CredentialMode::OAuth);
            assert!(backend.is_per_user());
            let oauth = backend.oauth.as_ref().expect("oauth table");
            assert_eq!(oauth.client_id, "c");
            assert_eq!(oauth.client_secret_env.as_deref(), Some("WIKI_SECRET"));
            assert_eq!(oauth.client_secret, None, "read when the config loads");
            assert_eq!(oauth.scopes, ["read", "write"]);
            config.validate().expect("should be valid");
        }

        #[test]
        fn an_oauth_backend_needs_no_static_client() {
            let config = with_mode("oauth", "[database]");
            assert!(config.backends[0].oauth.is_none());
            config.validate().expect("should be valid");
        }

        #[test]
        fn the_oauth_client_secret_is_read_from_the_environment() {
            let mut config = with_mode(
                "oauth",
                "[backends.oauth]\nclient_id = \"c\"\nclient_secret_env = \"WIKI_SECRET\"\n[database]",
            );
            let mut env = HashMap::new();
            env.insert("WIKI_SECRET".to_string(), "hunter2".to_string());
            config.resolve_env_vars(&env).expect("should resolve");
            let oauth = config.backends[0].oauth.as_ref().expect("oauth table");
            assert_eq!(oauth.client_secret.as_deref(), Some("hunter2"));
            assert!(!format!("{oauth:?}").contains("hunter2"));

            env.insert("WIKI_SECRET".to_string(), String::new());
            let error = config.resolve_env_vars(&env).expect_err("empty secret");
            assert!(error.to_string().contains("WIKI_SECRET"), "{error}");
            let error = config
                .resolve_env_vars(&HashMap::new())
                .expect_err("unset secret");
            assert!(error.to_string().contains("WIKI_SECRET"), "{error}");
        }

        #[test]
        fn an_oauth_backend_needs_http_a_url_and_a_database() {
            let config = parse(
                "transport = \"sse\"\nurl = \"http://x\"\ncredential_mode = \"oauth\"",
                "[database]",
            );
            assert!(reason(&config).contains("http"));
            let config = parse(
                "transport = \"stdio\"\ncommand = \"x\"\ncredential_mode = \"oauth\"",
                "[database]",
            );
            assert!(reason(&config).contains("stdio"));
            let config = with_mode("oauth", "");
            assert!(matches!(
                config.validate(),
                Err(ConfigError::PerUserRequiresDatabase { .. })
            ));
        }

        #[test]
        fn an_oauth_backend_takes_no_credential_fields() {
            let config = with_mode("oauth", &format!("{FIELD}\n[database]"));
            assert!(reason(&config).contains("credential_fields must be empty"));
        }

        #[test]
        fn an_oauth_client_needs_an_id() {
            let config = with_mode("oauth", "[backends.oauth]\nclient_id = \"\"\n[database]");
            assert!(reason(&config).contains("client_id"));
        }

        #[test]
        fn the_oauth_table_is_only_for_the_oauth_mode() {
            let table = "[backends.oauth]\nclient_id = \"c\"\n[database]";
            let config = per_user(&format!("{FIELD}\n{table}"));
            assert!(reason(&config).contains("credential_mode = \"oauth\""));
            let config = parse(HTTP, table);
            assert!(reason(&config).contains("credential_mode = \"oauth\""));
            let config = passthrough(
                "grant = \"token_exchange\"\nprovider = \"entra\"\n[backends.oauth]\nclient_id = \"c\"",
                OIDC,
            );
            assert!(reason(&config).contains("credential_mode = \"oauth\""));
        }

        #[test]
        fn the_passthrough_table_is_only_for_the_passthrough_mode() {
            let table = "[backends.passthrough]\ngrant = \"token_exchange\"\nprovider = \"entra\"\n[database]";
            let config = parse(HTTP, table);
            assert!(reason(&config).contains("credential_mode = \"passthrough\""));
            let config = with_mode(
                "oauth",
                "[backends.passthrough]\ngrant = \"token_exchange\"\nprovider = \"entra\"\n[database]",
            );
            assert!(reason(&config).contains("credential_mode = \"passthrough\""));
        }

        #[test]
        fn parses_a_token_exchange_backend() {
            let config = passthrough(
                "grant = \"token_exchange\"\nprovider = \"entra\"\naudience = \"api://wiki\"\nscope = \"read\"\nresource = \"https://wiki.example.com\"",
                OIDC_PUBLIC,
            );
            let backend = &config.backends[0];
            assert_eq!(backend.credential_mode, CredentialMode::Passthrough);
            assert!(backend.is_per_user());
            assert_eq!(
                backend.passthrough,
                Some(PassthroughConfig {
                    grant: PassthroughGrant::TokenExchange,
                    provider: "entra".into(),
                    audience: Some("api://wiki".into()),
                    scope: Some("read".into()),
                    resource: Some("https://wiki.example.com".into()),
                    assertion_scope: None,
                })
            );
            config.validate().expect("should be valid");
        }

        #[test]
        fn parses_an_entra_obo_backend() {
            let config = passthrough(
                "grant = \"entra_obo\"\nprovider = \"entra\"\nscope = \"api://wiki/.default\"",
                OIDC,
            );
            let passthrough = config.backends[0].passthrough.as_ref().expect("table");
            assert_eq!(passthrough.grant, PassthroughGrant::EntraObo);
            config.validate().expect("should be valid");
        }

        #[test]
        fn a_passthrough_backend_needs_its_table() {
            let config = with_mode("passthrough", &format!("[database]\n{OIDC}"));
            assert!(reason(&config).contains("passthrough table"));
        }

        #[test]
        fn the_passthrough_provider_must_be_configured() {
            let config = passthrough("grant = \"token_exchange\"\nprovider = \"other\"", OIDC);
            assert!(reason(&config).contains("'other'"));
            let config = passthrough("grant = \"token_exchange\"\nprovider = \"entra\"", "");
            assert!(reason(&config).contains("'entra'"));
        }

        #[test]
        fn entra_obo_needs_a_scope_and_a_client_secret() {
            let config = passthrough("grant = \"entra_obo\"\nprovider = \"entra\"", OIDC);
            assert!(reason(&config).contains("passthrough.scope"));
            let config = passthrough(
                "grant = \"entra_obo\"\nprovider = \"entra\"\nscope = \"api://x/.default\"",
                OIDC_PUBLIC,
            );
            assert!(reason(&config).contains("client secret"));
        }

        #[test]
        fn the_assertion_scope_is_only_for_entra_obo() {
            let config = passthrough(
                "grant = \"entra_obo\"\nprovider = \"entra\"\nscope = \"api://wiki/.default\"\nassertion_scope = \"api://gateway/.default\"",
                OIDC,
            );
            let passthrough_table = config.backends[0].passthrough.as_ref().expect("table");
            assert_eq!(
                passthrough_table.assertion_scope.as_deref(),
                Some("api://gateway/.default")
            );
            config.validate().expect("should be valid");

            let config = passthrough(
                "grant = \"token_exchange\"\nprovider = \"entra\"\nassertion_scope = \"api://gateway/.default\"",
                OIDC,
            );
            assert!(reason(&config).contains("assertion_scope"));
        }

        #[test]
        fn an_empty_assertion_scope_is_rejected() {
            let config = passthrough(
                "grant = \"entra_obo\"\nprovider = \"entra\"\nscope = \"api://wiki/.default\"\nassertion_scope = \"\"",
                OIDC,
            );
            assert!(reason(&config).contains("assertion_scope must not be empty"));
        }

        #[test]
        fn passthrough_takes_no_fields_and_needs_a_database() {
            let config = with_mode(
                "passthrough",
                &format!(
                    "{FIELD}\n[backends.passthrough]\ngrant = \"token_exchange\"\nprovider = \"entra\"\n[database]\n{OIDC}"
                ),
            );
            assert!(reason(&config).contains("credential_fields must be empty"));

            let config = with_mode(
                "passthrough",
                &format!(
                    "[backends.passthrough]\ngrant = \"token_exchange\"\nprovider = \"entra\"\n{OIDC}"
                ),
            );
            assert!(matches!(
                config.validate(),
                Err(ConfigError::PerUserRequiresDatabase { .. })
            ));
        }

        #[test]
        fn an_unknown_grant_does_not_parse() {
            let toml = format!(
                "{BASE}\n[[backends]]\nname = \"cat\"\n{HTTP}\ncredential_mode = \"passthrough\"\n[backends.passthrough]\ngrant = \"magic\"\nprovider = \"entra\""
            );
            assert!(toml::from_str::<Config>(&toml).is_err());
        }
    }
}
