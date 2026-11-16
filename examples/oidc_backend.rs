//! A small MCP server that mostly accepts only JWTs issued by the dev mock OIDC
//! provider (`http://127.0.0.1:4011/default`, see `example/compose.local.yml`),
//! to test the gateway's `credential_mode = "oauth"` and `"passthrough"`
//! (RFC 8693 token exchange) end to end. Dev only, nothing here is configurable.
//!
//! Run it with `cargo run --example oidc_backend`, or `just axon-oidc-backend`
//! from the yggdrasil root. It listens on 127.0.0.1:3003 and serves the tools
//! `whoami` (the endpoint and the verified claims of the calling token) and
//! `echo` on three endpoints, two of them behind their own bearer gate:
//!
//! - `/oauth/mcp` needs `aud` to contain `http://127.0.0.1:3003/oauth/mcp`.
//!   Add it to axon as a catalog entry with auth "oauth" and any client id (the
//!   mock accepts any); the gateway asks for the token with RFC 8707 `resource`.
//! - `/passthrough/mcp` needs `aud` to contain `axon-demo`. Add a backend with
//!   `credential_mode = "passthrough"`, grant `token_exchange`, provider `sso`
//!   and audience `axon-demo`.
//! - `/open/mcp` takes no token at all, so `whoami` reports no claims there.
//!
//! The gated two check the signature against the mock's JWKS, `iss` and `exp`, and answer
//! 401 with a `WWW-Authenticate` header pointing at the protected resource
//! metadata under `/.well-known/oauth-protected-resource/<endpoint>`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get};
use color_eyre::eyre::Result;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::StreamableHttpServerConfig;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::EnvFilter;

const ADDR: &str = "127.0.0.1:3003";
const BASE_URL: &str = "http://127.0.0.1:3003";
const ISSUER: &str = "http://127.0.0.1:4011/default";
const JWKS_URL: &str = "http://127.0.0.1:4011/default/jwks";
/// Endpoint path and the audience its tokens need.
const ENDPOINTS: [(&str, &str); 2] = [
    ("/oauth/mcp", "http://127.0.0.1:3003/oauth/mcp"),
    ("/passthrough/mcp", "axon-demo"),
];
/// Endpoint without a token check, for a shared backend (the e2e suite registers one).
const OPEN_PATH: &str = "/open/mcp";
/// The claims `whoami` reports, when the token has them.
const CLAIMS: [&str; 9] = [
    "sub",
    "iss",
    "aud",
    "azp",
    "client_id",
    "preferred_username",
    "email",
    "groups",
    "exp",
];

/// The mock's signing keys, refetched once when a token names an unknown `kid`.
struct Keys {
    http: reqwest::Client,
    set: RwLock<JwkSet>,
}

impl Keys {
    async fn fetch(http: &reqwest::Client) -> Result<JwkSet> {
        let body = http
            .get(JWKS_URL)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        Ok(serde_json::from_str(&body)?)
    }

    async fn load() -> Result<Self> {
        let http = reqwest::Client::new();
        let set = RwLock::new(Self::fetch(&http).await?);
        Ok(Self { http, set })
    }

    async fn find(&self, kid: &str) -> Result<Jwk, String> {
        if let Some(jwk) = self.set.read().await.find(kid) {
            return Ok(jwk.clone());
        }
        info!(kid, "unknown kid, refetching the JWKS");
        let fresh = Self::fetch(&self.http)
            .await
            .map_err(|error| format!("JWKS refetch failed: {error}"))?;
        let jwk = fresh
            .find(kid)
            .cloned()
            .ok_or_else(|| format!("no key with kid {kid} in the JWKS"))?;
        *self.set.write().await = fresh;
        Ok(jwk)
    }
}

/// One bearer gate: the endpoint it protects and the audience it requires.
#[derive(Clone)]
struct Gate {
    path: &'static str,
    audience: &'static str,
    keys: Arc<Keys>,
}

/// What the gate hands to the MCP service in the request extensions.
#[derive(Clone)]
struct Verified {
    path: &'static str,
    claims: Value,
}

async fn verify(keys: &Keys, token: &str, audience: &str) -> Result<Value, String> {
    let header =
        jsonwebtoken::decode_header(token).map_err(|error| format!("malformed: {error}"))?;
    let kid = header
        .kid
        .ok_or_else(|| "the token header has no kid".to_string())?;
    let jwk = keys.find(&kid).await?;
    let key = DecodingKey::from_jwk(&jwk).map_err(|error| format!("unusable key: {error}"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    jsonwebtoken::decode::<Value>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|error| error.to_string())
}

fn unauthorized(path: &str, rejected: bool) -> Response {
    let mut challenge = format!(
        "Bearer resource_metadata=\"{BASE_URL}/.well-known/oauth-protected-resource{path}\""
    );
    if rejected {
        challenge.push_str(", error=\"invalid_token\"");
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
    )
        .into_response()
}

async fn check_bearer(State(gate): State<Gate>, mut request: Request, next: Next) -> Response {
    let path = gate.path;
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    let Some(token) = token else {
        info!(path, "rejected: no bearer token");
        return unauthorized(path, false);
    };
    match verify(&gate.keys, token, gate.audience).await {
        Ok(claims) => {
            request.extensions_mut().insert(Verified { path, claims });
            next.run(request).await
        }
        Err(reason) => {
            info!(path, %reason, "rejected: invalid token");
            unauthorized(path, true)
        }
    }
}

fn metadata(path: &'static str) -> MethodRouter {
    get(move || async move {
        Json(json!({
            "resource": format!("{BASE_URL}{path}"),
            "authorization_servers": [ISSUER],
            "scopes_supported": ["openid"],
            "bearer_methods_supported": ["header"],
        }))
    })
}

fn tool(name: &'static str, description: &'static str, schema: Value) -> Tool {
    Tool::new(
        name,
        description,
        Arc::new(serde_json::from_value(schema).unwrap_or_default()),
    )
}

#[derive(Clone)]
struct OidcBackend;

impl ServerHandler for OidcBackend {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("oidc-backend", "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![
            tool(
                "whoami",
                "The endpoint and the verified token claims of this request",
                json!({"type": "object"}),
            ),
            tool(
                "echo",
                "Returns the message",
                json!({
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                }),
            ),
        ]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let text = match name.as_str() {
            "whoami" => {
                let verified = context
                    .extensions
                    .get::<axum::http::request::Parts>()
                    .and_then(|parts| parts.extensions.get::<Verified>())
                    .ok_or_else(|| {
                        McpError::internal_error("no verified token on the request", None)
                    })?;
                let mut who = Map::new();
                who.insert("endpoint".to_string(), json!(verified.path));
                for claim in CLAIMS {
                    if let Some(value) = verified.claims.get(claim) {
                        who.insert(claim.to_string(), value.clone());
                    }
                }
                serde_json::to_string_pretty(&Value::Object(who))
                    .map_err(|error| McpError::internal_error(error.to_string(), None))?
            }
            "echo" => request
                .arguments
                .as_ref()
                .and_then(|arguments| arguments.get("message"))
                .and_then(Value::as_str)
                .ok_or_else(|| McpError::invalid_params("`message` must be a string", None))?
                .to_string(),
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown tool '{other}'"),
                    None,
                ));
            }
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let keys = Arc::new(Keys::load().await?);
    let service = StreamableHttpService::new(
        || Ok(OidcBackend),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );

    let mut router = Router::new();
    for (path, audience) in ENDPOINTS {
        let gate = Gate {
            path,
            audience,
            keys: keys.clone(),
        };
        let mcp = Router::new()
            .nest_service(path, service.clone())
            .layer(middleware::from_fn_with_state(gate, check_bearer));
        router = router.merge(mcp).route(
            &format!("/.well-known/oauth-protected-resource{path}"),
            metadata(path),
        );
        info!("serving {BASE_URL}{path} (aud {audience})");
    }
    router = router.nest_service(OPEN_PATH, service.clone());
    info!("serving {BASE_URL}{OPEN_PATH} (no token)");

    let listener = TcpListener::bind(ADDR).await?;
    info!("listening on {ADDR}, trusting {ISSUER}");
    axum::serve(listener, router).await?;
    Ok(())
}
