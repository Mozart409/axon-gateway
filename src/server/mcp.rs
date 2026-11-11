//! The MCP endpoints (`/mcp`, `/mcp/toolset/{name}`, plus the deprecated alias
//! `/mcp/group/{name}`) and the toolset listing.
//!
//! The wire protocol (Streamable HTTP, sessions, `Accept` and protocol version
//! checks, JSON-RPC framing) is rmcp's [`StreamableHttpService`]. [`AxonMcp`] is the
//! handler behind it and only translates: rmcp's typed requests become the gateway's
//! [`JsonRpcRequest`], and the gateway's [`JsonRpcResponse`] becomes rmcp's result or
//! error, so the gateway stays the one place of policy. [`authenticate_mcp`] runs in
//! front of the transport and tells the handler who is calling.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{RawPathParams, Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use rmcp::ErrorData;
use rmcp::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ErrorCode, Extensions,
    GetPromptRequestParams, GetPromptResponse, GetPromptResult, Implementation, ListPromptsResult,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, ProgressNotificationParam,
    ProgressToken, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, RequestId, ServerCapabilities, ServerConfig, SubscriptionFilter,
};
use rmcp::service::{NotificationContext, RequestContext, RoleServer, SubscriptionContext};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::AppState;
use super::auth::{ClientIp, authenticate};
use super::mcp_sessions::{PgSessionStore, SessionOwners, session_owner};
use super::oauth;
use crate::audit::{CallOutcome, ToolCallEvent};
use crate::auth::AuthManager;
use crate::gateway::{Caller, DescribeTool, HandleRequest, HandleToolsetRequest};
use crate::personal::{UserBackendKind, UserSlot};
use crate::principal::{PrincipalPolicy, TokenScope};
use crate::relay::{CallRelay, PROGRESS_BUFFER};
use crate::types::{JsonRpcRequest, JsonRpcResponse};

/// Longest `User-Agent` kept in the audit.
const MAX_USER_AGENT_CHARS: usize = 200;

/// The header that carries the id of a pre-2026-07-28 session.
const SESSION_ID_HEADER: &str = "mcp-session-id";

/// JSON-RPC code of a gateway that failed to answer.
const INTERNAL_ERROR: i32 = -32603;

/// JSON-RPC code of a legacy token that may not call the tool.
const FORBIDDEN: i32 = -32000;

/// Who is calling and how, as [`authenticate_mcp`] found out. It travels in the
/// request's extensions through rmcp, which hands the handler the request's
/// `http::request::Parts`.
#[derive(Clone)]
struct McpCaller {
    caller: Arc<Caller>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    /// The toolset named in the path of `/mcp/toolset/{name}`; `None` on `/mcp`
    toolset: Option<String>,
}

/// The caller [`authenticate_mcp`] recorded on the request behind `extensions`.
fn mcp_caller(extensions: &Extensions) -> Result<McpCaller, ErrorData> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<McpCaller>())
        .cloned()
        .ok_or_else(|| ErrorData::internal_error("request carries no authenticated caller", None))
}

/// The owner a caller's tool-list changes are published for: the user behind a
/// principal. Legacy token and open callers have none and hear only global changes.
fn change_owner(caller: &Caller) -> Option<Uuid> {
    match caller {
        Caller::Principal(principal) => principal.owner_id(),
        Caller::Open | Caller::Token(_) => None,
    }
}

/// Log which principal (user or service account and token) sent a request.
/// `method` is the `Mcp-Method` header, empty when the request has none.
fn log_principal(caller: &Caller, method: &str, client_ip: Option<&str>) {
    if let Caller::Principal(principal) = caller {
        tracing::debug!(
            principal = principal.label(),
            method,
            ip = client_ip,
            "MCP request"
        );
    }
}

/// Authenticates a request to an MCP endpoint before rmcp's transport sees it.
///
/// A refused request gets `authenticate`'s response unchanged (a 401 stays an HTTP
/// 401). An accepted one carries an [`McpCaller`] in its extensions, and is counted
/// by the `Mcp-Method` header the client sent (rmcp checks it against the body).
///
/// A session of a client before 2026-07-28 belongs to the caller that opened it: a
/// request naming it from anyone else gets the 404 of an unknown session. A new
/// session (the response carries its id) is bound to the caller before the client
/// hears of it.
pub(super) async fn authenticate_mcp(
    State((state, owners)): State<(AppState, SessionOwners)>,
    ClientIp(client_ip): ClientIp,
    path_params: RawPathParams,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    let caller = match authenticate(request.headers(), &state, client_ip.as_deref()).await {
        // A 401 tells an OAuth client where to find the authorization server
        Ok(caller) => caller,
        Err(response) => return oauth::with_challenge(*response, &state, &path),
    };
    // An OAuth access token is for the endpoint it was issued for
    if let Some(response) = oauth::refuse_wrong_audience(&caller, &state, &path) {
        return response;
    }
    let mcp_method = request
        .headers()
        .get("mcp-method")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    crate::metrics::record_mcp_request(mcp_method, crate::metrics::principal_type(&caller));
    log_principal(&caller, mcp_method, client_ip.as_deref());

    let toolset = path_params
        .iter()
        .find(|(name, _)| *name == "toolset_name")
        .map(|(_, value)| value.to_owned());
    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|agent| agent.chars().take(MAX_USER_AGENT_CHARS).collect());
    let session_id = request
        .headers()
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let owner = session_owner(&caller);
    if let Some(id) = &session_id {
        match owners.owner(id).await {
            Ok(Some(bound)) if bound != owner => {
                return (StatusCode::NOT_FOUND, "Session not found").into_response();
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "could not look up the owner of an MCP session");
                return session_store_unavailable();
            }
        }
    }
    let is_delete = request.method() == http::Method::DELETE;
    request.extensions_mut().insert(McpCaller {
        caller: Arc::new(caller),
        client_ip,
        user_agent,
        toolset,
    });
    let response = next.run(request).await;

    match session_id {
        None => {
            let Some(id) = response
                .headers()
                .get(SESSION_ID_HEADER)
                .and_then(|value| value.to_str().ok())
            else {
                return response;
            };
            if let Err(error) = owners.bind(id, &owner).await {
                tracing::warn!(%error, "could not bind an MCP session to its caller");
                if let Err(error) = owners.forget(id).await {
                    tracing::warn!(%error, "could not drop an unbound MCP session");
                }
                return session_store_unavailable();
            }
        }
        Some(id) if is_delete && response.status().is_success() => {
            if let Err(error) = owners.forget(&id).await {
                tracing::warn!(%error, "could not drop the owner of an ended MCP session");
            }
        }
        Some(_) => {}
    }
    response
}

/// The answer when the session store cannot be reached.
fn session_store_unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable").into_response()
}

/// The rmcp Streamable HTTP service that serves [`AxonMcp`].
///
/// Sessions are kept for clients before 2026-07-28 (`legacy_session_mode`); the
/// newer protocol is stateless. With a database they are also stored in it, so a
/// session survives on any replica that shares the database: a replica that does not
/// know a session id restores it from there. Without one they live in this process
/// only. Replies are plain JSON rather than an event stream, and `mcp_allowed_hosts`
/// guards against DNS rebinding.
pub(super) fn mcp_service(state: &AppState) -> StreamableHttpService<AxonMcp, LocalSessionManager> {
    crate::metrics::describe_mcp_metrics();
    let handler = AxonMcp {
        state: state.clone(),
    };
    let mut config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(true)
        .with_json_response(true)
        .with_allowed_hosts(state.mcp_allowed_hosts.clone());
    if let Some(store) = &state.store {
        config.session_store = Some(Arc::new(PgSessionStore(store.clone())));
    }
    StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

/// The MCP handler: asks the gateway actor for everything and relays its answer.
#[derive(Clone)]
pub(super) struct AxonMcp {
    state: AppState,
}

/// What the tool-call audit needs from a `tools/call` made by a principal,
/// taken before the call so the time can be measured around it.
struct CallAudit {
    principal: PrincipalPolicy,
    name: String,
    arguments: Value,
    client_ip: Option<String>,
    user_agent: Option<String>,
    trace_id: Option<String>,
    started: Instant,
}

impl CallAudit {
    /// `Some` for a `tools/call` of a principal while the audit is on. Legacy
    /// token and open callers (standalone mode) are not recorded.
    fn start(state: &AppState, auth: &McpCaller, request: &JsonRpcRequest) -> Option<Self> {
        let Caller::Principal(principal) = auth.caller.as_ref() else {
            return None;
        };
        if request.method != "tools/call" || state.audit.is_none() {
            return None;
        }
        Some(Self {
            principal: principal.clone(),
            name: request
                .params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            arguments: request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(Value::Null),
            client_ip: auth.client_ip.clone(),
            user_agent: auth.user_agent.clone(),
            trace_id: crate::telemetry::current_trace_id(),
            started: Instant::now(),
        })
    }

    /// Queues the event. The tool lookup and the queueing run in a task, so
    /// the response is not delayed; the arguments are never logged here. A
    /// tool of the caller's own personal backend (found in `slot` when the
    /// shared registry has no such tool) is recorded without its arguments.
    fn finish(
        self,
        state: &AppState,
        response: Option<&JsonRpcResponse>,
        slot: Option<Arc<UserSlot>>,
    ) {
        let Some(sink) = state.audit.clone() else {
            return;
        };
        let duration = self.started.elapsed();
        let (outcome, error_code, error_message) = outcome_of(response);
        let gateway = state.gateway.clone();
        tokio::spawn(async move {
            let described = gateway
                .ask(DescribeTool {
                    namespaced_name: self.name.clone(),
                })
                .await
                .ok()
                .flatten();
            let mut personal = false;
            let described = match (described, slot) {
                (None, Some(slot)) => {
                    let own = slot
                        .registry
                        .ask(crate::registry::DescribeTool {
                            namespaced_tool_name: self.name.clone(),
                        })
                        .await
                        .ok()
                        .flatten();
                    personal = own.as_ref().is_some_and(|tool| {
                        matches!(
                            slot.kinds.get(&tool.backend_name),
                            Some(UserBackendKind::Personal { .. })
                        )
                    });
                    own
                }
                (described, _) => described,
            };
            let (backend, tool, annotations) = match described {
                Some(tool) => (tool.backend_name, tool.original_tool_name, tool.annotations),
                None => (String::new(), self.name, None),
            };
            sink.record(ToolCallEvent {
                user_id: self.principal.owner_id(),
                principal_label: self.principal.label().to_owned(),
                token_id: self.principal.token_id(),
                auth_method: if self.principal.token_id().is_some() {
                    "pat"
                } else {
                    "config_token"
                }
                .to_owned(),
                backend,
                tool,
                outcome,
                error_code,
                error_message,
                duration,
                trace_id: self.trace_id,
                client_ip: self.client_ip,
                user_agent: self.user_agent,
                arguments: if personal {
                    Value::Null
                } else {
                    self.arguments
                },
                annotations,
                personal,
            });
        });
    }
}

/// The audit outcome of a gateway answer: a JSON-RPC error, a tool result with
/// `isError` (message from its first text content), or success. No answer at
/// all counts as an internal error.
fn outcome_of(response: Option<&JsonRpcResponse>) -> (CallOutcome, Option<i32>, Option<String>) {
    let Some(response) = response else {
        return (
            CallOutcome::Error,
            Some(INTERNAL_ERROR),
            Some("gateway error".to_owned()),
        );
    };
    if let Some(error) = &response.error {
        return (
            CallOutcome::Error,
            Some(error.code),
            Some(error.message.clone()),
        );
    }
    let result = response.result.as_ref();
    if result
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let message = result
            .and_then(|result| result.get("content"))
            .and_then(Value::as_array)
            .and_then(|content| {
                content
                    .iter()
                    .find_map(|item| item.get("text").and_then(Value::as_str).map(str::to_owned))
            });
        return (CallOutcome::ToolError, None, message);
    }
    (CallOutcome::Ok, None, None)
}

impl AxonMcp {
    /// Asks the gateway `method` with `params` on behalf of the caller of the
    /// request, audits it when it is a principal's `tools/call`, and turns the
    /// answer into the rmcp result type `R`.
    async fn forward<P: Serialize, R: DeserializeOwned>(
        &self,
        auth: &McpCaller,
        id: &RequestId,
        method: &str,
        params: &P,
        relay: Option<CallRelay>,
    ) -> Result<R, ErrorData> {
        let params = serde_json::to_value(params)
            .map_err(|error| ErrorData::invalid_params(format!("Invalid params: {error}"), None))?;
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_owned(),
            id: serde_json::to_value(id).ok(),
            method: method.to_owned(),
            params,
        };
        let audit = CallAudit::start(&self.state, auth, &request);
        let slot = if method.starts_with("tools/") && auth.toolset.is_none() {
            self.personal_slot(auth).await
        } else {
            None
        };
        let response = self.ask_gateway(auth, request, relay, slot.clone()).await;
        if let Some(audit) = audit {
            audit.finish(&self.state, response.as_ref().ok(), slot);
        }
        let result = into_result(response?)?;
        serde_json::from_value(result).map_err(|error| {
            tracing::error!("Gateway answered {method} with an unexpected result: {error}");
            ErrorData::internal_error("gateway error", None)
        })
    }

    /// The caller's own and catalog backends: for a principal with an owner
    /// when personal backends are on and the user has any.
    async fn personal_slot(&self, auth: &McpCaller) -> Option<Arc<UserSlot>> {
        let hub = self.state.personal.as_ref()?;
        let Caller::Principal(principal) = auth.caller.as_ref() else {
            return None;
        };
        hub.slot(principal.owner_id()?).await
    }

    /// Sends the request to the gateway actor. On `/mcp` the caller's own
    /// backends (`slot`) are served next to the shared ones. On `/mcp/toolset/{name}` a
    /// principal that owns a toolset of that name is narrowed with it and served like
    /// on `/mcp`, listing and calls both; anyone else gets the config toolset, which
    /// only filters `tools/list` (tool calls are forwarded normally). Neither serves
    /// personal tools.
    async fn ask_gateway(
        &self,
        auth: &McpCaller,
        request: JsonRpcRequest,
        relay: Option<CallRelay>,
        slot: Option<Arc<UserSlot>>,
    ) -> Result<JsonRpcResponse, ErrorData> {
        let gateway = &self.state.gateway;
        let answer = match auth.toolset.as_deref() {
            None => gateway
                .ask(HandleRequest {
                    request,
                    caller: auth.caller.clone(),
                    relay,
                    hub: slot.as_ref().and_then(|_| self.state.personal.clone()),
                    personal: slot,
                })
                .await
                .map_err(|error| format!("{error:?}")),
            Some(name) => match own_toolset(&self.state, &auth.caller, name).await? {
                Some(principal) => gateway
                    .ask(HandleRequest {
                        request,
                        caller: Arc::new(Caller::Principal(principal)),
                        relay,
                        personal: None,
                        hub: None,
                    })
                    .await
                    .map_err(|error| format!("{error:?}")),
                None => gateway
                    .ask(HandleToolsetRequest {
                        request,
                        caller: auth.caller.clone(),
                        toolset_name: name.to_owned(),
                        relay,
                    })
                    .await
                    .map_err(|error| format!("{error:?}")),
            },
        };
        answer.map_err(|error| {
            tracing::error!("Gateway error: {error}");
            ErrorData::internal_error("gateway error", None)
        })
    }
}

/// The result of a gateway answer, or its JSON-RPC error with the same code,
/// message and data.
fn into_result(response: JsonRpcResponse) -> Result<Value, ErrorData> {
    match response.error {
        Some(error) => Err(ErrorData::new(
            ErrorCode(error.code),
            error.message,
            error.data,
        )),
        None => Ok(response.result.unwrap_or(Value::Null)),
    }
}

/// What a `tools/call` hands down to the backend call: the client's progress
/// (only when it sent a progress token) and its cancellation.
fn call_relay(context: &RequestContext<RoleServer>) -> CallRelay {
    let progress = context.meta.get_progress_token().map(|token| {
        let (sender, receiver) = mpsc::channel(PROGRESS_BUFFER);
        tokio::spawn(forward_progress(receiver, token, context.peer.clone()));
        sender
    });
    CallRelay {
        progress,
        cancel: context.ct.clone(),
    }
}

/// Passes the backend's progress notifications on to the client, under the
/// client's own progress token. Ends when the call is over and the channel closes.
async fn forward_progress(
    mut receiver: mpsc::Receiver<ProgressNotificationParam>,
    token: ProgressToken,
    peer: rmcp::Peer<RoleServer>,
) {
    while let Some(mut progress) = receiver.recv().await {
        progress.progress_token = token.clone();
        if let Err(error) = peer.notify_progress(progress).await {
            tracing::debug!("Could not forward progress to the client: {error}");
        }
    }
}

impl ServerHandler for AxonMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::new(
            "axon-gateway",
            env!("CARGO_PKG_VERSION"),
        ))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2026_07_28,
        ])
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        self.forward(&auth, &context.id, "tools/list", &request, None)
            .await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        // A legacy token's tool-level permissions are checked here. A principal's
        // are checked in the gateway, which answers a tool it may not call like an
        // unknown one.
        if let Caller::Token(identity) = auth.caller.as_ref()
            && let Err(error) = AuthManager::check_tool_permission(Some(identity), &request.name)
        {
            tracing::warn!("Tool permission denied: {error}");
            return Err(ErrorData::new(
                ErrorCode(FORBIDDEN),
                "Forbidden: the token may not call this tool",
                None,
            ));
        }
        let relay = call_relay(&context);
        let result = self
            .forward::<_, CallToolResult>(&auth, &context.id, "tools/call", &request, Some(relay))
            .await?;
        Ok(result.into())
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        self.forward(&auth, &context.id, "resources/list", &request, None)
            .await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        let result = self
            .forward::<_, ReadResourceResult>(&auth, &context.id, "resources/read", &request, None)
            .await?;
        Ok(result.into())
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        self.forward(&auth, &context.id, "prompts/list", &request, None)
            .await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let auth = mcp_caller(&context.extensions)?;
        let result = self
            .forward::<_, GetPromptResult>(&auth, &context.id, "prompts/get", &request, None)
            .await?;
        Ok(result.into())
    }

    /// Only tool-list changes are offered; rmcp narrows the request to the
    /// intersection with this and the advertised capabilities.
    fn accepted_subscription_filter(
        &self,
        _requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Some(SubscriptionFilter::builder().tools_list_changed().build())
    }

    /// A 2026-07-28 `subscriptions/listen`: tells the caller whenever its tool list
    /// may have changed, until the client cancels the request or the bus closes.
    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let auth = mcp_caller(&context.request_context().extensions)?;
        let owner = change_owner(&auth.caller);
        let mut subscription = self.state.changes.subscribe();
        loop {
            tokio::select! {
                () = context.cancelled() => return Ok(()),
                changed = subscription.changed_for(owner) => {
                    if !changed || context.sink().notify_tool_list_changed().await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Sessions before 2026-07-28 have no `subscriptions/listen`: once the client
    /// is initialized, a task sends it `notifications/tools/list_changed` on its
    /// stream. It ends when sending fails (the session is gone) or the bus closes.
    async fn on_initialized(&self, context: NotificationContext<RoleServer>) {
        let auth = match mcp_caller(&context.extensions) {
            Ok(auth) => auth,
            Err(error) => {
                tracing::warn!("No tool-list notifications for a session: {error}");
                return;
            }
        };
        let owner = change_owner(&auth.caller);
        let mut changes = self.state.changes.subscribe();
        let peer = context.peer.clone();
        tokio::spawn(async move {
            while changes.changed_for(owner).await {
                if peer.notify_tool_list_changed().await.is_err() {
                    break;
                }
            }
        });
    }
}

/// The caller narrowed with its own toolset called `name`. `Ok(None)` when it has
/// none (the caller is no principal, has no owner, there is no multi-user store, or
/// no such toolset) and the config toolset path applies; `Err` is a store failure.
async fn own_toolset(
    state: &AppState,
    caller: &Caller,
    name: &str,
) -> Result<Option<PrincipalPolicy>, ErrorData> {
    let (Caller::Principal(principal), Some((store, _))) = (caller, state.multi_user()) else {
        return Ok(None);
    };
    let Some(owner_id) = principal.owner_id() else {
        return Ok(None);
    };
    match store.toolset_by_name(owner_id, name).await {
        Ok(Some(toolset)) => {
            let scope = TokenScope {
                backends: toolset.backends,
                tools: toolset.tools,
            };
            Ok(Some(principal.clone().with_toolset(scope)))
        }
        Ok(None) => Ok(None),
        Err(error) => {
            tracing::error!("Failed to look up a user toolset: {error}");
            Err(ErrorData::internal_error(
                "Failed to look up the toolset",
                None,
            ))
        }
    }
}

/// List available toolsets
pub(super) async fn list_toolsets(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let toolsets = state
        .gateway
        .ask(crate::gateway::GetToolsets)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list toolsets: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(json!({ "toolsets": toolsets })))
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::auth::SharedAuth;
    use crate::config::GatewayConfig;
    use crate::server::create_router;
    use crate::server::tests::test_state;

    /// The `_meta` every 2026-07-28 request carries.
    fn stateless_meta() -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { "name": "test", "version": "0" },
        })
    }

    /// A 2026-07-28 JSON-RPC request with the headers rmcp requires of it.
    fn stateless_request(
        uri: &str,
        method: &str,
        name: Option<&str>,
        params: Value,
    ) -> Request<Body> {
        let mut params = params;
        params["_meta"] = stateless_meta();
        let mut builder = Request::builder()
            .uri(uri)
            .method(http::Method::POST)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = name {
            builder = builder.header("mcp-name", name);
        }
        let body = json!({ "jsonrpc": "2.0", "id": 7, "method": method, "params": params });
        builder
            .body(Body::from(body.to_string()))
            .expect("request should build")
    }

    async fn send(state: AppState, request: Request<Body>) -> (StatusCode, Vec<u8>) {
        let response = create_router(state)
            .oneshot(request)
            .await
            .expect("router should respond");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        (status, body.to_vec())
    }

    async fn call(uri: &str, method: &str, name: Option<&str>, params: Value) -> Value {
        let (status, body) = send(test_state(), stateless_request(uri, method, name, params)).await;
        assert!(status.is_success() || status.is_client_error(), "{status}");
        serde_json::from_slice(&body).expect("json body")
    }

    #[rstest::rstest]
    #[case("/mcp", "notifications/initialized")]
    #[case("/mcp", "notifications/cancelled")]
    #[case("/mcp/toolset/any", "notifications/initialized")]
    #[case("/mcp/group/any", "notifications/initialized")]
    #[tokio::test]
    async fn notifications_get_202_with_empty_body(#[case] uri: &str, #[case] method: &str) {
        let body = json!({ "jsonrpc": "2.0", "method": method, "params": {} });
        let request = Request::builder()
            .uri(uri)
            .method(http::Method::POST)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method)
            .body(Body::from(body.to_string()))
            .expect("request should build");
        let (status, body) = send(test_state(), request).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(body.is_empty(), "notification body must be empty");
    }

    #[tokio::test]
    async fn bare_json_post_is_rejected() {
        // The transport is strict: no `Accept`, no protocol version, no session
        let request = Request::builder()
            .uri("/mcp")
            .method(http::Method::POST)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }).to_string(),
            ))
            .expect("request should build");
        let (status, _) = send(test_state(), request).await;
        assert_eq!(status, StatusCode::NOT_ACCEPTABLE);
    }

    #[tokio::test]
    async fn requests_with_id_get_a_json_response() {
        let payload = call("/mcp", "tools/list", None, json!({})).await;
        assert_eq!(payload["id"], 7);
        assert!(payload["result"].is_object(), "{payload}");
    }

    #[tokio::test]
    async fn tools_list_is_answered_by_the_gateway() {
        let payload = call("/mcp", "tools/list", None, json!({})).await;
        assert_eq!(payload["id"], 7);
        assert_eq!(payload["result"]["tools"], json!([]));
    }

    #[tokio::test]
    async fn gateway_errors_keep_their_code_and_message() {
        let payload = call(
            "/mcp",
            "tools/call",
            Some("nope"),
            json!({ "name": "nope", "arguments": {} }),
        )
        .await;
        assert_eq!(payload["error"]["code"], -32601);
        assert_eq!(payload["error"]["message"], "Unknown tool: nope");
    }

    #[tokio::test]
    async fn requests_need_the_token_when_auth_is_configured() {
        let config = GatewayConfig {
            bind: String::from("127.0.0.1:0"),
            base_url: String::from("http://127.0.0.1:8080"),
            auth_token: Some(String::from("secret")),
            rate_limit_per_minute: 0,
            allow_stdio: false,
            allowed_hosts: vec![],
            idle_timeout_secs: 300,
        };
        let state = AppState {
            auth_manager: SharedAuth::new(AuthManager::new(&config, &[])),
            ..test_state()
        };
        let (status, _) = send(
            state.clone(),
            stateless_request("/mcp", "tools/list", None, json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let mut request = stateless_request("/mcp", "tools/list", None, json!({}));
        request
            .headers_mut()
            .insert("authorization", "Bearer secret".parse().expect("header"));
        let (status, _) = send(state, request).await;
        assert_eq!(status, StatusCode::OK);
    }

    fn named_token(name: &str, token: &str) -> crate::config::TokenConfig {
        crate::config::TokenConfig {
            name: name.to_owned(),
            token: token.to_owned(),
            allowed_tools: Vec::new(),
            allowed_backends: Vec::new(),
            rate_limit_per_minute: 0,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// A request of a pre-2026-07-28 client with `token`, in the session `session`
    /// (none for the `initialize` that opens one).
    fn legacy_request(token: &str, session: Option<&str>, method: &str) -> Request<Body> {
        let body = match session {
            None => json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" },
                },
            }),
            Some(_) => json!({ "jsonrpc": "2.0", "method": method, "params": {} }),
        };
        let mut builder = Request::builder()
            .uri("/mcp")
            .method(http::Method::POST)
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18")
            .header("mcp-method", method);
        if let Some(session) = session {
            builder = builder.header(SESSION_ID_HEADER, session);
        }
        builder
            .body(Body::from(body.to_string()))
            .expect("request should build")
    }

    #[tokio::test]
    async fn a_session_answers_only_the_token_that_opened_it() {
        let config = GatewayConfig {
            bind: String::from("127.0.0.1:0"),
            base_url: String::from("http://127.0.0.1:8080"),
            auth_token: None,
            rate_limit_per_minute: 0,
            allow_stdio: false,
            allowed_hosts: vec![],
            idle_timeout_secs: 300,
        };
        let tokens = [named_token("a", "token-a"), named_token("b", "token-b")];
        let state = AppState {
            auth_manager: SharedAuth::new(AuthManager::new(&config, &tokens)),
            ..test_state()
        };
        // One router, so the sessions and their owners are shared between requests
        let router = create_router(state);

        let opened = router
            .clone()
            .oneshot(legacy_request("token-a", None, "initialize"))
            .await
            .expect("router should respond");
        assert_eq!(opened.status(), StatusCode::OK);
        let session = opened
            .headers()
            .get(SESSION_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("initialize opens a session")
            .to_owned();

        let own = router
            .clone()
            .oneshot(legacy_request(
                "token-a",
                Some(&session),
                "notifications/initialized",
            ))
            .await
            .expect("router should respond");
        assert_eq!(own.status(), StatusCode::ACCEPTED);

        let foreign = router
            .oneshot(legacy_request(
                "token-b",
                Some(&session),
                "notifications/initialized",
            ))
            .await
            .expect("router should respond");
        assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn serves_the_three_protocol_versions() {
        let handler = AxonMcp {
            state: test_state(),
        };
        let versions = handler.supported_protocol_versions();
        let names: Vec<&str> = versions.iter().map(ProtocolVersion::as_str).collect();
        assert_eq!(names, ["2025-06-18", "2025-11-25", "2026-07-28"]);
    }
}
