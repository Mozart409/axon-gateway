//! Authentication of the MCP endpoints.

use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use super::AppState;
use crate::auth::AuthError;
use crate::gateway::Caller;
use crate::policy::OptOuts;
use crate::principal::{PrincipalPolicy, TokenScope};
use crate::store::{PAT_PREFIX, Store, StoreError};

/// 401 with the `WWW-Authenticate` challenge.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
    )
        .into_response()
}

/// Resolve who is calling from the request headers (the error is boxed: a
/// `Response` is large for an error type).
///
/// A bearer token with the personal access token prefix (multi-user mode only)
/// becomes a [`Caller::Principal`]: its owner's policy, narrowed by the token
/// scope and the owner's opt-outs. Anything else goes through the legacy
/// [`AuthManager`](crate::auth::AuthManager): a named `[[tokens]]` entry is a
/// [`Caller::Token`], the shared token or no auth at all is [`Caller::Open`].
/// Multi-user mode is deny-by-default: with no legacy auth configured, a
/// request without a PAT is answered 401, never `Open`.
pub(super) async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<Caller, Box<Response>> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let provided_token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    if provided_token.starts_with(PAT_PREFIX) {
        return authenticate_pat(provided_token, state).await;
    }

    let auth_manager = state.auth_manager.load();
    if !auth_manager.auth_required() {
        return if state.multi_user().is_some() {
            Err(Box::new(unauthorized()))
        } else {
            Ok(Caller::Open)
        };
    }

    if provided_token.is_empty() {
        return Err(Box::new(unauthorized()));
    }

    match auth_manager.validate_token(provided_token) {
        Ok(Some(identity)) => Ok(Caller::Token(identity)),
        Ok(None) => Ok(Caller::Open),
        Err(AuthError::RateLimited { .. }) => {
            Err(Box::new(StatusCode::TOO_MANY_REQUESTS.into_response()))
        }
        Err(_) => Err(Box::new(unauthorized())),
    }
}

/// A personal access token or a service account's token.
async fn authenticate_pat(token: &str, state: &AppState) -> Result<Caller, Box<Response>> {
    let Some((store, oidc)) = state.multi_user() else {
        return Err(Box::new(unauthorized()));
    };
    let principal = match store.authenticate_token(token, None).await {
        Ok(Some(principal)) => principal,
        Ok(None) => return Err(Box::new(unauthorized())),
        Err(error) => return Err(Box::new(unavailable(&error))),
    };

    let owner = &principal.owner;
    let policy = state.policy.current();
    let groups = if principal.is_service_account {
        policy.groups_for_service_account(owner.id)
    } else {
        // No configured provider for the issuer: no IdP mapping applies
        let provider_id = oidc.id_for_issuer(&owner.issuer).unwrap_or("");
        policy.groups_for(owner.id, provider_id, &owner.groups)
    };
    let opt_outs = opt_outs(store, owner.id).await?;

    let owner_label = owner
        .email
        .clone()
        .or_else(|| owner.display_name.clone())
        .unwrap_or_else(|| owner.id.to_string());
    Ok(Caller::Principal(PrincipalPolicy::new(
        format!("{owner_label} / {}", principal.token.name),
        policy.effective(&groups),
        opt_outs,
        TokenScope {
            backends: principal.token.scope_backends,
            tools: principal.token.scope_tools,
        },
    )))
}

async fn opt_outs(store: &Store, user_id: Uuid) -> Result<OptOuts, Box<Response>> {
    store
        .opt_outs(user_id)
        .await
        .map(|rows| OptOuts::new(rows.into_iter().map(|row| (row.backend, row.tool))))
        .map_err(|error| Box::new(unavailable(&error)))
}

/// 503 for a token or opt-out lookup that failed: the caller cannot be
/// authenticated, which is not the same as being refused.
fn unavailable(error: &StoreError) -> Response {
    tracing::error!(%error, "Token authentication failed");
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}
