//! Bearer token verification for the MCP endpoints.

use axum::http::{HeaderMap, StatusCode};

use crate::auth::{AuthError, AuthManager, TokenIdentity};

/// Extract and validate auth token from request headers.
///
/// Returns `Ok(Some(identity))` for named tokens, `Ok(None)` for shared
/// token or no auth configured, or `Err(StatusCode)` on auth failure.
pub(super) fn verify_auth(
    headers: &HeaderMap,
    auth_manager: &AuthManager,
) -> Result<Option<TokenIdentity>, StatusCode> {
    if !auth_manager.auth_required() {
        return Ok(None);
    }

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let provided_token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);

    if provided_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    match auth_manager.validate_token(provided_token) {
        Ok(identity) => Ok(identity),
        Err(AuthError::RateLimited { .. }) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}
