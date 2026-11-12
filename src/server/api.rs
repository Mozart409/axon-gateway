//! Health, readiness, build, status and metrics endpoints.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Json, Response},
};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Utc};
use serde_json::json;

use super::AppState;
use super::auth::{ClientIp, authenticate};
use super::session::SESSION_COOKIE;
use crate::gateway::{Caller, GetDetailedStatus, GetStatus};
use crate::policy::Permission;
use crate::rbac::resolve;

/// Health check endpoint
pub(super) async fn health_check() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Liveness probe: the process is up and serving HTTP.
pub(super) async fn livez() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Upper bound for the database ping in `/readyz`.
const DATABASE_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

fn gateway_alive(state: &AppState) -> Result<(), &'static str> {
    if state.gateway.is_alive() {
        Ok(())
    } else {
        Err("gateway actor stopped")
    }
}

/// Pings the database when one is configured; standalone mode always passes.
async fn database_reachable(state: &AppState) -> Result<(), &'static str> {
    let Some(store) = &state.store else {
        return Ok(());
    };
    match tokio::time::timeout(DATABASE_CHECK_TIMEOUT, store.ping()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err("database unreachable"),
    }
}

/// Readiness probe: 200 when every readiness check passes, else 503 with the reason.
///
/// Checks run in order (gateway, then database); the first failure wins.
pub(super) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let result = match gateway_alive(&state) {
        Ok(()) => database_reachable(&state)
            .await
            .map_err(|reason| ("database", reason)),
        Err(reason) => Err(("gateway", reason)),
    };
    if let Err((name, reason)) = result {
        tracing::warn!(check = %name, %reason, "Readiness check failed");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "reason": reason })),
        );
    }
    (StatusCode::OK, Json(json!({ "status": "ready" })))
}

/// Build and process metadata endpoint
pub(super) async fn get_build_info(State(state): State<AppState>) -> impl IntoResponse {
    let started_utc: DateTime<Utc> = state.started_at.into();
    let started_unix = state
        .started_at
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("AXON_GIT_SHA").unwrap_or("dev"),
        "pid": state.process_id,
        "sse_clients": state.sse_clients.load(Ordering::SeqCst),
        "started_utc": started_utc.to_rfc3339(),
        "started_unix": started_unix,
    }))
}

/// Guard of the `/status*` endpoints: in database mode the caller needs the
/// `gateway.admin` permission, as a bearer token (PAT, service account token, JWT) or,
/// without an `Authorization` header, as a dashboard session cookie (GET only, so no CSRF
/// token). 401 with the `Bearer` challenge when nobody is authenticated, 403 without the
/// permission. Standalone mode lets everyone through.
pub(super) async fn require_status_access(
    state: &AppState,
    headers: &HeaderMap,
    client_ip: Option<&str>,
) -> Result<(), Box<Response>> {
    let Some((store, oidc)) = state.multi_user() else {
        return Ok(());
    };
    let policy = state.policy.current();

    if !headers.contains_key(header::AUTHORIZATION)
        && let Some(cookie) = CookieJar::from_headers(headers).get(SESSION_COOKIE)
    {
        match store.session_user(cookie.value()).await {
            Ok(Some(session)) => {
                let permissions = resolve(&policy, &session).1;
                return admin_or_forbidden(permissions.has(Permission::GatewayAdmin));
            }
            // An unknown or expired session: the bearer path below answers the 401
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "could not look up a dashboard session");
                return Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()));
            }
        }
    }

    let principal = match authenticate(headers, state, client_ip).await {
        Ok(Caller::Principal(principal)) => principal,
        Ok(Caller::Open | Caller::Token(_)) => {
            return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
        }
        Err(response) => return Err(response),
    };
    let Some(owner_id) = principal.owner_id() else {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    };
    let owner = match store.user_state(owner_id).await {
        Ok(Some(owner)) => owner.user,
        Ok(None) => return Err(Box::new(StatusCode::FORBIDDEN.into_response())),
        Err(error) => {
            tracing::warn!(%error, "could not look up the owner of a token");
            return Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()));
        }
    };
    let (groups, is_admin) = if principal.is_service_account() {
        (policy.groups_for_service_account(owner.id), false)
    } else {
        let provider_id = oidc.id_for_issuer(&owner.issuer).unwrap_or_default();
        (
            policy.groups_for(owner.id, &provider_id, &owner.groups),
            owner.is_admin,
        )
    };
    admin_or_forbidden(
        policy
            .permissions_for(owner.id, &groups, is_admin)
            .has(Permission::GatewayAdmin),
    )
}

fn admin_or_forbidden(is_admin: bool) -> Result<(), Box<Response>> {
    if is_admin {
        Ok(())
    } else {
        Err(Box::new(StatusCode::FORBIDDEN.into_response()))
    }
}

/// Gateway status endpoint
pub(super) async fn get_status(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_status_access(&state, &headers, client_ip.as_deref()).await {
        return *response;
    }
    match state.gateway.ask(GetStatus).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => {
            tracing::error!("Failed to get status: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Detailed gateway status endpoint
pub(super) async fn get_detailed_status(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
) -> Response {
    if let Err(response) = require_status_access(&state, &headers, client_ip.as_deref()).await {
        return *response;
    }
    match state.gateway.ask(GetDetailedStatus).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => {
            tracing::error!("Failed to get detailed status: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Prometheus metrics endpoint
pub(super) async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics_handle.render()
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::server::create_router;
    use crate::server::tests::test_state;

    async fn get_json(state: AppState, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = create_router(state)
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        (
            status,
            serde_json::from_slice(&body).expect("body should be json"),
        )
    }

    #[tokio::test]
    async fn build_endpoint_returns_metadata() {
        let app = create_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/build")
                    .method(http::Method::GET)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should be readable");
        let payload: serde_json::Value =
            serde_json::from_slice(&body).expect("build payload should be json");

        assert!(payload.get("version").is_some());
        assert!(payload.get("pid").is_some());
        assert!(payload.get("started_utc").is_some());
        assert!(payload.get("sse_clients").is_some());
    }

    #[tokio::test]
    async fn livez_returns_ok() {
        let (status, payload) = get_json(test_state(), "/livez").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn readyz_is_ready_while_gateway_runs() {
        let (status, payload) = get_json(test_state(), "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload, json!({ "status": "ready" }));
    }

    #[tokio::test]
    async fn readyz_stays_ready_without_a_database() {
        let state = test_state();
        assert!(state.store.is_none());

        let (status, payload) = get_json(state, "/readyz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload, json!({ "status": "ready" }));
    }

    #[tokio::test]
    async fn readyz_is_unavailable_when_gateway_stopped() {
        let state = test_state();
        state.gateway.kill();
        state.gateway.wait_for_shutdown().await;

        let (status, payload) = get_json(state, "/readyz").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            payload,
            json!({ "status": "not_ready", "reason": "gateway actor stopped" })
        );
    }
}
