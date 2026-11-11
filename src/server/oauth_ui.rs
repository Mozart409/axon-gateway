//! The dashboard side of the MCP OAuth flow: the consent page an authorization request
//! continues at, the decision it posts, and the "Connected apps" page.
//!
//! `/oauth/authorize/continue` and the decision sit behind the session guard, which sends
//! a browser without a session through the dashboard login and back. The decision is a
//! plain form post, so it carries the session's CSRF token in a field (as the logout
//! form does) and gets the same-site check. The apps page and its htmx revoke action are
//! ordinary dashboard routes. Outside multi-user mode they are all 404s.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use oauth2::url::form_urlencoded;
use reqwest::Url;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use super::admin_ui::{error_response, fragment, not_found, page_error};
use super::oauth::{consent_client_host, error_page, redirect_to_client};
use super::oauth_views::{Consent, render_apps_page, render_apps_section, render_consent_page};
use super::{AppState, reject_cross_site_middleware, session};
use crate::rbac::AdminError;
use crate::store::{NewCode, SessionUser};

/// The consent and decision routes, behind the session guard (and, for the decision, the
/// same-site check).
pub(super) fn consent_routes(state: &AppState) -> Router<AppState> {
    if state.multi_user().is_none() {
        return Router::new();
    }
    Router::new()
        .route("/oauth/authorize/continue", get(handle_continue))
        .route(
            "/oauth/authorize/decision",
            post(handle_decision).route_layer(middleware::from_fn_with_state(
                state.clone(),
                reject_cross_site_middleware,
            )),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require_session,
        ))
}

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new().route("/ui/me/apps", get(handle_apps))
}

/// The POST actions, to merge into the routes behind the CSRF and same-site checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new().route("/ui/actions/me/apps/{id}/revoke", post(handle_revoke))
}

/// `host[:port]` of a redirect URI
fn redirect_host(redirect_uri: &str) -> String {
    let Ok(url) = Url::parse(redirect_uri) else {
        return String::from("an invalid address");
    };
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// A page nobody may frame: the consent page is what a clickjacking attack would target
fn unframeable(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn expired_request(state: &AppState) -> Response {
    error_page(
        state,
        StatusCode::BAD_REQUEST,
        "This request has expired",
        "It took too long or was already answered. Start again from the app.",
    )
}

/// `GET /oauth/authorize/continue?request=<id>`: the consent page
#[derive(Debug, Deserialize)]
struct ContinueQuery {
    request: Option<String>,
}

async fn handle_continue(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<ContinueQuery>,
) -> Response {
    let (Some(Extension(session)), Some((store, _))) = (user, state.multi_user()) else {
        return not_found(&state);
    };
    let Some(id) = query.request.as_deref() else {
        return expired_request(&state);
    };
    let request = match store.auth_request(id).await {
        Ok(Some(request)) => request,
        Ok(None) => return expired_request(&state),
        Err(error) => return page_error(&state, &session, &AdminError::Store(error)),
    };
    let client_host = consent_client_host(&request);
    let redirect_host = redirect_host(&request.redirect_uri);
    let page = render_consent_page(
        &state,
        &session,
        &Consent {
            request: &request,
            client_host: client_host.as_deref(),
            redirect_host: &redirect_host,
        },
    );
    unframeable(Html(page.into_string()).into_response())
}

/// `POST /oauth/authorize/decision`: Approve issues a code and sends the browser back to
/// the client, Deny sends it back with `access_denied`.
async fn handle_decision(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    body: Bytes,
) -> Response {
    let (Some(Extension(session)), Some((store, _))) = (user, state.multi_user()) else {
        return not_found(&state);
    };
    let fields: HashMap<String, String> = form_urlencoded::parse(&body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let csrf_ok = fields
        .get("csrf_token")
        .is_some_and(|given| bool::from(session.csrf_token.as_bytes().ct_eq(given.as_bytes())));
    if !csrf_ok {
        tracing::warn!("Rejected an OAuth decision without a valid CSRF token");
        return (StatusCode::FORBIDDEN, "missing or invalid CSRF token\n").into_response();
    }
    let approve = match fields.get("decision").map(String::as_str) {
        Some("approve") => true,
        Some("deny") => false,
        _ => return (StatusCode::BAD_REQUEST, "unknown decision\n").into_response(),
    };
    let Some(id) = fields.get("request") else {
        return expired_request(&state);
    };
    let request = match store.take_auth_request(id).await {
        Ok(Some(request)) => request,
        Ok(None) => return expired_request(&state),
        Err(error) => return page_error(&state, &session, &AdminError::Store(error)),
    };
    let client_state = request.state.as_deref();

    if !approve {
        tracing::info!(client_id = %request.client_id, "OAuth authorization denied");
        return redirect_to_client(
            &state,
            &request.redirect_uri,
            client_state,
            &[
                ("error", "access_denied"),
                ("error_description", "the user denied the request"),
            ],
        );
    }
    let code = store
        .create_oauth_code(&NewCode {
            client_id: &request.client_id,
            client_name: request.client_name.as_deref(),
            redirect_uri: &request.redirect_uri,
            code_challenge: &request.code_challenge,
            user_id: session.user.id,
            scope: &request.scope,
            resource: &request.resource,
        })
        .await;
    match code {
        Ok(code) => {
            tracing::info!(client_id = %request.client_id, "OAuth authorization approved");
            redirect_to_client(
                &state,
                &request.redirect_uri,
                client_state,
                &[("code", code.as_str())],
            )
        }
        Err(error) => {
            tracing::error!(%error, "Could not issue an OAuth authorization code");
            redirect_to_client(
                &state,
                &request.redirect_uri,
                client_state,
                &[
                    ("error", "server_error"),
                    ("error_description", "the database is unavailable"),
                ],
            )
        }
    }
}

/// `GET /ui/me/apps`: the user's connected apps
async fn handle_apps(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (Some(Extension(session)), Some((store, _))) = (user, state.multi_user()) else {
        return not_found(&state);
    };
    match store.list_oauth_grants(Some(session.user.id)).await {
        Ok(grants) => {
            Html(render_apps_page(&state, &session, &grants).into_string()).into_response()
        }
        Err(error) => page_error(&state, &session, &AdminError::Store(error)),
    }
}

/// `POST /ui/actions/me/apps/{id}/revoke`
async fn handle_revoke(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    let (Some(Extension(session)), Some((store, _))) = (user, state.multi_user()) else {
        return not_found(&state);
    };
    match store.revoke_oauth_grant(id, Some(session.user.id)).await {
        Ok(true) => {}
        Ok(false) => return error_response(&AdminError::NotFound),
        Err(error) => return error_response(&AdminError::Store(error)),
    }
    match store.list_oauth_grants(Some(session.user.id)).await {
        Ok(grants) => fragment(&render_apps_section(&grants)),
        Err(error) => error_response(&AdminError::Store(error)),
    }
}
