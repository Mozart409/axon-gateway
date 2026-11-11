//! The browser side of connecting a catalog entry to the user's own account at
//! the service's authorization server (`credential_mode = "oauth"`):
//!
//! - `GET /oauth/upstream/client.json`, the client ID metadata document the
//!   gateway identifies itself with (public, no session);
//! - `POST /ui/actions/catalog/{name}/connect`, which sends the browser to the
//!   service's sign-in, and `.../disconnect`;
//! - `GET /oauth/upstream/callback`, where the authorization server sends it
//!   back.
//!
//! Connect and disconnect are form posts, not htmx-only actions: a plain form
//! navigates to the other site, so they take the session's CSRF token from the
//! `csrf_token` field (like the consent decision) or from `X-CSRF-Token`. An
//! htmx request gets what htmx can use instead of a redirect: `HX-Redirect`
//! for the sign-in, the refreshed catalog section after a disconnect, the flash
//! fragment for an error. The callback sits behind the session guard, which
//! sends a browser without a session through the dashboard login and back to
//! it. Outside multi-user mode, or without the personal hub, none of it exists.

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use oauth2::url::form_urlencoded;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::admin_ui::not_found;
use super::oauth::{base, error_page};
use super::personal_api::{
    PersonalApiError, begin_connection, clean_return_to, connect_failure, delete_connection,
    finish_connection,
};
use super::personal_ui::{action_error, catalog_fragment};
use super::{AppState, reject_cross_site_middleware, session};
use crate::rbac::AdminError;
use crate::store::SessionUser;
use crate::upstream_oauth::client_metadata_document;

/// Header htmx sends the CSRF token in
const CSRF_HEADER: &str = "x-csrf-token";
/// Where a connection returns to when it was started without a `return_to`
const CATALOG_PAGE: &str = "/ui/catalog";
/// Longest piece of the authorization server's error shown on the error page
const MAX_SHOWN_CHARS: usize = 300;

/// The metadata document, and the connect, disconnect and callback routes
/// behind the session guard (and, for the posts, the same-site check).
pub(super) fn routes(state: &AppState) -> Router<AppState> {
    if state.multi_user().is_none() || state.personal.is_none() {
        return Router::new();
    }
    let actions = Router::new()
        .route("/ui/actions/catalog/{name}/connect", post(handle_connect))
        .route(
            "/ui/actions/catalog/{name}/disconnect",
            post(handle_disconnect),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_cross_site_middleware,
        ));
    Router::new()
        .route("/oauth/upstream/callback", get(handle_callback))
        .merge(actions)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require_session,
        ))
        .route("/oauth/upstream/client.json", get(handle_client_metadata))
}

/// `GET /oauth/upstream/client.json`
async fn handle_client_metadata(State(state): State<AppState>) -> Response {
    Json(client_metadata_document(base(&state))).into_response()
}

/// The fields of a form post
fn form_fields(body: &Bytes) -> HashMap<String, String> {
    form_urlencoded::parse(body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// Whether the request carries the session's CSRF token, in the header or in
/// the `csrf_token` field
fn csrf_ok(expected: &str, headers: &HeaderMap, fields: &HashMap<String, String>) -> bool {
    headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .or_else(|| fields.get("csrf_token").map(String::as_str))
        .is_some_and(|given| bool::from(expected.as_bytes().ct_eq(given.as_bytes())))
}

/// An htmx request, which wants a fragment or a header, not a redirect
fn is_htmx(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
}

/// The status and the text of a failure shown on a page
fn failure_status(error: &PersonalApiError) -> (StatusCode, String) {
    match error {
        PersonalApiError::Connect(error) => connect_failure(error),
        PersonalApiError::Disabled => (StatusCode::NOT_FOUND, error.to_string()),
        PersonalApiError::Admin(AdminError::Store(source)) => {
            tracing::warn!(error = %source, "A connection request failed in the database");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                String::from("the database is unavailable"),
            )
        }
        PersonalApiError::Admin(admin) => {
            let status = match admin {
                AdminError::Forbidden => StatusCode::FORBIDDEN,
                AdminError::NotFound => StatusCode::NOT_FOUND,
                AdminError::Conflict(_) => StatusCode::CONFLICT,
                AdminError::Invalid(_) | AdminError::Store(_) => StatusCode::BAD_REQUEST,
            };
            (status, admin.to_string())
        }
        PersonalApiError::Internal(message) => {
            tracing::warn!(message, "A connection request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("the request could not be completed"),
            )
        }
    }
}

/// A failure of an action: the flash fragment for htmx, else an error page
fn action_failure(
    state: &AppState,
    headers: &HeaderMap,
    title: &str,
    error: &PersonalApiError,
) -> Response {
    if is_htmx(headers) {
        return action_error(error);
    }
    let (status, message) = failure_status(error);
    error_page(state, status, title, &message)
}

/// The session and the form of a post whose CSRF token checked out, or the
/// refusal
fn checked_post(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(SessionUser, HashMap<String, String>), Box<Response>> {
    let Some(Extension(session)) = user else {
        return Err(Box::new(not_found(state)));
    };
    let fields = form_fields(body);
    if !csrf_ok(&session.csrf_token, headers, &fields) {
        tracing::warn!("Rejected a catalog connection request without a valid CSRF token");
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "missing or invalid CSRF token\n").into_response(),
        ));
    }
    Ok((session, fields))
}

/// `POST /ui/actions/catalog/{name}/connect`: 303 to the service's sign-in
/// (`HX-Redirect` for htmx). The optional `return_to` field is where the
/// callback sends the browser afterwards, if it is a local path.
async fn handle_connect(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (session, fields) = match checked_post(&state, user, &headers, &body) {
        Ok(checked) => checked,
        Err(response) => return *response,
    };
    let return_to = clean_return_to(fields.get("return_to").map(String::as_str));
    match begin_connection(&state, &session, &name, return_to).await {
        Ok(url) if is_htmx(&headers) => (StatusCode::OK, [("hx-redirect", url)]).into_response(),
        Ok(url) => Redirect::to(&url).into_response(),
        Err(error) => action_failure(&state, &headers, "The service cannot be connected", &error),
    }
}

/// `POST /ui/actions/catalog/{name}/disconnect`: 303 back to the catalog
/// (the refreshed section for htmx)
async fn handle_disconnect(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (session, _) = match checked_post(&state, user, &headers, &body) {
        Ok(checked) => checked,
        Err(response) => return *response,
    };
    match delete_connection(&state, &session, &name).await {
        Ok(()) if is_htmx(&headers) => catalog_fragment(&state, &session).await,
        Ok(()) => Redirect::to(CATALOG_PAGE).into_response(),
        Err(error) => action_failure(
            &state,
            &headers,
            "The service cannot be disconnected",
            &error,
        ),
    }
}

/// The answer of the authorization server: `code` and `state` (and `iss`), or
/// `error`. No `Debug`: the code is a credential.
#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// At most [`MAX_SHOWN_CHARS`] of something the other side sent
fn shown(text: &str) -> String {
    text.chars().take(MAX_SHOWN_CHARS).collect()
}

/// `GET /oauth/upstream/callback`: finishes the connection and sends the
/// browser to where it started (the catalog by default). An `error` from the
/// authorization server, or an answer that does not check out, is a 400 page;
/// the stored request is left to expire when the server answered with an
/// error.
async fn handle_callback(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    if let Some(error) = query.error.as_deref() {
        let message = match query.error_description.as_deref() {
            Some(description) if !description.is_empty() => {
                format!(
                    "The service's authorization server answered with the error {}: {}",
                    shown(error),
                    shown(description)
                )
            }
            _ => format!(
                "The service's authorization server answered with the error {}.",
                shown(error)
            ),
        };
        return error_page(
            &state,
            StatusCode::BAD_REQUEST,
            "The service did not connect",
            &message,
        );
    }
    let (Some(code), Some(request_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return error_page(
            &state,
            StatusCode::BAD_REQUEST,
            "The service did not connect",
            "The authorization server's answer has no code or no state. Start again from the catalog.",
        );
    };
    match finish_connection(&state, &session, request_state, code, query.iss.as_deref()).await {
        Ok((_, return_to)) => {
            let target = clean_return_to(return_to.as_deref());
            Redirect::to(target.as_deref().unwrap_or(CATALOG_PAGE)).into_response()
        }
        Err(error) => {
            let (status, message) = failure_status(&error);
            error_page(&state, status, "The service did not connect", &message)
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::personal::ConnectError;

    fn fields(body: &str) -> HashMap<String, String> {
        form_fields(&Bytes::copy_from_slice(body.as_bytes()))
    }

    #[test]
    fn a_form_is_read_into_fields() {
        let form = fields("csrf_token=tok&return_to=%2Fui%2Fcatalog%3Fa%3Db");
        assert_eq!(form.get("csrf_token").map(String::as_str), Some("tok"));
        assert_eq!(
            form.get("return_to").map(String::as_str),
            Some("/ui/catalog?a=b")
        );
    }

    #[test]
    fn the_csrf_token_may_come_in_the_field_or_the_header() {
        let none = HeaderMap::new();
        assert!(csrf_ok("tok", &none, &fields("csrf_token=tok")));
        assert!(!csrf_ok("tok", &none, &fields("csrf_token=other")));
        assert!(!csrf_ok("tok", &none, &fields("")));

        let mut header = HeaderMap::new();
        header.insert(CSRF_HEADER, HeaderValue::from_static("tok"));
        assert!(csrf_ok("tok", &header, &fields("")));
        // the header decides when both are there
        assert!(csrf_ok("tok", &header, &fields("csrf_token=other")));
        header.insert(CSRF_HEADER, HeaderValue::from_static("other"));
        assert!(!csrf_ok("tok", &header, &fields("csrf_token=tok")));
    }

    #[test]
    fn only_htmx_requests_are_told_apart() {
        let mut headers = HeaderMap::new();
        assert!(!is_htmx(&headers));
        headers.insert("hx-request", HeaderValue::from_static("true"));
        assert!(is_htmx(&headers));
    }

    #[test]
    fn the_other_sides_text_is_cut_short() {
        assert_eq!(shown("access_denied"), "access_denied");
        assert_eq!(
            shown(&"x".repeat(MAX_SHOWN_CHARS + 50)).len(),
            MAX_SHOWN_CHARS
        );
    }

    #[test]
    fn a_refused_callback_is_a_400_and_a_missing_service_a_404() {
        let status = |error: ConnectError| failure_status(&PersonalApiError::Connect(error)).0;
        assert_eq!(
            status(ConnectError::UnknownRequest),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(status(ConnectError::WrongUser), StatusCode::BAD_REQUEST);
        assert_eq!(status(ConnectError::NotConnectable), StatusCode::NOT_FOUND);
        let (status, message) = failure_status(&PersonalApiError::Admin(AdminError::NotFound));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(message, "not found");
    }
}
