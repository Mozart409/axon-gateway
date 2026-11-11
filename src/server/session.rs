//! Dashboard login: the `/auth` routes, the session guard in front of `/ui`
//! and the CSRF check on dashboard actions.
//!
//! Sessions are server-side. The browser holds a random token in
//! `__Host-axon_session`; the database holds its hash. The cookie is `Secure`,
//! `HttpOnly` and `SameSite=Lax`, and the `__Host-` prefix makes the browser
//! refuse it unless it is also host-only on `/`.
//!
//! The login is bound to the browser that started it: `/auth/login/{id}` sets
//! a short `__Host-axon_login` cookie holding the OIDC `state`, and the
//! callback refuses a `state` that does not match it (compared in constant
//! time). Without that, an attacker could finish their own login in a
//! victim's browser.
//!
//! Everything here is inert unless the gateway is in multi-user mode (an
//! `[auth.oidc]` provider and a `[database]`): the guard lets requests
//! through and the `/auth` routes answer 404.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use oauth2::url::form_urlencoded;
use serde::Deserialize;
use serde_json::json;
use subtle::ConstantTimeEq;

use super::views::{self, LoginOption};
use super::{AppState, ui};
use crate::oidc::OidcError;
use crate::store::{LoginUser, OidcFlow, SESSION_MAX_AGE, SessionUser};

/// The session cookie.
pub(super) const SESSION_COOKIE: &str = "__Host-axon_session";
/// The cookie that ties a login in progress to the browser that started it.
pub(super) const LOGIN_COOKIE: &str = "__Host-axon_login";
/// How long a login may take between `/auth/login/{id}` and the callback.
const LOGIN_TTL_SECS: i64 = 600;
/// Header htmx sends the CSRF token in (set through `hx-headers`).
const CSRF_HEADER: &str = "x-csrf-token";

/// Where a login may send the browser afterwards: a same-site absolute path
/// only, so `?return_to=` cannot be turned into an open redirect. Defaults to
/// the dashboard.
pub(super) fn safe_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(path)
            if path.starts_with('/')
                && !path.starts_with("//")
                && !path.starts_with("/\\")
                && path.len() <= 512
                && !path.chars().any(char::is_control) =>
        {
            path.to_owned()
        }
        _ => "/ui".to_owned(),
    }
}

/// A `__Host-` cookie: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no
/// `Domain`.
pub(super) fn host_cookie(name: &'static str, value: String, max_age_secs: i64) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(max_age_secs))
        .build()
}

/// The cookie that deletes `name`.
fn expired_cookie(name: &'static str) -> Cookie<'static> {
    host_cookie(name, String::new(), 0)
}

fn session_max_age_secs() -> i64 {
    i64::try_from(SESSION_MAX_AGE.as_secs()).unwrap_or(i64::MAX)
}

/// Constant-time string comparison, so a token check leaks nothing about it.
fn secrets_match(expected: &str, given: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
}

/// Whether the `state` the provider returned is the one this browser was
/// given.
fn state_matches(cookie: Option<&str>, returned: &str) -> bool {
    cookie.is_some_and(|cookie| secrets_match(cookie, returned))
}

/// Whether `given` is the session's CSRF token.
fn csrf_matches(session: &SessionUser, given: Option<&str>) -> bool {
    given.is_some_and(|given| secrets_match(&session.csrf_token, given))
}

fn header_csrf(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
}

/// `/auth/login/{id}?return_to=<encoded>`. Provider ids are `[a-z0-9-]+`
/// (checked at config load), so only the query needs encoding.
fn login_href(provider_id: &str, return_to: &str) -> String {
    let encoded: String = form_urlencoded::byte_serialize(return_to.as_bytes()).collect();
    format!("/auth/login/{provider_id}?return_to={encoded}")
}

pub(super) fn error_page(
    state: &AppState,
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    (
        status,
        Html(views::render_auth_error_page(state, title, message).into_string()),
    )
        .into_response()
}

fn database_unavailable(state: &AppState) -> Response {
    error_page(
        state,
        StatusCode::SERVICE_UNAVAILABLE,
        "The login is unavailable",
        "The database did not answer. Try again in a moment.",
    )
}

fn login_expired(state: &AppState) -> Response {
    error_page(
        state,
        StatusCode::BAD_REQUEST,
        "This login has expired",
        "It took too long, was already used, or was started in another browser. Try again.",
    )
}

async fn not_found(state: &AppState) -> Response {
    ui::handle_not_found(State(state.clone()))
        .await
        .into_response()
}

/// Middleware for every `/ui` and `/api/` route. Outside multi-user mode it
/// lets everything through; otherwise it resolves the session cookie, puts the
/// [`SessionUser`] into the request extensions, and sends everyone else to
/// log in (`/api/` gets a 401 instead).
pub(super) async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return next.run(request).await;
    };

    let jar = CookieJar::from_headers(request.headers());
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        match store.session_user(cookie.value()).await {
            Ok(Some(user)) => {
                request.extensions_mut().insert(user);
                return next.run(request).await;
            }
            Ok(None) => crate::metrics::record_authn("session", "invalid"),
            Err(error) => {
                tracing::warn!(%error, "could not look up a dashboard session");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "session check unavailable\n",
                )
                    .into_response();
            }
        }
    }

    unauthenticated(request.method(), request.headers(), request.uri())
}

/// What a request without a valid session gets: a page navigation goes to
/// the login and back, an htmx request is told to navigate there, anything
/// else (form posts, the event stream's reconnects) a bare 401. The JSON API
/// always answers 401 with a JSON body.
fn unauthenticated(method: &Method, headers: &HeaderMap, uri: &Uri) -> Response {
    if uri.path().starts_with("/api/") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "not signed in" })),
        )
            .into_response();
    }
    if method != Method::GET {
        return (StatusCode::UNAUTHORIZED, "log in at /auth/login\n").into_response();
    }
    if headers.contains_key("hx-request") {
        return (
            StatusCode::UNAUTHORIZED,
            [("hx-redirect", "/auth/login")],
            "log in at /auth/login\n",
        )
            .into_response();
    }
    let target = uri.path_and_query().map_or("/ui", |target| target.as_str());
    let encoded: String = form_urlencoded::byte_serialize(target.as_bytes()).collect();
    Redirect::to(&format!("/auth/login?return_to={encoded}")).into_response()
}

/// Middleware for `/ui/actions/*`, behind [`require_session`]: a state
/// changing request must carry the session's CSRF token in `X-CSRF-Token`.
/// Without a session in the extensions (not multi-user) it does nothing.
pub(super) async fn require_csrf(request: Request, next: Next) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        && let Some(session) = request.extensions().get::<SessionUser>()
        && !csrf_matches(session, header_csrf(request.headers()))
    {
        tracing::warn!(path = %request.uri().path(), "Rejected dashboard action without a valid CSRF token");
        return (StatusCode::FORBIDDEN, "missing or invalid CSRF token\n").into_response();
    }
    next.run(request).await
}

/// `GET /auth/login?return_to=`
#[derive(Debug, Deserialize)]
pub(super) struct LoginQuery {
    return_to: Option<String>,
}

/// The login page: one button per provider, or straight to the provider
/// when there is only one.
pub(super) async fn login_index(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let Some((_, providers)) = state.multi_user() else {
        return not_found(&state).await;
    };

    let return_to = safe_return_to(query.return_to.as_deref());
    let options: Vec<LoginOption> = providers
        .list()
        .iter()
        .map(|provider| LoginOption {
            display_name: provider.display_name().to_owned(),
            href: login_href(provider.id(), &return_to),
        })
        .collect();
    if let [only] = options.as_slice() {
        return Redirect::to(&only.href).into_response();
    }
    Html(views::render_login_page(&state, &options).into_string()).into_response()
}

/// `GET /auth/login/{id}`: starts a login and redirects to the provider.
pub(super) async fn login_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let Some((store, providers)) = state.multi_user() else {
        return not_found(&state).await;
    };
    let Some(provider) = providers.get(&id) else {
        return not_found(&state).await;
    };

    let redirect = match provider.authorize().await {
        Ok(redirect) => redirect,
        Err(error) => {
            tracing::warn!(%error, provider = %id, "could not start a dashboard login");
            return error_page(
                &state,
                StatusCode::BAD_GATEWAY,
                "The login provider is unreachable",
                "The gateway could not reach the identity provider. Try again in a moment.",
            );
        }
    };

    let flow = OidcFlow {
        provider_id: provider.id().to_owned(),
        pkce_verifier: redirect.pkce_verifier.clone(),
        nonce: redirect.nonce.clone(),
        return_to: safe_return_to(query.return_to.as_deref()),
    };
    if let Err(error) = store.create_oidc_flow(&redirect.state, &flow).await {
        tracing::warn!(%error, "could not record a dashboard login");
        return database_unavailable(&state);
    }

    let jar = jar.add(host_cookie(
        LOGIN_COOKIE,
        redirect.state.clone(),
        LOGIN_TTL_SECS,
    ));
    (jar, Redirect::to(&redirect.url)).into_response()
}

/// `GET /auth/callback?code=...&state=...` (or `?error=...`)
#[derive(Debug, Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Finishes a login: checks the state, exchanges the code, opens a session.
pub(super) async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some((store, providers)) = state.multi_user() else {
        return not_found(&state).await;
    };

    let login_state = jar
        .get(LOGIN_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    // Whatever happens next, this login attempt is over.
    let jar = jar.add(expired_cookie(LOGIN_COOKIE));

    if let Some(error) = &query.error {
        tracing::info!(%error, "the identity provider refused a dashboard login");
        crate::metrics::record_authn("session", "invalid");
        return (
            jar,
            error_page(
                &state,
                StatusCode::BAD_REQUEST,
                "The login was refused",
                "The identity provider did not approve the login.",
            ),
        )
            .into_response();
    }
    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return (
            jar,
            error_page(
                &state,
                StatusCode::BAD_REQUEST,
                "That is not a login callback",
                "The identity provider's answer had no code or state.",
            ),
        )
            .into_response();
    };
    if !state_matches(login_state.as_deref(), &returned_state) {
        tracing::warn!("a login callback did not match the browser that started it");
        crate::metrics::record_authn("session", "invalid");
        return (jar, login_expired(&state)).into_response();
    }

    match finish_login(&state, store, providers, &code, &returned_state).await {
        Ok((token, return_to)) => {
            let jar = jar.add(host_cookie(SESSION_COOKIE, token, session_max_age_secs()));
            (jar, Redirect::to(&return_to)).into_response()
        }
        Err(page) => (jar, *page).into_response(),
    }
}

/// Consumes the stored flow, exchanges the code and opens a session. Returns
/// the session token and where to send the browser, or the page to show.
// One linear login sequence; splitting it would scatter the flow's checks
#[allow(clippy::too_many_lines)]
async fn finish_login(
    state: &AppState,
    store: &crate::store::Store,
    providers: &crate::oidc::OidcProviders,
    code: &str,
    returned_state: &str,
) -> Result<(String, String), Box<Response>> {
    let flow = match store.take_oidc_flow(returned_state).await {
        Ok(Some(flow)) => flow,
        Ok(None) => {
            crate::metrics::record_authn("session", "expired");
            return Err(Box::new(login_expired(state)));
        }
        Err(error) => {
            tracing::warn!(%error, "could not load a dashboard login");
            return Err(Box::new(database_unavailable(state)));
        }
    };
    let Some(provider) = providers.get(&flow.provider_id) else {
        tracing::warn!(provider = %flow.provider_id, "a login names a provider that is gone");
        crate::metrics::record_authn("session", "expired");
        return Err(Box::new(login_expired(state)));
    };

    let login = match provider
        .exchange(code, &flow.pkce_verifier, &flow.nonce)
        .await
    {
        Ok(login) => login,
        Err(OidcError::EmailDomainNotAllowed) => {
            tracing::info!(provider = %flow.provider_id, "a login was refused: email domain not allowed");
            crate::metrics::record_authn("session", "invalid");
            return Err(Box::new(error_page(
                state,
                StatusCode::FORBIDDEN,
                "Access denied",
                "Your account is not allowed to use this gateway.",
            )));
        }
        Err(error) => {
            tracing::warn!(%error, provider = %flow.provider_id, "a dashboard login failed at the provider");
            crate::metrics::record_authn("session", "invalid");
            return Err(Box::new(error_page(
                state,
                StatusCode::BAD_REQUEST,
                "The login could not be verified",
                "The identity provider's answer did not check out. Start again from the login page.",
            )));
        }
    };

    let user = store
        .upsert_user_on_login(&LoginUser {
            issuer: &login.issuer,
            subject: &login.subject,
            email: login.email.as_deref(),
            display_name: login.name.as_deref(),
            groups: &login.groups,
            is_admin: login.is_admin,
        })
        .await
        .map_err(|error| {
            tracing::warn!(%error, "could not record a dashboard user");
            Box::new(database_unavailable(state))
        })?;
    // A user the provider pushed over SCIM links to this login now, takes its
    // SCIM groups and, when it is inactive there, is disabled before the check below
    store
        .link_scim_user_on_login(
            &flow.provider_id,
            user.id,
            login.email.as_deref(),
            login.scim_key.as_deref(),
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "could not link a dashboard user to its SCIM user");
            Box::new(database_unavailable(state))
        })?;
    let disabled = store.user_disabled(user.id).await.map_err(|error| {
        tracing::warn!(%error, "could not check whether a dashboard user is disabled");
        Box::new(database_unavailable(state))
    })?;
    if disabled {
        tracing::info!(user_id = %user.id, "a login was refused: the user is disabled");
        crate::metrics::record_authn("session", "disabled");
        return Err(Box::new(error_page(
            state,
            StatusCode::FORBIDDEN,
            "Access denied",
            "Your account has been disabled by an administrator.",
        )));
    }
    if let Some(hub) = state.personal.as_deref()
        && hub.wants_idp_refresh_token(&flow.provider_id)
        && let Some(refresh_token) = login.refresh_token.as_deref()
        && let Err(error) = hub
            .store_idp_refresh_token(user.id, &flow.provider_id, refresh_token)
            .await
    {
        tracing::warn!(%error, provider = %flow.provider_id, "could not keep the identity provider's refresh token");
    }
    let session = store
        .create_session(user.id, &flow.provider_id, Some(&login.id_token))
        .await
        .map_err(|error| {
            tracing::warn!(%error, "could not open a dashboard session");
            Box::new(database_unavailable(state))
        })?;

    crate::metrics::record_authn("session", "ok");
    tracing::info!(
        user_id = %user.id,
        provider = %flow.provider_id,
        is_admin = user.is_admin,
        "dashboard login"
    );
    Ok((session.token, safe_return_to(Some(&flow.return_to))))
}

/// `POST /auth/logout`: ends the session, server side and in the browser,
/// then signs out at the provider when it has an end-session endpoint.
pub(super) async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((store, providers)) = state.multi_user() else {
        return not_found(&state).await;
    };

    let token = jar
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let jar = jar.add(expired_cookie(SESSION_COOKIE));
    let Some(token) = token else {
        return (jar, Redirect::to("/")).into_response();
    };

    let session = match store.session_user(&token).await {
        Ok(Some(session)) => session,
        Ok(None) => return (jar, Redirect::to("/")).into_response(),
        Err(error) => {
            tracing::warn!(%error, "could not look up a dashboard session");
            return database_unavailable(&state);
        }
    };

    // The token comes from the `X-CSRF-Token` header (htmx) or, for a plain
    // form post, the `csrf_token` field.
    let given = header_csrf(&headers).map(str::to_owned).or_else(|| {
        form_urlencoded::parse(&body)
            .find(|(name, _)| name == "csrf_token")
            .map(|(_, value)| value.into_owned())
    });
    if !csrf_matches(&session, given.as_deref()) {
        tracing::warn!("Rejected dashboard logout without a valid CSRF token");
        return (StatusCode::FORBIDDEN, "missing or invalid CSRF token\n").into_response();
    }

    if let Err(error) = store.delete_session(&token).await {
        tracing::warn!(%error, "could not delete a dashboard session");
    }

    let landing = format!("{}/", state.base_url.trim_end_matches('/'));
    let location = match providers.get(&session.provider_id) {
        Some(provider) => {
            provider
                .end_session_url(session.id_token.as_deref(), &landing)
                .await
        }
        None => None,
    }
    .unwrap_or_else(|| "/".to_owned());
    (jar, Redirect::to(&location)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_return_path_cannot_leave_the_site() {
        assert_eq!(safe_return_to(Some("/ui/backends/x")), "/ui/backends/x");
        assert_eq!(safe_return_to(Some("//evil.example/")), "/ui");
        assert_eq!(safe_return_to(Some("/\\evil.example")), "/ui");
        assert_eq!(safe_return_to(Some("https://evil.example/")), "/ui");
        assert_eq!(safe_return_to(Some("/a\r\nSet-Cookie: x")), "/ui");
        assert_eq!(safe_return_to(None), "/ui");
    }

    #[test]
    fn the_state_must_match_the_cookie() {
        assert!(state_matches(Some("abc"), "abc"));
        assert!(!state_matches(Some("abc"), "abd"));
        assert!(!state_matches(Some("abc"), "abcd"));
        assert!(!state_matches(None, "abc"));
    }

    #[test]
    fn session_cookies_are_locked_down() {
        let cookie = host_cookie(SESSION_COOKIE, "t".to_owned(), 60).to_string();
        for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=60"] {
            assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
        }
        assert!(!cookie.contains("Domain"), "a __Host- cookie has no Domain");
    }

    #[test]
    fn login_links_encode_the_return_path() {
        assert_eq!(
            login_href("mock", "/ui?a=b&c=d"),
            "/auth/login/mock?return_to=%2Fui%3Fa%3Db%26c%3Dd"
        );
    }
}
