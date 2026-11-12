//! Break-glass admin login: `/auth/break-glass`, the landing of the link that
//! `axon-gateway admin login-link` prints.
//!
//! Opening the link only shows a confirmation page; the code is consumed by
//! the `POST` behind its button, so a link previewer or a prefetch cannot burn
//! it. The session that follows is an admin session of the built-in
//! break-glass user, one hour long. Like the rest of `/auth` this answers 404
//! outside multi-user mode.

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use maud::{DOCTYPE, Markup, html};
use serde::Deserialize;

use super::auth::{ClientIp, within_ip_limit};
use super::session::{SESSION_COOKIE, error_page, host_cookie, too_many_requests};
use super::{AppState, ui, views};
use crate::store::BREAK_GLASS_SESSION_MAX_AGE;

/// Where a break-glass login lands
const LANDING: &str = "/ui/admin";
/// Page views and logins together, per client IP and minute
const LIMIT_PER_MINUTE: u32 = 10;

/// `/auth/break-glass`: the confirmation page and the login behind it.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/auth/break-glass", get(confirm_page).post(redeem))
}

/// `GET /auth/break-glass?code=...`
#[derive(Debug, Deserialize)]
struct CodeQuery {
    code: Option<String>,
}

/// `POST /auth/break-glass`
#[derive(Debug, Deserialize)]
struct CodeForm {
    code: String,
}

fn link_expired(state: &AppState) -> Response {
    error_page(
        state,
        StatusCode::FORBIDDEN,
        "Link expired",
        "This login link was already used, has expired, or is not valid. Create a new one with `axon-gateway admin login-link`.",
    )
}

async fn not_found(state: &AppState) -> Response {
    ui::handle_not_found(State(state.clone()))
        .await
        .into_response()
}

/// The page that asks for confirmation. It does not touch the code.
fn render_confirm_page(state: &AppState, code: &str) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="referrer" content="no-referrer";
                title { "Break-glass sign in - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                link rel="stylesheet" href="/styles/output.css?v=1";
            }
            body class="bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100" {
                main class="mx-auto flex min-h-screen max-w-3xl items-center px-6 py-12" {
                    section class="w-full rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900" {
                        p class="text-xs font-semibold uppercase tracking-widest text-slate-500 dark:text-slate-400" {
                            "Axon Gateway"
                        }
                        h1 class="mt-3 text-3xl font-semibold tracking-tight" {
                            "Break-glass sign in"
                        }
                        p class="mt-3 text-slate-600 dark:text-slate-300" {
                            "This starts a one-hour admin session without the identity provider. The link works once, and the sign-in is audited."
                        }
                        form class="mt-6 flex flex-col items-center gap-3" method="post" action="/auth/break-glass" {
                            input type="hidden" name="code" value=(code);
                            button
                                type="submit"
                                class="w-full max-w-xs rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
                            {
                                "Sign in as break-glass admin"
                            }
                        }
                        p class="mt-8 border-t border-slate-200 pt-4 font-mono text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400" {
                            (views::build_fingerprint(state))
                        }
                    }
                }
            }
        }
    }
}

/// Shows the confirmation page; the code is not consumed here.
async fn confirm_page(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    Query(query): Query<CodeQuery>,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return not_found(&state).await;
    };
    if !within_ip_limit(store, "break_glass", client_ip.as_deref(), LIMIT_PER_MINUTE).await {
        return too_many_requests(&state);
    }
    let Some(code) = query.code.filter(|code| !code.is_empty()) else {
        return link_expired(&state);
    };
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Html(render_confirm_page(&state, &code).into_string()),
    )
        .into_response()
}

/// Consumes the code, opens the session and sends the browser to the admin UI.
async fn redeem(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    jar: CookieJar,
    Form(form): Form<CodeForm>,
) -> Response {
    let Some((store, _)) = state.multi_user() else {
        return not_found(&state).await;
    };
    if !within_ip_limit(store, "break_glass", client_ip.as_deref(), LIMIT_PER_MINUTE).await {
        return too_many_requests(&state);
    }
    // A login is a state change too: a foreign page must not be able to sign
    // the browser in with a code it knows.
    if super::is_cross_site(&headers, &state.base_url) {
        tracing::warn!("Rejected cross-site break-glass login");
        return (StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
    }

    match store.redeem_break_glass_code(&form.code).await {
        Ok(Some(session)) => {
            tracing::warn!(user_id = %session.user_id, "break-glass admin login");
            crate::metrics::record_authn("break_glass", "ok");
            // Rotate: the session this browser had before is no longer valid
            if let Some(previous) = jar
                .get(SESSION_COOKIE)
                .map(|cookie| cookie.value().to_owned())
                && let Err(error) = store.delete_session(&previous).await
            {
                tracing::warn!(%error, "could not delete the previous dashboard session");
            }
            let max_age = i64::try_from(BREAK_GLASS_SESSION_MAX_AGE.as_secs()).unwrap_or(i64::MAX);
            let jar = jar.add(host_cookie(SESSION_COOKIE, session.token, max_age));
            (jar, Redirect::to(LANDING)).into_response()
        }
        Ok(None) => {
            tracing::warn!("a break-glass login was refused: unknown, used or expired code");
            crate::metrics::record_authn("break_glass", "invalid");
            link_expired(&state)
        }
        Err(error) => {
            tracing::warn!(%error, "could not redeem a break-glass code");
            error_page(
                &state,
                StatusCode::SERVICE_UNAVAILABLE,
                "The login is unavailable",
                "The database did not answer. Try again in a moment.",
            )
        }
    }
}
