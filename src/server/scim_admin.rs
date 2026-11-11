//! The admin side of SCIM: the JSON routes under `/api/v1/admin/scim` and the
//! page `/ui/admin/scim`, where an admin creates, rotates and deletes a
//! provider's SCIM token and reads the base URL to give the identity provider.
//! The token is shown once, when it is created; only its hash is stored.
//!
//! Needs `users.manage` and `groups.manage` (or the admin role). The JSON
//! routes have the guards of `admin_api` (multi-user check, session, same-site
//! check, CSRF token on writes) and answer errors the same way; the page and
//! its actions are merged into the dashboard routes like the other admin
//! pages (see `create_router`).

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Utc};
use maud::{Markup, PreEscaped, html};
use serde_json::{Value, json};

use super::admin_api::{ApiError, ApiPath, ApiResult};
use super::admin_ui::{not_found, page_error};
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, CARD, CODE, FAINT, HEADING, MUTED, TABLE, TABLE_WRAP, TBODY,
    TD, TH, THEAD, render_layout,
};
use super::{AppState, reject_cross_site_middleware, session};
use crate::policy::Permission;
use crate::rbac::{AdminError, resolve};
use crate::store::scim::ScimProviderState;
use crate::store::{Actor, SessionUser, Store};

const PANEL_ID: &str = "scim-panel";

/// One provider with its SCIM state
struct Row {
    id: String,
    display_name: String,
    /// What the identity provider is given as the SCIM base URL
    base_url: String,
    state: ScimProviderState,
}

/// A token that was just created, to show once
struct Issued<'a> {
    provider: &'a str,
    token: &'a str,
}

/// The JSON routes, with their guards.
pub(super) fn api_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/admin/scim", get(handle_list))
        .route(
            "/api/v1/admin/scim/{provider}/token",
            post(handle_create_token).delete(handle_delete_token),
        )
        .route_layer(middleware::from_fn(session::require_csrf))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            reject_cross_site_middleware,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session::require_session,
        ))
        .route_layer(middleware::from_fn_with_state(state, require_multi_user))
}

/// The GET page, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new().route("/ui/admin/scim", get(handle_page))
}

/// The page's POST actions, to merge into the routes behind the CSRF guard.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/ui/actions/admin/scim/{provider}/token",
            post(handle_ui_create_token),
        )
        .route(
            "/ui/actions/admin/scim/{provider}/token/delete",
            post(handle_ui_delete_token),
        )
}

/// The API does not exist outside multi-user mode.
async fn require_multi_user(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if state.multi_user().is_none() {
        return ApiError::from(AdminError::NotFound).into_response();
    }
    next.run(request).await
}

/// Email, else display name, else subject: how the audit log names the user.
fn actor_for(session: &SessionUser) -> Actor {
    let user = &session.user;
    let label = [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
        .to_owned();
    Actor {
        user_id: Some(user.id),
        label,
    }
}

/// The store and the provider ids, when the caller may manage SCIM
fn authorize<'a>(
    state: &'a AppState,
    session: &SessionUser,
) -> Result<(&'a Store, &'a crate::oidc::OidcProviders), AdminError> {
    let (store, providers) = state.multi_user().ok_or(AdminError::NotFound)?;
    let policy = state.policy.current();
    let (_, permissions) = resolve(&policy, session);
    // A SCIM token can put any user into any SCIM group, and those names feed the
    // IdP group mappings, so the minter must hold what every bound role grants.
    let allowed = permissions.is_admin()
        || (permissions.has(Permission::UsersManage)
            && permissions.has(Permission::GroupsManage)
            && permissions
                .missing(&policy.bound_group_permissions())
                .is_empty());
    if allowed {
        Ok((store, providers))
    } else {
        Err(AdminError::Forbidden)
    }
}

fn base_url(state: &AppState, provider: &str) -> String {
    format!(
        "{}/scim/v2/{provider}",
        state.base_url.trim_end_matches('/')
    )
}

async fn load(state: &AppState, session: &SessionUser) -> Result<Vec<Row>, AdminError> {
    let (store, providers) = authorize(state, session)?;
    let providers = providers.list();
    let ids: Vec<String> = providers
        .iter()
        .map(|provider| provider.id().to_owned())
        .collect();
    let states = store.scim_overview(&ids).await?;
    Ok(providers
        .iter()
        .zip(states)
        .map(|(provider, state_row)| Row {
            id: provider.id().to_owned(),
            display_name: provider.display_name().to_owned(),
            base_url: base_url(state, provider.id()),
            state: state_row,
        })
        .collect())
}

/// Creates (or rotates) the provider's token and returns its plaintext.
async fn create_token(
    state: &AppState,
    session: &SessionUser,
    provider: &str,
) -> Result<String, AdminError> {
    let (store, providers) = authorize(state, session)?;
    if providers.get(provider).is_none() {
        return Err(AdminError::NotFound);
    }
    Ok(store
        .create_scim_token(&actor_for(session), provider)
        .await?)
}

async fn delete_token(
    state: &AppState,
    session: &SessionUser,
    provider: &str,
) -> Result<(), AdminError> {
    let (store, providers) = authorize(state, session)?;
    if providers.get(provider).is_none() {
        return Err(AdminError::NotFound);
    }
    if store
        .delete_scim_token(&actor_for(session), provider)
        .await?
    {
        Ok(())
    } else {
        Err(AdminError::NotFound)
    }
}

fn row_json(row: &Row) -> Value {
    json!({
        "provider": row.id,
        "display_name": row.display_name,
        "base_url": row.base_url,
        "has_token": row.state.token_created_at.is_some(),
        "created_at": row.state.token_created_at.map(|at| at.to_rfc3339()),
        "last_used_at": row.state.token_last_used_at.map(|at| at.to_rfc3339()),
        "users": row.state.users,
        "groups": row.state.groups,
    })
}

/// `GET /api/v1/admin/scim`: every provider with its token state and counts
async fn handle_list(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
) -> ApiResult<Json<Value>> {
    let rows = load(&state, &session).await?;
    let providers: Vec<Value> = rows.iter().map(row_json).collect();
    Ok(Json(json!({ "providers": providers })))
}

/// `POST /api/v1/admin/scim/{provider}/token`: creates or rotates the token;
/// the plaintext is in this answer only
async fn handle_create_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(provider): ApiPath<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let token = create_token(&state, &session, &provider).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": token, "base_url": base_url(&state, &provider) })),
    ))
}

/// `DELETE /api/v1/admin/scim/{provider}/token`
async fn handle_delete_token(
    State(state): State<AppState>,
    Extension(session): Extension<SessionUser>,
    ApiPath(provider): ApiPath<String>,
) -> ApiResult<StatusCode> {
    delete_token(&state, &session, &provider).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Handle `GET /ui/admin/scim`
async fn handle_page(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    match load(&state, &session).await {
        Ok(rows) => {
            Html(render_scim_page(&state, &session, &rows, None).into_string()).into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// The panel again, with the new token when there is one
async fn panel_response(
    state: &AppState,
    session: &SessionUser,
    issued: Option<&Issued<'_>>,
) -> Response {
    match load(state, session).await {
        Ok(rows) => Html(render_panel(&rows, issued).into_string()).into_response(),
        Err(error) => page_error(state, session, &error),
    }
}

/// Handle `POST /ui/actions/admin/scim/{provider}/token`
async fn handle_ui_create_token(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(provider): Path<String>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    match create_token(&state, &session, &provider).await {
        Ok(token) => {
            let issued = Issued {
                provider: &provider,
                token: &token,
            };
            panel_response(&state, &session, Some(&issued)).await
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle `POST /ui/actions/admin/scim/{provider}/token/delete`
async fn handle_ui_delete_token(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(provider): Path<String>,
) -> Response {
    let Some(Extension(session)) = user else {
        return not_found(&state);
    };
    match delete_token(&state, &session, &provider).await {
        Ok(()) => panel_response(&state, &session, None).await,
        Err(error) => page_error(&state, &session, &error),
    }
}

fn when(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M UTC").to_string()
}

/// The box that shows a new token, once
fn render_issued(issued: &Issued<'_>) -> Markup {
    html! {
        div
            class="mt-4 rounded-lg border border-emerald-300 bg-emerald-50 p-4 dark:border-emerald-800 dark:bg-emerald-950/40"
            role="status"
        {
            p class="text-sm font-semibold text-emerald-900 dark:text-emerald-200" {
                "SCIM token for " code { (issued.provider) } " created"
            }
            p class="mt-1 text-sm text-emerald-900 dark:text-emerald-200" {
                "Copy it now. It is not shown again, and the previous token no longer works."
            }
            code
                class="mt-2 block select-all break-all rounded-md bg-white px-3 py-2 font-mono text-sm text-slate-900 dark:bg-slate-900 dark:text-slate-100"
            {
                (issued.token)
            }
        }
    }
}

/// The providers table, which the actions swap whole
fn render_panel(rows: &[Row], issued: Option<&Issued<'_>>) -> Markup {
    html! {
        section id=(PANEL_ID) class=(CARD) {
            h2 class=(HEADING) { "SCIM provisioning" }
            p class=(format!("mt-1 {MUTED}")) {
                "An identity provider such as Entra ID or Okta pushes users and groups to the base URL "
                "with the provider's token as a bearer token. Creating a token again replaces the old one."
            }
            @if let Some(issued) = issued {
                (render_issued(issued))
            }
            @if rows.is_empty() {
                p class=(format!("mt-4 {FAINT}")) { "No OIDC provider is configured." }
            } @else {
                div class=(format!("mt-4 {TABLE_WRAP}")) {
                    table class=(TABLE) {
                        thead class=(THEAD) {
                            tr {
                                th class=(TH) { "Provider" }
                                th class=(TH) { "Base URL" }
                                th class=(TH) { "Token" }
                                th class=(TH) { "Users" }
                                th class=(TH) { "Groups" }
                                th class=(TH) {}
                            }
                        }
                        tbody class=(TBODY) {
                            @for row in rows {
                                (render_row(row))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_row(row: &Row) -> Markup {
    let target = format!("#{PANEL_ID}");
    let has_token = row.state.token_created_at.is_some();
    let create_path = format!("/ui/actions/admin/scim/{}/token", row.id);
    let delete_path = format!("/ui/actions/admin/scim/{}/token/delete", row.id);
    html! {
        tr {
            td class=(TD) {
                (row.display_name)
                @if row.display_name != row.id {
                    " " span class=(FAINT) { "(" (row.id) ")" }
                }
            }
            td class=(TD) { code class=(CODE) { (row.base_url) } }
            td class=(TD) {
                @if let Some(created) = row.state.token_created_at {
                    "created " (when(created))
                    br;
                    span class=(FAINT) {
                        @if let Some(used) = row.state.token_last_used_at {
                            "last used " (when(used))
                        } @else {
                            "never used"
                        }
                    }
                } @else {
                    span class=(FAINT) { "none" }
                }
            }
            td class=(TD) { (row.state.users) }
            td class=(TD) { (row.state.groups) }
            td class=(TD) {
                div class="flex flex-wrap gap-2" {
                    button
                        class=(BUTTON)
                        type="button"
                        hx-post=(create_path)
                        hx-target=(target)
                        hx-swap="outerHTML"
                        hx-confirm=[has_token.then_some("Replace the token? The identity provider stops working until it has the new one.")]
                    {
                        @if has_token { "Rotate token" } @else { "Create token" }
                    }
                    @if has_token {
                        button
                            class=(BUTTON_DANGER)
                            type="button"
                            hx-post=(delete_path)
                            hx-target=(target)
                            hx-swap="outerHTML"
                            hx-confirm="Delete the token? The identity provider can no longer push users and groups."
                        {
                            "Delete token"
                        }
                    }
                }
            }
        }
    }
}

/// The page: a back link and the panel.
fn render_scim_page(
    state: &AppState,
    user: &SessionUser,
    rows: &[Row],
    issued: Option<&Issued<'_>>,
) -> Markup {
    let content = html! {
        a href="/ui/admin" class=(BACK_LINK) { (PreEscaped("&larr;")) " Admin" }
        h1 class="mt-4 mb-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
            "SCIM provisioning"
        }
        (render_panel(rows, issued))
    };
    render_layout(state, user, "SCIM provisioning", &content)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn row(id: &str, token: bool) -> Row {
        let at = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap();
        Row {
            id: id.to_owned(),
            display_name: "Entra".to_owned(),
            base_url: format!("https://axon.example/scim/v2/{id}"),
            state: ScimProviderState {
                provider: id.to_owned(),
                token_created_at: token.then_some(at),
                token_last_used_at: None,
                users: 3,
                groups: 2,
            },
        }
    }

    #[test]
    fn the_json_row_says_whether_there_is_a_token() {
        let with = row_json(&row("entra", true));
        assert_eq!(with["has_token"], true);
        assert_eq!(with["provider"], "entra");
        assert_eq!(with["base_url"], "https://axon.example/scim/v2/entra");
        assert_eq!(with["users"], 3);
        assert_eq!(with["groups"], 2);
        assert!(with["created_at"].is_string());
        assert!(with["last_used_at"].is_null());

        let without = row_json(&row("entra", false));
        assert_eq!(without["has_token"], false);
        assert!(without["created_at"].is_null());
    }

    #[test]
    fn the_token_shows_only_in_the_one_time_box() {
        let rows = [row("entra", true)];
        let issued = Issued {
            provider: "entra",
            token: "axon_scim_secret",
        };
        let with = render_panel(&rows, Some(&issued)).into_string();
        assert!(with.contains("axon_scim_secret"));
        assert!(with.contains("Rotate token"));
        assert!(with.contains("/ui/actions/admin/scim/entra/token/delete"));
        let without = render_panel(&rows, None).into_string();
        assert!(!without.contains("axon_scim_secret"));

        let fresh = render_panel(&[row("entra", false)], None).into_string();
        assert!(fresh.contains("Create token"));
        assert!(!fresh.contains("Delete token"));
    }
}
