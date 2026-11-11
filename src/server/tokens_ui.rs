//! The token pages and their htmx actions: `/ui/tokens` for a user's own
//! personal access tokens, `/ui/admin/service-accounts` for the admin's
//! service accounts and their tokens.
//!
//! The routes sit behind the session guard (and, for actions, the CSRF and
//! same-site checks); outside multi-user mode every one of them is a 404. What
//! a user may do is decided by [`MyTokens`] (anyone signed in, own tokens
//! only) and [`Admin`] (`service_accounts.manage`), the services the JSON API
//! uses too. Errors and the flash area work as on the admin pages. A new
//! token's secret is in the one response that creates it, which is marked
//! `no-store`.

use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;

use super::AppState;
use super::admin_ui::{
    AdminForm, admin_for, backend_names, error_response, fragment, not_found, page_error,
    split_globs,
};
use super::tokens_views::{
    AccountRow, Issued, ServiceAccountsOverview, render_service_accounts_page,
    render_service_accounts_section, render_tokens_page, render_tokens_section,
};
use crate::principal::TokenScope;
use crate::rbac::{Admin, AdminError, MyTokens, resolve};
use crate::store::{IssuedToken, SessionUser};

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/tokens", get(handle_tokens))
        .route("/ui/admin/service-accounts", get(handle_service_accounts))
        .merge(super::toolsets_ui::page_routes())
        .merge(super::personal_ui::page_routes())
}

/// The POST actions, to merge into the routes behind the CSRF and same-site
/// checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/actions/tokens", post(handle_token_create))
        .route("/ui/actions/tokens/{id}/revoke", post(handle_token_revoke))
        .route(
            "/ui/actions/admin/service-accounts",
            post(handle_account_create),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/disabled",
            post(handle_account_disabled),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/delete",
            post(handle_account_delete),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/tokens",
            post(handle_account_token_create),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/tokens/{token_id}/revoke",
            post(handle_account_token_revoke),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/jwt-bindings",
            post(handle_account_jwt_binding_create),
        )
        .route(
            "/ui/actions/admin/service-accounts/{id}/jwt-bindings/{binding_id}/delete",
            post(handle_account_jwt_binding_delete),
        )
        .merge(super::toolsets_ui::action_routes())
        .merge(super::personal_ui::action_routes())
}

/// The create token form, read as pairs because `scope_backends` repeats
type FormPairs = Vec<(String, String)>;

/// The fields of the create token forms
struct TokenForm {
    name: String,
    expires_in_days: Option<u32>,
    scope: TokenScope,
    toolset_id: Option<Uuid>,
}

impl TokenForm {
    fn parse(pairs: &[(String, String)]) -> Result<Self, AdminError> {
        let first = |key: &str| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        let expires_in_days = match first("expires_in_days")
            .map(str::trim)
            .filter(|days| !days.is_empty())
        {
            Some(days) => Some(days.parse().map_err(|_| {
                AdminError::Invalid(String::from("expires in must be a whole number of days"))
            })?),
            None => None,
        };
        let backends = pairs
            .iter()
            .filter(|(name, value)| name == "scope_backends" && !value.trim().is_empty())
            .map(|(_, value)| value.clone())
            .collect();
        let toolset_id = match first("toolset_id")
            .map(str::trim)
            .filter(|id| !id.is_empty())
        {
            Some(id) => Some(
                id.parse()
                    .map_err(|_| AdminError::Invalid(String::from("unknown toolset")))?,
            ),
            None => None,
        };
        Ok(Self {
            name: first("name").unwrap_or_default().to_owned(),
            toolset_id,
            expires_in_days,
            scope: TokenScope {
                backends,
                tools: split_globs(first("scope_tools")),
            },
        })
    }
}

/// `no-store` on a response that may carry a token secret
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The backends the user is granted, which a token of theirs may be narrowed to.
pub(super) fn granted_backends(state: &AppState, session: &SessionUser) -> Vec<String> {
    let policy = state.policy.current();
    let (groups, _) = resolve(&policy, session);
    policy.effective(&groups).backends()
}

/// The session and the token service, or the 404 outside multi-user mode
/// (boxed: a `Response` is large for an error type).
pub(super) fn tokens_for(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
) -> Result<(SessionUser, MyTokens<'_>), Box<Response>> {
    let Some(Extension(session)) = user else {
        return Err(Box::new(not_found(state)));
    };
    match MyTokens::from_state(state, &session) {
        Some(tokens) => Ok((session, tokens)),
        None => Err(Box::new(not_found(state))),
    }
}

/// The answer to an action on `/ui/tokens`: the tokens section, with the new
/// token's secret when there is one, or the error.
async fn tokens_fragment(
    state: &AppState,
    session: &SessionUser,
    tokens: &MyTokens<'_>,
    issued: Option<&IssuedToken>,
) -> Response {
    match tokens.list().await {
        Ok(list) => {
            let backends = granted_backends(state, session);
            let toolsets = match tokens.toolsets().await {
                Ok(toolsets) => toolsets,
                Err(error) => return error_response(&error),
            };
            no_store(fragment(&render_tokens_section(
                &list, &backends, &toolsets, issued,
            )))
        }
        Err(error) => error_response(&error),
    }
}

/// Handle GET /ui/tokens - the user's own tokens
pub(super) async fn handle_tokens(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let (list, toolsets) = match (tokens.list().await, tokens.toolsets().await) {
        (Ok(list), Ok(toolsets)) => (list, toolsets),
        (Err(error), _) | (_, Err(error)) => return page_error(&state, &session, &error),
    };
    let backends = granted_backends(&state, &session);
    Html(render_tokens_page(&state, &session, &list, &backends, &toolsets).into_string())
        .into_response()
}

/// Handle POST /ui/actions/tokens - issue a token for the user
pub(super) async fn handle_token_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let form = match TokenForm::parse(&pairs) {
        Ok(form) => form,
        Err(error) => return error_response(&error),
    };
    match tokens
        .create(
            &form.name,
            form.expires_in_days,
            &form.scope,
            form.toolset_id,
        )
        .await
    {
        Ok(issued) => tokens_fragment(&state, &session, &tokens, Some(&issued)).await,
        Err(error) => error_response(&error),
    }
}

/// Handle POST /ui/actions/tokens/{id}/revoke
pub(super) async fn handle_token_revoke(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = tokens.revoke(id).await {
        return error_response(&error);
    }
    tokens_fragment(&state, &session, &tokens, None).await
}

async fn load_accounts(
    state: &AppState,
    admin: &Admin<'_>,
) -> Result<ServiceAccountsOverview, AdminError> {
    let accounts = admin.service_accounts().await?;
    let mut rows = Vec::with_capacity(accounts.len());
    for account in accounts {
        let tokens = admin.service_account_tokens(account.id).await?;
        let bindings = admin.jwt_bindings(account.id).await?;
        rows.push(AccountRow {
            account,
            tokens,
            bindings,
        });
    }
    let issuers = state.multi_user().map_or_else(Vec::new, |(_, oidc)| {
        oidc.iter()
            .filter(|provider| provider.accepts_access_tokens())
            .map(|provider| provider.issuer().to_owned())
            .collect()
    });
    Ok(ServiceAccountsOverview {
        accounts: rows,
        backends: backend_names(state).await,
        issuers,
    })
}

/// The answer to an action on `/ui/admin/service-accounts`: the section, with
/// the secret of the token just issued to the account `issued.0` when there is
/// one, or the error.
async fn accounts_fragment(
    state: &AppState,
    admin: &Admin<'_>,
    issued: Option<(Uuid, &IssuedToken)>,
) -> Response {
    let overview = match load_accounts(state, admin).await {
        Ok(overview) => overview,
        Err(error) => return error_response(&error),
    };
    let issued = issued.map(|(account_id, issued)| Issued {
        account: overview
            .accounts
            .iter()
            .find(|row| row.account.id == account_id)
            .map(|row| row.account.name.as_str()),
        issued,
    });
    no_store(fragment(&render_service_accounts_section(
        &overview,
        issued.as_ref(),
    )))
}

/// Handle GET /ui/admin/service-accounts - service accounts and their tokens
pub(super) async fn handle_service_accounts(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match load_accounts(&state, &admin).await {
        Ok(overview) => {
            Html(render_service_accounts_page(&state, &session, &overview).into_string())
                .into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// `POST /ui/actions/admin/service-accounts` form
#[derive(Debug, Deserialize)]
pub(super) struct CreateAccountForm {
    name: String,
    description: Option<String>,
}

/// Handle POST /ui/actions/admin/service-accounts - create an account
pub(super) async fn handle_account_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<CreateAccountForm>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin
        .create_service_account(form.name.trim(), form.description.as_deref())
        .await
    {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}

/// `POST /ui/actions/admin/service-accounts/{id}/disabled` form
#[derive(Debug, Deserialize)]
pub(super) struct DisabledForm {
    disabled: bool,
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/disabled - disable or
/// enable an account
pub(super) async fn handle_account_disabled(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
    AdminForm(form): AdminForm<DisabledForm>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.set_service_account_disabled(id, form.disabled).await {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/delete
pub(super) async fn handle_account_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.delete_service_account(id).await {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/tokens - issue a token
pub(super) async fn handle_account_token_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let form = match TokenForm::parse(&pairs) {
        Ok(form) => form,
        Err(error) => return error_response(&error),
    };
    match admin
        .issue_service_account_token(id, &form.name, form.expires_in_days, &form.scope)
        .await
    {
        Ok(issued) => accounts_fragment(&state, &admin, Some((id, &issued))).await,
        Err(error) => error_response(&error),
    }
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/tokens/{token_id}/revoke
pub(super) async fn handle_account_token_revoke(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path((id, token_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.revoke_service_account_token(id, token_id).await {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}

/// `POST /ui/actions/admin/service-accounts/{id}/jwt-bindings` form
#[derive(Debug, Deserialize)]
pub(super) struct JwtBindingForm {
    issuer: String,
    subject: String,
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/jwt-bindings - bind an
/// `IdP` subject to the account
pub(super) async fn handle_account_jwt_binding_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
    AdminForm(form): AdminForm<JwtBindingForm>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.service_account(id).await {
        return error_response(&error);
    }
    if let Err(error) = super::tokens_api::require_accepting_issuer(&state, &form.issuer) {
        return error_response(&error);
    }
    if let Err(error) = admin
        .create_jwt_binding(id, &form.issuer, &form.subject)
        .await
    {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}

/// Handle POST /ui/actions/admin/service-accounts/{id}/jwt-bindings/{binding_id}/delete
pub(super) async fn handle_account_jwt_binding_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path((id, binding_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.delete_jwt_binding(id, binding_id).await {
        return error_response(&error);
    }
    accounts_fragment(&state, &admin, None).await
}
