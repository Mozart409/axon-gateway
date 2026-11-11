//! The admin pages under `/ui/admin` and their htmx actions under
//! `/ui/actions/admin`: RBAC groups, grants, role bindings, users and the
//! audit log.
//! (The service account pages are in `tokens_ui`, which reuses the helpers
//! here.)
//!
//! The routes sit behind the session guard (and, for actions, the CSRF and
//! same-site checks); outside multi-user mode every one of them is a 404. What
//! a user may do is decided by [`Admin`], the same service the JSON API uses.
//! This module maps HTTP to it and its errors back: a page answers a 403 page
//! or a plain-text status, an action answers the flash fragment with the
//! status (403, 404, 409, 400, 503) and `HX-Retarget`/`HX-Reswap` headers, so
//! the message shows in the page's flash area instead of replacing a section.
//! Successful actions answer the re-rendered section.

use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Form, Router};
use maud::{Markup, html};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::admin_views::{
    self, Access, AdminOverview, GroupDetail, GroupRow, UsersPage, render_flash_area,
};
use super::{AppState, FlashLevel, FlashMessage, views};
use crate::gateway::GetDetailedStatus;
use crate::policy::{AUTHENTICATED_GROUP, GrantConfig, Role, RoleSubject};
use crate::rbac::{Admin, AdminError, resolve};
use crate::store::{ServiceAccount, SessionUser, User};

/// Users the member and role binding selects offer
const USERS_LIMIT: i64 = 500;
/// Audit entries per page
const AUDIT_PAGE: usize = 50;
/// One more than a page, to know whether an older page exists
const AUDIT_FETCH: i64 = 51;

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/admin", get(handle_admin))
        .route("/ui/admin/groups/{name}", get(handle_admin_group))
        .route("/ui/admin/audit", get(handle_admin_audit))
        .route("/ui/admin/users", get(handle_admin_users))
}

/// The POST actions, to merge into the routes behind the CSRF and same-site
/// checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/actions/admin/groups", post(handle_admin_group_create))
        .route(
            "/ui/actions/admin/groups/{name}/update",
            post(handle_admin_group_update),
        )
        .route(
            "/ui/actions/admin/groups/{name}/delete",
            post(handle_admin_group_delete),
        )
        .route(
            "/ui/actions/admin/groups/{name}/idp-mappings/add",
            post(handle_admin_mapping_add),
        )
        .route(
            "/ui/actions/admin/groups/{name}/idp-mappings/remove",
            post(handle_admin_mapping_remove),
        )
        .route(
            "/ui/actions/admin/groups/{name}/members/add",
            post(handle_admin_member_add),
        )
        .route(
            "/ui/actions/admin/groups/{name}/members/remove",
            post(handle_admin_member_remove),
        )
        .route("/ui/actions/admin/grants", post(handle_admin_grant_create))
        .route(
            "/ui/actions/admin/grants/{id}/delete",
            post(handle_admin_grant_delete),
        )
        .route(
            "/ui/actions/admin/role-bindings",
            post(handle_admin_binding_create),
        )
        .route(
            "/ui/actions/admin/role-bindings/{id}/delete",
            post(handle_admin_binding_delete),
        )
        .route(
            "/ui/actions/admin/users/{id}/disable",
            post(handle_admin_user_disable),
        )
        .route(
            "/ui/actions/admin/users/{id}/enable",
            post(handle_admin_user_enable),
        )
}

/// A form-encoded body whose rejection is the flash fragment with a 400
pub(super) struct AdminForm<T>(pub(super) T);

impl<S, T> FromRequest<S> for AdminForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(request: Request, state: &S) -> Result<Self, Response> {
        match Form::<T>::from_request(request, state).await {
            Ok(Form(value)) => Ok(Self(value)),
            Err(rejection) => Err(flash_response(
                StatusCode::BAD_REQUEST,
                rejection.body_text(),
            )),
        }
    }
}

pub(super) fn not_found(state: &AppState) -> Response {
    (
        StatusCode::NOT_FOUND,
        Html(views::render_not_found_page(state).into_string()),
    )
        .into_response()
}

/// The session and the admin service, or the 404 outside multi-user mode
/// (boxed: a `Response` is large for an error type).
pub(super) async fn admin_for(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
) -> Result<(SessionUser, Admin<'_>), Box<Response>> {
    let Some(Extension(session)) = user else {
        return Err(Box::new(not_found(state)));
    };
    match Admin::from_state(state, &session).await {
        Some(admin) => Ok((session, admin)),
        None => Err(Box::new(not_found(state))),
    }
}

fn status_and_message(error: &AdminError) -> (StatusCode, String) {
    match error {
        AdminError::Forbidden => (StatusCode::FORBIDDEN, error.to_string()),
        AdminError::NotFound => (StatusCode::NOT_FOUND, error.to_string()),
        AdminError::Conflict(_) => (StatusCode::CONFLICT, error.to_string()),
        AdminError::Invalid(_) => (StatusCode::BAD_REQUEST, error.to_string()),
        AdminError::Store(error) => {
            tracing::warn!(%error, "An admin page request failed in the database");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the database is unavailable".to_owned(),
            )
        }
    }
}

/// An action error: the flash fragment, shown in the flash area at the top of
/// the page.
pub(super) fn flash_response(status: StatusCode, message: String) -> Response {
    let flash = FlashMessage {
        level: FlashLevel::Error,
        message,
    };
    (
        status,
        [("HX-Retarget", "#admin-flash"), ("HX-Reswap", "innerHTML")],
        Html(views::render_flash(&flash).into_string()),
    )
        .into_response()
}

pub(super) fn error_response(error: &AdminError) -> Response {
    let (status, message) = status_and_message(error);
    flash_response(status, message)
}

/// A page error: the 403 page, the 404 page or a plain status line.
pub(super) fn page_error(state: &AppState, session: &SessionUser, error: &AdminError) -> Response {
    match error {
        AdminError::Forbidden => (
            StatusCode::FORBIDDEN,
            Html(admin_views::render_forbidden_page(state, session).into_string()),
        )
            .into_response(),
        AdminError::NotFound => not_found(state),
        _ => {
            let (status, message) = status_and_message(error);
            (status, format!("{message}\n")).into_response()
        }
    }
}

/// A successful action: the re-rendered fragment, plus an out-of-band swap
/// that clears an error left in the flash area.
pub(super) fn fragment(markup: &Markup) -> Response {
    let body = html! {
        (markup)
        (render_flash_area(true))
    };
    Html(body.into_string()).into_response()
}

pub(super) async fn backend_names(state: &AppState) -> Vec<String> {
    match state.gateway.ask(GetDetailedStatus).await {
        Ok(status) => {
            let mut names: Vec<String> = status
                .backends
                .into_iter()
                .map(|backend| backend.name)
                .collect();
            // Catalog entries are granted like shared backends
            if let Some(hub) = &state.personal {
                names.extend(hub.catalog().into_iter().map(|item| item.name));
            }
            names.sort();
            names.dedup();
            names
        }
        Err(error) => {
            tracing::warn!(?error, "Failed to list backends for an admin page");
            Vec::new()
        }
    }
}

/// The users to pick from; none for a viewer who may not list them.
async fn load_users(admin: &Admin<'_>) -> Result<Vec<User>, AdminError> {
    match admin.users(USERS_LIMIT).await {
        Err(AdminError::Forbidden) => Ok(Vec::new()),
        other => other,
    }
}

/// The service accounts to pick from; none for a viewer who may not list them.
async fn load_accounts(admin: &Admin<'_>) -> Result<Vec<ServiceAccount>, AdminError> {
    match admin.service_accounts().await {
        Err(AdminError::Forbidden) => Ok(Vec::new()),
        other => other,
    }
}

fn access_of(state: &AppState, session: &SessionUser) -> Access {
    let (_, permissions) = resolve(&state.policy.current(), session);
    Access::of(&permissions)
}

async fn load_overview(
    state: &AppState,
    session: &SessionUser,
    admin: &Admin<'_>,
) -> Result<AdminOverview, AdminError> {
    let groups = admin.groups()?;
    let mut rows = Vec::with_capacity(groups.len());
    for group in groups {
        let members = admin.group(&group.name)?.1.len();
        rows.push(GroupRow { group, members });
    }
    let group_names = std::iter::once(AUTHENTICATED_GROUP.to_owned())
        .chain(rows.iter().map(|row| row.group.name.clone()))
        .collect();

    Ok(AdminOverview {
        access: access_of(state, session),
        groups: rows,
        grants: admin.grants()?,
        bindings: admin.role_bindings()?,
        group_names,
        backends: backend_names(state).await,
        users: load_users(admin).await?,
    })
}

async fn load_group_detail(
    state: &AppState,
    session: &SessionUser,
    admin: &Admin<'_>,
    name: &str,
) -> Result<GroupDetail, AdminError> {
    let (group, members) = admin.group(name)?;
    let providers: Vec<String> = state
        .multi_user()
        .map(|(_, oidc)| {
            oidc.iter()
                .map(|provider| provider.id().to_owned())
                .collect()
        })
        .unwrap_or_default();

    Ok(GroupDetail {
        access: access_of(state, session),
        group,
        members,
        users: load_users(admin).await?,
        accounts: load_accounts(admin).await?,
        providers,
    })
}

/// The answer to an action on `/ui/admin`: the overview sections `render`
/// picks, or the error.
async fn overview_fragment(
    state: &AppState,
    session: &SessionUser,
    admin: &Admin<'_>,
    render: impl FnOnce(&AdminOverview) -> Markup,
) -> Response {
    match load_overview(state, session, admin).await {
        Ok(overview) => fragment(&render(&overview)),
        Err(error) => error_response(&error),
    }
}

/// The answer to an action on a group page: the group section `render` picks,
/// or the error.
async fn group_fragment(
    state: &AppState,
    session: &SessionUser,
    admin: &Admin<'_>,
    name: &str,
    render: impl FnOnce(&GroupDetail) -> Markup,
) -> Response {
    match load_group_detail(state, session, admin, name).await {
        Ok(detail) => fragment(&render(&detail)),
        Err(error) => error_response(&error),
    }
}

/// Handle GET /ui/admin - groups, grants and role bindings
pub(super) async fn handle_admin(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match load_overview(&state, &session, &admin).await {
        Ok(overview) => {
            Html(admin_views::render_admin_page(&state, &session, &overview).into_string())
                .into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle GET /ui/admin/groups/{name} - one group
pub(super) async fn handle_admin_group(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match load_group_detail(&state, &session, &admin, &name).await {
        Ok(detail) => Html(admin_views::render_group_page(&state, &session, &detail).into_string())
            .into_response(),
        Err(error) => page_error(&state, &session, &error),
    }
}

async fn load_users_page(
    state: &AppState,
    session: &SessionUser,
    admin: &Admin<'_>,
) -> Result<UsersPage, AdminError> {
    Ok(UsersPage {
        access: access_of(state, session),
        viewer: session.user.id,
        users: admin.managed_users(USERS_LIMIT).await?,
    })
}

/// Handle GET /ui/admin/users - the human users and their state
pub(super) async fn handle_admin_users(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match load_users_page(&state, &session, &admin).await {
        Ok(page) => Html(admin_views::render_users_page(&state, &session, &page).into_string())
            .into_response(),
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Disables or re-enables a user, then answers the re-rendered users table.
async fn set_user_disabled(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
    id: Uuid,
    disabled: bool,
) -> Response {
    let (session, admin) = match admin_for(state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.set_user_disabled(id, disabled).await {
        return error_response(&error);
    }
    match load_users_page(state, &session, &admin).await {
        Ok(page) => fragment(&admin_views::render_users_section(&page)),
        Err(error) => error_response(&error),
    }
}

/// Handle POST /ui/actions/admin/users/{id}/disable
pub(super) async fn handle_admin_user_disable(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    set_user_disabled(&state, user, id, true).await
}

/// Handle POST /ui/actions/admin/users/{id}/enable
pub(super) async fn handle_admin_user_enable(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    set_user_disabled(&state, user, id, false).await
}

/// `GET /ui/admin/audit?before=`: `before` is an entry id, for paging
#[derive(Debug, Deserialize)]
pub(super) struct AuditQuery {
    before: Option<i64>,
}

/// Handle GET /ui/admin/audit - the audit log, newest first
pub(super) async fn handle_admin_audit(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut entries = match admin.audit(AUDIT_FETCH, query.before).await {
        Ok(entries) => entries,
        Err(error) => return page_error(&state, &session, &error),
    };
    let older = if entries.len() > AUDIT_PAGE {
        entries.truncate(AUDIT_PAGE);
        entries.last().map(|entry| entry.id)
    } else {
        None
    };
    Html(
        admin_views::render_audit_page(&state, &session, &entries, query.before, older)
            .into_string(),
    )
    .into_response()
}

/// `POST /ui/actions/admin/groups` form
#[derive(Debug, Deserialize)]
pub(super) struct CreateGroupForm {
    name: String,
    description: Option<String>,
}

/// Handle POST /ui/actions/admin/groups - create a group
pub(super) async fn handle_admin_group_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<CreateGroupForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin
        .create_group(form.name.trim(), form.description.as_deref())
        .await
    {
        return error_response(&error);
    }
    // The new group is selectable in the grant and role binding forms too.
    overview_fragment(&state, &session, &admin, |overview| {
        html! {
            (admin_views::render_groups_section(overview, false))
            (admin_views::render_grants_section(overview, true))
            (admin_views::render_bindings_section(overview, true))
        }
    })
    .await
}

/// `POST /ui/actions/admin/groups/{name}/update` form; blank clears
#[derive(Debug, Deserialize)]
pub(super) struct UpdateGroupForm {
    description: Option<String>,
}

/// Handle POST /ui/actions/admin/groups/{name}/update - edit the description
pub(super) async fn handle_admin_group_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(form): AdminForm<UpdateGroupForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.update_group(&name, form.description.as_deref()).await {
        return error_response(&error);
    }
    group_fragment(
        &state,
        &session,
        &admin,
        &name,
        admin_views::render_group_settings,
    )
    .await
}

/// Handle POST /ui/actions/admin/groups/{name}/delete - delete a group, then
/// back to the overview
pub(super) async fn handle_admin_group_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (_, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match admin.delete_group(&name).await {
        Ok(()) => ([("HX-Redirect", "/ui/admin")], ()).into_response(),
        Err(error) => error_response(&error),
    }
}

/// `POST /ui/actions/admin/groups/{name}/idp-mappings/{add,remove}` form
#[derive(Debug, Deserialize)]
pub(super) struct MappingForm {
    provider: String,
    value: String,
}

/// Handle POST /ui/actions/admin/groups/{name}/idp-mappings/add
pub(super) async fn handle_admin_mapping_add(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(form): AdminForm<MappingForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin
        .add_idp_mapping(&name, &form.provider, form.value.trim())
        .await
    {
        return error_response(&error);
    }
    group_fragment(
        &state,
        &session,
        &admin,
        &name,
        admin_views::render_group_mappings,
    )
    .await
}

/// Handle POST /ui/actions/admin/groups/{name}/idp-mappings/remove
pub(super) async fn handle_admin_mapping_remove(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(form): AdminForm<MappingForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin
        .remove_idp_mapping(&name, &form.provider, &form.value)
        .await
    {
        return error_response(&error);
    }
    group_fragment(
        &state,
        &session,
        &admin,
        &name,
        admin_views::render_group_mappings,
    )
    .await
}

/// `POST /ui/actions/admin/groups/{name}/members/{add,remove}` form
#[derive(Debug, Deserialize)]
pub(super) struct MemberForm {
    user_id: Uuid,
}

/// Handle POST /ui/actions/admin/groups/{name}/members/add
pub(super) async fn handle_admin_member_add(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(form): AdminForm<MemberForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.add_member(&name, form.user_id).await {
        return error_response(&error);
    }
    group_fragment(
        &state,
        &session,
        &admin,
        &name,
        admin_views::render_group_members,
    )
    .await
}

/// Handle POST /ui/actions/admin/groups/{name}/members/remove
pub(super) async fn handle_admin_member_remove(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(form): AdminForm<MemberForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.remove_member(&name, form.user_id).await {
        return error_response(&error);
    }
    group_fragment(
        &state,
        &session,
        &admin,
        &name,
        admin_views::render_group_members,
    )
    .await
}

/// `POST /ui/actions/admin/grants` form: the globs are comma separated, the
/// checkboxes are present when checked
#[derive(Debug, Deserialize)]
pub(super) struct GrantForm {
    group: String,
    backend: String,
    include: Option<String>,
    exclude: Option<String>,
    read_only: Option<String>,
    mandatory: Option<String>,
}

/// The non-empty, trimmed entries of a comma separated list.
pub(super) fn split_globs(text: Option<&str>) -> Vec<String> {
    text.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Handle POST /ui/actions/admin/grants - add a grant
pub(super) async fn handle_admin_grant_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<GrantForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut include = split_globs(form.include.as_deref());
    if include.is_empty() {
        include.push(String::from("*"));
    }
    let grant = GrantConfig {
        group: form.group,
        backend: form.backend,
        include,
        exclude: split_globs(form.exclude.as_deref()),
        read_only: form.read_only.is_some(),
        mandatory: form.mandatory.is_some(),
    };
    if let Err(error) = admin.create_grant(grant).await {
        return error_response(&error);
    }
    overview_fragment(&state, &session, &admin, |overview| {
        admin_views::render_grants_section(overview, false)
    })
    .await
}

/// Handle POST /ui/actions/admin/grants/{id}/delete
pub(super) async fn handle_admin_grant_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<i64>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.delete_grant(id).await {
        return error_response(&error);
    }
    overview_fragment(&state, &session, &admin, |overview| {
        admin_views::render_grants_section(overview, false)
    })
    .await
}

/// `POST /ui/actions/admin/role-bindings` form: the role and exactly one of
/// group and user (the other select is left empty)
#[derive(Debug, Deserialize)]
pub(super) struct BindingForm {
    role: String,
    group: Option<String>,
    user_id: Option<String>,
}

/// Handle POST /ui/actions/admin/role-bindings - add a role binding
pub(super) async fn handle_admin_binding_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(form): AdminForm<BindingForm>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(role) = Role::parse(&form.role) else {
        return error_response(&AdminError::Invalid(format!(
            "unknown role {:?}",
            form.role
        )));
    };
    let group = form.group.filter(|group| !group.is_empty());
    let user_id = form.user_id.filter(|user_id| !user_id.is_empty());
    let subject = match (group, user_id) {
        (Some(group), None) => RoleSubject::Group(group),
        (None, Some(user_id)) => match Uuid::parse_str(&user_id) {
            Ok(user_id) => RoleSubject::User(user_id),
            Err(_) => return error_response(&AdminError::Invalid(String::from("invalid user"))),
        },
        _ => {
            return error_response(&AdminError::Invalid(String::from(
                "choose exactly one of group and user",
            )));
        }
    };
    if let Err(error) = admin.create_role_binding(role, subject).await {
        return error_response(&error);
    }
    overview_fragment(&state, &session, &admin, |overview| {
        admin_views::render_bindings_section(overview, false)
    })
    .await
}

/// Handle POST /ui/actions/admin/role-bindings/{id}/delete
pub(super) async fn handle_admin_binding_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<i64>,
) -> Response {
    let (session, admin) = match admin_for(&state, user).await {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = admin.delete_role_binding(id).await {
        return error_response(&error);
    }
    overview_fragment(&state, &session, &admin, |overview| {
        admin_views::render_bindings_section(overview, false)
    })
    .await
}
