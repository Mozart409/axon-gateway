//! The personal MCP server pages and their htmx actions: `/ui/me/backends` for
//! a user's own servers, `/ui/catalog` for the catalog with the user's
//! credentials (and its admin, with `catalog.manage`) and
//! `/ui/admin/personal-backends` for the admin's overview of everybody's
//! servers (`users.manage`).
//!
//! The routes sit behind the session guard (and, for actions, the CSRF and
//! same-site checks) because `tokens_ui` merges them into its own; outside
//! multi-user mode, and without the personal hub, every one of them is a 404.
//! What a user may do is decided by the functions of `personal_api`, the logic
//! the JSON API uses too; this module only reads forms, calls them and renders
//! their errors in the flash area like the other pages. Header values and
//! credential values go in with the form and are never rendered back.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::Deserialize;
use uuid::Uuid;

use super::AppState;
use super::admin_ui::{AdminForm, error_response, flash_response, fragment, not_found, page_error};
use super::personal_api::{
    CatalogPatch, NewCatalogItem, NewPersonal, PersonalApiError, PersonalPatch, PersonalSaved,
    connect_failure, create_catalog_entry, create_personal, delete_catalog_entry,
    delete_credential, delete_personal, delete_personal_of, list_all_personal, list_catalog,
    list_personal, set_credential, set_personal_enabled, split_scopes, update_catalog_entry,
    update_personal,
};
use super::personal_views::{
    render_admin_page, render_admin_section, render_backends_page, render_backends_section,
    render_catalog_page, render_catalog_section,
};
use crate::config::CredentialField;
use crate::policy::Permission;
use crate::rbac::{AdminError, resolve};
use crate::store::SessionUser;

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/me/backends", get(handle_backends))
        .route("/ui/catalog", get(handle_catalog))
        .route("/ui/admin/personal-backends", get(handle_admin_personal))
}

/// The POST actions, to merge into the routes behind the CSRF and same-site
/// checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/actions/me/backends", post(handle_backend_create))
        .route(
            "/ui/actions/me/backends/{prefix}/update",
            post(handle_backend_update),
        )
        .route(
            "/ui/actions/me/backends/{prefix}/headers",
            post(handle_backend_headers),
        )
        .route(
            "/ui/actions/me/backends/{prefix}/enabled",
            post(handle_backend_enabled),
        )
        .route(
            "/ui/actions/me/backends/{prefix}/delete",
            post(handle_backend_delete),
        )
        .route("/ui/actions/catalog", post(handle_entry_create))
        .route(
            "/ui/actions/catalog/{name}/update",
            post(handle_entry_update),
        )
        .route(
            "/ui/actions/catalog/{name}/delete",
            post(handle_entry_delete),
        )
        .route(
            "/ui/actions/catalog/{name}/credential",
            post(handle_credential_set),
        )
        .route(
            "/ui/actions/catalog/{name}/credential/delete",
            post(handle_credential_delete),
        )
        .route(
            "/ui/actions/admin/personal-backends/{owner}/{prefix}/enabled",
            post(handle_admin_enabled),
        )
        .route(
            "/ui/actions/admin/personal-backends/{owner}/{prefix}/delete",
            post(handle_admin_delete),
        )
}

/// A form read as pairs, because the header and credential field rows repeat
type FormPairs = Vec<(String, String)>;

/// `POST .../update` of a personal server
#[derive(Debug, Deserialize)]
struct UrlForm {
    url: String,
}

/// The `enabled` switch of a server
#[derive(Debug, Deserialize)]
struct EnabledForm {
    enabled: bool,
}

/// The values of every row of a repeated key, in order
fn all<'a>(pairs: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> {
    pairs
        .iter()
        .filter(move |(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// The header rows of a form; rows with neither a name nor a value are the
/// empty ones of the form and are dropped
fn headers_of(pairs: &[(String, String)]) -> Result<BTreeMap<String, String>, AdminError> {
    let mut headers = BTreeMap::new();
    for (name, value) in all(pairs, "header_name").zip(all(pairs, "header_value")) {
        let name = name.trim();
        if name.is_empty() && value.is_empty() {
            continue;
        }
        if headers.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(AdminError::Invalid(format!(
                "the header {name:?} is listed twice"
            )));
        }
    }
    Ok(headers)
}

/// The credential field rows of the catalog create form; rows without a name
/// and a header are the empty ones of the form and are dropped. The prefix is
/// kept as typed, because it often ends in a space.
fn fields_of(pairs: &[(String, String)]) -> Vec<CredentialField> {
    all(pairs, "field_name")
        .zip(all(pairs, "field_label"))
        .zip(all(pairs, "field_header"))
        .zip(all(pairs, "field_prefix"))
        .filter(|(((name, _), header), _)| !(name.trim().is_empty() && header.trim().is_empty()))
        .map(|(((name, label), header), prefix)| CredentialField {
            name: name.trim().to_owned(),
            label: Some(label.to_owned()),
            header: header.trim().to_owned(),
            prefix: Some(prefix.to_owned()),
        })
        .collect()
}

/// The values of the credential form, whose inputs are named `field:<name>`
fn values_of(pairs: &[(String, String)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .filter_map(|(key, value)| {
            key.strip_prefix("field:")
                .map(|name| (name.to_owned(), value.clone()))
        })
        .collect()
}

/// The OAuth client secret of the catalog forms: what was typed, else an
/// empty string when "clear" is ticked (which clears the stored one), else
/// nothing (which keeps it)
fn secret_of(pairs: &[(String, String)]) -> Option<String> {
    if first(pairs, "clear_oauth_secret").is_some() {
        return Some(String::new());
    }
    first(pairs, "oauth_client_secret")
        .filter(|secret| !secret.is_empty())
        .map(str::to_owned)
}

/// The first value of a key
fn first<'a>(pairs: &'a [(String, String)], key: &'a str) -> Option<&'a str> {
    all(pairs, key).next()
}

/// The session, or the 404 when there is none or the personal hub is off
/// (boxed: a `Response` is large for an error type).
fn session_for(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
) -> Result<SessionUser, Box<Response>> {
    match user {
        Some(Extension(session)) if state.personal.is_some() => Ok(session),
        _ => Err(Box::new(not_found(state))),
    }
}

/// An action error: the flash fragment
pub(super) fn action_error(error: &PersonalApiError) -> Response {
    match error {
        PersonalApiError::Admin(error) => error_response(error),
        PersonalApiError::Disabled => flash_response(StatusCode::NOT_FOUND, error.to_string()),
        PersonalApiError::Connect(error) => {
            let (status, message) = connect_failure(error);
            flash_response(status, message)
        }
        PersonalApiError::Internal(message) => {
            tracing::warn!(message, "A personal backend page request failed");
            flash_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("the request could not be completed"),
            )
        }
    }
}

/// A page error: the 403 page, the 404 page or a plain status line.
fn page_failure(state: &AppState, session: &SessionUser, error: &PersonalApiError) -> Response {
    match error {
        PersonalApiError::Admin(error) => page_error(state, session, error),
        PersonalApiError::Disabled => not_found(state),
        PersonalApiError::Connect(error) => {
            let (status, message) = connect_failure(error);
            (status, format!("{message}\n")).into_response()
        }
        PersonalApiError::Internal(message) => {
            tracing::warn!(message, "A personal backend page request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the request could not be completed\n",
            )
                .into_response()
        }
    }
}

/// Whether the user may change the catalog
fn can_manage_catalog(state: &AppState, session: &SessionUser) -> bool {
    let (_, permissions) = resolve(&state.policy.current(), session);
    permissions.has(Permission::CatalogManage)
}

/// The answer to an action on `/ui/me/backends`: the section, with the result
/// of the save and test when there is one, or the error.
async fn backends_fragment(
    state: &AppState,
    session: &SessionUser,
    saved: Option<&PersonalSaved>,
) -> Response {
    match list_personal(state, session).await {
        Ok(list) => fragment(&render_backends_section(&list, saved)),
        Err(error) => action_error(&error),
    }
}

/// The answer to an action on `/ui/catalog`: the section, or the error.
pub(super) async fn catalog_fragment(state: &AppState, session: &SessionUser) -> Response {
    match list_catalog(state, session).await {
        Ok(list) => fragment(&render_catalog_section(
            &list,
            can_manage_catalog(state, session),
        )),
        Err(error) => action_error(&error),
    }
}

/// The answer to an action on `/ui/admin/personal-backends`: the section, or
/// the error.
async fn admin_fragment(state: &AppState, session: &SessionUser) -> Response {
    match list_all_personal(state, session).await {
        Ok(list) => fragment(&render_admin_section(&list)),
        Err(error) => action_error(&error),
    }
}

/// Handle GET /ui/me/backends - the user's own servers
async fn handle_backends(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match list_personal(&state, &session).await {
        Ok(list) => {
            Html(render_backends_page(&state, &session, &list).into_string()).into_response()
        }
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/me/backends - add a server and test it
async fn handle_backend_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let headers = match headers_of(&pairs) {
        Ok(headers) => headers,
        Err(error) => return error_response(&error),
    };
    let input = NewPersonal {
        prefix: first(&pairs, "prefix")
            .unwrap_or_default()
            .trim()
            .to_owned(),
        url: first(&pairs, "url").unwrap_or_default().to_owned(),
        headers,
    };
    match create_personal(&state, &session, input).await {
        Ok(saved) => backends_fragment(&state, &session, Some(&saved)).await,
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/me/backends/{prefix}/update - change the url
async fn handle_backend_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(prefix): Path<String>,
    AdminForm(form): AdminForm<UrlForm>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let patch = PersonalPatch {
        url: Some(form.url),
        ..PersonalPatch::default()
    };
    match update_personal(&state, &session, &prefix, patch).await {
        Ok(saved) => backends_fragment(&state, &session, Some(&saved)).await,
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/me/backends/{prefix}/headers - replace all headers
async fn handle_backend_headers(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(prefix): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let headers = match headers_of(&pairs) {
        Ok(headers) => headers,
        Err(error) => return error_response(&error),
    };
    let patch = PersonalPatch {
        headers: Some(headers),
        ..PersonalPatch::default()
    };
    match update_personal(&state, &session, &prefix, patch).await {
        Ok(saved) => backends_fragment(&state, &session, Some(&saved)).await,
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/me/backends/{prefix}/enabled - switch a server
async fn handle_backend_enabled(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(prefix): Path<String>,
    AdminForm(form): AdminForm<EnabledForm>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let patch = PersonalPatch {
        enabled: Some(form.enabled),
        ..PersonalPatch::default()
    };
    match update_personal(&state, &session, &prefix, patch).await {
        Ok(_) => backends_fragment(&state, &session, None).await,
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/me/backends/{prefix}/delete
async fn handle_backend_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(prefix): Path<String>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = delete_personal(&state, &session, &prefix).await {
        return action_error(&error);
    }
    backends_fragment(&state, &session, None).await
}

/// Handle GET /ui/catalog - the catalog and the user's credentials
async fn handle_catalog(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match list_catalog(&state, &session).await {
        Ok(list) => {
            let manage = can_manage_catalog(&state, &session);
            Html(render_catalog_page(&state, &session, &list, manage).into_string()).into_response()
        }
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/catalog/{name}/credential - store the user's credential
async fn handle_credential_set(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = set_credential(&state, &session, &name, values_of(&pairs)).await {
        return action_error(&error);
    }
    catalog_fragment(&state, &session).await
}

/// Handle POST /ui/actions/catalog/{name}/credential/delete
async fn handle_credential_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = delete_credential(&state, &session, &name).await {
        return action_error(&error);
    }
    catalog_fragment(&state, &session).await
}

/// Handle POST /ui/actions/catalog - add a catalog entry
async fn handle_entry_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let input = NewCatalogItem {
        name: first(&pairs, "name").unwrap_or_default().trim().to_owned(),
        description: first(&pairs, "description").map(str::to_owned),
        url: first(&pairs, "url").unwrap_or_default().to_owned(),
        credential_fields: fields_of(&pairs),
        auth: first(&pairs, "auth").map(str::to_owned),
        oauth_client_id: first(&pairs, "oauth_client_id").map(str::to_owned),
        oauth_scopes: split_scopes(first(&pairs, "oauth_scopes").unwrap_or_default()),
        oauth_client_secret: secret_of(&pairs),
    };
    if let Err(error) = create_catalog_entry(&state, &session, input).await {
        return action_error(&error);
    }
    catalog_fragment(&state, &session).await
}

/// Handle POST /ui/actions/catalog/{name}/update - change an entry of the database
async fn handle_entry_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let patch = CatalogPatch {
        description: first(&pairs, "description").map(str::to_owned),
        url: first(&pairs, "url").map(str::to_owned),
        enabled: first(&pairs, "enabled").and_then(|enabled| enabled.parse().ok()),
        auth: first(&pairs, "auth").map(str::to_owned),
        // The edit form always sends them: empty clears the client id and the
        // scopes, the secret is kept unless one is typed or cleared
        oauth_client_id: first(&pairs, "oauth_client_id").map(str::to_owned),
        oauth_scopes: first(&pairs, "oauth_scopes").map(split_scopes),
        oauth_client_secret: secret_of(&pairs),
        ..CatalogPatch::default()
    };
    if let Err(error) = update_catalog_entry(&state, &session, &name, patch).await {
        return action_error(&error);
    }
    catalog_fragment(&state, &session).await
}

/// Handle POST /ui/actions/catalog/{name}/delete
async fn handle_entry_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = delete_catalog_entry(&state, &session, &name).await {
        return action_error(&error);
    }
    catalog_fragment(&state, &session).await
}

/// Handle GET /ui/admin/personal-backends - everybody's servers
async fn handle_admin_personal(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match list_all_personal(&state, &session).await {
        Ok(list) => Html(render_admin_page(&state, &session, &list).into_string()).into_response(),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/personal-backends/{owner}/{prefix}/enabled
async fn handle_admin_enabled(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path((owner, prefix)): Path<(Uuid, String)>,
    AdminForm(form): AdminForm<EnabledForm>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = set_personal_enabled(&state, &session, owner, &prefix, form.enabled).await {
        return action_error(&error);
    }
    admin_fragment(&state, &session).await
}

/// Handle POST /ui/actions/admin/personal-backends/{owner}/{prefix}/delete
async fn handle_admin_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path((owner, prefix)): Path<(Uuid, String)>,
) -> Response {
    let session = match session_for(&state, user) {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(error) = delete_personal_of(&state, &session, owner, &prefix).await {
        return action_error(&error);
    }
    admin_fragment(&state, &session).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> FormPairs {
        items
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn empty_header_rows_are_dropped() {
        let form = pairs(&[
            ("header_name", " Authorization "),
            ("header_value", "Bearer x"),
            ("header_name", ""),
            ("header_value", ""),
            ("header_name", "X-Org"),
            ("header_value", "acme"),
        ]);
        let headers = headers_of(&form).expect("rows should parse");
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer x")
        );
        assert_eq!(headers.get("X-Org").map(String::as_str), Some("acme"));
    }

    #[test]
    fn a_value_without_a_name_is_kept_for_the_api_to_refuse() {
        let form = pairs(&[("header_name", ""), ("header_value", "secret")]);
        let headers = headers_of(&form).expect("row should parse");
        assert_eq!(headers.get("").map(String::as_str), Some("secret"));
    }

    #[test]
    fn a_repeated_header_is_refused() {
        let form = pairs(&[
            ("header_name", "X-Org"),
            ("header_value", "a"),
            ("header_name", "X-Org"),
            ("header_value", "b"),
        ]);
        assert!(matches!(headers_of(&form), Err(AdminError::Invalid(_))));
    }

    #[test]
    fn field_rows_keep_the_prefix_as_typed() {
        let form = pairs(&[
            ("field_name", "token"),
            ("field_label", "API token"),
            ("field_header", "Authorization"),
            ("field_prefix", "Bearer "),
            ("field_name", ""),
            ("field_label", ""),
            ("field_header", ""),
            ("field_prefix", ""),
        ]);
        let fields = fields_of(&form);
        assert_eq!(fields.len(), 1);
        assert_eq!(
            fields.first().and_then(|f| f.prefix.as_deref()),
            Some("Bearer ")
        );
        assert_eq!(fields.first().map(|f| f.name.as_str()), Some("token"));
    }

    #[test]
    fn the_client_secret_is_kept_unless_typed_or_cleared() {
        // empty: keep the stored one
        assert_eq!(secret_of(&pairs(&[("oauth_client_secret", "")])), None);
        assert_eq!(secret_of(&pairs(&[])), None);
        // typed: replace it
        assert_eq!(
            secret_of(&pairs(&[("oauth_client_secret", "s3cret")])).as_deref(),
            Some("s3cret")
        );
        // the box: clear it, even when something was typed
        assert_eq!(
            secret_of(&pairs(&[("clear_oauth_secret", "true")])).as_deref(),
            Some("")
        );
        assert_eq!(
            secret_of(&pairs(&[
                ("oauth_client_secret", "s3cret"),
                ("clear_oauth_secret", "true"),
            ]))
            .as_deref(),
            Some("")
        );
    }

    #[test]
    fn scopes_of_a_form_split_on_spaces_and_commas() {
        let form = pairs(&[("oauth_scopes", "read write,admin")]);
        assert_eq!(
            first(&form, "oauth_scopes").map(split_scopes),
            Some(vec![
                String::from("read"),
                String::from("write"),
                String::from("admin")
            ])
        );
        let blank = pairs(&[("oauth_scopes", "")]);
        assert_eq!(
            first(&blank, "oauth_scopes").map(split_scopes),
            Some(Vec::new())
        );
    }

    #[test]
    fn credential_values_are_read_from_prefixed_keys() {
        let form = pairs(&[("field:token", "abc"), ("field:org", ""), ("other", "x")]);
        let values = values_of(&form);
        assert_eq!(values.len(), 2);
        assert_eq!(values.get("token").map(String::as_str), Some("abc"));
        assert_eq!(values.get("org").map(String::as_str), Some(""));
    }
}
