//! The configuration pages under `/ui/admin/config` and their htmx actions
//! under `/ui/actions/admin/config`: shared backends, gateway toolsets, OIDC
//! providers and the global settings, stored in the database.
//!
//! The routes sit behind the session guard (and, for actions, the CSRF and
//! same-site checks); outside database mode every one of them is a 404. What a
//! user may do is decided by [`ConfigCtx`], the logic the JSON API uses too;
//! this module only reads forms, calls it and renders its errors in the flash
//! area like the other pages. A save answers the re-rendered section, a create
//! or delete answers an `HX-Redirect`. On a form, an empty secret input keeps
//! the stored value, a "clear" checkbox clears it, and a header or variable
//! row is removed with its "remove" checkbox.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};

use super::AppState;
use super::admin_ui::{AdminForm, error_response, flash_response, fragment, not_found, page_error};
use super::config_api::{Area, BackendInput, ConfigApiError, ConfigCtx, ProviderInput};
use super::config_views::{
    FormEnv, PageCtx, render_backend_edit, render_backend_page, render_backends_page,
    render_provider_edit, render_provider_page, render_providers_page, render_settings_page,
    render_settings_section, render_toolset_edit, render_toolset_page, render_toolsets_page,
};
use crate::config::{
    BackendConfig, CredentialField, CredentialMode, GatewaySettings, OidcProviderConfig,
    PassthroughConfig, PassthroughGrant, ToolsetConfig, TransportType, UpstreamOAuthConfig,
};
use crate::rbac::AdminError;
use crate::store::SessionUser;

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/admin/config/backends", get(handle_backends))
        .route("/ui/admin/config/backends/{name}", get(handle_backend))
        .route("/ui/admin/config/toolsets", get(handle_toolsets))
        .route("/ui/admin/config/toolsets/{name}", get(handle_toolset))
        .route("/ui/admin/config/oidc-providers", get(handle_providers))
        .route("/ui/admin/config/oidc-providers/{id}", get(handle_provider))
        .route("/ui/admin/config/settings", get(handle_settings))
}

/// The POST actions, to merge into the routes behind the CSRF and same-site
/// checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/ui/actions/admin/config/backends",
            post(handle_backend_create),
        )
        .route(
            "/ui/actions/admin/config/backends/{name}/update",
            post(handle_backend_update),
        )
        .route(
            "/ui/actions/admin/config/backends/{name}/delete",
            post(handle_backend_delete),
        )
        .route(
            "/ui/actions/admin/config/toolsets",
            post(handle_toolset_create),
        )
        .route(
            "/ui/actions/admin/config/toolsets/{name}/update",
            post(handle_toolset_update),
        )
        .route(
            "/ui/actions/admin/config/toolsets/{name}/delete",
            post(handle_toolset_delete),
        )
        .route(
            "/ui/actions/admin/config/oidc-providers",
            post(handle_provider_create),
        )
        .route(
            "/ui/actions/admin/config/oidc-providers/{id}/update",
            post(handle_provider_update),
        )
        .route(
            "/ui/actions/admin/config/oidc-providers/{id}/delete",
            post(handle_provider_delete),
        )
        .route(
            "/ui/actions/admin/config/settings",
            post(handle_settings_save),
        )
}

/// A form read as pairs, because the header and variable rows repeat
type FormPairs = Vec<(String, String)>;

/// The values of every row of a repeated key, in order
fn all<'a>(pairs: &'a [(String, String)], key: &'a str) -> impl Iterator<Item = &'a str> {
    pairs
        .iter()
        .filter(move |(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

/// The first value of a key
fn first<'a>(pairs: &'a [(String, String)], key: &'a str) -> Option<&'a str> {
    all(pairs, key).next()
}

/// A text input, trimmed; empty is none
fn text(pairs: &[(String, String)], key: &str) -> Option<String> {
    first(pairs, key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// A checkbox: ticked when the key is there
fn flag(pairs: &[(String, String)], key: &str) -> bool {
    first(pairs, key).is_some()
}

/// A textarea with one entry per line, blank lines dropped
fn lines_of(pairs: &[(String, String)], key: &str) -> Vec<String> {
    first(pairs, key)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A number input; empty is none
fn number<T: FromStr>(
    pairs: &[(String, String)],
    key: &str,
    label: &str,
) -> Result<Option<T>, AdminError> {
    let Some(value) = text(pairs, key) else {
        return Ok(None);
    };
    value
        .parse()
        .map(Some)
        .map_err(|_| AdminError::Invalid(format!("{label} must be a whole number")))
}

/// A secret input: what was typed, else an empty string when "clear" is ticked
/// (which clears the stored one), else nothing (which keeps it)
fn secret_of(pairs: &[(String, String)], key: &str, clear_key: &str) -> Option<String> {
    if flag(pairs, clear_key) {
        return Some(String::new());
    }
    first(pairs, key)
        .filter(|secret| !secret.is_empty())
        .map(str::to_owned)
}

/// The header or variable rows of a form (`{prefix}_name`, `{prefix}_value`,
/// `{prefix}_remove`). An empty value keeps the stored one, a ticked row is
/// removed, and rows with neither a name nor a value are the empty ones of the
/// form.
fn secret_rows_of(
    pairs: &[(String, String)],
    prefix: &str,
    label: &str,
) -> Result<BTreeMap<String, Option<String>>, AdminError> {
    let (remove_key, name_key, value_key) = (
        format!("{prefix}_remove"),
        format!("{prefix}_name"),
        format!("{prefix}_value"),
    );
    let removed: BTreeSet<&str> = all(pairs, &remove_key).collect();
    let mut rows = BTreeMap::new();
    for (name, value) in all(pairs, &name_key).zip(all(pairs, &value_key)) {
        let name = name.trim();
        if name.is_empty() {
            if value.is_empty() {
                continue;
            }
            return Err(AdminError::Invalid(format!("a {label} value needs a name")));
        }
        if removed.contains(name) {
            continue;
        }
        let value = (!value.is_empty()).then(|| value.to_owned());
        if rows.insert(name.to_owned(), value).is_some() {
            return Err(AdminError::Invalid(format!(
                "the {label} {name:?} is listed twice"
            )));
        }
    }
    Ok(rows)
}

/// The credential fields of a per-user backend (`credential_name`,
/// `credential_label`, `credential_header`, `credential_prefix`); rows with
/// nothing in them are the empty ones of the form. The prefix keeps its
/// spaces, as in `Bearer `.
fn credential_fields_of(pairs: &[(String, String)]) -> Result<Vec<CredentialField>, AdminError> {
    let rows = all(pairs, "credential_name")
        .zip(all(pairs, "credential_label"))
        .zip(all(pairs, "credential_header"))
        .zip(all(pairs, "credential_prefix"));
    let mut fields: Vec<CredentialField> = Vec::new();
    for (((name, label), header), prefix) in rows {
        let (name, label, header) = (name.trim(), label.trim(), header.trim());
        if [name, label, header, prefix]
            .iter()
            .all(|cell| cell.is_empty())
        {
            continue;
        }
        if name.is_empty() || header.is_empty() {
            return Err(AdminError::Invalid(String::from(
                "a credential field needs a name and a header",
            )));
        }
        if fields.iter().any(|field| field.name == name) {
            return Err(AdminError::Invalid(format!(
                "the credential field {name:?} is listed twice"
            )));
        }
        fields.push(CredentialField {
            name: name.to_owned(),
            label: (!label.is_empty()).then(|| label.to_owned()),
            header: header.to_owned(),
            prefix: (!prefix.is_empty()).then(|| prefix.to_owned()),
        });
    }
    Ok(fields)
}

/// The credential mode and the section of the selected mode onto `config`; the
/// sections of the other modes are dropped. A form without a mode leaves all of
/// it as it is.
fn apply_credential_mode(
    config: &mut BackendConfig,
    pairs: &[(String, String)],
) -> Result<(), AdminError> {
    let Some(mode) = first(pairs, "credential_mode") else {
        return Ok(());
    };
    let stored_oauth = config.oauth.take();
    config.passthrough = None;
    config.credential_fields = Vec::new();
    config.credential_mode = match mode {
        "shared" => CredentialMode::Shared,
        "per_user" => {
            config.credential_fields = credential_fields_of(pairs)?;
            CredentialMode::PerUser
        }
        "oauth" => {
            let scopes = lines_of(pairs, "oauth_scopes");
            config.oauth = match text(pairs, "oauth_client_id") {
                Some(client_id) => Some(UpstreamOAuthConfig {
                    client_id,
                    // Not on the form: the environment variable of a file config
                    client_secret_env: stored_oauth.and_then(|oauth| oauth.client_secret_env),
                    client_secret: None,
                    scopes,
                }),
                None if scopes.is_empty() => None,
                None => {
                    return Err(AdminError::Invalid(String::from(
                        "OAuth scopes need a client ID; leave both empty to register dynamically",
                    )));
                }
            };
            CredentialMode::OAuth
        }
        "passthrough" => {
            let grant = match first(pairs, "passthrough_grant").unwrap_or("token_exchange") {
                "token_exchange" => PassthroughGrant::TokenExchange,
                "entra_obo" => PassthroughGrant::EntraObo,
                other => {
                    return Err(AdminError::Invalid(format!(
                        "the grant {other:?} is not token_exchange or entra_obo"
                    )));
                }
            };
            let Some(provider) = text(pairs, "passthrough_provider") else {
                return Err(AdminError::Invalid(String::from(
                    "identity passthrough needs the OIDC provider that issued the user's token",
                )));
            };
            config.passthrough = Some(PassthroughConfig {
                grant,
                provider,
                audience: text(pairs, "passthrough_audience"),
                scope: text(pairs, "passthrough_scope"),
                resource: text(pairs, "passthrough_resource"),
                assertion_scope: text(pairs, "passthrough_assertion_scope"),
            });
            CredentialMode::Passthrough
        }
        other => {
            return Err(AdminError::Invalid(format!(
                "the credential mode {other:?} is not shared, per_user, oauth or passthrough"
            )));
        }
    };
    Ok(())
}

/// The fields of the backend form onto `config`. A form without a credential
/// mode leaves the mode and its sections (credential fields, OAuth client,
/// passthrough) as they are.
fn apply_backend_form(
    config: &mut BackendConfig,
    pairs: &[(String, String)],
) -> Result<(), AdminError> {
    config.transport = match first(pairs, "transport").unwrap_or("http") {
        "http" => TransportType::Http,
        "sse" => TransportType::Sse,
        "stdio" => TransportType::Stdio,
        other => {
            return Err(AdminError::Invalid(format!(
                "the transport {other:?} is not http, sse or stdio"
            )));
        }
    };
    config.url = text(pairs, "url");
    config.command = text(pairs, "command");
    let args = lines_of(pairs, "args");
    config.args = (!args.is_empty()).then_some(args);
    config.enabled = flag(pairs, "enabled");
    config.allowed_tools = lines_of(pairs, "allowed_tools");
    if let Some(value) = number(pairs, "timeout_secs", "the call timeout")? {
        config.timeout_secs = value;
    }
    if let Some(value) = number(pairs, "health_check_interval_secs", "the health interval")? {
        config.health_check_interval_secs = value;
    }
    if let Some(value) = number(pairs, "max_consecutive_failures", "the failure limit")? {
        config.max_consecutive_failures = value;
    }
    if let Some(value) = number(
        pairs,
        "circuit_breaker_cooldown_secs",
        "the breaker cooldown",
    )? {
        config.circuit_breaker_cooldown_secs = value;
    }
    config.idle_timeout_secs = number(pairs, "idle_timeout_secs", "the idle timeout")?;
    apply_credential_mode(config, pairs)
}

/// The backend form as input: the config as `config` holds it with the form's
/// fields applied, and the secrets the form gave.
fn backend_input_of(
    mut config: BackendConfig,
    pairs: &[(String, String)],
) -> Result<BackendInput, AdminError> {
    apply_backend_form(&mut config, pairs)?;
    config.auth_token = secret_of(pairs, "auth_token", "clear_auth_token");
    Ok(BackendInput {
        config,
        headers: secret_rows_of(pairs, "header", "header")?,
        env: secret_rows_of(pairs, "env", "variable")?,
        oauth_client_secret: secret_of(pairs, "oauth_client_secret", "clear_oauth_secret"),
    })
}

/// The fields of the provider form onto `config`; the position of the form
fn apply_provider_form(
    config: &mut OidcProviderConfig,
    pairs: &[(String, String)],
) -> Result<Option<i32>, AdminError> {
    let defaults = OidcProviderConfig::default();
    config.display_name = text(pairs, "display_name");
    config.issuer = text(pairs, "issuer").unwrap_or_default();
    config.client_id = text(pairs, "client_id").unwrap_or_default();
    let scopes = lines_of(pairs, "scopes");
    config.scopes = if scopes.is_empty() {
        defaults.scopes
    } else {
        scopes
    };
    config.groups_claim = text(pairs, "groups_claim").unwrap_or(defaults.groups_claim);
    config.allowed_email_domains = lines_of(pairs, "allowed_email_domains");
    config.admin_groups = lines_of(pairs, "admin_groups");
    config.accept_access_tokens = flag(pairs, "accept_access_tokens");
    config.access_token_audience = text(pairs, "access_token_audience");
    config.graph_overage = flag(pairs, "graph_overage");
    config.graph_url = text(pairs, "graph_url");
    config.scim_match_claim = text(pairs, "scim_match_claim");
    number(pairs, "position", "the position")
}

fn toolset_of(name: String, pairs: &[(String, String)]) -> ToolsetConfig {
    ToolsetConfig {
        name,
        tools: lines_of(pairs, "tools"),
        backends: lines_of(pairs, "backends"),
        description: text(pairs, "description"),
    }
}

/// The session and the configuration operations, or the 404 outside database
/// mode (boxed: a `Response` is large for an error type).
fn ctx_for(
    state: &AppState,
    user: Option<Extension<SessionUser>>,
) -> Result<(SessionUser, ConfigCtx<'_>), Box<Response>> {
    let Some(Extension(session)) = user else {
        return Err(Box::new(not_found(state)));
    };
    match ConfigCtx::from_state(state, &session) {
        Some(ctx) => Ok((session, ctx)),
        None => Err(Box::new(not_found(state))),
    }
}

fn page_ctx(ctx: &ConfigCtx<'_>, area: Area) -> PageCtx {
    PageCtx {
        read_backends: ctx.can_read(Area::Backends),
        read_gateway: ctx.can_read(Area::Gateway),
        can_write: ctx.can_write(area),
        allow_stdio: ctx.allow_stdio(),
    }
}

/// An action error: the flash fragment
fn action_error(error: &ConfigApiError) -> Response {
    match error {
        ConfigApiError::Admin(error) => error_response(error),
        ConfigApiError::Internal(message) => {
            tracing::warn!(message, "A configuration page request failed");
            flash_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                String::from("the request could not be completed"),
            )
        }
    }
}

/// A page error: the 403 page, the 404 page or a plain status line.
fn page_failure(state: &AppState, session: &SessionUser, error: &ConfigApiError) -> Response {
    match error {
        ConfigApiError::Admin(error) => page_error(state, session, error),
        ConfigApiError::Internal(message) => {
            tracing::warn!(message, "A configuration page request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the request could not be completed\n",
            )
                .into_response()
        }
    }
}

/// A successful create or delete: htmx goes to `to`
fn redirect(to: &str) -> Response {
    (StatusCode::OK, [("HX-Redirect", to.to_owned())]).into_response()
}

fn page_response(markup: maud::Markup) -> Response {
    Html(markup.into_string()).into_response()
}

// -- backends -----------------------------------------------------------------

/// Handle GET /ui/admin/config/backends
async fn handle_backends(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let providers = match ctx.provider_ids().await {
        Ok(providers) => providers,
        Err(error) => return page_failure(&state, &session, &error),
    };
    match ctx.list_backends().await {
        Ok(list) => page_response(render_backends_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Backends),
            FormEnv::new(&state.base_url, &providers),
            &list,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle GET /ui/admin/config/backends/{name}
async fn handle_backend(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let providers = match ctx.provider_ids().await {
        Ok(providers) => providers,
        Err(error) => return page_failure(&state, &session, &error),
    };
    match ctx.get_backend(&name).await {
        Ok(view) => page_response(render_backend_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Backends),
            FormEnv::new(&state.base_url, &providers),
            &view,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/config/backends - create a backend
async fn handle_backend_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(name) = text(&pairs, "name") else {
        return error_response(&AdminError::Invalid(String::from("the name is required")));
    };
    let base = BackendConfig {
        name,
        ..BackendConfig::default()
    };
    let input = match backend_input_of(base, &pairs) {
        Ok(input) => input,
        Err(error) => return error_response(&error),
    };
    match ctx.create_backend(input).await {
        Ok(view) => redirect(&format!("/ui/admin/config/backends/{}", view.config.name)),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/backends/{name}/update
async fn handle_backend_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let stored = match ctx.get_backend(&name).await {
        Ok(view) => view,
        Err(error) => return action_error(&error),
    };
    let input = match backend_input_of(stored.config, &pairs) {
        Ok(input) => input,
        Err(error) => return error_response(&error),
    };
    let providers = match ctx.provider_ids().await {
        Ok(providers) => providers,
        Err(error) => return action_error(&error),
    };
    match ctx.update_backend(&name, input).await {
        Ok(view) => fragment(&render_backend_edit(
            &view,
            page_ctx(&ctx, Area::Backends),
            FormEnv::new(&state.base_url, &providers),
            true,
        )),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/backends/{name}/delete
async fn handle_backend_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.delete_backend(&name).await {
        Ok(()) => redirect("/ui/admin/config/backends"),
        Err(error) => action_error(&error),
    }
}

// -- toolsets -----------------------------------------------------------------

/// Handle GET /ui/admin/config/toolsets
async fn handle_toolsets(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.list_toolsets().await {
        Ok(list) => page_response(render_toolsets_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Backends),
            &list,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle GET /ui/admin/config/toolsets/{name}
async fn handle_toolset(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.get_toolset(&name).await {
        Ok(view) => page_response(render_toolset_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Backends),
            &view,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/config/toolsets - create a toolset
async fn handle_toolset_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(name) = text(&pairs, "name") else {
        return error_response(&AdminError::Invalid(String::from("the name is required")));
    };
    match ctx.create_toolset(toolset_of(name, &pairs)).await {
        Ok(view) => redirect(&format!("/ui/admin/config/toolsets/{}", view.config.name)),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/toolsets/{name}/update
async fn handle_toolset_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx
        .update_toolset(&name, toolset_of(name.clone(), &pairs))
        .await
    {
        Ok(view) => fragment(&render_toolset_edit(
            &view,
            page_ctx(&ctx, Area::Backends),
            true,
        )),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/toolsets/{name}/delete
async fn handle_toolset_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(name): Path<String>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.delete_toolset(&name).await {
        Ok(()) => redirect("/ui/admin/config/toolsets"),
        Err(error) => action_error(&error),
    }
}

// -- OIDC providers -----------------------------------------------------------

/// Handle GET /ui/admin/config/oidc-providers
async fn handle_providers(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.list_providers().await {
        Ok(list) => page_response(render_providers_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Gateway),
            &list,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle GET /ui/admin/config/oidc-providers/{id}
async fn handle_provider(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<String>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.get_provider(&id).await {
        Ok(view) => page_response(render_provider_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Gateway),
            &view,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/config/oidc-providers - create a provider
async fn handle_provider_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let Some(id) = text(&pairs, "id") else {
        return error_response(&AdminError::Invalid(String::from("the id is required")));
    };
    let mut config = OidcProviderConfig {
        id,
        ..OidcProviderConfig::default()
    };
    let position = match apply_provider_form(&mut config, &pairs) {
        Ok(position) => position,
        Err(error) => return error_response(&error),
    };
    let input = ProviderInput {
        config,
        position,
        client_secret: secret_of(&pairs, "client_secret", "clear_client_secret"),
    };
    match ctx.create_provider(input).await {
        Ok(view) => redirect(&format!(
            "/ui/admin/config/oidc-providers/{}",
            view.config.id
        )),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/oidc-providers/{id}/update
async fn handle_provider_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<String>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let stored = match ctx.get_provider(&id).await {
        Ok(view) => view,
        Err(error) => return action_error(&error),
    };
    let mut config = stored.config;
    let position = match apply_provider_form(&mut config, &pairs) {
        Ok(position) => position,
        Err(error) => return error_response(&error),
    };
    let input = ProviderInput {
        config,
        position,
        client_secret: secret_of(&pairs, "client_secret", "clear_client_secret"),
    };
    match ctx.update_provider(&id, input).await {
        Ok(view) => fragment(&render_provider_edit(
            &view,
            page_ctx(&ctx, Area::Gateway),
            true,
        )),
        Err(error) => action_error(&error),
    }
}

/// Handle POST /ui/actions/admin/config/oidc-providers/{id}/delete
async fn handle_provider_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<String>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.delete_provider(&id).await {
        Ok(()) => redirect("/ui/admin/config/oidc-providers"),
        Err(error) => action_error(&error),
    }
}

// -- settings -----------------------------------------------------------------

/// Handle GET /ui/admin/config/settings
async fn handle_settings(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match ctx.settings().await {
        Ok(settings) => page_response(render_settings_page(
            &state,
            &session,
            page_ctx(&ctx, Area::Gateway),
            &settings,
        )),
        Err(error) => page_failure(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/admin/config/settings - save the settings
async fn handle_settings_save(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (_, ctx) = match ctx_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let mut settings = match ctx.settings().await {
        Ok(settings) => settings,
        Err(error) => return action_error(&error),
    };
    if let Err(error) = apply_settings_form(&mut settings, &pairs) {
        return error_response(&error);
    }
    match ctx.put_settings(settings).await {
        Ok(saved) => fragment(&render_settings_section(
            &saved,
            page_ctx(&ctx, Area::Gateway),
            true,
        )),
        Err(error) => action_error(&error),
    }
}

/// The fields of the settings form onto `settings`; an empty number keeps the
/// current value
fn apply_settings_form(
    settings: &mut GatewaySettings,
    pairs: &[(String, String)],
) -> Result<(), AdminError> {
    if let Some(value) = number(pairs, "rate_limit_per_minute", "the rate limit")? {
        settings.rate_limit_per_minute = value;
    }
    if let Some(value) = number(pairs, "idle_timeout_secs", "the idle timeout")? {
        settings.idle_timeout_secs = value;
    }
    settings.allowed_hosts = lines_of(pairs, "allowed_hosts");
    let personal = &mut settings.personal_backends;
    personal.enabled = flag(pairs, "personal_enabled");
    if let Some(value) = number(pairs, "personal_max_per_user", "the personal backend limit")? {
        personal.max_per_user = value;
    }
    if let Some(value) = number(pairs, "personal_max_calls_per_minute", "the call limit")? {
        personal.max_calls_per_minute = value;
    }
    if let Some(value) = number(pairs, "personal_max_instances", "the connection limit")? {
        personal.max_instances = value;
    }
    personal.egress_allow = lines_of(pairs, "personal_egress_allow");
    personal.egress_deny = lines_of(pairs, "personal_egress_deny");
    Ok(())
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
    fn header_rows_keep_on_empty_and_drop_on_remove() {
        let form = pairs(&[
            ("header_name", "X-Keep"),
            ("header_value", ""),
            ("header_name", "X-Gone"),
            ("header_value", ""),
            ("header_name", "X-New"),
            ("header_value", "v"),
            ("header_name", ""),
            ("header_value", ""),
            ("header_remove", "X-Gone"),
        ]);
        let rows = secret_rows_of(&form, "header", "header").unwrap();
        assert_eq!(
            rows,
            BTreeMap::from([
                ("X-Keep".to_owned(), None),
                ("X-New".to_owned(), Some("v".to_owned())),
            ])
        );
    }

    #[test]
    fn a_header_value_without_a_name_is_refused() {
        let form = pairs(&[("header_name", ""), ("header_value", "v")]);
        assert!(secret_rows_of(&form, "header", "header").is_err());
    }

    #[test]
    fn a_secret_input_keeps_unless_typed_or_cleared() {
        let typed = pairs(&[("auth_token", "tok")]);
        assert_eq!(
            secret_of(&typed, "auth_token", "clear_auth_token"),
            Some("tok".to_owned())
        );
        let empty = pairs(&[("auth_token", "")]);
        assert_eq!(secret_of(&empty, "auth_token", "clear_auth_token"), None);
        let cleared = pairs(&[("auth_token", ""), ("clear_auth_token", "true")]);
        assert_eq!(
            secret_of(&cleared, "auth_token", "clear_auth_token"),
            Some(String::new())
        );
    }

    fn oauth_form() -> FormPairs {
        pairs(&[
            ("transport", "http"),
            ("url", "http://localhost:9000/mcp"),
            ("credential_mode", "oauth"),
            ("oauth_client_id", "axon-client"),
            ("oauth_client_secret", ""),
            ("oauth_scopes", "read\n\n write \n"),
        ])
    }

    #[test]
    fn an_oauth_form_builds_the_static_client_and_keeps_the_secret() {
        let stored = BackendConfig {
            name: "wiki".to_owned(),
            passthrough: Some(PassthroughConfig {
                grant: PassthroughGrant::TokenExchange,
                provider: "pocket".to_owned(),
                audience: None,
                scope: None,
                resource: None,
                assertion_scope: None,
            }),
            ..BackendConfig::default()
        };
        let input = backend_input_of(stored, &oauth_form()).unwrap();
        assert_eq!(input.config.credential_mode, CredentialMode::OAuth);
        let oauth = input.config.oauth.unwrap();
        assert_eq!(oauth.client_id, "axon-client");
        assert_eq!(oauth.scopes, ["read", "write"]);
        assert!(input.config.passthrough.is_none());
        // Empty keeps the stored secret, a typed one sets it, "clear" clears it
        assert_eq!(input.oauth_client_secret, None);
        let mut typed = oauth_form();
        typed.retain(|(key, _)| key != "oauth_client_secret");
        typed.push(("oauth_client_secret".to_owned(), "shh".to_owned()));
        let input = backend_input_of(BackendConfig::default(), &typed).unwrap();
        assert_eq!(input.oauth_client_secret.as_deref(), Some("shh"));
        let mut cleared = oauth_form();
        cleared.push(("clear_oauth_secret".to_owned(), "true".to_owned()));
        let input = backend_input_of(BackendConfig::default(), &cleared).unwrap();
        assert_eq!(input.oauth_client_secret, Some(String::new()));
    }

    #[test]
    fn an_oauth_form_without_a_client_registers_dynamically() {
        let form = pairs(&[("credential_mode", "oauth"), ("oauth_client_id", "")]);
        let input = backend_input_of(BackendConfig::default(), &form).unwrap();
        assert_eq!(input.config.credential_mode, CredentialMode::OAuth);
        assert!(input.config.oauth.is_none());
        let scoped = pairs(&[("credential_mode", "oauth"), ("oauth_scopes", "read")]);
        assert!(backend_input_of(BackendConfig::default(), &scoped).is_err());
    }

    #[test]
    fn a_per_user_form_builds_the_credential_fields() {
        let form = pairs(&[
            ("credential_mode", "per_user"),
            ("credential_name", "token"),
            ("credential_label", "API token"),
            ("credential_header", "Authorization"),
            ("credential_prefix", "Bearer "),
            ("credential_name", ""),
            ("credential_label", ""),
            ("credential_header", ""),
            ("credential_prefix", ""),
        ]);
        let stored = BackendConfig {
            oauth: Some(UpstreamOAuthConfig {
                client_id: "old".to_owned(),
                client_secret_env: None,
                client_secret: None,
                scopes: Vec::new(),
            }),
            ..BackendConfig::default()
        };
        let input = backend_input_of(stored, &form).unwrap();
        assert_eq!(input.config.credential_mode, CredentialMode::PerUser);
        assert_eq!(
            input.config.credential_fields,
            [CredentialField {
                name: "token".to_owned(),
                label: Some("API token".to_owned()),
                header: "Authorization".to_owned(),
                prefix: Some("Bearer ".to_owned()),
            }]
        );
        assert!(input.config.oauth.is_none());
        let headerless = pairs(&[
            ("credential_mode", "per_user"),
            ("credential_name", "token"),
            ("credential_label", ""),
            ("credential_header", ""),
            ("credential_prefix", ""),
        ]);
        assert!(backend_input_of(BackendConfig::default(), &headerless).is_err());
    }

    #[test]
    fn a_passthrough_form_builds_the_exchange() {
        let form = pairs(&[
            ("credential_mode", "passthrough"),
            ("passthrough_grant", "entra_obo"),
            ("passthrough_provider", "pocket"),
            ("passthrough_audience", ""),
            ("passthrough_scope", "api://wiki/.default"),
            ("passthrough_resource", ""),
            ("passthrough_assertion_scope", ""),
        ]);
        let input = backend_input_of(BackendConfig::default(), &form).unwrap();
        assert_eq!(input.config.credential_mode, CredentialMode::Passthrough);
        let passthrough = input.config.passthrough.unwrap();
        assert_eq!(passthrough.grant, PassthroughGrant::EntraObo);
        assert_eq!(passthrough.provider, "pocket");
        assert_eq!(passthrough.scope.as_deref(), Some("api://wiki/.default"));
        assert_eq!(passthrough.audience, None);
        let no_provider = pairs(&[("credential_mode", "passthrough")]);
        assert!(backend_input_of(BackendConfig::default(), &no_provider).is_err());
    }

    #[test]
    fn a_shared_form_drops_the_other_sections() {
        let stored = BackendConfig {
            credential_mode: CredentialMode::PerUser,
            credential_fields: vec![CredentialField {
                name: "token".to_owned(),
                label: None,
                header: "Authorization".to_owned(),
                prefix: None,
            }],
            ..BackendConfig::default()
        };
        let form = pairs(&[("credential_mode", "shared")]);
        let input = backend_input_of(stored, &form).unwrap();
        assert_eq!(input.config.credential_mode, CredentialMode::Shared);
        assert_eq!(input.config.credential_fields.len(), 0);
        let unknown = pairs(&[("credential_mode", "magic")]);
        assert!(backend_input_of(BackendConfig::default(), &unknown).is_err());
    }

    #[test]
    fn the_backend_form_keeps_the_fields_it_does_not_have() {
        let mut config = BackendConfig {
            name: "wiki".to_owned(),
            credential_mode: CredentialMode::PerUser,
            ..BackendConfig::default()
        };
        let form = pairs(&[
            ("transport", "http"),
            ("url", " http://localhost:9000/mcp "),
            ("enabled", "true"),
            ("timeout_secs", "45"),
        ]);
        apply_backend_form(&mut config, &form).unwrap();
        assert_eq!(config.credential_mode, CredentialMode::PerUser);
        assert_eq!(config.url.as_deref(), Some("http://localhost:9000/mcp"));
        assert_eq!(config.timeout_secs, 45);
        assert!(config.enabled);
    }
}
