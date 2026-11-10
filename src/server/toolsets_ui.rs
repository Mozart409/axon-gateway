//! The toolsets page and its htmx actions: `/ui/toolsets` for a user's own toolsets.
//!
//! The routes sit behind the session guard (and, for actions, the CSRF and same-site
//! checks) because `tokens_ui` merges them into its own; outside multi-user mode every
//! one of them is a 404. What a user may do is decided by [`MyTokens`], the service the
//! JSON API uses too, so only the user's own toolsets can be read or changed. Errors and
//! the flash area work as on the token pages: a toolset that a valid token pins answers
//! a delete with 409.

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use uuid::Uuid;

use super::AppState;
use super::admin_ui::{AdminForm, error_response, fragment, page_error};
use super::tokens_ui::{granted_backends, tokens_for};
use super::toolsets_views::{render_toolsets_page, render_toolsets_section};
use crate::principal::TokenScope;
use crate::rbac::MyTokens;
use crate::store::SessionUser;

/// The GET pages, to merge into the routes behind the session guard.
pub(super) fn page_routes() -> Router<AppState> {
    Router::new().route("/ui/toolsets", get(handle_toolsets))
}

/// The POST actions, to merge into the routes behind the CSRF and same-site checks.
pub(super) fn action_routes() -> Router<AppState> {
    Router::new()
        .route("/ui/actions/toolsets", post(handle_toolset_create))
        .route("/ui/actions/toolsets/{id}", post(handle_toolset_update))
        .route(
            "/ui/actions/toolsets/{id}/delete",
            post(handle_toolset_delete),
        )
}

/// The toolset forms, read as pairs because `backends` repeats
type FormPairs = Vec<(String, String)>;

/// The fields of the create and edit forms
struct ToolsetForm {
    name: String,
    description: Option<String>,
    scope: TokenScope,
}

impl ToolsetForm {
    fn parse(pairs: &[(String, String)]) -> Self {
        let first = |key: &str| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        let backends = pairs
            .iter()
            .filter(|(name, value)| name == "backends" && !value.trim().is_empty())
            .map(|(_, value)| value.clone())
            .collect();
        Self {
            name: first("name").unwrap_or_default().to_owned(),
            description: first("description").map(str::to_owned),
            scope: TokenScope {
                backends,
                tools: split_lines(first("tools")),
            },
        }
    }
}

/// The non-empty, trimmed lines of a textarea.
fn split_lines(text: Option<&str>) -> Vec<String> {
    text.unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The answer to an action on `/ui/toolsets`: the toolsets section, or the error.
async fn toolsets_fragment(
    state: &AppState,
    session: &SessionUser,
    tokens: &MyTokens<'_>,
) -> Response {
    match tokens.toolsets().await {
        Ok(list) => {
            let backends = granted_backends(state, session);
            fragment(&render_toolsets_section(&list, &backends))
        }
        Err(error) => error_response(&error),
    }
}

/// Handle GET /ui/toolsets - the user's own toolsets
pub(super) async fn handle_toolsets(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    match tokens.toolsets().await {
        Ok(list) => {
            let backends = granted_backends(&state, &session);
            Html(render_toolsets_page(&state, &session, &list, &backends).into_string())
                .into_response()
        }
        Err(error) => page_error(&state, &session, &error),
    }
}

/// Handle POST /ui/actions/toolsets - create a toolset for the user
pub(super) async fn handle_toolset_create(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let form = ToolsetForm::parse(&pairs);
    match tokens
        .create_toolset(&form.name, form.description.as_deref(), &form.scope)
        .await
    {
        Ok(_) => toolsets_fragment(&state, &session, &tokens).await,
        Err(error) => error_response(&error),
    }
}

/// Handle POST /ui/actions/toolsets/{id} - replace a toolset of the user
pub(super) async fn handle_toolset_update(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
    AdminForm(pairs): AdminForm<FormPairs>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    let form = ToolsetForm::parse(&pairs);
    match tokens
        .update_toolset(id, &form.name, form.description.as_deref(), &form.scope)
        .await
    {
        Ok(_) => toolsets_fragment(&state, &session, &tokens).await,
        Err(error) => error_response(&error),
    }
}

/// Handle POST /ui/actions/toolsets/{id}/delete
pub(super) async fn handle_toolset_delete(
    State(state): State<AppState>,
    user: Option<Extension<SessionUser>>,
    Path(id): Path<Uuid>,
) -> Response {
    let (session, tokens) = match tokens_for(&state, user) {
        Ok(pair) => pair,
        Err(response) => return *response,
    };
    if let Err(error) = tokens.delete_toolset(id).await {
        return error_response(&error);
    }
    toolsets_fragment(&state, &session, &tokens).await
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
    fn lines_are_trimmed_and_blank_ones_dropped() {
        assert_eq!(
            split_lines(Some("prom_*\r\n  loki_query \n\n")),
            vec![String::from("prom_*"), String::from("loki_query")]
        );
        assert_eq!(split_lines(None), Vec::<String>::new());
    }

    #[test]
    fn the_form_reads_repeated_backends() {
        let form = ToolsetForm::parse(&pairs(&[
            ("name", "ops"),
            ("description", "daily"),
            ("tools", "prom_*\nloki_*"),
            ("backends", "prom"),
            ("backends", "loki"),
        ]));
        assert_eq!(form.name, "ops");
        assert_eq!(form.description.as_deref(), Some("daily"));
        assert_eq!(form.scope.tools.len(), 2);
        assert_eq!(
            form.scope.backends,
            vec![String::from("prom"), String::from("loki")]
        );
    }

    #[test]
    fn a_pinned_delete_is_a_conflict() {
        // the 409 for a pinned delete comes from the AdminError mapping
        assert!(matches!(
            crate::rbac::AdminError::from(crate::store::ToolsetError::Pinned),
            crate::rbac::AdminError::Conflict(_)
        ));
    }
}
