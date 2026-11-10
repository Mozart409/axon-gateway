//! HTML rendering (maud) for the toolsets page (`/ui/toolsets`): a user's own
//! toolsets, each a named set of tool globs and backends that a token can be pinned to.
//!
//! Like `tokens_views`, these are pure view functions and the section is also the
//! fragment every action answers with (`hx-target` the section's id,
//! `hx-swap="outerHTML"`).

use maud::{Markup, PreEscaped, html};

use super::AppState;
use super::admin_views::{
    BACK_LINK, BUTTON, BUTTON_DANGER, CARD, FAINT, FORM_ROW, HEADING, INPUT, LABEL, MUTED,
    render_flash_area, render_layout,
};
use crate::store::{SessionUser, Toolset};

const SECTION: &str = "#my-toolsets";
const CHECKBOX: &str = "flex items-center gap-2 text-sm text-slate-700 dark:text-slate-200";

/// Backend names to offer: the ones the user is granted, plus any the toolset already
/// lists (so that they can be unticked)
fn backend_choices<'a>(granted: &'a [String], toolset: Option<&'a Toolset>) -> Vec<&'a String> {
    let mut choices: Vec<&String> = granted.iter().collect();
    if let Some(toolset) = toolset {
        for backend in &toolset.backends {
            if !choices.contains(&backend) {
                choices.push(backend);
            }
        }
    }
    choices
}

/// The fields of a toolset form, empty for a new one. The tool globs are one per line,
/// the backends checkboxes (the `backends` key repeats).
fn render_fields(toolset: Option<&Toolset>, granted: &[String]) -> Markup {
    let tools = toolset
        .map(|toolset| toolset.tools.join("\n"))
        .unwrap_or_default();
    let description = toolset
        .and_then(|toolset| toolset.description.as_deref())
        .unwrap_or_default();
    html! {
        label class=(LABEL) {
            "Name"
            input
                class=(INPUT)
                type="text"
                name="name"
                maxlength="64"
                pattern="[a-z0-9_\\-]+"
                placeholder="daily-ops"
                value=(toolset.map_or("", |toolset| toolset.name.as_str()))
                required;
        }
        label class=(LABEL) {
            "Description"
            input
                class=(format!("{INPUT} w-72"))
                type="text"
                name="description"
                maxlength="500"
                value=(description);
        }
        label class=(LABEL) {
            "Tool globs (one per line, none: no narrowing)"
            textarea class=(format!("{INPUT} w-72 font-mono")) name="tools" rows="4" placeholder="prom_*" {
                (tools)
            }
        }
        @let choices = backend_choices(granted, toolset);
        @if !choices.is_empty() {
            fieldset class=(LABEL) {
                "Backends (none ticked: all you may use)"
                @for backend in choices {
                    label class=(CHECKBOX) {
                        input
                            type="checkbox"
                            name="backends"
                            value=(backend)
                            checked[toolset.is_some_and(|toolset| toolset.backends.contains(backend))];
                        (backend)
                    }
                }
            }
        }
    }
}

/// What a toolset narrows to, one line for the heading
fn summary(toolset: &Toolset) -> String {
    format!(
        "{} tool glob(s), {} backend(s)",
        toolset.tools.len(),
        toolset.backends.len()
    )
}

/// One toolset: its edit form and delete button
fn render_toolset(toolset: &Toolset, granted: &[String]) -> Markup {
    let base = format!("/ui/actions/toolsets/{}", toolset.id);
    html! {
        div class="mt-6 border-t border-slate-200 pt-4 dark:border-slate-800" {
            div class="flex flex-wrap items-center gap-3" {
                h3 class="text-base font-semibold text-slate-900 dark:text-slate-100" {
                    (toolset.name)
                }
                span class=(FAINT) { (summary(toolset)) }
                button
                    class=(BUTTON_DANGER)
                    type="button"
                    hx-post=(format!("{base}/delete"))
                    hx-target=(SECTION)
                    hx-swap="outerHTML"
                    hx-confirm="Delete this toolset? A token that is still valid and pinned to it blocks this."
                {
                    "Delete"
                }
            }
            form class=(FORM_ROW) hx-post=(base) hx-target=(SECTION) hx-swap="outerHTML" {
                (render_fields(Some(toolset), granted))
                button class=(BUTTON) type="submit" { "Save" }
            }
        }
    }
}

/// A user's toolsets and the create form, the swap target of the toolset actions.
/// `backends` are the backends the user is granted.
pub(super) fn render_toolsets_section(toolsets: &[Toolset], backends: &[String]) -> Markup {
    html! {
        section id="my-toolsets" class=(CARD) {
            h2 class=(HEADING) { "Toolsets" }
            p class=(format!("mt-1 {MUTED}")) {
                "A toolset is a named set of tool globs and backends. It only narrows what you may "
                "use. Pin a token to one on the "
                a href="/ui/tokens" class="underline" { "tokens page" }
                ": the token then follows later edits of the toolset at once. "
                "Tool globs match the namespaced tool name, like prom_query*. "
                "A toolset also limits "
                code class="text-slate-900 dark:text-slate-100" { "/mcp/toolset/<name>" }
                " when you call it with your own token."
            }
            @if toolsets.is_empty() {
                p class=(format!("mt-4 text-sm {FAINT}")) { "No toolsets yet." }
            }
            @for toolset in toolsets {
                (render_toolset(toolset, backends))
            }
            div class="mt-6 border-t border-slate-200 pt-4 dark:border-slate-800" {
                h3 class="text-base font-semibold text-slate-900 dark:text-slate-100" { "New toolset" }
                form class=(FORM_ROW) hx-post="/ui/actions/toolsets" hx-target=(SECTION) hx-swap="outerHTML" {
                    (render_fields(None, backends))
                    button class=(BUTTON) type="submit" { "Create toolset" }
                }
            }
        }
    }
}

/// Toolsets page (`GET /ui/toolsets`).
pub(super) fn render_toolsets_page(
    state: &AppState,
    user: &SessionUser,
    toolsets: &[Toolset],
    backends: &[String],
) -> Markup {
    let content = html! {
        section class=(CARD) {
            a href="/ui" class=(BACK_LINK) { (PreEscaped("&larr;")) " Back to dashboard" }
            h1 class="mt-4 text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-100" {
                "Toolsets"
            }
        }
        (render_flash_area(false))
        (render_toolsets_section(toolsets, backends))
    };
    render_layout(state, user, "Toolsets", &content)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;

    fn toolset(name: &str, tools: &[&str], backends: &[&str]) -> Toolset {
        Toolset {
            id: Uuid::from_u128(9),
            owner_id: Uuid::nil(),
            name: name.to_owned(),
            description: Some(String::from("for <ops>")),
            tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            backends: backends
                .iter()
                .map(|backend| (*backend).to_owned())
                .collect(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn a_toolset_renders_its_form_and_actions() {
        let toolsets = [toolset("ops", &["prom_*", "loki_query"], &["prom"])];
        let granted = [String::from("prom"), String::from("loki")];
        let html = render_toolsets_section(&toolsets, &granted).into_string();

        assert!(html.contains("/ui/actions/toolsets/00000000-0000-0000-0000-000000000009\""));
        assert!(html.contains("/ui/actions/toolsets/00000000-0000-0000-0000-000000000009/delete"));
        assert!(html.contains("hx-post=\"/ui/actions/toolsets\""));
        assert!(html.contains("prom_*\nloki_query"));
        // the existing toolset ticks its backend, the create form ticks nothing
        assert_eq!(html.matches("checked").count(), 1);
        assert!(html.contains("for &lt;ops&gt;"));
    }

    #[test]
    fn a_backend_no_longer_granted_stays_untickable() {
        let toolsets = [toolset("ops", &[], &["gone"])];
        let html = render_toolsets_section(&toolsets, &[]).into_string();
        assert!(html.contains("value=\"gone\""));
    }

    #[test]
    fn no_toolsets_says_so() {
        let html = render_toolsets_section(&[], &[]).into_string();
        assert!(html.contains("No toolsets yet."));
        assert!(!html.contains("name=\"backends\""));
    }
}
