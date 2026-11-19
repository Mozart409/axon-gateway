//! The page shell of the dashboard: grouped sidebar, top bar with the theme
//! picker, and the theme cookie.
//!
//! Every signed-in page is rendered through [`render_shell`]. The chosen theme
//! lives in the `axon_theme` cookie; [`theme_middleware`] reads it for each
//! request and [`current_theme`] hands it to the page functions without
//! changing every handler.

use axum::Form;
use axum::extract::Request;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use super::views::{build_fingerprint, csrf_hx_headers};
use super::{AppState, session};
use crate::policy::Permission;
use crate::rbac::resolve;
use crate::store::SessionUser;

/// The cookie that holds the theme slug.
const THEME_COOKIE: &str = "axon_theme";
/// One year, in seconds.
const THEME_MAX_AGE_SECS: i64 = 365 * 24 * 60 * 60;
/// htmx under the page CSP: no injected indicator `<style>`, no `eval`. Action
/// errors answer 4xx/5xx with a flash fragment, which htmx drops unless told
/// to swap it.
const HTMX_CONFIG: &str = r#"{"includeIndicatorStyles":false,"allowEval":false,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"[45]..","swap":true,"error":true}]}"#;
/// The font the stylesheet needs first; preloaded so text does not reflow.
const PRELOAD_FONT: &str = "/static/fonts/Geist-Variable.woff2";

/// A colour theme. The slugs are the `data-theme` values in `styles/input.css`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Theme {
    /// Light or dark, following the browser's `prefers-color-scheme`
    #[default]
    System,
    Light,
    Dark,
    KanagawaWave,
    KanagawaDragon,
    KanagawaLotus,
    Nord,
    NordLight,
    Dracula,
    Alucard,
    CatppuccinLatte,
    CatppuccinMocha,
    GruvboxDark,
    GruvboxLight,
    TokyoNight,
}

impl Theme {
    /// Every theme, in the order the picker lists them.
    pub(super) const ALL: [Theme; 15] = [
        Theme::System,
        Theme::Light,
        Theme::Dark,
        Theme::KanagawaWave,
        Theme::KanagawaDragon,
        Theme::KanagawaLotus,
        Theme::Nord,
        Theme::NordLight,
        Theme::Dracula,
        Theme::Alucard,
        Theme::CatppuccinLatte,
        Theme::CatppuccinMocha,
        Theme::GruvboxDark,
        Theme::GruvboxLight,
        Theme::TokyoNight,
    ];

    /// The `data-theme` value and cookie value.
    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
            Self::KanagawaWave => "kanagawa-wave",
            Self::KanagawaDragon => "kanagawa-dragon",
            Self::KanagawaLotus => "kanagawa-lotus",
            Self::Nord => "nord",
            Self::NordLight => "nord-light",
            Self::Dracula => "dracula",
            Self::Alucard => "alucard",
            Self::CatppuccinLatte => "catppuccin-latte",
            Self::CatppuccinMocha => "catppuccin-mocha",
            Self::GruvboxDark => "gruvbox-dark",
            Self::GruvboxLight => "gruvbox-light",
            Self::TokyoNight => "tokyo-night",
        }
    }

    /// The name the picker shows.
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::System => "System",
            Self::Light => "Light",
            Self::Dark => "Dark",
            Self::KanagawaWave => "Kanagawa Wave",
            Self::KanagawaDragon => "Kanagawa Dragon",
            Self::KanagawaLotus => "Kanagawa Lotus",
            Self::Nord => "Nord",
            Self::NordLight => "Nord Light",
            Self::Dracula => "Dracula",
            Self::Alucard => "Alucard",
            Self::CatppuccinLatte => "Catppuccin Latte",
            Self::CatppuccinMocha => "Catppuccin Mocha",
            Self::GruvboxDark => "Gruvbox Dark",
            Self::GruvboxLight => "Gruvbox Light",
            Self::TokyoNight => "Tokyo Night",
        }
    }

    /// The theme with this slug, if there is one.
    pub(super) fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|theme| theme.slug() == slug)
    }
}

tokio::task_local! {
    /// The theme of the request being handled.
    static THEME: Theme;
}

/// The theme of the current request: the cookie's, or [`Theme::System`] when
/// there is no cookie or the code runs outside a request.
pub(super) fn current_theme() -> Theme {
    THEME.try_with(|theme| *theme).unwrap_or_default()
}

/// Run the request with the theme from its cookie in [`current_theme`].
pub(super) async fn theme_middleware(request: Request, next: Next) -> Response {
    let theme = CookieJar::from_headers(request.headers())
        .get(THEME_COOKIE)
        .and_then(|cookie| Theme::from_slug(cookie.value()))
        .unwrap_or_default();
    THEME.scope(theme, next.run(request)).await
}

/// Form of `POST /ui/actions/theme`.
#[derive(Deserialize)]
pub(super) struct ThemeForm {
    theme: String,
}

/// `POST /ui/actions/theme`: remember the theme in a cookie and make htmx
/// reload the page. An unknown slug answers 400.
pub(super) async fn handle_set_theme(
    jar: CookieJar,
    form: Result<Form<ThemeForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return (StatusCode::BAD_REQUEST, "invalid form\n").into_response();
    };
    let Some(theme) = Theme::from_slug(&form.theme) else {
        return (StatusCode::BAD_REQUEST, "unknown theme\n").into_response();
    };
    let cookie = session::host_cookie(THEME_COOKIE, theme.slug().to_owned(), THEME_MAX_AGE_SECS);
    (
        StatusCode::NO_CONTENT,
        jar.add(cookie),
        [("HX-Refresh", "true")],
    )
        .into_response()
}

/// The icon sprite, inlined once per page: Chromium does not render a `<use>`
/// that points into an external SVG file.
const ICON_SPRITE: &str = include_str!("../../static/icons.svg");

/// An icon from the inlined sprite (`static/icons.svg`); `name` is the Lucide name.
pub(super) fn icon(name: &str) -> Markup {
    html! {
        svg class="icon" aria-hidden="true" {
            use href=(format!("#{name}")) {}
        }
    }
}

/// The sidebar entry a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Nav {
    /// No entry: the page belongs to none of them
    None,
    Overview,
    MyTools,
    Usage,
    Tokens,
    ConnectedApps,
    Toolsets,
    MyServers,
    Catalog,
    /// Admin overview: groups, grants and role bindings
    Admin,
    AdminRoles,
    AdminUsers,
    AdminServiceAccounts,
    AdminScim,
    AdminPersonalBackends,
    AdminAudit,
    AdminToolCalls,
    AdminUsage,
    AdminAuditSettings,
    Config,
}

/// One sidebar entry.
fn nav_item(active: Nav, nav: Nav, href: &str, icon_name: &str, label: &str) -> Markup {
    html! {
        a class="nav-item" href=(href) aria-current=[(active == nav).then_some("page")] {
            (icon(icon_name))
            span { (label) }
        }
    }
}

/// What the sidebar of one user shows.
#[allow(
    clippy::struct_excessive_bools,
    reason = "one flag per permission the sidebar gates"
)]
struct NavAccess {
    /// "My MCP servers" and the catalog
    personal: bool,
    /// The admin overview and the roles page, which list groups, grants or
    /// bindings (`groups.manage`, `roles.manage` or `audit.read`)
    listing: bool,
    /// The users page (`users.manage` or `groups.manage`)
    manage_users: bool,
    /// Half of the SCIM page's `users.manage` and `groups.manage`
    manage_groups: bool,
    /// The service accounts page (`service_accounts.manage`)
    manage_service_accounts: bool,
    /// The audit pages (`audit.read`)
    read_audit: bool,
    /// The admin's view of everybody's personal servers
    personal_admin: bool,
    /// The first configuration page the user may open
    config_href: Option<&'static str>,
}

/// The brand, the grouped links and the build fingerprint. It renders twice,
/// as the sidebar and as the drawer of small screens.
fn nav_contents(state: &AppState, access: &NavAccess, active: Nav, in_drawer: bool) -> Markup {
    html! {
        div class="brand" {
            span class="brand-mark" { (icon("axon")) }
            "Axon"
            @if in_drawer {
                button
                    class="btn icon ghost nav-close"
                    type="button"
                    popovertarget="nav-drawer"
                    popovertargetaction="hide"
                    aria-label="Close menu"
                {
                    (icon("x"))
                }
            }
        }
        div class="nav-label" { "Workspace" }
        (nav_item(active, Nav::Overview, "/ui", "layout-dashboard", "Overview"))
        (nav_item(active, Nav::MyTools, "/ui/tools", "wrench", "My tools"))
        (nav_item(active, Nav::Usage, "/ui/me/usage", "activity", "Usage"))
        div class="nav-label" { "Access" }
        (nav_item(active, Nav::Tokens, "/ui/tokens", "key-round", "Tokens"))
        (nav_item(active, Nav::ConnectedApps, "/ui/me/apps", "app-window", "Connected apps"))
        (nav_item(active, Nav::Toolsets, "/ui/toolsets", "layers", "Toolsets"))
        @if access.personal {
            div class="nav-label" { "Servers" }
            (nav_item(active, Nav::MyServers, "/ui/me/backends", "server", "My MCP servers"))
            (nav_item(active, Nav::Catalog, "/ui/catalog", "library", "Catalog"))
        }
        @if access.listing
            || access.manage_users
            || access.manage_groups
            || access.manage_service_accounts
            || access.personal_admin
        {
            div class="nav-label" { "Admin" }
            @if access.listing {
                (nav_item(active, Nav::Admin, "/ui/admin", "shield", "Admin"))
                (nav_item(active, Nav::AdminRoles, "/ui/admin/roles", "badge-check", "Roles"))
            }
            @if access.manage_users || access.manage_groups {
                (nav_item(active, Nav::AdminUsers, "/ui/admin/users", "users", "Users"))
            }
            @if access.manage_service_accounts {
                (nav_item(
                    active,
                    Nav::AdminServiceAccounts,
                    "/ui/admin/service-accounts",
                    "bot",
                    "Service accounts",
                ))
            }
            @if access.manage_users && access.manage_groups {
                (nav_item(
                    active,
                    Nav::AdminScim,
                    "/ui/admin/scim",
                    "refresh-cw",
                    "SCIM provisioning",
                ))
            }
            @if access.personal_admin {
                (nav_item(
                    active,
                    Nav::AdminPersonalBackends,
                    "/ui/admin/personal-backends",
                    "plug",
                    "Personal MCP servers",
                ))
            }
        }
        @if access.read_audit {
            div class="nav-label" { "Audit" }
            (nav_item(active, Nav::AdminAudit, "/ui/admin/audit", "scroll-text", "Audit log"))
            (nav_item(
                active,
                Nav::AdminToolCalls,
                "/ui/admin/tool-calls",
                "list",
                "Tool calls",
            ))
            (nav_item(active, Nav::AdminUsage, "/ui/admin/usage", "activity", "Usage"))
            (nav_item(
                active,
                Nav::AdminAuditSettings,
                "/ui/admin/audit-settings",
                "settings",
                "Audit settings",
            ))
        }
        @if let Some(href) = access.config_href {
            div class="nav-label" { "Config" }
            (nav_item(active, Nav::Config, href, "sliders-horizontal", "Config"))
        }
        div class="side-foot" {
            span class="mono muted" { (build_fingerprint(state)) }
        }
    }
}

/// The initials the avatar shows.
fn initials(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

/// The whole document of a signed-in page: head, sidebar, top bar and `content`.
#[allow(clippy::too_many_lines)]
pub(super) fn render_shell(
    state: &AppState,
    user: &SessionUser,
    title: &str,
    active: Nav,
    content: &Markup,
) -> Markup {
    let hx_headers = csrf_hx_headers(user);
    let theme = current_theme();
    let (groups, permissions) = resolve(&state.policy.current(), user);
    let manages_backends =
        permissions.has(Permission::BackendsView) || permissions.has(Permission::BackendsManage);
    // The same rules as the configuration pages' own sub-navigation
    let config_href = if state.store.is_none() || state.db_config.is_none() {
        None
    } else if manages_backends {
        Some("/ui/admin/config/backends")
    } else if permissions.has(Permission::GatewayAdmin) {
        Some("/ui/admin/config/oidc-providers")
    } else {
        None
    };
    // Each entry mirrors the permission its page's handler requires (rbac and
    // the page modules), so nothing is listed the user may not open.
    let manage_users = permissions.has(Permission::UsersManage);
    let manage_groups = permissions.has(Permission::GroupsManage);
    let access = NavAccess {
        personal: state.personal.is_some(),
        listing: manage_groups
            || permissions.has(Permission::RolesManage)
            || permissions.has(Permission::AuditRead),
        manage_users,
        manage_groups,
        manage_service_accounts: permissions.has(Permission::ServiceAccountsManage),
        read_audit: permissions.has(Permission::AuditRead),
        personal_admin: manage_users && state.personal.is_some(),
        config_href,
    };
    let name = user
        .user
        .display_name
        .as_deref()
        .or(user.user.email.as_deref())
        .unwrap_or(&user.user.subject);

    html! {
        (DOCTYPE)
        html lang="en" data-theme=(theme.slug()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " - Axon Gateway" }
                link rel="icon" type="image/svg+xml" href="/favicon.svg";
                meta name="csrf-token" content=(user.csrf_token);
                meta name="htmx-config" content=(HTMX_CONFIG);
                script src="/static/htmx-2.0.4.min.js" defer {};
                script src="/static/htmx-ext-sse-2.2.2.js" defer {};
                link rel="preload" href=(PRELOAD_FONT) as="font" type="font/woff2" crossorigin;
                link rel="stylesheet" href="/styles/output.css?v=2";
            }
            body class="axon" hx-headers=(hx_headers) {
                (PreEscaped(ICON_SPRITE))
                div class="shell" {
                    nav class="side" aria-label="Main" {
                        (nav_contents(state, &access, active, false))
                    }
                    div class="main" {
                        header class="top" {
                            button
                                class="btn icon ghost menu-btn"
                                type="button"
                                popovertarget="nav-drawer"
                                aria-label="Open menu"
                            {
                                (icon("menu"))
                            }
                            h1 class="crumb" { (title) }
                            div class="spacer" {}
                            label class="theme-pick muted" {
                                (icon("palette"))
                                span class="hide-sm" { "Theme" }
                                select
                                    class="input sm"
                                    name="theme"
                                    aria-label="Theme"
                                    hx-post="/ui/actions/theme"
                                    hx-trigger="change"
                                    hx-swap="none"
                                {
                                    @for option in Theme::ALL {
                                        option value=(option.slug()) selected[option == theme] {
                                            (option.label())
                                        }
                                    }
                                }
                            }
                            div class="top-user" {
                                span class="avatar" aria-hidden="true" { (initials(name)) }
                                span class="hide-sm" { (name) }
                                @for group in &groups {
                                    span class="pill hide-sm" title="Group" { (group) }
                                }
                                @if permissions.is_admin() {
                                    span class="pill warn hide-sm" { "admin" }
                                }
                                form method="post" action="/auth/logout" {
                                    input type="hidden" name="csrf_token" value=(user.csrf_token);
                                    button class="btn sm ghost" type="submit" aria-label="Log out" {
                                        (icon("log-out"))
                                        span class="hide-sm" { "Log out" }
                                    }
                                }
                            }
                        }
                        main class="content" {
                            div class="page" { (content) }
                        }
                    }
                }
                div id="nav-drawer" class="nav-drawer" popover {
                    (nav_contents(state, &access, active, true))
                }
            }
        }
    }
}
