//! What one authenticated MCP caller may see and call
//!
//! Pure logic, no I/O. A [`PrincipalPolicy`] combines the caller's [`EffectivePolicy`]
//! (grants of its groups), its [`OptOuts`] and the [`TokenScope`] of the token it
//! presented. [`PrincipalPolicy::permits`] is the single check for `tools/list` and
//! `tools/call`, so a tool that is hidden behaves exactly like one that does not exist.

use crate::authz::tool_matches_pattern;
use crate::policy::{EffectivePolicy, OptOuts, ToolRef};

/// A token's narrowing of its owner's policy; empty lists mean "no narrowing"
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenScope {
    /// Backends the token may use, matched exactly
    pub backends: Vec<String>,
    /// Globs on the namespaced tool name, like `allowed_tools` of a legacy `[[tokens]]`
    pub tools: Vec<String>,
}

impl TokenScope {
    fn allows_backend(&self, backend: &str) -> bool {
        self.backends.is_empty() || self.backends.iter().any(|allowed| allowed == backend)
    }

    fn allows_tool(&self, namespaced: &str) -> bool {
        self.tools.is_empty()
            || self
                .tools
                .iter()
                .any(|pattern| tool_matches_pattern(namespaced, pattern))
    }
}

/// What one MCP caller may see and call
#[derive(Debug, Clone)]
pub struct PrincipalPolicy {
    label: String,
    effective: EffectivePolicy,
    opt_outs: OptOuts,
    scope: TokenScope,
}

impl PrincipalPolicy {
    /// `label` names the caller in logs and metrics
    pub fn new(
        label: String,
        effective: EffectivePolicy,
        opt_outs: OptOuts,
        scope: TokenScope,
    ) -> Self {
        Self {
            label,
            effective,
            opt_outs,
            scope,
        }
    }

    /// Owner email, or service account name and token name
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Backend usable at all: granted to the principal and inside the token scope
    pub fn backend_permitted(&self, backend: &str) -> bool {
        self.scope.allows_backend(backend)
            && self
                .effective
                .backends()
                .iter()
                .any(|granted| granted == backend)
    }

    /// Tool in `tools/list` and callable: visible (allowed, and mandatory or not opted
    /// out) and inside the token scope. `namespaced` is the gateway-facing name the
    /// scope globs match; `tool.name` is the original name grants match. A token only
    /// narrows, so a mandatory tool outside the scope is not permitted either.
    pub fn permits(&self, tool: ToolRef<'_>, namespaced: &str) -> bool {
        self.scope.allows_backend(tool.backend)
            && self.scope.allows_tool(namespaced)
            && self.effective.visible(tool, &self.opt_outs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{GrantConfig, IdpMapping, Policy, RbacConfig, RbacGroupConfig};

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn grant(group: &str, backend: &str, include: &[&str], mandatory: bool) -> GrantConfig {
        GrantConfig {
            group: group.to_string(),
            backend: backend.to_string(),
            include: strings(include),
            exclude: Vec::new(),
            read_only: false,
            mandatory,
        }
    }

    fn group(name: &str) -> RbacGroupConfig {
        RbacGroupConfig {
            name: name.to_string(),
            description: None,
            idp: Vec::<IdpMapping>::new(),
            service_accounts: Vec::new(),
        }
    }

    fn tool<'a>(backend: &'a str, name: &'a str) -> ToolRef<'a> {
        ToolRef {
            backend,
            name,
            read_only_hint: false,
        }
    }

    fn scope(backends: &[&str], tools: &[&str]) -> TokenScope {
        TokenScope {
            backends: strings(backends),
            tools: strings(tools),
        }
    }

    /// `it` gets all of `prom`, `dev` gets `get_*` of `forgejo` and a mandatory `whoami`
    fn config() -> RbacConfig {
        RbacConfig {
            groups: vec![group("it"), group("dev")],
            grants: vec![
                grant("it", "prom", &["*"], false),
                grant("dev", "forgejo", &["get_*"], false),
                grant("dev", "forgejo", &["whoami"], true),
            ],
            role_bindings: Vec::new(),
        }
    }

    fn principal(groups: &[&str], opt_outs: OptOuts, scope: TokenScope) -> PrincipalPolicy {
        let effective = Policy::from_config(&config()).effective(&strings(groups));
        PrincipalPolicy::new("alice@example.com".to_string(), effective, opt_outs, scope)
    }

    #[test]
    fn label_is_kept() {
        let policy = principal(&["it"], OptOuts::default(), TokenScope::default());
        assert_eq!(policy.label(), "alice@example.com");
    }

    #[test]
    fn two_groups_are_a_union() {
        let policy = principal(&["it", "dev"], OptOuts::default(), TokenScope::default());
        assert!(policy.permits(tool("prom", "query"), "prom_query"));
        assert!(policy.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
        assert!(!policy.permits(tool("forgejo", "delete_repo"), "forgejo_delete_repo"));
        let only_it = principal(&["it"], OptOuts::default(), TokenScope::default());
        assert!(!only_it.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
    }

    #[test]
    fn empty_policy_permits_nothing() {
        let policy = principal(&[], OptOuts::default(), TokenScope::default());
        assert!(!policy.permits(tool("prom", "query"), "prom_query"));
        assert!(!policy.backend_permitted("prom"));
    }

    #[test]
    fn opt_out_hides_a_tool_and_a_backend() {
        let opt_outs = OptOuts::new([
            ("prom".to_string(), Some("query".to_string())),
            ("forgejo".to_string(), None),
        ]);
        let policy = principal(&["it", "dev"], opt_outs, TokenScope::default());
        assert!(!policy.permits(tool("prom", "query"), "prom_query"));
        assert!(policy.permits(tool("prom", "series"), "prom_series"));
        assert!(!policy.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
    }

    #[test]
    fn mandatory_overrides_the_opt_out() {
        let opt_outs = OptOuts::new([("forgejo".to_string(), None)]);
        let policy = principal(&["dev"], opt_outs, TokenScope::default());
        assert!(policy.permits(tool("forgejo", "whoami"), "forgejo_whoami"));
        assert!(!policy.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
    }

    #[test]
    fn token_backend_scope_narrows() {
        let policy = principal(&["it", "dev"], OptOuts::default(), scope(&["prom"], &[]));
        assert!(policy.permits(tool("prom", "query"), "prom_query"));
        assert!(!policy.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
    }

    #[test]
    fn token_tool_glob_narrows_on_the_namespaced_name() {
        let policy = principal(
            &["it"],
            OptOuts::default(),
            scope(&[], &["prom_query*", "prom_labels"]),
        );
        assert!(policy.permits(tool("prom", "query"), "prom_query"));
        assert!(policy.permits(tool("prom", "query_range"), "prom_query_range"));
        assert!(policy.permits(tool("prom", "labels"), "prom_labels"));
        assert!(!policy.permits(tool("prom", "series"), "prom_series"));
        // the glob does not match the original name
        let by_original = principal(&["it"], OptOuts::default(), scope(&[], &["query"]));
        assert!(!by_original.permits(tool("prom", "query"), "prom_query"));
    }

    #[test]
    fn scope_never_widens_beyond_the_grants() {
        let policy = principal(
            &["it"],
            OptOuts::default(),
            scope(&["prom", "forgejo"], &["forgejo_*"]),
        );
        assert!(!policy.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
        assert!(!policy.backend_permitted("forgejo"));
        // both lists must agree: the backend is in scope, the tool glob is not
        assert!(!policy.permits(tool("prom", "query"), "prom_query"));
    }

    #[test]
    fn mandatory_tool_outside_the_token_scope_is_not_permitted() {
        let policy = principal(&["dev"], OptOuts::default(), scope(&["prom"], &[]));
        assert!(!policy.permits(tool("forgejo", "whoami"), "forgejo_whoami"));
        let by_glob = principal(&["dev"], OptOuts::default(), scope(&[], &["forgejo_get_*"]));
        assert!(!by_glob.permits(tool("forgejo", "whoami"), "forgejo_whoami"));
        assert!(by_glob.permits(tool("forgejo", "get_repo"), "forgejo_get_repo"));
    }

    #[test]
    fn backend_permitted_follows_grants_and_scope() {
        let policy = principal(&["it"], OptOuts::default(), TokenScope::default());
        assert!(policy.backend_permitted("prom"));
        assert!(!policy.backend_permitted("forgejo"));

        let scoped_out = principal(&["it", "dev"], OptOuts::default(), scope(&["forgejo"], &[]));
        assert!(!scoped_out.backend_permitted("prom"));
        assert!(scoped_out.backend_permitted("forgejo"));
    }
}
