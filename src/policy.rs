//! RBAC policy: groups, tool grants and the view layer
//!
//! Pure logic, no I/O. [`RbacConfig`] is the config layer; [`Policy`] compiles it
//! and maps a login to groups; [`EffectivePolicy`] is the allow-only union of the
//! grants of a user's groups and decides what a tool call may do. [`OptOuts`] is
//! the view layer: it only narrows what [`EffectivePolicy::visible`] shows and
//! never denies anything.
//!
//! Grant globs match the tool's original name as its backend reports it, not the
//! `{backend}_` namespaced name.

use std::collections::{BTreeSet, HashSet};

use serde::Deserialize;

use crate::authz::tool_matches_pattern;

/// Built-in group every logged-in user is a member of. It may not be declared in config.
pub const AUTHENTICATED_GROUP: &str = "authenticated";

fn all_tools() -> Vec<String> {
    vec!["*".to_string()]
}

/// The `[rbac]` config section
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RbacConfig {
    /// `[[rbac.groups]]`: groups declared in config
    #[serde(default)]
    pub groups: Vec<RbacGroupConfig>,
    /// `[[rbac.grants]]`: which group may use which backend's tools
    #[serde(default)]
    pub grants: Vec<GrantConfig>,
}

/// A group declared in config
#[derive(Debug, Clone, Deserialize)]
pub struct RbacGroupConfig {
    /// Unique name, `[a-z0-9_-]+`
    pub name: String,
    /// Free text shown next to the group
    #[serde(default)]
    pub description: Option<String>,
    /// Identity provider claim values whose holders are members of this group
    #[serde(default)]
    pub idp: Vec<IdpMapping>,
}

/// `(provider, claim value)` that puts a user into a group
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IdpMapping {
    /// `id` of an `[[auth.oidc]]` provider
    pub provider: String,
    /// Claim value, for example an Entra group object id
    pub value: String,
}

/// A grant of one backend's tools to a group
#[derive(Debug, Clone, Deserialize)]
pub struct GrantConfig {
    /// A declared group or [`AUTHENTICATED_GROUP`]
    pub group: String,
    /// Backend name
    pub backend: String,
    /// Tool globs (original tool names, see [`tool_matches_pattern`]); default `["*"]`
    #[serde(default = "all_tools")]
    pub include: Vec<String>,
    /// Tool globs removed from `include` within this grant
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Only tools annotated `readOnlyHint: true` pass
    #[serde(default)]
    pub read_only: bool,
    /// Users cannot opt out of tools this grant allows
    #[serde(default)]
    pub mandatory: bool,
}

fn valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

impl RbacConfig {
    /// Check the section against the configured backends and OIDC provider ids.
    ///
    /// # Errors
    ///
    /// Returns a message naming the first problem found.
    pub fn validate(&self, backends: &[&str], providers: &[&str]) -> Result<(), String> {
        let mut names: HashSet<&str> = HashSet::new();
        for group in &self.groups {
            if !valid_group_name(&group.name) {
                return Err(format!(
                    "rbac group name {:?} must match [a-z0-9_-]+",
                    group.name
                ));
            }
            if group.name == AUTHENTICATED_GROUP {
                return Err(format!(
                    "rbac group name {AUTHENTICATED_GROUP:?} is built in and cannot be declared"
                ));
            }
            if !names.insert(group.name.as_str()) {
                return Err(format!("duplicate rbac group {:?}", group.name));
            }
            for mapping in &group.idp {
                if !providers.contains(&mapping.provider.as_str()) {
                    return Err(format!(
                        "rbac group {:?} maps idp provider {:?}: no [[auth.oidc]] provider with id {}",
                        group.name, mapping.provider, mapping.provider
                    ));
                }
            }
        }
        for grant in &self.grants {
            if grant.group != AUTHENTICATED_GROUP && !names.contains(grant.group.as_str()) {
                return Err(format!(
                    "rbac grant for backend {:?} names unknown group {:?}",
                    grant.backend, grant.group
                ));
            }
            if !backends.contains(&grant.backend.as_str()) {
                return Err(format!(
                    "rbac grant for group {:?} names unknown backend {:?}",
                    grant.group, grant.backend
                ));
            }
            if grant.include.is_empty() {
                return Err(format!(
                    "rbac grant for group {:?} on backend {:?} has an empty include list",
                    grant.group, grant.backend
                ));
            }
        }
        Ok(())
    }
}

/// A tool as a grant sees it
#[derive(Debug, Clone, Copy)]
pub struct ToolRef<'a> {
    /// Backend name
    pub backend: &'a str,
    /// Original tool name, as the backend reports it
    pub name: &'a str,
    /// Whether the tool carries `readOnlyHint: true`
    pub read_only_hint: bool,
}

/// A grant, for display and explanations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSummary {
    /// Group the grant is for
    pub group: String,
    /// Backend the grant covers
    pub backend: String,
    /// Include globs
    pub include: Vec<String>,
    /// Exclude globs
    pub exclude: Vec<String>,
    /// Whether only read-only tools pass
    pub read_only: bool,
    /// Whether users cannot opt out
    pub mandatory: bool,
}

impl From<&GrantConfig> for GrantSummary {
    fn from(grant: &GrantConfig) -> Self {
        Self {
            group: grant.group.clone(),
            backend: grant.backend.clone(),
            include: grant.include.clone(),
            exclude: grant.exclude.clone(),
            read_only: grant.read_only,
            mandatory: grant.mandatory,
        }
    }
}

impl GrantSummary {
    /// Why this grant does not cover the tool, or `None` when it does.
    /// The caller has already checked the backend.
    fn miss(&self, tool: ToolRef<'_>) -> Option<Miss> {
        if !self
            .include
            .iter()
            .any(|pattern| tool_matches_pattern(tool.name, pattern))
        {
            return Some(Miss::NotIncluded);
        }
        if self
            .exclude
            .iter()
            .any(|pattern| tool_matches_pattern(tool.name, pattern))
        {
            return Some(Miss::Excluded);
        }
        if self.read_only && !tool.read_only_hint {
            return Some(Miss::NotReadOnly);
        }
        None
    }
}

/// Why a grant for the tool's backend does not allow the tool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// No include glob matches
    NotIncluded,
    /// An exclude glob matches
    Excluded,
    /// The grant is read-only and the tool has no `readOnlyHint`
    NotReadOnly,
}

/// Which grants allow a tool and why the others do not
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// Grants that allow the tool
    pub allowed_by: Vec<GrantSummary>,
    /// Grants for the tool's backend that do not, with the reason. Both lists empty
    /// means no grant for the user's groups covers this backend.
    pub missed: Vec<(GrantSummary, Miss)>,
}

#[derive(Debug, Clone)]
struct GroupDef {
    name: String,
    description: Option<String>,
    idp: Vec<IdpMapping>,
}

/// Compiled groups and grants
#[derive(Debug, Clone)]
pub struct Policy {
    groups: Vec<GroupDef>,
    grants: Vec<GrantSummary>,
}

impl Policy {
    /// Compile a (validated) config
    pub fn from_config(config: &RbacConfig) -> Self {
        Self {
            groups: config
                .groups
                .iter()
                .map(|group| GroupDef {
                    name: group.name.clone(),
                    description: group.description.clone(),
                    idp: group.idp.clone(),
                })
                .collect(),
            grants: config.grants.iter().map(GrantSummary::from).collect(),
        }
    }

    /// Groups of a login: [`AUTHENTICATED_GROUP`] plus every config group with an idp
    /// mapping for this provider whose value is among the claim values. Sorted, deduplicated.
    pub fn groups_for(&self, provider_id: &str, claim_values: &[String]) -> Vec<String> {
        let mut groups = BTreeSet::new();
        groups.insert(AUTHENTICATED_GROUP.to_string());
        for group in &self.groups {
            let member = group.idp.iter().any(|mapping| {
                mapping.provider == provider_id && claim_values.contains(&mapping.value)
            });
            if member {
                groups.insert(group.name.clone());
            }
        }
        groups.into_iter().collect()
    }

    /// The union of the grants of the given groups
    pub fn effective(&self, groups: &[String]) -> EffectivePolicy {
        EffectivePolicy {
            grants: self
                .grants
                .iter()
                .filter(|grant| groups.contains(&grant.group))
                .cloned()
                .collect(),
        }
    }

    /// Description of a declared group, for display
    pub fn group_description(&self, name: &str) -> Option<&str> {
        self.groups
            .iter()
            .find(|group| group.name == name)
            .and_then(|group| group.description.as_deref())
    }
}

/// What a set of groups may use. Allow-only: adding a grant never removes access.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    grants: Vec<GrantSummary>,
}

impl EffectivePolicy {
    fn for_backend<'a>(&'a self, backend: &'a str) -> impl Iterator<Item = &'a GrantSummary> {
        self.grants
            .iter()
            .filter(move |grant| grant.backend == backend)
    }

    /// Allowed iff some grant for the tool's backend includes it, does not exclude it and
    /// (if read-only) the tool has the hint. Denied by default.
    pub fn allows(&self, tool: ToolRef<'_>) -> bool {
        self.for_backend(tool.backend)
            .any(|grant| grant.miss(tool).is_none())
    }

    /// Whether at least one grant with `mandatory = true` allows the tool
    pub fn is_mandatory(&self, tool: ToolRef<'_>) -> bool {
        self.for_backend(tool.backend)
            .any(|grant| grant.mandatory && grant.miss(tool).is_none())
    }

    /// Which grants allow the tool and why the others for its backend do not
    pub fn explain(&self, tool: ToolRef<'_>) -> Explanation {
        let mut explanation = Explanation {
            allowed_by: Vec::new(),
            missed: Vec::new(),
        };
        for grant in self.for_backend(tool.backend) {
            match grant.miss(tool) {
                None => explanation.allowed_by.push(grant.clone()),
                Some(miss) => explanation.missed.push((grant.clone(), miss)),
            }
        }
        explanation
    }

    /// Backends with at least one grant, sorted and deduplicated
    pub fn backends(&self) -> Vec<String> {
        self.grants
            .iter()
            .map(|grant| grant.backend.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// View layer: allowed, and either mandatory or not opted out
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the gateway filters tools/list with it in Phase 3"
        )
    )]
    pub fn visible(&self, tool: ToolRef<'_>, opt_outs: &OptOuts) -> bool {
        self.allows(tool) && (self.is_mandatory(tool) || !opt_outs.hides(tool.backend, tool.name))
    }
}

/// A user's opt-outs: whole backends and single tools (original names). Not a deny:
/// it only narrows the view.
#[derive(Debug, Clone, Default)]
pub struct OptOuts {
    backends: HashSet<String>,
    tools: HashSet<(String, String)>,
}

impl OptOuts {
    /// Build from `(backend, tool)` entries; `(backend, None)` hides the whole backend
    pub fn new(entries: impl IntoIterator<Item = (String, Option<String>)>) -> Self {
        let mut opt_outs = Self::default();
        for (backend, tool) in entries {
            match tool {
                Some(tool) => {
                    opt_outs.tools.insert((backend, tool));
                }
                None => {
                    opt_outs.backends.insert(backend);
                }
            }
        }
        opt_outs
    }

    /// Whether the user hid this tool, directly or through its backend
    pub fn hides(&self, backend: &str, tool: &str) -> bool {
        self.hides_backend(backend)
            || self
                .tools
                .contains(&(backend.to_string(), tool.to_string()))
    }

    /// Whether the user hid the whole backend
    pub fn hides_backend(&self, backend: &str) -> bool {
        self.backends.contains(backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn grant(group: &str, backend: &str, include: &[&str], exclude: &[&str]) -> GrantConfig {
        GrantConfig {
            group: group.to_string(),
            backend: backend.to_string(),
            include: strings(include),
            exclude: strings(exclude),
            read_only: false,
            mandatory: false,
        }
    }

    fn group(name: &str, idp: &[(&str, &str)]) -> RbacGroupConfig {
        RbacGroupConfig {
            name: name.to_string(),
            description: None,
            idp: idp
                .iter()
                .map(|(provider, value)| IdpMapping {
                    provider: (*provider).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        }
    }

    fn tool<'a>(backend: &'a str, name: &'a str, read_only_hint: bool) -> ToolRef<'a> {
        ToolRef {
            backend,
            name,
            read_only_hint,
        }
    }

    fn effective(config: &RbacConfig, groups: &[&str]) -> EffectivePolicy {
        Policy::from_config(config).effective(&strings(groups))
    }

    #[test]
    fn union_across_two_groups() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("dev", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("dev", "forgejo", &["get_*"], &[]),
            ],
        };
        let both = effective(&config, &["it", "dev"]);
        assert!(both.allows(tool("prometheus", "query", false)));
        assert!(both.allows(tool("forgejo", "get_repo", false)));
        assert!(!both.allows(tool("forgejo", "delete_repo", false)));
        assert_eq!(both.backends(), strings(&["forgejo", "prometheus"]));

        let only_dev = effective(&config, &["dev"]);
        assert!(!only_dev.allows(tool("prometheus", "query", false)));
        assert!(only_dev.allows(tool("forgejo", "get_repo", false)));
        assert_eq!(only_dev.backends(), strings(&["forgejo"]));
    }

    #[test]
    fn denies_by_default() {
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![grant("it", "prometheus", &["*"], &[])],
        };
        let nobody = effective(&config, &[]);
        assert!(!nobody.allows(tool("prometheus", "query", true)));
        assert_eq!(nobody.backends(), Vec::<String>::new());

        let it = effective(&config, &["it"]);
        assert!(!it.allows(tool("unknown", "query", true)));

        let empty = effective(&RbacConfig::default(), &["authenticated", "it"]);
        assert!(!empty.allows(tool("prometheus", "query", true)));
    }

    #[test]
    fn exclude_beats_include_within_a_grant_but_union_can_still_allow() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("ops", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("ops", "prometheus", &["delete_series"], &[]),
            ],
        };
        let it = effective(&config, &["it"]);
        assert!(it.allows(tool("prometheus", "query", false)));
        assert!(!it.allows(tool("prometheus", "delete_series", false)));

        let both = effective(&config, &["it", "ops"]);
        assert!(both.allows(tool("prometheus", "delete_series", false)));
        assert!(!both.allows(tool("prometheus", "delete_rules", false)));
    }

    #[test]
    fn read_only_grant_passes_only_hinted_tools() {
        let mut read_only = grant("it", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only],
        };
        let it = effective(&config, &["it"]);
        assert!(it.allows(tool("prometheus", "query", true)));
        assert!(!it.allows(tool("prometheus", "query", false)));
    }

    #[test]
    fn read_only_grant_does_not_limit_another_grant() {
        let mut read_only = grant("authenticated", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only, grant("it", "prometheus", &["*"], &[])],
        };
        assert!(!effective(&config, &["authenticated"]).allows(tool(
            "prometheus",
            "reload",
            false
        )));
        assert!(effective(&config, &["authenticated", "it"]).allows(tool(
            "prometheus",
            "reload",
            false
        )));
    }

    #[test]
    fn mandatory_needs_an_allowing_mandatory_grant() {
        let mut mandatory = grant("authenticated", "hindsight", &["*"], &["forget"]);
        mandatory.mandatory = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![mandatory, grant("it", "hindsight", &["forget"], &[])],
        };
        let it = effective(&config, &["authenticated", "it"]);
        assert!(it.is_mandatory(tool("hindsight", "recall", false)));
        // allowed only through the non-mandatory grant
        assert!(it.allows(tool("hindsight", "forget", false)));
        assert!(!it.is_mandatory(tool("hindsight", "forget", false)));
        // not allowed at all
        assert!(!it.is_mandatory(tool("prometheus", "query", false)));
        assert!(!effective(&config, &["it"]).is_mandatory(tool("hindsight", "recall", false)));
    }

    #[test]
    fn explain_lists_allowed_by_and_misses() {
        let mut read_only = grant("ops", "prometheus", &["*"], &[]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("dev", &[]), group("ops", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &["delete_*"]),
                grant("dev", "prometheus", &["get_*"], &[]),
                read_only,
                grant("it", "forgejo", &["*"], &[]),
            ],
        };
        let policy = effective(&config, &["it", "dev", "ops"]);

        let explanation = policy.explain(tool("prometheus", "delete_series", false));
        assert_eq!(explanation.allowed_by, Vec::<GrantSummary>::new());
        let misses: Vec<(&str, Miss)> = explanation
            .missed
            .iter()
            .map(|(grant, miss)| (grant.group.as_str(), *miss))
            .collect();
        assert_eq!(
            misses,
            vec![
                ("it", Miss::Excluded),
                ("dev", Miss::NotIncluded),
                ("ops", Miss::NotReadOnly),
            ]
        );

        let explanation = policy.explain(tool("prometheus", "get_rules", true));
        let allowed: Vec<&str> = explanation
            .allowed_by
            .iter()
            .map(|grant| grant.group.as_str())
            .collect();
        assert_eq!(allowed, vec!["it", "dev", "ops"]);
        assert_eq!(explanation.missed, Vec::<(GrantSummary, Miss)>::new());
    }

    #[test]
    fn explain_is_empty_without_a_grant_for_the_backend() {
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![grant("it", "prometheus", &["*"], &[])],
        };
        let explanation = effective(&config, &["it"]).explain(tool("forgejo", "get_repo", true));
        assert_eq!(explanation.allowed_by, Vec::<GrantSummary>::new());
        assert_eq!(explanation.missed, Vec::<(GrantSummary, Miss)>::new());
    }

    #[test]
    fn explain_matches_allows() {
        let mut read_only = grant("it", "prometheus", &["get_*", "list_*"], &["list_secret"]);
        read_only.read_only = true;
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![read_only],
        };
        let it = effective(&config, &["it"]);
        for name in ["get_a", "list_b", "list_secret", "other"] {
            for hint in [true, false] {
                let tool = tool("prometheus", name, hint);
                assert_eq!(it.allows(tool), !it.explain(tool).allowed_by.is_empty());
            }
        }
    }

    fn login_config() -> RbacConfig {
        RbacConfig {
            groups: vec![
                group("it", &[("entra", "id-it"), ("entra", "id-admins")]),
                group("dev", &[("entra", "id-dev"), ("github", "id-it")]),
                group("manual", &[]),
            ],
            grants: Vec::new(),
        }
    }

    #[test]
    fn groups_for_always_contains_authenticated() {
        let policy = Policy::from_config(&login_config());
        assert_eq!(policy.groups_for("entra", &[]), strings(&["authenticated"]));
        assert_eq!(
            policy.groups_for("entra", &strings(&["unknown"])),
            strings(&["authenticated"])
        );
        assert_eq!(
            Policy::from_config(&RbacConfig::default()).groups_for("entra", &strings(&["x"])),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn groups_for_ignores_other_providers() {
        let policy = Policy::from_config(&login_config());
        // "id-it" is mapped for entra to "it" and for github to "dev"
        assert_eq!(
            policy.groups_for("entra", &strings(&["id-it"])),
            strings(&["authenticated", "it"])
        );
        assert_eq!(
            policy.groups_for("github", &strings(&["id-it"])),
            strings(&["authenticated", "dev"])
        );
        assert_eq!(
            policy.groups_for("other", &strings(&["id-it", "id-dev"])),
            strings(&["authenticated"])
        );
    }

    #[test]
    fn groups_for_handles_multiple_mappings_and_dedups() {
        let policy = Policy::from_config(&login_config());
        // two claim values map to "it": one entry only
        assert_eq!(
            policy.groups_for(
                "entra",
                &strings(&["id-it", "id-admins", "id-dev", "id-dev"])
            ),
            strings(&["authenticated", "dev", "it"])
        );
    }

    #[test]
    fn group_description_is_looked_up_by_name() {
        let mut it = group("it", &[]);
        it.description = Some("IT staff".to_string());
        let config = RbacConfig {
            groups: vec![it, group("dev", &[])],
            grants: Vec::new(),
        };
        let policy = Policy::from_config(&config);
        assert_eq!(policy.group_description("it"), Some("IT staff"));
        assert_eq!(policy.group_description("dev"), None);
        assert_eq!(policy.group_description("missing"), None);
    }

    #[test]
    fn visible_applies_backend_and_tool_opt_outs() {
        let config = RbacConfig {
            groups: vec![group("it", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("it", "forgejo", &["*"], &[]),
            ],
        };
        let it = effective(&config, &["it"]);
        let opt_outs = OptOuts::new([
            ("prometheus".to_string(), None),
            ("forgejo".to_string(), Some("delete_repo".to_string())),
        ]);

        assert!(!it.visible(tool("prometheus", "query", true), &opt_outs));
        assert!(it.visible(tool("forgejo", "get_repo", true), &opt_outs));
        assert!(!it.visible(tool("forgejo", "delete_repo", true), &opt_outs));
        // opt-outs never widen: not allowed stays not visible
        assert!(!it.visible(tool("loki", "query", true), &OptOuts::default()));
        // no opt-outs: visible equals allowed
        assert!(it.visible(tool("prometheus", "query", true), &OptOuts::default()));
    }

    #[test]
    fn mandatory_overrides_opt_outs() {
        let mut mandatory = grant("authenticated", "hindsight", &["recall"], &[]);
        mandatory.mandatory = true;
        let config = RbacConfig {
            groups: Vec::new(),
            grants: vec![mandatory, grant("authenticated", "hindsight", &["*"], &[])],
        };
        let policy = effective(&config, &["authenticated"]);
        let opt_outs = OptOuts::new([("hindsight".to_string(), None)]);
        assert!(policy.visible(tool("hindsight", "recall", false), &opt_outs));
        assert!(!policy.visible(tool("hindsight", "retain", false), &opt_outs));

        let opt_outs = OptOuts::new([("hindsight".to_string(), Some("recall".to_string()))]);
        assert!(policy.visible(tool("hindsight", "recall", false), &opt_outs));
    }

    #[test]
    fn opt_outs_hide_by_backend_or_tool() {
        let opt_outs = OptOuts::new([
            ("prometheus".to_string(), None),
            ("forgejo".to_string(), Some("delete_repo".to_string())),
        ]);
        assert!(opt_outs.hides_backend("prometheus"));
        assert!(!opt_outs.hides_backend("forgejo"));
        assert!(opt_outs.hides("prometheus", "anything"));
        assert!(opt_outs.hides("forgejo", "delete_repo"));
        assert!(!opt_outs.hides("forgejo", "get_repo"));
        assert!(!opt_outs.hides("loki", "delete_repo"));
        assert!(!OptOuts::default().hides("prometheus", "query"));
    }

    fn valid_config() -> RbacConfig {
        RbacConfig {
            groups: vec![group("it", &[("entra", "x")]), group("dev-2_a", &[])],
            grants: vec![
                grant("it", "prometheus", &["*"], &[]),
                grant("authenticated", "forgejo", &["*"], &[]),
            ],
        }
    }

    #[test]
    fn validate_accepts_a_good_config() {
        assert_eq!(
            valid_config().validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );
        assert_eq!(RbacConfig::default().validate(&[], &[]), Ok(()));
    }

    fn validate_err(config: &RbacConfig) -> String {
        config
            .validate(&["prometheus", "forgejo"], &["entra"])
            .unwrap_err()
    }

    #[test]
    fn validate_rejects_bad_group_names() {
        for name in ["", "IT", "it team", "it.team", "ü"] {
            let config = RbacConfig {
                groups: vec![group(name, &[])],
                grants: Vec::new(),
            };
            assert!(validate_err(&config).contains("[a-z0-9_-]+"), "{name:?}");
        }
    }

    #[test]
    fn validate_rejects_duplicate_groups() {
        let config = RbacConfig {
            groups: vec![group("it", &[]), group("it", &[])],
            grants: Vec::new(),
        };
        assert!(validate_err(&config).contains("duplicate"));
    }

    #[test]
    fn validate_rejects_the_reserved_group() {
        let config = RbacConfig {
            groups: vec![group(AUTHENTICATED_GROUP, &[])],
            grants: Vec::new(),
        };
        assert!(validate_err(&config).contains("built in"));
    }

    #[test]
    fn validate_rejects_grants_for_unknown_groups() {
        let mut config = valid_config();
        config.grants.push(grant("nope", "prometheus", &["*"], &[]));
        let err = validate_err(&config);
        assert!(
            err.contains("unknown group") && err.contains("nope"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_grants_for_unknown_backends() {
        let mut config = valid_config();
        config.grants.push(grant("it", "nope", &["*"], &[]));
        let err = validate_err(&config);
        assert!(
            err.contains("unknown backend") && err.contains("nope"),
            "{err}"
        );
    }

    #[test]
    fn validate_rejects_unknown_providers() {
        let config = RbacConfig {
            groups: vec![group("it", &[("okta", "x")])],
            grants: Vec::new(),
        };
        assert!(validate_err(&config).contains("no [[auth.oidc]] provider with id okta"));
        // an empty provider list is an error too
        assert!(
            config
                .validate(&[], &[])
                .unwrap_err()
                .contains("no [[auth.oidc]] provider with id okta")
        );
    }

    #[test]
    fn validate_rejects_empty_include() {
        let mut config = valid_config();
        config.grants.push(grant("it", "prometheus", &[], &[]));
        assert!(validate_err(&config).contains("empty include"));
    }

    #[test]
    fn parses_a_full_rbac_section() {
        #[derive(Deserialize)]
        struct Root {
            rbac: RbacConfig,
        }
        let root: Root = toml::from_str(
            r#"
            [[rbac.groups]]
            name = "it"
            description = "IT staff"
            idp = [{ provider = "entra", value = "0000-aaaa" }]

            [[rbac.groups]]
            name = "dev"

            [[rbac.grants]]
            group = "it"
            backend = "prometheus"
            include = ["get_*"]
            exclude = ["get_secret"]
            read_only = true
            mandatory = true

            [[rbac.grants]]
            group = "authenticated"
            backend = "forgejo"
            "#,
        )
        .unwrap();
        let rbac = root.rbac;

        assert_eq!(rbac.groups.len(), 2);
        assert_eq!(rbac.groups[0].name, "it");
        assert_eq!(rbac.groups[0].description.as_deref(), Some("IT staff"));
        assert_eq!(
            rbac.groups[0].idp,
            vec![IdpMapping {
                provider: "entra".to_string(),
                value: "0000-aaaa".to_string(),
            }]
        );
        assert_eq!(rbac.groups[1].description, None);
        assert_eq!(rbac.groups[1].idp, Vec::<IdpMapping>::new());

        assert_eq!(rbac.grants.len(), 2);
        let full = &rbac.grants[0];
        assert_eq!(full.include, strings(&["get_*"]));
        assert_eq!(full.exclude, strings(&["get_secret"]));
        assert!(full.read_only && full.mandatory);
        let defaults = &rbac.grants[1];
        assert_eq!(defaults.include, strings(&["*"]));
        assert_eq!(defaults.exclude, Vec::<String>::new());
        assert!(!defaults.read_only && !defaults.mandatory);

        assert_eq!(
            rbac.validate(&["prometheus", "forgejo"], &["entra"]),
            Ok(())
        );
    }

    #[test]
    fn an_absent_rbac_section_is_empty() {
        let rbac: RbacConfig = toml::from_str("").unwrap();
        assert!(rbac.groups.is_empty());
        assert!(rbac.grants.is_empty());
    }
}
