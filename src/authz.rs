//! Authorization decisions for the MCP Gateway
//!
//! A [`Scope`] says which tools and backends a caller may use; [`Scope::allows`]
//! is the single place that decides. RBAC grants will produce a `Scope` later.

/// What a caller may use. An empty list leaves that kind of resource unrestricted.
#[derive(Debug, Clone, Copy)]
pub struct Scope<'a> {
    /// Allowed tool patterns (see [`tool_matches_pattern`])
    pub tools: &'a [String],
    /// Allowed backend names, matched exactly
    pub backends: &'a [String],
}

/// A resource a caller asks to use
#[derive(Debug, Clone, Copy)]
pub enum Resource<'a> {
    /// A tool, by its (prefixed) name
    Tool(&'a str),
    /// A backend, by name
    Backend(&'a str),
}

impl Scope<'_> {
    /// Whether this scope permits the resource
    pub fn allows(&self, resource: Resource<'_>) -> bool {
        match resource {
            Resource::Tool(name) => {
                self.tools.is_empty()
                    || self
                        .tools
                        .iter()
                        .any(|pattern| tool_matches_pattern(name, pattern))
            }
            Resource::Backend(name) => {
                self.backends.is_empty() || self.backends.iter().any(|backend| backend == name)
            }
        }
    }
}

/// Check if a tool name matches a pattern.
///
/// Supports:
/// - Exact match: `"backend_tool_name"`
/// - Prefix wildcard: `"backend_*"` (matches all tools from backend)
/// - Wildcard only: `"*"` (matches everything)
pub fn tool_matches_pattern(tool_name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return tool_name.starts_with(prefix);
    }
    tool_name == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn test_tool_matches_pattern() {
        let cases = [
            ("backend_tool", "backend_tool", true),
            ("backend_tool", "backend_*", true),
            ("anything", "*", true),
            ("", "*", true),
            ("backend_tool", "other_*", false),
            ("backend_tool", "backend_other", false),
            // An empty prefix before the wildcard is "*"; a bare empty pattern is exact.
            ("backend_tool", "", false),
            ("", "", true),
        ];
        for (tool, pattern, expected) in cases {
            assert_eq!(
                tool_matches_pattern(tool, pattern),
                expected,
                "tool {tool:?} against pattern {pattern:?}"
            );
        }
    }

    #[test]
    fn test_unrestricted_scope_allows_everything() {
        let scope = Scope {
            tools: &[],
            backends: &[],
        };
        assert!(scope.allows(Resource::Tool("anything")));
        assert!(scope.allows(Resource::Backend("anything")));
    }

    #[test]
    fn test_tool_scope() {
        let tools = strings(&["homeassistant_*", "jellyfin_search"]);
        let scope = Scope {
            tools: &tools,
            backends: &[],
        };
        let cases = [
            ("homeassistant_turn_on", true),
            ("jellyfin_search", true),
            ("jellyfin_list", false),
            ("proxmox_list_vms", false),
        ];
        for (tool, expected) in cases {
            assert_eq!(
                scope.allows(Resource::Tool(tool)),
                expected,
                "tool {tool:?}"
            );
        }

        let all = strings(&["*"]);
        let scope = Scope {
            tools: &all,
            backends: &[],
        };
        assert!(scope.allows(Resource::Tool("anything")));
    }

    #[test]
    fn test_backend_scope_is_exact() {
        let backends = strings(&["homeassistant"]);
        let scope = Scope {
            tools: &[],
            backends: &backends,
        };
        let cases = [
            ("homeassistant", true),
            ("homeassistant2", false),
            ("home", false),
            ("jellyfin", false),
        ];
        for (backend, expected) in cases {
            assert_eq!(
                scope.allows(Resource::Backend(backend)),
                expected,
                "backend {backend:?}"
            );
        }
    }

    #[test]
    fn test_tool_restriction_leaves_backends_open_and_vice_versa() {
        let tools = strings(&["homeassistant_*"]);
        let only_tools = Scope {
            tools: &tools,
            backends: &[],
        };
        assert!(only_tools.allows(Resource::Backend("jellyfin")));
        assert!(!only_tools.allows(Resource::Tool("jellyfin_search")));

        let backends = strings(&["homeassistant"]);
        let only_backends = Scope {
            tools: &[],
            backends: &backends,
        };
        assert!(only_backends.allows(Resource::Tool("jellyfin_search")));
        assert!(!only_backends.allows(Resource::Backend("jellyfin")));
    }
}
