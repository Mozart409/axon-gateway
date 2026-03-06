//! Authentication and authorization for the MCP Gateway
//!
//! Provides:
//! - Constant-time token comparison to prevent timing attacks
//! - Multi-token support with per-token permissions (tool ACLs)
//! - Rate limiting per token
//! - Token resolution from request headers

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use subtle::ConstantTimeEq;

use crate::config::{GatewayConfig, TokenConfig};

/// Resolved identity from a valid auth token
#[derive(Debug, Clone)]
pub struct TokenIdentity {
    /// Display name of the token
    pub name: String,
    /// Allowed tool patterns (empty = all allowed)
    pub allowed_tools: Vec<String>,
    /// Allowed backends (empty = all allowed)
    pub allowed_backends: Vec<String>,
    /// Rate limit for this token (requests per minute, 0 = unlimited)
    pub rate_limit_per_minute: u32,
}

/// Rate limiter entry tracking request counts per window
#[derive(Debug)]
struct RateLimitEntry {
    /// Number of requests in the current window
    count: u32,
    /// Start of the current window
    window_start: Instant,
}

/// Authentication manager handling token validation, ACLs, and rate limiting
pub struct AuthManager {
    /// The simple shared token (backward compat)
    shared_token: Option<String>,
    /// Named tokens with permissions (`token_value` -> identity)
    token_map: HashMap<String, TokenIdentity>,
    /// Global rate limit (requests per minute per token, 0 = unlimited)
    global_rate_limit: u32,
    /// Rate limit state: `token_name` -> rate limit entry
    rate_limits: Arc<DashMap<String, RateLimitEntry>>,
}

impl AuthManager {
    /// Create a new `AuthManager` from gateway and token configs
    pub fn new(gateway_config: &GatewayConfig, tokens: &[TokenConfig]) -> Self {
        let mut token_map = HashMap::new();
        for tc in tokens {
            token_map.insert(
                tc.token.clone(),
                TokenIdentity {
                    name: tc.name.clone(),
                    allowed_tools: tc.allowed_tools.clone(),
                    allowed_backends: tc.allowed_backends.clone(),
                    rate_limit_per_minute: tc.rate_limit_per_minute,
                },
            );
        }

        Self {
            shared_token: gateway_config.auth_token.clone(),
            token_map,
            global_rate_limit: gateway_config.rate_limit_per_minute,
            rate_limits: Arc::new(DashMap::new()),
        }
    }

    /// Validate a bearer token and return the resolved identity.
    ///
    /// Returns `Ok(Some(identity))` for named tokens, `Ok(None)` for the shared
    /// token (which has no restrictions), or `Err(AuthError)` on failure.
    pub fn validate_token(&self, provided: &str) -> Result<Option<TokenIdentity>, AuthError> {
        // Check named tokens first (constant-time comparison)
        for (token_value, identity) in &self.token_map {
            if constant_time_eq(provided, token_value) {
                // Check rate limit
                self.check_rate_limit(&identity.name, identity.rate_limit_per_minute)?;
                return Ok(Some(identity.clone()));
            }
        }

        // Fall back to shared token
        if let Some(shared) = &self.shared_token
            && constant_time_eq(provided, shared)
        {
            self.check_rate_limit("__shared__", 0)?;
            return Ok(None); // No restrictions
        }

        // No auth configured at all — allow everything
        if self.shared_token.is_none() && self.token_map.is_empty() {
            return Ok(None);
        }

        Err(AuthError::InvalidToken)
    }

    /// Check if auth is required (any token configured)
    pub fn auth_required(&self) -> bool {
        self.shared_token.is_some() || !self.token_map.is_empty()
    }

    /// Check if a token identity is allowed to call a specific tool
    pub fn check_tool_permission(
        identity: Option<&TokenIdentity>,
        tool_name: &str,
    ) -> Result<(), AuthError> {
        let Some(identity) = identity else {
            return Ok(()); // No identity = shared token = all allowed
        };

        if identity.allowed_tools.is_empty() {
            return Ok(()); // Empty = all tools allowed
        }

        for pattern in &identity.allowed_tools {
            if tool_matches_pattern(tool_name, pattern) {
                return Ok(());
            }
        }

        Err(AuthError::ToolNotPermitted {
            tool: tool_name.to_string(),
            token: identity.name.clone(),
        })
    }

    /// Check if a token identity is allowed to access a specific backend
    pub fn check_backend_permission(
        identity: Option<&TokenIdentity>,
        backend_name: &str,
    ) -> Result<(), AuthError> {
        let Some(identity) = identity else {
            return Ok(()); // Shared token = all allowed
        };

        if identity.allowed_backends.is_empty() {
            return Ok(()); // Empty = all backends allowed
        }

        if identity
            .allowed_backends
            .contains(&backend_name.to_string())
        {
            return Ok(());
        }

        Err(AuthError::BackendNotPermitted {
            backend: backend_name.to_string(),
            token: identity.name.clone(),
        })
    }

    /// Check rate limit for a given token name
    fn check_rate_limit(&self, token_name: &str, token_rate_limit: u32) -> Result<(), AuthError> {
        // Determine effective rate limit (token-specific overrides global)
        let limit = if token_rate_limit > 0 {
            token_rate_limit
        } else {
            self.global_rate_limit
        };

        if limit == 0 {
            return Ok(()); // Unlimited
        }

        let now = Instant::now();
        let window = std::time::Duration::from_mins(1);

        let mut entry = self
            .rate_limits
            .entry(token_name.to_string())
            .or_insert(RateLimitEntry {
                count: 0,
                window_start: now,
            });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        if entry.count > limit {
            return Err(AuthError::RateLimited {
                token: token_name.to_string(),
                limit,
            });
        }

        Ok(())
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        // Even checking length can leak info, but subtle requires equal
        // lengths. Do a dummy comparison to avoid short-circuit.
        let _ = a.as_bytes().ct_eq(a.as_bytes());
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Check if a tool name matches a pattern.
///
/// Supports:
/// - Exact match: `"backend_tool_name"`
/// - Prefix wildcard: `"backend_*"` (matches all tools from backend)
/// - Wildcard only: `"*"` (matches everything)
fn tool_matches_pattern(tool_name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return tool_name.starts_with(prefix);
    }
    tool_name == pattern
}

/// Authentication errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum AuthError {
    #[error("invalid or missing authentication token")]
    InvalidToken,

    #[error("token '{token}' is not permitted to call tool '{tool}'")]
    ToolNotPermitted { tool: String, token: String },

    #[error("token '{token}' is not permitted to access backend '{backend}'")]
    BackendNotPermitted { backend: String, token: String },

    #[error("rate limit exceeded for token '{token}' ({limit}/min)")]
    RateLimited { token: String, limit: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(!constant_time_eq("hello", "world"));
        assert!(!constant_time_eq("hello", "hell"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn test_tool_matches_pattern() {
        assert!(tool_matches_pattern("backend_tool", "backend_tool"));
        assert!(tool_matches_pattern("backend_tool", "backend_*"));
        assert!(tool_matches_pattern("anything", "*"));
        assert!(!tool_matches_pattern("backend_tool", "other_*"));
        assert!(!tool_matches_pattern("backend_tool", "backend_other"));
    }

    #[test]
    fn test_validate_shared_token() {
        let config = GatewayConfig {
            bind: "0.0.0.0:8080".to_string(),
            auth_token: Some("secret".to_string()),
            rate_limit_per_minute: 0,
        };
        let auth = AuthManager::new(&config, &[]);

        assert!(auth.validate_token("secret").is_ok());
        assert!(auth.validate_token("wrong").is_err());
    }

    #[test]
    fn test_validate_named_token() {
        let config = GatewayConfig {
            bind: "0.0.0.0:8080".to_string(),
            auth_token: None,
            rate_limit_per_minute: 0,
        };
        let tokens = vec![TokenConfig {
            name: "agent1".to_string(),
            token: "tok_abc123".to_string(),
            allowed_tools: vec!["homeassistant_*".to_string()],
            allowed_backends: vec![],
            rate_limit_per_minute: 0,
            metadata: HashMap::new(),
        }];
        let auth = AuthManager::new(&config, &tokens);

        let identity = auth.validate_token("tok_abc123").unwrap();
        assert!(identity.is_some());
        let id = identity.unwrap();
        assert_eq!(id.name, "agent1");
        assert_eq!(id.allowed_tools, vec!["homeassistant_*"]);
    }

    #[test]
    fn test_no_auth_configured() {
        let config = GatewayConfig {
            bind: "0.0.0.0:8080".to_string(),
            auth_token: None,
            rate_limit_per_minute: 0,
        };
        let auth = AuthManager::new(&config, &[]);

        // No auth configured = all tokens valid
        assert!(auth.validate_token("anything").is_ok());
        assert!(!auth.auth_required());
    }

    #[test]
    fn test_tool_permission_check() {
        let identity = TokenIdentity {
            name: "test".to_string(),
            allowed_tools: vec!["homeassistant_*".to_string(), "jellyfin_search".to_string()],
            allowed_backends: vec![],
            rate_limit_per_minute: 0,
        };

        assert!(
            AuthManager::check_tool_permission(Some(&identity), "homeassistant_turn_on").is_ok()
        );
        assert!(AuthManager::check_tool_permission(Some(&identity), "jellyfin_search").is_ok());
        assert!(AuthManager::check_tool_permission(Some(&identity), "proxmox_list_vms").is_err());
        assert!(AuthManager::check_tool_permission(None, "anything").is_ok());
    }

    #[test]
    fn test_rate_limiting() {
        let config = GatewayConfig {
            bind: "0.0.0.0:8080".to_string(),
            auth_token: Some("secret".to_string()),
            rate_limit_per_minute: 3,
        };
        let auth = AuthManager::new(&config, &[]);

        // First 3 should succeed
        assert!(auth.validate_token("secret").is_ok());
        assert!(auth.validate_token("secret").is_ok());
        assert!(auth.validate_token("secret").is_ok());
        // 4th should be rate limited
        assert!(matches!(
            auth.validate_token("secret"),
            Err(AuthError::RateLimited { .. })
        ));
    }
}
