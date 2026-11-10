//! Who may do what with the tool-call audit
//!
//! [`AuditAdmin`] is the service behind the audit API and pages, the way
//! `rbac::Admin` is for RBAC: it checks the caller's permissions, validates
//! input and writes through the store, which audits every change.
//!
//! - viewing calls, rules and settings needs `audit.read`,
//! - reading stored arguments needs `audit.read_sensitive` (each read is audited),
//! - managing rules and settings needs `gateway.admin`.

use crate::audit::{
    ANY_BACKEND, AuditSettings, AuditSink, CaptureMode, CaptureRule, NewCaptureRule,
    StoredArguments, ToolCallFilter, ToolCallRecord,
};
use crate::policy::{Permission, Permissions};
use crate::rbac::{AdminError, PolicyHandle, resolve};
use crate::server::AppState;
use crate::store::{Actor, SessionUser, Store, User};

/// Longest retention accepted, in days (ten years).
pub const MAX_RETENTION_DAYS: i32 = 3650;
const MAX_BACKEND_CHARS: usize = 100;
const MAX_PATTERN_CHARS: usize = 200;
const MAX_DROP_KEYS: usize = 50;
const MAX_KEY_CHARS: usize = 100;

/// Email, else display name, else subject: how the audit log names the user.
fn actor_label(user: &User) -> String {
    [user.email.as_deref(), user.display_name.as_deref()]
        .into_iter()
        .flatten()
        .find(|label| !label.trim().is_empty())
        .unwrap_or(&user.subject)
        .to_owned()
}

/// A checked capture rule: trimmed names, a known mode, sane glob and keys.
///
/// # Errors
/// [`AdminError::Invalid`] naming the field that is wrong.
pub fn validate_rule(
    backend: &str,
    tool_pattern: &str,
    mode: &str,
    drop_keys: &[String],
) -> Result<NewCaptureRule, AdminError> {
    let backend = backend.trim();
    if backend.is_empty()
        || backend.chars().count() > MAX_BACKEND_CHARS
        || backend.chars().any(char::is_whitespace)
        || (backend != ANY_BACKEND && backend.contains('*'))
    {
        return Err(AdminError::Invalid(format!(
            "backend must be a backend name or {ANY_BACKEND}, at most {MAX_BACKEND_CHARS} characters"
        )));
    }

    let tool_pattern = tool_pattern.trim();
    let wildcards = tool_pattern.matches('*').count();
    let wildcard_misplaced = wildcards > 1 || (wildcards == 1 && !tool_pattern.ends_with('*'));
    if tool_pattern.is_empty()
        || tool_pattern.chars().count() > MAX_PATTERN_CHARS
        || tool_pattern.chars().any(char::is_whitespace)
        || wildcard_misplaced
    {
        return Err(AdminError::Invalid(format!(
            "tool pattern must be a tool name, or a prefix ending in *, at most {MAX_PATTERN_CHARS} characters"
        )));
    }

    let mode = CaptureMode::parse(mode.trim())
        .ok_or_else(|| AdminError::Invalid("mode must be none, redacted or full".to_owned()))?;

    let mut keys: Vec<String> = Vec::new();
    for key in drop_keys
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
    {
        if key.chars().count() > MAX_KEY_CHARS {
            return Err(AdminError::Invalid(format!(
                "a key to drop must be at most {MAX_KEY_CHARS} characters"
            )));
        }
        if !keys.iter().any(|known| known == key) {
            keys.push(key.to_owned());
        }
    }
    if keys.len() > MAX_DROP_KEYS {
        return Err(AdminError::Invalid(format!(
            "at most {MAX_DROP_KEYS} keys can be dropped"
        )));
    }

    Ok(NewCaptureRule {
        backend: backend.to_owned(),
        tool_pattern: tool_pattern.to_owned(),
        mode,
        drop_keys: keys,
    })
}

/// Splits a comma- or whitespace-separated list of keys, as a form sends it.
#[must_use]
pub fn split_keys(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Checked retention settings.
///
/// # Errors
/// [`AdminError::Invalid`] unless both are between 1 and [`MAX_RETENTION_DAYS`].
pub fn validate_settings(
    arguments_retention_days: i32,
    metadata_retention_days: i32,
) -> Result<AuditSettings, AdminError> {
    for (name, days) in [
        ("arguments retention", arguments_retention_days),
        ("metadata retention", metadata_retention_days),
    ] {
        if !(1..=MAX_RETENTION_DAYS).contains(&days) {
            return Err(AdminError::Invalid(format!(
                "{name} must be between 1 and {MAX_RETENTION_DAYS} days"
            )));
        }
    }
    Ok(AuditSettings {
        arguments_retention_days,
        metadata_retention_days,
    })
}

/// The audit operations for one logged-in user.
pub struct AuditAdmin<'a> {
    store: &'a Store,
    actor: Actor,
    permissions: Permissions,
    /// The writer to tell when the capture rules change; `None` outside multi-user mode.
    sink: Option<&'a AuditSink>,
}

impl<'a> AuditAdmin<'a> {
    pub fn new(store: &'a Store, policy: &PolicyHandle, session: &SessionUser) -> Self {
        let (_, permissions) = resolve(&policy.current(), session);
        Self {
            store,
            actor: Actor {
                user_id: Some(session.user.id),
                label: actor_label(&session.user),
            },
            permissions,
            sink: None,
        }
    }

    /// The service for a session; `None` outside multi-user mode.
    pub fn from_state(state: &'a AppState, session: &SessionUser) -> Option<Self> {
        let (store, _) = state.multi_user()?;
        let mut admin = Self::new(store, &state.policy, session);
        admin.sink = state.audit.as_ref();
        Some(admin)
    }

    fn require(&self, permission: Permission) -> Result<(), AdminError> {
        if self.permissions.has(permission) {
            Ok(())
        } else {
            Err(AdminError::Forbidden)
        }
    }

    /// Whether the caller may read stored arguments (`audit.read_sensitive`).
    #[must_use]
    pub fn can_read_arguments(&self) -> bool {
        self.permissions.has(Permission::AuditReadSensitive)
    }

    /// Whether the caller may change rules and settings (`gateway.admin`).
    #[must_use]
    pub fn can_manage(&self) -> bool {
        self.permissions.has(Permission::GatewayAdmin)
    }

    /// Calls matching `filter`, newest first, older than `before` when given.
    ///
    /// # Errors
    /// Forbidden without `audit.read`; a store error.
    pub async fn calls(
        &self,
        filter: &ToolCallFilter,
        before: Option<i64>,
        limit: i64,
    ) -> Result<Vec<ToolCallRecord>, AdminError> {
        self.require(Permission::AuditRead)?;
        Ok(self.store.list_tool_calls(filter, before, limit).await?)
    }

    /// One call, without its arguments.
    ///
    /// # Errors
    /// Forbidden without `audit.read`; not found for an unknown id.
    pub async fn call(&self, id: i64) -> Result<ToolCallRecord, AdminError> {
        self.require(Permission::AuditRead)?;
        self.store.tool_call(id).await?.ok_or(AdminError::NotFound)
    }

    /// The stored arguments of a call; the read is audited.
    ///
    /// # Errors
    /// Forbidden without `audit.read_sensitive`; not found for an unknown call
    /// and for a call without stored arguments (never captured, or past their
    /// retention).
    pub async fn arguments(&self, id: i64) -> Result<StoredArguments, AdminError> {
        self.require(Permission::AuditReadSensitive)?;
        self.store
            .tool_call_arguments(&self.actor, id)
            .await?
            .ok_or(AdminError::NotFound)
    }

    /// All capture rules, oldest first.
    ///
    /// # Errors
    /// Forbidden without `audit.read`; a store error.
    pub async fn capture_rules(&self) -> Result<Vec<CaptureRule>, AdminError> {
        self.require(Permission::AuditRead)?;
        Ok(self.store.capture_rules().await?)
    }

    /// Creates a capture rule and returns it.
    ///
    /// # Errors
    /// Forbidden without `gateway.admin`; invalid input; a store error.
    pub async fn create_capture_rule(
        &self,
        backend: &str,
        tool_pattern: &str,
        mode: &str,
        drop_keys: &[String],
    ) -> Result<CaptureRule, AdminError> {
        self.require(Permission::GatewayAdmin)?;
        let new = validate_rule(backend, tool_pattern, mode, drop_keys)?;
        let id = self.store.create_capture_rule(&self.actor, &new).await?;
        self.rules_changed();
        Ok(CaptureRule {
            id,
            backend: new.backend,
            tool_pattern: new.tool_pattern,
            mode: new.mode,
            drop_keys: new.drop_keys,
        })
    }

    /// Tells the writer to reload the rules before its next batch.
    fn rules_changed(&self) {
        if let Some(sink) = self.sink {
            sink.mark_rules_dirty();
        }
    }

    /// Deletes a capture rule.
    ///
    /// # Errors
    /// Forbidden without `gateway.admin`; not found for an unknown id.
    pub async fn delete_capture_rule(&self, id: i64) -> Result<(), AdminError> {
        self.require(Permission::GatewayAdmin)?;
        self.store
            .delete_capture_rule(&self.actor, id)
            .await?
            .ok_or(AdminError::NotFound)?;
        self.rules_changed();
        Ok(())
    }

    /// The retention settings.
    ///
    /// # Errors
    /// Forbidden without `audit.read`; a store error.
    pub async fn settings(&self) -> Result<AuditSettings, AdminError> {
        self.require(Permission::AuditRead)?;
        Ok(self.store.audit_settings().await?)
    }

    /// Replaces the retention settings and returns them.
    ///
    /// # Errors
    /// Forbidden without `gateway.admin`; invalid for a retention outside
    /// 1 to 3650 days; a store error.
    pub async fn update_settings(
        &self,
        arguments_retention_days: i32,
        metadata_retention_days: i32,
    ) -> Result<AuditSettings, AdminError> {
        self.require(Permission::GatewayAdmin)?;
        let settings = validate_settings(arguments_retention_days, metadata_retention_days)?;
        self.store
            .update_audit_settings(&self.actor, &settings)
            .await?;
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        backend: &str,
        pattern: &str,
        mode: &str,
        keys: &[&str],
    ) -> Result<NewCaptureRule, AdminError> {
        let keys: Vec<String> = keys.iter().map(|key| (*key).to_owned()).collect();
        validate_rule(backend, pattern, mode, &keys)
    }

    fn is_invalid<T: std::fmt::Debug>(result: &Result<T, AdminError>) -> bool {
        matches!(result, Err(AdminError::Invalid(_)))
    }

    #[test]
    fn a_valid_rule_is_trimmed() {
        let new = rule(
            " pg ",
            " run_* ",
            " full ",
            &["content", " body ", "content", ""],
        )
        .unwrap();
        assert_eq!(
            new,
            NewCaptureRule {
                backend: "pg".to_owned(),
                tool_pattern: "run_*".to_owned(),
                mode: CaptureMode::Full,
                drop_keys: vec!["content".to_owned(), "body".to_owned()],
            }
        );
        assert!(rule("*", "*", "none", &[]).is_ok());
        assert!(rule("files", "read_file", "redacted", &[]).is_ok());
    }

    #[test]
    fn a_bad_backend_is_invalid() {
        for backend in ["", "  ", "a b", "pg*", "*pg", "**"] {
            assert!(is_invalid(&rule(backend, "*", "none", &[])), "{backend:?}");
        }
        assert!(is_invalid(&rule(&"x".repeat(101), "*", "none", &[])));
    }

    #[test]
    fn a_bad_pattern_is_invalid() {
        for pattern in ["", " ", "a b", "*a", "a*b", "a**", "**"] {
            assert!(is_invalid(&rule("pg", pattern, "none", &[])), "{pattern:?}");
        }
        assert!(is_invalid(&rule("pg", &"x".repeat(201), "none", &[])));
    }

    #[test]
    fn a_bad_mode_is_invalid() {
        for mode in ["", "all", "FULL", "redact"] {
            assert!(is_invalid(&rule("pg", "*", mode, &[])), "{mode:?}");
        }
    }

    #[test]
    fn bad_drop_keys_are_invalid() {
        let long = "k".repeat(101);
        assert!(is_invalid(&rule("pg", "*", "full", &[long.as_str()])));
        let many: Vec<String> = (0..=MAX_DROP_KEYS).map(|n| format!("k{n}")).collect();
        assert!(is_invalid(&validate_rule("pg", "*", "full", &many)));
        let max: Vec<String> = (0..MAX_DROP_KEYS).map(|n| format!("k{n}")).collect();
        assert!(validate_rule("pg", "*", "full", &max).is_ok());
    }

    #[test]
    fn keys_split_on_commas_and_whitespace() {
        assert_eq!(
            split_keys("content, body\nraw  ,, "),
            vec!["content".to_owned(), "body".to_owned(), "raw".to_owned()]
        );
        assert_eq!(split_keys(""), Vec::<String>::new());
    }

    #[test]
    fn settings_are_bounded() {
        assert_eq!(
            validate_settings(1, MAX_RETENTION_DAYS).unwrap(),
            AuditSettings {
                arguments_retention_days: 1,
                metadata_retention_days: MAX_RETENTION_DAYS,
            }
        );
        for (arguments, metadata) in [
            (0, 30),
            (30, 0),
            (-1, 30),
            (30, -5),
            (MAX_RETENTION_DAYS + 1, 30),
            (30, MAX_RETENTION_DAYS + 1),
        ] {
            assert!(
                is_invalid(&validate_settings(arguments, metadata)),
                "{arguments} {metadata}"
            );
        }
    }
}
