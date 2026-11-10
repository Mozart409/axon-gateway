//! Tool-call audit: what is captured, how it is redacted and how it is written
//!
//! Every tool call leaves a metadata row (`tool_calls`). Its arguments are
//! stored apart (`audit_arguments`, shorter retention) and only when the
//! capture policy says so:
//!
//! - an admin rule per backend and tool glob wins ([`capture_for`]); the most
//!   specific matching rule decides the mode and the keys to drop,
//! - without a rule the tool's MCP annotations decide: `readOnlyHint: true`
//!   captures nothing, anything else (an unannotated tool counts as
//!   potentially destructive) captures redacted arguments.
//!
//! [`prepare_arguments`] applies the mode. Tool results are never stored.
//!
//! The hot path must never wait for the database: [`AuditSink::record`] only
//! pushes into a bounded queue and counts what does not fit. A background task
//! batches the events, applies the policy and writes them in one transaction.
//! Nothing here logs argument values.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use uuid::Uuid;

use crate::authz::tool_matches_pattern;
use crate::metrics;
use crate::store::Store;

/// Events the queue holds before [`AuditSink::record`] starts dropping.
const CHANNEL_CAPACITY: usize = 1024;
/// Most events written in one transaction.
const MAX_BATCH: usize = 100;
/// How long a batch waits for more events once it has one.
const BATCH_WINDOW: Duration = Duration::from_secs(1);
/// How often the capture rules are re-read from the database.
const RULES_REFRESH: Duration = Duration::from_secs(30);
/// How often old rows are purged.
const PURGE_INTERVAL: Duration = Duration::from_secs(3600);

/// Strings in captured arguments are cut after this many bytes.
const MAX_STRING_BYTES: usize = 2048;
const TRUNCATED_SUFFIX: &str = "…[truncated]";
/// What replaces the value of a sensitive key in redacted mode.
const REDACTED: &str = "[redacted]";
/// Error messages are cut after this many characters.
const MAX_ERROR_CHARS: usize = 500;
/// A rule's backend that matches every backend.
pub const ANY_BACKEND: &str = "*";

/// Keys (matched case-insensitively, as substrings) whose values are masked in
/// redacted mode.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "private_key",
];

/// What to keep of a call's arguments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    /// Keep nothing
    None,
    /// Keep them with sensitive values masked
    Redacted,
    /// Keep them as sent (long strings are still truncated)
    Full,
}

impl CaptureMode {
    /// The value stored in the database and shown in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Redacted => "redacted",
            Self::Full => "full",
        }
    }

    /// The mode named `value`; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "redacted" => Some(Self::Redacted),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// How a tool call ended
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallOutcome {
    /// The tool ran and returned a result
    Ok,
    /// The call failed before or around the tool (denied, backend down, ...)
    Error,
    /// The tool ran and reported an error (`isError: true`)
    ToolError,
}

impl CallOutcome {
    /// The value stored in the database and shown in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::ToolError => "tool_error",
        }
    }

    /// The outcome named `value`; `None` for anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "error" => Some(Self::Error),
            "tool_error" => Some(Self::ToolError),
            _ => None,
        }
    }
}

/// An admin override of the capture default
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRule {
    pub id: i64,
    /// A backend name, or [`ANY_BACKEND`]
    pub backend: String,
    /// A glob on the original tool name (see [`tool_matches_pattern`])
    pub tool_pattern: String,
    pub mode: CaptureMode,
    /// Keys removed from the arguments at any depth
    pub drop_keys: Vec<String>,
}

/// A capture rule to create
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCaptureRule {
    pub backend: String,
    pub tool_pattern: String,
    pub mode: CaptureMode,
    pub drop_keys: Vec<String>,
}

/// The retention of the audit tables
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRow)]
pub struct AuditSettings {
    /// Days arguments are kept
    pub arguments_retention_days: i32,
    /// Days call metadata is kept
    pub metadata_retention_days: i32,
}

/// What a purge removed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PurgeCounts {
    pub arguments: u64,
    pub calls: u64,
}

/// One stored tool call (metadata only)
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct ToolCallRecord {
    pub id: i64,
    pub at: DateTime<Utc>,
    /// `None` once the user is deleted
    pub user_id: Option<Uuid>,
    pub principal_label: String,
    pub token_id: Option<Uuid>,
    /// `pat` or `config_token`
    pub auth_method: String,
    pub backend: String,
    /// The backend's own tool name
    pub tool: String,
    /// `ok`, `error` or `tool_error`
    pub outcome: String,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub duration_ms: i32,
    pub trace_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    /// `redacted` or `full` when arguments are stored for the call
    pub arguments_capture: Option<String>,
}

/// Filters of the tool call listing; `None` matches everything
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolCallFilter {
    pub user_id: Option<Uuid>,
    pub backend: Option<String>,
    /// The backend's own tool name, exactly
    pub tool: Option<String>,
    /// `ok`, `error` or `tool_error`
    pub outcome: Option<String>,
}

/// The stored arguments of one call
#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct StoredArguments {
    pub call_id: i64,
    pub at: DateTime<Utc>,
    /// `redacted` or `full`
    pub capture: String,
    pub arguments: Value,
}

/// A tool call, ready for the database
#[derive(Clone, PartialEq)]
pub struct NewToolCall {
    pub user_id: Option<Uuid>,
    pub principal_label: String,
    pub token_id: Option<Uuid>,
    pub auth_method: String,
    pub backend: String,
    pub tool: String,
    pub outcome: CallOutcome,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub duration_ms: i32,
    pub trace_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    /// The capture mode (`Redacted` or `Full`) and the prepared arguments
    pub arguments: Option<(CaptureMode, Value)>,
}

/// A tool call as the `/mcp` handler reports it
#[derive(Clone)]
pub struct ToolCallEvent {
    pub user_id: Option<Uuid>,
    /// Email, display name or service account name; survives the user's deletion
    pub principal_label: String,
    pub token_id: Option<Uuid>,
    /// `pat` or `config_token`
    pub auth_method: String,
    pub backend: String,
    /// The backend's own tool name, not the namespaced one
    pub tool: String,
    pub outcome: CallOutcome,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub duration: Duration,
    pub trace_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    /// The arguments as the client sent them; the sink applies the capture policy
    pub arguments: Value,
    /// The tool's MCP annotations, for the default capture mode
    pub annotations: Option<Value>,
}

// `Debug` leaves the arguments out, so that logging an event with `{:?}` cannot
// leak them.
impl std::fmt::Debug for NewToolCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewToolCall")
            .field("principal_label", &self.principal_label)
            .field("backend", &self.backend)
            .field("tool", &self.tool)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ToolCallEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCallEvent")
            .field("principal_label", &self.principal_label)
            .field("backend", &self.backend)
            .field("tool", &self.tool)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

/// Whether the tool's annotations say it only reads.
fn read_only(annotations: Option<&Value>) -> bool {
    annotations
        .and_then(|annotations| annotations.get("readOnlyHint"))
        .and_then(Value::as_bool)
        == Some(true)
}

/// Orders matching rules: exact backend, then an exact tool name over a glob,
/// then the longer pattern, then the newer rule.
fn specificity(rule: &CaptureRule) -> (bool, bool, usize, i64) {
    (
        rule.backend != ANY_BACKEND,
        !rule.tool_pattern.contains('*'),
        rule.tool_pattern.len(),
        rule.id,
    )
}

/// The capture mode and the keys to drop for a call.
///
/// The most specific matching rule wins. Without a rule, a tool annotated
/// `readOnlyHint: true` is not captured and any other tool (no annotations
/// included: the MCP spec treats it as potentially destructive) is captured
/// redacted.
#[must_use]
pub fn capture_for(
    rules: &[CaptureRule],
    backend: &str,
    tool: &str,
    annotations: Option<&Value>,
) -> (CaptureMode, Vec<String>) {
    let best = rules
        .iter()
        .filter(|rule| {
            (rule.backend == ANY_BACKEND || rule.backend == backend)
                && tool_matches_pattern(tool, &rule.tool_pattern)
        })
        .max_by_key(|rule| specificity(rule));
    match best {
        Some(rule) => (rule.mode, rule.drop_keys.clone()),
        None if read_only(annotations) => (CaptureMode::None, Vec::new()),
        None => (CaptureMode::Redacted, Vec::new()),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|part| key.contains(part))
}

/// `text`, cut at `max_bytes` on a char boundary with a marker when longer.
fn truncate_string(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATED_SUFFIX}", text.get(..end).unwrap_or_default())
}

fn clean(value: &Value, redact: bool, drop_keys: &[String]) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(key, _)| {
                    !drop_keys
                        .iter()
                        .any(|dropped| dropped.eq_ignore_ascii_case(key))
                })
                .map(|(key, value)| {
                    let value = if redact && is_sensitive_key(key) {
                        Value::String(REDACTED.to_owned())
                    } else {
                        clean(value, redact, drop_keys)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| clean(item, redact, drop_keys))
                .collect(),
        ),
        Value::String(text) => Value::String(truncate_string(text, MAX_STRING_BYTES)),
        other => other.clone(),
    }
}

/// The arguments as they are stored for `mode`; `None` when nothing is.
///
/// Keys in `drop_keys` (compared case-insensitively) are removed at any depth.
/// In [`CaptureMode::Redacted`] the value under a key that contains
/// `password`, `secret`, `token` and the like is replaced by `[redacted]`. In
/// both modes strings over 2 KiB are truncated.
#[must_use]
pub fn prepare_arguments(args: &Value, mode: CaptureMode, drop_keys: &[String]) -> Option<Value> {
    match mode {
        CaptureMode::None => None,
        CaptureMode::Redacted => Some(clean(args, true, drop_keys)),
        CaptureMode::Full => Some(clean(args, false, drop_keys)),
    }
}

/// Applies the capture policy to a batch of events.
fn build_rows(events: Vec<ToolCallEvent>, rules: &[CaptureRule]) -> Vec<NewToolCall> {
    events
        .into_iter()
        .map(|event| {
            let (mode, drop_keys) = capture_for(
                rules,
                &event.backend,
                &event.tool,
                event.annotations.as_ref(),
            );
            let arguments = prepare_arguments(&event.arguments, mode, &drop_keys)
                .map(|arguments| (mode, arguments));
            NewToolCall {
                user_id: event.user_id,
                principal_label: event.principal_label,
                token_id: event.token_id,
                auth_method: event.auth_method,
                backend: event.backend,
                tool: event.tool,
                outcome: event.outcome,
                error_code: event.error_code,
                error_message: event
                    .error_message
                    .map(|message| message.chars().take(MAX_ERROR_CHARS).collect()),
                duration_ms: i32::try_from(event.duration.as_millis()).unwrap_or(i32::MAX),
                trace_id: event.trace_id,
                client_ip: event.client_ip,
                user_agent: event.user_agent,
                arguments,
            }
        })
        .collect()
}

/// Handle to the audit writer; cheap to clone.
#[derive(Debug, Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<ToolCallEvent>,
    /// Set when a capture rule changed in this process: the writer reloads the
    /// rules before its next batch instead of waiting for [`RULES_REFRESH`].
    rules_dirty: Arc<AtomicBool>,
}

impl AuditSink {
    /// Starts the writer task and returns the handle to feed it. The task ends
    /// when the last handle is dropped, after writing what is queued.
    pub fn spawn(store: Store) -> AuditSink {
        metrics::describe_audit_metrics();
        let (sink, rx) = Self::channel(CHANNEL_CAPACITY);
        tokio::spawn(run_writer(store, rx, Arc::clone(&sink.rules_dirty)));
        sink
    }

    fn channel(capacity: usize) -> (Self, mpsc::Receiver<ToolCallEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        let sink = Self {
            tx,
            rules_dirty: Arc::new(AtomicBool::new(false)),
        };
        (sink, rx)
    }

    /// Makes the writer reload the capture rules before it writes its next
    /// batch. Call it after a rule was created or deleted.
    pub fn mark_rules_dirty(&self) {
        self.rules_dirty.store(true, Ordering::Release);
    }

    /// Queues an event without waiting. When the queue is full the event is
    /// dropped and `axon_audit_dropped_total` counts it.
    pub fn record(&self, event: ToolCallEvent) {
        if self.tx.try_send(event).is_err() {
            metrics::record_audit_dropped();
        }
    }
}

async fn reload_rules(store: &Store, rules: &mut Vec<CaptureRule>) {
    match store.capture_rules().await {
        Ok(fresh) => *rules = fresh,
        Err(error) => tracing::warn!(%error, "Failed to refresh the audit capture rules"),
    }
}

async fn write_batch(store: &Store, rules: &[CaptureRule], events: Vec<ToolCallEvent>) {
    let rows = build_rows(events, rules);
    if let Err(error) = store.insert_tool_calls(&rows).await {
        // Never log the rows: they carry arguments.
        tracing::error!(%error, events = rows.len(), "Failed to write tool call audit rows");
        metrics::record_audit_write_error();
    }
}

/// Collects events into batches of up to [`MAX_BATCH`] or [`BATCH_WINDOW`] and
/// writes them; keeps the capture rules fresh. Returns when the queue closes.
async fn run_writer(
    store: Store,
    mut rx: mpsc::Receiver<ToolCallEvent>,
    rules_dirty: Arc<AtomicBool>,
) {
    let mut rules: Vec<CaptureRule> = Vec::new();
    let mut refresh = tokio::time::interval(RULES_REFRESH);
    refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            // The first tick is immediate: the rules load before the first batch.
            _ = refresh.tick() => reload_rules(&store, &mut rules).await,
            first = rx.recv() => {
                let Some(first) = first else {
                    return;
                };
                let mut batch = vec![first];
                let deadline = Instant::now() + BATCH_WINDOW;
                let mut open = true;
                while batch.len() < MAX_BATCH {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(event)) => batch.push(event),
                        Ok(None) => {
                            open = false;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                if rules_dirty.swap(false, Ordering::AcqRel) {
                    reload_rules(&store, &mut rules).await;
                }
                write_batch(&store, &rules, batch).await;
                if !open {
                    return;
                }
            }
        }
    }
}

/// Deletes arguments and calls past their retention every hour, reading the
/// retention from the database each time.
pub fn spawn_audit_purge(store: Store) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PURGE_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match store.purge_audit().await {
                Ok(purged) => tracing::debug!(
                    arguments = purged.arguments,
                    calls = purged.calls,
                    "Purged audit rows past their retention"
                ),
                Err(error) => tracing::warn!(%error, "Failed to purge the audit tables"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rule(id: i64, backend: &str, pattern: &str, mode: CaptureMode) -> CaptureRule {
        CaptureRule {
            id,
            backend: backend.to_owned(),
            tool_pattern: pattern.to_owned(),
            mode,
            drop_keys: Vec::new(),
        }
    }

    fn mode_of(rules: &[CaptureRule], backend: &str, tool: &str) -> CaptureMode {
        capture_for(rules, backend, tool, None).0
    }

    fn keys(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn mode_names_round_trip() {
        for mode in [CaptureMode::None, CaptureMode::Redacted, CaptureMode::Full] {
            assert_eq!(CaptureMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(CaptureMode::parse("everything"), None);
        assert_eq!(CaptureMode::parse("Full"), None);
        assert_eq!(json!(CaptureMode::Redacted), json!("redacted"));
    }

    #[test]
    fn outcome_names_round_trip() {
        for outcome in [CallOutcome::Ok, CallOutcome::Error, CallOutcome::ToolError] {
            assert_eq!(CallOutcome::parse(outcome.as_str()), Some(outcome));
        }
        assert_eq!(CallOutcome::parse("denied"), None);
    }

    #[test]
    fn default_follows_the_annotations() {
        let read_only = json!({"readOnlyHint": true});
        let writes = json!({"readOnlyHint": false});
        let destructive = json!({"destructiveHint": true});
        let odd = json!({"readOnlyHint": "true"});
        let null = Value::Null;
        let cases = [
            (Some(&read_only), CaptureMode::None),
            (Some(&writes), CaptureMode::Redacted),
            (Some(&destructive), CaptureMode::Redacted),
            (Some(&odd), CaptureMode::Redacted),
            (Some(&null), CaptureMode::Redacted),
            (None, CaptureMode::Redacted),
        ];
        for (annotations, expected) in cases {
            let (mode, drop_keys) = capture_for(&[], "files", "read_file", annotations);
            assert_eq!(mode, expected, "annotations {annotations:?}");
            assert_eq!(drop_keys, Vec::<String>::new());
        }
    }

    #[test]
    fn a_matching_rule_beats_the_annotations() {
        let rules = [rule(1, "files", "read_*", CaptureMode::Full)];
        let read_only = json!({"readOnlyHint": true});
        let (mode, _) = capture_for(&rules, "files", "read_file", Some(&read_only));
        assert_eq!(mode, CaptureMode::Full);
        // A rule for another tool or backend does not apply.
        let (mode, _) = capture_for(&rules, "files", "write_file", Some(&read_only));
        assert_eq!(mode, CaptureMode::None);
        let (mode, _) = capture_for(&rules, "other", "read_file", Some(&read_only));
        assert_eq!(mode, CaptureMode::None);
    }

    #[test]
    fn a_rule_can_switch_capture_off() {
        let rules = [rule(1, "*", "*", CaptureMode::None)];
        assert_eq!(mode_of(&rules, "files", "delete_file"), CaptureMode::None);
    }

    #[test]
    fn an_exact_backend_beats_the_wildcard() {
        let rules = [
            rule(1, "files", "*", CaptureMode::Full),
            rule(2, "*", "read_file", CaptureMode::None),
        ];
        // The exact backend wins even against an exact tool name on `*`.
        assert_eq!(mode_of(&rules, "files", "read_file"), CaptureMode::Full);
        assert_eq!(mode_of(&rules, "other", "read_file"), CaptureMode::None);
    }

    #[test]
    fn an_exact_tool_beats_a_glob() {
        let rules = [
            rule(1, "files", "read_file*", CaptureMode::Full),
            rule(2, "files", "read_file", CaptureMode::None),
        ];
        // The glob is longer, but the exact name is more specific.
        assert_eq!(mode_of(&rules, "files", "read_file"), CaptureMode::None);
        assert_eq!(mode_of(&rules, "files", "read_file_x"), CaptureMode::Full);
    }

    #[test]
    fn a_longer_glob_beats_a_shorter_one() {
        let rules = [
            rule(9, "files", "*", CaptureMode::None),
            rule(2, "files", "read_*", CaptureMode::Full),
            rule(1, "files", "read_f*", CaptureMode::Redacted),
        ];
        assert_eq!(mode_of(&rules, "files", "read_file"), CaptureMode::Redacted);
        assert_eq!(mode_of(&rules, "files", "read_dir"), CaptureMode::Full);
        assert_eq!(mode_of(&rules, "files", "write"), CaptureMode::None);
    }

    #[test]
    fn the_higher_id_breaks_a_tie_whatever_the_order() {
        let old = rule(1, "files", "read_*", CaptureMode::Full);
        let new = rule(2, "files", "read_*", CaptureMode::None);
        assert_eq!(
            mode_of(&[old.clone(), new.clone()], "files", "read_file"),
            CaptureMode::None
        );
        assert_eq!(
            mode_of(&[new, old], "files", "read_file"),
            CaptureMode::None
        );
    }

    #[test]
    fn the_winning_rule_brings_its_drop_keys() {
        let mut specific = rule(2, "files", "write_file", CaptureMode::Redacted);
        specific.drop_keys = keys(&["content"]);
        let mut general = rule(1, "*", "*", CaptureMode::Full);
        general.drop_keys = keys(&["other"]);
        let rules = [general, specific];
        let (mode, drop_keys) = capture_for(&rules, "files", "write_file", None);
        assert_eq!(mode, CaptureMode::Redacted);
        assert_eq!(drop_keys, keys(&["content"]));
        let (_, drop_keys) = capture_for(&rules, "files", "read_file", None);
        assert_eq!(drop_keys, keys(&["other"]));
    }

    #[test]
    fn none_stores_nothing() {
        assert_eq!(
            prepare_arguments(&json!({"a": 1}), CaptureMode::None, &[]),
            None
        );
    }

    #[test]
    fn redacted_masks_sensitive_keys_at_any_depth() {
        let args = json!({
            "path": "/etc/hosts",
            "Password": "hunter2",
            "db_passwd": "x",
            "client_secret": "x",
            "access_token": "x",
            "Authorization": "Bearer abc",
            "API_KEY": "x",
            "apiKey": "x",
            "session_cookie": "x",
            "credentials": {"user": "root"},
            "private_key": "x",
            "nested": {"deep": [{"my-Token": "x", "ok": 1}]},
        });
        let prepared = prepare_arguments(&args, CaptureMode::Redacted, &[]).unwrap();
        assert_eq!(
            prepared,
            json!({
                "path": "/etc/hosts",
                "Password": "[redacted]",
                "db_passwd": "[redacted]",
                "client_secret": "[redacted]",
                "access_token": "[redacted]",
                "Authorization": "[redacted]",
                "API_KEY": "[redacted]",
                "apiKey": "[redacted]",
                "session_cookie": "[redacted]",
                "credentials": "[redacted]",
                "private_key": "[redacted]",
                "nested": {"deep": [{"my-Token": "[redacted]", "ok": 1}]},
            })
        );
    }

    #[test]
    fn redaction_masks_values_of_any_type() {
        let args = json!({"token": 12345, "secret": null, "passwords": ["a", "b"]});
        let prepared = prepare_arguments(&args, CaptureMode::Redacted, &[]).unwrap();
        assert_eq!(
            prepared,
            json!({"token": "[redacted]", "secret": "[redacted]", "passwords": "[redacted]"})
        );
    }

    #[test]
    fn full_keeps_sensitive_keys() {
        let args = json!({"password": "hunter2", "query": "select 1"});
        let prepared = prepare_arguments(&args, CaptureMode::Full, &[]).unwrap();
        assert_eq!(prepared, args);
    }

    #[test]
    fn drop_keys_remove_at_any_depth_in_both_modes() {
        let args = json!({
            "content": "big",
            "path": "a",
            "files": [{"Content": "x", "name": "f"}],
            "nested": {"content": {"deeper": 1}, "keep": true},
        });
        let expected = json!({
            "path": "a",
            "files": [{"name": "f"}],
            "nested": {"keep": true},
        });
        for mode in [CaptureMode::Redacted, CaptureMode::Full] {
            let prepared = prepare_arguments(&args, mode, &keys(&["content"])).unwrap();
            assert_eq!(prepared, expected, "mode {mode:?}");
        }
    }

    #[test]
    fn a_dropped_sensitive_key_leaves_no_trace() {
        let args = json!({"password": "x", "a": 1});
        let prepared =
            prepare_arguments(&args, CaptureMode::Redacted, &keys(&["password"])).unwrap();
        assert_eq!(prepared, json!({"a": 1}));
    }

    #[test]
    fn scalars_and_empty_values_pass_through() {
        for value in [json!(null), json!(7), json!(true), json!({}), json!([])] {
            for mode in [CaptureMode::Redacted, CaptureMode::Full] {
                assert_eq!(prepare_arguments(&value, mode, &[]), Some(value.clone()));
            }
        }
    }

    #[test]
    fn long_strings_are_truncated_in_both_modes() {
        let long = "a".repeat(5000);
        let args = json!({"text": long, "list": [long], "short": "ok"});
        for mode in [CaptureMode::Redacted, CaptureMode::Full] {
            let prepared = prepare_arguments(&args, mode, &[]).unwrap();
            let expected = format!("{}{TRUNCATED_SUFFIX}", "a".repeat(MAX_STRING_BYTES));
            assert_eq!(prepared["text"], json!(expected));
            assert_eq!(prepared["list"][0], json!(expected));
            assert_eq!(prepared["short"], json!("ok"));
        }
    }

    #[test]
    fn a_string_at_the_limit_is_kept() {
        let text = "b".repeat(MAX_STRING_BYTES);
        assert_eq!(truncate_string(&text, MAX_STRING_BYTES), text);
    }

    #[test]
    fn truncation_stays_on_a_char_boundary() {
        // 'é' is two bytes: the limit falls in the middle of one.
        let text = "é".repeat(MAX_STRING_BYTES);
        let cut = truncate_string(&text, MAX_STRING_BYTES);
        assert_eq!(
            cut,
            format!("{}{TRUNCATED_SUFFIX}", "é".repeat(MAX_STRING_BYTES / 2))
        );
        // Four-byte characters, limit at 2049 bytes into a character.
        let emoji = "😀".repeat(1000);
        let cut = truncate_string(&emoji, MAX_STRING_BYTES + 1);
        assert_eq!(
            cut,
            format!("{}{TRUNCATED_SUFFIX}", "😀".repeat(MAX_STRING_BYTES / 4))
        );
        assert_eq!(truncate_string("héllo", 2), format!("h{TRUNCATED_SUFFIX}"));
        assert_eq!(truncate_string("😀", 0), TRUNCATED_SUFFIX);
    }

    #[test]
    fn keys_are_never_truncated_or_altered() {
        let key = "k".repeat(5000);
        let mut map = serde_json::Map::new();
        map.insert(key, json!("v"));
        let args = Value::Object(map);
        let prepared = prepare_arguments(&args, CaptureMode::Full, &[]).unwrap();
        assert_eq!(prepared, args);
    }

    fn event(tool: &str) -> ToolCallEvent {
        ToolCallEvent {
            user_id: None,
            principal_label: "alice@example.com".to_owned(),
            token_id: None,
            auth_method: "pat".to_owned(),
            backend: "files".to_owned(),
            tool: tool.to_owned(),
            outcome: CallOutcome::Ok,
            error_code: None,
            error_message: None,
            duration: Duration::from_millis(12),
            trace_id: Some("abc".to_owned()),
            client_ip: Some("10.0.0.1".to_owned()),
            user_agent: None,
            arguments: json!({"path": "/x", "password": "p"}),
            annotations: None,
        }
    }

    #[test]
    fn rows_apply_the_capture_policy() {
        let rules = [rule(1, "files", "dump_*", CaptureMode::Full)];
        let mut read_only = event("read_file");
        read_only.annotations = Some(json!({"readOnlyHint": true}));
        let rows = build_rows(
            vec![event("write_file"), read_only, event("dump_all")],
            &rules,
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[0].arguments,
            Some((
                CaptureMode::Redacted,
                json!({"path": "/x", "password": "[redacted]"})
            ))
        );
        assert_eq!(rows[1].arguments, None);
        assert_eq!(
            rows[2].arguments,
            Some((CaptureMode::Full, json!({"path": "/x", "password": "p"})))
        );
        assert_eq!(rows[0].duration_ms, 12);
        assert_eq!(rows[0].tool, "write_file");
        assert_eq!(rows[0].outcome, CallOutcome::Ok);
    }

    #[test]
    fn rows_truncate_error_messages_and_saturate_durations() {
        let mut failing = event("read_file");
        failing.outcome = CallOutcome::Error;
        failing.error_code = Some(-32603);
        failing.error_message = Some("é".repeat(900));
        failing.duration = Duration::from_secs(u64::from(u32::MAX));
        let rows = build_rows(vec![failing], &[]);
        assert_eq!(
            rows[0].error_message.as_deref().map(|m| m.chars().count()),
            Some(MAX_ERROR_CHARS)
        );
        assert_eq!(rows[0].duration_ms, i32::MAX);
        assert_eq!(rows[0].error_code, Some(-32603));
    }

    #[tokio::test]
    async fn a_full_queue_drops_instead_of_blocking() {
        let (sink, mut rx) = AuditSink::channel(2);
        for _ in 0..5 {
            sink.record(event("read_file"));
        }
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, 2);
    }

    #[tokio::test]
    async fn recording_after_the_writer_is_gone_does_not_panic() {
        let (sink, rx) = AuditSink::channel(2);
        drop(rx);
        sink.record(event("read_file"));
    }

    #[tokio::test]
    async fn clones_feed_the_same_queue() {
        let (sink, mut rx) = AuditSink::channel(4);
        let other = sink.clone();
        sink.record(event("a"));
        other.record(event("b"));
        assert_eq!(rx.recv().await.map(|e| e.tool), Some("a".to_owned()));
        assert_eq!(rx.recv().await.map(|e| e.tool), Some("b".to_owned()));
    }
}
