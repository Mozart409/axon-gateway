//! The SCIM 2.0 protocol (RFC 7643, RFC 7644) without HTTP or a database:
//! `filter` parsing (`eq` only), PATCH operations in the shapes Entra ID and
//! Okta send, the resource JSON and the discovery documents.
//!
//! `server::scim_api` maps requests onto this and `store::scim` stores the
//! result. Leniency follows what the identity providers do: attribute names
//! and operations are case-insensitive, booleans may be strings (`"False"`),
//! a PATCH without a path carries an object, and attributes this gateway has
//! no use for (the enterprise extension, say) are accepted and dropped.

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::store::scim::{GroupChange, ScimEmail, ScimGroup, ScimMember, ScimUser, UserAttrs};

pub const CONTENT_TYPE: &str = "application/scim+json";
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONFIG_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RESOURCE_TYPE_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

/// The most resources a list answers with, advertised as `filter.maxResults`
pub const MAX_COUNT: i64 = 200;
/// Resources per page when the client does not ask
pub const DEFAULT_COUNT: i64 = 100;
/// Operations in one PATCH
const MAX_OPERATIONS: usize = 100;
/// Longest attribute value, in characters
const MAX_FIELD: usize = 512;
/// Emails of one user
const MAX_EMAILS: usize = 20;
/// Members in one request
const MAX_MEMBERS: usize = 10_000;

/// A SCIM error response: HTTP status, the optional `scimType` and the detail
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScimError {
    pub status: u16,
    pub scim_type: Option<&'static str>,
    pub detail: String,
}

impl ScimError {
    fn new(status: u16, scim_type: Option<&'static str>, detail: impl Into<String>) -> Self {
        Self {
            status,
            scim_type,
            detail: detail.into(),
        }
    }

    pub fn invalid_value(detail: impl Into<String>) -> Self {
        Self::new(400, Some("invalidValue"), detail)
    }

    pub fn invalid_syntax(detail: impl Into<String>) -> Self {
        Self::new(400, Some("invalidSyntax"), detail)
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self::new(400, Some("invalidFilter"), detail)
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self::new(400, Some("invalidPath"), detail)
    }

    pub fn no_target(detail: impl Into<String>) -> Self {
        Self::new(400, Some("noTarget"), detail)
    }

    pub fn mutability(detail: impl Into<String>) -> Self {
        Self::new(400, Some("mutability"), detail)
    }

    pub fn uniqueness(detail: impl Into<String>) -> Self {
        Self::new(409, Some("uniqueness"), detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, None, detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, None, detail)
    }

    pub fn too_many_requests() -> Self {
        Self::new(429, None, "too many requests")
    }

    pub fn unavailable() -> Self {
        Self::new(503, None, "the database is unavailable")
    }

    /// The error document; `status` is a string, as the RFC has it
    pub fn body(&self) -> Value {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.to_string(),
            "detail": self.detail,
        });
        if let (Some(scim_type), Some(map)) = (self.scim_type, body.as_object_mut()) {
            map.insert("scimType".to_owned(), json!(scim_type));
        }
        body
    }
}

/// `attribute eq "value"`, the only filter this endpoint has
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Lower case, without a schema URN prefix (`username`, `emails.value`)
    pub attr: String,
    pub value: String,
}

/// An attribute name as the protocol writes it: letters, digits and `. : _ - $`,
/// a schema URN prefix dropped, lower case. `None` for anything else.
fn normalize_attr(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-' | '$'))
    {
        return None;
    }
    let is_urn = raw
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:"));
    let name = if is_urn {
        raw.rsplit_once(':').map_or(raw, |(_, name)| name)
    } else {
        raw
    };
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// The end (exclusive) of the JSON string literal at the start of `text`
fn string_end(text: &str) -> Option<usize> {
    let mut chars = text.char_indices();
    if chars.next()?.1 != '"' {
        return None;
    }
    let mut escaped = false;
    for (index, c) in chars {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(index + 1);
        }
    }
    None
}

/// Parses `attribute eq "value"`. Attribute names and `eq` are
/// case-insensitive; the value is a JSON string (escapes included). Every
/// other operator, and `and`, `or`, `not` and parentheses, are `invalidFilter`.
///
/// # Errors
/// `invalidFilter` for anything but a single `eq` comparison with a string.
pub fn parse_filter(input: &str) -> Result<Filter, ScimError> {
    let unsupported =
        || ScimError::invalid_filter("only a single `attribute eq \"value\"` filter is supported");
    let (attr, rest) = input
        .trim()
        .split_once(char::is_whitespace)
        .ok_or_else(unsupported)?;
    let rest = rest.trim_start();
    let (operator, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(unsupported());
    }
    let attr = normalize_attr(attr).ok_or_else(unsupported)?;
    let value = value.trim();
    let end = string_end(value).ok_or_else(unsupported)?;
    let (literal, trailing) = (value.get(..end), value.get(end..));
    if trailing.is_none_or(|trailing| !trailing.trim().is_empty()) {
        return Err(unsupported());
    }
    let value: String = literal
        .and_then(|literal| serde_json::from_str(literal).ok())
        .ok_or_else(|| ScimError::invalid_filter("the filter value is not a valid string"))?;
    Ok(Filter { attr, value })
}

/// What a PATCH operation does
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpKind {
    Add,
    Replace,
    Remove,
}

/// A PATCH path: `attr`, `attr.sub`, `attr[filter]` or `attr[filter].sub`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPath {
    pub attr: String,
    pub sub: Option<String>,
    pub filter: Option<Filter>,
}

/// One operation of a PATCH
#[derive(Debug, Clone, PartialEq)]
pub struct PatchOp {
    pub kind: OpKind,
    /// `None` when the value is an object of attributes
    pub path: Option<PatchPath>,
    pub value: Option<Value>,
}

/// Splits `rest` (what follows a `[`) at the `]` outside quotes
fn split_bracket(rest: &str) -> Option<(&str, &str)> {
    let mut in_string = false;
    let mut escaped = false;
    for (index, c) in rest.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ']' {
            return Some((rest.get(..index)?, rest.get(index + 1..)?));
        }
    }
    None
}

/// Parses a PATCH `path`.
///
/// # Errors
/// `invalidPath` when it is not one of the forms above.
pub fn parse_path(raw: &str) -> Result<PatchPath, ScimError> {
    let bad = || ScimError::invalid_path(format!("cannot parse the path {raw:?}"));
    let (head, bracket) = match raw.trim().split_once('[') {
        Some((head, rest)) => (head, Some(rest)),
        None => (raw, None),
    };
    let head = normalize_attr(head).ok_or_else(bad)?;
    let (attr, mut sub) = match head.split_once('.') {
        Some((attr, sub)) => (attr.to_owned(), Some(sub.to_owned())),
        None => (head, None),
    };
    if attr.is_empty()
        || sub
            .as_deref()
            .is_some_and(|sub| sub.is_empty() || sub.contains('.'))
    {
        return Err(bad());
    }
    let mut filter = None;
    if let Some(rest) = bracket {
        let (inner, after) = split_bracket(rest).ok_or_else(bad)?;
        filter = Some(parse_filter(inner)?);
        let after = after.trim();
        if let Some(name) = after.strip_prefix('.') {
            sub = Some(normalize_attr(name).ok_or_else(bad)?);
        } else if !after.is_empty() {
            return Err(bad());
        }
    }
    Ok(PatchPath { attr, sub, filter })
}

/// The value of `name` in a JSON object, whatever its case
fn field<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// Parses the body of a PATCH.
///
/// # Errors
/// `invalidSyntax` or `invalidPath` for a body that is no `PatchOp`, `noTarget`
/// for a remove without a path, `invalidValue` for an add or replace without
/// a value.
pub fn parse_patch(body: &Value) -> Result<Vec<PatchOp>, ScimError> {
    let operations = body
        .as_object()
        .and_then(|map| field(map, "operations"))
        .and_then(Value::as_array)
        .ok_or_else(|| ScimError::invalid_syntax("a PATCH needs an Operations array"))?;
    if operations.is_empty() || operations.len() > MAX_OPERATIONS {
        return Err(ScimError::invalid_value(format!(
            "a PATCH carries 1 to {MAX_OPERATIONS} operations"
        )));
    }
    operations.iter().map(parse_op).collect()
}

fn parse_op(op: &Value) -> Result<PatchOp, ScimError> {
    let map = op
        .as_object()
        .ok_or_else(|| ScimError::invalid_syntax("an operation must be an object"))?;
    let kind = match field(map, "op")
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("add") => OpKind::Add,
        Some("replace") => OpKind::Replace,
        Some("remove") => OpKind::Remove,
        _ => {
            return Err(ScimError::invalid_syntax(
                "op must be add, remove or replace",
            ));
        }
    };
    let path = match field(map, "path") {
        Some(Value::String(path)) if !path.trim().is_empty() => Some(parse_path(path)?),
        None | Some(Value::Null | Value::String(_)) => None,
        Some(_) => return Err(ScimError::invalid_path("path must be a string")),
    };
    let value = field(map, "value").cloned();
    match (kind, &path, &value) {
        (OpKind::Remove, None, _) => Err(ScimError::no_target("remove needs a path")),
        (OpKind::Add | OpKind::Replace, _, None) => {
            Err(ScimError::invalid_value("add and replace need a value"))
        }
        _ => Ok(PatchOp { kind, path, value }),
    }
}

/// A string attribute: trimmed, empty or null is `None`
fn string_value(value: Option<&Value>) -> Result<Option<String>, ScimError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            if text.chars().count() > MAX_FIELD {
                return Err(ScimError::invalid_value(format!(
                    "a value is longer than {MAX_FIELD} characters"
                )));
            }
            let text = text.trim();
            Ok((!text.is_empty()).then(|| text.to_owned()))
        }
        Some(_) => Err(ScimError::invalid_value("expected a string")),
    }
}

/// A boolean, or the strings `true` and `false` in any case (Entra sends
/// `"False"`)
fn bool_value(value: Option<&Value>) -> Result<bool, ScimError> {
    match value {
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("true") => Ok(true),
        Some(Value::String(text)) if text.trim().eq_ignore_ascii_case("false") => Ok(false),
        _ => Err(ScimError::invalid_value("expected true or false")),
    }
}

fn clear_name(attrs: &mut UserAttrs) {
    attrs.given_name = None;
    attrs.family_name = None;
    attrs.name_formatted = None;
}

fn set_name_part(
    attrs: &mut UserAttrs,
    part: &str,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match part.to_ascii_lowercase().as_str() {
        "givenname" => attrs.given_name = string_value(value)?,
        "familyname" => attrs.family_name = string_value(value)?,
        "formatted" => attrs.name_formatted = string_value(value)?,
        _ => {}
    }
    Ok(())
}

fn set_name(attrs: &mut UserAttrs, replace: bool, value: Option<&Value>) -> Result<(), ScimError> {
    match value {
        None | Some(Value::Null) => clear_name(attrs),
        Some(Value::Object(map)) => {
            if replace {
                clear_name(attrs);
            }
            for (part, value) in map {
                set_name_part(attrs, part, Some(value))?;
            }
        }
        Some(_) => return Err(ScimError::invalid_value("name must be an object")),
    }
    Ok(())
}

fn email_matches(email: &ScimEmail, filter: &Filter) -> bool {
    match filter.attr.as_str() {
        "value" => email.value.eq_ignore_ascii_case(&filter.value),
        "type" => email
            .kind
            .as_deref()
            .is_some_and(|kind| kind.eq_ignore_ascii_case(&filter.value)),
        "primary" => bool_value(Some(&Value::String(filter.value.clone())))
            .is_ok_and(|flag| email.primary.unwrap_or(false) == flag),
        _ => false,
    }
}

fn set_email_field(
    email: &mut ScimEmail,
    field: &str,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match field {
        "value" => {
            email.value = string_value(value)?
                .ok_or_else(|| ScimError::invalid_value("an email needs a value"))?;
        }
        "type" => email.kind = string_value(value)?,
        "primary" => email.primary = Some(bool_value(value)?),
        _ => {}
    }
    Ok(())
}

/// `emails` values: an array of objects, or one object
fn parse_emails(value: Option<&Value>) -> Result<Vec<ScimEmail>, ScimError> {
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().collect::<Vec<_>>(),
        Some(item @ Value::Object(_)) => vec![item],
        Some(_) => return Err(ScimError::invalid_value("emails must be an array")),
    };
    if items.len() > MAX_EMAILS {
        return Err(ScimError::invalid_value(format!(
            "at most {MAX_EMAILS} emails"
        )));
    }
    items
        .into_iter()
        .map(|item| {
            let map = item
                .as_object()
                .ok_or_else(|| ScimError::invalid_value("an email must be an object"))?;
            let mut email = ScimEmail::default();
            for (name, value) in map {
                set_email_field(&mut email, &name.to_ascii_lowercase(), Some(value))?;
            }
            if email.value.is_empty() {
                return Err(ScimError::invalid_value("an email needs a value"));
            }
            Ok(email)
        })
        .collect()
}

fn set_emails(
    attrs: &mut UserAttrs,
    kind: OpKind,
    path: &PatchPath,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    if path.filter.is_none() && path.sub.is_none() {
        match kind {
            OpKind::Remove => attrs.emails.clear(),
            OpKind::Replace => attrs.emails = parse_emails(value)?,
            OpKind::Add => {
                for email in parse_emails(value)? {
                    if !attrs
                        .emails
                        .iter()
                        .any(|known| known.value.eq_ignore_ascii_case(&email.value))
                    {
                        attrs.emails.push(email);
                    }
                }
            }
        }
        return Ok(());
    }

    let selected = |email: &ScimEmail| {
        path.filter
            .as_ref()
            .is_none_or(|filter| email_matches(email, filter))
    };
    if kind == OpKind::Remove {
        match path.sub.as_deref() {
            None | Some("value") => attrs.emails.retain(|email| !selected(email)),
            Some("type") => {
                for email in attrs.emails.iter_mut().filter(|email| selected(email)) {
                    email.kind = None;
                }
            }
            Some("primary") => {
                for email in attrs.emails.iter_mut().filter(|email| selected(email)) {
                    email.primary = None;
                }
            }
            Some(_) => {}
        }
        return Ok(());
    }

    // `emails[type eq "work"].value` and `emails[type eq "work"]` with an
    // object: set it on the emails that match, or add one that does
    let set = |email: &mut ScimEmail| -> Result<(), ScimError> {
        if let Some(sub) = path.sub.as_deref() {
            set_email_field(email, sub, value)
        } else {
            let Some(Value::Object(map)) = value else {
                return Err(ScimError::invalid_value("an email must be an object"));
            };
            for (name, value) in map {
                set_email_field(email, &name.to_ascii_lowercase(), Some(value))?;
            }
            Ok(())
        }
    };
    let mut matched = false;
    for email in attrs.emails.iter_mut().filter(|email| selected(email)) {
        set(email)?;
        matched = true;
    }
    if !matched {
        if attrs.emails.len() >= MAX_EMAILS {
            return Err(ScimError::invalid_value(format!(
                "at most {MAX_EMAILS} emails"
            )));
        }
        let mut email = ScimEmail::default();
        if let Some(filter) = &path.filter {
            set_email_field(
                &mut email,
                &filter.attr,
                Some(&Value::String(filter.value.clone())),
            )?;
        }
        set(&mut email)?;
        if email.value.is_empty() {
            return Err(ScimError::invalid_value("an email needs a value"));
        }
        attrs.emails.push(email);
    }
    Ok(())
}

/// Applies one attribute write to a user. Unknown attributes are ignored.
fn set_user_attr(
    attrs: &mut UserAttrs,
    kind: OpKind,
    path: &PatchPath,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    let removing = kind == OpKind::Remove;
    let value = if removing { None } else { value };
    match (path.attr.as_str(), path.sub.as_deref()) {
        ("username", None) => {
            if removing {
                return Err(ScimError::mutability("userName cannot be removed"));
            }
            attrs.user_name = string_value(value)?
                .ok_or_else(|| ScimError::invalid_value("userName must not be empty"))?;
        }
        ("externalid", None) => attrs.external_id = string_value(value)?,
        ("displayname", None) => attrs.display_name = string_value(value)?,
        ("active", None) => {
            if removing {
                return Err(ScimError::mutability("active cannot be removed"));
            }
            attrs.active = bool_value(value)?;
        }
        ("name", None) => set_name(attrs, kind != OpKind::Add, value)?,
        ("name", Some(part)) => set_name_part(attrs, part, value)?,
        ("emails", _) => set_emails(attrs, kind, path, value)?,
        _ => {}
    }
    Ok(())
}

/// The attributes of a user from a POST or PUT body (every attribute not in
/// the body is unset, `active` defaults to true).
///
/// # Errors
/// `invalidSyntax` for a body that is no object, `invalidValue` for a missing
/// `userName` or a value of the wrong type.
pub fn user_attrs_from_json(body: &Value) -> Result<UserAttrs, ScimError> {
    let map = body
        .as_object()
        .ok_or_else(|| ScimError::invalid_syntax("the body must be a JSON object"))?;
    let mut attrs = UserAttrs::default();
    for (key, value) in map {
        // A key that is no attribute name is not one this endpoint knows
        let Ok(path) = parse_path(key) else {
            continue;
        };
        if matches!(path.attr.as_str(), "schemas" | "id" | "meta" | "groups") {
            continue;
        }
        set_user_attr(&mut attrs, OpKind::Replace, &path, Some(value))?;
    }
    if attrs.user_name.is_empty() {
        return Err(ScimError::invalid_value("userName is required"));
    }
    Ok(attrs)
}

/// Applies the operations of a PATCH to a user's attributes.
///
/// # Errors
/// `invalidValue`, `invalidPath` or `mutability` for an operation that does
/// not fit the attribute.
pub fn apply_user_patch(attrs: &mut UserAttrs, ops: &[PatchOp]) -> Result<(), ScimError> {
    for op in ops {
        if let Some(path) = &op.path {
            set_user_attr(attrs, op.kind, path, op.value.as_ref())?;
        } else {
            let Some(Value::Object(map)) = &op.value else {
                return Err(ScimError::invalid_value(
                    "a patch without a path needs an object of attributes",
                ));
            };
            for (key, value) in map {
                let path = parse_path(key)?;
                set_user_attr(attrs, op.kind, &path, Some(value))?;
            }
        }
    }
    if attrs.user_name.is_empty() {
        return Err(ScimError::invalid_value("userName must not be empty"));
    }
    Ok(())
}

/// The attributes of a group a client writes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAttrs {
    pub display_name: String,
    pub external_id: Option<String>,
    /// SCIM user ids
    pub members: Vec<Uuid>,
}

/// The ids in a `members` value: an array of `{"value": "<id>"}`. With
/// `strict` an entry that is no id is an error, otherwise it is skipped (it
/// cannot name a member).
fn member_ids(value: Option<&Value>, strict: bool) -> Result<Vec<Uuid>, ScimError> {
    let items = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items.iter().collect::<Vec<_>>(),
        Some(item @ Value::Object(_)) => vec![item],
        Some(_) => return Err(ScimError::invalid_value("members must be an array")),
    };
    if items.len() > MAX_MEMBERS {
        return Err(ScimError::invalid_value(format!(
            "at most {MAX_MEMBERS} members per request"
        )));
    }
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .as_object()
            .and_then(|map| field(map, "value"))
            .and_then(Value::as_str)
            .and_then(|text| Uuid::parse_str(text.trim()).ok());
        match id {
            Some(id) => ids.push(id),
            None if strict => {
                return Err(ScimError::invalid_value(
                    "a member needs the id of a user in `value`",
                ));
            }
            None => {}
        }
    }
    Ok(ids)
}

/// The attributes of a group from a POST or PUT body.
///
/// # Errors
/// `invalidSyntax` for a body that is no object, `invalidValue` for a missing
/// `displayName` or a member that is no id.
pub fn group_attrs_from_json(body: &Value) -> Result<GroupAttrs, ScimError> {
    let map = body
        .as_object()
        .ok_or_else(|| ScimError::invalid_syntax("the body must be a JSON object"))?;
    let mut display_name = None;
    let mut external_id = None;
    let mut members = Vec::new();
    for (key, value) in map {
        match normalize_attr(key).as_deref() {
            Some("displayname") => display_name = string_value(Some(value))?,
            Some("externalid") => external_id = string_value(Some(value))?,
            Some("members") => members = member_ids(Some(value), true)?,
            _ => {}
        }
    }
    let display_name =
        display_name.ok_or_else(|| ScimError::invalid_value("displayName is required"))?;
    Ok(GroupAttrs {
        display_name,
        external_id,
        members,
    })
}

fn group_change(
    changes: &mut Vec<GroupChange>,
    kind: OpKind,
    path: &PatchPath,
    value: Option<&Value>,
) -> Result<(), ScimError> {
    match (path.attr.as_str(), path.sub.as_deref()) {
        ("displayname", None) => {
            if kind == OpKind::Remove {
                return Err(ScimError::mutability("displayName cannot be removed"));
            }
            let name = string_value(value)?
                .ok_or_else(|| ScimError::invalid_value("displayName must not be empty"))?;
            changes.push(GroupChange::SetDisplayName(name));
        }
        ("externalid", None) => {
            let external_id = if kind == OpKind::Remove {
                None
            } else {
                string_value(value)?
            };
            changes.push(GroupChange::SetExternalId(external_id));
        }
        ("members", _) => match (kind, &path.filter) {
            (OpKind::Remove, Some(filter)) if filter.attr == "value" => {
                // An id that parses to nothing names no member
                changes.push(GroupChange::RemoveMembers(
                    Uuid::parse_str(filter.value.trim()).into_iter().collect(),
                ));
            }
            (_, Some(_)) => {
                return Err(ScimError::invalid_path(
                    "members can only be selected with `value eq \"<id>\"` to remove one",
                ));
            }
            (OpKind::Remove, None) => {
                if value.is_some_and(|value| !value.is_null()) {
                    changes.push(GroupChange::RemoveMembers(member_ids(value, false)?));
                } else {
                    changes.push(GroupChange::ReplaceMembers(Vec::new()));
                }
            }
            (OpKind::Add, None) => changes.push(GroupChange::AddMembers(member_ids(value, true)?)),
            (OpKind::Replace, None) => {
                changes.push(GroupChange::ReplaceMembers(member_ids(value, true)?));
            }
        },
        _ => {}
    }
    Ok(())
}

/// The changes a PATCH makes to a group, in order.
///
/// # Errors
/// `invalidValue`, `invalidPath` or `mutability` for an operation that does
/// not fit the attribute.
pub fn group_changes(ops: &[PatchOp]) -> Result<Vec<GroupChange>, ScimError> {
    let mut changes = Vec::new();
    for op in ops {
        if let Some(path) = &op.path {
            group_change(&mut changes, op.kind, path, op.value.as_ref())?;
        } else {
            let Some(Value::Object(map)) = &op.value else {
                return Err(ScimError::invalid_value(
                    "a patch without a path needs an object of attributes",
                ));
            };
            for (key, value) in map {
                let path = parse_path(key)?;
                group_change(&mut changes, op.kind, &path, Some(value))?;
            }
        }
    }
    Ok(changes)
}

/// `startIndex` (from 1) and `count` of a list request: defaults for what is
/// missing or no number, `count` capped at [`MAX_COUNT`].
#[must_use]
pub fn page(start_index: Option<&str>, count: Option<&str>) -> (i64, i64) {
    let start_index = start_index
        .and_then(|text| text.trim().parse::<i64>().ok())
        .map_or(1, |index| index.max(1));
    let count = count
        .and_then(|text| text.trim().parse::<i64>().ok())
        .map_or(DEFAULT_COUNT, |count| count.clamp(0, MAX_COUNT));
    (start_index, count)
}

fn timestamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn meta(kind: &str, created: DateTime<Utc>, modified: DateTime<Utc>, location: &str) -> Value {
    json!({
        "resourceType": kind,
        "created": timestamp(created),
        "lastModified": timestamp(modified),
        "location": location,
    })
}

/// The User resource. `base` is `<base_url>/scim/v2/<provider>`.
#[must_use]
pub fn user_resource(base: &str, user: &ScimUser) -> Value {
    let mut map = Map::new();
    map.insert("schemas".to_owned(), json!([USER_SCHEMA]));
    map.insert("id".to_owned(), json!(user.id));
    if let Some(external_id) = &user.external_id {
        map.insert("externalId".to_owned(), json!(external_id));
    }
    map.insert("userName".to_owned(), json!(user.user_name));
    let mut name = Map::new();
    for (key, part) in [
        ("formatted", &user.name_formatted),
        ("givenName", &user.given_name),
        ("familyName", &user.family_name),
    ] {
        if let Some(part) = part {
            name.insert(key.to_owned(), json!(part));
        }
    }
    if !name.is_empty() {
        map.insert("name".to_owned(), Value::Object(name));
    }
    if let Some(display_name) = &user.display_name {
        map.insert("displayName".to_owned(), json!(display_name));
    }
    if user
        .emails
        .as_array()
        .is_some_and(|emails| !emails.is_empty())
    {
        map.insert("emails".to_owned(), user.emails.clone());
    }
    map.insert("active".to_owned(), json!(user.active));
    map.insert(
        "meta".to_owned(),
        meta(
            "User",
            user.created_at,
            user.updated_at,
            &format!("{base}/Users/{}", user.id),
        ),
    );
    Value::Object(map)
}

/// The Group resource; `members` is `None` when the client excluded them.
#[must_use]
pub fn group_resource(base: &str, group: &ScimGroup, members: Option<&[ScimMember]>) -> Value {
    let mut map = Map::new();
    map.insert("schemas".to_owned(), json!([GROUP_SCHEMA]));
    map.insert("id".to_owned(), json!(group.id));
    if let Some(external_id) = &group.external_id {
        map.insert("externalId".to_owned(), json!(external_id));
    }
    map.insert("displayName".to_owned(), json!(group.display_name));
    if let Some(members) = members {
        let members: Vec<Value> = members
            .iter()
            .filter(|member| member.group_id == group.id)
            .map(|member| {
                json!({
                    "value": member.user_id,
                    "$ref": format!("{base}/Users/{}", member.user_id),
                    "display": member.user_name,
                    "type": "User",
                })
            })
            .collect();
        map.insert("members".to_owned(), Value::Array(members));
    }
    map.insert(
        "meta".to_owned(),
        meta(
            "Group",
            group.created_at,
            group.updated_at,
            &format!("{base}/Groups/{}", group.id),
        ),
    );
    Value::Object(map)
}

/// A `ListResponse` of one page of `resources` out of `total`
#[must_use]
pub fn list_response(resources: &[Value], total: i64, start_index: i64) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// `GET /ServiceProviderConfig`: PATCH and filters (`eq` only) are supported,
/// nothing else is.
#[must_use]
pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": [CONFIG_SCHEMA],
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": MAX_COUNT },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "A SCIM token created on the gateway's admin page, sent as a bearer token",
            "specUri": "https://www.rfc-editor.org/info/rfc6750",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig"),
        },
    })
}

/// `GET /ResourceTypes`
#[must_use]
pub fn resource_types(base: &str) -> Value {
    let types = [
        ("User", "/Users", "User Account", USER_SCHEMA),
        ("Group", "/Groups", "Group", GROUP_SCHEMA),
    ];
    let resources = types
        .into_iter()
        .map(|(name, endpoint, description, schema)| {
            json!({
                "schemas": [RESOURCE_TYPE_SCHEMA],
                "id": name,
                "name": name,
                "endpoint": endpoint,
                "description": description,
                "schema": schema,
                "meta": {
                    "resourceType": "ResourceType",
                    "location": format!("{base}/ResourceTypes/{name}"),
                },
            })
        })
        .collect::<Vec<_>>();
    let total = i64::try_from(resources.len()).unwrap_or(0);
    list_response(&resources, total, 1)
}

fn attribute(
    name: &str,
    kind: &str,
    multi_valued: bool,
    required: bool,
    mutability: &str,
    sub_attributes: &[Value],
) -> Value {
    let mut attribute = json!({
        "name": name,
        "type": kind,
        "multiValued": multi_valued,
        "required": required,
        "caseExact": false,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": "none",
    });
    if !sub_attributes.is_empty()
        && let Some(map) = attribute.as_object_mut()
    {
        map.insert("subAttributes".to_owned(), json!(sub_attributes));
    }
    attribute
}

/// `GET /Schemas`: the User and Group attributes this endpoint stores
#[must_use]
pub fn schemas(base: &str) -> Value {
    let mut user_name = attribute("userName", "string", false, true, "readWrite", &[]);
    if let Some(map) = user_name.as_object_mut() {
        map.insert("uniqueness".to_owned(), json!("server"));
    }
    let user_attributes = [
        user_name,
        attribute("externalId", "string", false, false, "readWrite", &[]),
        attribute("displayName", "string", false, false, "readWrite", &[]),
        attribute(
            "name",
            "complex",
            false,
            false,
            "readWrite",
            &[
                attribute("formatted", "string", false, false, "readWrite", &[]),
                attribute("givenName", "string", false, false, "readWrite", &[]),
                attribute("familyName", "string", false, false, "readWrite", &[]),
            ],
        ),
        attribute(
            "emails",
            "complex",
            true,
            false,
            "readWrite",
            &[
                attribute("value", "string", false, false, "readWrite", &[]),
                attribute("type", "string", false, false, "readWrite", &[]),
                attribute("primary", "boolean", false, false, "readWrite", &[]),
            ],
        ),
        attribute("active", "boolean", false, false, "readWrite", &[]),
    ];
    let group_attributes = [
        attribute("displayName", "string", false, true, "readWrite", &[]),
        attribute("externalId", "string", false, false, "readWrite", &[]),
        attribute(
            "members",
            "complex",
            true,
            false,
            "readWrite",
            &[
                attribute("value", "string", false, false, "immutable", &[]),
                attribute("$ref", "reference", false, false, "immutable", &[]),
                attribute("display", "string", false, false, "readOnly", &[]),
                attribute("type", "string", false, false, "immutable", &[]),
            ],
        ),
    ];
    let schema = |id: &str, name: &str, description: &str, attributes: &[Value]| {
        json!({
            "schemas": [SCHEMA_SCHEMA],
            "id": id,
            "name": name,
            "description": description,
            "attributes": attributes,
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{id}") },
        })
    };
    list_response(
        &[
            schema(USER_SCHEMA, "User", "User Account", &user_attributes),
            schema(GROUP_SCHEMA, "Group", "Group", &group_attributes),
        ],
        2,
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(input: &str) -> Filter {
        parse_filter(input).unwrap()
    }

    fn user_row() -> ScimUser {
        let at = "2026-10-05T12:00:00Z".parse().unwrap();
        ScimUser {
            id: Uuid::nil(),
            provider: "mock".to_owned(),
            user_name: "alice@example.com".to_owned(),
            external_id: Some("alice-sub".to_owned()),
            display_name: Some("Alice".to_owned()),
            given_name: Some("Alice".to_owned()),
            family_name: None,
            name_formatted: None,
            emails: json!([{ "value": "alice@example.com", "type": "work", "primary": true }]),
            active: true,
            user_id: None,
            linked_by: None,
            created_at: at,
            updated_at: at,
        }
    }

    fn ops(body: &Value) -> Vec<PatchOp> {
        parse_patch(body).unwrap()
    }

    fn patched(attrs: &mut UserAttrs, body: &Value) {
        apply_user_patch(attrs, &ops(body)).unwrap();
    }

    fn attrs() -> UserAttrs {
        UserAttrs {
            user_name: "alice@example.com".to_owned(),
            ..UserAttrs::default()
        }
    }

    #[test]
    fn a_filter_is_an_eq_on_one_attribute() {
        assert_eq!(
            filter(r#"userName eq "alice@example.com""#),
            Filter {
                attr: "username".to_owned(),
                value: "alice@example.com".to_owned()
            }
        );
        assert_eq!(filter(r#"  EXTERNALID EQ "x" "#).attr, "externalid");
        assert_eq!(filter(r#"displayName Eq "Ops""#).value, "Ops");
        // a schema URN prefix is dropped
        assert_eq!(
            filter(r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a""#).attr,
            "username"
        );
    }

    #[test]
    fn a_filter_value_is_a_json_string() {
        assert_eq!(
            filter(r#"userName eq "a \"quoted\" name""#).value,
            "a \"quoted\" name"
        );
        assert_eq!(filter(r#"userName eq "back\\slash""#).value, "back\\slash");
        assert_eq!(filter(r#"userName eq "café""#).value, "caf\u{e9}");
        assert_eq!(filter(r#"userName eq "a eq b""#).value, "a eq b");
        assert_eq!(filter(r#"userName eq """#).value, "");
    }

    #[test]
    fn every_other_filter_is_invalid() {
        for input in [
            r#"userName ne "a""#,
            r#"userName co "a""#,
            r#"userName sw "a""#,
            r"userName pr",
            r#"meta.lastModified gt "2020-01-01T00:00:00Z""#,
            r#"userName eq "a" and active eq "true""#,
            r#"userName eq "a" or userName eq "b""#,
            r#"not (userName eq "a")"#,
            r#"(userName eq "a")"#,
            r"active eq true",
            r#"userName eq "unterminated"#,
            r"userName",
            "",
        ] {
            let error = parse_filter(input).unwrap_err();
            assert_eq!(error.status, 400, "{input}");
            assert_eq!(error.scim_type, Some("invalidFilter"), "{input}");
        }
    }

    #[test]
    fn a_path_has_an_attribute_a_filter_and_a_sub_attribute() {
        let path = parse_path("active").unwrap();
        assert_eq!(
            (path.attr.as_str(), path.sub, path.filter),
            ("active", None, None)
        );

        let path = parse_path("name.givenName").unwrap();
        assert_eq!(path.attr, "name");
        assert_eq!(path.sub.as_deref(), Some("givenname"));

        let path = parse_path(r#"members[value eq "abc"]"#).unwrap();
        assert_eq!(path.attr, "members");
        assert_eq!(path.filter.unwrap().value, "abc");

        let path = parse_path(r#"emails[type eq "work"].value"#).unwrap();
        assert_eq!(path.attr, "emails");
        assert_eq!(path.sub.as_deref(), Some("value"));
        assert_eq!(path.filter.unwrap().attr, "type");

        let path = parse_path(r#"emails[value eq "a]b"]"#).unwrap();
        assert_eq!(path.filter.unwrap().value, "a]b");

        for bad in [
            "",
            "name..",
            r#"members[value eq "a""#,
            r#"members[value eq "a"]x"#,
        ] {
            assert_eq!(parse_path(bad).unwrap_err().status, 400, "{bad}");
        }
    }

    #[test]
    fn entra_replaces_active_with_a_capitalised_op_and_a_string_boolean() {
        let mut user = attrs();
        patched(
            &mut user,
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [{ "op": "Replace", "path": "active", "value": "False" }],
            }),
        );
        assert!(!user.active);
        patched(
            &mut user,
            &json!({ "Operations": [{ "op": "replace", "path": "active", "value": "True" }] }),
        );
        assert!(user.active);
        patched(
            &mut user,
            &json!({ "Operations": [{ "op": "Replace", "path": "active", "value": false }] }),
        );
        assert!(!user.active);
    }

    #[test]
    fn a_pathless_replace_carries_an_object_of_attributes() {
        let mut user = attrs();
        patched(
            &mut user,
            &json!({ "Operations": [{
                "op": "replace",
                "value": {
                    "active": "False",
                    "displayName": "Alice A",
                    "name": { "givenName": "Alice", "familyName": "A" },
                    "externalId": "ext-1",
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "ops",
                    "name.formatted": "Alice A",
                },
            }] }),
        );
        assert!(!user.active);
        assert_eq!(user.display_name.as_deref(), Some("Alice A"));
        assert_eq!(user.given_name.as_deref(), Some("Alice"));
        assert_eq!(user.family_name.as_deref(), Some("A"));
        assert_eq!(user.name_formatted.as_deref(), Some("Alice A"));
        assert_eq!(user.external_id.as_deref(), Some("ext-1"));
    }

    #[test]
    fn a_patch_sets_and_removes_name_parts_and_emails() {
        let mut user = attrs();
        patched(
            &mut user,
            &json!({ "Operations": [
                { "op": "Add", "path": "name.givenName", "value": "Alice" },
                { "op": "Add", "path": "emails[type eq \"work\"].value", "value": "a@work.example" },
                { "op": "Add", "path": "emails", "value": [{ "value": "a@home.example", "type": "home" }] },
            ] }),
        );
        assert_eq!(user.given_name.as_deref(), Some("Alice"));
        assert_eq!(user.emails.len(), 2);
        assert_eq!(user.emails.first().unwrap().kind.as_deref(), Some("work"));

        patched(
            &mut user,
            &json!({ "Operations": [
                { "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "b@work.example" },
                { "op": "Remove", "path": "name.givenName" },
                { "op": "Remove", "path": "emails[type eq \"home\"]" },
            ] }),
        );
        assert_eq!(user.given_name, None);
        assert_eq!(user.emails.len(), 1);
        assert_eq!(user.emails.first().unwrap().value, "b@work.example");
    }

    #[test]
    fn a_patch_cannot_remove_the_user_name_or_empty_it() {
        let mut user = attrs();
        let remove = ops(&json!({ "Operations": [{ "op": "remove", "path": "userName" }] }));
        assert_eq!(
            apply_user_patch(&mut user, &remove).unwrap_err().scim_type,
            Some("mutability")
        );
        let blank =
            ops(&json!({ "Operations": [{ "op": "replace", "path": "userName", "value": "" }] }));
        assert_eq!(
            apply_user_patch(&mut user, &blank).unwrap_err().scim_type,
            Some("invalidValue")
        );
    }

    #[test]
    fn a_malformed_patch_is_a_400() {
        for body in [
            json!({}),
            json!({ "Operations": [] }),
            json!({ "Operations": [{ "op": "move", "path": "active", "value": true }] }),
            json!({ "Operations": [{ "op": "remove" }] }),
            json!({ "Operations": [{ "op": "replace", "path": "active" }] }),
            json!({ "Operations": ["nope"] }),
        ] {
            assert_eq!(parse_patch(&body).unwrap_err().status, 400, "{body}");
        }
        let mut user = attrs();
        let bad_bool = ops(
            &json!({ "Operations": [{ "op": "replace", "path": "active", "value": "maybe" }] }),
        );
        assert_eq!(
            apply_user_patch(&mut user, &bad_bool).unwrap_err().status,
            400
        );
    }

    #[test]
    fn a_user_body_needs_a_user_name_and_defaults_to_active() {
        let user = user_attrs_from_json(&json!({
            "schemas": [USER_SCHEMA],
            "userName": "bob@example.com",
            "externalId": "bob-sub",
            "name": { "givenName": "Bob", "familyName": "B" },
            "emails": [{ "value": "bob@example.com", "type": "work", "primary": true }],
            "groups": [],
        }))
        .unwrap();
        assert_eq!(user.user_name, "bob@example.com");
        assert_eq!(user.external_id.as_deref(), Some("bob-sub"));
        assert!(user.active);
        assert_eq!(user.family_name.as_deref(), Some("B"));
        assert_eq!(user.emails.len(), 1);

        for body in [
            json!({ "userName": "" }),
            json!({ "displayName": "x" }),
            json!([]),
        ] {
            assert_eq!(
                user_attrs_from_json(&body).unwrap_err().status,
                400,
                "{body}"
            );
        }
        let inactive =
            user_attrs_from_json(&json!({ "userName": "c", "active": "false" })).unwrap();
        assert!(!inactive.active);
    }

    #[test]
    fn group_patches_add_remove_and_replace_members() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let changes = group_changes(&ops(&json!({ "Operations": [
            { "op": "Add", "path": "members", "value": [{ "value": a.to_string() }] },
            { "op": "Remove", "path": format!("members[value eq \"{b}\"]") },
            { "op": "Remove", "path": "members", "value": [{ "value": a.to_string() }] },
            { "op": "Replace", "path": "members", "value": [{ "value": b.to_string() }] },
            { "op": "Remove", "path": "members" },
            { "op": "Replace", "path": "displayName", "value": "Ops" },
            { "op": "replace", "value": { "externalId": "g-1" } },
        ] })))
        .unwrap();
        assert_eq!(
            changes,
            vec![
                GroupChange::AddMembers(vec![a]),
                GroupChange::RemoveMembers(vec![b]),
                GroupChange::RemoveMembers(vec![a]),
                GroupChange::ReplaceMembers(vec![b]),
                GroupChange::ReplaceMembers(vec![]),
                GroupChange::SetDisplayName("Ops".to_owned()),
                GroupChange::SetExternalId(Some("g-1".to_owned())),
            ]
        );
    }

    #[test]
    fn a_member_that_is_no_id_cannot_be_added_but_removing_it_is_a_no_op() {
        let add = ops(
            &json!({ "Operations": [{ "op": "add", "path": "members", "value": [{ "value": "nope" }] }] }),
        );
        assert_eq!(
            group_changes(&add).unwrap_err().scim_type,
            Some("invalidValue")
        );
        let remove = ops(
            &json!({ "Operations": [{ "op": "remove", "path": "members[value eq \"nope\"]" }] }),
        );
        assert_eq!(
            group_changes(&remove).unwrap(),
            vec![GroupChange::RemoveMembers(vec![])]
        );
    }

    #[test]
    fn a_group_body_needs_a_display_name() {
        let id = Uuid::new_v4();
        let group = group_attrs_from_json(&json!({
            "displayName": "Ops",
            "externalId": "g-1",
            "members": [{ "value": id.to_string(), "display": "x" }],
        }))
        .unwrap();
        assert_eq!(group.display_name, "Ops");
        assert_eq!(group.external_id.as_deref(), Some("g-1"));
        assert_eq!(group.members, vec![id]);
        assert_eq!(
            group_attrs_from_json(&json!({ "members": [] }))
                .unwrap_err()
                .status,
            400
        );
    }

    #[test]
    fn paging_has_defaults_and_a_cap() {
        assert_eq!(page(None, None), (1, DEFAULT_COUNT));
        assert_eq!(page(Some("0"), Some("5")), (1, 5));
        assert_eq!(page(Some("11"), Some("100000")), (11, MAX_COUNT));
        assert_eq!(page(Some("x"), Some("-3")), (1, 0));
    }

    #[test]
    fn a_user_resource_has_the_meta_and_only_what_is_set() {
        let base = "https://axon.example/scim/v2/mock";
        let resource = user_resource(base, &user_row());
        assert_eq!(resource["schemas"], json!([USER_SCHEMA]));
        assert_eq!(resource["id"], Uuid::nil().to_string());
        assert_eq!(resource["userName"], "alice@example.com");
        assert_eq!(resource["externalId"], "alice-sub");
        assert_eq!(resource["name"], json!({ "givenName": "Alice" }));
        assert_eq!(resource["active"], true);
        assert_eq!(resource["emails"][0]["value"], "alice@example.com");
        assert_eq!(resource["meta"]["resourceType"], "User");
        assert_eq!(resource["meta"]["created"], "2026-10-05T12:00:00.000Z");
        assert_eq!(resource["meta"]["lastModified"], "2026-10-05T12:00:00.000Z");
        assert_eq!(
            resource["meta"]["location"],
            format!("{base}/Users/{}", Uuid::nil())
        );

        let mut minimal = user_row();
        minimal.external_id = None;
        minimal.given_name = None;
        minimal.display_name = None;
        minimal.emails = json!([]);
        let resource = user_resource(base, &minimal);
        for absent in ["externalId", "name", "displayName", "emails"] {
            assert!(resource.get(absent).is_none(), "{absent}");
        }
    }

    #[test]
    fn a_group_resource_lists_its_members_unless_they_are_excluded() {
        let base = "https://axon.example/scim/v2/mock";
        let at = "2026-10-05T12:00:00Z".parse().unwrap();
        let group = ScimGroup {
            id: Uuid::new_v4(),
            provider: "mock".to_owned(),
            display_name: "Ops".to_owned(),
            external_id: None,
            created_at: at,
            updated_at: at,
        };
        let member = ScimMember {
            group_id: group.id,
            user_id: Uuid::new_v4(),
            user_name: "alice@example.com".to_owned(),
        };
        let other = ScimMember {
            group_id: Uuid::new_v4(),
            ..member.clone()
        };
        let resource = group_resource(base, &group, Some(&[member.clone(), other]));
        assert_eq!(resource["displayName"], "Ops");
        assert_eq!(resource["members"].as_array().unwrap().len(), 1);
        assert_eq!(resource["members"][0]["value"], member.user_id.to_string());
        assert_eq!(resource["members"][0]["display"], "alice@example.com");
        assert_eq!(resource["meta"]["resourceType"], "Group");
        assert!(group_resource(base, &group, None).get("members").is_none());
    }

    #[test]
    fn a_list_response_counts_the_page_and_the_total() {
        let list = list_response(&[json!({ "id": "a" }), json!({ "id": "b" })], 7, 3);
        assert_eq!(list["schemas"], json!([LIST_SCHEMA]));
        assert_eq!(list["totalResults"], 7);
        assert_eq!(list["startIndex"], 3);
        assert_eq!(list["itemsPerPage"], 2);
        assert_eq!(list["Resources"].as_array().unwrap().len(), 2);
        assert_eq!(list_response(&[], 0, 1)["Resources"], json!([]));
    }

    #[test]
    fn an_error_has_a_string_status_and_the_scim_type() {
        let body = ScimError::uniqueness("userName taken").body();
        assert_eq!(body["schemas"], json!([ERROR_SCHEMA]));
        assert_eq!(body["status"], "409");
        assert_eq!(body["scimType"], "uniqueness");
        assert_eq!(body["detail"], "userName taken");
        assert!(ScimError::not_found("x").body().get("scimType").is_none());
    }

    #[test]
    fn the_discovery_documents_say_what_is_supported() {
        let base = "https://axon.example/scim/v2/mock";
        let config = service_provider_config(base);
        assert_eq!(config["patch"]["supported"], true);
        assert_eq!(config["filter"]["supported"], true);
        assert_eq!(config["filter"]["maxResults"], MAX_COUNT);
        for off in ["bulk", "sort", "etag", "changePassword"] {
            assert_eq!(config[off]["supported"], false, "{off}");
        }
        assert_eq!(
            config["authenticationSchemes"][0]["type"],
            "oauthbearertoken"
        );

        let types = resource_types(base);
        assert_eq!(types["totalResults"], 2);
        assert_eq!(types["Resources"][0]["endpoint"], "/Users");
        assert_eq!(types["Resources"][1]["schema"], GROUP_SCHEMA);

        let schemas = schemas(base);
        assert_eq!(schemas["Resources"][0]["id"], USER_SCHEMA);
        assert_eq!(schemas["Resources"][0]["attributes"][0]["name"], "userName");
        assert_eq!(
            schemas["Resources"][0]["attributes"][0]["uniqueness"],
            "server"
        );
        assert_eq!(schemas["Resources"][1]["id"], GROUP_SCHEMA);
    }
}
