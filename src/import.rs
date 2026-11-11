//! `axon-gateway admin import-config <file> [--dry-run]`: writes a TOML config
//! file into the database
//!
//! The file wins: settings, backends, gateway toolsets, OIDC providers and the
//! RBAC section are upserted, and each `[[tokens]]` entry becomes a service
//! account with a fresh token. Everything runs in one transaction, which a dry
//! run rolls back. The report goes to stderr; stdout carries only the new
//! tokens, one `name<TAB>token` line each.

use std::collections::HashMap;
use std::fmt::Write as _;

use color_eyre::eyre::{WrapErr, eyre};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::config::{Config, TokenConfig};
use crate::crypto::Keyring;
use crate::dbconfig::{
    BackendSecrets, open_backend_secrets, open_provider_secret, seal_backend_secrets,
    seal_provider_secret, split_backend, split_provider,
};
use crate::policy::parse_permissions;
use crate::store::{self, Change, MAX_SERVICE_TOKEN_LIFETIME, SealedColumns, SecretUpdate, Store};

/// `[gateway]` keys that the environment replaces: the key and what to do instead
const GATEWAY_ENV_ONLY: [(&str, &str); 4] = [
    ("bind", "set AXON_BIND"),
    ("base_url", "set AXON_BASE_URL"),
    (
        "auth_token",
        "the shared token is gone, use a service account token",
    ),
    ("allow_stdio", "set AXON_ALLOW_STDIO=true"),
];

/// Warnings for the parts of the file that are environment-only now
#[must_use]
pub fn env_only_warnings(file: &toml::Table) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(gateway) = file.get("gateway").and_then(toml::Value::as_table) {
        for (key, instead) in GATEWAY_ENV_ONLY {
            if gateway.contains_key(key) {
                warnings.push(format!("[gateway] {key} is not imported: {instead}"));
            }
        }
    }
    if file.contains_key("database") {
        warnings.push("[database] is not imported: set AXON_DATABASE_URL".to_owned());
    }
    warnings
}

/// Warnings for the narrowing of `[[tokens]]` entries, which the service
/// accounts do not carry: their tools come from their groups
#[must_use]
pub fn token_warnings(tokens: &[TokenConfig]) -> Vec<String> {
    let mut warnings = Vec::new();
    for token in tokens {
        for (key, set, instead) in [
            (
                "allowed_tools",
                !token.allowed_tools.is_empty(),
                "a service account's tools come from its groups",
            ),
            (
                "allowed_backends",
                !token.allowed_backends.is_empty(),
                "a service account's backends come from its groups",
            ),
            (
                "rate_limit_per_minute",
                token.rate_limit_per_minute != 0,
                "the gateway-wide rate limit applies",
            ),
            (
                "metadata",
                !token.metadata.is_empty(),
                "nothing replaces it, it was never used",
            ),
        ] {
            if set {
                warnings.push(format!(
                    "[[tokens]] '{}': {key} is not imported, {instead}",
                    token.name
                ));
            }
        }
    }
    warnings
}

/// How many rows of one kind the import created, updated or found unchanged
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    created: u64,
    updated: u64,
    unchanged: u64,
}

impl Counts {
    fn record(&mut self, change: Change) {
        match change {
            Change::Created => self.created += 1,
            Change::Updated => self.updated += 1,
            Change::Unchanged => self.unchanged += 1,
        }
    }

    fn describe(self) -> String {
        format!(
            "{} created, {} updated, {} unchanged",
            self.created, self.updated, self.unchanged
        )
    }
}

/// What the import did, by kind of row, in the order the kinds were first seen
#[derive(Debug, Default)]
struct Report {
    kinds: Vec<(&'static str, Counts)>,
}

impl Report {
    fn record(&mut self, kind: &'static str, change: Change) {
        if let Some((_, counts)) = self.kinds.iter_mut().find(|(name, _)| *name == kind) {
            counts.record(change);
            return;
        }
        let mut counts = Counts::default();
        counts.record(change);
        self.kinds.push((kind, counts));
    }

    fn total(&self) -> Counts {
        self.kinds
            .iter()
            .fold(Counts::default(), |total, (_, counts)| Counts {
                created: total.created + counts.created,
                updated: total.updated + counts.updated,
                unchanged: total.unchanged + counts.unchanged,
            })
    }

    /// The text printed at the end of a run
    fn render(&self, path: &str, dry_run: bool) -> String {
        let mut text = if dry_run {
            format!("Dry run of {path}, nothing was written. The file would change:\n")
        } else {
            format!("Imported {path}:\n")
        };
        for (kind, counts) in &self.kinds {
            let _ = writeln!(text, "  {kind:<16} {}", counts.describe());
        }
        let _ = write!(text, "Total: {}", self.total().describe());
        text
    }

    /// The counts per kind, for the audit row
    fn details(&self) -> Value {
        let kinds: serde_json::Map<String, Value> = self
            .kinds
            .iter()
            .map(|(kind, counts)| {
                (
                    (*kind).to_owned(),
                    json!({
                        "created": counts.created,
                        "updated": counts.updated,
                        "unchanged": counts.unchanged,
                    }),
                )
            })
            .collect();
        Value::Object(kinds)
    }
}

/// What to do with the sealed secrets of a backend whose file value is `secrets`.
/// The ciphertext differs on every sealing, so the stored value is opened and
/// compared: an unchanged secret is kept as it is.
fn backend_secret_update(
    keyring: &Keyring,
    name: &str,
    stored: Option<&SealedColumns>,
    secrets: &BackendSecrets,
) -> color_eyre::Result<SecretUpdate> {
    if secrets.is_empty() {
        return Ok(clear_or_keep(stored));
    }
    if let Some(stored) = stored
        && open_backend_secrets(keyring, name, stored).is_ok_and(|open| open == *secrets)
    {
        return Ok(SecretUpdate::Keep);
    }
    let sealed = seal_backend_secrets(keyring, name, secrets)
        .wrap_err_with(|| format!("failed to seal the secrets of backend '{name}'"))?;
    Ok(sealed.map_or(SecretUpdate::Keep, SecretUpdate::Set))
}

/// [`backend_secret_update`] for the client secret of an OIDC provider
fn provider_secret_update(
    keyring: &Keyring,
    id: &str,
    stored: Option<&SealedColumns>,
    secret: Option<&str>,
) -> color_eyre::Result<SecretUpdate> {
    let Some(secret) = secret else {
        return Ok(clear_or_keep(stored));
    };
    if let Some(stored) = stored
        && open_provider_secret(keyring, id, stored).is_ok_and(|open| open == secret)
    {
        return Ok(SecretUpdate::Keep);
    }
    seal_provider_secret(keyring, id, secret)
        .map(SecretUpdate::Set)
        .wrap_err_with(|| format!("failed to seal the client secret of provider '{id}'"))
}

/// The file has no secret: drop a stored one
fn clear_or_keep(stored: Option<&SealedColumns>) -> SecretUpdate {
    if stored.is_some() {
        SecretUpdate::Clear
    } else {
        SecretUpdate::Keep
    }
}

/// The writes of one import, on the connection of its transaction
struct Importer<'a> {
    conn: &'a mut PgConnection,
    keyring: &'a Keyring,
    report: Report,
    /// Service accounts met so far: id, and whether this run created it
    accounts: HashMap<String, (Uuid, bool)>,
    /// `(name, token)` of every token issued
    tokens: Vec<(String, String)>,
}

impl Importer<'_> {
    async fn apply(&mut self, config: &Config) -> color_eyre::Result<()> {
        let change = store::import_settings(self.conn, &config.settings()).await?;
        self.report.record("settings", change);
        self.backends(config).await?;
        self.toolsets(config).await?;
        self.providers(config).await?;
        self.rbac(config).await?;
        self.service_tokens(config).await
    }

    async fn backends(&mut self, config: &Config) -> color_eyre::Result<()> {
        for backend in &config.backends {
            let (spec, secrets) = split_backend(backend);
            let stored = store::stored_backend_secret(self.conn, &spec.name).await?;
            let update =
                backend_secret_update(self.keyring, &spec.name, stored.as_ref(), &secrets)?;
            let change = store::import_backend(self.conn, &spec, &update)
                .await
                .wrap_err_with(|| format!("failed to import backend '{}'", spec.name))?;
            self.report.record("backends", change);
        }
        Ok(())
    }

    async fn toolsets(&mut self, config: &Config) -> color_eyre::Result<()> {
        for toolset in &config.toolsets {
            let change = store::import_toolset(self.conn, toolset)
                .await
                .wrap_err_with(|| format!("failed to import toolset '{}'", toolset.name))?;
            self.report.record("toolsets", change);
        }
        Ok(())
    }

    async fn providers(&mut self, config: &Config) -> color_eyre::Result<()> {
        for (index, provider) in config.auth.oidc.iter().enumerate() {
            let position = i32::try_from(index).wrap_err("too many OIDC providers")?;
            let (spec, secret) = split_provider(provider);
            let stored = store::stored_provider_secret(self.conn, &spec.id).await?;
            let update =
                provider_secret_update(self.keyring, &spec.id, stored.as_ref(), secret.as_deref())?;
            let change = store::import_oidc_provider(self.conn, &spec, position, &update)
                .await
                .wrap_err_with(|| format!("failed to import OIDC provider '{}'", spec.id))?;
            self.report.record("oidc_providers", change);
        }
        Ok(())
    }

    async fn rbac(&mut self, config: &Config) -> color_eyre::Result<()> {
        let rbac = &config.rbac;
        for role in &rbac.roles {
            let permissions = parse_permissions(&role.permissions)
                .map_err(|reason| eyre!("role '{}': {reason}", role.name))?;
            let change = store::import_role(
                self.conn,
                &role.name,
                role.description.as_deref(),
                &permissions,
            )
            .await?;
            self.report.record("roles", change);
        }
        for group in &rbac.groups {
            let change =
                store::import_group(self.conn, &group.name, group.description.as_deref()).await?;
            self.report.record("groups", change);
            for mapping in &group.idp {
                let change = store::import_idp_mapping(
                    self.conn,
                    &group.name,
                    &mapping.provider,
                    &mapping.value,
                )
                .await?;
                self.report.record("idp_mappings", change);
            }
            for account in &group.service_accounts {
                let (id, _) = self.service_account(account).await?;
                let change = store::import_membership(self.conn, &group.name, id).await?;
                self.report.record("memberships", change);
            }
        }
        for grant in &rbac.grants {
            let change = store::import_grant(self.conn, grant).await?;
            self.report.record("grants", change);
        }
        for binding in &rbac.role_bindings {
            let change =
                store::import_role_binding(self.conn, &binding.role, &binding.group).await?;
            self.report.record("role_bindings", change);
        }
        Ok(())
    }

    /// Each `[[tokens]]` entry is a service account; a new one gets a token
    async fn service_tokens(&mut self, config: &Config) -> color_eyre::Result<()> {
        for token in &config.tokens {
            let (id, created) = self.service_account(&token.name).await?;
            if created {
                let plaintext = store::import_service_token(self.conn, id, &token.name).await?;
                self.tokens.push((token.name.clone(), plaintext));
                self.report.record("tokens", Change::Created);
            } else {
                self.report.record("tokens", Change::Unchanged);
            }
        }
        Ok(())
    }

    /// The service account `name`, created when missing; `true` when this run
    /// created it. Counted once, however often the file names it.
    async fn service_account(&mut self, name: &str) -> color_eyre::Result<(Uuid, bool)> {
        if let Some(account) = self.accounts.get(name) {
            return Ok(*account);
        }
        let (id, created) = store::import_service_account(self.conn, name)
            .await
            .wrap_err_with(|| format!("failed to import service account '{name}'"))?;
        self.report.record(
            "service_accounts",
            if created {
                Change::Created
            } else {
                Change::Unchanged
            },
        );
        self.accounts.insert(name.to_owned(), (id, created));
        Ok((id, created))
    }
}

/// Imports the config file at `path` into `db`, or only reports what it
/// would do with `dry_run`.
///
/// # Errors
/// Fails when the file cannot be loaded or a write fails; nothing is written then.
pub async fn run(
    db: &Store,
    keyring: &Keyring,
    path: &str,
    dry_run: bool,
) -> color_eyre::Result<()> {
    let config = Config::load_for_import(path)
        .wrap_err_with(|| format!("failed to load config from '{path}'"))?;
    let text =
        std::fs::read_to_string(path).wrap_err_with(|| format!("failed to read '{path}'"))?;
    let file: toml::Table =
        toml::from_str(&text).wrap_err_with(|| format!("failed to parse '{path}'"))?;
    for warning in env_only_warnings(&file)
        .into_iter()
        .chain(token_warnings(&config.tokens))
    {
        eprintln!("warning: {warning}");
    }

    let mut tx = db
        .begin_import()
        .await
        .wrap_err("failed to start the transaction")?;
    let mut importer = Importer {
        conn: &mut tx,
        keyring,
        report: Report::default(),
        accounts: HashMap::new(),
        tokens: Vec::new(),
    };
    importer.apply(&config).await?;
    let Importer { report, tokens, .. } = importer;

    if dry_run {
        tx.rollback()
            .await
            .wrap_err("failed to roll the transaction back")?;
        eprintln!("{}", report.render(path, true));
        return Ok(());
    }
    store::audit_import(&mut tx, report.details()).await?;
    tx.commit().await.wrap_err("failed to commit the import")?;
    eprintln!("{}", report.render(path, false));
    // the only time a token exists in plaintext
    let issued = !tokens.is_empty();
    for (name, token) in tokens {
        println!("{name}\t{token}");
    }
    if issued && let Ok(lifetime) = chrono::TimeDelta::from_std(MAX_SERVICE_TOKEN_LIFETIME) {
        let expires = chrono::Utc::now() + lifetime;
        eprintln!(
            "note: the new tokens expire on {}",
            expires.format("%Y-%m-%d")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    fn keyring() -> Keyring {
        Keyring::from_text("k1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()
    }

    fn token(name: &str, tools: &[&str], backends: &[&str]) -> TokenConfig {
        TokenConfig {
            name: name.to_owned(),
            token: "secret".to_owned(),
            allowed_tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
            allowed_backends: backends.iter().map(|name| (*name).to_owned()).collect(),
            rate_limit_per_minute: 0,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn environment_only_keys_are_warned_about() {
        let file = table(
            "[gateway]\nbind = \"0.0.0.0:8080\"\nbase_url = \"https://x\"\nauth_token = \"t\"\n\
             allow_stdio = true\nrate_limit_per_minute = 5\n[database]\nurl_env = \"X\"\n",
        );
        let warnings = env_only_warnings(&file);
        assert_eq!(warnings.len(), 5, "{warnings:?}");
        for key in [
            "bind",
            "base_url",
            "auth_token",
            "allow_stdio",
            "[database]",
        ] {
            assert!(
                warnings.iter().any(|warning| warning.contains(key)),
                "{key}: {warnings:?}"
            );
        }
    }

    #[test]
    fn a_file_without_environment_only_keys_has_no_warnings() {
        let file = table("[gateway]\nrate_limit_per_minute = 5\n\n[[backends]]\nname = \"a\"\n");
        assert!(
            env_only_warnings(&file).is_empty(),
            "{:?}",
            env_only_warnings(&file)
        );
        assert!(
            env_only_warnings(&toml::Table::new()).is_empty(),
            "{:?}",
            env_only_warnings(&toml::Table::new())
        );
    }

    #[test]
    fn token_narrowing_is_warned_about() {
        let tokens = [
            token("plain", &[], &[]),
            token("tools", &["a_*"], &[]),
            token("both", &["a_*"], &["a"]),
        ];
        let warnings = token_warnings(&tokens);
        assert_eq!(warnings.len(), 3, "{warnings:?}");
        assert!(warnings.iter().all(|warning| !warning.contains("'plain'")));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("allowed_backends"))
        );
    }

    #[test]
    fn the_report_counts_by_kind_and_in_total() {
        let mut report = Report::default();
        report.record("backends", Change::Created);
        report.record("backends", Change::Unchanged);
        report.record("groups", Change::Updated);
        report.record("backends", Change::Created);

        assert_eq!(
            report.total(),
            Counts {
                created: 2,
                updated: 1,
                unchanged: 1
            }
        );
        let text = report.render("config.toml", false);
        assert!(text.starts_with("Imported config.toml:\n"), "{text}");
        assert!(text.contains("backends"), "{text}");
        assert!(text.contains("2 created, 0 updated, 1 unchanged"), "{text}");
        assert!(
            text.ends_with("Total: 2 created, 1 updated, 1 unchanged"),
            "{text}"
        );
        assert!(
            report
                .render("config.toml", true)
                .starts_with("Dry run of config.toml")
        );
        assert_eq!(
            report.details(),
            json!({
                "backends": { "created": 2, "updated": 0, "unchanged": 1 },
                "groups": { "created": 0, "updated": 1, "unchanged": 0 },
            })
        );
    }

    #[test]
    fn an_unchanged_backend_secret_is_kept() {
        let keyring = keyring();
        let secrets = BackendSecrets {
            auth_token: Some("t".to_owned()),
            ..BackendSecrets::default()
        };
        let sealed = seal_backend_secrets(&keyring, "wiki", &secrets)
            .unwrap()
            .unwrap();

        let same = backend_secret_update(&keyring, "wiki", Some(&sealed), &secrets).unwrap();
        assert!(matches!(same, SecretUpdate::Keep));

        let other = BackendSecrets {
            auth_token: Some("changed".to_owned()),
            ..BackendSecrets::default()
        };
        let changed = backend_secret_update(&keyring, "wiki", Some(&sealed), &other).unwrap();
        assert!(matches!(changed, SecretUpdate::Set(_)));
        let first = backend_secret_update(&keyring, "wiki", None, &secrets).unwrap();
        assert!(matches!(first, SecretUpdate::Set(_)));

        let none = BackendSecrets::default();
        let dropped = backend_secret_update(&keyring, "wiki", Some(&sealed), &none).unwrap();
        assert!(matches!(dropped, SecretUpdate::Clear));
        let nothing = backend_secret_update(&keyring, "wiki", None, &none).unwrap();
        assert!(matches!(nothing, SecretUpdate::Keep));
    }

    #[test]
    fn an_unchanged_provider_secret_is_kept() {
        let keyring = keyring();
        let sealed = seal_provider_secret(&keyring, "sso", "s3cret").unwrap();

        let same = provider_secret_update(&keyring, "sso", Some(&sealed), Some("s3cret")).unwrap();
        assert!(matches!(same, SecretUpdate::Keep));
        let changed = provider_secret_update(&keyring, "sso", Some(&sealed), Some("new")).unwrap();
        assert!(matches!(changed, SecretUpdate::Set(_)));
        let dropped = provider_secret_update(&keyring, "sso", Some(&sealed), None).unwrap();
        assert!(matches!(dropped, SecretUpdate::Clear));
        let public = provider_secret_update(&keyring, "sso", None, None).unwrap();
        assert!(matches!(public, SecretUpdate::Keep));
    }
}
