//! `axon-gateway admin ...`: operator commands that talk to the database
//! directly, for when the dashboard cannot be reached the usual way.
//!
//! `admin login-link` is the break-glass admin login for an identity provider
//! that is down, `admin rewrap-secrets` moves the sealed secrets (personal
//! backends, catalog credentials, configured backends and providers) onto the
//! active key, and `admin import-config` writes a config file into the
//! database. All of them run in the database-mode environment
//! (`AXON_DATABASE_URL`, and the KEK where they seal or open secrets).

use color_eyre::eyre::{WrapErr, eyre};

use crate::bootstrap::{Bootstrap, ENV_DATABASE_URL};
use crate::crypto::{Keyring, Sealed};
use crate::import;
use crate::store::{BREAK_GLASS_CODE_TTL, SealedColumns, Store};

const USAGE: &str = "\
Usage: axon-gateway admin <command>

Commands:
  login-link                     Print a one-time URL that starts a 1-hour
                                 admin session as the break-glass user
  rewrap-secrets                 Re-wrap every sealed secret (personal
                                 backends, catalog credentials, backends and
                                 OIDC providers) under the active key
  import-config <file> [--dry-run] [--no-tokens]
                                 Write a TOML config file into the database:
                                 the file wins, new [[tokens]] entries get a
                                 fresh token on stdout. --dry-run rolls the
                                 import back and only reports; --no-tokens
                                 creates those service accounts without a
                                 token (issue one in the dashboard or the API)

The commands use the database-mode environment: AXON_DATABASE_URL, and the key
(AXON_KEK_FILE or AXON_KEK) for rewrap-secrets and import-config.";

/// A parsed `admin` command line
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// `login-link`
    LoginLink,
    /// `rewrap-secrets`
    RewrapSecrets,
    /// `import-config <file> [--dry-run] [--no-tokens]`
    ImportConfig {
        file: String,
        dry_run: bool,
        no_tokens: bool,
    },
    /// `--help`
    Help,
}

/// Parses the arguments after the program name, which must start with
/// `admin`. The error is the reason, to print above the usage text.
fn parse(args: &[String]) -> Result<Command, String> {
    let mut args = args.iter().map(String::as_str);
    if args.next() != Some("admin") {
        return Err("not an admin command".to_owned());
    }
    match args.next() {
        Some("login-link") => no_arguments(args).map(|()| Command::LoginLink),
        Some("rewrap-secrets") => no_arguments(args).map(|()| Command::RewrapSecrets),
        Some("import-config") => parse_import(args),
        Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some(other) => Err(format!("unknown admin command '{other}'")),
        None => Err("missing admin command".to_owned()),
    }
}

/// A command line that takes nothing
fn no_arguments<'a>(mut args: impl Iterator<Item = &'a str>) -> Result<(), String> {
    match args.next() {
        Some(arg) => Err(format!("unexpected argument '{arg}'")),
        None => Ok(()),
    }
}

/// The `<file>`, `--dry-run` and `--no-tokens` of `import-config`, in any order
fn parse_import<'a>(args: impl Iterator<Item = &'a str>) -> Result<Command, String> {
    let mut file = None;
    let mut dry_run = false;
    let mut no_tokens = false;
    for arg in args {
        if arg == "--dry-run" {
            dry_run = true;
        } else if arg == "--no-tokens" {
            no_tokens = true;
        } else if arg.starts_with("--") || file.is_some() {
            return Err(format!("unexpected argument '{arg}'"));
        } else {
            file = Some(arg.to_owned());
        }
    }
    let file = file.ok_or("import-config needs the path of a config file")?;
    Ok(Command::ImportConfig {
        file,
        dry_run,
        no_tokens,
    })
}

/// Runs the admin command in `args` (the arguments after the program name,
/// starting with `admin`). A usage error prints the usage text and exits with
/// status 2.
///
/// # Errors
/// Fails when the database environment is missing or the database cannot be
/// reached or written, and for `import-config` when the file cannot be loaded.
pub async fn run(args: &[String]) -> color_eyre::Result<()> {
    match parse(args) {
        Ok(Command::LoginLink) => login_link().await,
        Ok(Command::RewrapSecrets) => rewrap_secrets().await,
        Ok(Command::ImportConfig {
            file,
            dry_run,
            no_tokens,
        }) => import_config(&file, dry_run, no_tokens).await,
        Ok(Command::Help) => {
            println!("{USAGE}");
            Ok(())
        }
        Err(reason) => {
            eprintln!("error: {reason}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}

/// Reads the bootstrap environment, connects to the database it names and
/// applies the migrations.
async fn connect() -> color_eyre::Result<(Bootstrap, Store)> {
    let bootstrap = Bootstrap::from_env().wrap_err("failed to read the bootstrap environment")?;
    let url = bootstrap.database_url.as_deref().ok_or_else(|| {
        eyre!("{ENV_DATABASE_URL} is not set; the admin commands run in database mode")
    })?;
    let store = Store::connect_url(url)
        .await
        .wrap_err("failed to connect to the database")?;
    Ok((bootstrap, store))
}

/// The key-encryption keys from the environment
fn keyring() -> color_eyre::Result<Keyring> {
    Keyring::from_env()
        .wrap_err("failed to read the secret keys")?
        .ok_or_else(|| eyre!("no secret keys are configured (AXON_KEK_FILE or AXON_KEK)"))
}

/// Imports a config file into the database.
async fn import_config(file: &str, dry_run: bool, no_tokens: bool) -> color_eyre::Result<()> {
    let keyring = keyring()?;
    let (_, store) = connect().await?;
    import::run(&store, &keyring, file, dry_run, no_tokens).await
}

/// Creates a break-glass code and prints the URL that redeems it.
async fn login_link() -> color_eyre::Result<()> {
    let (bootstrap, store) = connect().await?;
    let code = store
        .create_break_glass_code()
        .await
        .wrap_err("failed to create the login code")?;

    let base_url = bootstrap.base_url.trim_end_matches('/');
    println!("{base_url}/auth/break-glass?code={code}");
    println!(
        "The link expires in {} minutes and works once.",
        BREAK_GLASS_CODE_TTL.as_secs() / 60
    );
    Ok(())
}

/// Re-wraps the data key of every sealed secret that is not under the active
/// key, and prints how many it moved.
async fn rewrap_secrets() -> color_eyre::Result<()> {
    let keyring = keyring()?;
    let (_, store) = connect().await?;

    let mut rewrapped = 0_u64;
    let mut current = 0_u64;
    for (target, columns) in store
        .sealed_secrets()
        .await
        .wrap_err("failed to read the sealed secrets")?
    {
        let sealed = Sealed::from(&columns);
        let Some(fresh) = keyring
            .rewrap(&sealed)
            .wrap_err_with(|| format!("failed to re-wrap {target:?}"))?
        else {
            current += 1;
            continue;
        };
        store
            .replace_sealed(&target, &SealedColumns::from(fresh))
            .await
            .wrap_err_with(|| format!("failed to store the re-wrapped {target:?}"))?;
        rewrapped += 1;
    }
    for (target, columns) in store
        .config_sealed_secrets()
        .await
        .wrap_err("failed to read the sealed configuration secrets")?
    {
        let sealed = Sealed::from(&columns);
        let Some(fresh) = keyring
            .rewrap(&sealed)
            .wrap_err_with(|| format!("failed to re-wrap {target:?}"))?
        else {
            current += 1;
            continue;
        };
        store
            .replace_config_sealed(&target, &SealedColumns::from(fresh))
            .await
            .wrap_err_with(|| format!("failed to store the re-wrapped {target:?}"))?;
        rewrapped += 1;
    }
    println!("rewrapped {rewrapped}, already current {current}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn login_link_takes_no_arguments() {
        assert_eq!(
            parse(&args(&["admin", "login-link"])),
            Ok(Command::LoginLink)
        );
        assert!(parse(&args(&["admin", "login-link", "--config", "a.toml"])).is_err());
        assert!(parse(&args(&["admin", "login-link", "stray"])).is_err());
    }

    #[test]
    fn rewrap_secrets_takes_no_arguments() {
        assert_eq!(
            parse(&args(&["admin", "rewrap-secrets"])),
            Ok(Command::RewrapSecrets)
        );
        assert!(parse(&args(&["admin", "rewrap-secrets", "--config=a.toml"])).is_err());
        assert!(parse(&args(&["admin", "rewrap-secrets", "stray"])).is_err());
    }

    fn import(file: &str, dry_run: bool, no_tokens: bool) -> Command {
        Command::ImportConfig {
            file: file.to_owned(),
            dry_run,
            no_tokens,
        }
    }

    #[test]
    fn import_config_takes_a_file_and_optional_flags() {
        assert_eq!(
            parse(&args(&["admin", "import-config", "a.toml"])),
            Ok(import("a.toml", false, false))
        );
        assert_eq!(
            parse(&args(&["admin", "import-config", "a.toml", "--dry-run"])),
            Ok(import("a.toml", true, false))
        );
        assert_eq!(
            parse(&args(&["admin", "import-config", "--dry-run", "a.toml"])),
            Ok(import("a.toml", true, false))
        );
        assert_eq!(
            parse(&args(&["admin", "import-config", "a.toml", "--no-tokens"])),
            Ok(import("a.toml", false, true))
        );
        assert_eq!(
            parse(&args(&["admin", "import-config", "--no-tokens", "a.toml"])),
            Ok(import("a.toml", false, true))
        );
        assert_eq!(
            parse(&args(&[
                "admin",
                "import-config",
                "--no-tokens",
                "a.toml",
                "--dry-run"
            ])),
            Ok(import("a.toml", true, true))
        );
        assert_eq!(
            parse(&args(&[
                "admin",
                "import-config",
                "--dry-run",
                "--no-tokens",
                "a.toml"
            ])),
            Ok(import("a.toml", true, true))
        );
    }

    #[test]
    fn import_config_without_a_file_is_a_usage_error() {
        assert!(parse(&args(&["admin", "import-config"])).is_err());
        assert!(parse(&args(&["admin", "import-config", "--dry-run"])).is_err());
        assert!(parse(&args(&["admin", "import-config", "--no-tokens"])).is_err());
        assert!(parse(&args(&["admin", "import-config", "a.toml", "b.toml"])).is_err());
        assert!(parse(&args(&["admin", "import-config", "a.toml", "--nope"])).is_err());
    }

    #[test]
    fn bad_command_lines_are_refused() {
        assert!(parse(&args(&["admin"])).is_err());
        assert!(parse(&args(&["admin", "frobnicate"])).is_err());
        assert!(parse(&args(&["admin", "login-link", "--nope"])).is_err());
        assert!(parse(&args(&["serve"])).is_err());
    }

    #[test]
    fn help_is_not_an_error() {
        assert_eq!(parse(&args(&["admin", "--help"])), Ok(Command::Help));
    }
}
