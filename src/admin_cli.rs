//! `axon-gateway admin ...`: operator commands that talk to the database
//! directly, for when the dashboard cannot be reached the usual way.
//!
//! Today that is `admin login-link`, the break-glass admin login for an
//! identity provider that is down.

use std::env;

use color_eyre::eyre::{WrapErr, eyre};

use crate::config::Config;
use crate::store::{BREAK_GLASS_CODE_TTL, Store};

const USAGE: &str = "\
Usage: axon-gateway admin <command>

Commands:
  login-link [--config <path>]   Print a one-time URL that starts a 1-hour
                                 admin session as the break-glass user

The config path falls back to AXON_GATEWAY_CONFIG, then config.toml.";

/// A parsed `admin` command line
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// `login-link`, with the `--config` path when one was given
    LoginLink { config: Option<String> },
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
        Some("login-link") => {
            let mut config = None;
            while let Some(arg) = args.next() {
                if let Some(path) = arg.strip_prefix("--config=") {
                    config = Some(path.to_owned());
                } else if arg == "--config" {
                    let path = args.next().ok_or("--config needs a path")?;
                    config = Some(path.to_owned());
                } else {
                    return Err(format!("unexpected argument '{arg}'"));
                }
            }
            Ok(Command::LoginLink { config })
        }
        Some("--help" | "-h" | "help") => Ok(Command::Help),
        Some(other) => Err(format!("unknown admin command '{other}'")),
        None => Err("missing admin command".to_owned()),
    }
}

/// `--config`, else `AXON_GATEWAY_CONFIG`, else `config.toml`
fn config_path(explicit: Option<String>, from_env: Option<String>) -> String {
    explicit
        .or(from_env)
        .unwrap_or_else(|| "config.toml".to_owned())
}

/// Runs the admin command in `args` (the arguments after the program name,
/// starting with `admin`). A usage error prints the usage text and exits with
/// status 2.
///
/// # Errors
/// Fails when the config cannot be loaded, has no `[database]`, or the
/// database cannot be reached or written.
pub async fn run(args: &[String]) -> color_eyre::Result<()> {
    match parse(args) {
        Ok(Command::LoginLink { config }) => {
            login_link(&config_path(config, env::var("AXON_GATEWAY_CONFIG").ok())).await
        }
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

/// Creates a break-glass code and prints the URL that redeems it.
async fn login_link(config_path: &str) -> color_eyre::Result<()> {
    let config = Config::load(config_path)
        .wrap_err_with(|| format!("failed to load config from '{config_path}'"))?;
    let database = config.database.as_ref().ok_or_else(|| {
        eyre!("'{config_path}' has no [database] section; the break-glass login needs one")
    })?;
    let store = Store::connect(database)
        .await
        .wrap_err("failed to connect to the database")?;
    let code = store
        .create_break_glass_code()
        .await
        .wrap_err("failed to create the login code")?;

    let base_url = config.gateway.base_url.trim_end_matches('/');
    println!("{base_url}/auth/break-glass?code={code}");
    println!(
        "The link expires in {} minutes and works once.",
        BREAK_GLASS_CODE_TTL.as_secs() / 60
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn login_link_takes_an_optional_config() {
        assert_eq!(
            parse(&args(&["admin", "login-link"])),
            Ok(Command::LoginLink { config: None })
        );
        assert_eq!(
            parse(&args(&["admin", "login-link", "--config", "a.toml"])),
            Ok(Command::LoginLink {
                config: Some("a.toml".to_owned())
            })
        );
        assert_eq!(
            parse(&args(&["admin", "login-link", "--config=b.toml"])),
            Ok(Command::LoginLink {
                config: Some("b.toml".to_owned())
            })
        );
    }

    #[test]
    fn bad_command_lines_are_refused() {
        assert!(parse(&args(&["admin"])).is_err());
        assert!(parse(&args(&["admin", "frobnicate"])).is_err());
        assert!(parse(&args(&["admin", "login-link", "--config"])).is_err());
        assert!(parse(&args(&["admin", "login-link", "--nope"])).is_err());
        assert!(parse(&args(&["admin", "login-link", "stray"])).is_err());
        assert!(parse(&args(&["serve"])).is_err());
    }

    #[test]
    fn help_is_not_an_error() {
        assert_eq!(parse(&args(&["admin", "--help"])), Ok(Command::Help));
    }

    #[test]
    fn the_config_path_falls_back_to_the_environment_then_the_default() {
        let given = || Some("given.toml".to_owned());
        let from_env = || Some("env.toml".to_owned());
        assert_eq!(config_path(given(), from_env()), "given.toml");
        assert_eq!(config_path(None, from_env()), "env.toml");
        assert_eq!(config_path(None, None), "config.toml");
    }
}
