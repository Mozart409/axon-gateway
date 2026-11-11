//! `axon-gateway admin import-config` and the two start modes: the import's
//! dry run, its idempotence and its one-time tokens, a gateway that starts
//! from the environment alone, and the refusals (database mode with a config
//! path, standalone mode with a file that needs a database).
//!
//! The tests that need a database skip themselves unless
//! `AXON_TEST_DATABASE_URL` is set (see `oidc_login.rs`).

// Integration tests are test code: exempt them from the panic-family denies.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

mod support;

use std::path::Path;
use std::time::Duration;

use reqwest::StatusCode;
use support::mock_backend::MockBackend;
use support::{
    ConfigBuilder, Gateway, free_port, import_config_cli, mcp_post, poll_until, rpc, run_cli,
};
use tempfile::NamedTempFile;

const DATABASE_ENV: &str = "AXON_TEST_GATEWAY_DATABASE_URL";

/// One token entry, a group that lists its account and grants `read_file`.
const RBAC_AND_TOKENS: &str = r#"
[[rbac.groups]]
name = "ops"
service_accounts = ["ci-bot"]

[[rbac.grants]]
group = "ops"
backend = "files"
include = ["read_file"]

[[tokens]]
name = "ci-bot"
token = "ci-bot-secret"
"#;

/// A file in a temporary place.
fn write_file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp config");
    std::io::Write::write_all(&mut file, content.as_bytes()).expect("write config");
    file
}

/// A config with the `files` backend at `backend_url` and `RBAC_AND_TOKENS`.
fn config_for(backend_url: &str) -> String {
    ConfigBuilder::new(&format!("127.0.0.1:{}", free_port()))
        .http_backend("files", backend_url)
        .database(DATABASE_ENV)
        .rbac(RBAC_AND_TOKENS)
        .render()
}

/// The rows of `table`.
async fn count(url: &str, table: &str) -> i64 {
    let pool = sqlx::PgPool::connect(url)
        .await
        .expect("the test database must be reachable");
    let rows: i64 =
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("select count(*) from {table}")))
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    rows
}

/// The tokens `import-config` printed, one `name<TAB>token` per line.
fn printed_tokens(stdout: &str) -> Vec<(&str, &str)> {
    stdout
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect()
}

/// `base` with a schema of its own.
async fn isolated_url(base: &str, schema: &str) -> String {
    let pool = sqlx::PgPool::connect(base)
        .await
        .expect("the test database must be reachable");
    for statement in [
        format!("drop schema if exists {schema} cascade"),
        format!("create schema {schema}"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .expect("the test database must allow recreating the test schema");
    }
    pool.close().await;

    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

/// A database URL for `schema`; `None` (after saying why) without
/// `AXON_TEST_DATABASE_URL`.
async fn database(schema: &str) -> Option<String> {
    let Ok(base) = std::env::var("AXON_TEST_DATABASE_URL") else {
        eprintln!("skipping: AXON_TEST_DATABASE_URL is not set");
        return None;
    };
    Some(isolated_url(&base, schema).await)
}

fn import(file: &Path, url: &str, dry_run: bool) -> support::CliOutput {
    import_config_cli(file, url, dry_run, &[(DATABASE_ENV, url)])
}

#[tokio::test]
async fn a_dry_run_writes_nothing_and_prints_no_tokens() {
    let Some(url) = database("axon_import_dry_run").await else {
        return;
    };
    let backend = MockBackend::start(&["read_file"]).await;
    let file = write_file(&config_for(&backend.url()));

    let output = import(file.path(), &url, true);
    assert!(output.status.success(), "{}", output.stderr);
    assert_eq!(output.stdout.trim(), "", "a dry run prints no token");
    assert!(output.stderr.contains("Dry run"), "{}", output.stderr);
    assert!(output.stderr.contains("backends"), "{}", output.stderr);
    for table in [
        "gateway_backends",
        "rbac_groups",
        "rbac_grants",
        "api_tokens",
    ] {
        assert_eq!(count(&url, table).await, 0, "{table} after a dry run");
    }

    // The real import then creates all of it.
    let output = import(file.path(), &url, false);
    assert!(output.status.success(), "{}", output.stderr);
    assert!(!output.stderr.contains("Dry run"), "{}", output.stderr);
    assert_eq!(count(&url, "gateway_backends").await, 1);
    assert_eq!(count(&url, "rbac_groups").await, 1);
    assert_eq!(count(&url, "api_tokens").await, 1);
}

#[tokio::test]
async fn a_token_entry_prints_one_token_and_a_second_import_changes_nothing() {
    let Some(url) = database("axon_import_twice").await else {
        return;
    };
    let backend = MockBackend::start(&["read_file"]).await;
    let file = write_file(&config_for(&backend.url()));

    let first = import(file.path(), &url, false);
    assert!(first.status.success(), "{}", first.stderr);
    let tokens = printed_tokens(&first.stdout);
    assert_eq!(tokens.len(), 1, "{}", first.stdout);
    assert_eq!(tokens[0].0, "ci-bot");
    assert!(tokens[0].1.starts_with("axon_pat_"), "{}", tokens[0].1);
    // The token the file held is not the one printed, and is not stored.
    assert!(!first.stdout.contains("ci-bot-secret"));
    assert!(first.stderr.contains("created"), "{}", first.stderr);

    let second = import(file.path(), &url, false);
    assert!(second.status.success(), "{}", second.stderr);
    assert_eq!(
        second.stdout.trim(),
        "",
        "no new token for an existing account"
    );
    assert!(
        second.stderr.contains("Total: 0 created, 0 updated"),
        "{}",
        second.stderr
    );
    assert_eq!(count(&url, "api_tokens").await, 1);
    assert_eq!(count(&url, "gateway_backends").await, 1);
}

#[tokio::test]
async fn the_gateway_started_from_the_environment_serves_the_imported_backend() {
    let Some(url) = database("axon_import_env_only").await else {
        return;
    };
    let backend = MockBackend::start(&["read_file", "delete_file"]).await;
    let bind = format!("127.0.0.1:{}", free_port());
    let config = ConfigBuilder::new(&bind)
        .http_backend("files", &backend.url())
        .database(DATABASE_ENV)
        .rbac(RBAC_AND_TOKENS)
        .render();

    // The harness imports the file, then starts the binary without it.
    let gateway =
        Gateway::start_with_env(&config, &format!("http://{bind}"), &[(DATABASE_ENV, &url)]).await;
    let pat = gateway.token("ci-bot").to_string();
    let client = reqwest::Client::new();
    let mcp = format!("{}/mcp", gateway.base);

    let names = poll_until(100, Duration::from_millis(100), || async {
        let (status, body) = mcp_post(&client, &mcp, Some(&pat), &rpc("tools/list")).await;
        if status != StatusCode::OK {
            return None;
        }
        let names: Vec<String> = body["result"]["tools"]
            .as_array()?
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .collect();
        (!names.is_empty()).then_some(names)
    })
    .await
    .expect("the imported backend should be served");
    assert_eq!(names, ["files_read_file"]);

    // The file's own token is no credential in database mode.
    let (status, _) = mcp_post(&client, &mcp, Some("ci-bot-secret"), &rpc("tools/list")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[test]
fn database_mode_refuses_a_config_path() {
    let config = ConfigBuilder::new(&format!("127.0.0.1:{}", free_port())).render();
    let file = write_file(&config);
    let path = file.path().to_str().unwrap();
    // The refusal comes before the database is touched.
    let env = [("AXON_DATABASE_URL", "postgres://127.0.0.1:1/unused")];

    let by_argument = run_cli(&[path], &env, Duration::from_secs(20))
        .expect("the gateway should refuse to start, not keep running");
    assert!(!by_argument.status.success());
    assert!(
        by_argument.stderr.contains("admin import-config"),
        "{}",
        by_argument.stderr
    );
    assert!(
        by_argument.stderr.contains("no config file"),
        "{}",
        by_argument.stderr
    );

    let by_variable = run_cli(
        &[],
        &[env[0], ("AXON_GATEWAY_CONFIG", path)],
        Duration::from_secs(20),
    )
    .expect("the gateway should refuse to start, not keep running");
    assert!(!by_variable.status.success());
    assert!(
        by_variable.stderr.contains("admin import-config"),
        "{}",
        by_variable.stderr
    );
}

#[test]
fn standalone_mode_refuses_a_file_that_needs_a_database() {
    let bind = format!("127.0.0.1:{}", free_port());
    let per_user = "[[backends]]\nname = \"mine\"\nurl = \"http://127.0.0.1:1/mcp\"\ntransport = \"http\"\ncredential_mode = \"per_user\"\n";
    for (what, config) in [
        (
            "[database]",
            ConfigBuilder::new(&bind).database(DATABASE_ENV).render(),
        ),
        (
            "[[auth.oidc]]",
            ConfigBuilder::new(&bind)
                .oidc_provider("sso", "https://idp.example.com", "client", "")
                .render(),
        ),
        (
            "[rbac]",
            ConfigBuilder::new(&bind)
                .rbac("[[rbac.groups]]\nname = \"ops\"\n")
                .render(),
        ),
        (
            "a per-user backend",
            ConfigBuilder::new(&bind).raw_backend(per_user).render(),
        ),
    ] {
        let file = write_file(&config);
        let output = run_cli(
            &[file.path().to_str().unwrap()],
            &[],
            Duration::from_secs(20),
        )
        .unwrap_or_else(|| panic!("{what}: the gateway should refuse to start"));
        assert!(!output.status.success(), "{what}: {}", output.stderr);
        assert!(
            output.stderr.contains("import-config"),
            "{what}: {}",
            output.stderr
        );
    }
}
