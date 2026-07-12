//! Config file watcher for hot reload
//!
//! Watches the config file for changes and triggers a reload
//! when modifications are detected.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kameo::actor::ActorRef;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::gateway::{GatewayActor, ReloadConfig};

/// Start watching the config file for changes
///
/// This spawns a background task that watches the config file and
/// sends a `ReloadConfig` message to the gateway when changes are detected.
///
/// The watch is placed on the config file's **parent directory** rather than the
/// file itself. Many writers (editors, and atomic config deploys such as a
/// symlink swap into an immutable store) replace the file via `rename(2)`, which
/// leaves an inotify watch on the *file* pointing at the old, now-detached inode
/// so no further events arrive. Watching the directory and filtering on the file
/// name survives those atomic replaces.
pub fn start_config_watcher(
    config_path: impl AsRef<Path>,
    gateway: ActorRef<GatewayActor>,
) -> Result<(), notify::Error> {
    let config_path = config_path.as_ref().to_path_buf();
    let config_path_display = config_path.display().to_string();

    // The directory to watch, and the file name to filter events on.
    let watch_dir: PathBuf = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let file_name = config_path.file_name().map(std::ffi::OsStr::to_os_string);

    // Channel bridging notify's own thread (sync callback) to our async task.
    // `tokio::sync::mpsc` is used instead of `std::sync::mpsc` because the
    // consumer awaits in an async task: a blocking `std::sync::mpsc::recv()`
    // inside `tokio::spawn` parks a runtime worker thread for the lifetime of
    // the process, which on a small runtime can starve the HTTP server.
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();

    let file_name_for_cb = file_name.clone();
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            let Ok(event) = res else { return };

            // Only react to create/modify/rename-style events.
            if !(event.kind.is_modify() || event.kind.is_create()) {
                return;
            }

            // When watching the directory, only react to our config file.
            let relevant = match &file_name_for_cb {
                Some(name) => event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(name.as_os_str())),
                None => true,
            };

            if relevant {
                // Unbounded send never blocks; a closed receiver just means we
                // are shutting down, so the error is safely ignored.
                let _ = tx.send(());
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(2)),
    )?;

    watcher.watch(&watch_dir, RecursiveMode::NonRecursive)?;

    tracing::info!(
        "Started config file watcher for: {} (watching {})",
        config_path_display,
        watch_dir.display()
    );

    // Spawn a task to handle file change events
    tokio::spawn(async move {
        // Keep the watcher alive for as long as the task runs.
        let _watcher = watcher;

        loop {
            // Wait for an event (async — does not block a runtime worker).
            if rx.recv().await.is_none() {
                tracing::debug!("Config watcher channel closed");
                break;
            }

            // Debounce: wait for events to settle, then drain any that queued up
            // (an atomic replace typically emits several events in quick succession).
            tokio::time::sleep(Duration::from_millis(500)).await;
            while rx.try_recv().is_ok() {}

            tracing::info!("Config file changed, reloading...");

            // Try to load the new config
            match Config::load(&config_path) {
                Ok(new_config) => {
                    // Send reload message to gateway
                    match gateway.ask(ReloadConfig { config: new_config }).await {
                        Ok(result) => {
                            if result.errors.is_empty() {
                                tracing::info!(
                                    "Config reloaded successfully: {} added, {} removed",
                                    result.added.len(),
                                    result.removed.len()
                                );
                            } else {
                                tracing::warn!(
                                    "Config reloaded with errors: {} added, {} removed, {} errors: {:?}",
                                    result.added.len(),
                                    result.removed.len(),
                                    result.errors.len(),
                                    result.errors
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!("Failed to reload config: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to parse config file: {}", e);
                }
            }
        }
    });

    Ok(())
}
