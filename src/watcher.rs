//! Config file watcher for hot reload
//!
//! Watches the config file for changes and triggers a reload
//! when modifications are detected.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use kameo::actor::ActorRef;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::config::Config;
use crate::gateway::{GatewayActor, ReloadConfig};

/// Start watching the config file for changes
///
/// This spawns a background task that watches the config file and
/// sends a `ReloadConfig` message to the gateway when changes are detected.
pub fn start_config_watcher(
    config_path: impl AsRef<Path>,
    gateway: ActorRef<GatewayActor>,
) -> Result<(), notify::Error> {
    let config_path = config_path.as_ref().to_path_buf();
    let config_path_display = config_path.display().to_string();

    // Create a channel for receiving file system events
    let (tx, rx) = mpsc::channel();

    // Create a watcher with a debounce duration
    let mut watcher = RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| {
            if let Ok(event) = res {
                // Only trigger on modify events
                if event.kind.is_modify() {
                    let _ = tx.send(());
                }
            }
        },
        notify::Config::default().with_poll_interval(Duration::from_secs(2)),
    )?;

    // Watch the config file
    watcher.watch(&config_path, RecursiveMode::NonRecursive)?;

    tracing::info!("Started config file watcher for: {}", config_path_display);

    // Spawn a task to handle file change events
    let config_path_clone = config_path.clone();
    tokio::spawn(async move {
        // Keep the watcher alive
        let _watcher = watcher;

        // Debounce: wait for events and batch them
        loop {
            // Wait for an event
            if rx.recv().is_err() {
                tracing::debug!("Config watcher channel closed");
                break;
            }

            // Debounce: consume any additional events that arrive quickly
            tokio::time::sleep(Duration::from_millis(500)).await;
            while rx.try_recv().is_ok() {}

            tracing::info!("Config file changed, reloading...");

            // Try to load the new config
            match Config::load(&config_path_clone) {
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
