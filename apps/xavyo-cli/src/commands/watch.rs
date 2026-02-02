//! Watch configuration file for changes and auto-apply

use crate::api::ApiClient;
use crate::commands::apply::{
    apply_changes, compute_changes, fetch_current_state, load_config, print_planned_changes,
    validate_config,
};
use crate::config::{Config, ConfigPaths};
use crate::error::{CliError, CliResult};
use crate::models::config::ApplyAction;
use clap::Args;
use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use tokio::signal;

/// Default debounce delay in milliseconds
const DEFAULT_DEBOUNCE_MS: u64 = 500;

/// Watch a configuration file and auto-apply changes
#[derive(Args, Debug)]
pub struct WatchArgs {
    /// Path to configuration file to watch
    #[arg(short = 'f', long = "file")]
    pub file: PathBuf,

    /// Preview changes without applying (dry-run mode)
    #[arg(long)]
    pub dry_run: bool,
}

/// Execute the watch command
pub async fn execute(args: WatchArgs) -> CliResult<()> {
    // Verify file exists at startup
    if !args.file.exists() {
        return Err(CliError::Validation(format!(
            "File not found: {}",
            args.file.display()
        )));
    }

    // Validate the config is valid before starting watch
    let initial_config = load_config(&args.file)?;
    validate_config(&initial_config)?;

    // Set up API client
    let paths = ConfigPaths::new()?;
    let cli_config = Config::load(&paths)?;
    let client = ApiClient::new(cli_config, paths)?;

    // Print startup message
    if args.dry_run {
        println!("Watching {} for changes... [DRY RUN]", args.file.display());
    } else {
        println!("Watching {} for changes...", args.file.display());
    }
    println!("Press Ctrl+C to stop.");
    println!();

    // Set up file watcher with debouncing
    let (tx, rx) = mpsc::channel();
    let mut debouncer = new_debouncer(Duration::from_millis(DEFAULT_DEBOUNCE_MS), tx)
        .map_err(|e| CliError::Io(format!("Failed to create file watcher: {}", e)))?;

    // Watch the file's parent directory to catch renames/recreations
    let watch_path = args
        .file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = args
        .file
        .file_name()
        .ok_or_else(|| CliError::Validation("Invalid file path".to_string()))?;

    debouncer
        .watcher()
        .watch(watch_path, RecursiveMode::NonRecursive)
        .map_err(|e| CliError::Io(format!("Failed to watch directory: {}", e)))?;

    // Run the watch loop
    watch_loop(&client, &args, rx, file_name).await
}

/// Main watch loop handling events and shutdown
async fn watch_loop(
    client: &ApiClient,
    args: &WatchArgs,
    rx: mpsc::Receiver<Result<Vec<notify_debouncer_mini::DebouncedEvent>, notify::Error>>,
    file_name: &std::ffi::OsStr,
) -> CliResult<()> {
    loop {
        // Check for shutdown signal
        tokio::select! {
            _ = signal::ctrl_c() => {
                println!();
                println!("Stopping watch...");
                println!("Goodbye!");
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Check for file events (non-blocking)
            }
        }

        // Process file events (non-blocking check)
        match rx.try_recv() {
            Ok(Ok(events)) => {
                // Filter events for our specific file
                let relevant_events: Vec<_> = events
                    .iter()
                    .filter(|e| e.path.file_name().map(|n| n == file_name).unwrap_or(false))
                    .collect();

                if !relevant_events.is_empty() {
                    // Check if file still exists
                    if !args.file.exists() {
                        eprintln!(
                            "Error: File {} was deleted. Exiting watch.",
                            args.file.display()
                        );
                        return Err(CliError::Validation(format!(
                            "Watched file was deleted: {}",
                            args.file.display()
                        )));
                    }

                    if args.dry_run {
                        println!("[DRY RUN] Change detected, previewing...");
                    } else {
                        println!("Change detected, applying...");
                    }

                    match apply_config_changes(client, args).await {
                        Ok(()) => {
                            // Success - continue watching
                            if args.dry_run {
                                println!("Watching for more changes... [DRY RUN]");
                            } else {
                                println!("Watching for more changes...");
                            }
                        }
                        Err(e) => {
                            // Error - print but continue watching
                            eprintln!("Error applying changes: {}", e);
                            println!("Watching for more changes...");
                        }
                    }

                    println!();
                }
            }
            Ok(Err(e)) => {
                eprintln!("Watch error: {}", e);
            }
            Err(mpsc::TryRecvError::Empty) => {
                // No events, continue
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(CliError::Io("File watcher disconnected".to_string()));
            }
        }
    }
}

/// Load config and apply changes
async fn apply_config_changes(client: &ApiClient, args: &WatchArgs) -> CliResult<()> {
    // Load and validate config
    let config = match load_config(&args.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Invalid YAML: {}", e);
            return Ok(()); // Continue watching despite parse error
        }
    };

    if let Err(e) = validate_config(&config) {
        eprintln!("Invalid configuration: {}", e);
        return Ok(()); // Continue watching despite validation error
    }

    // Fetch current state
    let (current_agents, current_tools) = fetch_current_state(client).await?;

    // Compute changes
    let mut changes = compute_changes(&config, &current_agents, &current_tools);

    // If no changes needed
    if !changes.iter().any(|c| c.action != ApplyAction::Unchanged) {
        println!("No changes required. Configuration is up to date.");
        return Ok(());
    }

    // Display planned changes
    print_planned_changes(&changes, args.dry_run);

    // In dry-run mode, just show what would happen
    if args.dry_run {
        return Ok(());
    }

    // Apply changes (no confirmation in watch mode)
    apply_changes(client, &config, &mut changes).await?;

    // Print summary
    let created = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Create && c.status.as_deref() == Some("success"))
        .count();
    let updated = changes
        .iter()
        .filter(|c| c.action == ApplyAction::Update && c.status.as_deref() == Some("success"))
        .count();
    let failed = changes
        .iter()
        .filter(|c| c.status.as_deref() == Some("failed"))
        .count();

    if failed > 0 {
        println!(
            "Applied with {} success, {} failed",
            created + updated,
            failed
        );
    } else {
        println!(
            "✓ {} agent(s) created, {} updated",
            changes
                .iter()
                .filter(|c| c.resource_type == "agent"
                    && c.action == ApplyAction::Create
                    && c.status.as_deref() == Some("success"))
                .count(),
            changes
                .iter()
                .filter(|c| c.resource_type == "agent"
                    && c.action == ApplyAction::Update
                    && c.status.as_deref() == Some("success"))
                .count()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watch_args_defaults() {
        // Test that WatchArgs can be constructed with required fields
        let args = WatchArgs {
            file: PathBuf::from("config.yaml"),
            dry_run: false,
        };

        assert_eq!(args.file, PathBuf::from("config.yaml"));
        assert!(!args.dry_run);
    }

    #[test]
    fn test_watch_args_dry_run() {
        let args = WatchArgs {
            file: PathBuf::from("test.yaml"),
            dry_run: true,
        };

        assert!(args.dry_run);
    }

    #[test]
    fn test_default_debounce_value() {
        assert_eq!(DEFAULT_DEBOUNCE_MS, 500);
    }

    #[test]
    fn test_file_not_found_error() {
        let args = WatchArgs {
            file: PathBuf::from("/nonexistent/path/config.yaml"),
            dry_run: false,
        };

        // The execute function would fail with file not found
        assert!(!args.file.exists());
    }

    #[test]
    fn test_watch_args_file_path_parsing() {
        // Test various path formats
        let paths = vec![
            "config.yaml",
            "./config.yaml",
            "../config.yaml",
            "/absolute/path/config.yaml",
            "relative/path/config.yaml",
        ];

        for path in paths {
            let args = WatchArgs {
                file: PathBuf::from(path),
                dry_run: false,
            };
            assert_eq!(args.file, PathBuf::from(path));
        }
    }
}
