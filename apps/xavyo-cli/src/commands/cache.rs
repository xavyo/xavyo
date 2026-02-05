//! Cache management CLI commands

use crate::cache::{CacheStore, FileCacheStore};
use crate::config::ConfigPaths;
use crate::error::CliResult;
use clap::{Args, Subcommand};
use dialoguer::Confirm;

/// Cache management commands
#[derive(Args, Debug)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: CacheCommands,
}

#[derive(Subcommand, Debug)]
pub enum CacheCommands {
    /// Show cache status and information
    Status(CacheStatusArgs),
    /// Clear all cached data
    Clear(CacheClearArgs),
}

/// Arguments for the cache status command
#[derive(Args, Debug)]
pub struct CacheStatusArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Arguments for the cache clear command
#[derive(Args, Debug)]
pub struct CacheClearArgs {
    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Execute cache commands
pub async fn execute(args: CacheArgs) -> CliResult<()> {
    match args.command {
        CacheCommands::Status(status_args) => execute_cache_status(status_args).await,
        CacheCommands::Clear(clear_args) => execute_cache_clear(clear_args).await,
    }
}

/// Execute cache status command
async fn execute_cache_status(args: CacheStatusArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let store = FileCacheStore::new(&paths)?;

    let status = store.status()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Cache Status:");
        println!("  Location: {}", status.cache_dir.display());
        println!("  Total Size: {}", status.size_human());
        println!("  Entries: {}", status.entry_count);
        println!(
            "  Default TTL: {} seconds ({} hour)",
            status.default_ttl_seconds,
            status.default_ttl_seconds / 3600
        );
        println!();

        if status.is_empty() {
            println!("No cached resources.");
        } else {
            println!("Cached Resources:");
            println!(
                "  {:<12} | {:<20} | {:<8} | Size",
                "Resource", "Cached At", "Status"
            );
            println!("  {}", "-".repeat(60));

            for resource in &status.cached_resources {
                println!(
                    "  {:<12} | {:<20} | {:<8} | {}",
                    resource.resource_type,
                    resource.cached_at.format("%Y-%m-%d %H:%M:%S"),
                    resource.status_str(),
                    resource.size_human()
                );
            }
        }
        println!();
    }

    Ok(())
}

/// Execute cache clear command
async fn execute_cache_clear(args: CacheClearArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    let store = FileCacheStore::new(&paths)?;

    // Get current status for summary
    let status = store.status()?;

    if status.is_empty() {
        println!("Cache is already empty.");
        return Ok(());
    }

    // Confirm unless --yes is used
    if !args.yes {
        if !atty::is(atty::Stream::Stdin) {
            return Err(crate::error::CliError::Validation(
                "Cannot confirm cache clear in non-interactive mode. Use --yes to skip confirmation."
                    .to_string(),
            ));
        }

        let confirm = Confirm::new()
            .with_prompt(format!(
                "Clear {} cached entries ({})? This cannot be undone.",
                status.entry_count,
                status.size_human()
            ))
            .default(false)
            .interact()?;

        if !confirm {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Clear the cache
    let count = store.clear_all()?;

    println!("Cache cleared successfully.");
    println!("Removed {} entries ({})", count, status.size_human());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_status_args() {
        let args = CacheStatusArgs { json: true };
        assert!(args.json);
    }

    #[test]
    fn test_cache_clear_args() {
        let args = CacheClearArgs { yes: true };
        assert!(args.yes);
    }
}
