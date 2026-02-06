//! Plugin management commands
//!
//! Commands for discovering, installing, managing, and creating plugins.

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use crate::plugin::manifest::PluginManifest;
use crate::plugin::registry::{extract_plugin_package, RegistryClient};
use crate::plugin::scaffold::create_plugin_scaffold;
use crate::plugin::state::{InstalledPlugin, PluginSource, PluginState};
use crate::plugin::{ensure_plugins_dir, packages_dir};
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// CLI arguments for the plugin command
#[derive(Args)]
pub struct PluginArgs {
    #[command(subcommand)]
    pub command: PluginCommand,
}

/// Plugin subcommands
#[derive(Subcommand)]
pub enum PluginCommand {
    /// List available or installed plugins
    List(ListArgs),
    /// Install a plugin from the registry or local path
    Install(InstallArgs),
    /// Uninstall a plugin
    Uninstall(UninstallArgs),
    /// Enable a disabled plugin
    Enable(EnableArgs),
    /// Disable an installed plugin
    Disable(DisableArgs),
    /// Update a plugin to the latest version
    Update(UpdateArgs),
    /// Initialize a new plugin project
    Init(InitArgs),
    /// Validate a plugin manifest
    Validate(ValidateArgs),
}

/// Arguments for plugin list
#[derive(Args)]
pub struct ListArgs {
    /// Only show installed plugins
    #[arg(short, long)]
    pub installed: bool,
}

/// Arguments for plugin install
#[derive(Args)]
pub struct InstallArgs {
    /// Plugin name (from registry) or path (with --path)
    pub name: String,
    /// Install from a local path instead of the registry
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Skip version compatibility check
    #[arg(long)]
    pub force: bool,
}

/// Arguments for plugin uninstall
#[derive(Args)]
pub struct UninstallArgs {
    /// Plugin name to uninstall
    pub name: String,
}

/// Arguments for plugin enable
#[derive(Args)]
pub struct EnableArgs {
    /// Plugin name to enable
    pub name: String,
}

/// Arguments for plugin disable
#[derive(Args)]
pub struct DisableArgs {
    /// Plugin name to disable
    pub name: String,
}

/// Arguments for plugin update
#[derive(Args)]
pub struct UpdateArgs {
    /// Plugin name to update (or --all for all plugins)
    pub name: Option<String>,
    /// Update all installed plugins
    #[arg(long)]
    pub all: bool,
}

/// Arguments for plugin init
#[derive(Args)]
pub struct InitArgs {
    /// Name for the new plugin
    pub name: String,
    /// Directory to create plugin in (default: current directory)
    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,
}

/// Arguments for plugin validate
#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the plugin directory (default: current directory)
    pub path: Option<PathBuf>,
}

/// Execute the plugin command
pub async fn execute(args: PluginArgs) -> CliResult<()> {
    let paths = ConfigPaths::new()?;
    ensure_plugins_dir(&paths)?;

    match args.command {
        PluginCommand::List(list_args) => execute_list(list_args, &paths).await,
        PluginCommand::Install(install_args) => execute_install(install_args, &paths).await,
        PluginCommand::Uninstall(uninstall_args) => execute_uninstall(uninstall_args, &paths).await,
        PluginCommand::Enable(enable_args) => execute_enable(enable_args, &paths).await,
        PluginCommand::Disable(disable_args) => execute_disable(disable_args, &paths).await,
        PluginCommand::Update(update_args) => execute_update(update_args, &paths).await,
        PluginCommand::Init(init_args) => execute_init(init_args),
        PluginCommand::Validate(validate_args) => execute_validate(validate_args),
    }
}

/// Execute plugin list command
async fn execute_list(args: ListArgs, paths: &ConfigPaths) -> CliResult<()> {
    if args.installed {
        // List installed plugins
        let state = PluginState::load(paths)?;
        let plugins: Vec<_> = state.all().collect();

        if plugins.is_empty() {
            println!("No plugins installed.");
            println!();
            println!("Install plugins with: xavyo plugin install <name>");
            return Ok(());
        }

        println!("Installed plugins:");
        println!();
        for plugin in plugins {
            let status = if plugin.enabled {
                "enabled"
            } else {
                "disabled"
            };
            println!("  {} v{} ({})", plugin.name, plugin.version, status);
        }
    } else {
        // List available plugins from registry
        let client = RegistryClient::new();
        match client.fetch_plugins().await {
            Ok(plugins) => {
                if plugins.is_empty() {
                    println!("No plugins available in the registry.");
                    return Ok(());
                }

                println!("Available plugins:");
                println!();
                for plugin in plugins {
                    let author = plugin.author.as_deref().unwrap_or("Unknown");
                    println!("  {} v{}", plugin.name, plugin.version);
                    println!("    {}", plugin.description);
                    println!("    Author: {}", author);
                    println!();
                }
            }
            Err(e) => {
                eprintln!("Failed to fetch plugins from registry: {}", e);
                eprintln!();
                eprintln!("Use --installed to list locally installed plugins.");
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Execute plugin install command
async fn execute_install(args: InstallArgs, paths: &ConfigPaths) -> CliResult<()> {
    let mut state = PluginState::load(paths)?;

    // Check if already installed
    if state.is_installed(&args.name) {
        return Err(CliError::PluginAlreadyInstalled {
            name: args.name.clone(),
        });
    }

    if let Some(local_path) = args.path {
        // Install from local path
        install_from_local(&args.name, &local_path, &mut state, paths, args.force).await
    } else {
        // Install from registry
        install_from_registry(&args.name, &mut state, paths, args.force).await
    }
}

/// Install a plugin from a local path
async fn install_from_local(
    name: &str,
    local_path: &PathBuf,
    state: &mut PluginState,
    paths: &ConfigPaths,
    force: bool,
) -> CliResult<()> {
    // Verify manifest exists
    let manifest_path = local_path.join("plugin.toml");
    if !manifest_path.exists() {
        return Err(CliError::ManifestParseError {
            path: manifest_path.display().to_string(),
            details: "plugin.toml not found in the specified path".to_string(),
        });
    }

    // Load and validate manifest
    let manifest = PluginManifest::load(&manifest_path)?;
    manifest.validate()?;

    // Check version compatibility
    if !force {
        let cli_version = env!("CARGO_PKG_VERSION");
        if !manifest.is_compatible_with(cli_version)? {
            return Err(CliError::VersionMismatch {
                name: manifest.plugin.name.clone(),
                required: manifest
                    .plugin
                    .min_cli_version
                    .clone()
                    .unwrap_or_else(|| "any".to_string()),
                current: cli_version.to_string(),
            });
        }
    }

    // Copy to packages directory
    let dest_dir = packages_dir(paths).join(name);
    if dest_dir.exists() {
        std::fs::remove_dir_all(&dest_dir).map_err(|e| {
            CliError::Io(format!("Failed to remove existing plugin directory: {}", e))
        })?;
    }

    copy_dir_recursive(local_path, &dest_dir)?;

    // Add to installed state
    let plugin = InstalledPlugin::new(
        manifest.plugin.name.clone(),
        manifest.plugin.version.clone(),
        PluginSource::Local {
            path: local_path.clone(),
        },
        dest_dir,
    );
    state.add(plugin);
    state.save(paths)?;

    println!(
        "Plugin '{}' v{} installed successfully.",
        name, manifest.plugin.version
    );
    Ok(())
}

/// Install a plugin from the registry
async fn install_from_registry(
    name: &str,
    state: &mut PluginState,
    paths: &ConfigPaths,
    force: bool,
) -> CliResult<()> {
    let client = RegistryClient::new();

    // Fetch plugin info
    println!("Fetching plugin '{}'...", name);
    let plugin_info = client.fetch_plugin(name).await?;

    // Check version compatibility
    if !force {
        if let Some(ref min_version) = plugin_info.min_cli_version {
            let cli_version = env!("CARGO_PKG_VERSION");
            let min = semver::Version::parse(min_version).map_err(|_| CliError::PluginInvalid {
                name: name.to_string(),
                reason: format!("Invalid min_cli_version: {}", min_version),
            })?;
            let current =
                semver::Version::parse(cli_version).map_err(|_| CliError::PluginInvalid {
                    name: name.to_string(),
                    reason: format!("Invalid CLI version: {}", cli_version),
                })?;
            if current < min {
                return Err(CliError::VersionMismatch {
                    name: name.to_string(),
                    required: min_version.clone(),
                    current: cli_version.to_string(),
                });
            }
        }
    }

    // Download plugin
    println!("Downloading plugin...");
    let temp_dir = std::env::temp_dir();
    let archive_path = temp_dir.join(format!("{}-{}.tar.gz", name, plugin_info.version));
    client.download_plugin(&plugin_info, &archive_path).await?;

    // Extract plugin
    println!("Extracting plugin...");
    let dest_dir = packages_dir(paths).join(name);
    if dest_dir.exists() {
        std::fs::remove_dir_all(&dest_dir).map_err(|e| {
            CliError::Io(format!("Failed to remove existing plugin directory: {}", e))
        })?;
    }
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| CliError::Io(format!("Failed to create plugin directory: {}", e)))?;

    extract_plugin_package(&archive_path, &dest_dir)?;

    // Validate extracted plugin
    let manifest_path = dest_dir.join("plugin.toml");
    let manifest = PluginManifest::load(&manifest_path)?;
    manifest.validate()?;

    // Add to installed state
    let plugin = InstalledPlugin::new(
        plugin_info.name.clone(),
        plugin_info.version.clone(),
        PluginSource::Registry {
            url: client.registry_url.clone(),
        },
        dest_dir,
    );
    state.add(plugin);
    state.save(paths)?;

    println!(
        "Plugin '{}' v{} installed successfully.",
        plugin_info.name, plugin_info.version
    );
    Ok(())
}

/// Execute plugin uninstall command
async fn execute_uninstall(args: UninstallArgs, paths: &ConfigPaths) -> CliResult<()> {
    let mut state = PluginState::load(paths)?;

    let plugin = state
        .remove(&args.name)
        .ok_or_else(|| CliError::PluginNotFound {
            name: args.name.clone(),
        })?;

    // Remove plugin directory
    if plugin.path.exists() {
        std::fs::remove_dir_all(&plugin.path).map_err(|e| {
            CliError::Io(format!(
                "Failed to remove plugin directory {}: {}",
                plugin.path.display(),
                e
            ))
        })?;
    }

    state.save(paths)?;

    println!("Plugin '{}' uninstalled successfully.", args.name);
    Ok(())
}

/// Execute plugin enable command
async fn execute_enable(args: EnableArgs, paths: &ConfigPaths) -> CliResult<()> {
    let mut state = PluginState::load(paths)?;

    let plugin = state
        .get_mut(&args.name)
        .ok_or_else(|| CliError::PluginNotFound {
            name: args.name.clone(),
        })?;

    if plugin.enabled {
        println!("Plugin '{}' is already enabled.", args.name);
        return Ok(());
    }

    plugin.enable();
    state.save(paths)?;

    println!("Plugin '{}' enabled.", args.name);
    Ok(())
}

/// Execute plugin disable command
async fn execute_disable(args: DisableArgs, paths: &ConfigPaths) -> CliResult<()> {
    let mut state = PluginState::load(paths)?;

    let plugin = state
        .get_mut(&args.name)
        .ok_or_else(|| CliError::PluginNotFound {
            name: args.name.clone(),
        })?;

    if !plugin.enabled {
        println!("Plugin '{}' is already disabled.", args.name);
        return Ok(());
    }

    plugin.disable();
    state.save(paths)?;

    println!("Plugin '{}' disabled.", args.name);
    Ok(())
}

/// Execute plugin update command
async fn execute_update(args: UpdateArgs, paths: &ConfigPaths) -> CliResult<()> {
    let mut state = PluginState::load(paths)?;
    let client = RegistryClient::new();

    if args.all {
        // Update all plugins
        let plugin_names: Vec<String> = state.all().map(|p| p.name.clone()).collect();

        if plugin_names.is_empty() {
            println!("No plugins installed.");
            return Ok(());
        }

        println!("Checking for updates...");
        let mut updated = 0;

        for name in plugin_names {
            match update_single_plugin(&name, &mut state, &client, paths).await {
                Ok(true) => updated += 1,
                Ok(false) => {}
                Err(e) => eprintln!("Failed to update '{}': {}", name, e),
            }
        }

        if updated == 0 {
            println!("All plugins are up to date.");
        } else {
            println!("{} plugin(s) updated.", updated);
        }
    } else if let Some(name) = args.name {
        // Update single plugin
        if !state.is_installed(&name) {
            return Err(CliError::PluginNotFound { name });
        }

        match update_single_plugin(&name, &mut state, &client, paths).await? {
            true => println!("Plugin '{}' updated successfully.", name),
            false => println!("Plugin '{}' is already at the latest version.", name),
        }
    } else {
        return Err(CliError::Config(
            "Specify a plugin name or use --all to update all plugins".to_string(),
        ));
    }

    Ok(())
}

/// Update a single plugin, returns true if updated
async fn update_single_plugin(
    name: &str,
    state: &mut PluginState,
    client: &RegistryClient,
    paths: &ConfigPaths,
) -> CliResult<bool> {
    let plugin = state.get(name).ok_or_else(|| CliError::PluginNotFound {
        name: name.to_string(),
    })?;

    // Only update registry-installed plugins
    match &plugin.source {
        PluginSource::Registry { .. } => {}
        PluginSource::Local { .. } => {
            println!("  {} (local plugin, skipping)", name);
            return Ok(false);
        }
    }

    let current_version =
        semver::Version::parse(&plugin.version).map_err(|_| CliError::PluginInvalid {
            name: name.to_string(),
            reason: format!("Invalid current version: {}", plugin.version),
        })?;

    // Fetch latest version from registry
    let latest = client.fetch_plugin(name).await?;
    let latest_version =
        semver::Version::parse(&latest.version).map_err(|_| CliError::PluginInvalid {
            name: name.to_string(),
            reason: format!("Invalid registry version: {}", latest.version),
        })?;

    if latest_version <= current_version {
        return Ok(false);
    }

    println!("  {} {} -> {}", name, plugin.version, latest.version);

    // Download and install new version
    let temp_dir = std::env::temp_dir();
    let archive_path = temp_dir.join(format!("{}-{}.tar.gz", name, latest.version));
    client.download_plugin(&latest, &archive_path).await?;

    // Extract to packages directory
    let dest_dir = packages_dir(paths).join(name);
    if dest_dir.exists() {
        std::fs::remove_dir_all(&dest_dir)
            .map_err(|e| CliError::Io(format!("Failed to remove old plugin: {}", e)))?;
    }
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| CliError::Io(format!("Failed to create plugin directory: {}", e)))?;

    extract_plugin_package(&archive_path, &dest_dir)?;

    // Update state
    if let Some(plugin) = state.get_mut(name) {
        plugin.update_version(latest.version);
    }
    state.save(paths)?;

    Ok(true)
}

/// Execute plugin init command
fn execute_init(args: InitArgs) -> CliResult<()> {
    let output_dir = args.output.unwrap_or_else(|| PathBuf::from("."));

    create_plugin_scaffold(&args.name, &output_dir)?;

    let plugin_dir = output_dir.join(&args.name);
    println!("Plugin '{}' created at {}", args.name, plugin_dir.display());
    println!();
    println!("Next steps:");
    println!("  1. cd {}", plugin_dir.display());
    println!("  2. Edit plugin.toml with your plugin details");
    println!("  3. cargo build --release");
    println!("  4. cp target/release/{} bin/", args.name);
    println!("  5. xavyo plugin install --path .");

    Ok(())
}

/// Execute plugin validate command
fn execute_validate(args: ValidateArgs) -> CliResult<()> {
    let path = args.path.unwrap_or_else(|| PathBuf::from("."));
    let manifest_path = path.join("plugin.toml");

    if !manifest_path.exists() {
        return Err(CliError::ManifestParseError {
            path: manifest_path.display().to_string(),
            details: "plugin.toml not found".to_string(),
        });
    }

    let manifest = PluginManifest::load(&manifest_path)?;

    match manifest.validate() {
        Ok(()) => {
            println!("Plugin manifest is valid.");
            println!();
            println!("  Name: {}", manifest.plugin.name);
            println!("  Version: {}", manifest.plugin.version);
            println!("  Commands: {}", manifest.commands.len());
            for cmd in &manifest.commands {
                println!("    - {} ({})", cmd.name, cmd.description);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Plugin manifest validation failed:");
            eprintln!("  {}", e);
            Err(e)
        }
    }
}

/// Recursively copy a directory
fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> CliResult<()> {
    std::fs::create_dir_all(dst).map_err(|e| {
        CliError::Io(format!(
            "Failed to create directory {}: {}",
            dst.display(),
            e
        ))
    })?;

    for entry in std::fs::read_dir(src)
        .map_err(|e| CliError::Io(format!("Failed to read directory {}: {}", src.display(), e)))?
    {
        let entry = entry.map_err(|e| CliError::Io(format!("Failed to read entry: {}", e)))?;
        let path = entry.path();
        let dest_path = dst.join(entry.file_name());

        if path.is_dir() {
            copy_dir_recursive(&path, &dest_path)?;
        } else {
            std::fs::copy(&path, &dest_path).map_err(|e| {
                CliError::Io(format!(
                    "Failed to copy {} to {}: {}",
                    path.display(),
                    dest_path.display(),
                    e
                ))
            })?;
        }
    }

    Ok(())
}
