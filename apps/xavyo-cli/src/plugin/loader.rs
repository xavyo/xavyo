//! Plugin loader and command execution
//!
//! Handles loading enabled plugins at CLI startup and executing plugin commands
//! as subprocesses.

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use crate::plugin::manifest::{PluginCommand, PluginManifest};
use crate::plugin::state::{InstalledPlugin, PluginState};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Represents a loaded plugin with its manifest and commands
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LoadedPlugin {
    /// Plugin name
    pub name: String,
    /// Plugin manifest
    pub manifest: PluginManifest,
    /// Path to the plugin directory
    pub path: PathBuf,
    /// Available commands
    pub commands: Vec<PluginCommand>,
}

/// Plugin loader that manages loaded plugins
#[allow(dead_code)]
pub struct PluginLoader {
    /// Loaded plugins by name
    plugins: HashMap<String, LoadedPlugin>,
    /// Command to plugin mapping (for quick lookup)
    command_map: HashMap<String, String>,
    /// Conflicting commands (command -> original plugin name)
    conflicts: HashMap<String, String>,
}

#[allow(dead_code)]
impl PluginLoader {
    /// Create a new empty plugin loader
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            command_map: HashMap::new(),
            conflicts: HashMap::new(),
        }
    }

    /// Load all enabled plugins from the plugin state
    pub fn load_enabled_plugins(&mut self, paths: &ConfigPaths) -> CliResult<()> {
        let state = PluginState::load(paths)?;

        for plugin in state.enabled() {
            if let Err(e) = self.load_plugin(plugin) {
                // Log warning but continue loading other plugins
                eprintln!("Warning: Failed to load plugin '{}': {}", plugin.name, e);
            }
        }

        Ok(())
    }

    /// Load a single plugin
    fn load_plugin(&mut self, installed: &InstalledPlugin) -> CliResult<()> {
        let manifest_path = installed.path.join("plugin.toml");
        let manifest = PluginManifest::load(&manifest_path)?;

        // Register commands and track conflicts
        for cmd in &manifest.commands {
            if let Some(existing) = self.command_map.get(&cmd.name) {
                // Command conflict - track it
                self.conflicts.insert(cmd.name.clone(), existing.clone());
            } else {
                self.command_map
                    .insert(cmd.name.clone(), manifest.plugin.name.clone());
            }
        }

        let loaded = LoadedPlugin {
            name: manifest.plugin.name.clone(),
            commands: manifest.commands.clone(),
            manifest,
            path: installed.path.clone(),
        };

        self.plugins.insert(loaded.name.clone(), loaded);

        Ok(())
    }

    /// Get a loaded plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<&LoadedPlugin> {
        self.plugins.get(name)
    }

    /// Get all loaded plugins
    pub fn all_plugins(&self) -> impl Iterator<Item = &LoadedPlugin> {
        self.plugins.values()
    }

    /// Find which plugin provides a command
    pub fn find_command_plugin(&self, command: &str) -> Option<&LoadedPlugin> {
        self.command_map
            .get(command)
            .and_then(|name| self.plugins.get(name))
    }

    /// Check if a command conflicts with another plugin
    pub fn has_conflict(&self, command: &str) -> bool {
        self.conflicts.contains_key(command)
    }

    /// Get the original plugin that claimed a conflicting command
    pub fn get_conflict_source(&self, command: &str) -> Option<&str> {
        self.conflicts.get(command).map(|s| s.as_str())
    }

    /// Get all available commands (for help display)
    pub fn all_commands(&self) -> Vec<(&str, &str, &str)> {
        let mut commands = Vec::new();

        for plugin in self.plugins.values() {
            for cmd in &plugin.commands {
                commands.push((
                    plugin.name.as_str(),
                    cmd.name.as_str(),
                    cmd.description.as_str(),
                ));
            }
        }

        commands.sort_by(|a, b| a.1.cmp(b.1));
        commands
    }

    /// Execute a plugin command
    pub fn execute_command(
        &self,
        plugin_name: &str,
        command_name: &str,
        args: &[String],
    ) -> CliResult<i32> {
        let plugin = self
            .plugins
            .get(plugin_name)
            .ok_or_else(|| CliError::PluginNotFound {
                name: plugin_name.to_string(),
            })?;

        let cmd = plugin
            .commands
            .iter()
            .find(|c| c.name == command_name)
            .ok_or_else(|| CliError::PluginCommandNotFound {
                plugin: plugin_name.to_string(),
                command: command_name.to_string(),
            })?;

        let binary_path = plugin.path.join("bin").join(&cmd.binary);

        if !binary_path.exists() {
            return Err(CliError::PluginInvalid {
                name: plugin_name.to_string(),
                reason: format!("Binary '{}' not found", cmd.binary),
            });
        }

        // Build command arguments
        let mut cmd_args = Vec::new();
        if let Some(ref subcommand) = cmd.subcommand {
            cmd_args.push(subcommand.clone());
        }
        cmd_args.extend(args.iter().cloned());

        // Execute the plugin binary
        let status = Command::new(&binary_path)
            .args(&cmd_args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| CliError::PluginExecutionError {
                plugin: plugin_name.to_string(),
                command: command_name.to_string(),
                details: e.to_string(),
            })?;

        Ok(status.code().unwrap_or(-1))
    }
}

impl Default for PluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Core CLI commands that plugins cannot override
#[allow(dead_code)]
pub const CORE_COMMANDS: &[&str] = &[
    "login",
    "logout",
    "signup",
    "setup",
    "whoami",
    "status",
    "doctor",
    "agents",
    "tools",
    "authorize",
    "apply",
    "export",
    "watch",
    "completions",
    "upgrade",
    "init",
    "diff",
    "rollback",
    "sessions",
    "audit",
    "shell",
    "cache",
    "plugin", // The plugin command itself
];

/// Check if a command name conflicts with a core command
#[allow(dead_code)]
pub fn conflicts_with_core(command: &str) -> bool {
    CORE_COMMANDS.contains(&command)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_loader() {
        let loader = PluginLoader::new();
        assert_eq!(loader.plugins.len(), 0);
        assert_eq!(loader.command_map.len(), 0);
    }

    #[test]
    fn test_all_commands_empty() {
        let loader = PluginLoader::new();
        let commands = loader.all_commands();
        assert!(commands.is_empty());
    }

    #[test]
    fn test_conflicts_with_core() {
        assert!(conflicts_with_core("login"));
        assert!(conflicts_with_core("plugin"));
        assert!(!conflicts_with_core("custom-command"));
        assert!(!conflicts_with_core("my-plugin"));
    }

    #[test]
    fn test_core_commands_coverage() {
        // Ensure we have all expected core commands
        assert!(CORE_COMMANDS.contains(&"agents"));
        assert!(CORE_COMMANDS.contains(&"tools"));
        assert!(CORE_COMMANDS.contains(&"apply"));
        assert!(CORE_COMMANDS.contains(&"export"));
    }
}
