//! Plugin state management
//!
//! Handles tracking of installed plugins, their status (enabled/disabled),
//! and persistence to the installed.json state file.

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use crate::plugin::{installed_state_path, plugins_dir};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Root structure for installed.json file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginState {
    /// Schema version for migrations
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Map of plugin name to installed state
    #[serde(default)]
    pub plugins: HashMap<String, InstalledPlugin>,
}

fn default_schema_version() -> u32 {
    1
}

/// Represents the state of an installed plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPlugin {
    /// Plugin name (matches manifest)
    pub name: String,
    /// Installed version
    pub version: String,
    /// Whether plugin is active
    pub enabled: bool,
    /// Installation timestamp (UTC)
    pub installed_at: DateTime<Utc>,
    /// Last update timestamp
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    /// Where plugin was installed from
    pub source: PluginSource,
    /// Absolute path to plugin directory
    pub path: PathBuf,
}

/// Source of plugin installation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PluginSource {
    /// Installed from plugin registry
    Registry {
        /// Registry URL
        url: String,
    },
    /// Installed from local filesystem
    Local {
        /// Original local path
        path: PathBuf,
    },
}

impl PluginState {
    /// Create a new empty plugin state
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            plugins: HashMap::new(),
        }
    }

    /// Load plugin state from the installed.json file
    pub fn load(paths: &ConfigPaths) -> CliResult<Self> {
        let state_path = installed_state_path(paths);

        if !state_path.exists() {
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(&state_path).map_err(|e| {
            CliError::Io(format!(
                "Failed to read plugin state file {}: {}",
                state_path.display(),
                e
            ))
        })?;

        serde_json::from_str(&content).map_err(|e| {
            CliError::Io(format!(
                "Failed to parse plugin state file {}: {}",
                state_path.display(),
                e
            ))
        })
    }

    /// Save plugin state to the installed.json file
    pub fn save(&self, paths: &ConfigPaths) -> CliResult<()> {
        // Ensure plugins directory exists
        let plugins = plugins_dir(paths);
        std::fs::create_dir_all(&plugins).map_err(|e| {
            CliError::Io(format!(
                "Failed to create plugins directory {}: {}",
                plugins.display(),
                e
            ))
        })?;

        let state_path = installed_state_path(paths);
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| CliError::Io(format!("Failed to serialize plugin state: {}", e)))?;

        std::fs::write(&state_path, content).map_err(|e| {
            CliError::Io(format!(
                "Failed to write plugin state file {}: {}",
                state_path.display(),
                e
            ))
        })
    }

    /// Get an installed plugin by name
    pub fn get(&self, name: &str) -> Option<&InstalledPlugin> {
        self.plugins.get(name)
    }

    /// Get a mutable reference to an installed plugin
    pub fn get_mut(&mut self, name: &str) -> Option<&mut InstalledPlugin> {
        self.plugins.get_mut(name)
    }

    /// Check if a plugin is installed
    pub fn is_installed(&self, name: &str) -> bool {
        self.plugins.contains_key(name)
    }

    /// Add or update an installed plugin
    pub fn add(&mut self, plugin: InstalledPlugin) {
        self.plugins.insert(plugin.name.clone(), plugin);
    }

    /// Remove an installed plugin
    pub fn remove(&mut self, name: &str) -> Option<InstalledPlugin> {
        self.plugins.remove(name)
    }

    /// Get all installed plugins
    pub fn all(&self) -> impl Iterator<Item = &InstalledPlugin> {
        self.plugins.values()
    }

    /// Get all enabled plugins
    #[allow(dead_code)]
    pub fn enabled(&self) -> impl Iterator<Item = &InstalledPlugin> {
        self.plugins.values().filter(|p| p.enabled)
    }

    /// Get count of installed plugins
    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.plugins.len()
    }
}

impl InstalledPlugin {
    /// Create a new installed plugin record
    pub fn new(name: String, version: String, source: PluginSource, path: PathBuf) -> Self {
        Self {
            name,
            version,
            enabled: true,
            installed_at: Utc::now(),
            updated_at: None,
            source,
            path,
        }
    }

    /// Enable this plugin
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this plugin
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Update version and timestamp
    pub fn update_version(&mut self, new_version: String) {
        self.version = new_version;
        self.updated_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_paths() -> (TempDir, ConfigPaths) {
        let temp = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp.path().to_path_buf(),
            config_file: temp.path().join("config.json"),
            session_file: temp.path().join("session.json"),
            credentials_file: temp.path().join("credentials.json"),
            cache_dir: temp.path().join("cache"),
            history_file: temp.path().join("shell_history"),
            version_history_dir: temp.path().join("history"),
        };
        (temp, paths)
    }

    #[test]
    fn test_new_state() {
        let state = PluginState::new();
        assert_eq!(state.schema_version, 1);
        assert!(state.plugins.is_empty());
    }

    #[test]
    fn test_add_plugin() {
        let mut state = PluginState::new();
        let plugin = InstalledPlugin::new(
            "test-plugin".to_string(),
            "1.0.0".to_string(),
            PluginSource::Registry {
                url: "https://example.com".to_string(),
            },
            PathBuf::from("/tmp/plugins/test-plugin"),
        );

        state.add(plugin);

        assert!(state.is_installed("test-plugin"));
        assert_eq!(state.count(), 1);
    }

    #[test]
    fn test_remove_plugin() {
        let mut state = PluginState::new();
        let plugin = InstalledPlugin::new(
            "test-plugin".to_string(),
            "1.0.0".to_string(),
            PluginSource::Local {
                path: PathBuf::from("/tmp/local-plugin"),
            },
            PathBuf::from("/tmp/plugins/test-plugin"),
        );

        state.add(plugin);
        assert!(state.is_installed("test-plugin"));

        let removed = state.remove("test-plugin");
        assert!(removed.is_some());
        assert!(!state.is_installed("test-plugin"));
    }

    #[test]
    fn test_enable_disable() {
        let mut plugin = InstalledPlugin::new(
            "test".to_string(),
            "1.0.0".to_string(),
            PluginSource::Registry {
                url: "https://example.com".to_string(),
            },
            PathBuf::from("/tmp/test"),
        );

        assert!(plugin.enabled);

        plugin.disable();
        assert!(!plugin.enabled);

        plugin.enable();
        assert!(plugin.enabled);
    }

    #[test]
    fn test_save_load() {
        let (_temp, paths) = test_paths();

        let mut state = PluginState::new();
        state.add(InstalledPlugin::new(
            "saved-plugin".to_string(),
            "2.0.0".to_string(),
            PluginSource::Registry {
                url: "https://plugins.xavyo.io".to_string(),
            },
            PathBuf::from("/tmp/plugins/saved-plugin"),
        ));

        state.save(&paths).unwrap();

        let loaded = PluginState::load(&paths).unwrap();
        assert!(loaded.is_installed("saved-plugin"));
        assert_eq!(loaded.get("saved-plugin").unwrap().version, "2.0.0");
    }

    #[test]
    fn test_enabled_filter() {
        let mut state = PluginState::new();

        let mut enabled_plugin = InstalledPlugin::new(
            "enabled".to_string(),
            "1.0.0".to_string(),
            PluginSource::Local {
                path: PathBuf::from("/tmp/enabled"),
            },
            PathBuf::from("/tmp/plugins/enabled"),
        );

        let mut disabled_plugin = InstalledPlugin::new(
            "disabled".to_string(),
            "1.0.0".to_string(),
            PluginSource::Local {
                path: PathBuf::from("/tmp/disabled"),
            },
            PathBuf::from("/tmp/plugins/disabled"),
        );
        disabled_plugin.disable();

        state.add(enabled_plugin);
        state.add(disabled_plugin);

        let enabled_count = state.enabled().count();
        assert_eq!(enabled_count, 1);
    }
}
