//! Plugin manifest parsing and validation
//!
//! Handles parsing of plugin.toml files that describe plugin metadata,
//! commands, and requirements.

use crate::error::{CliError, CliResult};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Plugin manifest structure (plugin.toml)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin metadata section
    pub plugin: PluginMetadata,
    /// Commands provided by the plugin
    #[serde(default)]
    pub commands: Vec<PluginCommand>,
}

/// Plugin metadata from the [plugin] section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Unique plugin identifier (lowercase, alphanumeric + hyphens)
    pub name: String,
    /// Plugin version (semver)
    pub version: String,
    /// Human-readable description
    pub description: String,
    /// Plugin author name or organization
    #[serde(default)]
    pub author: Option<String>,
    /// Minimum required xavyo-cli version
    #[serde(default)]
    pub min_cli_version: Option<String>,
    /// URL to plugin homepage
    #[serde(default)]
    pub homepage: Option<String>,
    /// URL to source repository
    #[serde(default)]
    pub repository: Option<String>,
    /// License identifier (e.g., "MIT")
    #[serde(default)]
    pub license: Option<String>,
}

/// Command definition from a plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginCommand {
    /// Command name as invoked by user
    pub name: String,
    /// Help text for the command
    pub description: String,
    /// Name of executable file in plugin's bin/ directory
    pub binary: String,
    /// If set, passed as first argument to binary
    #[serde(default)]
    pub subcommand: Option<String>,
    /// Argument definitions for help generation
    #[serde(default)]
    pub args: Vec<ArgDefinition>,
}

/// Argument definition for command help text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgDefinition {
    /// Argument name
    pub name: String,
    /// Help text for argument
    pub description: String,
    /// Whether argument is required
    #[serde(default)]
    pub required: bool,
    /// Short flag (e.g., 'v' for -v)
    #[serde(default)]
    pub short: Option<char>,
}

impl PluginManifest {
    /// Parse a plugin manifest from TOML content
    #[allow(dead_code)]
    pub fn parse(content: &str) -> CliResult<Self> {
        toml::from_str(content).map_err(|e| CliError::ManifestParseError {
            path: "inline".to_string(),
            details: e.to_string(),
        })
    }

    /// Load a plugin manifest from a file
    pub fn load(path: &Path) -> CliResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| CliError::ManifestParseError {
            path: path.display().to_string(),
            details: format!("Failed to read file: {}", e),
        })?;

        toml::from_str(&content).map_err(|e| CliError::ManifestParseError {
            path: path.display().to_string(),
            details: e.to_string(),
        })
    }

    /// Validate the manifest structure and content
    pub fn validate(&self) -> CliResult<()> {
        // Validate plugin name format
        if !is_valid_plugin_name(&self.plugin.name) {
            return Err(CliError::PluginInvalid {
                name: self.plugin.name.clone(),
                reason: "Plugin name must be lowercase alphanumeric with hyphens, 2-50 characters"
                    .to_string(),
            });
        }

        // Validate version is valid semver
        if Version::parse(&self.plugin.version).is_err() {
            return Err(CliError::PluginInvalid {
                name: self.plugin.name.clone(),
                reason: format!(
                    "Invalid version '{}': must be valid semver",
                    self.plugin.version
                ),
            });
        }

        // Validate min_cli_version if present
        if let Some(ref min_version) = self.plugin.min_cli_version {
            if Version::parse(min_version).is_err() {
                return Err(CliError::PluginInvalid {
                    name: self.plugin.name.clone(),
                    reason: format!(
                        "Invalid min_cli_version '{}': must be valid semver",
                        min_version
                    ),
                });
            }
        }

        // Validate at least one command
        if self.commands.is_empty() {
            return Err(CliError::PluginInvalid {
                name: self.plugin.name.clone(),
                reason: "Plugin must define at least one command".to_string(),
            });
        }

        // Validate each command
        for cmd in &self.commands {
            if !is_valid_command_name(&cmd.name) {
                return Err(CliError::PluginInvalid {
                    name: self.plugin.name.clone(),
                    reason: format!(
                        "Invalid command name '{}': must be lowercase alphanumeric with hyphens",
                        cmd.name
                    ),
                });
            }
        }

        Ok(())
    }

    /// Check if this plugin is compatible with the given CLI version
    pub fn is_compatible_with(&self, cli_version: &str) -> CliResult<bool> {
        if let Some(ref min_version) = self.plugin.min_cli_version {
            let min = Version::parse(min_version).map_err(|_| CliError::PluginInvalid {
                name: self.plugin.name.clone(),
                reason: format!("Invalid min_cli_version: {}", min_version),
            })?;

            let current = Version::parse(cli_version).map_err(|_| CliError::PluginInvalid {
                name: self.plugin.name.clone(),
                reason: format!("Invalid CLI version: {}", cli_version),
            })?;

            Ok(current >= min)
        } else {
            // No minimum version specified, compatible with all versions
            Ok(true)
        }
    }

    /// Get the parsed version
    #[allow(dead_code)]
    pub fn version(&self) -> CliResult<Version> {
        Version::parse(&self.plugin.version).map_err(|_| CliError::PluginInvalid {
            name: self.plugin.name.clone(),
            reason: format!("Invalid version: {}", self.plugin.version),
        })
    }
}

/// Check if a plugin name is valid
fn is_valid_plugin_name(name: &str) -> bool {
    if name.len() < 2 || name.len() > 50 {
        return false;
    }

    let chars: Vec<char> = name.chars().collect();

    // Must start with a letter
    if !chars[0].is_ascii_lowercase() {
        return false;
    }

    // Must end with a letter or digit
    if !chars[chars.len() - 1].is_ascii_alphanumeric() {
        return false;
    }

    // All characters must be lowercase alphanumeric or hyphen
    chars
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
}

/// Check if a command name is valid
fn is_valid_command_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    let chars: Vec<char> = name.chars().collect();

    // Must start with a letter
    if !chars[0].is_ascii_lowercase() {
        return false;
    }

    // All characters must be lowercase alphanumeric or hyphen
    chars
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_manifest() {
        let toml = r#"
[plugin]
name = "test-plugin"
version = "1.0.0"
description = "A test plugin"
author = "Test Author"
min_cli_version = "0.1.0"

[[commands]]
name = "test"
description = "Run test"
binary = "test-binary"
"#;

        let manifest = PluginManifest::parse(toml).unwrap();
        assert_eq!(manifest.plugin.name, "test-plugin");
        assert_eq!(manifest.plugin.version, "1.0.0");
        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.commands[0].name, "test");
    }

    #[test]
    fn test_validate_valid_manifest() {
        let toml = r#"
[plugin]
name = "valid-plugin"
version = "1.0.0"
description = "Valid plugin"

[[commands]]
name = "cmd"
description = "A command"
binary = "binary"
"#;

        let manifest = PluginManifest::parse(toml).unwrap();
        assert!(manifest.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_name() {
        let toml = r#"
[plugin]
name = "InvalidName"
version = "1.0.0"
description = "Invalid"

[[commands]]
name = "cmd"
description = "A command"
binary = "binary"
"#;

        let manifest = PluginManifest::parse(toml).unwrap();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_validate_no_commands() {
        let toml = r#"
[plugin]
name = "no-commands"
version = "1.0.0"
description = "No commands"
"#;

        let manifest = PluginManifest::parse(toml).unwrap();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn test_is_compatible_with() {
        let toml = r#"
[plugin]
name = "versioned"
version = "1.0.0"
description = "Versioned"
min_cli_version = "0.2.0"

[[commands]]
name = "cmd"
description = "A command"
binary = "binary"
"#;

        let manifest = PluginManifest::parse(toml).unwrap();
        assert!(manifest.is_compatible_with("0.2.0").unwrap());
        assert!(manifest.is_compatible_with("0.3.0").unwrap());
        assert!(manifest.is_compatible_with("1.0.0").unwrap());
        assert!(!manifest.is_compatible_with("0.1.0").unwrap());
    }

    #[test]
    fn test_valid_plugin_names() {
        assert!(is_valid_plugin_name("ab"));
        assert!(is_valid_plugin_name("test-plugin"));
        assert!(is_valid_plugin_name("plugin123"));
        assert!(is_valid_plugin_name("my-plugin-2"));

        assert!(!is_valid_plugin_name("a")); // Too short
        assert!(!is_valid_plugin_name("Invalid")); // Uppercase
        assert!(!is_valid_plugin_name("test_plugin")); // Underscore
        assert!(!is_valid_plugin_name("-plugin")); // Starts with hyphen
        assert!(!is_valid_plugin_name("plugin-")); // Ends with hyphen
    }
}
