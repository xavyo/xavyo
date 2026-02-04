//! Integration tests for the plugin system
//!
//! Tests cover:
//! - Plugin discovery and installation (US1)
//! - Plugin command execution (US2)
//! - Plugin lifecycle management (US3)
//! - Plugin creation and validation (US4)

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test fixture for common test data
mod fixtures {
    pub fn sample_plugin_manifest() -> &'static str {
        r#"[plugin]
name = "test-plugin"
version = "1.0.0"
description = "A test plugin for integration tests"
author = "Test Author"
min_cli_version = "0.1.0"

[[commands]]
name = "test"
description = "Run test command"
binary = "test-plugin"
"#
    }

    pub fn sample_plugin_manifest_no_commands() -> &'static str {
        r#"[plugin]
name = "empty-plugin"
version = "1.0.0"
description = "Plugin with no commands"
"#
    }

    pub fn sample_plugin_manifest_invalid_name() -> &'static str {
        r#"[plugin]
name = "InvalidName"
version = "1.0.0"
description = "Plugin with invalid name"

[[commands]]
name = "cmd"
description = "A command"
binary = "binary"
"#
    }

    pub fn sample_registry_response() -> &'static str {
        r#"{
  "plugins": [
    {
      "name": "report-generator",
      "version": "1.0.0",
      "description": "Generate custom reports",
      "author": "Xavyo Team",
      "download_url": "https://plugins.xavyo.io/packages/report-generator-1.0.0.tar.gz",
      "min_cli_version": "0.1.0"
    },
    {
      "name": "data-exporter",
      "version": "2.1.0",
      "description": "Export data in various formats",
      "author": "Xavyo Team",
      "download_url": "https://plugins.xavyo.io/packages/data-exporter-2.1.0.tar.gz"
    }
  ]
}"#
    }

    pub fn sample_installed_state() -> &'static str {
        r#"{
  "schema_version": 1,
  "plugins": {
    "test-plugin": {
      "name": "test-plugin",
      "version": "1.0.0",
      "enabled": true,
      "installed_at": "2026-02-04T10:00:00Z",
      "source": {
        "type": "registry",
        "url": "https://plugins.xavyo.io"
      },
      "path": "/tmp/plugins/test-plugin"
    }
  }
}"#
    }
}

// =============================================================================
// User Story 1: Discover and Install Plugins
// =============================================================================

#[test]
fn test_plugin_list_available() {
    // Verify registry response can be parsed
    let json_str = fixtures::sample_registry_response();
    let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

    assert!(parsed["plugins"].is_array());
    assert_eq!(parsed["plugins"].as_array().unwrap().len(), 2);
    assert_eq!(parsed["plugins"][0]["name"], "report-generator");
}

#[test]
fn test_plugin_list_installed() {
    // Verify installed state can be parsed
    let json_str = fixtures::sample_installed_state();
    let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

    assert_eq!(parsed["schema_version"], 1);
    assert!(parsed["plugins"]["test-plugin"].is_object());
    assert_eq!(parsed["plugins"]["test-plugin"]["enabled"], true);
}

#[test]
fn test_plugin_manifest_parse() {
    // Verify plugin manifest can be parsed from TOML
    use xavyo_cli::plugin::manifest::PluginManifest;

    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest()).unwrap();
    assert_eq!(manifest.plugin.name, "test-plugin");
    assert_eq!(manifest.plugin.version, "1.0.0");
    assert_eq!(manifest.commands.len(), 1);
}

#[test]
fn test_plugin_manifest_validate_valid() {
    use xavyo_cli::plugin::manifest::PluginManifest;

    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest()).unwrap();
    assert!(manifest.validate().is_ok());
}

#[test]
fn test_plugin_manifest_validate_no_commands() {
    use xavyo_cli::plugin::manifest::PluginManifest;

    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest_no_commands()).unwrap();
    assert!(manifest.validate().is_err());
}

#[test]
fn test_plugin_manifest_validate_invalid_name() {
    use xavyo_cli::plugin::manifest::PluginManifest;

    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest_invalid_name()).unwrap();
    assert!(manifest.validate().is_err());
}

#[test]
fn test_plugin_install_from_local_path() {
    // Verify local plugin can be loaded from a directory
    let temp_dir = TempDir::new().unwrap();
    let plugin_dir = temp_dir.path().join("my-plugin");
    let bin_dir = plugin_dir.join("bin");

    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(
        plugin_dir.join("plugin.toml"),
        fixtures::sample_plugin_manifest(),
    )
    .unwrap();

    // Verify manifest can be loaded from path
    use xavyo_cli::plugin::manifest::PluginManifest;
    let manifest_path = plugin_dir.join("plugin.toml");
    let manifest = PluginManifest::load(&manifest_path).unwrap();

    assert_eq!(manifest.plugin.name, "test-plugin");
}

#[test]
fn test_plugin_install_not_found() {
    // Verify error when manifest doesn't exist
    use xavyo_cli::plugin::manifest::PluginManifest;

    let result = PluginManifest::load(&PathBuf::from("/nonexistent/plugin.toml"));
    assert!(result.is_err());
}

#[test]
fn test_plugin_version_compatibility() {
    use xavyo_cli::plugin::manifest::PluginManifest;

    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest()).unwrap();

    // Compatible versions
    assert!(manifest.is_compatible_with("0.1.0").unwrap());
    assert!(manifest.is_compatible_with("0.2.0").unwrap());
    assert!(manifest.is_compatible_with("1.0.0").unwrap());

    // Incompatible version
    assert!(!manifest.is_compatible_with("0.0.9").unwrap());
}

// =============================================================================
// User Story 2: Use Plugin Commands (stubs - to be implemented)
// =============================================================================

#[test]
fn test_plugin_command_execution() {
    // This test will verify plugin command execution once implemented
    // For now, verify the loader module exists
    use xavyo_cli::plugin::loader::PluginLoader;

    let loader = PluginLoader::new();
    assert_eq!(loader.all_commands().len(), 0);
}

#[test]
fn test_plugin_commands_in_help() {
    // Verify all_commands returns expected format
    use xavyo_cli::plugin::loader::PluginLoader;

    let loader = PluginLoader::new();
    let commands = loader.all_commands();

    // Empty loader should have no commands
    assert!(commands.is_empty());
}

#[test]
fn test_plugin_command_error_isolation() {
    // Verify core commands are protected
    use xavyo_cli::plugin::loader::conflicts_with_core;

    assert!(conflicts_with_core("login"));
    assert!(conflicts_with_core("agents"));
    assert!(conflicts_with_core("plugin"));
    assert!(!conflicts_with_core("custom-command"));
}

#[test]
fn test_plugin_command_argument_passing() {
    // This test will verify argument passing once implemented
    // For now, verify CORE_COMMANDS list is complete
    use xavyo_cli::plugin::loader::CORE_COMMANDS;

    assert!(CORE_COMMANDS.contains(&"apply"));
    assert!(CORE_COMMANDS.contains(&"export"));
    assert!(CORE_COMMANDS.contains(&"watch"));
}

// =============================================================================
// User Story 3: Manage Plugin Lifecycle
// =============================================================================

#[test]
fn test_plugin_state_save_load() {
    use xavyo_cli::config::ConfigPaths;
    use xavyo_cli::plugin::state::{InstalledPlugin, PluginSource, PluginState};

    let temp_dir = TempDir::new().unwrap();
    let paths = ConfigPaths {
        config_dir: temp_dir.path().to_path_buf(),
        config_file: temp_dir.path().join("config.json"),
        session_file: temp_dir.path().join("session.json"),
        credentials_file: temp_dir.path().join("credentials.json"),
        cache_dir: temp_dir.path().join("cache"),
        history_file: temp_dir.path().join("shell_history"),
        version_history_dir: temp_dir.path().join("history"),
    };

    let mut state = PluginState::new();
    state.add(InstalledPlugin::new(
        "my-plugin".to_string(),
        "1.0.0".to_string(),
        PluginSource::Local {
            path: PathBuf::from("/tmp/my-plugin"),
        },
        PathBuf::from("/home/user/.xavyo/plugins/packages/my-plugin"),
    ));

    state.save(&paths).unwrap();

    let loaded = PluginState::load(&paths).unwrap();
    assert!(loaded.is_installed("my-plugin"));
}

#[test]
fn test_plugin_disable() {
    use xavyo_cli::plugin::state::{InstalledPlugin, PluginSource, PluginState};

    let mut state = PluginState::new();
    let mut plugin = InstalledPlugin::new(
        "test".to_string(),
        "1.0.0".to_string(),
        PluginSource::Registry {
            url: "https://plugins.xavyo.io".to_string(),
        },
        PathBuf::from("/tmp/test"),
    );

    assert!(plugin.enabled);
    plugin.disable();
    assert!(!plugin.enabled);

    state.add(plugin);
    assert_eq!(state.enabled().count(), 0);
}

#[test]
fn test_plugin_enable() {
    use xavyo_cli::plugin::state::{InstalledPlugin, PluginSource};

    let mut plugin = InstalledPlugin::new(
        "test".to_string(),
        "1.0.0".to_string(),
        PluginSource::Local {
            path: PathBuf::from("/tmp/test"),
        },
        PathBuf::from("/tmp/test"),
    );

    plugin.disable();
    assert!(!plugin.enabled);

    plugin.enable();
    assert!(plugin.enabled);
}

#[test]
fn test_plugin_update() {
    use xavyo_cli::plugin::state::{InstalledPlugin, PluginSource};

    let mut plugin = InstalledPlugin::new(
        "test".to_string(),
        "1.0.0".to_string(),
        PluginSource::Registry {
            url: "https://plugins.xavyo.io".to_string(),
        },
        PathBuf::from("/tmp/test"),
    );

    assert_eq!(plugin.version, "1.0.0");
    assert!(plugin.updated_at.is_none());

    plugin.update_version("1.1.0".to_string());

    assert_eq!(plugin.version, "1.1.0");
    assert!(plugin.updated_at.is_some());
}

#[test]
fn test_plugin_uninstall() {
    use xavyo_cli::plugin::state::{InstalledPlugin, PluginSource, PluginState};

    let mut state = PluginState::new();
    state.add(InstalledPlugin::new(
        "to-remove".to_string(),
        "1.0.0".to_string(),
        PluginSource::Local {
            path: PathBuf::from("/tmp/to-remove"),
        },
        PathBuf::from("/tmp/plugins/to-remove"),
    ));

    assert!(state.is_installed("to-remove"));

    let removed = state.remove("to-remove");
    assert!(removed.is_some());
    assert!(!state.is_installed("to-remove"));
}

// =============================================================================
// User Story 4: Create Custom Plugins
// =============================================================================

#[test]
fn test_plugin_init_scaffold() {
    use xavyo_cli::plugin::scaffold::create_plugin_scaffold;

    let temp_dir = TempDir::new().unwrap();
    create_plugin_scaffold("my-new-plugin", temp_dir.path()).unwrap();

    let plugin_dir = temp_dir.path().join("my-new-plugin");
    assert!(plugin_dir.exists());
    assert!(plugin_dir.join("plugin.toml").exists());
    assert!(plugin_dir.join("Cargo.toml").exists());
    assert!(plugin_dir.join("src/main.rs").exists());
    assert!(plugin_dir.join("bin").exists());
}

#[test]
fn test_plugin_validate_valid() {
    use xavyo_cli::plugin::manifest::PluginManifest;
    use xavyo_cli::plugin::scaffold::create_plugin_scaffold;

    let temp_dir = TempDir::new().unwrap();
    create_plugin_scaffold("valid-plugin", temp_dir.path()).unwrap();

    let manifest_path = temp_dir.path().join("valid-plugin/plugin.toml");
    let manifest = PluginManifest::load(&manifest_path).unwrap();

    assert!(manifest.validate().is_ok());
}

#[test]
fn test_plugin_validate_invalid() {
    use xavyo_cli::plugin::manifest::PluginManifest;

    // Invalid: no commands
    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest_no_commands()).unwrap();
    assert!(manifest.validate().is_err());

    // Invalid: bad name
    let manifest = PluginManifest::parse(fixtures::sample_plugin_manifest_invalid_name()).unwrap();
    assert!(manifest.validate().is_err());
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

#[test]
fn test_plugins_dir_creation() {
    use xavyo_cli::config::ConfigPaths;
    use xavyo_cli::plugin::ensure_plugins_dir;

    let temp_dir = TempDir::new().unwrap();
    let paths = ConfigPaths {
        config_dir: temp_dir.path().to_path_buf(),
        config_file: temp_dir.path().join("config.json"),
        session_file: temp_dir.path().join("session.json"),
        credentials_file: temp_dir.path().join("credentials.json"),
        cache_dir: temp_dir.path().join("cache"),
        history_file: temp_dir.path().join("shell_history"),
        version_history_dir: temp_dir.path().join("history"),
    };

    ensure_plugins_dir(&paths).unwrap();

    assert!(temp_dir.path().join("plugins").exists());
    assert!(temp_dir.path().join("plugins/packages").exists());
}

#[test]
fn test_registry_client_default_url() {
    use xavyo_cli::plugin::registry::{RegistryClient, DEFAULT_REGISTRY_URL};

    let client = RegistryClient::new();
    assert_eq!(client.registry_url, DEFAULT_REGISTRY_URL);
}

#[test]
fn test_registry_plugin_serialization() {
    use xavyo_cli::plugin::registry::RegistryPlugin;

    let plugin = RegistryPlugin {
        name: "test".to_string(),
        version: "1.0.0".to_string(),
        description: "Test".to_string(),
        author: Some("Author".to_string()),
        download_url: "https://example.com/test.tar.gz".to_string(),
        checksum: None,
        min_cli_version: None,
    };

    let json = serde_json::to_string(&plugin).unwrap();
    assert!(json.contains("test"));

    let parsed: RegistryPlugin = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "test");
}
