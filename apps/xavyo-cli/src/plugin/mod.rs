//! Plugin system for xavyo-cli
//!
//! This module provides functionality for discovering, installing, managing,
//! and executing plugins that extend the CLI's capabilities.

pub mod loader;
pub mod manifest;
pub mod registry;
pub mod scaffold;
pub mod state;

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use std::path::PathBuf;

/// Get the plugins directory path (~/.xavyo/plugins/)
pub fn plugins_dir(paths: &ConfigPaths) -> PathBuf {
    paths.config_dir.join("plugins")
}

/// Get the packages directory path (~/.xavyo/plugins/packages/)
pub fn packages_dir(paths: &ConfigPaths) -> PathBuf {
    plugins_dir(paths).join("packages")
}

/// Get the installed plugins state file path
pub fn installed_state_path(paths: &ConfigPaths) -> PathBuf {
    plugins_dir(paths).join("installed.json")
}

/// Get the registry cache file path
#[allow(dead_code)]
pub fn registry_cache_path(paths: &ConfigPaths) -> PathBuf {
    plugins_dir(paths).join("registry-cache.json")
}

/// Ensure the plugins directory structure exists
pub fn ensure_plugins_dir(paths: &ConfigPaths) -> CliResult<()> {
    let plugins = plugins_dir(paths);
    let packages = packages_dir(paths);

    std::fs::create_dir_all(&plugins).map_err(|e| {
        CliError::Io(format!(
            "Failed to create plugins directory {}: {}",
            plugins.display(),
            e
        ))
    })?;

    std::fs::create_dir_all(&packages).map_err(|e| {
        CliError::Io(format!(
            "Failed to create packages directory {}: {}",
            packages.display(),
            e
        ))
    })?;

    Ok(())
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
    fn test_plugins_dir() {
        let (_temp, paths) = test_paths();
        let dir = plugins_dir(&paths);
        assert!(dir.ends_with("plugins"));
    }

    #[test]
    fn test_packages_dir() {
        let (_temp, paths) = test_paths();
        let dir = packages_dir(&paths);
        assert!(dir.ends_with("packages"));
    }

    #[test]
    fn test_ensure_plugins_dir() {
        let (_temp, paths) = test_paths();
        ensure_plugins_dir(&paths).unwrap();
        assert!(plugins_dir(&paths).exists());
        assert!(packages_dir(&paths).exists());
    }
}
