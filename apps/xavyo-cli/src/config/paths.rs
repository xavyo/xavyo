//! Platform-specific configuration paths

use crate::error::{CliError, CliResult};
use std::path::PathBuf;

/// Configuration paths for the xavyo CLI
#[derive(Debug, Clone)]
pub struct ConfigPaths {
    /// Base configuration directory
    pub config_dir: PathBuf,
    /// Path to config.json
    pub config_file: PathBuf,
    /// Path to session.json
    pub session_file: PathBuf,
    /// Path to credentials.enc (fallback encrypted file)
    pub credentials_file: PathBuf,
    /// Path to cache directory
    pub cache_dir: PathBuf,
    /// Path to shell history file
    pub history_file: PathBuf,
    /// Path to version history directory
    pub version_history_dir: PathBuf,
}

impl ConfigPaths {
    /// Get configuration paths for the current platform
    ///
    /// Paths:
    /// - Linux: ~/.config/xavyo/
    /// - macOS: ~/Library/Application Support/xavyo/
    /// - Windows: %APPDATA%\xavyo\
    pub fn new() -> CliResult<Self> {
        let config_dir = Self::get_config_dir()?;
        let cache_dir = config_dir.join("cache");
        let history_file = config_dir.join("shell_history");
        let version_history_dir = config_dir.join("history");

        Ok(Self {
            config_file: config_dir.join("config.json"),
            session_file: config_dir.join("session.json"),
            credentials_file: config_dir.join("credentials.enc"),
            cache_dir,
            history_file,
            version_history_dir,
            config_dir,
        })
    }

    /// Get the configuration directory, respecting `XAVYO_CONFIG_DIR` env var
    fn get_config_dir() -> CliResult<PathBuf> {
        // Check for override environment variable
        if let Ok(dir) = std::env::var("XAVYO_CONFIG_DIR") {
            return Ok(PathBuf::from(dir));
        }

        // Use platform-specific config directory
        let base_dir = dirs::config_dir().ok_or_else(|| {
            CliError::Config("Could not determine configuration directory".to_string())
        })?;

        Ok(base_dir.join("xavyo"))
    }

    /// Ensure the configuration directory exists
    pub fn ensure_dir_exists(&self) -> CliResult<()> {
        if !self.config_dir.exists() {
            std::fs::create_dir_all(&self.config_dir)?;
        }
        Ok(())
    }

    /// Ensure the cache directory exists
    pub fn ensure_cache_dir_exists(&self) -> CliResult<()> {
        if !self.cache_dir.exists() {
            std::fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_paths_new() {
        // This test may fail on systems without a config directory
        if dirs::config_dir().is_some() {
            let paths = ConfigPaths::new().unwrap();
            assert!(paths.config_file.ends_with("config.json"));
            assert!(paths.session_file.ends_with("session.json"));
            assert!(paths.credentials_file.ends_with("credentials.enc"));
        }
    }

    #[test]
    fn test_config_dir_override() {
        std::env::set_var("XAVYO_CONFIG_DIR", "/tmp/xavyo-test");
        let paths = ConfigPaths::new().unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/tmp/xavyo-test"));
        std::env::remove_var("XAVYO_CONFIG_DIR");
    }
}
