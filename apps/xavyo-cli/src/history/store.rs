//! Version history storage operations
//!
//! Provides the `VersionHistory` service for managing configuration version
//! storage on disk, including loading, saving, and retrieving versions.

use std::path::{Path, PathBuf};

use crate::error::{CliError, CliResult};
use crate::models::config::XavyoConfig;

use super::retention::enforce_retention;
use super::version::{ConfigVersion, VersionIndex};

/// Service for managing configuration version history
pub struct VersionHistory {
    /// Path to history directory
    history_dir: PathBuf,
    /// Current index (loaded from disk)
    index: VersionIndex,
}

impl VersionHistory {
    /// Load or create history from disk
    pub fn load(history_dir: &Path) -> CliResult<Self> {
        let index_path = history_dir.join("index.json");

        let index = if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)
                .map_err(|e| CliError::Config(format!("Failed to read history index: {}", e)))?;

            serde_json::from_str(&content).map_err(|e| {
                CliError::Config(format!(
                    "History index corrupted. Delete {} to reset. Error: {}",
                    history_dir.display(),
                    e
                ))
            })?
        } else {
            VersionIndex::default()
        };

        Ok(Self {
            history_dir: history_dir.to_path_buf(),
            index,
        })
    }

    /// Save the current index to disk
    pub fn save_index(&self) -> CliResult<()> {
        let index_path = self.history_dir.join("index.json");
        let content = serde_json::to_string_pretty(&self.index)
            .map_err(|e| CliError::Config(format!("Failed to serialize index: {}", e)))?;

        std::fs::write(&index_path, content)
            .map_err(|e| CliError::Config(format!("Failed to write index: {}", e)))?;

        Ok(())
    }

    /// Save a new version, returns assigned version number
    pub fn save_version(&mut self, config: &XavyoConfig, source: Option<&str>) -> CliResult<u32> {
        // Assign new version number
        let version_num = self.index.add_version();

        // Create version object
        let version = ConfigVersion::new(version_num, config.clone(), source.map(String::from));

        // Save version file
        self.save_version_file(&version)?;

        // Save updated index
        self.save_index()?;

        // Enforce retention policy
        enforce_retention(self)?;

        Ok(version_num)
    }

    /// Save a ConfigVersion to its file
    fn save_version_file(&self, version: &ConfigVersion) -> CliResult<()> {
        let path = self.version_file_path(version.version);
        let content = serde_json::to_string_pretty(version)
            .map_err(|e| CliError::Config(format!("Failed to serialize version: {}", e)))?;

        std::fs::write(&path, content)
            .map_err(|e| CliError::Config(format!("Failed to write version file: {}", e)))?;

        Ok(())
    }

    /// Get a specific version by number
    pub fn get_version(&self, version: u32) -> CliResult<ConfigVersion> {
        if !self.index.has_version(version) {
            return Err(CliError::VersionNotFound {
                version,
                available: self.index.versions.clone(),
            });
        }

        let path = self.version_file_path(version);
        let content = std::fs::read_to_string(&path)
            .map_err(|e| CliError::Config(format!("Failed to read version {}: {}", version, e)))?;

        serde_json::from_str(&content)
            .map_err(|e| CliError::Config(format!("Failed to parse version {}: {}", version, e)))
    }

    /// Get the latest version (highest number)
    pub fn get_latest(&self) -> CliResult<Option<ConfigVersion>> {
        match self.index.latest_version() {
            Some(version) => Ok(Some(self.get_version(version)?)),
            None => Ok(None),
        }
    }

    /// List all versions with metadata
    pub fn list_versions(&self) -> CliResult<Vec<ConfigVersion>> {
        let mut versions = Vec::new();
        for &version_num in &self.index.versions {
            versions.push(self.get_version(version_num)?);
        }
        // Return newest first
        versions.reverse();
        Ok(versions)
    }

    /// Get the version file path for a given version number
    pub fn version_file_path(&self, version: u32) -> PathBuf {
        self.history_dir.join(format!("v{:03}.json", version))
    }

    /// Get a mutable reference to the index
    pub fn index_mut(&mut self) -> &mut VersionIndex {
        &mut self.index
    }

    /// Get a reference to the index
    pub fn index(&self) -> &VersionIndex {
        &self.index
    }

    /// Get the history directory path
    #[allow(dead_code)]
    pub fn history_dir(&self) -> &Path {
        &self.history_dir
    }

    /// Check if any versions exist
    pub fn has_versions(&self) -> bool {
        !self.index.versions.is_empty()
    }

    /// Get available version numbers
    #[allow(dead_code)]
    pub fn available_versions(&self) -> &[u32] {
        &self.index.versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_config() -> XavyoConfig {
        XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        }
    }

    #[test]
    fn test_version_history_load_new() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let history = VersionHistory::load(temp_dir.path()).unwrap();
        assert!(!history.has_versions());
        assert_eq!(history.index().next_version, 1);
    }

    #[test]
    fn test_version_history_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let config = create_test_config();

        // Save a version
        {
            let mut history = VersionHistory::load(temp_dir.path()).unwrap();
            let version_num = history.save_version(&config, Some("test.yaml")).unwrap();
            assert_eq!(version_num, 1);
        }

        // Load and verify
        {
            let history = VersionHistory::load(temp_dir.path()).unwrap();
            assert!(history.has_versions());
            assert_eq!(history.index().next_version, 2);

            let version = history.get_version(1).unwrap();
            assert_eq!(version.version, 1);
            assert_eq!(version.summary.source, Some("test.yaml".to_string()));
        }
    }

    #[test]
    fn test_version_history_multiple_versions() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let config = create_test_config();

        let mut history = VersionHistory::load(temp_dir.path()).unwrap();

        // Save multiple versions
        assert_eq!(history.save_version(&config, Some("v1.yaml")).unwrap(), 1);
        assert_eq!(history.save_version(&config, Some("v2.yaml")).unwrap(), 2);
        assert_eq!(history.save_version(&config, Some("v3.yaml")).unwrap(), 3);

        // List versions (should be newest first)
        let versions = history.list_versions().unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3);
        assert_eq!(versions[1].version, 2);
        assert_eq!(versions[2].version, 1);

        // Get latest
        let latest = history.get_latest().unwrap().unwrap();
        assert_eq!(latest.version, 3);
    }

    #[test]
    fn test_version_history_version_not_found() {
        let temp_dir = TempDir::new().unwrap();
        std::fs::create_dir_all(temp_dir.path()).unwrap();

        let history = VersionHistory::load(temp_dir.path()).unwrap();
        let result = history.get_version(99);
        assert!(result.is_err());
    }

    #[test]
    fn test_version_file_path() {
        let temp_dir = TempDir::new().unwrap();
        let history = VersionHistory::load(temp_dir.path()).unwrap();

        assert!(history.version_file_path(1).ends_with("v001.json"));
        assert!(history.version_file_path(10).ends_with("v010.json"));
        assert!(history.version_file_path(100).ends_with("v100.json"));
    }
}
