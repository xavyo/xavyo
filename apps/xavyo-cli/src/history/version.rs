//! Version types for configuration history
//!
//! Defines the data structures for storing configuration snapshots,
//! including version metadata and the full configuration state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::config::XavyoConfig;

/// Summary metadata for quick display without loading full config
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionSummary {
    /// Number of agents in this version
    pub agent_count: usize,
    /// Number of tools in this version
    pub tool_count: usize,
    /// Optional description (e.g., source file name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

impl VersionSummary {
    /// Create a new version summary from a configuration
    pub fn from_config(config: &XavyoConfig, source: Option<String>) -> Self {
        Self {
            agent_count: config.agents.len(),
            tool_count: config.tools.len(),
            source,
        }
    }
}

/// A saved configuration version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigVersion {
    /// Sequential version number (1, 2, 3, ...)
    pub version: u32,
    /// When this version was saved (UTC)
    pub timestamp: DateTime<Utc>,
    /// The full configuration at this point in time
    pub config: XavyoConfig,
    /// Summary metadata for display
    pub summary: VersionSummary,
}

impl ConfigVersion {
    /// Create a new configuration version
    pub fn new(version: u32, config: XavyoConfig, source: Option<String>) -> Self {
        let summary = VersionSummary::from_config(&config, source);
        Self {
            version,
            timestamp: Utc::now(),
            config,
            summary,
        }
    }
}

/// Index of all saved versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionIndex {
    /// Next version number to assign
    pub next_version: u32,
    /// List of available versions (version numbers)
    pub versions: Vec<u32>,
    /// Maximum versions to retain
    pub max_versions: usize,
}

impl Default for VersionIndex {
    fn default() -> Self {
        Self {
            next_version: 1,
            versions: Vec::new(),
            max_versions: 10,
        }
    }
}

impl VersionIndex {
    /// Create a new version index with custom max versions
    #[allow(dead_code)]
    pub fn with_max_versions(max_versions: usize) -> Self {
        Self {
            max_versions,
            ..Default::default()
        }
    }

    /// Get the latest version number, if any
    pub fn latest_version(&self) -> Option<u32> {
        self.versions.last().copied()
    }

    /// Check if a version exists
    pub fn has_version(&self, version: u32) -> bool {
        self.versions.contains(&version)
    }

    /// Add a new version and return its number
    pub fn add_version(&mut self) -> u32 {
        let version = self.next_version;
        self.versions.push(version);
        self.next_version += 1;
        version
    }

    /// Remove a version from the index
    pub fn remove_version(&mut self, version: u32) {
        self.versions.retain(|&v| v != version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::config::XavyoConfig;

    #[test]
    fn test_version_summary_from_config() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        };
        let summary = VersionSummary::from_config(&config, Some("test.yaml".to_string()));
        assert_eq!(summary.agent_count, 0);
        assert_eq!(summary.tool_count, 0);
        assert_eq!(summary.source, Some("test.yaml".to_string()));
    }

    #[test]
    fn test_version_index_default() {
        let index = VersionIndex::default();
        assert_eq!(index.next_version, 1);
        assert!(index.versions.is_empty());
        assert_eq!(index.max_versions, 10);
    }

    #[test]
    fn test_version_index_add_version() {
        let mut index = VersionIndex::default();
        assert_eq!(index.add_version(), 1);
        assert_eq!(index.add_version(), 2);
        assert_eq!(index.add_version(), 3);
        assert_eq!(index.versions, vec![1, 2, 3]);
        assert_eq!(index.next_version, 4);
    }

    #[test]
    fn test_version_index_latest_version() {
        let mut index = VersionIndex::default();
        assert_eq!(index.latest_version(), None);
        index.add_version();
        assert_eq!(index.latest_version(), Some(1));
        index.add_version();
        assert_eq!(index.latest_version(), Some(2));
    }

    #[test]
    fn test_version_index_has_version() {
        let mut index = VersionIndex::default();
        index.add_version();
        index.add_version();
        assert!(index.has_version(1));
        assert!(index.has_version(2));
        assert!(!index.has_version(3));
    }

    #[test]
    fn test_version_index_remove_version() {
        let mut index = VersionIndex::default();
        index.add_version();
        index.add_version();
        index.add_version();
        index.remove_version(2);
        assert_eq!(index.versions, vec![1, 3]);
    }

    #[test]
    fn test_config_version_new() {
        let config = XavyoConfig {
            version: "1".to_string(),
            agents: vec![],
            tools: vec![],
        };
        let version = ConfigVersion::new(1, config.clone(), Some("test.yaml".to_string()));
        assert_eq!(version.version, 1);
        assert_eq!(version.summary.agent_count, 0);
        assert_eq!(version.summary.tool_count, 0);
        assert_eq!(version.summary.source, Some("test.yaml".to_string()));
    }
}
