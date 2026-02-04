//! Upgrade operation models

use semver::Version;
use serde::Serialize;

use super::release::Release;

/// Result of version check operation
#[derive(Debug, Clone)]
pub struct UpgradeInfo {
    /// Currently installed version
    pub current_version: Version,

    /// Latest available version
    pub latest_version: Version,

    /// Whether upgrade is available
    pub update_available: bool,

    /// Full release info if update available
    pub release: Option<Release>,

    /// Direct URL for platform-specific binary
    pub download_url: Option<String>,
}

impl UpgradeInfo {
    /// Create upgrade info for when already on latest
    pub fn up_to_date(current: Version) -> Self {
        UpgradeInfo {
            current_version: current.clone(),
            latest_version: current,
            update_available: false,
            release: None,
            download_url: None,
        }
    }

    /// Create upgrade info for when update is available
    pub fn available(current: Version, release: Release, download_url: String) -> Self {
        UpgradeInfo {
            current_version: current,
            latest_version: release.version.clone(),
            update_available: true,
            release: Some(release),
            download_url: Some(download_url),
        }
    }
}

/// JSON output format for upgrade check
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeCheckJson {
    /// Currently installed version
    pub current_version: String,

    /// Latest available version
    pub latest_version: String,

    /// Whether upgrade is available
    pub update_available: bool,

    /// Release notes (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
}

impl From<&UpgradeInfo> for UpgradeCheckJson {
    fn from(info: &UpgradeInfo) -> Self {
        UpgradeCheckJson {
            current_version: info.current_version.to_string(),
            latest_version: info.latest_version.to_string(),
            update_available: info.update_available,
            release_notes: info.release.as_ref().and_then(|r| r.body.clone()),
        }
    }
}

/// JSON output format for upgrade result
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeResultJson {
    /// Whether upgrade completed successfully
    pub success: bool,

    /// Version before upgrade
    pub previous_version: String,

    /// Version after upgrade
    pub new_version: String,

    /// Human-readable result message
    pub message: String,
}

impl UpgradeResultJson {
    /// Create a success result
    pub fn success(previous: &str, new: &str) -> Self {
        UpgradeResultJson {
            success: true,
            previous_version: previous.to_string(),
            new_version: new.to_string(),
            message: format!("Successfully upgraded from {previous} to {new}"),
        }
    }

    /// Create a failure result
    pub fn failure(previous: &str, message: &str) -> Self {
        UpgradeResultJson {
            success: false,
            previous_version: previous.to_string(),
            new_version: previous.to_string(),
            message: message.to_string(),
        }
    }

    /// Create an already-up-to-date result
    pub fn up_to_date(version: &str) -> Self {
        UpgradeResultJson {
            success: true,
            previous_version: version.to_string(),
            new_version: version.to_string(),
            message: format!("Already on latest version ({version})"),
        }
    }
}
