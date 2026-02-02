//! Release models for the upgrade command

use chrono::{DateTime, Utc};
use semver::Version;
use serde::Deserialize;

/// Represents a GitHub release
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRelease {
    /// Git tag name (e.g., "v0.2.0")
    pub tag_name: String,

    /// Release title
    pub name: String,

    /// Release notes in markdown
    pub body: Option<String>,

    /// Publication timestamp
    pub published_at: DateTime<Utc>,

    /// Downloadable assets
    pub assets: Vec<GitHubAsset>,
}

/// Represents a downloadable release asset
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubAsset {
    /// Asset filename (e.g., "xavyo-0.2.0-linux-x86_64")
    pub name: String,

    /// Direct download URL
    pub browser_download_url: String,

    /// File size in bytes
    pub size: u64,

    /// MIME type
    #[serde(default)]
    pub content_type: String,
}

/// Parsed release information for internal use
#[derive(Debug, Clone)]
pub struct Release {
    /// Parsed semantic version
    pub version: Version,

    /// Git tag (e.g., "v0.2.0")
    #[allow(dead_code)]
    pub tag_name: String,

    /// Release title
    #[allow(dead_code)]
    pub name: String,

    /// Release notes (markdown)
    pub body: Option<String>,

    /// Publication timestamp
    #[allow(dead_code)]
    pub published_at: DateTime<Utc>,

    /// Downloadable assets
    pub assets: Vec<Asset>,
}

/// Parsed asset information
#[derive(Debug, Clone)]
pub struct Asset {
    /// Asset filename
    pub name: String,

    /// Direct download URL
    pub download_url: String,

    /// File size in bytes
    pub size: u64,

    /// MIME type
    #[allow(dead_code)]
    pub content_type: String,
}

impl TryFrom<GitHubRelease> for Release {
    type Error = semver::Error;

    fn try_from(gh: GitHubRelease) -> Result<Self, Self::Error> {
        // Parse version from tag, stripping leading 'v' if present
        let version_str = gh.tag_name.strip_prefix('v').unwrap_or(&gh.tag_name);
        let version = Version::parse(version_str)?;

        Ok(Release {
            version,
            tag_name: gh.tag_name,
            name: gh.name,
            body: gh.body,
            published_at: gh.published_at,
            assets: gh.assets.into_iter().map(Asset::from).collect(),
        })
    }
}

impl From<GitHubAsset> for Asset {
    fn from(gh: GitHubAsset) -> Self {
        Asset {
            name: gh.name,
            download_url: gh.browser_download_url,
            size: gh.size,
            content_type: gh.content_type,
        }
    }
}

impl Release {
    /// Find an asset by name
    pub fn find_asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }

    /// Find the checksums file asset
    pub fn find_checksums(&self) -> Option<&Asset> {
        self.assets
            .iter()
            .find(|a| a.name == "checksums.sha256" || a.name.ends_with(".sha256"))
    }
}
