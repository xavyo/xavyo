//! Plugin registry client
//!
//! Handles communication with the plugin registry to discover, download,
//! and update plugins.

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use crate::plugin::registry_cache_path;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default plugin registry URL
pub const DEFAULT_REGISTRY_URL: &str = "https://plugins.xavyo.io";

/// Plugin metadata from the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPlugin {
    /// Plugin name
    pub name: String,
    /// Latest available version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    #[serde(default)]
    pub author: Option<String>,
    /// URL to download plugin package
    pub download_url: String,
    /// SHA256 checksum of package
    #[serde(default)]
    pub checksum: Option<String>,
    /// Minimum CLI version required
    #[serde(default)]
    pub min_cli_version: Option<String>,
}

/// Cached registry data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct RegistryCache {
    /// When the cache was last fetched
    pub fetched_at: DateTime<Utc>,
    /// Registry URL this cache is from
    pub registry_url: String,
    /// Cached plugin list
    pub plugins: Vec<RegistryPlugin>,
}

/// Plugin registry client
pub struct RegistryClient {
    /// Base URL of the registry
    pub registry_url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl RegistryClient {
    /// Create a new registry client with the default URL
    pub fn new() -> Self {
        Self::with_url(DEFAULT_REGISTRY_URL.to_string())
    }

    /// Create a new registry client with a custom URL
    pub fn with_url(registry_url: String) -> Self {
        Self {
            registry_url,
            client: reqwest::Client::new(),
        }
    }

    /// Fetch the list of available plugins from the registry
    pub async fn fetch_plugins(&self) -> CliResult<Vec<RegistryPlugin>> {
        let url = format!("{}/plugins.json", self.registry_url);

        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| CliError::RegistryUnavailable {
                    url: url.clone(),
                    details: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(CliError::RegistryUnavailable {
                url: url.clone(),
                details: format!("HTTP {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct PluginsResponse {
            plugins: Vec<RegistryPlugin>,
        }

        let data: PluginsResponse =
            response
                .json()
                .await
                .map_err(|e| CliError::RegistryUnavailable {
                    url: url.clone(),
                    details: format!("Failed to parse response: {}", e),
                })?;

        Ok(data.plugins)
    }

    /// Fetch details for a specific plugin
    pub async fn fetch_plugin(&self, name: &str) -> CliResult<RegistryPlugin> {
        let url = format!("{}/plugins/{}.json", self.registry_url, name);

        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| CliError::RegistryUnavailable {
                    url: url.clone(),
                    details: e.to_string(),
                })?;

        if response.status().as_u16() == 404 {
            return Err(CliError::PluginNotFound {
                name: name.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(CliError::RegistryUnavailable {
                url: url.clone(),
                details: format!("HTTP {}", response.status()),
            });
        }

        let plugin: RegistryPlugin =
            response
                .json()
                .await
                .map_err(|e| CliError::RegistryUnavailable {
                    url: url.clone(),
                    details: format!("Failed to parse response: {}", e),
                })?;

        Ok(plugin)
    }

    /// Download a plugin package to the specified path
    pub async fn download_plugin(
        &self,
        plugin: &RegistryPlugin,
        dest_path: &Path,
    ) -> CliResult<()> {
        let response = self
            .client
            .get(&plugin.download_url)
            .send()
            .await
            .map_err(|e| CliError::RegistryUnavailable {
                url: plugin.download_url.clone(),
                details: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(CliError::RegistryUnavailable {
                url: plugin.download_url.clone(),
                details: format!("HTTP {}", response.status()),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| CliError::Io(format!("Failed to download plugin package: {}", e)))?;

        std::fs::write(dest_path, &bytes).map_err(|e| {
            CliError::Io(format!(
                "Failed to write plugin package to {}: {}",
                dest_path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Save plugins to cache
    #[allow(dead_code)]
    pub fn save_cache(&self, plugins: &[RegistryPlugin], paths: &ConfigPaths) -> CliResult<()> {
        let cache = RegistryCache {
            fetched_at: Utc::now(),
            registry_url: self.registry_url.clone(),
            plugins: plugins.to_vec(),
        };

        let cache_path = registry_cache_path(paths);
        let content = serde_json::to_string_pretty(&cache)
            .map_err(|e| CliError::Io(format!("Failed to serialize cache: {}", e)))?;

        std::fs::write(&cache_path, content).map_err(|e| {
            CliError::Io(format!(
                "Failed to write cache file {}: {}",
                cache_path.display(),
                e
            ))
        })
    }

    /// Load cached plugins
    #[allow(dead_code)]
    pub fn load_cache(paths: &ConfigPaths) -> CliResult<Option<RegistryCache>> {
        let cache_path = registry_cache_path(paths);

        if !cache_path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&cache_path).map_err(|e| {
            CliError::Io(format!(
                "Failed to read cache file {}: {}",
                cache_path.display(),
                e
            ))
        })?;

        let cache: RegistryCache = serde_json::from_str(&content).map_err(|e| {
            CliError::Io(format!(
                "Failed to parse cache file {}: {}",
                cache_path.display(),
                e
            ))
        })?;

        Ok(Some(cache))
    }
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a .tar.gz plugin package to the destination directory
pub fn extract_plugin_package(archive_path: &Path, dest_dir: &Path) -> CliResult<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = std::fs::File::open(archive_path).map_err(|e| {
        CliError::Io(format!(
            "Failed to open archive {}: {}",
            archive_path.display(),
            e
        ))
    })?;

    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    archive.unpack(dest_dir).map_err(|e| {
        CliError::Io(format!(
            "Failed to extract archive to {}: {}",
            dest_dir.display(),
            e
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_client_default_url() {
        let client = RegistryClient::new();
        assert_eq!(client.registry_url, DEFAULT_REGISTRY_URL);
    }

    #[test]
    fn test_registry_client_custom_url() {
        let client = RegistryClient::with_url("https://custom.registry.io".to_string());
        assert_eq!(client.registry_url, "https://custom.registry.io");
    }

    #[test]
    fn test_registry_plugin_serialize() {
        let plugin = RegistryPlugin {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A test plugin".to_string(),
            author: Some("Test Author".to_string()),
            download_url: "https://example.com/plugin.tar.gz".to_string(),
            checksum: Some("sha256:abc123".to_string()),
            min_cli_version: Some("0.1.0".to_string()),
        };

        let json = serde_json::to_string(&plugin).unwrap();
        assert!(json.contains("test-plugin"));
        assert!(json.contains("1.0.0"));
    }
}
