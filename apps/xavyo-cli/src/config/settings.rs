//! CLI configuration settings

use crate::config::ConfigPaths;
use crate::error::CliResult;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default API URL
pub const DEFAULT_API_URL: &str = "https://api.xavyo.net";
/// Default Auth URL
pub const DEFAULT_AUTH_URL: &str = "https://auth.xavyo.net";
/// Default OAuth client ID for CLI
pub const DEFAULT_CLIENT_ID: &str = "xavyo-cli";
/// Default HTTP timeout in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// CLI configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API endpoint URL
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Authentication endpoint URL
    #[serde(default = "default_auth_url")]
    pub auth_url: String,

    /// OAuth client ID for CLI
    #[serde(default = "default_client_id")]
    pub client_id: String,

    /// HTTP request timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_api_url() -> String {
    std::env::var("XAVYO_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string())
}

fn default_auth_url() -> String {
    std::env::var("XAVYO_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_URL.to_string())
}

fn default_client_id() -> String {
    DEFAULT_CLIENT_ID.to_string()
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: default_api_url(),
            auth_url: default_auth_url(),
            client_id: default_client_id(),
            timeout_secs: default_timeout_secs(),
        }
    }
}

impl Config {
    /// Load configuration from file, or create with defaults if not found
    pub fn load(paths: &ConfigPaths) -> CliResult<Self> {
        if paths.config_file.exists() {
            Self::load_from_file(&paths.config_file)
        } else {
            Ok(Self::default())
        }
    }

    /// Load configuration from a specific file
    fn load_from_file(path: &Path) -> CliResult<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save(&self, paths: &ConfigPaths) -> CliResult<()> {
        paths.ensure_dir_exists()?;
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&paths.config_file, content)?;
        Ok(())
    }

    /// Get the device code endpoint URL
    pub fn device_code_url(&self) -> String {
        format!("{}/oauth/device/code", self.auth_url)
    }

    /// Get the device token endpoint URL
    pub fn device_token_url(&self) -> String {
        format!("{}/oauth/device/token", self.auth_url)
    }

    /// Get the token refresh endpoint URL
    pub fn token_url(&self) -> String {
        format!("{}/oauth/token", self.auth_url)
    }

    /// Get the tenant provision endpoint URL
    pub fn provision_url(&self) -> String {
        format!("{}/v1/tenants/provision", self.api_url)
    }

    /// Get the health check endpoint URL
    pub fn health_url(&self) -> String {
        format!("{}/health", self.api_url)
    }

    /// Get the auth health check endpoint URL
    pub fn auth_health_url(&self) -> String {
        format!("{}/health", self.auth_url)
    }

    /// Get the signup endpoint URL
    pub fn signup_url(&self) -> String {
        format!("{}/auth/signup", self.auth_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.api_url.is_empty());
        assert!(!config.auth_url.is_empty());
        assert!(!config.client_id.is_empty());
        assert!(config.timeout_secs > 0);
    }

    #[test]
    fn test_config_endpoints() {
        let config = Config {
            api_url: "https://api.test.io".to_string(),
            auth_url: "https://auth.test.io".to_string(),
            client_id: "test-cli".to_string(),
            timeout_secs: 30,
        };

        assert_eq!(
            config.device_code_url(),
            "https://auth.test.io/oauth/device/code"
        );
        assert_eq!(
            config.device_token_url(),
            "https://auth.test.io/oauth/device/token"
        );
        assert_eq!(
            config.provision_url(),
            "https://api.test.io/v1/tenants/provision"
        );
        assert_eq!(config.health_url(), "https://api.test.io/health");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let loaded: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.api_url, loaded.api_url);
        assert_eq!(config.auth_url, loaded.auth_url);
    }
}
