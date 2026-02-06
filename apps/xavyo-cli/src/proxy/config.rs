//! Proxy configuration handling
//!
//! Supports HTTP, HTTPS, and SOCKS5 proxies with optional authentication.
//! Credentials are always masked in logs and error messages.

use crate::error::{CliError, CliResult};
use regex::Regex;
use std::sync::OnceLock;

/// Global proxy configuration, set once at startup
static GLOBAL_PROXY_CONFIG: OnceLock<Option<ProxyConfig>> = OnceLock::new();

/// Initialize the global proxy configuration
///
/// This should be called once at CLI startup with the parsed proxy flags.
/// Subsequent calls are ignored.
pub fn init_global_proxy(config: Option<ProxyConfig>) {
    let _ = GLOBAL_PROXY_CONFIG.set(config);
}

/// Get the global proxy configuration
///
/// Returns None if no proxy config was set (use system defaults)
pub fn global_proxy_config() -> Option<&'static ProxyConfig> {
    GLOBAL_PROXY_CONFIG.get().and_then(|opt| opt.as_ref())
}

/// Proxy configuration for HTTP client
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Explicit proxy URL (overrides environment variables)
    pub proxy_url: Option<String>,
    /// When true, disable all proxy detection
    pub no_proxy: bool,
}

impl ProxyConfig {
    /// Create a new ProxyConfig from CLI arguments
    pub fn from_cli_args(proxy: Option<String>, no_proxy: bool) -> CliResult<Option<Self>> {
        // Check for mutual exclusion
        if proxy.is_some() && no_proxy {
            return Err(CliError::InvalidProxyUrl {
                url: proxy.unwrap_or_default(),
                reason: "--proxy and --no-proxy cannot be used together".to_string(),
            });
        }

        // If neither flag is set, return None to use default behavior
        if proxy.is_none() && !no_proxy {
            return Ok(None);
        }

        // Validate proxy URL if provided
        if let Some(ref url) = proxy {
            validate_proxy_url(url)?;
        }

        Ok(Some(ProxyConfig {
            proxy_url: proxy,
            no_proxy,
        }))
    }

    /// Check if proxy should be disabled
    pub fn is_disabled(&self) -> bool {
        self.no_proxy
    }

    /// Get the proxy URL if configured
    pub fn get_proxy_url(&self) -> Option<&str> {
        self.proxy_url.as_deref()
    }
}

/// Validate a proxy URL
pub fn validate_proxy_url(url: &str) -> CliResult<()> {
    // Check for supported schemes
    let valid_schemes = ["http://", "https://", "socks5://", "socks5h://"];

    if !valid_schemes.iter().any(|scheme| url.starts_with(scheme)) {
        let scheme = url.split("://").next().unwrap_or("(none)");
        return Err(CliError::InvalidProxyUrl {
            url: mask_proxy_credentials(url),
            reason: format!(
                "Unsupported proxy scheme '{}'. Supported schemes: http://, https://, socks5://, socks5h://",
                scheme
            ),
        });
    }

    // Basic URL structure validation
    if let Err(e) = reqwest::Url::parse(url) {
        return Err(CliError::InvalidProxyUrl {
            url: mask_proxy_credentials(url),
            reason: format!("Invalid URL format: {}", e),
        });
    }

    Ok(())
}

/// Mask credentials in a proxy URL for safe logging
///
/// Converts `http://user:password@host:port` to `http://***:***@host:port`
pub fn mask_proxy_credentials(url: &str) -> String {
    // Match user:pass@ pattern
    let re = Regex::new(r"://([^:]+):([^@]+)@").unwrap();
    re.replace(url, "://***:***@").to_string()
}

/// Parse credentials from a proxy URL
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProxyCredentials {
    pub username: String,
    pub password: String,
}

impl ProxyCredentials {
    /// Extract credentials from a proxy URL if present
    #[allow(dead_code)]
    pub fn from_url(url: &str) -> Option<Self> {
        let parsed = reqwest::Url::parse(url).ok()?;

        let username = parsed.username();
        let password = parsed.password()?;

        if username.is_empty() {
            return None;
        }

        // URL-decode the credentials
        let username = urlencoding::decode(username).ok()?.to_string();
        let password = urlencoding::decode(password).ok()?.to_string();

        Some(ProxyCredentials { username, password })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_proxy_url_http() {
        assert!(validate_proxy_url("http://proxy.corp.com:8080").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_https() {
        assert!(validate_proxy_url("https://proxy.corp.com:8443").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_socks5() {
        assert!(validate_proxy_url("socks5://localhost:1080").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_socks5h() {
        assert!(validate_proxy_url("socks5h://localhost:1080").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_with_auth() {
        assert!(validate_proxy_url("http://user:pass@proxy.corp.com:8080").is_ok());
    }

    #[test]
    fn test_validate_proxy_url_invalid_scheme() {
        let result = validate_proxy_url("ftp://proxy.corp.com:21");
        assert!(result.is_err());
        if let Err(CliError::InvalidProxyUrl { reason, .. }) = result {
            assert!(reason.contains("Unsupported proxy scheme"));
        }
    }

    #[test]
    fn test_validate_proxy_url_no_scheme() {
        let result = validate_proxy_url("proxy.corp.com:8080");
        assert!(result.is_err());
    }

    #[test]
    fn test_mask_proxy_credentials() {
        assert_eq!(
            mask_proxy_credentials("http://user:secret@proxy:8080"),
            "http://***:***@proxy:8080"
        );
    }

    #[test]
    fn test_mask_proxy_credentials_no_auth() {
        assert_eq!(
            mask_proxy_credentials("http://proxy:8080"),
            "http://proxy:8080"
        );
    }

    #[test]
    fn test_mask_proxy_credentials_complex_password() {
        assert_eq!(
            mask_proxy_credentials("http://user:p%40ss%3Aword@proxy:8080"),
            "http://***:***@proxy:8080"
        );
    }

    #[test]
    fn test_proxy_credentials_from_url() {
        let creds = ProxyCredentials::from_url("http://myuser:mypass@proxy:8080").unwrap();
        assert_eq!(creds.username, "myuser");
        assert_eq!(creds.password, "mypass");
    }

    #[test]
    fn test_proxy_credentials_from_url_encoded() {
        let creds = ProxyCredentials::from_url("http://user:p%40ss@proxy:8080").unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "p@ss");
    }

    #[test]
    fn test_proxy_credentials_from_url_none() {
        assert!(ProxyCredentials::from_url("http://proxy:8080").is_none());
    }

    #[test]
    fn test_proxy_config_from_cli_no_flags() {
        let config = ProxyConfig::from_cli_args(None, false).unwrap();
        assert!(config.is_none());
    }

    #[test]
    fn test_proxy_config_from_cli_proxy_flag() {
        let config = ProxyConfig::from_cli_args(Some("http://proxy:8080".to_string()), false)
            .unwrap()
            .unwrap();
        assert_eq!(config.get_proxy_url(), Some("http://proxy:8080"));
        assert!(!config.is_disabled());
    }

    #[test]
    fn test_proxy_config_from_cli_no_proxy_flag() {
        let config = ProxyConfig::from_cli_args(None, true).unwrap().unwrap();
        assert!(config.is_disabled());
        assert!(config.get_proxy_url().is_none());
    }

    #[test]
    fn test_proxy_config_conflict() {
        let result = ProxyConfig::from_cli_args(Some("http://proxy:8080".to_string()), true);
        assert!(result.is_err());
    }
}
