//! Integration tests for proxy support
//!
//! Tests cover:
//! - HTTP/HTTPS proxy via environment variables
//! - Authenticated proxy connections
//! - CLI flag overrides (--proxy, --no-proxy)
//! - SOCKS5 proxy support
//! - Error handling and credential masking

use xavyo_cli::proxy::ProxyConfig;

// ============================================================================
// Test Fixtures
// ============================================================================

/// Helper to create a test proxy URL
fn test_proxy_url(host: &str, port: u16) -> String {
    format!("http://{}:{}", host, port)
}

/// Helper to create an authenticated proxy URL
fn test_auth_proxy_url(user: &str, pass: &str, host: &str, port: u16) -> String {
    format!("http://{}:{}@{}:{}", user, pass, host, port)
}

// ============================================================================
// Phase 3: User Story 1 - HTTP Proxy via Environment Variables
// ============================================================================

#[test]
fn test_proxy_config_default() {
    let config = ProxyConfig::from_cli_args(None, false).unwrap();
    assert!(
        config.is_none(),
        "Default should be None for system proxy detection"
    );
}

#[test]
fn test_proxy_config_explicit_url() {
    let url = test_proxy_url("proxy.corp.com", 8080);
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
    assert!(!config.is_disabled());
}

#[test]
fn test_proxy_config_https_scheme() {
    let url = "https://proxy.corp.com:8443".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

// ============================================================================
// Phase 4: User Story 2 - Authenticated Proxy
// ============================================================================

#[test]
fn test_proxy_authentication_basic() {
    let url = test_auth_proxy_url("myuser", "mypassword", "proxy.corp.com", 8080);
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

#[test]
fn test_proxy_authentication_special_chars() {
    // URL-encoded special characters in password
    let url = "http://user:p%40ss%3Aword@proxy.corp.com:8080".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

#[test]
fn test_proxy_credential_masking() {
    use xavyo_cli::proxy::mask_proxy_credentials;

    let url = "http://user:supersecret@proxy.corp.com:8080";
    let masked = mask_proxy_credentials(url);

    assert!(!masked.contains("supersecret"));
    assert!(masked.contains("***:***@"));
    assert!(masked.contains("proxy.corp.com:8080"));
}

#[test]
fn test_proxy_credential_masking_no_creds() {
    use xavyo_cli::proxy::mask_proxy_credentials;

    let url = "http://proxy.corp.com:8080";
    let masked = mask_proxy_credentials(url);

    assert_eq!(masked, url);
}

// ============================================================================
// Phase 5: User Story 3 - CLI Flag Override
// ============================================================================

#[test]
fn test_proxy_cli_flag_override() {
    let url = "http://override-proxy:8080".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

#[test]
fn test_no_proxy_flag_bypass() {
    let config = ProxyConfig::from_cli_args(None, true).unwrap().unwrap();

    assert!(config.is_disabled());
    assert!(config.get_proxy_url().is_none());
}

#[test]
fn test_proxy_invalid_url_error() {
    let result = ProxyConfig::from_cli_args(Some("not-a-valid-url".to_string()), false);

    assert!(result.is_err());
}

#[test]
fn test_proxy_unsupported_scheme_error() {
    let result = ProxyConfig::from_cli_args(Some("ftp://proxy.corp.com:21".to_string()), false);

    assert!(result.is_err());
}

#[test]
fn test_proxy_flag_conflict_error() {
    let result = ProxyConfig::from_cli_args(Some("http://proxy:8080".to_string()), true);

    assert!(result.is_err());
}

// ============================================================================
// Phase 6: User Story 4 - SOCKS5 Proxy
// ============================================================================

#[test]
fn test_proxy_socks5() {
    let url = "socks5://localhost:1080".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

#[test]
fn test_proxy_socks5h() {
    let url = "socks5h://localhost:1080".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

#[test]
fn test_proxy_socks5_auth() {
    let url = "socks5://user:pass@localhost:1080".to_string();
    let config = ProxyConfig::from_cli_args(Some(url.clone()), false)
        .unwrap()
        .unwrap();

    assert_eq!(config.get_proxy_url(), Some(url.as_str()));
}

// ============================================================================
// ProxyCredentials Tests
// ============================================================================

#[test]
fn test_proxy_credentials_from_url() {
    use xavyo_cli::proxy::ProxyCredentials;

    let creds = ProxyCredentials::from_url("http://myuser:mypass@proxy:8080").unwrap();
    assert_eq!(creds.username, "myuser");
    assert_eq!(creds.password, "mypass");
}

#[test]
fn test_proxy_credentials_url_encoded() {
    use xavyo_cli::proxy::ProxyCredentials;

    let creds = ProxyCredentials::from_url("http://user:p%40ss@proxy:8080").unwrap();
    assert_eq!(creds.username, "user");
    assert_eq!(creds.password, "p@ss");
}

#[test]
fn test_proxy_credentials_none_when_no_auth() {
    use xavyo_cli::proxy::ProxyCredentials;

    let creds = ProxyCredentials::from_url("http://proxy:8080");
    assert!(creds.is_none());
}
