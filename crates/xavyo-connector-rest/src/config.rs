//! REST Connector configuration
//!
//! Configuration types for REST API connections.
//!
//! # Security
//!
//! This module includes SSRF (Server-Side Request Forgery) protection
//! to prevent connector URLs from targeting internal services.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use xavyo_connector::config::{AuthConfig, ConnectionSettings, ConnectorConfig, TlsConfig};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::types::ConnectorType;

use crate::rate_limit::{LogVerbosity, RateLimitConfig, RetryConfig};

/// SSRF protection: Validate that a URL does not target internal services.
///
/// This function blocks requests to:
/// - Private IPv4 ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
/// - Loopback addresses (127.x.x.x, ::1)
/// - Link-local addresses (169.254.x.x, fe80::/10)
/// - Metadata service endpoints
fn validate_url_ssrf(url: &url::Url) -> Result<(), String> {
    // Only allow HTTPS for production connectors
    let scheme = url.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(format!("Unsupported scheme: {}", scheme));
    }

    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    // Check if it's an IP address directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(format!(
                "Private/internal IP addresses are not allowed: {}",
                ip
            ));
        }
    } else {
        // It's a hostname - resolve it and check all IPs
        let port = url.port().unwrap_or(443);
        let addr_str = format!("{}:{}", host, port);

        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(format!(
                        "Hostname {} resolves to private/internal IP: {}",
                        host,
                        addr.ip()
                    ));
                }
            }
        }
    }

    // Block common internal hostnames
    let lower_host = host.to_lowercase();
    let blocked_hosts = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata",
        "metadata.google.internal",
        "169.254.169.254",
    ];

    for blocked in blocked_hosts {
        if lower_host == blocked || lower_host.ends_with(&format!(".{}", blocked)) {
            return Err(format!("Blocked internal hostname: {}", host));
        }
    }

    Ok(())
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
        IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || {
            // Shared address space (100.64.0.0/10)
            let octets = ip.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }
    let segments = ip.segments();
    // Unique local (fc00::/7)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    false
}

/// HTTP method for API operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// Configuration for REST connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestConfig {
    /// Base URL for API requests (e.g., "https://api.example.com/v1").
    pub base_url: String,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: AuthConfig,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Connection settings (timeouts, retries).
    #[serde(default)]
    pub connection: ConnectionSettings,

    /// Default headers to include in all requests.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub default_headers: HashMap<String, String>,

    /// Content type for request bodies.
    #[serde(default = "default_content_type")]
    pub content_type: String,

    /// Accept header value.
    #[serde(default = "default_accept")]
    pub accept: String,

    /// Endpoint configuration for operations.
    #[serde(default)]
    pub endpoints: EndpointConfig,

    /// Pagination configuration.
    #[serde(default)]
    pub pagination: PaginationConfig,

    /// Response parsing configuration.
    #[serde(default)]
    pub response: ResponseConfig,

    /// Optional OpenAPI specification URL for schema discovery.
    /// If provided, schema will be discovered from the OpenAPI spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub openapi_url: Option<String>,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Retry configuration with exponential backoff.
    #[serde(default)]
    pub retry: RetryConfig,

    /// Logging verbosity for request/response logging.
    #[serde(default)]
    pub log_verbosity: LogVerbosity,

    /// Allow localhost URLs (for testing only).
    /// WARNING: Never enable in production - disables SSRF protection.
    #[serde(default)]
    pub allow_localhost: bool,
}

fn default_content_type() -> String {
    "application/json".to_string()
}

fn default_accept() -> String {
    "application/json".to_string()
}

impl RestConfig {
    /// Create a new REST config with required fields.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            auth: AuthConfig::None,
            tls: TlsConfig::default(),
            connection: ConnectionSettings::default(),
            default_headers: HashMap::new(),
            content_type: default_content_type(),
            accept: default_accept(),
            endpoints: EndpointConfig::default(),
            pagination: PaginationConfig::default(),
            response: ResponseConfig::default(),
            openapi_url: None,
            rate_limit: RateLimitConfig::default(),
            retry: RetryConfig::default(),
            log_verbosity: LogVerbosity::default(),
            allow_localhost: false,
        }
    }

    /// Set OpenAPI specification URL for schema discovery.
    pub fn with_openapi_url(mut self, url: impl Into<String>) -> Self {
        self.openapi_url = Some(url.into());
        self
    }

    /// Set authentication.
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = auth;
        self
    }

    /// Set basic authentication.
    pub fn with_basic_auth(self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.with_auth(AuthConfig::basic(username, password))
    }

    /// Set bearer token authentication.
    pub fn with_bearer_token(self, token: impl Into<String>) -> Self {
        self.with_auth(AuthConfig::bearer(token))
    }

    /// Set API key authentication.
    pub fn with_api_key(self, key: impl Into<String>) -> Self {
        self.with_auth(AuthConfig::api_key(key))
    }

    /// Set OAuth2 client credentials authentication.
    pub fn with_oauth2(
        self,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        self.with_auth(AuthConfig::oauth2(token_url, client_id, client_secret))
    }

    /// Add a default header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.default_headers.insert(name.into(), value.into());
        self
    }

    /// Build the full URL for an endpoint.
    pub fn url(&self, path: &str) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{}/{}", base, path)
    }

    /// Set rate limiting configuration.
    pub fn with_rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = config;
        self
    }

    /// Set retry configuration.
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry = config;
        self
    }

    /// Set logging verbosity.
    pub fn with_log_verbosity(mut self, verbosity: LogVerbosity) -> Self {
        self.log_verbosity = verbosity;
        self
    }

    /// Disable rate limiting.
    pub fn without_rate_limit(mut self) -> Self {
        self.rate_limit = RateLimitConfig::disabled();
        self
    }

    /// Disable retries.
    pub fn without_retry(mut self) -> Self {
        self.retry = RetryConfig::disabled();
        self
    }

    /// Allow localhost URLs (for testing only).
    ///
    /// # Warning
    ///
    /// This disables SSRF protection for localhost URLs. **NEVER** use in production!
    /// Only use this for integration tests with mock servers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // In integration tests only:
    /// let config = RestConfig::new(&mock_server.uri())
    ///     .with_allow_localhost();
    /// ```
    pub fn with_allow_localhost(mut self) -> Self {
        self.allow_localhost = true;
        self
    }
}

impl ConnectorConfig for RestConfig {
    fn connector_type() -> ConnectorType {
        ConnectorType::Rest
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.base_url.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "base_url is required".to_string(),
            });
        }

        // Validate URL format
        let url =
            url::Url::parse(&self.base_url).map_err(|e| ConnectorError::InvalidConfiguration {
                message: format!("invalid base_url: {}", e),
            })?;

        // SSRF protection: validate the URL is not targeting internal services
        // Skip this check if allow_localhost is true (for testing only!)
        if !self.allow_localhost {
            validate_url_ssrf(&url).map_err(|e| ConnectorError::InvalidConfiguration {
                message: format!("SSRF protection: {}", e),
            })?;

            // Also validate OAuth2 token URL if present
            if let AuthConfig::OAuth2 { token_url, .. } = &self.auth {
                let oauth_url = url::Url::parse(token_url).map_err(|e| {
                    ConnectorError::InvalidConfiguration {
                        message: format!("invalid OAuth2 token_url: {}", e),
                    }
                })?;
                validate_url_ssrf(&oauth_url).map_err(|e| {
                    ConnectorError::InvalidConfiguration {
                        message: format!("SSRF protection for OAuth2 token_url: {}", e),
                    }
                })?;
            }
        }

        Ok(())
    }

    fn get_credentials(&self) -> Vec<(&'static str, String)> {
        self.auth.get_credentials()
    }

    fn redacted(&self) -> Self {
        let mut config = self.clone();
        config.auth = config.auth.redacted();
        config
    }
}

/// Configuration for API endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Endpoint for listing users (GET).
    #[serde(default = "default_users_endpoint")]
    pub list_users: String,

    /// Endpoint for getting a user by ID (GET).
    #[serde(default = "default_user_endpoint")]
    pub get_user: String,

    /// Endpoint for creating a user (POST).
    #[serde(default = "default_users_endpoint")]
    pub create_user: String,

    /// Endpoint for updating a user (PUT/PATCH).
    #[serde(default = "default_user_endpoint")]
    pub update_user: String,

    /// Endpoint for deleting a user (DELETE).
    #[serde(default = "default_user_endpoint")]
    pub delete_user: String,

    /// Endpoint for listing groups (GET).
    #[serde(default = "default_groups_endpoint")]
    pub list_groups: String,

    /// Endpoint for getting a group by ID (GET).
    #[serde(default = "default_group_endpoint")]
    pub get_group: String,

    /// HTTP method for updates (PUT or PATCH).
    #[serde(default = "default_update_method")]
    pub update_method: HttpMethod,

    /// ID placeholder in URLs (default: "{id}").
    #[serde(default = "default_id_placeholder")]
    pub id_placeholder: String,
}

fn default_users_endpoint() -> String {
    "/users".to_string()
}

fn default_user_endpoint() -> String {
    "/users/{id}".to_string()
}

fn default_groups_endpoint() -> String {
    "/groups".to_string()
}

fn default_group_endpoint() -> String {
    "/groups/{id}".to_string()
}

fn default_update_method() -> HttpMethod {
    HttpMethod::Put
}

fn default_id_placeholder() -> String {
    "{id}".to_string()
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self {
            list_users: default_users_endpoint(),
            get_user: default_user_endpoint(),
            create_user: default_users_endpoint(),
            update_user: default_user_endpoint(),
            delete_user: default_user_endpoint(),
            list_groups: default_groups_endpoint(),
            get_group: default_group_endpoint(),
            update_method: default_update_method(),
            id_placeholder: default_id_placeholder(),
        }
    }
}

impl EndpointConfig {
    /// Get the endpoint for an object by ID, replacing the placeholder.
    pub fn endpoint_for_id(&self, template: &str, id: &str) -> String {
        template.replace(&self.id_placeholder, id)
    }
}

/// Configuration for API pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationConfig {
    /// Pagination style.
    #[serde(default)]
    pub style: PaginationStyle,

    /// Query parameter for page number.
    #[serde(default = "default_page_param")]
    pub page_param: String,

    /// Query parameter for page size.
    #[serde(default = "default_size_param")]
    pub size_param: String,

    /// Query parameter for offset (offset-based pagination).
    #[serde(default = "default_offset_param")]
    pub offset_param: String,

    /// Default page size.
    #[serde(default = "default_page_size")]
    pub default_page_size: u32,

    /// Maximum page size.
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u32,
}

fn default_page_param() -> String {
    "page".to_string()
}

fn default_size_param() -> String {
    "pageSize".to_string()
}

fn default_offset_param() -> String {
    "offset".to_string()
}

fn default_page_size() -> u32 {
    100
}

fn default_max_page_size() -> u32 {
    1000
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            style: PaginationStyle::PageBased,
            page_param: default_page_param(),
            size_param: default_size_param(),
            offset_param: default_offset_param(),
            default_page_size: default_page_size(),
            max_page_size: default_max_page_size(),
        }
    }
}

/// Pagination style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PaginationStyle {
    /// Page-based pagination (page=1, pageSize=100).
    #[default]
    PageBased,
    /// Offset-based pagination (offset=0, limit=100).
    OffsetBased,
    /// Cursor-based pagination (cursor=abc123).
    CursorBased,
    /// No pagination support.
    None,
}

/// Configuration for parsing API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// JSON path to the array of results (e.g., "data", "results", "items").
    #[serde(default)]
    pub results_path: Option<String>,

    /// JSON path to the total count field.
    #[serde(default)]
    pub total_count_path: Option<String>,

    /// JSON path to the next page cursor.
    #[serde(default)]
    pub next_cursor_path: Option<String>,

    /// JSON path to the ID field in response objects.
    #[serde(default = "default_id_path")]
    pub id_path: String,

    /// Field name for error messages in error responses.
    #[serde(default = "default_error_message_path")]
    pub error_message_path: String,
}

fn default_id_path() -> String {
    "id".to_string()
}

fn default_error_message_path() -> String {
    "message".to_string()
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            results_path: None,
            total_count_path: None,
            next_cursor_path: None,
            id_path: default_id_path(),
            error_message_path: default_error_message_path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rest_config_new() {
        let config = RestConfig::new("https://api.example.com/v1").with_bearer_token("token123");

        assert_eq!(config.base_url, "https://api.example.com/v1");
        if let AuthConfig::Bearer { token } = &config.auth {
            assert_eq!(token, "token123");
        } else {
            panic!("Expected Bearer auth");
        }
    }

    #[test]
    fn test_rest_config_url() {
        let config = RestConfig::new("https://api.example.com/v1/");
        assert_eq!(config.url("/users"), "https://api.example.com/v1/users");
        assert_eq!(config.url("users"), "https://api.example.com/v1/users");
    }

    #[test]
    fn test_rest_config_validation() {
        let config = RestConfig::new("https://api.example.com/v1");
        assert!(config.validate().is_ok());

        let empty_url = RestConfig::new("");
        assert!(empty_url.validate().is_err());

        let invalid_url = RestConfig::new("not-a-url");
        assert!(invalid_url.validate().is_err());
    }

    #[test]
    fn test_rest_config_headers() {
        let config = RestConfig::new("https://api.example.com")
            .with_header("X-Custom-Header", "value1")
            .with_header("X-Another-Header", "value2");

        assert_eq!(
            config.default_headers.get("X-Custom-Header"),
            Some(&"value1".to_string())
        );
        assert_eq!(
            config.default_headers.get("X-Another-Header"),
            Some(&"value2".to_string())
        );
    }

    #[test]
    fn test_rest_config_redacted() {
        let config = RestConfig::new("https://api.example.com").with_bearer_token("secret-token");

        let redacted = config.redacted();
        if let AuthConfig::Bearer { token } = &redacted.auth {
            assert_eq!(token, "***REDACTED***");
        } else {
            panic!("Expected Bearer auth");
        }
    }

    #[test]
    fn test_endpoint_config_id_replacement() {
        let endpoints = EndpointConfig::default();
        let url = endpoints.endpoint_for_id("/users/{id}", "123");
        assert_eq!(url, "/users/123");
    }

    #[test]
    fn test_rest_config_serialization() {
        let config = RestConfig::new("https://api.example.com")
            .with_basic_auth("admin", "secret")
            .with_header("X-Custom", "value");

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RestConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.base_url, "https://api.example.com");
        assert_eq!(
            parsed.default_headers.get("X-Custom"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_pagination_config_defaults() {
        let pagination = PaginationConfig::default();
        assert_eq!(pagination.style, PaginationStyle::PageBased);
        assert_eq!(pagination.page_param, "page");
        assert_eq!(pagination.size_param, "pageSize");
        assert_eq!(pagination.default_page_size, 100);
    }

    #[test]
    fn test_response_config_defaults() {
        let response = ResponseConfig::default();
        assert_eq!(response.id_path, "id");
        assert_eq!(response.error_message_path, "message");
        assert!(response.results_path.is_none());
    }
}
