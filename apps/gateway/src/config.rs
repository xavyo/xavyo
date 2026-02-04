//! Gateway configuration loading and types.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::error::{GatewayError, GatewayResult};

/// Root gateway configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub backends: Vec<BackendConfig>,
    pub rate_limits: RateLimitConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// HTTP server configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_body_size")]
    pub max_body_size_bytes: usize,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_timeout() -> u64 {
    30
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

/// Configuration for a single backend service.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct BackendConfig {
    pub name: String,
    pub path_prefix: String,
    pub url: String,
    #[serde(default = "default_backend_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_openapi_path")]
    pub openapi_path: String,
    #[serde(default = "default_requires_auth")]
    pub requires_auth: bool,
    #[serde(default = "default_strip_prefix")]
    pub strip_prefix: bool,
}

fn default_backend_timeout() -> u64 {
    30
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_openapi_path() -> String {
    "/docs/openapi.json".to_string()
}

fn default_requires_auth() -> bool {
    true
}

fn default_strip_prefix() -> bool {
    true
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_minute")]
    pub default_requests_per_minute: u32,
    #[serde(default = "default_burst_size")]
    pub default_burst_size: u32,
    #[serde(default)]
    pub tenant_overrides: HashMap<String, TenantLimit>,
    #[serde(default)]
    pub endpoint_overrides: Vec<EndpointLimit>,
}

fn default_enabled() -> bool {
    true
}

fn default_requests_per_minute() -> u32 {
    100
}

fn default_burst_size() -> u32 {
    10
}

/// Per-tenant rate limit override.
#[derive(Debug, Clone, Deserialize)]
pub struct TenantLimit {
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

/// Per-endpoint rate limit override.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct EndpointLimit {
    pub path_pattern: String,
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

/// Authentication configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AuthConfig {
    pub public_key_path: String,
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub public_paths: Vec<String>,
}

/// Metrics configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[allow(dead_code)]
pub struct MetricsConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

/// CORS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,
    #[serde(default = "default_max_age")]
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            max_age_secs: default_max_age(),
        }
    }
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "PATCH".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_allowed_headers() -> Vec<String> {
    vec![
        "Authorization".to_string(),
        "Content-Type".to_string(),
        "X-Request-ID".to_string(),
        "X-Tenant-ID".to_string(),
    ]
}

fn default_max_age() -> u64 {
    86400
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

impl GatewayConfig {
    /// Load configuration from a YAML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> GatewayResult<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            GatewayError::Config(format!(
                "Failed to read config file {}: {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Self::from_yaml(&content)
    }

    /// Parse configuration from a YAML string.
    pub fn from_yaml(content: &str) -> GatewayResult<Self> {
        serde_yaml::from_str(content)
            .map_err(|e| GatewayError::Config(format!("Failed to parse config: {e}")))
    }

    /// Get the configuration file path from environment or default.
    pub fn config_path() -> String {
        std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "./config/gateway.yaml".to_string())
    }

    /// Apply environment variable overrides.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(host) = std::env::var("GATEWAY_HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("GATEWAY_PORT") {
            if let Ok(port) = port.parse() {
                self.server.port = port;
            }
        }
    }

    /// Find a backend by path prefix.
    pub fn find_backend(&self, path: &str) -> Option<&BackendConfig> {
        self.backends
            .iter()
            .find(|b| path.starts_with(&b.path_prefix))
    }

    /// Check if a path is public (no auth required).
    pub fn is_public_path(&self, path: &str) -> bool {
        for public_path in &self.auth.public_paths {
            if public_path.ends_with('*') {
                let prefix = &public_path[..public_path.len() - 1];
                if path.starts_with(prefix) {
                    return true;
                }
            } else if path == public_path {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
server:
  port: 8080

backends:
  - name: test-api
    path_prefix: /test
    url: http://localhost:9000

rate_limits:
  enabled: true

auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
"#;

        let config = GatewayConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].name, "test-api");
    }

    #[test]
    fn test_find_backend() {
        let yaml = r#"
server:
  port: 8080

backends:
  - name: idp-api
    path_prefix: /idp
    url: http://localhost:8081
  - name: crm-api
    path_prefix: /crm
    url: http://localhost:8082

rate_limits:
  enabled: true

auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
"#;

        let config = GatewayConfig::from_yaml(yaml).unwrap();

        let backend = config.find_backend("/idp/users");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name, "idp-api");

        let backend = config.find_backend("/crm/contacts");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name, "crm-api");

        let backend = config.find_backend("/unknown/path");
        assert!(backend.is_none());
    }

    #[test]
    fn test_is_public_path() {
        let yaml = r#"
server:
  port: 8080

backends: []

rate_limits:
  enabled: true

auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
  public_paths:
    - /health
    - /metrics
    - /docs/*
"#;

        let config = GatewayConfig::from_yaml(yaml).unwrap();

        assert!(config.is_public_path("/health"));
        assert!(config.is_public_path("/metrics"));
        assert!(config.is_public_path("/docs/swagger"));
        assert!(config.is_public_path("/docs/openapi.json"));
        assert!(!config.is_public_path("/idp/users"));
        assert!(!config.is_public_path("/private"));
    }
}
