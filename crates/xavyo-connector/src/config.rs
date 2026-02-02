//! Connector Framework configuration types
//!
//! Base trait and common configuration structures.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::ConnectorResult;
use crate::types::ConnectorType;

/// Trait for connector-specific configuration.
///
/// Each connector type implements this trait to define its configuration
/// schema and validation rules.
pub trait ConnectorConfig: Serialize + DeserializeOwned + Clone + Send + Sync {
    /// Get the connector type this configuration is for.
    fn connector_type() -> ConnectorType;

    /// Validate the configuration.
    ///
    /// Returns an error if the configuration is invalid.
    fn validate(&self) -> ConnectorResult<()>;

    /// Get credentials that need to be encrypted.
    ///
    /// Returns a list of (field_name, value) pairs for sensitive data.
    fn get_credentials(&self) -> Vec<(&'static str, String)>;

    /// Create a redacted version of this config (for logging/display).
    ///
    /// Sensitive fields should be replaced with placeholders.
    fn redacted(&self) -> Self;
}

/// Common connection settings shared across connector types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSettings {
    /// Connection timeout in seconds.
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Read timeout in seconds.
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,

    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// Maximum retry attempts for transient failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry delay in milliseconds.
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_read_timeout() -> u64 {
    60
}

fn default_pool_size() -> u32 {
    5
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_delay_ms() -> u64 {
    1000
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            connection_timeout_secs: default_connection_timeout(),
            read_timeout_secs: default_read_timeout(),
            pool_size: default_pool_size(),
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
        }
    }
}

impl ConnectionSettings {
    /// Create new connection settings with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the connection timeout.
    pub fn with_connection_timeout(mut self, secs: u64) -> Self {
        self.connection_timeout_secs = secs;
        self
    }

    /// Set the read timeout.
    pub fn with_read_timeout(mut self, secs: u64) -> Self {
        self.read_timeout_secs = secs;
        self
    }

    /// Set the pool size.
    pub fn with_pool_size(mut self, size: u32) -> Self {
        self.pool_size = size;
        self
    }

    /// Get connection timeout as Duration.
    pub fn connection_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.connection_timeout_secs)
    }

    /// Get read timeout as Duration.
    pub fn read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.read_timeout_secs)
    }
}

/// SSL/TLS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Whether to use SSL/TLS.
    #[serde(default)]
    pub enabled: bool,

    /// Whether to verify the server certificate.
    #[serde(default = "default_true")]
    pub verify_certificate: bool,

    /// Path to CA certificate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert_path: Option<String>,

    /// Path to client certificate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert_path: Option<String>,

    /// Path to client key file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key_path: Option<String>,

    /// Acceptable TLS versions (e.g., ["1.2", "1.3"]).
    #[serde(default)]
    pub tls_versions: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            verify_certificate: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            tls_versions: Vec::new(),
        }
    }
}

impl TlsConfig {
    /// Validate the TLS configuration and log security warnings.
    ///
    /// This should be called after deserializing TLS configuration from
    /// external sources (environment, config files, database) to detect
    /// and warn about insecure configurations.
    pub fn validate_security(&self) {
        if self.enabled && !self.verify_certificate {
            tracing::warn!(
                target: "security",
                "SECURITY WARNING: TLS certificate verification is DISABLED. \
                 This makes the connection vulnerable to Man-in-the-Middle attacks. \
                 This should ONLY be used for local development."
            );

            // In release builds, log an error as well
            #[cfg(not(debug_assertions))]
            tracing::error!(
                target: "security",
                "CRITICAL: TLS certificate verification disabled in production environment!"
            );
        }
    }

    /// Create a new TLS config with SSL enabled.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Create a new TLS config with SSL enabled but no certificate verification.
    ///
    /// # Warning
    ///
    /// **SECURITY RISK**: This configuration disables TLS certificate verification,
    /// making the connection vulnerable to Man-in-the-Middle (MITM) attacks.
    /// This should ONLY be used for local development and testing.
    ///
    /// In production, this will log a security warning.
    #[cfg(any(test, debug_assertions))]
    pub fn insecure() -> Self {
        tracing::warn!(
            target: "security",
            "TLS certificate verification disabled - THIS IS INSECURE"
        );
        Self {
            enabled: true,
            verify_certificate: false,
            ..Default::default()
        }
    }

    /// Create a new TLS config with SSL enabled but no certificate verification.
    ///
    /// # Warning
    ///
    /// **SECURITY RISK**: This configuration is not available in release builds.
    /// Certificate verification is required for production use.
    #[cfg(not(any(test, debug_assertions)))]
    #[deprecated(
        since = "0.1.0",
        note = "insecure TLS is disabled in release builds - use enabled() with proper CA certificates"
    )]
    pub fn insecure() -> Self {
        tracing::error!(
            target: "security",
            "CRITICAL: Attempted to disable TLS certificate verification in production - using secure defaults instead"
        );
        // Return secure defaults in release builds
        Self::enabled()
    }

    /// Set the CA certificate path.
    pub fn with_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set client certificate and key paths.
    pub fn with_client_cert(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }
}

/// Authentication method configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// No authentication.
    #[default]
    None,

    /// Basic authentication (username/password).
    Basic {
        username: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<String>,
    },

    /// API key authentication.
    ApiKey {
        key: String,
        #[serde(default = "default_api_key_header")]
        header_name: String,
    },

    /// Bearer token authentication.
    Bearer { token: String },

    /// OAuth2 client credentials flow.
    #[serde(rename = "oauth2")]
    OAuth2 {
        token_url: String,
        client_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_secret: Option<String>,
        #[serde(default)]
        scopes: Vec<String>,
    },
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

impl AuthConfig {
    /// Create basic authentication config.
    pub fn basic(username: impl Into<String>, password: impl Into<String>) -> Self {
        AuthConfig::Basic {
            username: username.into(),
            password: Some(password.into()),
        }
    }

    /// Create API key authentication config.
    pub fn api_key(key: impl Into<String>) -> Self {
        AuthConfig::ApiKey {
            key: key.into(),
            header_name: default_api_key_header(),
        }
    }

    /// Create bearer token authentication config.
    pub fn bearer(token: impl Into<String>) -> Self {
        AuthConfig::Bearer {
            token: token.into(),
        }
    }

    /// Create OAuth2 client credentials config.
    pub fn oauth2(
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        AuthConfig::OAuth2 {
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            scopes: Vec::new(),
        }
    }

    /// Get credentials that need to be encrypted.
    pub fn get_credentials(&self) -> Vec<(&'static str, String)> {
        match self {
            AuthConfig::None => vec![],
            AuthConfig::Basic { password, .. } => password
                .as_ref()
                .map_or(vec![], |p| vec![("password", p.clone())]),
            AuthConfig::ApiKey { key, .. } => vec![("api_key", key.clone())],
            AuthConfig::Bearer { token } => vec![("token", token.clone())],
            AuthConfig::OAuth2 { client_secret, .. } => client_secret
                .as_ref()
                .map_or(vec![], |s| vec![("client_secret", s.clone())]),
        }
    }

    /// Create a redacted version.
    pub fn redacted(&self) -> Self {
        match self {
            AuthConfig::None => AuthConfig::None,
            AuthConfig::Basic { username, .. } => AuthConfig::Basic {
                username: username.clone(),
                password: Some("***REDACTED***".to_string()),
            },
            AuthConfig::ApiKey { header_name, .. } => AuthConfig::ApiKey {
                key: "***REDACTED***".to_string(),
                header_name: header_name.clone(),
            },
            AuthConfig::Bearer { .. } => AuthConfig::Bearer {
                token: "***REDACTED***".to_string(),
            },
            AuthConfig::OAuth2 {
                token_url,
                client_id,
                scopes,
                ..
            } => AuthConfig::OAuth2 {
                token_url: token_url.clone(),
                client_id: client_id.clone(),
                client_secret: Some("***REDACTED***".to_string()),
                scopes: scopes.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_settings_defaults() {
        let settings = ConnectionSettings::default();
        assert_eq!(settings.connection_timeout_secs, 30);
        assert_eq!(settings.read_timeout_secs, 60);
        assert_eq!(settings.pool_size, 5);
    }

    #[test]
    fn test_connection_settings_builder() {
        let settings = ConnectionSettings::new()
            .with_connection_timeout(60)
            .with_pool_size(10);

        assert_eq!(settings.connection_timeout_secs, 60);
        assert_eq!(settings.pool_size, 10);
    }

    #[test]
    fn test_tls_config_enabled() {
        let tls = TlsConfig::enabled();
        assert!(tls.enabled);
        assert!(tls.verify_certificate);
    }

    #[test]
    fn test_tls_config_insecure() {
        let tls = TlsConfig::insecure();
        assert!(tls.enabled);
        assert!(!tls.verify_certificate);
    }

    #[test]
    fn test_auth_config_basic() {
        let auth = AuthConfig::basic("admin", "secret");
        if let AuthConfig::Basic { username, password } = auth {
            assert_eq!(username, "admin");
            assert_eq!(password, Some("secret".to_string()));
        } else {
            panic!("Expected Basic auth");
        }
    }

    #[test]
    fn test_auth_config_credentials() {
        let auth = AuthConfig::basic("admin", "secret");
        let creds = auth.get_credentials();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], ("password", "secret".to_string()));
    }

    #[test]
    fn test_auth_config_redacted() {
        let auth = AuthConfig::basic("admin", "secret");
        let redacted = auth.redacted();
        if let AuthConfig::Basic { username, password } = redacted {
            assert_eq!(username, "admin");
            assert_eq!(password, Some("***REDACTED***".to_string()));
        } else {
            panic!("Expected Basic auth");
        }
    }

    #[test]
    fn test_auth_config_serialization() {
        let auth = AuthConfig::OAuth2 {
            token_url: "https://auth.example.com/token".to_string(),
            client_id: "my-client".to_string(),
            client_secret: Some("secret".to_string()),
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("\"type\":\"oauth2\""));
        assert!(json.contains("\"token_url\""));

        let parsed: AuthConfig = serde_json::from_str(&json).unwrap();
        if let AuthConfig::OAuth2 { client_id, .. } = parsed {
            assert_eq!(client_id, "my-client");
        } else {
            panic!("Expected OAuth2 auth");
        }
    }
}
