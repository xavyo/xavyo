//! Pluggable secret provider abstraction for the xavyo platform.
//!
//! This crate provides a `SecretProvider` trait that abstracts secret retrieval
//! from multiple backends: environment variables, files, HashiCorp Vault, and
//! AWS Secrets Manager.
//!
//! # Usage
//!
//! ```rust,ignore
//! use xavyo_secrets::{SecretProviderConfig, build_provider};
//!
//! let config = SecretProviderConfig::from_env()?;
//! let provider = build_provider(&config).await?;
//! let secret = provider.get_secret("jwt_signing_keys").await?;
//! let pem_str = secret.as_str()?;
//! ```

pub mod cache;
pub mod config;
pub mod dynamic;
pub mod health;
pub mod provider;
pub mod rotation;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

// Re-exports
pub use cache::CachedSecretProvider;
pub use config::SecretProviderConfig;
pub use dynamic::{
    DynamicCredential, DynamicCredentialRequest, DynamicProviderType, DynamicSecretProvider,
};
pub use health::{SecretHealthCheck, SecretHealthStatus};
pub use provider::internal::InternalSecretProvider;
pub use rotation::KeyRotationManager;

// Dynamic provider exports (F120)
#[cfg(feature = "vault-provider")]
pub use provider::infisical::{InfisicalAuthMethod, InfisicalConfig, InfisicalSecretProvider};
#[cfg(feature = "vault-provider")]
pub use provider::openbao::{OpenBaoAuthMethod, OpenBaoConfig, OpenBaoSecretProvider};

// ── SecretError ──────────────────────────────────────────────────────────

/// Errors returned by secret provider operations.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// Secret not found in provider.
    #[error("Secret not found: '{name}'")]
    NotFound { name: String },

    /// Provider is unreachable (network error, auth failure).
    #[error("Secret provider '{provider}' unavailable: {detail}")]
    ProviderUnavailable { provider: String, detail: String },

    /// Secret value is malformed (wrong format, empty, corrupt).
    #[error("Invalid secret value for '{name}': {detail}")]
    InvalidValue { name: String, detail: String },

    /// Configuration error (missing required config, invalid path).
    #[error("Secret provider configuration error: {detail}")]
    ConfigError { detail: String },

    /// Permission denied (file permissions, IAM policy).
    #[error("Permission denied: {detail}")]
    PermissionDenied { detail: String },
}

// ── SecretValue ──────────────────────────────────────────────────────────

/// A resolved secret value returned by any provider.
#[derive(Clone)]
pub struct SecretValue {
    /// Logical secret name (e.g., "jwt_signing_keys").
    pub name: String,

    /// Raw secret bytes (UTF-8 text or binary).
    pub value: Vec<u8>,

    /// Provider-specific version identifier (Vault version, AWS version ID).
    pub version: Option<String>,

    /// Timestamp when this value was fetched from the provider.
    pub loaded_at: DateTime<Utc>,
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .field("version", &self.version)
            .field("loaded_at", &self.loaded_at)
            .finish()
    }
}

impl SecretValue {
    /// Create a new SecretValue.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
            version: None,
            loaded_at: Utc::now(),
        }
    }

    /// Interpret the secret value as a UTF-8 string.
    pub fn as_str(&self) -> Result<&str, SecretError> {
        std::str::from_utf8(&self.value).map_err(|e| SecretError::InvalidValue {
            name: self.name.clone(),
            detail: format!("Not valid UTF-8: {e}"),
        })
    }

    /// Interpret the secret value as hex-encoded bytes (for encryption keys).
    pub fn as_hex_bytes(&self) -> Result<Vec<u8>, SecretError> {
        let hex_str = self.as_str()?;
        hex::decode(hex_str.trim()).map_err(|e| SecretError::InvalidValue {
            name: self.name.clone(),
            detail: format!("Not valid hex: {e}"),
        })
    }

    /// Interpret the secret value as base64-encoded bytes.
    pub fn as_base64_bytes(&self) -> Result<Vec<u8>, SecretError> {
        use base64::Engine;
        let b64_str = self.as_str()?;
        base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| SecretError::InvalidValue {
                name: self.name.clone(),
                detail: format!("Not valid base64: {e}"),
            })
    }
}

// ── SecretProvider Trait ──────────────────────────────────────────────────

/// Trait that all secret providers must implement.
///
/// Providers resolve logical secret names to their values from various
/// backends (env vars, files, Vault, AWS Secrets Manager).
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Retrieve a secret by its logical name.
    ///
    /// Returns `SecretError::NotFound` if the secret does not exist in the provider.
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError>;

    /// Check if the provider is reachable and operational.
    ///
    /// Returns `Ok(true)` if healthy, `Ok(false)` if degraded, `Err` if unhealthy.
    async fn health_check(&self) -> Result<bool, SecretError>;

    /// Return the provider type name for logging/diagnostics.
    fn provider_type(&self) -> &'static str;
}

// ── Provider Factory ─────────────────────────────────────────────────────

/// Build a secret provider based on the given configuration.
///
/// Returns the provider wrapped in a `CachedSecretProvider` for TTL-based caching.
pub async fn build_provider(
    config: &SecretProviderConfig,
) -> Result<Arc<dyn SecretProvider>, SecretError> {
    use config::ProviderType;

    let inner: Arc<dyn SecretProvider> = match config.provider_type {
        ProviderType::Env => {
            let p = provider::env::EnvSecretProvider::new(config.secret_mappings.clone());
            Arc::new(p)
        }
        #[cfg(feature = "file-provider")]
        ProviderType::File => {
            let p = provider::file::FileSecretProvider::new(config)?;
            Arc::new(p)
        }
        #[cfg(not(feature = "file-provider"))]
        ProviderType::File => {
            return Err(SecretError::ConfigError {
                detail: "File provider is not enabled. Compile with 'file-provider' feature."
                    .to_string(),
            });
        }
        #[cfg(feature = "vault-provider")]
        ProviderType::Vault => {
            let p = provider::vault::VaultSecretProvider::new(config).await?;
            Arc::new(p)
        }
        #[cfg(not(feature = "vault-provider"))]
        ProviderType::Vault => {
            return Err(SecretError::ConfigError {
                detail: "Vault provider is not enabled. Compile with 'vault-provider' feature."
                    .to_string(),
            });
        }
        #[cfg(feature = "aws-provider")]
        ProviderType::Aws => {
            let p = provider::aws::AwsSecretProvider::new(config).await?;
            Arc::new(p)
        }
        #[cfg(not(feature = "aws-provider"))]
        ProviderType::Aws => {
            return Err(SecretError::ConfigError {
                detail: "AWS provider is not enabled. Compile with 'aws-provider' feature."
                    .to_string(),
            });
        }
    };

    // Wrap in caching layer
    let cached = CachedSecretProvider::new(inner, config.cache_ttl_seconds);
    Ok(Arc::new(cached))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_value_as_str_valid() {
        let sv = SecretValue::new("test", b"hello world".to_vec());
        assert_eq!(sv.as_str().unwrap(), "hello world");
    }

    #[test]
    fn test_secret_value_as_str_invalid_utf8() {
        let sv = SecretValue::new("test", vec![0xFF, 0xFE]);
        let err = sv.as_str().unwrap_err();
        match err {
            SecretError::InvalidValue { name, detail } => {
                assert_eq!(name, "test");
                assert!(detail.contains("UTF-8"));
            }
            _ => panic!("Expected InvalidValue error"),
        }
    }

    #[test]
    fn test_secret_value_as_hex_bytes() {
        let sv = SecretValue::new("test", b"48656c6c6f".to_vec());
        let bytes = sv.as_hex_bytes().unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_secret_value_as_hex_bytes_invalid() {
        let sv = SecretValue::new("test", b"not-hex!".to_vec());
        assert!(sv.as_hex_bytes().is_err());
    }

    #[test]
    fn test_secret_value_as_base64_bytes() {
        let sv = SecretValue::new("test", b"SGVsbG8=".to_vec());
        let bytes = sv.as_base64_bytes().unwrap();
        assert_eq!(bytes, b"Hello");
    }

    #[test]
    fn test_secret_value_as_base64_bytes_invalid() {
        let sv = SecretValue::new("test", b"not-base64!!!".to_vec());
        assert!(sv.as_base64_bytes().is_err());
    }

    #[test]
    fn test_secret_value_new_sets_loaded_at() {
        let before = Utc::now();
        let sv = SecretValue::new("test", b"value".to_vec());
        let after = Utc::now();
        assert!(sv.loaded_at >= before && sv.loaded_at <= after);
        assert!(sv.version.is_none());
    }

    #[test]
    fn test_secret_error_display() {
        let err = SecretError::NotFound {
            name: "jwt_keys".to_string(),
        };
        assert_eq!(err.to_string(), "Secret not found: 'jwt_keys'");

        let err = SecretError::ProviderUnavailable {
            provider: "vault".to_string(),
            detail: "connection refused".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Secret provider 'vault' unavailable: connection refused"
        );

        let err = SecretError::InvalidValue {
            name: "key".to_string(),
            detail: "empty".to_string(),
        };
        assert_eq!(err.to_string(), "Invalid secret value for 'key': empty");

        let err = SecretError::ConfigError {
            detail: "missing VAULT_ADDR".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Secret provider configuration error: missing VAULT_ADDR"
        );

        let err = SecretError::PermissionDenied {
            detail: "file unreadable".to_string(),
        };
        assert_eq!(err.to_string(), "Permission denied: file unreadable");
    }
}
