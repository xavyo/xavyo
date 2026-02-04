//! Environment variable secret provider.
//!
//! Maps logical secret names to environment variable names using
//! uppercase + underscore convention. This is the default provider
//! for backward compatibility.

use async_trait::async_trait;
use std::collections::HashMap;

use crate::{SecretError, SecretProvider, SecretValue};

/// Secret provider that reads secrets from environment variables.
///
/// Logical names are mapped to env var names via the `mappings` `HashMap`,
/// or by converting to uppercase with underscores if no explicit mapping exists.
#[derive(Debug)]
pub struct EnvSecretProvider {
    /// Explicit logical name → env var name mappings from `SECRET_MAP`_* vars.
    mappings: HashMap<String, String>,
}

impl EnvSecretProvider {
    /// Create a new `EnvSecretProvider` with the given logical name mappings.
    #[must_use] 
    pub fn new(mappings: HashMap<String, String>) -> Self {
        Self { mappings }
    }

    /// Resolve a logical secret name to an environment variable name.
    ///
    /// If an explicit mapping exists (from `SECRET_MAP`_*), use the mapped value
    /// as the env var name. Otherwise, convert the logical name to uppercase.
    fn resolve_env_var_name(&self, logical_name: &str) -> String {
        if let Some(mapped) = self.mappings.get(logical_name) {
            // For env provider, the mapped value IS the env var name
            mapped.clone()
        } else {
            // Default: uppercase the logical name
            logical_name.to_uppercase()
        }
    }
}

#[async_trait]
impl SecretProvider for EnvSecretProvider {
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
        let env_var = self.resolve_env_var_name(name);

        match std::env::var(&env_var) {
            Ok(value) if !value.is_empty() => {
                tracing::debug!(
                    secret_name = name,
                    env_var = %env_var,
                    "Secret loaded from environment variable"
                );
                Ok(SecretValue::new(name, value.into_bytes()))
            }
            Ok(_) => {
                // Empty value treated as not found
                Err(SecretError::NotFound {
                    name: name.to_string(),
                })
            }
            Err(_) => Err(SecretError::NotFound {
                name: name.to_string(),
            }),
        }
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        // Env provider is always available
        Ok(true)
    }

    fn provider_type(&self) -> &'static str {
        "env"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_env_provider_get_existing() {
        std::env::set_var("TEST_SECRET_080_A", "my-secret-value");
        let provider = EnvSecretProvider::new(HashMap::new());
        let result = provider.get_secret("test_secret_080_a").await;
        assert!(result.is_ok());
        let sv = result.unwrap();
        assert_eq!(sv.as_str().unwrap(), "my-secret-value");
        assert_eq!(sv.name, "test_secret_080_a");
        std::env::remove_var("TEST_SECRET_080_A");
    }

    #[tokio::test]
    async fn test_env_provider_get_missing() {
        std::env::remove_var("TEST_NONEXISTENT_SECRET_080");
        let provider = EnvSecretProvider::new(HashMap::new());
        let result = provider.get_secret("test_nonexistent_secret_080").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SecretError::NotFound { name } => {
                assert_eq!(name, "test_nonexistent_secret_080");
            }
            other => panic!("Expected NotFound, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_env_provider_get_empty_value() {
        std::env::set_var("TEST_SECRET_080_EMPTY", "");
        let provider = EnvSecretProvider::new(HashMap::new());
        let result = provider.get_secret("test_secret_080_empty").await;
        assert!(result.is_err());
        std::env::remove_var("TEST_SECRET_080_EMPTY");
    }

    #[tokio::test]
    async fn test_env_provider_explicit_mapping() {
        std::env::set_var("MY_CUSTOM_JWT_VAR_080", "jwt-key-value");
        let mut mappings = HashMap::new();
        mappings.insert(
            "jwt_signing_keys".to_string(),
            "MY_CUSTOM_JWT_VAR_080".to_string(),
        );
        let provider = EnvSecretProvider::new(mappings);
        let result = provider.get_secret("jwt_signing_keys").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str().unwrap(), "jwt-key-value");
        std::env::remove_var("MY_CUSTOM_JWT_VAR_080");
    }

    #[tokio::test]
    async fn test_env_provider_health_check() {
        let provider = EnvSecretProvider::new(HashMap::new());
        let result = provider.health_check().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_env_provider_type() {
        let provider = EnvSecretProvider::new(HashMap::new());
        assert_eq!(provider.provider_type(), "env");
    }
}
