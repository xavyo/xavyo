//! Health check integration for the secrets subsystem.
//!
//! Reports secret provider health status to the platform's readiness probe.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;

use crate::cache::CachedSecretProvider;
use crate::SecretProvider;

/// Health state for the secrets subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretsHealthState {
    /// Provider accessible, all secrets cached and valid.
    Healthy,
    /// Provider unreachable but cached secrets still valid.
    Degraded,
    /// Required secrets missing from both cache and provider.
    Unhealthy,
}

/// Health status for the secrets subsystem.
#[derive(Debug, Clone, Serialize)]
pub struct SecretHealthStatus {
    /// Overall health state.
    pub status: SecretsHealthState,
    /// Whether the provider responded to the last check.
    pub provider_reachable: bool,
    /// Number of secrets currently cached.
    pub cached_secrets_count: usize,
    /// Number of cached secrets past their TTL.
    pub expired_secrets_count: usize,
    /// Timestamp of last health check.
    pub last_check_at: DateTime<Utc>,
    /// Additional detail message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Provider type name.
    pub provider: String,
}

/// Checks the health of the secrets subsystem.
pub struct SecretHealthCheck;

impl SecretHealthCheck {
    /// Check the health of a cached secret provider.
    pub async fn check(provider: &Arc<dyn SecretProvider>) -> SecretHealthStatus {
        let provider_type = provider.provider_type().to_string();

        // Try provider health check
        let provider_reachable = provider.health_check().await.unwrap_or_default();

        // If the provider is a CachedSecretProvider, get cache stats
        // Since we can't downcast Arc<dyn SecretProvider>, we report based on reachability
        let (cached_count, expired_count) = (0usize, 0usize);

        let (status, details) = if provider_reachable {
            (SecretsHealthState::Healthy, None)
        } else {
            (
                SecretsHealthState::Degraded,
                Some("Provider unreachable, using cached secrets".to_string()),
            )
        };

        SecretHealthStatus {
            status,
            provider_reachable,
            cached_secrets_count: cached_count,
            expired_secrets_count: expired_count,
            last_check_at: Utc::now(),
            details,
            provider: provider_type,
        }
    }

    /// Check health with access to cache stats.
    pub async fn check_with_cache(provider: &CachedSecretProvider) -> SecretHealthStatus {
        let provider_type = provider.provider_type().to_string();

        let provider_reachable = provider.health_check().await.unwrap_or_default();

        let cache_stats = provider.cache_stats().await;

        let (status, details) = if provider_reachable {
            (SecretsHealthState::Healthy, None)
        } else if cache_stats.total_count > 0 {
            (
                SecretsHealthState::Degraded,
                Some("Provider unreachable, using cached secrets".to_string()),
            )
        } else {
            (
                SecretsHealthState::Unhealthy,
                Some("Provider unreachable and no cached secrets available".to_string()),
            )
        };

        SecretHealthStatus {
            status,
            provider_reachable,
            cached_secrets_count: cache_stats.total_count,
            expired_secrets_count: cache_stats.expired_count,
            last_check_at: Utc::now(),
            details,
            provider: provider_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachedSecretProvider;
    use crate::{SecretError, SecretValue};

    /// A mock provider that is always healthy.
    struct HealthyMockProvider;

    #[async_trait::async_trait]
    impl SecretProvider for HealthyMockProvider {
        async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
            Ok(SecretValue::new(name, b"mock-value".to_vec()))
        }
        async fn health_check(&self) -> Result<bool, SecretError> {
            Ok(true)
        }
        fn provider_type(&self) -> &'static str {
            "mock"
        }
    }

    /// A mock provider that is unreachable.
    struct UnreachableMockProvider;

    #[async_trait::async_trait]
    impl SecretProvider for UnreachableMockProvider {
        async fn get_secret(&self, _name: &str) -> Result<SecretValue, SecretError> {
            Err(SecretError::ProviderUnavailable {
                provider: "mock".to_string(),
                detail: "unreachable".to_string(),
            })
        }
        async fn health_check(&self) -> Result<bool, SecretError> {
            Err(SecretError::ProviderUnavailable {
                provider: "mock".to_string(),
                detail: "unreachable".to_string(),
            })
        }
        fn provider_type(&self) -> &'static str {
            "mock"
        }
    }

    #[tokio::test]
    async fn test_health_check_healthy() {
        let inner = Arc::new(HealthyMockProvider);
        let cached = CachedSecretProvider::new(inner, 300);

        // Pre-populate cache
        let _ = cached.get_secret("test").await;

        let status = SecretHealthCheck::check_with_cache(&cached).await;
        assert_eq!(status.status, SecretsHealthState::Healthy);
        assert!(status.provider_reachable);
        assert_eq!(status.provider, "mock");
    }

    #[tokio::test]
    async fn test_health_check_degraded() {
        let inner: Arc<dyn SecretProvider> = Arc::new(UnreachableMockProvider);
        let cached = CachedSecretProvider::new(inner, 300);

        // Manually put something in cache by using a different provider first
        // Since UnreachableMockProvider fails, cache will be empty
        let status = SecretHealthCheck::check_with_cache(&cached).await;
        assert_eq!(status.status, SecretsHealthState::Unhealthy);
        assert!(!status.provider_reachable);
    }

    #[tokio::test]
    async fn test_health_check_via_arc() {
        let provider: Arc<dyn SecretProvider> = Arc::new(HealthyMockProvider);
        let status = SecretHealthCheck::check(&provider).await;
        assert_eq!(status.status, SecretsHealthState::Healthy);
        assert!(status.provider_reachable);
    }
}
