//! Internal PostgreSQL-backed dynamic secret provider (F120).
//!
//! This provider generates credentials internally without requiring
//! external secret managers. Credentials are stored in the database
//! and automatically expire based on TTL.

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::dynamic::{DynamicCredential, DynamicCredentialRequest, DynamicSecretProvider};
use crate::SecretError;

/// Internal provider that generates credentials without external dependencies.
///
/// This is the fallback provider when no external secret manager (`OpenBao`, Infisical)
/// is configured. It generates random usernames and passwords.
#[derive(Debug, Clone)]
pub struct InternalSecretProvider {
    /// Prefix for generated usernames.
    username_prefix: String,
}

impl Default for InternalSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl InternalSecretProvider {
    /// Create a new `InternalSecretProvider`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            username_prefix: "dynamic_".to_string(),
        }
    }

    /// Create with a custom username prefix.
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            username_prefix: prefix.into(),
        }
    }

    /// Generate a random username.
    fn generate_username(&self) -> String {
        let uuid = Uuid::new_v4().to_string().replace('-', "");
        format!("{}{}", self.username_prefix, &uuid[..12])
    }

    /// Generate a random password.
    fn generate_password(&self) -> String {
        Uuid::new_v4().to_string()
    }
}

#[async_trait]
impl DynamicSecretProvider for InternalSecretProvider {
    async fn generate_credentials(
        &self,
        request: &DynamicCredentialRequest,
    ) -> Result<DynamicCredential, SecretError> {
        let username = self.generate_username();
        let password = self.generate_password();

        // Generate lease_id for tracking (internal format: tenant:agent:type:uuid)
        let lease_id = format!(
            "{}:{}:{}:{}",
            request.tenant_id,
            request.agent_id,
            request.secret_type,
            Uuid::new_v4()
        );

        let credentials = serde_json::json!({
            "username": username,
            "password": password,
            "generated_at": Utc::now().to_rfc3339(),
            "secret_type": request.secret_type,
            "expires_in_seconds": request.ttl_seconds,
        });

        Ok(DynamicCredential {
            credentials,
            lease_id: Some(lease_id),
            ttl_seconds: request.ttl_seconds,
        })
    }

    async fn revoke_credentials(&self, lease_id: &str) -> Result<(), SecretError> {
        // Internal provider doesn't actually create external resources,
        // so revocation is a no-op. The credential record in the database
        // tracks the revocation status.
        tracing::info!(
            lease_id = lease_id,
            "Internal provider: credential revocation acknowledged (no external resources to revoke)"
        );
        Ok(())
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        // Internal provider is always healthy as it doesn't depend on external services
        Ok(true)
    }

    fn provider_type(&self) -> &'static str {
        "internal"
    }

    fn supports_revocation(&self) -> bool {
        // We track revocation in the database but don't have external resources to revoke
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_credentials() {
        let provider = InternalSecretProvider::new();
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: 300,
            role: None,
            context: None,
        };

        let result = provider.generate_credentials(&request).await.unwrap();

        assert!(result.credentials.get("username").is_some());
        assert!(result.credentials.get("password").is_some());
        assert!(result.lease_id.is_some());
        assert_eq!(result.ttl_seconds, 300);
    }

    #[tokio::test]
    async fn test_username_format() {
        let provider = InternalSecretProvider::new();
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test".to_string(),
            ttl_seconds: 60,
            role: None,
            context: None,
        };

        let result = provider.generate_credentials(&request).await.unwrap();
        let username = result.credentials["username"].as_str().unwrap();

        assert!(username.starts_with("dynamic_"));
        assert_eq!(username.len(), 20); // "dynamic_" (8) + 12 hex chars
    }

    #[tokio::test]
    async fn test_custom_prefix() {
        let provider = InternalSecretProvider::with_prefix("svc_");
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "test".to_string(),
            ttl_seconds: 60,
            role: None,
            context: None,
        };

        let result = provider.generate_credentials(&request).await.unwrap();
        let username = result.credentials["username"].as_str().unwrap();

        assert!(username.starts_with("svc_"));
    }

    #[tokio::test]
    async fn test_health_check_always_healthy() {
        let provider = InternalSecretProvider::new();
        let result = provider.health_check().await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_revoke_credentials_succeeds() {
        let provider = InternalSecretProvider::new();
        let result = provider.revoke_credentials("test-lease-id").await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_provider_type() {
        let provider = InternalSecretProvider::new();
        assert_eq!(provider.provider_type(), "internal");
    }

    #[test]
    fn test_supports_revocation() {
        let provider = InternalSecretProvider::new();
        assert!(provider.supports_revocation());
    }

    #[tokio::test]
    async fn test_lease_id_format() {
        let provider = InternalSecretProvider::new();
        let tenant_id = Uuid::new_v4();
        let agent_id = Uuid::new_v4();
        let request = DynamicCredentialRequest {
            tenant_id,
            agent_id,
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: 300,
            role: None,
            context: None,
        };

        let result = provider.generate_credentials(&request).await.unwrap();
        let lease_id = result.lease_id.unwrap();

        // Lease ID format: tenant_id:agent_id:secret_type:uuid
        let parts: Vec<&str> = lease_id.split(':').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], tenant_id.to_string());
        assert_eq!(parts[1], agent_id.to_string());
        assert_eq!(parts[2], "postgres-readonly");
    }
}
