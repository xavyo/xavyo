//! Dynamic Secret Provider trait for just-in-time credential generation (F120).
//!
//! This trait defines the interface for providers that can generate
//! ephemeral credentials on demand (database users, API keys, cloud tokens).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SecretError;

/// Result of generating dynamic credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCredential {
    /// The generated credentials as a JSON object.
    /// Structure depends on the secret type (e.g., {"username": "...", "password": "..."}).
    pub credentials: serde_json::Value,

    /// Provider-specific lease ID for tracking/revocation.
    /// For OpenBao/Vault, this is the `lease_id`.
    /// For internal provider, this is the credential record ID.
    pub lease_id: Option<String>,

    /// Time-to-live in seconds.
    pub ttl_seconds: i32,
}

/// Request for generating dynamic credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicCredentialRequest {
    /// Tenant ID for multi-tenant isolation.
    pub tenant_id: Uuid,

    /// Agent ID requesting the credentials.
    pub agent_id: Uuid,

    /// The secret type (e.g., "postgres-readonly", "api-key").
    pub secret_type: String,

    /// Requested TTL in seconds.
    pub ttl_seconds: i32,

    /// Optional role name within the secret type.
    pub role: Option<String>,

    /// Additional context for the credential generation.
    pub context: Option<serde_json::Value>,
}

/// Trait for providers that can generate dynamic/ephemeral credentials.
///
/// Unlike static `SecretProvider` which retrieves existing secrets,
/// `DynamicSecretProvider` creates new credentials on demand.
#[async_trait]
pub trait DynamicSecretProvider: Send + Sync {
    /// Generate new dynamic credentials.
    ///
    /// The credentials are created on demand with the specified TTL.
    /// For external providers (`OpenBao`, Infisical), this creates
    /// temporary database users or API keys.
    async fn generate_credentials(
        &self,
        request: &DynamicCredentialRequest,
    ) -> Result<DynamicCredential, SecretError>;

    /// Revoke credentials before their TTL expires.
    ///
    /// This is a best-effort operation - if the provider doesn't support
    /// revocation, it may return Ok without doing anything.
    async fn revoke_credentials(&self, lease_id: &str) -> Result<(), SecretError>;

    /// Check if the provider is healthy and can generate credentials.
    async fn health_check(&self) -> Result<bool, SecretError>;

    /// Return the provider type name.
    fn provider_type(&self) -> &'static str;

    /// Return whether this provider supports credential revocation.
    fn supports_revocation(&self) -> bool {
        true
    }
}

/// Provider type enumeration for dynamic secret providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DynamicProviderType {
    /// `OpenBao` (Vault API compatible, open source).
    OpenBao,
    /// Infisical (open source secrets manager).
    Infisical,
    /// Internal PostgreSQL-backed provider.
    Internal,
}

impl std::fmt::Display for DynamicProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DynamicProviderType::OpenBao => write!(f, "openbao"),
            DynamicProviderType::Infisical => write!(f, "infisical"),
            DynamicProviderType::Internal => write!(f, "internal"),
        }
    }
}

impl std::str::FromStr for DynamicProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openbao" => Ok(DynamicProviderType::OpenBao),
            "infisical" => Ok(DynamicProviderType::Infisical),
            "internal" => Ok(DynamicProviderType::Internal),
            _ => Err(format!("Unknown dynamic provider type: {s}")),
        }
    }
}

/// Generated credentials must include a lease id so they can be revoked.
#[cfg(feature = "vault-provider")]
pub(crate) fn require_lease_id(
    provider: &str,
    name: &str,
    lease_id: Option<String>,
) -> Result<String, SecretError> {
    match lease_id {
        Some(id) if !id.trim().is_empty() => Ok(id),
        _ => Err(SecretError::InvalidValue {
            name: name.to_string(),
            detail: format!("{provider} credential response missing lease_id"),
        }),
    }
}

/// Token or lease TTL from a provider response. Missing or non-positive
/// values must not be treated as a default lifetime.
#[cfg(feature = "vault-provider")]
pub(crate) fn require_positive_ttl(
    provider: &str,
    field: &str,
    ttl: Option<i64>,
) -> Result<i64, SecretError> {
    match ttl {
        Some(n) if n > 0 => Ok(n),
        _ => Err(SecretError::InvalidValue {
            name: field.to_string(),
            detail: format!("{provider} response missing a positive {field}"),
        }),
    }
}

/// Lease revoke HTTP status. 404 means already gone; other errors must not
/// look like a successful revocation.
#[cfg(feature = "vault-provider")]
pub(crate) fn lease_revocation_http_status(
    provider: &str,
    lease_id: &str,
    status: u16,
    body: &str,
) -> Result<(), SecretError> {
    if (200..300).contains(&status) || status == 404 {
        Ok(())
    } else {
        Err(SecretError::ProviderUnavailable {
            provider: provider.to_string(),
            detail: format!("Failed to revoke lease '{lease_id}': HTTP {status}: {body}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_provider_type_display() {
        assert_eq!(DynamicProviderType::OpenBao.to_string(), "openbao");
        assert_eq!(DynamicProviderType::Infisical.to_string(), "infisical");
        assert_eq!(DynamicProviderType::Internal.to_string(), "internal");
    }

    #[test]
    fn test_dynamic_provider_type_from_str() {
        assert_eq!(
            "openbao".parse::<DynamicProviderType>().unwrap(),
            DynamicProviderType::OpenBao
        );
        assert_eq!(
            "infisical".parse::<DynamicProviderType>().unwrap(),
            DynamicProviderType::Infisical
        );
        assert_eq!(
            "internal".parse::<DynamicProviderType>().unwrap(),
            DynamicProviderType::Internal
        );
        assert!("invalid".parse::<DynamicProviderType>().is_err());
    }

    #[test]
    fn test_dynamic_credential_serialization() {
        let cred = DynamicCredential {
            credentials: serde_json::json!({
                "username": "dynamic_abc123",
                "password": "secret123"
            }),
            lease_id: Some("lease-456".to_string()),
            ttl_seconds: 300,
        };

        let json = serde_json::to_string(&cred).unwrap();
        assert!(json.contains("dynamic_abc123"));
        assert!(json.contains("lease-456"));
        assert!(json.contains("300"));
    }

    #[test]
    #[cfg(feature = "vault-provider")]
    fn require_lease_id_does_not_succeed_when_missing() {
        assert_eq!(
            require_lease_id("openbao", "role", Some("lease-1".into())).unwrap(),
            "lease-1"
        );
        assert!(require_lease_id("openbao", "role", None).is_err());
        assert!(require_lease_id("infisical", "secret", Some("".into())).is_err());
        assert!(require_lease_id("infisical", "secret", Some("   ".into())).is_err());
        assert_eq!(
            require_positive_ttl("vault", "lease_duration", Some(3600)).unwrap(),
            3600
        );
        assert!(require_positive_ttl("vault", "lease_duration", None).is_err());
        assert!(require_positive_ttl("openbao", "lease_duration", Some(0)).is_err());
        assert!(require_positive_ttl("infisical", "expiresIn", Some(-1)).is_err());
    }

    #[test]
    #[cfg(feature = "vault-provider")]
    fn lease_revocation_http_status_does_not_succeed_on_error() {
        assert!(lease_revocation_http_status("infisical", "l1", 200, "").is_ok());
        assert!(lease_revocation_http_status("openbao", "l1", 204, "").is_ok());
        assert!(lease_revocation_http_status("infisical", "l1", 404, "gone").is_ok());
        let err = lease_revocation_http_status("openbao", "l1", 500, "boom").unwrap_err();
        assert!(
            matches!(err, SecretError::ProviderUnavailable { ref provider, ref detail }
                if provider == "openbao" && detail.contains("500")),
            "got {err:?}"
        );
        assert!(lease_revocation_http_status("infisical", "l1", 401, "denied").is_err());
    }

    #[test]
    fn test_dynamic_credential_request_serialization() {
        let request = DynamicCredentialRequest {
            tenant_id: Uuid::new_v4(),
            agent_id: Uuid::new_v4(),
            secret_type: "postgres-readonly".to_string(),
            ttl_seconds: 300,
            role: Some("reader".to_string()),
            context: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("postgres-readonly"));
        assert!(json.contains("reader"));
    }
}
