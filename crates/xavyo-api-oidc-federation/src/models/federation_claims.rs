//! Federation-specific claims for tokens issued after OIDC federation.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Optional claims added to tokens for federated users.
///
/// These claims capture the federation context and can be used by
/// downstream applications to identify the source of authentication
/// and apply appropriate policies.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct FederationClaims {
    /// Source IdP identifier (UUID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_id: Option<Uuid>,

    /// IdP issuer URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_issuer: Option<String>,

    /// Timestamp when federation occurred (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_at: Option<i64>,

    /// Original subject from IdP (before mapping).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federated_sub: Option<String>,
}

impl FederationClaims {
    /// Create a new builder for federation claims.
    pub fn builder() -> FederationClaimsBuilder {
        FederationClaimsBuilder::default()
    }

    /// Check if any federation claims are set.
    pub fn is_empty(&self) -> bool {
        self.idp_id.is_none()
            && self.idp_issuer.is_none()
            && self.federated_at.is_none()
            && self.federated_sub.is_none()
    }
}

/// Builder for FederationClaims.
#[derive(Debug, Default)]
pub struct FederationClaimsBuilder {
    idp_id: Option<Uuid>,
    idp_issuer: Option<String>,
    federated_at: Option<i64>,
    federated_sub: Option<String>,
}

impl FederationClaimsBuilder {
    /// Set the IdP identifier.
    pub fn idp_id(mut self, id: Uuid) -> Self {
        self.idp_id = Some(id);
        self
    }

    /// Set the IdP issuer URL.
    pub fn idp_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.idp_issuer = Some(issuer.into());
        self
    }

    /// Set the federation timestamp.
    pub fn federated_at(mut self, timestamp: i64) -> Self {
        self.federated_at = Some(timestamp);
        self
    }

    /// Set the federation timestamp to now.
    pub fn federated_now(mut self) -> Self {
        self.federated_at = Some(chrono::Utc::now().timestamp());
        self
    }

    /// Set the original subject from the IdP.
    pub fn federated_sub(mut self, sub: impl Into<String>) -> Self {
        self.federated_sub = Some(sub.into());
        self
    }

    /// Build the federation claims.
    pub fn build(self) -> FederationClaims {
        FederationClaims {
            idp_id: self.idp_id,
            idp_issuer: self.idp_issuer,
            federated_at: self.federated_at,
            federated_sub: self.federated_sub,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_claims_builder() {
        let idp_id = Uuid::new_v4();
        let claims = FederationClaims::builder()
            .idp_id(idp_id)
            .idp_issuer("https://idp.example.com")
            .federated_sub("user123")
            .federated_now()
            .build();

        assert_eq!(claims.idp_id, Some(idp_id));
        assert_eq!(
            claims.idp_issuer,
            Some("https://idp.example.com".to_string())
        );
        assert_eq!(claims.federated_sub, Some("user123".to_string()));
        assert!(claims.federated_at.is_some());
    }

    #[test]
    fn test_federation_claims_is_empty() {
        let empty = FederationClaims::default();
        assert!(empty.is_empty());

        let non_empty = FederationClaims::builder().idp_id(Uuid::new_v4()).build();
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_federation_claims_serialization() {
        let claims = FederationClaims::builder()
            .idp_issuer("https://idp.example.com")
            .build();

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("idp_issuer"));
        // Empty fields should not be serialized
        assert!(!json.contains("idp_id"));
    }
}
