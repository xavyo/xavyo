//! Provisioning request and response DTOs.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Context for provisioning operations, capturing request metadata for audit logging.
#[derive(Debug, Clone)]
pub struct ProvisionContext {
    /// System tenant ID (where the provisioning request originated).
    pub system_tenant_id: Uuid,
    /// User ID who initiated the provisioning (from JWT claims).
    pub admin_user_id: Uuid,
    /// Client IP address (from X-Forwarded-For, X-Real-IP, or peer).
    pub ip_address: Option<String>,
    /// User agent string from request headers.
    pub user_agent: Option<String>,
}

/// Request body for tenant provisioning.
///
/// This is used by authenticated system tenant users to create their own
/// isolated tenant with all necessary resources.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ProvisionTenantRequest {
    /// Human-readable organization name (1-100 characters).
    ///
    /// This will be used as the tenant's display name and to generate
    /// a unique slug. Allowed characters: alphanumeric, spaces, hyphens.
    #[schema(example = "Acme Corp")]
    pub organization_name: String,
}

/// Response from successful tenant provisioning.
///
/// Contains all the credentials and details needed to start using the new tenant.
/// **Important**: The `api_key` is shown only once and cannot be retrieved later.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProvisionTenantResponse {
    /// Created tenant details.
    pub tenant: TenantInfo,

    /// Created admin user details.
    pub admin: AdminInfo,

    /// OAuth client credentials for the default client.
    pub oauth_client: OAuthClientInfo,

    /// API endpoints for this tenant.
    pub endpoints: EndpointInfo,

    /// Suggested next steps for getting started.
    pub next_steps: Vec<String>,
}

/// Basic tenant information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantInfo {
    /// Unique tenant identifier.
    #[schema(example = "550e8400-e29b-41d4-a716-446655440000")]
    pub id: Uuid,

    /// URL-safe tenant slug.
    #[schema(example = "acme-corp")]
    pub slug: String,

    /// Human-readable tenant name.
    #[schema(example = "Acme Corp")]
    pub name: String,
}

/// Admin user information from provisioning.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminInfo {
    /// Admin user identifier.
    #[schema(example = "550e8400-e29b-41d4-a716-446655440001")]
    pub id: Uuid,

    /// Admin email address (from JWT claims).
    #[schema(example = "admin@acme.com")]
    pub email: String,

    /// API key for programmatic access.
    ///
    /// **WARNING**: This key is shown only once. Store it securely.
    /// The key is stored as a hash and cannot be retrieved later.
    #[schema(example = "xavyo_sk_live_a1b2c3d4e5f6789012345678901234567890")]
    pub api_key: String,
}

/// OAuth client credentials.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OAuthClientInfo {
    /// OAuth client identifier.
    #[schema(example = "client_a1b2c3d4e5f6")]
    pub client_id: String,

    /// OAuth client secret.
    ///
    /// **WARNING**: This secret is shown only once. Store it securely.
    #[schema(example = "secret_x9y8z7w6v5u4t3s2r1q0")]
    pub client_secret: String,
}

/// API endpoint information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EndpointInfo {
    /// Base API URL.
    #[schema(example = "https://api.xavyo.net")]
    pub api: String,

    /// Authentication URL.
    #[schema(example = "https://auth.xavyo.net")]
    pub auth: String,
}

impl ProvisionTenantRequest {
    /// Validate the organization name.
    ///
    /// Returns an error message if validation fails, None if valid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        let name = self.organization_name.trim();

        if name.is_empty() {
            return Some("organization_name is required".to_string());
        }

        if name.len() > 100 {
            return Some("organization_name must be 100 characters or less".to_string());
        }

        // Check for valid characters: alphanumeric, spaces, hyphens, underscores
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_')
        {
            return Some(
                "organization_name may only contain alphanumeric characters, spaces, hyphens, and underscores"
                    .to_string(),
            );
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_name() {
        let req = ProvisionTenantRequest {
            organization_name: "Acme Corp".to_string(),
        };
        assert!(req.validate().is_none());
    }

    #[test]
    fn test_validate_empty_name() {
        let req = ProvisionTenantRequest {
            organization_name: String::new(),
        };
        assert!(req.validate().is_some());
        assert!(req.validate().unwrap().contains("required"));
    }

    #[test]
    fn test_validate_whitespace_only() {
        let req = ProvisionTenantRequest {
            organization_name: "   ".to_string(),
        };
        assert!(req.validate().is_some());
    }

    #[test]
    fn test_validate_too_long() {
        let req = ProvisionTenantRequest {
            organization_name: "a".repeat(101),
        };
        assert!(req.validate().is_some());
        assert!(req.validate().unwrap().contains("100"));
    }

    #[test]
    fn test_validate_special_chars() {
        let req = ProvisionTenantRequest {
            organization_name: "Acme<script>".to_string(),
        };
        assert!(req.validate().is_some());
        assert!(req.validate().unwrap().contains("alphanumeric"));
    }

    #[test]
    fn test_validate_with_hyphens_underscores() {
        let req = ProvisionTenantRequest {
            organization_name: "Acme-Corp_Inc".to_string(),
        };
        assert!(req.validate().is_none());
    }
}
