//! Tenant provisioning models

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Request to provision a new tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRequest {
    /// Organization name for the new tenant
    pub organization_name: String,
}

impl ProvisionRequest {
    /// Create a new provision request
    pub fn new(organization_name: String) -> Self {
        Self { organization_name }
    }

    /// Validate the organization name
    ///
    /// Rules:
    /// - 1-100 characters
    /// - Alphanumeric, spaces, hyphens, underscores
    /// - No leading/trailing whitespace
    pub fn validate(&self) -> Result<(), &'static str> {
        let name = &self.organization_name;

        // Check length
        if name.is_empty() {
            return Err("Organization name cannot be empty");
        }
        if name.len() > 100 {
            return Err("Organization name cannot exceed 100 characters");
        }

        // Check for leading/trailing whitespace
        if name != name.trim() {
            return Err("Organization name cannot have leading or trailing whitespace");
        }

        // Check allowed characters
        let is_valid = name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_');

        if !is_valid {
            return Err("Organization name can only contain letters, numbers, spaces, hyphens, and underscores");
        }

        Ok(())
    }
}

/// Response from tenant provisioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionResponse {
    /// Tenant information
    pub tenant: TenantInfo,

    /// Admin user information
    pub admin: AdminInfo,

    /// OAuth client information
    pub oauth_client: OAuthClientInfo,

    /// API endpoints
    pub endpoints: EndpointInfo,

    /// Suggested next steps
    pub next_steps: Vec<String>,
}

/// Tenant information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInfo {
    /// Tenant ID
    pub id: Uuid,

    /// Tenant slug
    pub slug: String,

    /// Tenant name
    pub name: String,
}

/// Admin user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInfo {
    /// Admin user ID
    pub id: Uuid,

    /// Admin email
    pub email: String,

    /// API key (shown once)
    pub api_key: String,
}

/// OAuth client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClientInfo {
    /// Client ID
    pub client_id: String,

    /// Client secret (shown once)
    pub client_secret: String,
}

/// API endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// API endpoint URL
    pub api: String,

    /// Auth endpoint URL
    pub auth: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provision_request_validation_valid() {
        let request = ProvisionRequest::new("Acme Corp".to_string());
        assert!(request.validate().is_ok());

        let request = ProvisionRequest::new("My-Company_123".to_string());
        assert!(request.validate().is_ok());

        let request = ProvisionRequest::new("A".to_string());
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_provision_request_validation_empty() {
        let request = ProvisionRequest::new(String::new());
        assert_eq!(request.validate(), Err("Organization name cannot be empty"));
    }

    #[test]
    fn test_provision_request_validation_too_long() {
        let request = ProvisionRequest::new("a".repeat(101));
        assert_eq!(
            request.validate(),
            Err("Organization name cannot exceed 100 characters")
        );
    }

    #[test]
    fn test_provision_request_validation_whitespace() {
        let request = ProvisionRequest::new(" Acme Corp".to_string());
        assert_eq!(
            request.validate(),
            Err("Organization name cannot have leading or trailing whitespace")
        );

        let request = ProvisionRequest::new("Acme Corp ".to_string());
        assert_eq!(
            request.validate(),
            Err("Organization name cannot have leading or trailing whitespace")
        );
    }

    #[test]
    fn test_provision_request_validation_invalid_chars() {
        let request = ProvisionRequest::new("Acme@Corp".to_string());
        assert_eq!(
            request.validate(),
            Err("Organization name can only contain letters, numbers, spaces, hyphens, and underscores")
        );

        let request = ProvisionRequest::new("Acme/Corp".to_string());
        assert_eq!(
            request.validate(),
            Err("Organization name can only contain letters, numbers, spaces, hyphens, and underscores")
        );
    }

    #[test]
    fn test_provision_response_deserialization() {
        let json = r#"{
            "tenant": {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "slug": "acme-corp",
                "name": "Acme Corp"
            },
            "admin": {
                "id": "550e8400-e29b-41d4-a716-446655440002",
                "email": "admin@acme.com",
                "api_key": "xavyo_sk_live_abc123"
            },
            "oauth_client": {
                "client_id": "acme-corp-default",
                "client_secret": "cs_live_xyz789"
            },
            "endpoints": {
                "api": "https://api.xavyo.net",
                "auth": "https://auth.xavyo.net"
            },
            "next_steps": [
                "Save your credentials",
                "Run 'xavyo status' to verify"
            ]
        }"#;

        let response: ProvisionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.tenant.name, "Acme Corp");
        assert_eq!(response.tenant.slug, "acme-corp");
        assert_eq!(response.admin.email, "admin@acme.com");
        assert_eq!(response.next_steps.len(), 2);
    }
}
