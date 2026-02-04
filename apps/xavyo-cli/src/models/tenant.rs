//! Tenant-related models for multi-tenant switching
//!
//! Models for listing, switching, and displaying tenant information.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User's role within a tenant
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Owner,
    Admin,
    #[default]
    Member,
    Viewer,
}

impl std::fmt::Display for TenantRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TenantRole::Owner => write!(f, "owner"),
            TenantRole::Admin => write!(f, "admin"),
            TenantRole::Member => write!(f, "member"),
            TenantRole::Viewer => write!(f, "viewer"),
        }
    }
}

/// Information about a tenant the user has access to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantInfo {
    /// Unique tenant identifier
    pub id: Uuid,

    /// Display name (e.g., "Acme Corporation")
    pub name: String,

    /// URL-safe identifier (e.g., "acme-corp")
    pub slug: String,

    /// User's role within this tenant
    pub role: TenantRole,

    /// True if this is the currently active tenant context
    #[serde(default)]
    pub is_current: bool,
}

/// Response from listing tenants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantListResponse {
    /// List of accessible tenants
    pub tenants: Vec<TenantInfo>,

    /// Total number of tenants
    pub total: u32,

    /// True if more pages are available
    pub has_more: bool,

    /// Pagination cursor for next page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Request to switch active tenant
#[derive(Debug, Serialize)]
pub struct TenantSwitchRequest {
    /// Target tenant ID to switch to
    pub tenant_id: Uuid,
}

/// Response from switching tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSwitchResponse {
    /// Switched tenant ID
    pub tenant_id: Uuid,

    /// Switched tenant name
    pub tenant_name: String,

    /// Switched tenant slug
    pub tenant_slug: String,

    /// User's role in the tenant
    pub role: TenantRole,
}

/// JSON output for tenant current command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantCurrentOutput {
    /// Current tenant ID (null if none)
    pub tenant_id: Option<String>,

    /// Current tenant name (null if none)
    pub tenant_name: Option<String>,

    /// Current tenant slug (null if none)
    pub tenant_slug: Option<String>,

    /// User's role (null if no tenant)
    pub role: Option<String>,
}

/// JSON output for tenant switch command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSwitchOutput {
    /// Tenant ID after switch
    pub tenant_id: String,

    /// Tenant name after switch
    pub tenant_name: String,

    /// Tenant slug after switch
    pub tenant_slug: String,

    /// User's role in the tenant
    pub role: String,

    /// Whether a switch actually occurred (false if already on tenant)
    pub switched: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_role_display() {
        assert_eq!(TenantRole::Owner.to_string(), "owner");
        assert_eq!(TenantRole::Admin.to_string(), "admin");
        assert_eq!(TenantRole::Member.to_string(), "member");
        assert_eq!(TenantRole::Viewer.to_string(), "viewer");
    }

    #[test]
    fn test_tenant_role_default() {
        let role: TenantRole = Default::default();
        assert_eq!(role, TenantRole::Member);
    }

    #[test]
    fn test_tenant_role_serialization() {
        let role = TenantRole::Admin;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"admin\"");

        let deserialized: TenantRole = serde_json::from_str("\"owner\"").unwrap();
        assert_eq!(deserialized, TenantRole::Owner);
    }

    #[test]
    fn test_tenant_info_serialization() {
        let info = TenantInfo {
            id: Uuid::nil(),
            name: "Test Org".to_string(),
            slug: "test-org".to_string(),
            role: TenantRole::Admin,
            is_current: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"name\":\"Test Org\""));
        assert!(json.contains("\"slug\":\"test-org\""));
        assert!(json.contains("\"role\":\"admin\""));
        assert!(json.contains("\"is_current\":true"));
    }

    #[test]
    fn test_tenant_list_response_serialization() {
        let response = TenantListResponse {
            tenants: vec![TenantInfo {
                id: Uuid::nil(),
                name: "Test".to_string(),
                slug: "test".to_string(),
                role: TenantRole::Member,
                is_current: false,
            }],
            total: 1,
            has_more: false,
            next_cursor: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":1"));
        assert!(json.contains("\"has_more\":false"));
        // next_cursor should be skipped when None
        assert!(!json.contains("next_cursor"));
    }

    #[test]
    fn test_tenant_switch_request_serialization() {
        let request = TenantSwitchRequest {
            tenant_id: Uuid::nil(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("tenant_id"));
    }

    #[test]
    fn test_tenant_switch_response_deserialization() {
        let json = r#"{
            "tenant_id": "00000000-0000-0000-0000-000000000000",
            "tenant_name": "Test Org",
            "tenant_slug": "test-org",
            "role": "admin"
        }"#;

        let response: TenantSwitchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.tenant_name, "Test Org");
        assert_eq!(response.tenant_slug, "test-org");
        assert_eq!(response.role, TenantRole::Admin);
    }
}
