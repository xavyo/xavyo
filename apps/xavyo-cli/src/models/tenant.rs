//! Tenant-related models
//!
//! Models for displaying tenant information from the current session.

use serde::{Deserialize, Serialize};

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
}
