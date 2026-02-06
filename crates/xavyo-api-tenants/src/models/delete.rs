//! Request and response models for tenant soft delete API.
//!
//! F-DELETE: Provides soft delete mechanism with 30-day recovery window.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request to soft delete a tenant.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct DeleteTenantRequest {
    /// Reason for deletion (for admin reference).
    #[schema(example = "Customer requested account closure")]
    pub reason: String,

    /// If true, skip the 30-day grace period (not recommended).
    /// Defaults to false.
    #[serde(default)]
    #[schema(default = false)]
    pub immediate: bool,
}

impl DeleteTenantRequest {
    /// Validate the request.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        if self.reason.trim().is_empty() {
            return Some("Deletion reason is required".to_string());
        }
        if self.reason.len() > 1000 {
            return Some("Deletion reason must be at most 1000 characters".to_string());
        }
        None
    }
}

/// Response after soft deleting a tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeleteTenantResponse {
    /// The deleted tenant's ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// When the tenant was deleted.
    pub deleted_at: DateTime<Utc>,

    /// When permanent deletion will occur (if not restored).
    pub scheduled_purge_at: DateTime<Utc>,

    /// The deletion reason provided.
    pub reason: String,
}

/// Response after restoring a soft-deleted tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RestoreTenantResponse {
    /// The restored tenant's ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// When the tenant was restored.
    pub restored_at: DateTime<Utc>,
}

/// Information about a deleted tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeletedTenantInfo {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub id: Uuid,

    /// Tenant name.
    #[schema(example = "Acme Corp")]
    pub name: String,

    /// Tenant slug.
    #[schema(example = "acme-corp")]
    pub slug: String,

    /// When the tenant was deleted.
    pub deleted_at: DateTime<Utc>,

    /// When permanent deletion will occur.
    pub scheduled_purge_at: DateTime<Utc>,

    /// Reason for deletion.
    #[schema(example = "Customer requested account closure")]
    pub deletion_reason: Option<String>,
}

/// Response listing all soft-deleted tenants.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeletedTenantListResponse {
    /// List of deleted tenants.
    pub deleted_tenants: Vec<DeletedTenantInfo>,

    /// Total count of deleted tenants.
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_request_validation_empty_reason() {
        let request = DeleteTenantRequest {
            reason: String::new(),
            immediate: false,
        };
        assert_eq!(
            request.validate(),
            Some("Deletion reason is required".to_string())
        );
    }

    #[test]
    fn test_delete_request_validation_whitespace_reason() {
        let request = DeleteTenantRequest {
            reason: "   ".to_string(),
            immediate: false,
        };
        assert_eq!(
            request.validate(),
            Some("Deletion reason is required".to_string())
        );
    }

    #[test]
    fn test_delete_request_validation_too_long() {
        let request = DeleteTenantRequest {
            reason: "x".repeat(1001),
            immediate: false,
        };
        assert_eq!(
            request.validate(),
            Some("Deletion reason must be at most 1000 characters".to_string())
        );
    }

    #[test]
    fn test_delete_request_validation_valid() {
        let request = DeleteTenantRequest {
            reason: "Customer requested account closure".to_string(),
            immediate: false,
        };
        assert_eq!(request.validate(), None);
    }

    #[test]
    fn test_delete_request_default() {
        let request = DeleteTenantRequest::default();
        assert!(request.reason.is_empty());
        assert!(!request.immediate);
    }

    #[test]
    fn test_delete_response_serialization() {
        let response = DeleteTenantResponse {
            tenant_id: Uuid::new_v4(),
            deleted_at: Utc::now(),
            scheduled_purge_at: Utc::now(),
            reason: "Test deletion".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("deleted_at"));
        assert!(json.contains("scheduled_purge_at"));
        assert!(json.contains("Test deletion"));
    }

    #[test]
    fn test_restore_response_serialization() {
        let response = RestoreTenantResponse {
            tenant_id: Uuid::new_v4(),
            restored_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("restored_at"));
    }

    #[test]
    fn test_deleted_tenant_info_serialization() {
        let info = DeletedTenantInfo {
            id: Uuid::new_v4(),
            name: "Acme Corp".to_string(),
            slug: "acme-corp".to_string(),
            deleted_at: Utc::now(),
            scheduled_purge_at: Utc::now(),
            deletion_reason: Some("Customer requested".to_string()),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Acme Corp"));
        assert!(json.contains("acme-corp"));
        assert!(json.contains("Customer requested"));
    }

    #[test]
    fn test_deleted_tenant_list_response_serialization() {
        let response = DeletedTenantListResponse {
            deleted_tenants: vec![
                DeletedTenantInfo {
                    id: Uuid::new_v4(),
                    name: "Tenant 1".to_string(),
                    slug: "tenant-1".to_string(),
                    deleted_at: Utc::now(),
                    scheduled_purge_at: Utc::now(),
                    deletion_reason: Some("Reason 1".to_string()),
                },
                DeletedTenantInfo {
                    id: Uuid::new_v4(),
                    name: "Tenant 2".to_string(),
                    slug: "tenant-2".to_string(),
                    deleted_at: Utc::now(),
                    scheduled_purge_at: Utc::now(),
                    deletion_reason: None,
                },
            ],
            total: 2,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":2"));
        assert!(json.contains("Tenant 1"));
        assert!(json.contains("Tenant 2"));
    }

    #[test]
    fn test_deleted_tenant_list_response_empty() {
        let response = DeletedTenantListResponse {
            deleted_tenants: vec![],
            total: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"deleted_tenants\":[]"));
    }
}
