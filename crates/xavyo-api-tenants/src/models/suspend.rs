//! DTOs for tenant suspension operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request to suspend a tenant.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SuspendTenantRequest {
    /// Reason for suspension (admin-facing, not shown to end users).
    #[schema(example = "Violation of terms of service")]
    pub reason: String,
}

impl SuspendTenantRequest {
    /// Validate the request.
    #[must_use] 
    pub fn validate(&self) -> Option<String> {
        if self.reason.trim().is_empty() {
            return Some("reason is required".to_string());
        }
        if self.reason.len() > 500 {
            return Some("reason must be 500 characters or less".to_string());
        }
        None
    }
}

/// Response after suspending a tenant.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SuspendTenantResponse {
    /// ID of the suspended tenant.
    pub tenant_id: Uuid,

    /// Timestamp when suspension took effect.
    pub suspended_at: DateTime<Utc>,

    /// Reason for suspension.
    pub suspension_reason: String,
}

/// Response after reactivating a tenant.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReactivateTenantResponse {
    /// ID of the reactivated tenant.
    pub tenant_id: Uuid,

    /// Timestamp when reactivation occurred.
    pub reactivated_at: DateTime<Utc>,
}

/// Summary of a tenant's status (for admin view).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TenantStatusResponse {
    /// Unique tenant identifier.
    pub id: Uuid,

    /// Tenant name.
    pub name: String,

    /// Tenant slug.
    pub slug: String,

    /// Whether the tenant is currently suspended.
    pub is_suspended: bool,

    /// Suspension timestamp (if suspended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<DateTime<Utc>>,

    /// Suspension reason (if suspended).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<String>,

    /// Whether the tenant is soft deleted.
    pub is_deleted: bool,

    /// Deletion timestamp (if deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    /// Deletion reason (if deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_reason: Option<String>,

    /// When permanent deletion is scheduled (if deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_purge_at: Option<DateTime<Utc>>,

    /// When the tenant was created.
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_suspend_request_valid() {
        let req = SuspendTenantRequest {
            reason: "Terms of service violation".to_string(),
        };
        assert!(req.validate().is_none());
    }

    #[test]
    fn test_validate_suspend_request_empty_reason() {
        let req = SuspendTenantRequest {
            reason: String::new(),
        };
        assert!(req.validate().is_some());
        assert!(req.validate().unwrap().contains("required"));
    }

    #[test]
    fn test_validate_suspend_request_whitespace_only() {
        let req = SuspendTenantRequest {
            reason: "   ".to_string(),
        };
        assert!(req.validate().is_some());
    }

    #[test]
    fn test_validate_suspend_request_too_long() {
        let req = SuspendTenantRequest {
            reason: "a".repeat(501),
        };
        assert!(req.validate().is_some());
        assert!(req.validate().unwrap().contains("500"));
    }
}
