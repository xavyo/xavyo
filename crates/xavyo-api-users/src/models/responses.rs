//! Response models for the User Management API.

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Lifecycle state information for a user.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LifecycleStateInfo {
    /// Unique identifier for the lifecycle state.
    pub id: Uuid,

    /// Name of the lifecycle state (e.g., Draft, Active, Suspended).
    pub name: String,

    /// Whether this is a terminal state.
    pub is_terminal: bool,
}

/// User information returned in API responses.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserResponse {
    /// Unique identifier for the user.
    pub id: Uuid,

    /// User's email address.
    pub email: String,

    /// Whether the account is active.
    pub is_active: bool,

    /// Whether the email has been verified.
    pub email_verified: bool,

    /// Roles assigned to the user.
    pub roles: Vec<String>,

    /// When the user was created.
    pub created_at: DateTime<Utc>,

    /// When the user was last updated.
    pub updated_at: DateTime<Utc>,

    /// Current lifecycle state of the user (if governed by lifecycle policies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_state: Option<LifecycleStateInfo>,

    /// Custom attributes (F070).
    pub custom_attributes: serde_json::Value,
}

/// Response for listing users with pagination.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserListResponse {
    /// List of users.
    pub users: Vec<UserResponse>,

    /// Pagination metadata.
    pub pagination: PaginationMeta,
}

/// Pagination metadata for list responses.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginationMeta {
    /// Total number of matching records.
    pub total_count: i64,

    /// Current offset.
    pub offset: i64,

    /// Page size.
    pub limit: i64,

    /// Whether more records are available.
    pub has_more: bool,
}

impl PaginationMeta {
    /// Create pagination metadata from query results.
    #[must_use]
    pub fn new(total_count: i64, offset: i64, limit: i64) -> Self {
        Self {
            total_count,
            offset,
            limit,
            has_more: offset + limit < total_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_meta_has_more_true() {
        let meta = PaginationMeta::new(100, 0, 20);
        assert!(meta.has_more);
    }

    #[test]
    fn test_pagination_meta_has_more_false() {
        let meta = PaginationMeta::new(15, 0, 20);
        assert!(!meta.has_more);
    }

    #[test]
    fn test_pagination_meta_last_page() {
        let meta = PaginationMeta::new(100, 80, 20);
        assert!(!meta.has_more);
    }
}
