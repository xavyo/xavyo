//! Request models for the User Management API.

use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

/// Request to create a new user.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    /// User's email address.
    pub email: String,

    /// User's password (will be hashed).
    pub password: String,

    /// Roles to assign to the user.
    pub roles: Vec<String>,
}

/// Request to update an existing user.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    /// New email address (optional).
    #[serde(default)]
    pub email: Option<String>,

    /// New roles (optional, replaces all existing roles).
    #[serde(default)]
    pub roles: Option<Vec<String>>,

    /// New active status (optional).
    #[serde(default)]
    pub is_active: Option<bool>,
}

/// Query parameters for listing users.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListUsersQuery {
    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: Option<i64>,

    /// Maximum number of users to return (default: 20, max: 100).
    #[serde(default)]
    pub limit: Option<i64>,

    /// Filter by email (case-insensitive partial match).
    #[serde(default)]
    pub email: Option<String>,
}

impl ListUsersQuery {
    /// Default page size.
    pub const DEFAULT_LIMIT: i64 = 20;

    /// Maximum allowed page size.
    pub const MAX_LIMIT: i64 = 100;

    /// Get the offset, defaulting to 0.
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }

    /// Get the limit, clamped to valid range.
    #[must_use]
    pub fn limit(&self) -> i64 {
        self.limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_users_query_defaults() {
        let query = ListUsersQuery {
            offset: None,
            limit: None,
            email: None,
        };
        assert_eq!(query.offset(), 0);
        assert_eq!(query.limit(), 20);
    }

    #[test]
    fn test_list_users_query_clamping() {
        let query = ListUsersQuery {
            offset: Some(-5),
            limit: Some(500),
            email: None,
        };
        assert_eq!(query.offset(), 0);
        assert_eq!(query.limit(), 100);
    }
}
