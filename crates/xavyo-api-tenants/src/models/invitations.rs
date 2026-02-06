//! Request and response models for tenant invitation API (F-057).
//!
//! This module provides DTOs for the tenant user invitation feature,
//! allowing tenant administrators to invite users to their tenant via email.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// Request DTOs
// ============================================================================

/// Request to create a new invitation.
///
/// Creates an invitation for a user to join the tenant. The invitation
/// generates a secure token that expires after 7 days.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// Email address of the user to invite (RFC 5322 format).
    pub email: String,

    /// Role to assign when invitation is accepted.
    /// Defaults to "member" if not specified.
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "member".to_string()
}

impl CreateInvitationRequest {
    /// Validate the request and return an error message if invalid.
    pub fn validate(&self) -> Option<String> {
        // Validate email format (basic check)
        if self.email.is_empty() {
            return Some("Email is required".to_string());
        }

        if !self.email.contains('@') || !self.email.contains('.') {
            return Some("Invalid email format".to_string());
        }

        // Validate email length
        if self.email.len() > 254 {
            return Some("Email address too long (max 254 characters)".to_string());
        }

        // Validate role
        if self.role != "member" && self.role != "admin" {
            return Some("Role must be 'member' or 'admin'".to_string());
        }

        None
    }
}

/// Request to accept an invitation.
///
/// Uses the secure token from the invitation email to accept
/// and join the tenant.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AcceptInvitationRequest {
    /// Invitation token from the email link.
    pub token: String,

    /// Password for new account (required if creating new user).
    #[serde(default)]
    pub password: Option<String>,
}

impl AcceptInvitationRequest {
    /// Validate the request and return an error message if invalid.
    pub fn validate(&self) -> Option<String> {
        if self.token.is_empty() {
            return Some("Token is required".to_string());
        }

        // Validate password if provided
        if let Some(ref password) = self.password {
            if password.len() < 8 {
                return Some("Password must be at least 8 characters".to_string());
            }
        }

        None
    }
}

/// Query parameters for listing invitations.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ListInvitationsQuery {
    /// Filter by status (pending, sent, accepted, expired, cancelled).
    #[serde(default)]
    pub status: Option<String>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i32,
}

fn default_limit() -> i32 {
    20
}

impl ListInvitationsQuery {
    /// Validate the query parameters and return an error message if invalid.
    pub fn validate(&self) -> Option<String> {
        // Validate status if provided
        if let Some(ref status) = self.status {
            let valid_statuses = ["pending", "sent", "accepted", "expired", "cancelled"];
            if !valid_statuses.contains(&status.as_str()) {
                return Some(format!(
                    "Invalid status. Must be one of: {}",
                    valid_statuses.join(", ")
                ));
            }
        }

        // Validate limit
        if self.limit < 1 || self.limit > 100 {
            return Some("Limit must be between 1 and 100".to_string());
        }

        // Validate offset
        if self.offset < 0 {
            return Some("Offset must be non-negative".to_string());
        }

        None
    }
}

// ============================================================================
// Response DTOs
// ============================================================================

/// Response for a single invitation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationResponse {
    /// Unique invitation identifier.
    pub id: Uuid,

    /// Email address of the invitee.
    pub email: String,

    /// Role assigned to the user upon acceptance.
    pub role: String,

    /// Current status: pending, sent, accepted, expired, or cancelled.
    pub status: String,

    /// When the invitation was created.
    pub created_at: DateTime<Utc>,

    /// When the invitation expires.
    pub expires_at: DateTime<Utc>,

    /// User who created the invitation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<Uuid>,
}

/// Response for listing invitations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationListResponse {
    /// List of invitations.
    pub invitations: Vec<InvitationResponse>,

    /// Total count of invitations matching the filter.
    pub total: i64,

    /// Limit used in the query.
    pub limit: i32,

    /// Offset used in the query.
    pub offset: i32,
}

/// Response after accepting an invitation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AcceptInvitationResponse {
    /// Success message.
    pub message: String,

    /// User ID of the newly added or existing user.
    pub user_id: Uuid,

    /// Tenant ID the user joined.
    pub tenant_id: Uuid,

    /// Role assigned to the user.
    pub role: String,
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // T014: Test create invitation succeeds with valid email
    #[test]
    fn test_create_invitation_request_valid() {
        let request = CreateInvitationRequest {
            email: "user@example.com".to_string(),
            role: "member".to_string(),
        };
        assert!(request.validate().is_none());
    }

    // T015: Test create invitation fails for empty email
    #[test]
    fn test_create_invitation_request_empty_email() {
        let request = CreateInvitationRequest {
            email: "".to_string(),
            role: "member".to_string(),
        };
        assert_eq!(request.validate(), Some("Email is required".to_string()));
    }

    // Test create invitation fails for invalid email format
    #[test]
    fn test_create_invitation_request_invalid_email() {
        let request = CreateInvitationRequest {
            email: "invalid-email".to_string(),
            role: "member".to_string(),
        };
        assert_eq!(request.validate(), Some("Invalid email format".to_string()));
    }

    // Test create invitation fails for invalid role
    #[test]
    fn test_create_invitation_request_invalid_role() {
        let request = CreateInvitationRequest {
            email: "user@example.com".to_string(),
            role: "superadmin".to_string(),
        };
        assert_eq!(
            request.validate(),
            Some("Role must be 'member' or 'admin'".to_string())
        );
    }

    // Test create invitation with admin role
    #[test]
    fn test_create_invitation_request_admin_role() {
        let request = CreateInvitationRequest {
            email: "admin@example.com".to_string(),
            role: "admin".to_string(),
        };
        assert!(request.validate().is_none());
    }

    // Test accept invitation request validation
    #[test]
    fn test_accept_invitation_request_valid() {
        let request = AcceptInvitationRequest {
            token: "abc123def456".to_string(),
            password: Some("SecurePassword123!".to_string()),
        };
        assert!(request.validate().is_none());
    }

    // Test accept invitation request with empty token
    #[test]
    fn test_accept_invitation_request_empty_token() {
        let request = AcceptInvitationRequest {
            token: "".to_string(),
            password: None,
        };
        assert_eq!(request.validate(), Some("Token is required".to_string()));
    }

    // Test accept invitation request with short password
    #[test]
    fn test_accept_invitation_request_short_password() {
        let request = AcceptInvitationRequest {
            token: "abc123".to_string(),
            password: Some("short".to_string()),
        };
        assert_eq!(
            request.validate(),
            Some("Password must be at least 8 characters".to_string())
        );
    }

    // Test list invitations query validation
    #[test]
    fn test_list_invitations_query_valid() {
        let query = ListInvitationsQuery {
            status: Some("pending".to_string()),
            limit: 20,
            offset: 0,
        };
        assert!(query.validate().is_none());
    }

    // Test list invitations query with invalid status
    #[test]
    fn test_list_invitations_query_invalid_status() {
        let query = ListInvitationsQuery {
            status: Some("unknown".to_string()),
            limit: 20,
            offset: 0,
        };
        assert!(query.validate().is_some());
    }

    // Test list invitations query with invalid limit
    #[test]
    fn test_list_invitations_query_invalid_limit() {
        let query = ListInvitationsQuery {
            status: None,
            limit: 0,
            offset: 0,
        };
        assert_eq!(
            query.validate(),
            Some("Limit must be between 1 and 100".to_string())
        );
    }

    // Test list invitations query with negative offset
    #[test]
    fn test_list_invitations_query_negative_offset() {
        let query = ListInvitationsQuery {
            status: None,
            limit: 20,
            offset: -1,
        };
        assert_eq!(
            query.validate(),
            Some("Offset must be non-negative".to_string())
        );
    }
}
