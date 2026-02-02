//! Admin invitation request and response models (F-ADMIN-INVITE).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Request to create a new admin invitation.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateInvitationRequest {
    /// Email address of the person to invite.
    pub email: String,

    /// Optional role template to assign on acceptance.
    pub role_template_id: Option<Uuid>,
}

impl CreateInvitationRequest {
    /// Validate the request.
    pub fn validate(&self) -> Result<(), String> {
        if self.email.is_empty() {
            return Err("Email is required".to_string());
        }
        Ok(())
    }
}

/// Request to accept an invitation.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AcceptInvitationRequest {
    /// Invitation token from the email link.
    pub token: String,

    /// Password for the new account.
    pub password: String,
}

impl AcceptInvitationRequest {
    /// Validate the request.
    pub fn validate(&self) -> Result<(), String> {
        if self.token.is_empty() {
            return Err("Token is required".to_string());
        }
        if self.password.is_empty() {
            return Err("Password is required".to_string());
        }
        Ok(())
    }
}

/// Query parameters for listing invitations.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ListInvitationsQuery {
    /// Filter by status (pending, sent, accepted, expired, cancelled).
    pub status: Option<String>,

    /// Filter by email (partial match).
    pub email: Option<String>,

    /// Maximum number of results (default: 50, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i32,

    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: i32,
}

fn default_limit() -> i32 {
    50
}

impl ListInvitationsQuery {
    /// Validate and normalize the query parameters.
    pub fn validate(&mut self) -> Result<(), String> {
        // Validate status if provided
        if let Some(ref status) = self.status {
            let valid_statuses = ["pending", "sent", "accepted", "expired", "cancelled"];
            if !valid_statuses.contains(&status.as_str()) {
                return Err(format!(
                    "Invalid status '{}'. Must be one of: {}",
                    status,
                    valid_statuses.join(", ")
                ));
            }
        }

        // Clamp limit to 1-100
        self.limit = self.limit.clamp(1, 100);

        // Ensure offset is non-negative
        if self.offset < 0 {
            self.offset = 0;
        }

        Ok(())
    }
}

/// Response for a single invitation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationResponse {
    /// Invitation ID.
    pub id: Uuid,

    /// Invitee email address.
    pub email: String,

    /// Invitation status.
    pub status: String,

    /// Role template ID (if assigned).
    pub role_template_id: Option<Uuid>,

    /// Admin who created the invitation.
    pub invited_by_user_id: Option<Uuid>,

    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Acceptance timestamp (if accepted).
    pub accepted_at: Option<DateTime<Utc>>,
}

impl From<xavyo_db::models::UserInvitation> for InvitationResponse {
    fn from(inv: xavyo_db::models::UserInvitation) -> Self {
        Self {
            id: inv.id,
            email: inv.email.unwrap_or_default(),
            status: inv.status,
            role_template_id: inv.role_template_id,
            invited_by_user_id: inv.invited_by_user_id,
            expires_at: inv.expires_at,
            created_at: inv.created_at,
            accepted_at: inv.accepted_at,
        }
    }
}

/// Response for accepting an invitation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AcceptInvitationResponse {
    /// Success message.
    pub message: String,

    /// Created user ID.
    pub user_id: Uuid,

    /// User email.
    pub email: String,
}

/// Response for listing invitations.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InvitationListResponse {
    /// List of invitations.
    pub invitations: Vec<InvitationResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used.
    pub limit: i32,

    /// Offset used.
    pub offset: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_invitation_request_validation() {
        let req = CreateInvitationRequest {
            email: "".to_string(),
            role_template_id: None,
        };
        assert!(req.validate().is_err());

        let req = CreateInvitationRequest {
            email: "test@example.com".to_string(),
            role_template_id: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_accept_invitation_request_validation() {
        let req = AcceptInvitationRequest {
            token: "".to_string(),
            password: "test".to_string(),
        };
        assert!(req.validate().is_err());

        let req = AcceptInvitationRequest {
            token: "token123".to_string(),
            password: "".to_string(),
        };
        assert!(req.validate().is_err());

        let req = AcceptInvitationRequest {
            token: "token123".to_string(),
            password: "password".to_string(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn test_list_invitations_query_validation() {
        let mut query = ListInvitationsQuery {
            status: Some("invalid".to_string()),
            email: None,
            limit: 50,
            offset: 0,
        };
        assert!(query.validate().is_err());

        let mut query = ListInvitationsQuery {
            status: Some("pending".to_string()),
            email: None,
            limit: 50,
            offset: 0,
        };
        assert!(query.validate().is_ok());
    }

    #[test]
    fn test_list_invitations_query_clamping() {
        let mut query = ListInvitationsQuery {
            status: None,
            email: None,
            limit: 200,
            offset: -10,
        };
        query.validate().unwrap();
        assert_eq!(query.limit, 100);
        assert_eq!(query.offset, 0);
    }
}
