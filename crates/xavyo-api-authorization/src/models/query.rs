//! Request/response DTOs for authorization query endpoints (F083).

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_authorization::AuthorizationDecision;

/// Query parameters for the "can I" endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct CanIQuery {
    /// The action to check (e.g., "read", "write", "delete").
    pub action: String,

    /// The resource type to check (e.g., "report", "user").
    pub resource_type: String,

    /// Optional specific resource instance ID.
    pub resource_id: Option<String>,
}

/// Query parameters for the admin check endpoint.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AdminCheckQuery {
    /// The user to check authorization for.
    pub user_id: Uuid,

    /// The action to check.
    pub action: String,

    /// The resource type to check.
    pub resource_type: String,

    /// Optional specific resource instance ID.
    pub resource_id: Option<String>,
}

/// Request body for bulk authorization checks.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkCheckRequest {
    /// Optional user ID to check for (defaults to the caller).
    pub user_id: Option<Uuid>,

    /// The list of checks to perform (max 100).
    pub checks: Vec<CheckItem>,
}

/// A single check item in a bulk check request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CheckItem {
    /// The action to check.
    pub action: String,

    /// The resource type to check.
    pub resource_type: String,

    /// Optional specific resource instance ID.
    pub resource_id: Option<String>,
}

/// Response for a single authorization decision.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizationDecisionResponse {
    /// Whether the action is allowed.
    pub allowed: bool,

    /// Human-readable reason for the decision.
    pub reason: String,

    /// The source of the decision (e.g., "policy", "entitlement", "default_deny").
    pub source: String,

    /// The policy ID that made the decision (if applicable).
    pub policy_id: Option<Uuid>,

    /// Unique identifier for this decision (for audit trail).
    pub decision_id: Uuid,
}

/// Response for a bulk authorization check.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkCheckResponse {
    /// The list of decisions, one per check item.
    pub results: Vec<AuthorizationDecisionResponse>,
}

impl From<AuthorizationDecision> for AuthorizationDecisionResponse {
    fn from(d: AuthorizationDecision) -> Self {
        Self {
            allowed: d.allowed,
            reason: d.reason,
            source: d.source.to_string(),
            policy_id: d.policy_id,
            decision_id: d.decision_id,
        }
    }
}
