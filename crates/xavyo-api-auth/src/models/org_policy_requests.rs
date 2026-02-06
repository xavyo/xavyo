//! Request and response DTOs for organization security policy endpoints (F-066).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::org_policy_config::{
    IpRestrictionPolicyConfig, MfaPolicyConfig, PasswordPolicyConfig, PolicyConflictWarning,
    SessionPolicyConfig,
};

// ============================================================================
// Policy Type Enum
// ============================================================================

/// Organization security policy type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OrgPolicyTypeDto {
    /// Password complexity and expiration policy.
    Password,
    /// Multi-factor authentication policy.
    Mfa,
    /// Session duration and limits policy.
    Session,
    /// IP address restriction policy.
    IpRestriction,
}

impl std::fmt::Display for OrgPolicyTypeDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password => write!(f, "password"),
            Self::Mfa => write!(f, "mfa"),
            Self::Session => write!(f, "session"),
            Self::IpRestriction => write!(f, "ip_restriction"),
        }
    }
}

impl std::str::FromStr for OrgPolicyTypeDto {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "password" => Ok(Self::Password),
            "mfa" => Ok(Self::Mfa),
            "session" => Ok(Self::Session),
            "ip_restriction" => Ok(Self::IpRestriction),
            _ => Err(format!("Invalid policy type: {s}")),
        }
    }
}

// ============================================================================
// Policy Configuration Union
// ============================================================================

/// Union type for all policy configurations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PolicyConfigDto {
    /// Password policy configuration.
    Password(PasswordPolicyConfig),
    /// MFA policy configuration.
    Mfa(MfaPolicyConfig),
    /// Session policy configuration.
    Session(SessionPolicyConfig),
    /// IP restriction policy configuration.
    IpRestriction(IpRestrictionPolicyConfig),
}

// ============================================================================
// Response Types
// ============================================================================

/// Response for a single organization security policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrgSecurityPolicyResponse {
    /// Unique policy ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Organization (group) ID.
    pub group_id: Uuid,

    /// Organization name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,

    /// Policy type.
    pub policy_type: OrgPolicyTypeDto,

    /// Policy configuration (varies by policy_type).
    pub config: serde_json::Value,

    /// Whether the policy is active.
    pub is_active: bool,

    /// When the policy was created.
    pub created_at: DateTime<Utc>,

    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,

    /// User who created the policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<Uuid>,

    /// User who last updated the policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Uuid>,
}

/// Response for listing organization security policies.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrgSecurityPolicyListResponse {
    /// List of policies.
    pub items: Vec<OrgSecurityPolicyResponse>,

    /// Total count of policies.
    pub total: usize,
}

// ============================================================================
// Request Types
// ============================================================================

/// Request to create a new organization security policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateOrgSecurityPolicyRequest {
    /// Policy type to create.
    pub policy_type: OrgPolicyTypeDto,

    /// Policy configuration (must match policy_type).
    pub config: serde_json::Value,

    /// Whether the policy is active (defaults to true).
    #[serde(default = "default_active")]
    pub is_active: bool,
}

fn default_active() -> bool {
    true
}

/// Request to update an organization security policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateOrgSecurityPolicyRequest {
    /// Updated policy configuration.
    pub config: serde_json::Value,

    /// Updated active status (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Request to validate a policy before saving.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidatePolicyRequest {
    /// Policy type to validate.
    pub policy_type: OrgPolicyTypeDto,

    /// Policy configuration to validate.
    pub config: serde_json::Value,
}

// ============================================================================
// Effective Policy Response Types
// ============================================================================

/// Source of an effective policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceDto {
    /// Policy is defined directly on this organization.
    Local,
    /// Policy is inherited from a parent organization.
    Inherited,
    /// Policy falls back to tenant default.
    TenantDefault,
}

/// Source information for an effective policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicySourceInfo {
    /// How the policy was resolved.
    #[serde(rename = "type")]
    pub source_type: PolicySourceDto,

    /// Group ID if inherited or local.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<Uuid>,

    /// Group name if inherited or local.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
}

/// Response for effective policy for an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveOrgPolicyResponse {
    /// The resolved policy configuration.
    pub config: serde_json::Value,

    /// Source of the policy.
    pub source: PolicySourceInfo,
}

/// Response for effective policy for a user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectiveUserPolicyResponse {
    /// The resolved policy configuration (most restrictive across groups).
    pub config: serde_json::Value,

    /// All sources that contributed to the policy.
    pub sources: Vec<PolicySourceInfo>,

    /// How the policy was resolved.
    pub resolution_method: String,
}

/// Response for policy validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyValidationResponse {
    /// Whether the policy configuration is valid.
    pub valid: bool,

    /// List of conflict warnings with parent/child policies.
    pub warnings: Vec<PolicyConflictWarning>,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing organization security policies.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListOrgPoliciesQuery {
    /// Filter by policy type.
    pub policy_type: Option<OrgPolicyTypeDto>,

    /// Filter by active status.
    pub is_active: Option<bool>,
}

/// Path parameters for organization policy endpoints.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct OrgPolicyPath {
    /// Organization (group) ID.
    pub org_id: Uuid,
}

/// Path parameters for specific policy endpoints.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct OrgPolicyTypePath {
    /// Organization (group) ID.
    pub org_id: Uuid,

    /// Policy type.
    pub policy_type: String,
}

/// Path parameters for user effective policy endpoints.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct UserPolicyPath {
    /// User ID.
    pub user_id: Uuid,

    /// Policy type.
    pub policy_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_parsing() {
        assert_eq!(
            "password".parse::<OrgPolicyTypeDto>().unwrap(),
            OrgPolicyTypeDto::Password
        );
        assert_eq!(
            "mfa".parse::<OrgPolicyTypeDto>().unwrap(),
            OrgPolicyTypeDto::Mfa
        );
        assert_eq!(
            "session".parse::<OrgPolicyTypeDto>().unwrap(),
            OrgPolicyTypeDto::Session
        );
        assert_eq!(
            "ip_restriction".parse::<OrgPolicyTypeDto>().unwrap(),
            OrgPolicyTypeDto::IpRestriction
        );
        assert!("invalid".parse::<OrgPolicyTypeDto>().is_err());
    }

    #[test]
    fn test_policy_type_display() {
        assert_eq!(OrgPolicyTypeDto::Password.to_string(), "password");
        assert_eq!(OrgPolicyTypeDto::Mfa.to_string(), "mfa");
        assert_eq!(OrgPolicyTypeDto::Session.to_string(), "session");
        assert_eq!(
            OrgPolicyTypeDto::IpRestriction.to_string(),
            "ip_restriction"
        );
    }

    #[test]
    fn test_create_request_serialization() {
        let request = CreateOrgSecurityPolicyRequest {
            policy_type: OrgPolicyTypeDto::Password,
            config: serde_json::json!({
                "min_length": 12,
                "require_uppercase": true
            }),
            is_active: true,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("password"));
        assert!(json.contains("min_length"));
    }

    #[test]
    fn test_response_serialization() {
        let response = OrgSecurityPolicyResponse {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            group_id: Uuid::nil(),
            group_name: Some("Finance".to_string()),
            policy_type: OrgPolicyTypeDto::Mfa,
            config: serde_json::json!({"required": true}),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: None,
            updated_by: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("mfa"));
        assert!(json.contains("Finance"));
    }
}
