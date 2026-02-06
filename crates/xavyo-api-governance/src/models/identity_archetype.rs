//! Identity Archetype request/response models for governance API (F-058).
//!
//! These models handle API interactions for identity archetypes, which allow
//! defining sub-types of identities with custom schemas, policies, and inheritance.
//!
//! Note: Types are prefixed with "Identity" to distinguish from persona archetypes.
//!
//! ## F-059 Lifecycle State Machine Integration
//!
//! Each archetype can optionally reference a lifecycle model via `lifecycle_model_id`.
//! When F-059 is implemented, this integration enables:
//!
//! - **State Model Association**: Each archetype can have a different lifecycle state model
//!   (e.g., Employee uses "Standard Employee Lifecycle", Contractor uses "Contractor Lifecycle")
//! - **Effective Lifecycle Resolution**: Users inherit their lifecycle model from their archetype
//! - **State Transition Validation**: Lifecycle transitions are validated against the model
//! - **Archetype-Specific States**: Different archetypes can have different allowed states
//!   and transition rules
//!
//! ### Integration Points (for F-059 implementation):
//!
//! 1. `IdentityArchetype.lifecycle_model_id` - FK to lifecycle_models table
//! 2. `User.lifecycle_state` - Current state, validated against archetype's lifecycle model
//! 3. `get_effective_policies` - Should include lifecycle model resolution
//! 4. State transition API - Should validate against user's archetype lifecycle model

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{
    AncestryNode, ArchetypePolicyBinding, EffectivePolicy, IdentityArchetype, PolicyType,
};

/// Request to create a new identity archetype.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateIdentityArchetypeRequest {
    /// Archetype name (unique within tenant).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Archetype description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Parent archetype ID for inheritance.
    pub parent_archetype_id: Option<Uuid>,

    /// Schema extensions (custom attributes for this archetype).
    /// Format: {"attributes": [{"name": "...", "type": "string|number|date|boolean|enum|uuid", "required": bool, ...}]}
    pub schema_extensions: Option<serde_json::Value>,

    /// Lifecycle model ID (for F-059 integration).
    pub lifecycle_model_id: Option<Uuid>,
}

/// Request to update an existing identity archetype.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateIdentityArchetypeRequest {
    /// Archetype name (unique within tenant).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// Archetype description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Parent archetype ID for inheritance.
    /// Use `null` to clear the parent.
    pub parent_archetype_id: Option<Option<Uuid>>,

    /// Schema extensions (custom attributes for this archetype).
    pub schema_extensions: Option<serde_json::Value>,

    /// Lifecycle model ID (for F-059 integration).
    /// Use `null` to clear.
    pub lifecycle_model_id: Option<Option<Uuid>>,

    /// Whether the archetype is active.
    pub is_active: Option<bool>,
}

/// Query parameters for listing identity archetypes.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListIdentityArchetypesQuery {
    /// Filter by active status only.
    #[serde(default)]
    pub active_only: bool,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Identity archetype response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IdentityArchetypeResponse {
    /// Unique identifier for the archetype.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Archetype name.
    pub name: String,

    /// Archetype description.
    pub description: Option<String>,

    /// Parent archetype ID for inheritance.
    pub parent_archetype_id: Option<Uuid>,

    /// Schema extensions (custom attributes).
    pub schema_extensions: serde_json::Value,

    /// Lifecycle model ID.
    pub lifecycle_model_id: Option<Uuid>,

    /// Whether the archetype is active.
    pub is_active: bool,

    /// When the archetype was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the archetype was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<IdentityArchetype> for IdentityArchetypeResponse {
    fn from(archetype: IdentityArchetype) -> Self {
        Self {
            id: archetype.id,
            tenant_id: archetype.tenant_id,
            name: archetype.name,
            description: archetype.description,
            parent_archetype_id: archetype.parent_archetype_id,
            schema_extensions: archetype.schema_extensions,
            lifecycle_model_id: archetype.lifecycle_model_id,
            is_active: archetype.is_active,
            created_at: archetype.created_at,
            updated_at: archetype.updated_at,
        }
    }
}

/// Paginated list of identity archetypes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IdentityArchetypeListResponse {
    /// List of archetypes.
    pub items: Vec<IdentityArchetypeResponse>,

    /// Total count of matching archetypes.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

/// Ancestry node response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IdentityAncestryNodeResponse {
    /// Archetype ID.
    pub id: Uuid,

    /// Archetype name.
    pub name: String,

    /// Depth in the ancestry chain (1 = self, 2 = parent, 3 = grandparent, etc.).
    pub depth: i32,
}

impl From<AncestryNode> for IdentityAncestryNodeResponse {
    fn from(node: AncestryNode) -> Self {
        Self {
            id: node.id,
            name: node.name,
            depth: node.depth,
        }
    }
}

/// Archetype with ancestry chain response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IdentityArchetypeWithAncestryResponse {
    /// The archetype.
    #[serde(flatten)]
    pub archetype: IdentityArchetypeResponse,

    /// Ancestry chain from self to root.
    pub ancestry_chain: Vec<IdentityAncestryNodeResponse>,
}

/// Request to bind a policy to an archetype.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BindPolicyRequest {
    /// Type of policy (password, mfa, session).
    pub policy_type: PolicyTypeDto,

    /// ID of the policy to bind.
    pub policy_id: Uuid,
}

/// Policy type DTO for API requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyTypeDto {
    Password,
    Mfa,
    Session,
}

impl From<PolicyTypeDto> for PolicyType {
    fn from(dto: PolicyTypeDto) -> Self {
        match dto {
            PolicyTypeDto::Password => PolicyType::Password,
            PolicyTypeDto::Mfa => PolicyType::Mfa,
            PolicyTypeDto::Session => PolicyType::Session,
        }
    }
}

impl From<PolicyType> for PolicyTypeDto {
    fn from(policy_type: PolicyType) -> Self {
        match policy_type {
            PolicyType::Password => PolicyTypeDto::Password,
            PolicyType::Mfa => PolicyTypeDto::Mfa,
            PolicyType::Session => PolicyTypeDto::Session,
        }
    }
}

/// Policy binding response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyBindingResponse {
    /// Unique identifier for the binding.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Archetype ID.
    pub archetype_id: Uuid,

    /// Policy type.
    pub policy_type: String,

    /// Policy ID.
    pub policy_id: Uuid,

    /// When the binding was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<ArchetypePolicyBinding> for PolicyBindingResponse {
    fn from(binding: ArchetypePolicyBinding) -> Self {
        Self {
            id: binding.id,
            tenant_id: binding.tenant_id,
            archetype_id: binding.archetype_id,
            policy_type: binding.policy_type,
            policy_id: binding.policy_id,
            created_at: binding.created_at,
        }
    }
}

/// Effective policy response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectivePolicyResponse {
    /// Policy type.
    pub policy_type: String,

    /// Policy ID.
    pub policy_id: Uuid,

    /// Source archetype ID (where this policy is defined).
    pub source_archetype_id: Uuid,

    /// Source archetype name.
    pub source_archetype_name: String,
}

impl From<EffectivePolicy> for EffectivePolicyResponse {
    fn from(policy: EffectivePolicy) -> Self {
        Self {
            policy_type: policy.policy_type,
            policy_id: policy.policy_id,
            source_archetype_id: policy.source_archetype_id,
            source_archetype_name: policy.source_archetype_name,
        }
    }
}

/// List of effective policies for an archetype.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EffectivePoliciesResponse {
    /// Archetype ID.
    pub archetype_id: Uuid,

    /// Effective policies (resolved through inheritance).
    pub policies: Vec<EffectivePolicyResponse>,

    /// Effective lifecycle model ID (resolved through inheritance).
    /// This is the first lifecycle_model_id found walking up the archetype inheritance chain.
    /// Will be populated when F-059 lifecycle state machine is implemented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_lifecycle_model_id: Option<Uuid>,

    /// Source archetype ID for the effective lifecycle model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_model_source_archetype_id: Option<Uuid>,
}

/// Request to assign an archetype to a user.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AssignIdentityArchetypeRequest {
    /// Archetype ID to assign.
    pub archetype_id: Uuid,

    /// Custom attributes for this user based on the archetype schema.
    pub custom_attrs: Option<serde_json::Value>,
}

/// User archetype assignment response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserIdentityArchetypeResponse {
    /// User ID.
    pub user_id: Uuid,

    /// Assigned archetype (if any).
    pub archetype: Option<IdentityArchetypeResponse>,

    /// Custom attributes for this user.
    pub custom_attrs: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_conversion() {
        assert_eq!(
            PolicyType::from(PolicyTypeDto::Password),
            PolicyType::Password
        );
        assert_eq!(PolicyType::from(PolicyTypeDto::Mfa), PolicyType::Mfa);
        assert_eq!(
            PolicyType::from(PolicyTypeDto::Session),
            PolicyType::Session
        );
    }

    #[test]
    fn test_policy_type_dto_from_policy_type() {
        assert_eq!(
            PolicyTypeDto::from(PolicyType::Password),
            PolicyTypeDto::Password
        );
        assert_eq!(PolicyTypeDto::from(PolicyType::Mfa), PolicyTypeDto::Mfa);
        assert_eq!(
            PolicyTypeDto::from(PolicyType::Session),
            PolicyTypeDto::Session
        );
    }

    #[test]
    fn test_create_archetype_request_validation() {
        let request = CreateIdentityArchetypeRequest {
            name: "Employee".to_string(),
            description: Some("Standard employee archetype".to_string()),
            parent_archetype_id: None,
            schema_extensions: None,
            lifecycle_model_id: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_archetype_request_empty_name_fails() {
        let request = CreateIdentityArchetypeRequest {
            name: "".to_string(),
            description: None,
            parent_archetype_id: None,
            schema_extensions: None,
            lifecycle_model_id: None,
        };
        assert!(request.validate().is_err());
    }
}
