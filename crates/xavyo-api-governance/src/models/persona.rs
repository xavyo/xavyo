//! Request and response models for Persona Management endpoints (F063).
//!
//! Personas are virtual alternative identities linked to physical users,
//! enabling context-specific access with full audit trails.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    GovPersona, GovPersonaArchetype, GovPersonaAuditEvent, GovPersonaSession, PersonaAttributes,
    PersonaAuditEventType, PersonaStatus,
};

// ============================================================================
// Archetype Models
// ============================================================================

/// Request to create a new persona archetype.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateArchetypeRequest {
    /// Display name for the archetype (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Optional description of the archetype.
    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Template for generating persona names (e.g., "admin.{username}").
    #[validate(length(
        min = 1,
        max = 255,
        message = "Naming pattern must be between 1 and 255 characters"
    ))]
    pub naming_pattern: String,

    /// Attribute mappings configuration.
    #[serde(default)]
    pub attribute_mappings: Option<AttributeMappingsRequest>,

    /// Default entitlements to assign to new personas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_entitlements: Option<Vec<DefaultEntitlementRequest>>,

    /// Lifecycle policy configuration.
    #[serde(default)]
    pub lifecycle_policy: Option<LifecyclePolicyRequest>,
}

/// Request to update a persona archetype.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateArchetypeRequest {
    /// Updated name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated naming pattern.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Naming pattern must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub naming_pattern: Option<String>,

    /// Updated attribute mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_mappings: Option<AttributeMappingsRequest>,

    /// Updated default entitlements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_entitlements: Option<Vec<DefaultEntitlementRequest>>,

    /// Updated lifecycle policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle_policy: Option<LifecyclePolicyRequest>,

    /// Whether archetype is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Attribute mappings configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct AttributeMappingsRequest {
    /// Attributes to propagate from physical user.
    #[serde(default)]
    pub propagate: Vec<PropagateMappingRequest>,

    /// Computed attributes from templates.
    #[serde(default)]
    pub computed: Vec<ComputedMappingRequest>,

    /// Persona-only attribute names.
    #[serde(default)]
    pub persona_only: Vec<String>,
}

/// Propagation mapping configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PropagateMappingRequest {
    /// Source attribute name on physical user.
    pub source: String,

    /// Target attribute name on persona.
    pub target: String,

    /// Propagation mode: "always" or "default".
    #[serde(default = "default_propagate_mode")]
    pub mode: String,

    /// Whether persona can override this attribute.
    #[serde(default)]
    pub allow_override: bool,
}

fn default_propagate_mode() -> String {
    "always".to_string()
}

/// Computed attribute mapping.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ComputedMappingRequest {
    /// Target attribute name on persona.
    pub target: String,

    /// Handlebars template for computing value.
    pub template: String,

    /// Static variables for template.
    #[serde(default)]
    pub variables: serde_json::Map<String, serde_json::Value>,
}

/// Default entitlement to assign to new personas.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DefaultEntitlementRequest {
    /// Application ID.
    pub application_id: Uuid,

    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Assignment reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Lifecycle policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct LifecyclePolicyRequest {
    /// Default validity in days for new personas.
    #[validate(range(
        min = 1,
        max = 3650,
        message = "Default validity days must be between 1 and 3650"
    ))]
    #[serde(default = "default_validity_days")]
    pub default_validity_days: i32,

    /// Maximum validity in days.
    #[validate(range(
        min = 1,
        max = 3650,
        message = "Max validity days must be between 1 and 3650"
    ))]
    #[serde(default = "default_max_validity_days")]
    pub max_validity_days: i32,

    /// Days before expiry to send notification.
    #[validate(range(min = 1, message = "Notification days must be at least 1"))]
    #[serde(default = "default_notification_days")]
    pub notification_before_expiry_days: i32,

    /// Whether auto-extension is allowed.
    #[serde(default)]
    pub auto_extension_allowed: bool,

    /// Whether extension requires approval.
    #[serde(default = "default_true")]
    pub extension_requires_approval: bool,

    /// Action on physical user deactivation.
    #[serde(default = "default_deactivation_action")]
    pub on_physical_user_deactivation: String,
}

fn default_validity_days() -> i32 {
    365
}
fn default_max_validity_days() -> i32 {
    730
}
fn default_notification_days() -> i32 {
    7
}
fn default_true() -> bool {
    true
}
fn default_deactivation_action() -> String {
    "cascade_deactivate".to_string()
}

/// Archetype response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ArchetypeResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub naming_pattern: String,
    pub attribute_mappings: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_entitlements: Option<serde_json::Value>,
    pub lifecycle_policy: serde_json::Value,
    pub is_active: bool,
    /// Number of personas using this archetype.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personas_count: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<GovPersonaArchetype> for ArchetypeResponse {
    fn from(archetype: GovPersonaArchetype) -> Self {
        Self {
            id: archetype.id,
            name: archetype.name,
            description: archetype.description,
            naming_pattern: archetype.naming_pattern,
            attribute_mappings: archetype.attribute_mappings,
            default_entitlements: archetype.default_entitlements,
            lifecycle_policy: archetype.lifecycle_policy,
            is_active: archetype.is_active,
            personas_count: None,
            created_at: archetype.created_at,
            updated_at: archetype.updated_at,
        }
    }
}

/// List of archetypes response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ArchetypeListResponse {
    pub items: Vec<ArchetypeResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing archetypes.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListArchetypesQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,
    /// Filter by name (partial match).
    pub name_contains: Option<String>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Persona Models
// ============================================================================

/// Request to create a new persona.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreatePersonaRequest {
    /// Archetype to use for the persona.
    pub archetype_id: Uuid,

    /// Physical user who will own the persona.
    pub physical_user_id: Uuid,

    /// Attribute overrides (persona-specific values).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute_overrides: Option<serde_json::Map<String, serde_json::Value>>,

    /// When persona becomes valid (defaults to now).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,

    /// When persona expires (uses archetype default if not specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

/// Request to update a persona.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdatePersonaRequest {
    /// Updated display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Updated attribute overrides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_overrides: Option<serde_json::Map<String, serde_json::Value>>,

    /// Updated expiration date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
}

/// Request to deactivate a persona.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DeactivatePersonaRequest {
    /// Reason for deactivation (5-1000 characters).
    #[validate(length(
        min = 5,
        max = 1000,
        message = "Reason must be between 5 and 1000 characters"
    ))]
    pub reason: String,
}

/// Request to archive a persona.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ArchivePersonaRequest {
    /// Reason for archiving (5-1000 characters).
    #[validate(length(
        min = 5,
        max = 1000,
        message = "Reason must be between 5 and 1000 characters"
    ))]
    pub reason: String,
}

/// Request to extend persona validity.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ExtendPersonaRequest {
    /// New expiration date.
    pub new_valid_until: DateTime<Utc>,

    /// Reason for extension.
    #[validate(length(max = 1000, message = "Reason cannot exceed 1000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response for persona extension request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExtendPersonaResponse {
    /// Whether extension was approved or pending approval.
    pub status: ExtensionStatus,

    /// Updated persona (if approved).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona: Option<PersonaResponse>,

    /// Approval request ID (if `pending_approval`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
}

/// Extension request status.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionStatus {
    Approved,
    PendingApproval,
}

/// Basic persona response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaResponse {
    pub id: Uuid,
    pub archetype_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archetype_name: Option<String>,
    pub physical_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_user_name: Option<String>,
    pub persona_name: String,
    pub display_name: String,
    pub status: PersonaStatus,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<DateTime<Utc>>,
}

impl From<GovPersona> for PersonaResponse {
    fn from(persona: GovPersona) -> Self {
        Self {
            id: persona.id,
            archetype_id: persona.archetype_id,
            archetype_name: None,
            physical_user_id: persona.physical_user_id,
            physical_user_name: None,
            persona_name: persona.persona_name,
            display_name: persona.display_name,
            status: persona.status,
            valid_from: persona.valid_from,
            valid_until: persona.valid_until,
            created_at: persona.created_at,
            updated_at: persona.updated_at,
            deactivated_at: persona.deactivated_at,
        }
    }
}

/// Detailed persona response with attributes.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaDetailResponse {
    #[serde(flatten)]
    pub base: PersonaResponse,

    /// Persona attributes (inherited, overrides, `persona_specific`).
    pub attributes: PersonaAttributesResponse,

    /// Assigned entitlements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<PersonaEntitlementSummary>>,

    /// Physical user information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_user: Option<PersonaUserSummary>,
}

/// Persona attributes response.
#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
pub struct PersonaAttributesResponse {
    /// Attributes inherited from physical user.
    #[serde(default)]
    pub inherited: serde_json::Map<String, serde_json::Value>,

    /// Overridden attributes.
    #[serde(default)]
    pub overrides: serde_json::Map<String, serde_json::Value>,

    /// Persona-specific attributes.
    #[serde(default)]
    pub persona_specific: serde_json::Map<String, serde_json::Value>,

    /// When attributes were last propagated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_propagation_at: Option<DateTime<Utc>>,
}

impl From<PersonaAttributes> for PersonaAttributesResponse {
    fn from(attrs: PersonaAttributes) -> Self {
        Self {
            inherited: attrs.inherited,
            overrides: attrs.overrides,
            persona_specific: attrs.persona_specific,
            last_propagation_at: None,
        }
    }
}

/// List of personas response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaListResponse {
    pub items: Vec<PersonaResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing personas.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPersonasQuery {
    /// Filter by status.
    pub status: Option<PersonaStatus>,
    /// Filter by archetype.
    pub archetype_id: Option<Uuid>,
    /// Filter by physical user.
    pub physical_user_id: Option<Uuid>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

/// User's personas response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserPersonasResponse {
    pub physical_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_user_name: Option<String>,
    pub personas: Vec<PersonaResponse>,
    /// Currently active persona in session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_persona_id: Option<Uuid>,
}

/// Expiring personas response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpiringPersonasResponse {
    pub items: Vec<ExpiringPersonaSummary>,
    pub total: i64,
    pub within_days: i32,
    pub limit: i64,
    pub offset: i64,
}

/// Summary of an expiring persona.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExpiringPersonaSummary {
    pub id: Uuid,
    pub persona_name: String,
    pub physical_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archetype_name: Option<String>,
    pub valid_until: DateTime<Utc>,
    pub days_remaining: i32,
    pub notification_sent: bool,
}

/// Query parameters for listing expiring personas.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListExpiringPersonasQuery {
    /// Personas expiring within this many days.
    #[param(default = 7, minimum = 1, maximum = 90)]
    pub within_days: Option<i32>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Context Switching Models
// ============================================================================

/// Request to switch persona context.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SwitchContextRequest {
    /// Persona to switch to.
    pub persona_id: Uuid,

    /// Reason for switching.
    #[validate(length(max = 500, message = "Reason cannot exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Request to switch back to physical user.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SwitchBackRequest {
    /// Reason for switching back.
    #[validate(length(max = 500, message = "Reason cannot exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response after context switch.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SwitchContextResponse {
    /// Session ID.
    pub session_id: Uuid,

    /// New JWT with updated persona claims.
    pub access_token: String,

    /// Active persona ID (null if switched back to physical user).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_persona_id: Option<Uuid>,

    /// Active persona name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_persona_name: Option<String>,

    /// When the switch occurred.
    pub switched_at: DateTime<Utc>,
}

/// Current context response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CurrentContextResponse {
    pub physical_user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_user_name: Option<String>,
    pub is_persona_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_persona: Option<PersonaResponse>,
    pub session_started_at: DateTime<Utc>,
    pub session_expires_at: DateTime<Utc>,
}

/// List of context sessions response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContextSessionListResponse {
    pub items: Vec<ContextSessionSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Summary of a context session.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ContextSessionSummary {
    pub id: Uuid,
    pub switched_at: DateTime<Utc>,
    /// "Persona name" or "Physical User".
    pub from_context: String,
    /// "Persona name" or "Physical User".
    pub to_context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<GovPersonaSession> for ContextSessionSummary {
    fn from(session: GovPersonaSession) -> Self {
        let from_context = if session.previous_persona_id.is_some() {
            "Persona".to_string() // Would be filled with actual name
        } else {
            "Physical User".to_string()
        };

        let to_context = if session.active_persona_id.is_some() {
            "Persona".to_string() // Would be filled with actual name
        } else {
            "Physical User".to_string()
        };

        Self {
            id: session.id,
            switched_at: session.switched_at,
            from_context,
            to_context,
            reason: session.switch_reason,
        }
    }
}

/// Query parameters for listing context sessions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListContextSessionsQuery {
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Audit Models
// ============================================================================

/// Audit event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaAuditEventResponse {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persona_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archetype_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archetype_name: Option<String>,
    pub event_type: PersonaAuditEventType,
    pub actor_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,
    pub event_data: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl From<GovPersonaAuditEvent> for PersonaAuditEventResponse {
    fn from(event: GovPersonaAuditEvent) -> Self {
        Self {
            id: event.id,
            persona_id: event.persona_id,
            persona_name: None,
            archetype_id: event.archetype_id,
            archetype_name: None,
            event_type: event.event_type,
            actor_id: event.actor_id,
            actor_name: None,
            event_data: event.event_data,
            created_at: event.created_at,
        }
    }
}

/// List of audit events response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaAuditListResponse {
    pub items: Vec<PersonaAuditEventResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for searching audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct SearchAuditQuery {
    /// Filter by persona.
    pub persona_id: Option<Uuid>,
    /// Filter by archetype.
    pub archetype_id: Option<Uuid>,
    /// Filter by actor.
    pub actor_id: Option<Uuid>,
    /// Filter by event type.
    pub event_type: Option<PersonaAuditEventType>,
    /// Filter events from this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter events until this date.
    pub to_date: Option<DateTime<Utc>>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Shared Types (re-exported from certification module)
// ============================================================================

// Note: UserSummary and EntitlementSummary are defined in certification.rs
// Import them with: use super::certification::{UserSummary, EntitlementSummary};

/// Summary of a user for persona responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaUserSummary {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Summary of an entitlement for persona responses.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PersonaEntitlementSummary {
    pub id: Uuid,
    pub name: String,
    pub application_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_archetype_request_validation() {
        let request = CreateArchetypeRequest {
            name: "Admin Persona".to_string(),
            description: Some("Elevated privileges".to_string()),
            naming_pattern: "admin.{username}".to_string(),
            attribute_mappings: None,
            default_entitlements: None,
            lifecycle_policy: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_archetype_request_empty_name_fails() {
        let request = CreateArchetypeRequest {
            name: "".to_string(),
            description: None,
            naming_pattern: "admin.{username}".to_string(),
            attribute_mappings: None,
            default_entitlements: None,
            lifecycle_policy: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_deactivate_persona_request_validation() {
        let request = DeactivatePersonaRequest {
            reason: "Project completed".to_string(),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_deactivate_persona_request_short_reason_fails() {
        let request = DeactivatePersonaRequest {
            reason: "end".to_string(), // Too short (< 5 chars)
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_switch_context_request_validation() {
        let request = SwitchContextRequest {
            persona_id: Uuid::new_v4(),
            reason: Some("Administrative task".to_string()),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_lifecycle_policy_defaults() {
        let policy = LifecyclePolicyRequest {
            default_validity_days: default_validity_days(),
            max_validity_days: default_max_validity_days(),
            notification_before_expiry_days: default_notification_days(),
            auto_extension_allowed: false,
            extension_requires_approval: default_true(),
            on_physical_user_deactivation: default_deactivation_action(),
        };

        assert_eq!(policy.default_validity_days, 365);
        assert_eq!(policy.max_validity_days, 730);
        assert!(policy.validate().is_ok());
    }
}
