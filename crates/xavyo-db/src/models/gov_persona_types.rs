//! Persona type definitions (F063).
//!
//! Shared enums for persona management: status, link types, and audit event types.

use serde::{Deserialize, Serialize};

/// Persona lifecycle status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "persona_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PersonaStatus {
    /// Created but not yet active.
    #[default]
    Draft,
    /// Fully operational.
    Active,
    /// Within notification window of expiration.
    Expiring,
    /// Past valid_until, auto-deactivated.
    Expired,
    /// Manually suspended.
    Suspended,
    /// Soft-deleted, preserved for audit.
    Archived,
}

/// Persona link type (relationship between physical user and persona).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "persona_link_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PersonaLinkType {
    /// Primary ownership link.
    #[default]
    Owner,
    /// Delegated access (future use).
    Delegate,
}

/// Persona audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "persona_audit_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PersonaAuditEventType {
    /// Archetype was created.
    ArchetypeCreated,
    /// Archetype was updated.
    ArchetypeUpdated,
    /// Archetype was deleted.
    ArchetypeDeleted,
    /// Persona was created.
    PersonaCreated,
    /// Persona was activated.
    PersonaActivated,
    /// Persona was deactivated.
    PersonaDeactivated,
    /// Persona expired (validity ended).
    PersonaExpired,
    /// Persona validity was extended.
    PersonaExtended,
    /// Persona was archived.
    PersonaArchived,
    /// User switched to a persona context.
    ContextSwitched,
    /// User switched back from persona to physical user.
    ContextSwitchedBack,
    /// Attributes were propagated from physical user.
    AttributesPropagated,
    /// Entitlement was added to persona.
    EntitlementAdded,
    /// Entitlement was removed from persona.
    EntitlementRemoved,
}

impl PersonaStatus {
    /// Check if this status represents a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Archived)
    }

    /// Check if this status allows context switching.
    pub fn can_switch_to(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if this status can be activated.
    pub fn can_activate(&self) -> bool {
        matches!(self, Self::Draft | Self::Suspended | Self::Expired)
    }

    /// Check if this status can be deactivated.
    pub fn can_deactivate(&self) -> bool {
        matches!(self, Self::Active | Self::Expiring)
    }

    /// Check if this status can be archived.
    pub fn can_archive(&self) -> bool {
        !matches!(self, Self::Archived)
    }

    /// Check if this is an active operational status.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Expiring)
    }
}

impl PersonaLinkType {
    /// Check if this link type grants full control.
    pub fn has_full_control(&self) -> bool {
        matches!(self, Self::Owner)
    }
}

impl PersonaAuditEventType {
    /// Check if this event type relates to archetypes.
    pub fn is_archetype_event(&self) -> bool {
        matches!(
            self,
            Self::ArchetypeCreated | Self::ArchetypeUpdated | Self::ArchetypeDeleted
        )
    }

    /// Check if this event type relates to personas.
    pub fn is_persona_event(&self) -> bool {
        matches!(
            self,
            Self::PersonaCreated
                | Self::PersonaActivated
                | Self::PersonaDeactivated
                | Self::PersonaExpired
                | Self::PersonaExtended
                | Self::PersonaArchived
        )
    }

    /// Check if this event type relates to context switching.
    pub fn is_context_event(&self) -> bool {
        matches!(self, Self::ContextSwitched | Self::ContextSwitchedBack)
    }

    /// Check if this event type relates to entitlements.
    pub fn is_entitlement_event(&self) -> bool {
        matches!(self, Self::EntitlementAdded | Self::EntitlementRemoved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persona_status_serialization() {
        let draft = PersonaStatus::Draft;
        let json = serde_json::to_string(&draft).unwrap();
        assert_eq!(json, "\"draft\"");

        let active = PersonaStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let expiring = PersonaStatus::Expiring;
        let json = serde_json::to_string(&expiring).unwrap();
        assert_eq!(json, "\"expiring\"");

        let archived = PersonaStatus::Archived;
        let json = serde_json::to_string(&archived).unwrap();
        assert_eq!(json, "\"archived\"");
    }

    #[test]
    fn test_persona_status_deserialization() {
        let draft: PersonaStatus = serde_json::from_str("\"draft\"").unwrap();
        assert_eq!(draft, PersonaStatus::Draft);

        let active: PersonaStatus = serde_json::from_str("\"active\"").unwrap();
        assert_eq!(active, PersonaStatus::Active);
    }

    #[test]
    fn test_persona_link_type_serialization() {
        let owner = PersonaLinkType::Owner;
        let json = serde_json::to_string(&owner).unwrap();
        assert_eq!(json, "\"owner\"");

        let delegate = PersonaLinkType::Delegate;
        let json = serde_json::to_string(&delegate).unwrap();
        assert_eq!(json, "\"delegate\"");
    }

    #[test]
    fn test_audit_event_type_serialization() {
        let created = PersonaAuditEventType::ArchetypeCreated;
        let json = serde_json::to_string(&created).unwrap();
        assert_eq!(json, "\"archetype_created\"");

        let switched = PersonaAuditEventType::ContextSwitched;
        let json = serde_json::to_string(&switched).unwrap();
        assert_eq!(json, "\"context_switched\"");

        let propagated = PersonaAuditEventType::AttributesPropagated;
        let json = serde_json::to_string(&propagated).unwrap();
        assert_eq!(json, "\"attributes_propagated\"");
    }

    #[test]
    fn test_persona_status_can_switch_to() {
        assert!(!PersonaStatus::Draft.can_switch_to());
        assert!(PersonaStatus::Active.can_switch_to());
        assert!(!PersonaStatus::Expiring.can_switch_to());
        assert!(!PersonaStatus::Expired.can_switch_to());
        assert!(!PersonaStatus::Suspended.can_switch_to());
        assert!(!PersonaStatus::Archived.can_switch_to());
    }

    #[test]
    fn test_persona_status_can_activate() {
        assert!(PersonaStatus::Draft.can_activate());
        assert!(!PersonaStatus::Active.can_activate());
        assert!(!PersonaStatus::Expiring.can_activate());
        assert!(PersonaStatus::Expired.can_activate());
        assert!(PersonaStatus::Suspended.can_activate());
        assert!(!PersonaStatus::Archived.can_activate());
    }

    #[test]
    fn test_persona_status_can_deactivate() {
        assert!(!PersonaStatus::Draft.can_deactivate());
        assert!(PersonaStatus::Active.can_deactivate());
        assert!(PersonaStatus::Expiring.can_deactivate());
        assert!(!PersonaStatus::Expired.can_deactivate());
        assert!(!PersonaStatus::Suspended.can_deactivate());
        assert!(!PersonaStatus::Archived.can_deactivate());
    }

    #[test]
    fn test_persona_status_is_terminal() {
        assert!(!PersonaStatus::Draft.is_terminal());
        assert!(!PersonaStatus::Active.is_terminal());
        assert!(!PersonaStatus::Expiring.is_terminal());
        assert!(!PersonaStatus::Expired.is_terminal());
        assert!(!PersonaStatus::Suspended.is_terminal());
        assert!(PersonaStatus::Archived.is_terminal());
    }

    #[test]
    fn test_persona_status_is_active() {
        assert!(!PersonaStatus::Draft.is_active());
        assert!(PersonaStatus::Active.is_active());
        assert!(PersonaStatus::Expiring.is_active());
        assert!(!PersonaStatus::Expired.is_active());
        assert!(!PersonaStatus::Suspended.is_active());
        assert!(!PersonaStatus::Archived.is_active());
    }

    #[test]
    fn test_persona_link_type_has_full_control() {
        assert!(PersonaLinkType::Owner.has_full_control());
        assert!(!PersonaLinkType::Delegate.has_full_control());
    }

    #[test]
    fn test_audit_event_type_is_archetype_event() {
        assert!(PersonaAuditEventType::ArchetypeCreated.is_archetype_event());
        assert!(PersonaAuditEventType::ArchetypeUpdated.is_archetype_event());
        assert!(PersonaAuditEventType::ArchetypeDeleted.is_archetype_event());
        assert!(!PersonaAuditEventType::PersonaCreated.is_archetype_event());
    }

    #[test]
    fn test_audit_event_type_is_persona_event() {
        assert!(!PersonaAuditEventType::ArchetypeCreated.is_persona_event());
        assert!(PersonaAuditEventType::PersonaCreated.is_persona_event());
        assert!(PersonaAuditEventType::PersonaActivated.is_persona_event());
        assert!(PersonaAuditEventType::PersonaDeactivated.is_persona_event());
        assert!(PersonaAuditEventType::PersonaExpired.is_persona_event());
        assert!(PersonaAuditEventType::PersonaExtended.is_persona_event());
        assert!(PersonaAuditEventType::PersonaArchived.is_persona_event());
    }

    #[test]
    fn test_audit_event_type_is_context_event() {
        assert!(PersonaAuditEventType::ContextSwitched.is_context_event());
        assert!(PersonaAuditEventType::ContextSwitchedBack.is_context_event());
        assert!(!PersonaAuditEventType::PersonaCreated.is_context_event());
    }

    #[test]
    fn test_audit_event_type_is_entitlement_event() {
        assert!(PersonaAuditEventType::EntitlementAdded.is_entitlement_event());
        assert!(PersonaAuditEventType::EntitlementRemoved.is_entitlement_event());
        assert!(!PersonaAuditEventType::PersonaCreated.is_entitlement_event());
    }

    #[test]
    fn test_default_persona_status() {
        let status = PersonaStatus::default();
        assert_eq!(status, PersonaStatus::Draft);
    }

    #[test]
    fn test_default_persona_link_type() {
        let link_type = PersonaLinkType::default();
        assert_eq!(link_type, PersonaLinkType::Owner);
    }
}
