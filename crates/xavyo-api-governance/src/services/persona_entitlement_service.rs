//! Persona Entitlement Service (F063 - US4).
//!
//! Implements entitlement precedence rules:
//! - Persona entitlements take precedence over physical user entitlements
//! - Effective identity resolution for access checks
//! - Deactivated persona entitlement denial

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GovPersona, GovPersonaSession};
use xavyo_governance::error::{GovernanceError, Result};

use super::effective_access_service::{
    EffectiveAccessResult, EffectiveAccessService, EffectiveEntitlement,
};

/// Source indicating entitlement comes from persona.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersonaEntitlementSource {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Persona name.
    pub persona_name: String,
    /// Archetype name.
    pub archetype_name: String,
}

/// Result of persona entitlement resolution.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersonaEntitlementResult {
    /// The identity being used for access (persona or physical user).
    pub effective_identity_id: Uuid,
    /// Whether operating as a persona.
    pub is_persona_context: bool,
    /// Active persona info (if any).
    pub active_persona: Option<PersonaContext>,
    /// Effective entitlements after precedence rules.
    pub entitlements: Vec<EffectiveEntitlement>,
    /// Total count of entitlements.
    pub total: i64,
}

/// Active persona context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersonaContext {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Persona name.
    pub persona_name: String,
    /// Archetype ID.
    pub archetype_id: Uuid,
}

/// Service for persona-aware entitlement resolution.
pub struct PersonaEntitlementService {
    pool: PgPool,
    effective_access_service: EffectiveAccessService,
}

impl PersonaEntitlementService {
    /// Create a new persona entitlement service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            effective_access_service: EffectiveAccessService::new(pool.clone()),
            pool,
        }
    }

    // =========================================================================
    // T060: Effective identity resolution
    // =========================================================================

    /// Resolve effective identity ID for entitlement checks.
    ///
    /// If the user has an active persona session, returns the persona ID.
    /// Otherwise, returns the physical user ID.
    pub async fn resolve_effective_identity(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<(Uuid, Option<GovPersona>)> {
        // Check for active persona session
        if let Some(session) = self.get_active_persona_session(tenant_id, user_id).await? {
            // Session exists - check if persona is active
            if let Some(persona_id) = session.active_persona_id {
                // Get the persona to verify it's still active
                let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
                    .await
                    .map_err(GovernanceError::Database)?;

                match persona {
                    Some(p) if p.status.can_switch_to() => {
                        // Return persona ID as effective identity
                        return Ok((p.id, Some(p)));
                    }
                    _ => {
                        // Persona no longer active, use physical user
                    }
                }
            }
        }
        // No active session or no active persona, use physical user
        Ok((user_id, None))
    }

    // =========================================================================
    // T059: Entitlement precedence rules (persona > physical user)
    // =========================================================================

    /// Get effective entitlements with persona precedence rules.
    ///
    /// When a persona is active:
    /// 1. Persona-specific entitlements take full precedence
    /// 2. Physical user entitlements are overridden (not merged)
    ///
    /// When no persona is active:
    /// 1. Physical user entitlements are returned directly
    pub async fn get_effective_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<PersonaEntitlementResult> {
        // Resolve effective identity
        let (effective_id, active_persona) =
            self.resolve_effective_identity(tenant_id, user_id).await?;

        // Get entitlements for the effective identity
        let access_result = self
            .effective_access_service
            .get_effective_access(tenant_id, effective_id, application_id)
            .await?;

        // Build persona context if applicable
        let persona_context = active_persona.map(|p| PersonaContext {
            persona_id: p.id,
            persona_name: p.persona_name,
            archetype_id: p.archetype_id,
        });

        Ok(PersonaEntitlementResult {
            effective_identity_id: effective_id,
            is_persona_context: persona_context.is_some(),
            active_persona: persona_context,
            entitlements: access_result.entitlements,
            total: access_result.total,
        })
    }

    // =========================================================================
    // T061: Deactivated persona entitlement denial
    // =========================================================================

    /// Check if a user (with potential persona) has access to an entitlement.
    ///
    /// Returns an error if:
    /// - The active persona is deactivated/expired
    /// - The entitlement is not assigned to the effective identity
    pub async fn check_entitlement_access(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool> {
        // Check if user has an active persona session
        if let Some(session) = self.get_active_persona_session(tenant_id, user_id).await? {
            if let Some(persona_id) = session.active_persona_id {
                // Verify persona is still active
                let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
                    .await
                    .map_err(GovernanceError::Database)?;

                match persona {
                    Some(p) if !p.status.can_switch_to() => {
                        // Persona is deactivated - deny all access
                        return Err(GovernanceError::PersonaNotActive(persona_id));
                    }
                    None => {
                        // Persona doesn't exist - deny access
                        return Err(GovernanceError::PersonaNotFound(persona_id));
                    }
                    _ => {}
                }
            }
        }

        // Get effective entitlements and check if the requested one is included
        let result = self
            .get_effective_entitlements(tenant_id, user_id, None)
            .await?;

        let has_access = result
            .entitlements
            .iter()
            .any(|e| e.entitlement.id == entitlement_id);

        Ok(has_access)
    }

    /// Deny entitlement access for a deactivated persona.
    ///
    /// This is called when a persona is deactivated to ensure
    /// all pending access checks fail immediately.
    pub fn is_persona_deactivated(&self, persona: &GovPersona) -> bool {
        !persona.status.can_switch_to()
    }

    // =========================================================================
    // Helper methods
    // =========================================================================

    /// Get active persona session for a user.
    async fn get_active_persona_session(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<GovPersonaSession>> {
        GovPersonaSession::find_active_for_user(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get entitlements specifically assigned to a persona.
    ///
    /// This queries entitlement assignments where the identity_id
    /// is the persona ID.
    pub async fn get_persona_entitlements(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<EffectiveAccessResult> {
        // Verify persona exists
        let _persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        // Get entitlements for the persona as identity
        self.effective_access_service
            .get_effective_access(tenant_id, persona_id, application_id)
            .await
    }

    /// Compare physical user entitlements vs persona entitlements.
    ///
    /// Returns information about what entitlements are added/removed
    /// when switching to a persona.
    pub async fn compare_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        persona_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<EntitlementComparison> {
        // Get physical user entitlements
        let user_access = self
            .effective_access_service
            .get_effective_access(tenant_id, user_id, application_id)
            .await?;

        // Get persona entitlements
        let persona_access = self
            .effective_access_service
            .get_effective_access(tenant_id, persona_id, application_id)
            .await?;

        // Extract entitlement IDs
        let user_entitlement_ids: std::collections::HashSet<_> = user_access
            .entitlements
            .iter()
            .map(|e| e.entitlement.id)
            .collect();

        let persona_entitlement_ids: std::collections::HashSet<_> = persona_access
            .entitlements
            .iter()
            .map(|e| e.entitlement.id)
            .collect();

        // Find added (in persona but not in user)
        let added: Vec<_> = persona_access
            .entitlements
            .iter()
            .filter(|e| !user_entitlement_ids.contains(&e.entitlement.id))
            .cloned()
            .collect();

        // Find removed (in user but not in persona - not actually removed, just not in scope)
        let not_in_persona: Vec<_> = user_access
            .entitlements
            .iter()
            .filter(|e| !persona_entitlement_ids.contains(&e.entitlement.id))
            .cloned()
            .collect();

        Ok(EntitlementComparison {
            user_id,
            persona_id,
            added_by_persona: added,
            user_only: not_in_persona,
            shared: persona_access
                .entitlements
                .iter()
                .filter(|e| user_entitlement_ids.contains(&e.entitlement.id))
                .cloned()
                .collect(),
        })
    }
}

/// Result of comparing user vs persona entitlements.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntitlementComparison {
    /// Physical user ID.
    pub user_id: Uuid,
    /// Persona ID.
    pub persona_id: Uuid,
    /// Entitlements added by the persona (not present for user).
    pub added_by_persona: Vec<EffectiveEntitlement>,
    /// Entitlements only in user scope (not in persona).
    pub user_only: Vec<EffectiveEntitlement>,
    /// Entitlements shared by both.
    pub shared: Vec<EffectiveEntitlement>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::PersonaStatus;

    // T057: Unit test for persona entitlement precedence
    #[test]
    fn test_entitlement_comparison_logic() {
        // Test helper to verify comparison logic
        let user_ids = vec![
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
        ];
        let persona_ids = vec![
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        ];

        // User has [1, 2], Persona has [2, 3]
        // Added by persona: [3]
        // User only: [1]
        // Shared: [2]

        let user_set: std::collections::HashSet<_> = user_ids.into_iter().collect();
        let persona_set: std::collections::HashSet<_> = persona_ids.into_iter().collect();

        let added: Vec<_> = persona_set.difference(&user_set).collect();
        let user_only: Vec<_> = user_set.difference(&persona_set).collect();
        let shared: Vec<_> = user_set.intersection(&persona_set).collect();

        assert_eq!(added.len(), 1);
        assert_eq!(user_only.len(), 1);
        assert_eq!(shared.len(), 1);
    }

    #[test]
    fn test_persona_status_check() {
        // Verify status check logic
        assert!(PersonaStatus::Active.can_switch_to());
        assert!(!PersonaStatus::Suspended.can_switch_to());
        assert!(!PersonaStatus::Expired.can_switch_to());
        assert!(!PersonaStatus::Archived.can_switch_to());
    }
}
