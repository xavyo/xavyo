//! Persona authorization service for governance API (F063).
//!
//! Implements execution-phase authorization checks for persona operations.
//! Based on IGA's model: creating a persona = creating a new user,
//! which requires specific authorization.

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::models::{GovPersona, GovPersonaArchetype};
use xavyo_governance::error::{GovernanceError, Result};

/// Permission types for persona operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersonaPermission {
    /// Can create personas (equivalent to creating users in IGA)
    CreatePersona,
    /// Can manage (update/deactivate) own personas
    ManageOwnPersonas,
    /// Can manage any persona (admin)
    ManageAllPersonas,
    /// Can delete/archive personas
    DeletePersona,
    /// Can manage specific archetype
    ManageArchetype,
}

/// Result of an authorization check.
#[derive(Debug, Clone)]
pub struct AuthorizationResult {
    pub authorized: bool,
    pub reason: Option<String>,
    pub requires_approval: bool,
}

impl AuthorizationResult {
    #[must_use]
    pub fn allowed() -> Self {
        Self {
            authorized: true,
            reason: None,
            requires_approval: false,
        }
    }

    #[must_use]
    pub fn denied(reason: &str) -> Self {
        Self {
            authorized: false,
            reason: Some(reason.to_string()),
            requires_approval: false,
        }
    }

    #[must_use]
    pub fn requires_approval(reason: &str) -> Self {
        Self {
            authorized: false,
            reason: Some(reason.to_string()),
            requires_approval: true,
        }
    }
}

/// Service for persona authorization checks.
///
/// Implements IGA-style execution-phase authorization:
/// - Creating a persona means creating a new virtual user
/// - User must have explicit authorization for persona creation
/// - Archetype-specific authorizations can restrict which personas a user can manage
pub struct PersonaAuthorizationService {
    pool: PgPool,
}

impl PersonaAuthorizationService {
    /// Create a new authorization service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if user can create a persona.
    ///
    /// In IGA pattern: "Assignment of a new persona means that a new user needs to be created.
    /// The authorization for this operation is evaluated in the usual way."
    pub async fn can_create_persona(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        archetype_id: Uuid,
        target_user_id: Uuid,
    ) -> Result<AuthorizationResult> {
        // Check 1: Is actor creating persona for themselves?
        let is_self_assignment = actor_id == target_user_id;

        // Check 2: Does actor have persona creation permission?
        let has_create_permission = self
            .check_permission(tenant_id, actor_id, PersonaPermission::CreatePersona)
            .await?;

        // Check 3: Is actor authorized for this specific archetype?
        let archetype_authorized = self
            .check_archetype_permission(tenant_id, actor_id, archetype_id)
            .await?;

        // Self-assignment requires explicit persona creation authorization
        // (IGA pattern: "execution-phase authorizations to create new users are not part of default End User role")
        if is_self_assignment && !has_create_permission {
            warn!(
                tenant_id = %tenant_id,
                actor_id = %actor_id,
                archetype_id = %archetype_id,
                "Self-assignment of persona denied - user lacks persona creation permission"
            );
            return Ok(AuthorizationResult::denied(
                "Self-assignment of personas requires explicit persona creation permission",
            ));
        }

        // Non-self assignment requires manage-all permission
        if !is_self_assignment
            && !self
                .check_permission(tenant_id, actor_id, PersonaPermission::ManageAllPersonas)
                .await?
        {
            warn!(
                tenant_id = %tenant_id,
                actor_id = %actor_id,
                target_user_id = %target_user_id,
                "Persona creation for other user denied - lacks manage-all permission"
            );
            return Ok(AuthorizationResult::denied(
                "Creating personas for other users requires admin permission",
            ));
        }

        // Archetype-specific check
        if !archetype_authorized {
            warn!(
                tenant_id = %tenant_id,
                actor_id = %actor_id,
                archetype_id = %archetype_id,
                "Persona creation denied - not authorized for archetype"
            );
            return Ok(AuthorizationResult::denied(
                "Not authorized to create personas of this archetype",
            ));
        }

        info!(
            tenant_id = %tenant_id,
            actor_id = %actor_id,
            archetype_id = %archetype_id,
            target_user_id = %target_user_id,
            is_self = is_self_assignment,
            "Persona creation authorized"
        );

        Ok(AuthorizationResult::allowed())
    }

    /// Check if user can manage (update/deactivate) a persona.
    pub async fn can_manage_persona(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
    ) -> Result<AuthorizationResult> {
        // Get the persona to check ownership
        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        // Owner can manage their own personas
        if persona.physical_user_id == actor_id {
            let has_permission = self
                .check_permission(tenant_id, actor_id, PersonaPermission::ManageOwnPersonas)
                .await?;
            if has_permission {
                return Ok(AuthorizationResult::allowed());
            }
        }

        // Admin can manage any persona
        let has_admin = self
            .check_permission(tenant_id, actor_id, PersonaPermission::ManageAllPersonas)
            .await?;
        if has_admin {
            return Ok(AuthorizationResult::allowed());
        }

        Ok(AuthorizationResult::denied(
            "Not authorized to manage this persona",
        ))
    }

    /// Check if user can delete/archive a persona.
    pub async fn can_delete_persona(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        persona_id: Uuid,
    ) -> Result<AuthorizationResult> {
        // Get the persona
        let persona = GovPersona::find_by_id(&self.pool, tenant_id, persona_id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        // Check delete permission
        let has_delete = self
            .check_permission(tenant_id, actor_id, PersonaPermission::DeletePersona)
            .await?;

        // Owner with delete permission can delete own personas
        if persona.physical_user_id == actor_id && has_delete {
            return Ok(AuthorizationResult::allowed());
        }

        // Admin can delete any persona
        let has_admin = self
            .check_permission(tenant_id, actor_id, PersonaPermission::ManageAllPersonas)
            .await?;
        if has_admin {
            return Ok(AuthorizationResult::allowed());
        }

        Ok(AuthorizationResult::denied(
            "Not authorized to delete this persona",
        ))
    }

    /// Check if an operation would trigger an approval workflow.
    ///
    /// In IGA pattern: "The operation that automatically provisions, deprovisions or updates
    /// a persona must not be subject to approvals."
    pub async fn check_approval_conflict(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
        _operation: &str,
    ) -> Result<bool> {
        // Check if archetype has any assignments that would trigger approval
        let archetype = GovPersonaArchetype::find_by_id(&self.pool, tenant_id, archetype_id)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(archetype_id))?;

        // Check default_entitlements for any that require approval
        if let Some(ref entitlements) = archetype.default_entitlements {
            if let Some(arr) = entitlements.as_array() {
                for ent in arr {
                    if let Some(requires_approval) = ent.get("requires_approval") {
                        if requires_approval.as_bool().unwrap_or(false) {
                            warn!(
                                tenant_id = %tenant_id,
                                archetype_id = %archetype_id,
                                "Archetype has entitlements requiring approval - persona operations may behave unpredictably"
                            );
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    // =========================================================================
    // Internal permission checking
    // =========================================================================

    /// Check if user has a specific permission.
    ///
    /// NOTE: This is a simplified implementation. In production, this would
    /// integrate with the full RBAC/entitlement system.
    async fn check_permission(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        permission: PersonaPermission,
    ) -> Result<bool> {
        // For now, we grant basic permissions to all authenticated users
        // In production, this would check:
        // 1. User's roles/entitlements
        // 2. Delegated admin permissions
        // 3. Archetype-specific grants

        match permission {
            // Self-management of own personas is allowed by default
            PersonaPermission::ManageOwnPersonas => Ok(true),
            // Creating personas requires explicit grant (would check entitlements)
            // For now, allow authenticated users to create their own personas
            PersonaPermission::CreatePersona => Ok(true),
            // Admin permissions would require role check
            PersonaPermission::ManageAllPersonas => {
                // TODO: Check if user has admin role
                // For now, return false (requires explicit admin grant)
                Ok(false)
            }
            PersonaPermission::DeletePersona => {
                // TODO: Check if user has delete permission
                Ok(true)
            }
            PersonaPermission::ManageArchetype => {
                // TODO: Check archetype-specific permissions
                Ok(true)
            }
        }
    }

    /// Check if user is authorized for a specific archetype.
    async fn check_archetype_permission(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        _archetype_id: Uuid,
    ) -> Result<bool> {
        // In production, this would check:
        // 1. If archetype has restricted access
        // 2. If user has been granted access to this archetype
        // 3. If user's role allows creating this type of persona

        // For now, all active archetypes are accessible
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_result_allowed() {
        let result = AuthorizationResult::allowed();
        assert!(result.authorized);
        assert!(result.reason.is_none());
        assert!(!result.requires_approval);
    }

    #[test]
    fn test_authorization_result_denied() {
        let result = AuthorizationResult::denied("Test reason");
        assert!(!result.authorized);
        assert_eq!(result.reason, Some("Test reason".to_string()));
        assert!(!result.requires_approval);
    }

    #[test]
    fn test_authorization_result_requires_approval() {
        let result = AuthorizationResult::requires_approval("Needs approval");
        assert!(!result.authorized);
        assert!(result.requires_approval);
    }
}
