//! Role Assignment service for F-063: Role Inducements.
//!
//! Provides high-level role assignment operations that:
//! 1. Manage entitlement assignments based on role-entitlement mappings
//! 2. Trigger role constructions when roles are assigned
//! 3. Handle deprovisioning when roles are revoked
//!
//! This service wraps the lower-level `AssignmentService` and integrates
//! with `InducementTriggerService` to implement the construction pattern.

use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovAssignment, GovAssignmentStatus, GovAssignmentTargetType, GovEntitlementAssignment,
    GovRole, GovRoleEntitlement,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::{AssignmentService, InducementTriggerService};

/// Result of a role assignment operation.
#[derive(Debug, Clone)]
pub struct RoleAssignmentResult {
    /// The role that was assigned.
    pub role_id: Uuid,
    /// The user the role was assigned to.
    pub user_id: Uuid,
    /// Entitlement assignments created.
    pub entitlement_assignment_ids: Vec<Uuid>,
    /// Provisioning operation IDs queued from constructions.
    pub provisioning_operation_ids: Vec<Uuid>,
}

/// Result of a role revocation operation.
#[derive(Debug, Clone)]
pub struct RoleRevocationResult {
    /// The role that was revoked.
    pub role_id: Uuid,
    /// The user the role was revoked from.
    pub user_id: Uuid,
    /// Entitlement assignments revoked.
    pub entitlement_assignments_revoked: Vec<Uuid>,
    /// Deprovisioning operation IDs queued.
    pub deprovisioning_operation_ids: Vec<Uuid>,
}

/// Service for role-level assignment operations with construction triggering.
pub struct RoleAssignmentService {
    pool: PgPool,
    assignment_service: AssignmentService,
    inducement_trigger_service: InducementTriggerService,
}

impl RoleAssignmentService {
    /// Create a new role assignment service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            assignment_service: AssignmentService::new(pool.clone()),
            inducement_trigger_service: InducementTriggerService::new(pool.clone()),
            pool,
        }
    }

    /// Assign a role to a user.
    ///
    /// This method:
    /// 1. Verifies the role exists and is assignable (not abstract)
    /// 2. Assigns all entitlements mapped to the role to the user
    /// 3. Triggers provisioning operations for all role constructions
    ///
    /// Returns the assignment result including created assignments and queued operations.
    pub async fn assign_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        assigned_by: Uuid,
        justification: Option<String>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<RoleAssignmentResult> {
        // Verify role exists and is assignable
        let role = GovRole::find_by_id(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::GovRoleNotFound(role_id))?;

        if role.is_abstract {
            return Err(GovernanceError::Validation(format!(
                "Cannot assign abstract role '{}' directly to users",
                role.name
            )));
        }

        // Get entitlements mapped to this role
        let entitlement_ids =
            GovRoleEntitlement::list_entitlement_ids_by_role_id(&self.pool, tenant_id, role_id)
                .await
                .map_err(GovernanceError::Database)?;

        // Assign each entitlement to the user
        let mut entitlement_assignment_ids = Vec::new();
        for entitlement_id in entitlement_ids {
            // Check if already assigned
            if let Some(_existing) = GovEntitlementAssignment::find_by_target(
                &self.pool,
                tenant_id,
                entitlement_id,
                GovAssignmentTargetType::User,
                user_id,
            )
            .await
            .map_err(GovernanceError::Database)?
            {
                // Already assigned, skip
                tracing::debug!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    entitlement_id = %entitlement_id,
                    "Entitlement already assigned, skipping"
                );
                continue;
            }

            let input = CreateGovAssignment {
                entitlement_id,
                target_type: GovAssignmentTargetType::User,
                target_id: user_id,
                assigned_by,
                justification: justification.clone(),
                expires_at,
                parameter_hash: None,
                valid_from: None,
                valid_to: None,
            };

            match self.assignment_service.create(tenant_id, input).await {
                Ok(assignment) => {
                    entitlement_assignment_ids.push(assignment.id);
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        entitlement_id = %entitlement_id,
                        error = %e,
                        "Failed to assign entitlement during role assignment"
                    );
                    // Continue with other entitlements
                }
            }
        }

        // Trigger constructions for the role assignment
        let provisioning_operation_ids = self
            .inducement_trigger_service
            .trigger_constructions_for_assignment(tenant_id, user_id, role_id, Some(assigned_by))
            .await
            .unwrap_or_else(|e| {
                tracing::error!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    role_id = %role_id,
                    error = %e,
                    "Failed to trigger constructions for role assignment"
                );
                Vec::new()
            });

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            role_id = %role_id,
            role_name = %role.name,
            entitlement_count = entitlement_assignment_ids.len(),
            provisioning_count = provisioning_operation_ids.len(),
            assigned_by = %assigned_by,
            "Role assigned with constructions triggered"
        );

        Ok(RoleAssignmentResult {
            role_id,
            user_id,
            entitlement_assignment_ids,
            provisioning_operation_ids,
        })
    }

    /// Revoke a role from a user.
    ///
    /// This method:
    /// 1. Verifies the role exists
    /// 2. Determines which entitlements should be revoked (not needed by other roles)
    /// 3. Revokes those entitlements
    /// 4. Triggers deprovisioning operations based on construction policies
    ///
    /// Returns the revocation result including revoked assignments and queued operations.
    pub async fn revoke_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        revoked_by: Option<Uuid>,
    ) -> Result<RoleRevocationResult> {
        // Verify role exists
        let role = GovRole::find_by_id(&self.pool, tenant_id, role_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::GovRoleNotFound(role_id))?;

        // Get entitlements mapped to this role
        let role_entitlement_ids: HashSet<Uuid> =
            GovRoleEntitlement::list_entitlement_ids_by_role_id(&self.pool, tenant_id, role_id)
                .await
                .map_err(GovernanceError::Database)?
                .into_iter()
                .collect();

        // Get all roles assigned to the user (via entitlement assignments)
        // We need to find which other roles the user has to determine which entitlements to keep
        let other_entitlement_ids = self
            .get_user_entitlement_ids_from_other_roles(tenant_id, user_id, role_id)
            .await?;

        // Determine which entitlements to revoke (only those unique to this role)
        let entitlements_to_revoke: Vec<Uuid> = role_entitlement_ids
            .iter()
            .filter(|ent_id| !other_entitlement_ids.contains(ent_id))
            .copied()
            .collect();

        // Revoke the entitlements
        let mut entitlement_assignments_revoked = Vec::new();
        for entitlement_id in &entitlements_to_revoke {
            // Find the assignment
            if let Some(assignment) = GovEntitlementAssignment::find_by_target(
                &self.pool,
                tenant_id,
                *entitlement_id,
                GovAssignmentTargetType::User,
                user_id,
            )
            .await
            .map_err(GovernanceError::Database)?
            {
                if assignment.status == GovAssignmentStatus::Active {
                    match self
                        .assignment_service
                        .revoke(tenant_id, assignment.id, revoked_by)
                        .await
                    {
                        Ok(()) => {
                            entitlement_assignments_revoked.push(assignment.id);
                        }
                        Err(e) => {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                user_id = %user_id,
                                entitlement_id = %entitlement_id,
                                error = %e,
                                "Failed to revoke entitlement during role revocation"
                            );
                        }
                    }
                }
            }
        }

        // Trigger deprovisioning for the role revocation
        let deprovisioning_operation_ids = self
            .inducement_trigger_service
            .trigger_deprovisioning_for_revocation(tenant_id, user_id, role_id, revoked_by)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    role_id = %role_id,
                    error = %e,
                    "Failed to trigger deprovisioning for role revocation"
                );
                Vec::new()
            });

        tracing::info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            role_id = %role_id,
            role_name = %role.name,
            revoked_count = entitlement_assignments_revoked.len(),
            deprovisioning_count = deprovisioning_operation_ids.len(),
            revoked_by = ?revoked_by,
            "Role revoked with deprovisioning triggered"
        );

        Ok(RoleRevocationResult {
            role_id,
            user_id,
            entitlement_assignments_revoked,
            deprovisioning_operation_ids,
        })
    }

    /// Get user's directly assigned role IDs (based on GovRole entities).
    ///
    /// A user "has" a role if they have all the entitlements mapped to that role.
    /// This is a simplified check - in practice, you might want a dedicated
    /// user-role assignment table for explicit role tracking.
    pub async fn get_user_role_ids(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Uuid>> {
        // Get user's assigned entitlement IDs
        let user_entitlement_ids: HashSet<Uuid> = self
            .assignment_service
            .list_user_entitlement_ids(tenant_id, user_id)
            .await?
            .into_iter()
            .collect();

        if user_entitlement_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Get all non-abstract roles
        let roles = GovRole::list_by_tenant(
            &self.pool,
            tenant_id,
            &xavyo_db::models::GovRoleFilter {
                is_abstract: Some(false),
                ..Default::default()
            },
            1000, // Reasonable limit
            0,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let mut user_role_ids = Vec::new();

        for role in roles {
            // Get entitlements required by this role
            let role_entitlement_ids: HashSet<Uuid> =
                GovRoleEntitlement::list_entitlement_ids_by_role_id(&self.pool, tenant_id, role.id)
                    .await
                    .map_err(GovernanceError::Database)?
                    .into_iter()
                    .collect();

            // If user has ALL entitlements for this role, they have the role
            if !role_entitlement_ids.is_empty()
                && role_entitlement_ids.is_subset(&user_entitlement_ids)
            {
                user_role_ids.push(role.id);
            }
        }

        Ok(user_role_ids)
    }

    /// Check if a user has a specific role.
    pub async fn user_has_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool> {
        let user_role_ids = self.get_user_role_ids(tenant_id, user_id).await?;
        Ok(user_role_ids.contains(&role_id))
    }

    /// Get entitlement IDs that the user has from roles OTHER than the specified role.
    ///
    /// This is used during role revocation to determine which entitlements
    /// should NOT be revoked (because another role still requires them).
    async fn get_user_entitlement_ids_from_other_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        exclude_role_id: Uuid,
    ) -> Result<HashSet<Uuid>> {
        // Get all user's roles
        let user_role_ids = self.get_user_role_ids(tenant_id, user_id).await?;

        let mut other_entitlement_ids = HashSet::new();

        for role_id in user_role_ids {
            if role_id == exclude_role_id {
                continue;
            }

            let entitlement_ids =
                GovRoleEntitlement::list_entitlement_ids_by_role_id(&self.pool, tenant_id, role_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            other_entitlement_ids.extend(entitlement_ids);
        }

        Ok(other_entitlement_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_assignment_result() {
        let result = RoleAssignmentResult {
            role_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_assignment_ids: vec![Uuid::new_v4()],
            provisioning_operation_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        };

        assert!(!result.entitlement_assignment_ids.is_empty());
        assert_eq!(result.provisioning_operation_ids.len(), 2);
    }

    #[test]
    fn test_role_revocation_result() {
        let result = RoleRevocationResult {
            role_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            entitlement_assignments_revoked: vec![Uuid::new_v4()],
            deprovisioning_operation_ids: vec![],
        };

        assert!(!result.entitlement_assignments_revoked.is_empty());
        assert!(result.deprovisioning_operation_ids.is_empty());
    }
}
