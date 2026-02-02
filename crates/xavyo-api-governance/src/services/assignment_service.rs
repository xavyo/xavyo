//! Assignment service for governance API.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    BulkAssignmentFailure, BulkAssignmentRequest, BulkAssignmentResult, CreateGovAssignment,
    CreateManualTask, GovApplication, GovAssignmentFilter, GovAssignmentStatus,
    GovAssignmentTargetType, GovEntitlement, GovEntitlementAssignment, GovManualProvisioningTask,
    GovSlaPolicy, GovSodExemption, GovSodRule, ManualTaskOperation,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::EffectiveAccessService;

/// Service for governance assignment operations.
pub struct AssignmentService {
    pool: PgPool,
    effective_access_service: EffectiveAccessService,
}

impl AssignmentService {
    /// Create a new assignment service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            effective_access_service: EffectiveAccessService::new(pool.clone()),
            pool,
        }
    }

    /// List assignments for a tenant with pagination and filtering.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_assignments(
        &self,
        tenant_id: Uuid,
        entitlement_id: Option<Uuid>,
        target_type: Option<GovAssignmentTargetType>,
        target_id: Option<Uuid>,
        status: Option<GovAssignmentStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovEntitlementAssignment>, i64)> {
        let filter = GovAssignmentFilter {
            entitlement_id,
            target_type,
            target_id,
            status,
            assigned_by: None,
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            GovEntitlementAssignment::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((assignments, total))
    }

    /// Get an assignment by ID.
    pub async fn get_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<GovEntitlementAssignment> {
        GovEntitlementAssignment::find_by_id(&self.pool, tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))
    }

    /// Create a new assignment.
    pub async fn create_assignment(
        &self,
        tenant_id: Uuid,
        input: CreateGovAssignment,
    ) -> Result<GovEntitlementAssignment> {
        // Verify entitlement exists and is active
        let entitlement =
            GovEntitlement::find_by_id(&self.pool, tenant_id, input.entitlement_id).await?;
        let entitlement = match entitlement {
            None => {
                return Err(GovernanceError::EntitlementNotFound(input.entitlement_id));
            }
            Some(ent) if !ent.is_active() => {
                return Err(GovernanceError::Validation(
                    "Cannot assign inactive entitlement".to_string(),
                ));
            }
            Some(ent) => ent,
        };

        // Check for existing assignment
        if let Some(_existing) = GovEntitlementAssignment::find_by_target(
            &self.pool,
            tenant_id,
            input.entitlement_id,
            input.target_type,
            input.target_id,
        )
        .await?
        {
            return Err(GovernanceError::AssignmentAlreadyExists);
        }

        // Validate expiration date if provided
        if let Some(expires_at) = input.expires_at {
            if expires_at <= Utc::now() {
                return Err(GovernanceError::InvalidExpirationDate);
            }
        }

        // SoD Check: For user assignments, check for conflicts
        if input.target_type == GovAssignmentTargetType::User {
            self.check_sod_for_user(tenant_id, input.target_id, input.entitlement_id)
                .await?;
        }

        // Store target info before creating assignment
        let target_type = input.target_type;
        let target_id = input.target_id;

        let assignment = GovEntitlementAssignment::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // F064: Create manual provisioning task if application is semi-manual
        // Only for user assignments (not group assignments)
        if target_type == GovAssignmentTargetType::User {
            if let Err(e) = self
                .create_manual_task_if_needed(
                    tenant_id,
                    assignment.id,
                    entitlement.application_id,
                    target_id,
                    entitlement.id,
                    ManualTaskOperation::Grant,
                )
                .await
            {
                // Log error but don't fail the assignment - task creation is best-effort
                tracing::warn!(
                    tenant_id = %tenant_id,
                    assignment_id = %assignment.id,
                    error = %e,
                    "Failed to create manual provisioning task for semi-manual resource"
                );
            }
        }

        Ok(assignment)
    }

    /// Check if application is semi-manual and create a manual provisioning task if needed.
    ///
    /// This implements FR-003 of F064: System MUST automatically generate manual provisioning
    /// tasks when entitlements are assigned to semi-manual resources.
    async fn create_manual_task_if_needed(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        application_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        operation: ManualTaskOperation,
    ) -> Result<Option<GovManualProvisioningTask>> {
        // Check if application is semi-manual
        let application = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        if !application.is_semi_manual {
            return Ok(None);
        }

        // Calculate SLA deadline from default policy if available
        let sla_deadline = if let Some(sla_policy_id) = application.sla_policy_id {
            match GovSlaPolicy::find_by_id(&self.pool, tenant_id, sla_policy_id).await {
                Ok(Some(policy)) if policy.is_active => Some(policy.deadline_from(Utc::now())),
                _ => None,
            }
        } else {
            None
        };

        // Create the manual provisioning task
        let create_task = CreateManualTask {
            assignment_id,
            application_id,
            user_id,
            entitlement_id,
            operation_type: operation,
            sla_deadline,
        };

        let task = GovManualProvisioningTask::create(&self.pool, tenant_id, create_task)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %task.id,
            assignment_id = %assignment_id,
            application_id = %application_id,
            sla_deadline = ?sla_deadline,
            "Created manual provisioning task for semi-manual resource"
        );

        Ok(Some(task))
    }

    /// Check SoD rules for a user assignment.
    ///
    /// Returns an error if the assignment would violate an SoD rule without exemption.
    async fn check_sod_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<()> {
        // Find all active SoD rules involving this entitlement
        let rules = GovSodRule::find_active_by_entitlement(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)?;

        if rules.is_empty() {
            return Ok(());
        }

        // Get user's effective entitlements
        let effective_access = self
            .effective_access_service
            .get_effective_access(tenant_id, user_id, None)
            .await?;

        let user_entitlements: std::collections::HashSet<Uuid> = effective_access
            .entitlements
            .iter()
            .map(|e| e.entitlement.id)
            .collect();

        for rule in rules {
            let conflicting_id = rule
                .get_conflicting_entitlement(entitlement_id)
                .expect("Rule should contain the entitlement");

            // Check if user has the conflicting entitlement
            if user_entitlements.contains(&conflicting_id) {
                // Check for exemption
                let has_exemption =
                    GovSodExemption::has_active_exemption(&self.pool, tenant_id, rule.id, user_id)
                        .await
                        .map_err(GovernanceError::Database)?;

                if !has_exemption {
                    return Err(GovernanceError::SodViolationBlocked {
                        rule_id: rule.id,
                        rule_name: rule.name,
                        severity: format!("{:?}", rule.severity).to_lowercase(),
                        conflicting_entitlement_id: conflicting_id,
                    });
                }
            }
        }

        Ok(())
    }

    /// Create multiple assignments in bulk.
    pub async fn bulk_create_assignments(
        &self,
        tenant_id: Uuid,
        request: BulkAssignmentRequest,
    ) -> Result<BulkAssignmentResult> {
        // Verify entitlement exists and is active
        let entitlement =
            GovEntitlement::find_by_id(&self.pool, tenant_id, request.entitlement_id).await?;
        let entitlement = match entitlement {
            None => {
                return Err(GovernanceError::EntitlementNotFound(request.entitlement_id));
            }
            Some(ent) if !ent.is_active() => {
                return Err(GovernanceError::Validation(
                    "Cannot assign inactive entitlement".to_string(),
                ));
            }
            Some(ent) => ent,
        };

        // Validate expiration date if provided
        if let Some(expires_at) = request.expires_at {
            if expires_at <= Utc::now() {
                return Err(GovernanceError::InvalidExpirationDate);
            }
        }

        let mut successful = Vec::new();
        let mut failed = Vec::new();

        for target_id in request.target_ids {
            let input = CreateGovAssignment {
                entitlement_id: request.entitlement_id,
                target_type: request.target_type,
                target_id,
                assigned_by: request.assigned_by,
                expires_at: request.expires_at,
                justification: request.justification.clone(),
                parameter_hash: None,
                valid_from: None,
                valid_to: None,
            };

            // Check for existing assignment
            if GovEntitlementAssignment::find_by_target(
                &self.pool,
                tenant_id,
                input.entitlement_id,
                input.target_type,
                input.target_id,
            )
            .await?
            .is_some()
            {
                failed.push(BulkAssignmentFailure {
                    target_id,
                    reason: "Assignment already exists".to_string(),
                });
                continue;
            }

            // SoD Check for user assignments
            if input.target_type == GovAssignmentTargetType::User {
                if let Err(e) = self
                    .check_sod_for_user(tenant_id, target_id, input.entitlement_id)
                    .await
                {
                    failed.push(BulkAssignmentFailure {
                        target_id,
                        reason: e.to_string(),
                    });
                    continue;
                }
            }

            match GovEntitlementAssignment::create(&self.pool, tenant_id, input).await {
                Ok(assignment) => {
                    // F064: Create manual provisioning task if application is semi-manual
                    // Only for user assignments
                    if request.target_type == GovAssignmentTargetType::User {
                        if let Err(e) = self
                            .create_manual_task_if_needed(
                                tenant_id,
                                assignment.id,
                                entitlement.application_id,
                                target_id,
                                entitlement.id,
                                ManualTaskOperation::Grant,
                            )
                            .await
                        {
                            tracing::warn!(
                                tenant_id = %tenant_id,
                                assignment_id = %assignment.id,
                                error = %e,
                                "Failed to create manual provisioning task in bulk assignment"
                            );
                        }
                    }
                    successful.push(assignment.id);
                }
                Err(e) => {
                    failed.push(BulkAssignmentFailure {
                        target_id,
                        reason: e.to_string(),
                    });
                }
            }
        }

        Ok(BulkAssignmentResult { successful, failed })
    }

    /// Revoke (delete) an assignment.
    pub async fn revoke_assignment(&self, tenant_id: Uuid, assignment_id: Uuid) -> Result<()> {
        // Verify assignment exists and get its details
        let existing = self.get_assignment(tenant_id, assignment_id).await?;

        // F064: Create revocation task for semi-manual resources before deleting
        // Only for user assignments
        if existing.target_type == GovAssignmentTargetType::User {
            // Get entitlement to find application
            if let Ok(Some(entitlement)) =
                GovEntitlement::find_by_id(&self.pool, tenant_id, existing.entitlement_id).await
            {
                if let Err(e) = self
                    .create_manual_task_if_needed(
                        tenant_id,
                        assignment_id,
                        entitlement.application_id,
                        existing.target_id,
                        entitlement.id,
                        ManualTaskOperation::Revoke,
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        assignment_id = %assignment_id,
                        error = %e,
                        "Failed to create revocation task for semi-manual resource"
                    );
                }
            }
        }

        let deleted =
            GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::AssignmentNotFound(assignment_id))
        }
    }

    /// Suspend an assignment.
    pub async fn suspend_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<GovEntitlementAssignment> {
        // Verify assignment exists
        let existing = self.get_assignment(tenant_id, assignment_id).await?;

        let result = GovEntitlementAssignment::suspend(&self.pool, tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))?;

        // F064: Create modify task for semi-manual resources (suspend = revoke access)
        if existing.target_type == GovAssignmentTargetType::User {
            if let Ok(Some(entitlement)) =
                GovEntitlement::find_by_id(&self.pool, tenant_id, existing.entitlement_id).await
            {
                if let Err(e) = self
                    .create_manual_task_if_needed(
                        tenant_id,
                        assignment_id,
                        entitlement.application_id,
                        existing.target_id,
                        entitlement.id,
                        ManualTaskOperation::Revoke, // Suspend = temporarily revoke
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        assignment_id = %assignment_id,
                        error = %e,
                        "Failed to create suspend task for semi-manual resource"
                    );
                }
            }
        }

        Ok(result)
    }

    /// Reactivate a suspended assignment.
    pub async fn reactivate_assignment(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
    ) -> Result<GovEntitlementAssignment> {
        // Verify assignment exists
        let existing = self.get_assignment(tenant_id, assignment_id).await?;

        let result = GovEntitlementAssignment::reactivate(&self.pool, tenant_id, assignment_id)
            .await?
            .ok_or(GovernanceError::AssignmentNotFound(assignment_id))?;

        // F064: Create modify task for semi-manual resources (reactivate = re-grant access)
        if existing.target_type == GovAssignmentTargetType::User {
            if let Ok(Some(entitlement)) =
                GovEntitlement::find_by_id(&self.pool, tenant_id, existing.entitlement_id).await
            {
                if let Err(e) = self
                    .create_manual_task_if_needed(
                        tenant_id,
                        assignment_id,
                        entitlement.application_id,
                        existing.target_id,
                        entitlement.id,
                        ManualTaskOperation::Grant, // Reactivate = re-grant
                    )
                    .await
                {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        assignment_id = %assignment_id,
                        error = %e,
                        "Failed to create reactivate task for semi-manual resource"
                    );
                }
            }
        }

        Ok(result)
    }

    /// List entitlement IDs for a user (direct assignments only).
    pub async fn list_user_entitlement_ids(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        GovEntitlementAssignment::list_user_entitlement_ids(&self.pool, tenant_id, user_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List active assignments for a user (full assignment objects).
    pub async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        let filter = GovAssignmentFilter {
            entitlement_id: None,
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            status: Some(GovAssignmentStatus::Active),
            assigned_by: None,
        };

        let (assignments, _) =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await
                .map(|a| (a, 0i64))?;

        Ok(assignments)
    }

    /// Create a new assignment (simplified for lifecycle automation).
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateGovAssignment,
    ) -> Result<GovEntitlementAssignment> {
        self.create_assignment(tenant_id, input).await
    }

    /// Revoke an assignment by ID (simplified for lifecycle automation).
    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        assignment_id: Uuid,
        _revoked_by: Option<Uuid>,
    ) -> Result<()> {
        self.revoke_assignment(tenant_id, assignment_id).await
    }

    /// List entitlement IDs for a group.
    pub async fn list_group_entitlement_ids(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        GovEntitlementAssignment::list_group_entitlement_ids(&self.pool, tenant_id, group_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Expire assignments past their expiration date.
    pub async fn expire_past_due(&self, tenant_id: Uuid) -> Result<u64> {
        GovEntitlementAssignment::expire_past_due(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_service_creation() {
        // This test just verifies the service can be instantiated
        // Real tests would require a database connection
    }
}
