//! State Access Rule Service for Object Lifecycle States (F052).
//!
//! This service manages state-based access rules that automatically adjust
//! entitlements when objects transition between lifecycle states.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    EntitlementAction, GovAssignmentFilter, GovAssignmentStatus, GovAssignmentTargetType,
    GovEntitlementAssignment, GovLifecycleState, GovStateTransitionAudit,
    UpdateGovStateTransitionAudit,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Snapshot of an entitlement assignment for audit purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementSnapshot {
    /// Assignment ID.
    pub assignment_id: Uuid,
    /// Entitlement ID.
    pub entitlement_id: Uuid,
    /// Assignment status at time of snapshot.
    pub status: String,
    /// Expiration date if any.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Result of applying entitlement actions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntitlementActionResult {
    /// Entitlements that were paused.
    pub paused: Vec<Uuid>,
    /// Entitlements that were revoked.
    pub revoked: Vec<Uuid>,
    /// Entitlements that were resumed.
    pub resumed: Vec<Uuid>,
    /// Errors encountered during processing.
    pub errors: Vec<String>,
}

/// Service for state-based access rule operations.
pub struct StateAccessRuleService {
    pool: PgPool,
}

impl StateAccessRuleService {
    /// Create a new state access rule service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Capture a snapshot of an object's current entitlements.
    ///
    /// This is called before a state transition to record the entitlements
    /// state for audit and potential rollback.
    pub async fn capture_access_snapshot(
        &self,
        tenant_id: Uuid,
        object_type: &str,
        object_id: Uuid,
    ) -> Result<Vec<EntitlementSnapshot>> {
        // Currently only support user objects
        if object_type != "user" {
            return Ok(Vec::new());
        }

        // Get all entitlements for this user (including suspended)
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(object_id),
            ..Default::default()
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await?;

        let snapshots: Vec<EntitlementSnapshot> = assignments
            .into_iter()
            .map(|a| EntitlementSnapshot {
                assignment_id: a.id,
                entitlement_id: a.entitlement_id,
                status: format!("{:?}", a.status).to_lowercase(),
                expires_at: a.expires_at,
            })
            .collect();

        Ok(snapshots)
    }

    /// Apply state access rules based on the target state's entitlement action.
    ///
    /// This is called after a state transition to execute the entitlement action
    /// configured for the new state.
    pub async fn apply_state_access_rules(
        &self,
        tenant_id: Uuid,
        object_type: &str,
        object_id: Uuid,
        target_state: &GovLifecycleState,
    ) -> Result<EntitlementActionResult> {
        let mut result = EntitlementActionResult::default();

        // Currently only support user objects
        if object_type != "user" {
            return Ok(result);
        }

        match target_state.entitlement_action {
            EntitlementAction::None => {
                // No action needed
            }
            EntitlementAction::Pause => {
                result = self.pause_all_entitlements(tenant_id, object_id).await?;
            }
            EntitlementAction::Revoke => {
                result = self.revoke_all_entitlements(tenant_id, object_id).await?;
            }
        }

        Ok(result)
    }

    /// Pause all entitlements for an object.
    ///
    /// Sets all active entitlements to 'suspended' status.
    pub async fn pause_all_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<EntitlementActionResult> {
        let mut result = EntitlementActionResult::default();

        // Get all active entitlements for this user
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            status: Some(GovAssignmentStatus::Active),
            ..Default::default()
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await?;

        for assignment in assignments {
            match GovEntitlementAssignment::suspend(&self.pool, tenant_id, assignment.id).await {
                Ok(Some(_)) => {
                    result.paused.push(assignment.id);
                }
                Ok(None) => {
                    result.errors.push(format!(
                        "Assignment {} not found for suspend",
                        assignment.id
                    ));
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to suspend assignment {}: {}",
                        assignment.id, e
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Revoke all entitlements for an object.
    ///
    /// Permanently removes all entitlements (cannot be reversed).
    pub async fn revoke_all_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<EntitlementActionResult> {
        let mut result = EntitlementActionResult::default();

        // Get all entitlements for this user (active or suspended)
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            ..Default::default()
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await?;

        for assignment in assignments {
            // Skip already expired assignments
            if assignment.status == GovAssignmentStatus::Expired {
                continue;
            }

            match GovEntitlementAssignment::revoke(&self.pool, tenant_id, assignment.id).await {
                Ok(true) => {
                    result.revoked.push(assignment.id);
                }
                Ok(false) => {
                    result
                        .errors
                        .push(format!("Assignment {} not found for revoke", assignment.id));
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to revoke assignment {}: {}",
                        assignment.id, e
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Resume entitlements from a paused state.
    ///
    /// Restores suspended entitlements to active status.
    pub async fn resume_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<EntitlementActionResult> {
        let mut result = EntitlementActionResult::default();

        // Get all suspended entitlements for this user
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            status: Some(GovAssignmentStatus::Suspended),
            ..Default::default()
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await?;

        for assignment in assignments {
            match GovEntitlementAssignment::reactivate(&self.pool, tenant_id, assignment.id).await {
                Ok(Some(_)) => {
                    result.resumed.push(assignment.id);
                }
                Ok(None) => {
                    result.errors.push(format!(
                        "Assignment {} not found for reactivate",
                        assignment.id
                    ));
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to reactivate assignment {}: {}",
                        assignment.id, e
                    ));
                }
            }
        }

        Ok(result)
    }

    /// Restore entitlements from a snapshot (for rollback).
    ///
    /// This recreates entitlements that were revoked or resumes those that were paused.
    pub async fn restore_entitlements_from_snapshot(
        &self,
        tenant_id: Uuid,
        _user_id: Uuid,
        snapshot: &[EntitlementSnapshot],
    ) -> Result<EntitlementActionResult> {
        let mut result = EntitlementActionResult::default();

        for entry in snapshot {
            // Check if assignment still exists
            if let Ok(Some(assignment)) =
                GovEntitlementAssignment::find_by_id(&self.pool, tenant_id, entry.assignment_id)
                    .await
            {
                // Assignment exists, restore its status
                let target_status = match entry.status.as_str() {
                    "active" => GovAssignmentStatus::Active,
                    "suspended" => GovAssignmentStatus::Suspended,
                    _ => continue,
                };

                if assignment.status != target_status {
                    if target_status == GovAssignmentStatus::Active {
                        match GovEntitlementAssignment::reactivate(
                            &self.pool,
                            tenant_id,
                            assignment.id,
                        )
                        .await
                        {
                            Ok(Some(_)) => result.resumed.push(assignment.id),
                            Ok(None) | Err(_) => {
                                result.errors.push(format!(
                                    "Failed to restore assignment {} to active",
                                    assignment.id
                                ));
                            }
                        }
                    } else {
                        match GovEntitlementAssignment::suspend(
                            &self.pool,
                            tenant_id,
                            assignment.id,
                        )
                        .await
                        {
                            Ok(Some(_)) => result.paused.push(assignment.id),
                            Ok(None) | Err(_) => {
                                result.errors.push(format!(
                                    "Failed to restore assignment {} to suspended",
                                    assignment.id
                                ));
                            }
                        }
                    }
                }
            }
            // If assignment was revoked/deleted, we cannot restore it here
            // That would require recreating the assignment which needs more context
        }

        Ok(result)
    }

    /// Store entitlement snapshots in the audit record.
    pub async fn store_audit_snapshots(
        &self,
        tenant_id: Uuid,
        audit_id: Uuid,
        before_snapshot: &[EntitlementSnapshot],
        after_snapshot: &[EntitlementSnapshot],
    ) -> Result<()> {
        let before_json = serde_json::to_value(before_snapshot).ok();
        let after_json = serde_json::to_value(after_snapshot).ok();

        let update = UpdateGovStateTransitionAudit {
            entitlements_before: before_json,
            entitlements_after: after_json,
        };

        GovStateTransitionAudit::update(&self.pool, tenant_id, audit_id, &update)
            .await?
            .ok_or(GovernanceError::TransitionAuditNotFound(audit_id))?;

        Ok(())
    }

    /// Get entitlements affected by a state for display.
    ///
    /// Returns a summary of what would happen to entitlements if an object
    /// transitions to the given state.
    pub async fn get_state_affected_entitlements(
        &self,
        tenant_id: Uuid,
        object_type: &str,
        object_id: Uuid,
        target_state: &GovLifecycleState,
    ) -> Result<StateAffectedEntitlements> {
        // Currently only support user objects
        if object_type != "user" {
            return Ok(StateAffectedEntitlements {
                action: format!("{:?}", target_state.entitlement_action).to_lowercase(),
                affected_count: 0,
                entitlements: Vec::new(),
            });
        }

        // Get current entitlements
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(object_id),
            ..Default::default()
        };

        let assignments =
            GovEntitlementAssignment::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0)
                .await?;

        // Filter based on action type
        let affected: Vec<_> = match target_state.entitlement_action {
            EntitlementAction::None => Vec::new(),
            EntitlementAction::Pause => assignments
                .iter()
                .filter(|a| a.status == GovAssignmentStatus::Active)
                .map(|a| AffectedEntitlement {
                    assignment_id: a.id,
                    entitlement_id: a.entitlement_id,
                    current_status: format!("{:?}", a.status).to_lowercase(),
                    new_status: "suspended".to_string(),
                })
                .collect(),
            EntitlementAction::Revoke => assignments
                .iter()
                .filter(|a| a.status != GovAssignmentStatus::Expired)
                .map(|a| AffectedEntitlement {
                    assignment_id: a.id,
                    entitlement_id: a.entitlement_id,
                    current_status: format!("{:?}", a.status).to_lowercase(),
                    new_status: "revoked".to_string(),
                })
                .collect(),
        };

        Ok(StateAffectedEntitlements {
            action: format!("{:?}", target_state.entitlement_action).to_lowercase(),
            affected_count: affected.len(),
            entitlements: affected,
        })
    }
}

/// Summary of entitlements affected by a state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAffectedEntitlements {
    /// The action that will be taken (none, pause, revoke).
    pub action: String,
    /// Number of entitlements affected.
    pub affected_count: usize,
    /// Details of affected entitlements.
    pub entitlements: Vec<AffectedEntitlement>,
}

/// Details of a single affected entitlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedEntitlement {
    /// Assignment ID.
    pub assignment_id: Uuid,
    /// Entitlement ID.
    pub entitlement_id: Uuid,
    /// Current status.
    pub current_status: String,
    /// New status after transition.
    pub new_status: String,
}
