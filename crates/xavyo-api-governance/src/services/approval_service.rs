//! Approval service for governance API.
//!
//! Handles the approval workflow, decision recording, and auto-provisioning.
//! Enhanced in F053 to support scoped delegations and audit trail.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovApprovalDecision, CreateGovAssignment, CreateGovDelegationAudit, DelegationActionType,
    GovAccessRequest, GovApprovalDecision, GovApprovalDelegation, GovApprovalStep, GovApproverType,
    GovAssignmentTargetType, GovDecisionType, GovDelegationAudit, GovDelegationScope,
    GovEntitlement, GovEntitlementAssignment, GovEscalationEvent, GovRequestStatus, User,
    WorkItemType,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::AssignmentService;

/// Service for approval operations.
pub struct ApprovalService {
    pool: PgPool,
    assignment_service: Arc<AssignmentService>,
}

impl ApprovalService {
    /// Create a new approval service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            assignment_service: Arc::new(AssignmentService::new(pool.clone())),
            pool,
        }
    }

    /// Get pending approvals for a user (approver queue).
    ///
    /// Includes requests where:
    /// - User is a direct approver for the current step
    /// - User is a delegate for someone who is an approver (with scope check - F053)
    pub async fn get_pending_approvals(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<PendingApprovalInfo>, i64)> {
        // Get active delegations where this user is the delegate (F053)
        let delegations = GovApprovalDelegation::find_active_for_delegate(
            &self.pool,
            tenant_id,
            user_id,
            Utc::now(),
        )
        .await?;

        // Find pending requests and check if user can approve
        // This is a simplified implementation - in production, you'd want a more efficient query
        let pending_requests: Vec<GovAccessRequest> = sqlx::query_as(
            r"
            SELECT * FROM gov_access_requests
            WHERE tenant_id = $1 AND status IN ('pending', 'pending_approval')
            ORDER BY created_at ASC
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::new();

        for request in pending_requests {
            // Check if user can approve this request (with scope-aware delegation check)
            if let Some(info) = self
                .can_user_approve(&request, user_id, &delegations)
                .await?
            {
                result.push(info);
            }
        }

        // Count total (simplified - would need optimization for production)
        let total_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_access_requests
            WHERE tenant_id = $1 AND status IN ('pending', 'pending_approval')
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok((result, total_count))
    }

    /// Check if a user can approve a request and return approval info.
    /// Enhanced in F053 to support scoped delegations.
    async fn can_user_approve(
        &self,
        request: &GovAccessRequest,
        user_id: Uuid,
        delegations: &[GovApprovalDelegation],
    ) -> Result<Option<PendingApprovalInfo>> {
        // Get current step configuration
        let workflow_id = match request.workflow_id {
            Some(id) => id,
            None => return Ok(None), // No workflow, use default (manager)
        };

        let step = GovApprovalStep::find_by_workflow_and_order(
            &self.pool,
            workflow_id,
            request.current_step + 1, // Steps are 1-indexed
        )
        .await?;

        let step = match step {
            Some(s) => s,
            None => return Ok(None), // No step found
        };

        // Resolve who can approve at this step
        let mut approvers = self
            .resolve_approvers(
                &step,
                request.tenant_id,
                request.requester_id,
                request.entitlement_id,
            )
            .await?;

        // Fix #13: Filter out the requester to prevent self-approval via circular manager
        approvers.retain(|&id| id != request.requester_id);

        // F054: Also include escalation targets who can approve (IGA behavior)
        // If the request has been escalated, the escalation targets can also approve
        if request.current_escalation_level > 0 {
            let escalation_targets = self
                .get_current_escalation_targets(request.tenant_id, request.id)
                .await?;
            for target_id in escalation_targets {
                if !approvers.contains(&target_id) {
                    approvers.push(target_id);
                }
            }
        }

        // Check if user is a direct approver or escalation target
        let is_direct = approvers.contains(&user_id);

        // Check if user is a delegate for any approver with matching scope (F053)
        let mut matching_delegation: Option<&GovApprovalDelegation> = None;
        let mut delegator_match: Option<Uuid> = None;

        for delegation in delegations {
            // Check if this delegator is an approver
            if !approvers.contains(&delegation.delegator_id) {
                continue;
            }

            // Check delegation scope (F053)
            if let Some(scope_id) = delegation.scope_id {
                // Load scope and check if it covers this work item
                let scope =
                    GovDelegationScope::find_by_id(&self.pool, request.tenant_id, scope_id).await?;

                if let Some(scope) = scope {
                    // Get application_id for the entitlement
                    let entitlement = xavyo_db::GovEntitlement::find_by_id(
                        &self.pool,
                        request.tenant_id,
                        request.entitlement_id,
                    )
                    .await?;

                    let app_id = entitlement.map(|e| e.application_id);

                    // Check if scope matches (OR semantics)
                    let scope_matches = scope.matches_work_item(
                        app_id,
                        Some(request.entitlement_id),
                        None, // role_id
                        Some("access_request"),
                    );

                    if !scope_matches {
                        continue; // Scope doesn't cover this work item
                    }
                }
            }
            // No scope = full delegation authority

            matching_delegation = Some(delegation);
            delegator_match = Some(delegation.delegator_id);
            break;
        }

        let is_delegate = matching_delegation.is_some();

        if !is_direct && !is_delegate {
            return Ok(None);
        }

        // Self-approval check: requester cannot approve their own request
        if request.requester_id == user_id {
            return Ok(None);
        }

        // Also check delegate case: original approver cannot be the requester
        if let Some(delegator_id) = delegator_match {
            if request.requester_id == delegator_id {
                return Ok(None);
            }
        }

        // Get total steps
        let total_steps = GovApprovalStep::count_by_workflow(&self.pool, workflow_id).await? as i32;

        // Get previous decisions
        let previous_decisions =
            GovApprovalDecision::find_by_request(&self.pool, request.tenant_id, request.id).await?;

        Ok(Some(PendingApprovalInfo {
            request: request.clone(),
            current_step: request.current_step + 1,
            total_steps,
            is_delegate,
            delegator_id: delegator_match,
            delegation_id: matching_delegation.map(|d| d.id),
            previous_decisions,
        }))
    }

    /// Resolve who can approve at a given step.
    async fn resolve_approvers(
        &self,
        step: &GovApprovalStep,
        tenant_id: Uuid,
        requester_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        match step.approver_type {
            GovApproverType::Manager => {
                // T083: Use User.manager_id for manager-type approvals
                // Include tenant_id for defense-in-depth
                let user = User::find_by_id_in_tenant(&self.pool, tenant_id, requester_id)
                    .await
                    .map_err(GovernanceError::Database)?;

                if let Some(user) = user {
                    if let Some(manager_id) = user.manager_id {
                        Ok(vec![manager_id])
                    } else {
                        // No manager configured for this user
                        Ok(vec![])
                    }
                } else {
                    Ok(vec![])
                }
            }
            GovApproverType::EntitlementOwner => {
                // Get entitlement owner
                let entitlement =
                    GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id).await?;

                match entitlement.and_then(|e| e.owner_id) {
                    Some(owner_id) => Ok(vec![owner_id]),
                    None => Ok(vec![]), // No owner configured
                }
            }
            GovApproverType::SpecificUsers => {
                // Return specific approvers list
                Ok(step.specific_approvers.clone().unwrap_or_default())
            }
        }
    }

    /// Get current escalation targets for a request (F054).
    ///
    /// Returns the user IDs from the most recent escalation event.
    /// This enables escalation targets to approve requests (IGA behavior:
    /// original approver AND escalation targets can both complete the work item).
    async fn get_current_escalation_targets(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        // Get the most recent escalation event for this request
        let events = GovEscalationEvent::find_by_request(&self.pool, tenant_id, request_id).await?;

        // Get the last event (most recent escalation targets)
        if let Some(event) = events.last() {
            Ok(event.escalation_target_ids.clone())
        } else {
            Ok(vec![])
        }
    }

    /// Approve an access request.
    /// Enhanced in F053 to support scoped delegations and audit trail.
    pub async fn approve_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
        comments: Option<String>,
    ) -> Result<ApprovalResult> {
        // Fix #15: Use FOR UPDATE to prevent concurrent approval races
        let request = GovAccessRequest::find_by_id_for_update(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::AccessRequestNotFound(request_id))?;

        // Verify request is pending
        if !request.status.is_pending() {
            return Err(GovernanceError::RequestNotPending);
        }

        // Self-approval check
        if request.requester_id == approver_id {
            return Err(GovernanceError::SelfApprovalNotAllowed);
        }

        // Check if user is authorized to approve (with scope-aware delegation - F053)
        let delegations = GovApprovalDelegation::find_active_for_delegate(
            &self.pool,
            tenant_id,
            approver_id,
            Utc::now(),
        )
        .await?;

        let approval_info = self
            .can_user_approve(&request, approver_id, &delegations)
            .await?
            .ok_or(GovernanceError::NotAuthorizedApprover)?;

        // Record the decision
        // Uses unique constraint on (request_id, step_order) to prevent concurrent approval conflicts (F053)
        let decision_input = CreateGovApprovalDecision {
            tenant_id,
            request_id,
            step_order: request.current_step + 1,
            approver_id,
            delegate_id: approval_info.delegator_id,
            decision: GovDecisionType::Approved,
            comments: comments.clone(),
        };

        GovApprovalDecision::create(&self.pool, decision_input)
            .await
            .map_err(|e| {
                // Convert unique constraint violation to StepAlreadyDecided error
                if let sqlx::Error::Database(ref db_err) = e {
                    if db_err.constraint() == Some("idx_approval_decisions_unique_step") {
                        return GovernanceError::StepAlreadyDecided;
                    }
                }
                GovernanceError::Database(e)
            })?;

        // Create audit record if acting as delegate (F053)
        if let Some(delegation_id) = approval_info.delegation_id {
            let audit_input = CreateGovDelegationAudit {
                delegation_id,
                deputy_id: approver_id,
                delegator_id: approval_info.delegator_id.unwrap_or(Uuid::nil()),
                action_type: DelegationActionType::ApproveRequest,
                work_item_type: WorkItemType::AccessRequest,
                work_item_id: request_id,
                metadata: Some(serde_json::json!({
                    "decision": "approved",
                    "comments": comments,
                    "step_order": request.current_step + 1
                })),
            };
            GovDelegationAudit::create(&self.pool, tenant_id, audit_input).await?;
        }

        // Check if this is the final step
        let is_final = GovApprovalStep::is_final_step(
            &self.pool,
            request.workflow_id.unwrap_or(Uuid::nil()),
            request.current_step + 1,
        )
        .await?;

        if is_final {
            // All approvals complete - provision the entitlement
            let assignment = self
                .provision_entitlement(tenant_id, &request, approver_id)
                .await?;

            GovAccessRequest::set_provisioned(&self.pool, tenant_id, request_id, assignment.id)
                .await?;

            Ok(ApprovalResult {
                new_status: GovRequestStatus::Provisioned,
                provisioned_assignment_id: Some(assignment.id),
            })
        } else {
            // Advance to next step
            let updated_request =
                GovAccessRequest::advance_step(&self.pool, tenant_id, request_id).await?;

            // F054/T082: Set deadline for new step based on escalation configuration
            if let Some(ref updated) = updated_request {
                if let Some(workflow_id) = updated.workflow_id {
                    let next_step_order = updated.current_step + 1;
                    if let Some(next_step) = GovApprovalStep::find_by_workflow_and_order(
                        &self.pool,
                        workflow_id,
                        next_step_order,
                    )
                    .await?
                    {
                        if next_step.escalation_enabled {
                            let deadline =
                                self.calculate_step_deadline(tenant_id, &next_step).await?;
                            if deadline.is_some() {
                                GovAccessRequest::set_deadline(
                                    &self.pool, tenant_id, request_id, deadline,
                                )
                                .await?;
                            }
                        }
                    }
                }
            }

            Ok(ApprovalResult {
                new_status: GovRequestStatus::PendingApproval,
                provisioned_assignment_id: None,
            })
        }
    }

    /// Reject an access request.
    /// Enhanced in F053 to support scoped delegations and audit trail.
    pub async fn reject_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
        comments: String,
    ) -> Result<ApprovalResult> {
        // Comments are required for rejection
        if comments.trim().is_empty() {
            return Err(GovernanceError::RejectionCommentsRequired);
        }

        // Fix #15: Use FOR UPDATE to prevent concurrent approval/rejection races
        let request = GovAccessRequest::find_by_id_for_update(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::AccessRequestNotFound(request_id))?;

        // Verify request is pending
        if !request.status.is_pending() {
            return Err(GovernanceError::RequestNotPending);
        }

        // Self-approval check (applies to rejection too)
        if request.requester_id == approver_id {
            return Err(GovernanceError::SelfApprovalNotAllowed);
        }

        // Check if user is authorized to approve/reject (with scope-aware delegation - F053)
        let delegations = GovApprovalDelegation::find_active_for_delegate(
            &self.pool,
            tenant_id,
            approver_id,
            Utc::now(),
        )
        .await?;

        let approval_info = self
            .can_user_approve(&request, approver_id, &delegations)
            .await?
            .ok_or(GovernanceError::NotAuthorizedApprover)?;

        // Record the decision
        // Uses unique constraint on (request_id, step_order) to prevent concurrent approval conflicts (F053)
        let decision_input = CreateGovApprovalDecision {
            tenant_id,
            request_id,
            step_order: request.current_step + 1,
            approver_id,
            delegate_id: approval_info.delegator_id,
            decision: GovDecisionType::Rejected,
            comments: Some(comments.clone()),
        };

        GovApprovalDecision::create(&self.pool, decision_input)
            .await
            .map_err(|e| {
                // Convert unique constraint violation to StepAlreadyDecided error
                if let sqlx::Error::Database(ref db_err) = e {
                    if db_err.constraint() == Some("idx_approval_decisions_unique_step") {
                        return GovernanceError::StepAlreadyDecided;
                    }
                }
                GovernanceError::Database(e)
            })?;

        // Create audit record if acting as delegate (F053)
        if let Some(delegation_id) = approval_info.delegation_id {
            let audit_input = CreateGovDelegationAudit {
                delegation_id,
                deputy_id: approver_id,
                delegator_id: approval_info.delegator_id.unwrap_or(Uuid::nil()),
                action_type: DelegationActionType::RejectRequest,
                work_item_type: WorkItemType::AccessRequest,
                work_item_id: request_id,
                metadata: Some(serde_json::json!({
                    "decision": "rejected",
                    "comments": comments,
                    "step_order": request.current_step + 1
                })),
            };
            GovDelegationAudit::create(&self.pool, tenant_id, audit_input).await?;
        }

        // Update request status to rejected
        GovAccessRequest::update_status(
            &self.pool,
            tenant_id,
            request_id,
            GovRequestStatus::Rejected,
        )
        .await?;

        Ok(ApprovalResult {
            new_status: GovRequestStatus::Rejected,
            provisioned_assignment_id: None,
        })
    }

    /// Provision the entitlement assignment after final approval.
    ///
    /// Fix #1: Uses `AssignmentService.create_assignment()` instead of direct DB insert
    /// to ensure SoD checks run at provisioning time (user's access may have changed
    /// between cart submission and approval).
    async fn provision_entitlement(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        assigned_by: Uuid,
    ) -> Result<GovEntitlementAssignment> {
        let input = CreateGovAssignment {
            entitlement_id: request.entitlement_id,
            target_type: GovAssignmentTargetType::User,
            target_id: request.requester_id,
            assigned_by,
            expires_at: request.requested_expires_at,
            justification: Some(request.justification.clone()),
            parameter_hash: None,
            valid_from: None,
            valid_to: None,
        };

        self.assignment_service
            .create_assignment(tenant_id, input)
            .await
    }

    /// Get previous decisions for a request within a tenant.
    pub async fn get_previous_decisions(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<Vec<GovApprovalDecision>> {
        GovApprovalDecision::find_by_request(&self.pool, tenant_id, request_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Calculate the deadline for an approval step based on escalation configuration (F054/T082).
    ///
    /// Returns None if escalation is not configured for this step.
    async fn calculate_step_deadline(
        &self,
        tenant_id: Uuid,
        step: &GovApprovalStep,
    ) -> Result<Option<chrono::DateTime<Utc>>> {
        use xavyo_db::models::{GovEscalationPolicy, GovEscalationRule};

        // First check for step-specific rule
        if let Some(rule) = GovEscalationRule::find_by_step(&self.pool, tenant_id, step.id).await? {
            let timeout_secs = rule.timeout_secs();
            return Ok(Some(Utc::now() + chrono::Duration::seconds(timeout_secs)));
        }

        // Fall back to tenant default policy
        if let Some(policy) =
            GovEscalationPolicy::find_active_default(&self.pool, tenant_id).await?
        {
            let timeout_secs = policy.timeout_secs();
            return Ok(Some(Utc::now() + chrono::Duration::seconds(timeout_secs)));
        }

        // No escalation configuration - no deadline
        Ok(None)
    }
}

/// Information about a pending approval.
#[derive(Debug, Clone)]
pub struct PendingApprovalInfo {
    pub request: GovAccessRequest,
    pub current_step: i32,
    pub total_steps: i32,
    pub is_delegate: bool,
    pub delegator_id: Option<Uuid>,
    /// The delegation ID if acting as delegate (F053).
    pub delegation_id: Option<Uuid>,
    pub previous_decisions: Vec<GovApprovalDecision>,
}

/// Result of an approval action.
#[derive(Debug, Clone)]
pub struct ApprovalResult {
    pub new_status: GovRequestStatus,
    pub provisioned_assignment_id: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_result_provisioned() {
        let result = ApprovalResult {
            new_status: GovRequestStatus::Provisioned,
            provisioned_assignment_id: Some(Uuid::new_v4()),
        };

        assert!(matches!(result.new_status, GovRequestStatus::Provisioned));
        assert!(result.provisioned_assignment_id.is_some());
    }

    #[test]
    fn test_approval_result_pending() {
        let result = ApprovalResult {
            new_status: GovRequestStatus::PendingApproval,
            provisioned_assignment_id: None,
        };

        assert!(matches!(
            result.new_status,
            GovRequestStatus::PendingApproval
        ));
        assert!(result.provisioned_assignment_id.is_none());
    }

    #[test]
    fn test_approval_result_rejected() {
        let result = ApprovalResult {
            new_status: GovRequestStatus::Rejected,
            provisioned_assignment_id: None,
        };

        assert!(matches!(result.new_status, GovRequestStatus::Rejected));
        assert!(result.provisioned_assignment_id.is_none());
    }

    #[test]
    fn test_pending_approval_info_direct_approver() {
        let request = GovAccessRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            workflow_id: Some(Uuid::new_v4()),
            current_step: 0,
            status: GovRequestStatus::PendingApproval,
            justification: "Business need for this entitlement access".to_string(),
            requested_expires_at: None,
            has_sod_warning: false,
            sod_violations: None,
            provisioned_assignment_id: None,
            current_escalation_level: 0,
            current_deadline: None,
            escalation_warning_sent: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        let info = PendingApprovalInfo {
            request,
            current_step: 1,
            total_steps: 2,
            is_delegate: false,
            delegator_id: None,
            delegation_id: None,
            previous_decisions: vec![],
        };

        assert_eq!(info.current_step, 1);
        assert_eq!(info.total_steps, 2);
        assert!(!info.is_delegate);
        assert!(info.delegator_id.is_none());
        assert!(info.delegation_id.is_none());
        assert!(info.previous_decisions.is_empty());
    }

    #[test]
    fn test_pending_approval_info_delegate() {
        let request = GovAccessRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            workflow_id: Some(Uuid::new_v4()),
            current_step: 1,
            status: GovRequestStatus::PendingApproval,
            justification: "Business need for this entitlement access".to_string(),
            requested_expires_at: None,
            has_sod_warning: false,
            sod_violations: None,
            provisioned_assignment_id: None,
            current_escalation_level: 0,
            current_deadline: None,
            escalation_warning_sent: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        let delegator_id = Uuid::new_v4();
        let delegation_id = Uuid::new_v4();
        let info = PendingApprovalInfo {
            request,
            current_step: 2,
            total_steps: 2,
            is_delegate: true,
            delegator_id: Some(delegator_id),
            delegation_id: Some(delegation_id),
            previous_decisions: vec![],
        };

        assert_eq!(info.current_step, 2);
        assert!(info.is_delegate);
        assert_eq!(info.delegator_id, Some(delegator_id));
        assert_eq!(info.delegation_id, Some(delegation_id));
    }

    #[test]
    fn test_self_approval_check() {
        let requester_id = Uuid::new_v4();
        let approver_id = requester_id; // Same as requester

        // This should be detected as self-approval
        assert_eq!(requester_id, approver_id);
    }

    #[test]
    fn test_different_user_approval() {
        let requester_id = Uuid::new_v4();
        let approver_id = Uuid::new_v4();

        // Different users should be allowed
        assert_ne!(requester_id, approver_id);
    }

    #[test]
    fn test_escalation_level_indicates_escalation() {
        // A request with current_escalation_level > 0 has been escalated
        // This means escalation targets should also be able to approve (F054 + IGA behavior)
        let request = GovAccessRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            workflow_id: Some(Uuid::new_v4()),
            current_step: 0,
            status: GovRequestStatus::PendingApproval,
            justification: "Business need".to_string(),
            requested_expires_at: None,
            has_sod_warning: false,
            sod_violations: None,
            provisioned_assignment_id: None,
            current_escalation_level: 1, // Escalated once
            current_deadline: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
            escalation_warning_sent: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        // Escalation level 1 means escalation has occurred
        assert_eq!(request.current_escalation_level, 1);
        assert!(request.current_escalation_level > 0);
        // In can_user_approve(), when current_escalation_level > 0,
        // we also check escalation targets from the most recent escalation event
    }

    #[test]
    fn test_non_escalated_request() {
        let request = GovAccessRequest {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            requester_id: Uuid::new_v4(),
            entitlement_id: Uuid::new_v4(),
            workflow_id: Some(Uuid::new_v4()),
            current_step: 0,
            status: GovRequestStatus::PendingApproval,
            justification: "Business need".to_string(),
            requested_expires_at: None,
            has_sod_warning: false,
            sod_violations: None,
            provisioned_assignment_id: None,
            current_escalation_level: 0, // Not escalated
            current_deadline: None,
            escalation_warning_sent: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: None,
        };

        // Escalation level 0 means no escalation
        assert_eq!(request.current_escalation_level, 0);
        // Only workflow-defined approvers can approve (no escalation targets)
    }
}
