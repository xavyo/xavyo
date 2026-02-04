//! Lifecycle event service for JML workflow automation.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::{
    AccessSnapshotType, CreateAccessSnapshot, CreateGovAssignment, CreateLifecycleAction,
    CreateLifecycleEvent, GovAccessSnapshot, GovEntitlementAssignment, GovLifecycleAction,
    GovLifecycleEvent, LifecycleActionFilter, LifecycleActionType, LifecycleEventFilter,
    LifecycleEventType, SnapshotAssignment, SnapshotContent,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    AccessSnapshotSummary, LifecycleActionResponse, LifecycleEventResponse, ProcessEventResult,
    ProcessingSummary,
};
use crate::services::{AssignmentService, BirthrightPolicyService};

/// Service for lifecycle event operations.
pub struct LifecycleEventService {
    pool: PgPool,
    birthright_policy_service: Arc<BirthrightPolicyService>,
    assignment_service: Arc<AssignmentService>,
}

impl LifecycleEventService {
    /// Create a new lifecycle event service.
    #[must_use] 
    pub fn new(
        pool: PgPool,
        birthright_policy_service: Arc<BirthrightPolicyService>,
        assignment_service: Arc<AssignmentService>,
    ) -> Self {
        Self {
            pool,
            birthright_policy_service,
            assignment_service,
        }
    }

    /// Get a reference to the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a lifecycle event record.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateLifecycleEvent,
    ) -> Result<GovLifecycleEvent> {
        // Validate event data
        match input.event_type {
            LifecycleEventType::Mover => {
                if input.attributes_before.is_none() {
                    return Err(GovernanceError::MoverEventRequiresAttributesBefore);
                }
                if input.attributes_after.is_none() {
                    return Err(GovernanceError::EventRequiresAttributesAfter);
                }
            }
            LifecycleEventType::Joiner => {
                if input.attributes_after.is_none() {
                    return Err(GovernanceError::EventRequiresAttributesAfter);
                }
            }
            LifecycleEventType::Leaver => {
                // No attribute requirements for leaver
            }
        }

        GovLifecycleEvent::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get a lifecycle event by ID.
    pub async fn get(&self, tenant_id: Uuid, event_id: Uuid) -> Result<GovLifecycleEvent> {
        GovLifecycleEvent::find_by_id(&self.pool, tenant_id, event_id)
            .await?
            .ok_or(GovernanceError::LifecycleEventNotFound(event_id))
    }

    /// List lifecycle events with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &LifecycleEventFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovLifecycleEvent>, i64)> {
        let events =
            GovLifecycleEvent::list_by_tenant(&self.pool, tenant_id, filter, limit, offset).await?;
        let total = GovLifecycleEvent::count_by_tenant(&self.pool, tenant_id, filter).await?;

        Ok((events, total))
    }

    /// List actions for an event.
    pub async fn get_event_actions(&self, event_id: Uuid) -> Result<Vec<GovLifecycleAction>> {
        GovLifecycleAction::list_by_event(&self.pool, event_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List lifecycle actions with filtering.
    pub async fn list_actions(
        &self,
        tenant_id: Uuid,
        filter: &LifecycleActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovLifecycleAction>, i64)> {
        let actions =
            GovLifecycleAction::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        let total = GovLifecycleAction::count_by_tenant(&self.pool, tenant_id, filter).await?;

        Ok((actions, total))
    }

    /// Process a lifecycle event (joiner, mover, or leaver).
    pub async fn process_event(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
    ) -> Result<ProcessEventResult> {
        let event = self.get(tenant_id, event_id).await?;

        // Check if already processed
        if event.is_processed() {
            return Err(GovernanceError::LifecycleEventAlreadyProcessed(event_id));
        }

        let result = match event.event_type {
            LifecycleEventType::Joiner => self.process_joiner(tenant_id, &event).await?,
            LifecycleEventType::Leaver => self.process_leaver(tenant_id, &event).await?,
            LifecycleEventType::Mover => self.process_mover(tenant_id, &event).await?,
        };

        // Mark event as processed
        GovLifecycleEvent::mark_processed(&self.pool, tenant_id, event_id).await?;

        Ok(result)
    }

    /// Process a joiner event - auto-provision birthright access.
    async fn process_joiner(
        &self,
        tenant_id: Uuid,
        event: &GovLifecycleEvent,
    ) -> Result<ProcessEventResult> {
        let attributes = event
            .attributes_after
            .as_ref()
            .ok_or(GovernanceError::EventRequiresAttributesAfter)?;

        // Find matching birthright policies
        let matching_policies = self
            .birthright_policy_service
            .find_matching_policies(tenant_id, attributes)
            .await?;

        let mut summary = ProcessingSummary::default();
        let mut actions = Vec::new();

        // Get currently assigned entitlements for the user
        let current_assignments = self.get_user_assignments(tenant_id, event.user_id).await?;
        let current_entitlement_ids: HashSet<Uuid> = current_assignments
            .iter()
            .map(|a| a.entitlement_id)
            .collect();

        // Process each matching policy
        for policy in matching_policies {
            for entitlement_id in &policy.entitlement_ids {
                // Skip if already assigned
                if current_entitlement_ids.contains(entitlement_id) {
                    // Log skip action
                    let action = self
                        .create_action(
                            tenant_id,
                            event.id,
                            LifecycleActionType::Skip,
                            None,
                            Some(policy.id),
                            *entitlement_id,
                            None,
                        )
                        .await?;
                    actions.push(action);
                    summary.skipped += 1;
                    continue;
                }

                // Provision the entitlement
                let assignment_result = self
                    .provision_entitlement(
                        tenant_id,
                        event.user_id,
                        *entitlement_id,
                        Some(policy.id),
                    )
                    .await;

                match assignment_result {
                    Ok(assignment) => {
                        let action = self
                            .create_action(
                                tenant_id,
                                event.id,
                                LifecycleActionType::Provision,
                                Some(assignment.id),
                                Some(policy.id),
                                *entitlement_id,
                                None,
                            )
                            .await?;

                        // Mark as executed
                        let executed_action =
                            GovLifecycleAction::mark_executed(&self.pool, tenant_id, action.id)
                                .await?
                                .unwrap_or(action);

                        actions.push(executed_action);
                        summary.provisioned += 1;
                    }
                    Err(e) => {
                        // Log error but continue processing
                        let action = self
                            .create_action(
                                tenant_id,
                                event.id,
                                LifecycleActionType::Provision,
                                None,
                                Some(policy.id),
                                *entitlement_id,
                                None,
                            )
                            .await?;

                        GovLifecycleAction::record_error(
                            &self.pool,
                            tenant_id,
                            action.id,
                            &e.to_string(),
                        )
                        .await?;

                        actions.push(action);
                    }
                }
            }
        }

        // Reload event to get updated state
        let updated_event = self.get(tenant_id, event.id).await?;

        Ok(ProcessEventResult {
            event: LifecycleEventResponse::from(updated_event),
            actions: actions
                .into_iter()
                .map(LifecycleActionResponse::from)
                .collect(),
            snapshot: None,
            summary,
        })
    }

    /// Process a leaver event - snapshot access and revoke all.
    async fn process_leaver(
        &self,
        tenant_id: Uuid,
        event: &GovLifecycleEvent,
    ) -> Result<ProcessEventResult> {
        let mut summary = ProcessingSummary::default();
        let mut actions = Vec::new();

        // Create access snapshot before revocation
        let snapshot = self
            .create_access_snapshot(
                tenant_id,
                event.user_id,
                event.id,
                AccessSnapshotType::PreLeaver,
            )
            .await?;

        // Get all active assignments for the user
        let assignments = self.get_user_assignments(tenant_id, event.user_id).await?;

        // Revoke all assignments
        for assignment in assignments {
            // Create action record BEFORE revoke (assignment must exist for FK constraint)
            let action = self
                .create_action(
                    tenant_id,
                    event.id,
                    LifecycleActionType::Revoke,
                    Some(assignment.id),
                    None,
                    assignment.entitlement_id,
                    None,
                )
                .await?;

            let revoke_result = self.revoke_assignment(tenant_id, assignment.id).await;

            match revoke_result {
                Ok(()) => {
                    // Mark as executed
                    let executed_action =
                        GovLifecycleAction::mark_executed(&self.pool, tenant_id, action.id)
                            .await?
                            .unwrap_or(action);

                    actions.push(executed_action);
                    summary.revoked += 1;
                }
                Err(e) => {
                    GovLifecycleAction::record_error(
                        &self.pool,
                        tenant_id,
                        action.id,
                        &e.to_string(),
                    )
                    .await?;

                    actions.push(action);
                }
            }
        }

        // Reload event
        let updated_event = self.get(tenant_id, event.id).await?;

        Ok(ProcessEventResult {
            event: LifecycleEventResponse::from(updated_event),
            actions: actions
                .into_iter()
                .map(LifecycleActionResponse::from)
                .collect(),
            snapshot: Some(AccessSnapshotSummary::from(snapshot)),
            summary,
        })
    }

    /// Process a mover event - adjust access based on attribute changes.
    async fn process_mover(
        &self,
        tenant_id: Uuid,
        event: &GovLifecycleEvent,
    ) -> Result<ProcessEventResult> {
        let attributes_before = event
            .attributes_before
            .as_ref()
            .ok_or(GovernanceError::MoverEventRequiresAttributesBefore)?;
        let attributes_after = event
            .attributes_after
            .as_ref()
            .ok_or(GovernanceError::EventRequiresAttributesAfter)?;

        let mut summary = ProcessingSummary::default();
        let mut actions = Vec::new();

        // Create access snapshot before changes
        let snapshot = self
            .create_access_snapshot(
                tenant_id,
                event.user_id,
                event.id,
                AccessSnapshotType::PreMover,
            )
            .await?;

        // Find policies that matched before
        let policies_before = self
            .birthright_policy_service
            .find_matching_policies(tenant_id, attributes_before)
            .await?;

        // Find policies that match after
        let policies_after = self
            .birthright_policy_service
            .find_matching_policies(tenant_id, attributes_after)
            .await?;

        // Get entitlements from before/after policies
        let entitlements_before: HashSet<Uuid> = policies_before
            .iter()
            .flat_map(|p| p.entitlement_ids.clone())
            .collect();

        let entitlements_after: HashSet<Uuid> = policies_after
            .iter()
            .flat_map(|p| p.entitlement_ids.clone())
            .collect();

        // Entitlements to add (in after, not in before)
        let to_add: Vec<Uuid> = entitlements_after
            .difference(&entitlements_before)
            .copied()
            .collect();

        // Entitlements to remove (in before, not in after)
        let to_remove: Vec<Uuid> = entitlements_before
            .difference(&entitlements_after)
            .copied()
            .collect();

        // Get current assignments
        let current_assignments = self.get_user_assignments(tenant_id, event.user_id).await?;
        let current_entitlement_ids: HashSet<Uuid> = current_assignments
            .iter()
            .map(|a| a.entitlement_id)
            .collect();

        // Add new entitlements
        for entitlement_id in to_add {
            if current_entitlement_ids.contains(&entitlement_id) {
                summary.skipped += 1;
                continue;
            }

            // Find the policy that grants this entitlement
            let policy = policies_after
                .iter()
                .find(|p| p.entitlement_ids.contains(&entitlement_id));

            let assignment_result = self
                .provision_entitlement(
                    tenant_id,
                    event.user_id,
                    entitlement_id,
                    policy.map(|p| p.id),
                )
                .await;

            match assignment_result {
                Ok(assignment) => {
                    let action = self
                        .create_action(
                            tenant_id,
                            event.id,
                            LifecycleActionType::Provision,
                            Some(assignment.id),
                            policy.map(|p| p.id),
                            entitlement_id,
                            None,
                        )
                        .await?;

                    let executed_action =
                        GovLifecycleAction::mark_executed(&self.pool, tenant_id, action.id)
                            .await?
                            .unwrap_or(action);

                    actions.push(executed_action);
                    summary.provisioned += 1;
                }
                Err(e) => {
                    let action = self
                        .create_action(
                            tenant_id,
                            event.id,
                            LifecycleActionType::Provision,
                            None,
                            policy.map(|p| p.id),
                            entitlement_id,
                            None,
                        )
                        .await?;

                    GovLifecycleAction::record_error(
                        &self.pool,
                        tenant_id,
                        action.id,
                        &e.to_string(),
                    )
                    .await?;

                    actions.push(action);
                }
            }
        }

        // Schedule removal of old entitlements (with grace period)
        for entitlement_id in to_remove {
            // Find assignment for this entitlement
            let assignment = current_assignments
                .iter()
                .find(|a| a.entitlement_id == entitlement_id);

            if let Some(assignment) = assignment {
                // Find the policy that previously granted this
                let policy = policies_before
                    .iter()
                    .find(|p| p.entitlement_ids.contains(&entitlement_id));

                let grace_period_days = policy.map_or(0, |p| p.grace_period_days);

                if grace_period_days > 0 {
                    // Schedule revocation
                    let scheduled_at = Utc::now() + Duration::days(i64::from(grace_period_days));

                    let action = self
                        .create_action(
                            tenant_id,
                            event.id,
                            LifecycleActionType::ScheduleRevoke,
                            Some(assignment.id),
                            policy.map(|p| p.id),
                            entitlement_id,
                            Some(scheduled_at),
                        )
                        .await?;

                    actions.push(action);
                    summary.scheduled += 1;
                } else {
                    // Immediate revocation
                    let revoke_result = self.revoke_assignment(tenant_id, assignment.id).await;

                    match revoke_result {
                        Ok(()) => {
                            let action = self
                                .create_action(
                                    tenant_id,
                                    event.id,
                                    LifecycleActionType::Revoke,
                                    Some(assignment.id),
                                    policy.map(|p| p.id),
                                    entitlement_id,
                                    None,
                                )
                                .await?;

                            let executed_action =
                                GovLifecycleAction::mark_executed(&self.pool, tenant_id, action.id)
                                    .await?
                                    .unwrap_or(action);

                            actions.push(executed_action);
                            summary.revoked += 1;
                        }
                        Err(e) => {
                            let action = self
                                .create_action(
                                    tenant_id,
                                    event.id,
                                    LifecycleActionType::Revoke,
                                    Some(assignment.id),
                                    policy.map(|p| p.id),
                                    entitlement_id,
                                    None,
                                )
                                .await?;

                            GovLifecycleAction::record_error(
                                &self.pool,
                                tenant_id,
                                action.id,
                                &e.to_string(),
                            )
                            .await?;

                            actions.push(action);
                        }
                    }
                }
            }
        }

        // Reload event
        let updated_event = self.get(tenant_id, event.id).await?;

        Ok(ProcessEventResult {
            event: LifecycleEventResponse::from(updated_event),
            actions: actions
                .into_iter()
                .map(LifecycleActionResponse::from)
                .collect(),
            snapshot: Some(AccessSnapshotSummary::from(snapshot)),
            summary,
        })
    }

    /// Cancel a scheduled revocation action.
    pub async fn cancel_scheduled_action(
        &self,
        tenant_id: Uuid,
        action_id: Uuid,
    ) -> Result<GovLifecycleAction> {
        let action = GovLifecycleAction::find_by_id(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(GovernanceError::LifecycleActionNotFound(action_id))?;

        if action.action_type != LifecycleActionType::ScheduleRevoke {
            return Err(GovernanceError::CannotCancelNonScheduledAction);
        }

        if action.is_executed() {
            return Err(GovernanceError::LifecycleActionAlreadyExecuted(action_id));
        }

        if action.is_cancelled() {
            return Err(GovernanceError::LifecycleActionAlreadyCancelled(action_id));
        }

        GovLifecycleAction::cancel(&self.pool, tenant_id, action_id)
            .await?
            .ok_or(GovernanceError::LifecycleActionNotFound(action_id))
    }

    /// Execute due scheduled revocations.
    pub async fn execute_due_revocations(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<GovLifecycleAction>> {
        let now = Utc::now();
        let due_actions =
            GovLifecycleAction::list_due_revocations(&self.pool, tenant_id, now).await?;

        let mut executed = Vec::new();

        for action in due_actions {
            if let Some(assignment_id) = action.assignment_id {
                let revoke_result = self.revoke_assignment(tenant_id, assignment_id).await;

                match revoke_result {
                    Ok(()) => {
                        if let Some(executed_action) =
                            GovLifecycleAction::mark_executed(&self.pool, tenant_id, action.id)
                                .await?
                        {
                            executed.push(executed_action);
                        }
                    }
                    Err(e) => {
                        GovLifecycleAction::record_error(
                            &self.pool,
                            tenant_id,
                            action.id,
                            &e.to_string(),
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(executed)
    }

    // ========================================================================
    // Helper methods
    // ========================================================================

    /// Get active assignments for a user.
    async fn get_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<GovEntitlementAssignment>> {
        self.assignment_service
            .list_user_assignments(tenant_id, user_id)
            .await
    }

    /// Provision an entitlement to a user.
    async fn provision_entitlement(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
        _policy_id: Option<Uuid>,
    ) -> Result<GovEntitlementAssignment> {
        let input = CreateGovAssignment {
            target_type: xavyo_db::GovAssignmentTargetType::User,
            target_id: user_id,
            entitlement_id,
            // Use the user themselves as assigned_by for system-granted assignments
            // (birthright policies). A dedicated system user could be used in the future.
            assigned_by: user_id,
            expires_at: None,
            justification: Some("Birthright policy auto-provision".to_string()),
            parameter_hash: None,
            valid_from: None,
            valid_to: None,
        };

        self.assignment_service.create(tenant_id, input).await
    }

    /// Revoke an assignment.
    async fn revoke_assignment(&self, tenant_id: Uuid, assignment_id: Uuid) -> Result<()> {
        self.assignment_service
            .revoke(tenant_id, assignment_id, None)
            .await
    }

    /// Create a lifecycle action record.
    #[allow(clippy::too_many_arguments)]
    async fn create_action(
        &self,
        tenant_id: Uuid,
        event_id: Uuid,
        action_type: LifecycleActionType,
        assignment_id: Option<Uuid>,
        policy_id: Option<Uuid>,
        entitlement_id: Uuid,
        scheduled_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<GovLifecycleAction> {
        let input = CreateLifecycleAction {
            event_id,
            action_type,
            assignment_id,
            policy_id,
            entitlement_id,
            scheduled_at,
        };

        GovLifecycleAction::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Create an access snapshot.
    async fn create_access_snapshot(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        event_id: Uuid,
        snapshot_type: AccessSnapshotType,
    ) -> Result<GovAccessSnapshot> {
        let assignments = self.get_user_assignments(tenant_id, user_id).await?;

        // Build snapshot content
        let snapshot_assignments: Vec<SnapshotAssignment> = assignments
            .iter()
            .map(|a| SnapshotAssignment {
                id: a.id,
                entitlement_id: a.entitlement_id,
                entitlement_name: String::new(), // Would need to fetch entitlement details
                entitlement_external_id: None,
                application_id: Uuid::nil(), // Would need to fetch from entitlement
                application_name: String::new(),
                source: Some("assignment".to_string()),
                policy_id: None, // Would need to track this
                granted_at: a.assigned_at,
                granted_by: Some(a.assigned_by),
            })
            .collect();

        let content = SnapshotContent {
            assignments: snapshot_assignments,
            total_count: assignments.len() as i32,
            snapshot_at: Some(Utc::now()),
        };

        let input = CreateAccessSnapshot {
            user_id,
            event_id,
            snapshot_type,
            assignments: content,
        };

        GovAccessSnapshot::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }
}
