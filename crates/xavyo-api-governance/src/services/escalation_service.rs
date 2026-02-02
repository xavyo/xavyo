//! Escalation service for governance API (F054).
//!
//! Handles automatic escalation of access request work items when approvers
//! don't respond within configured timeouts.

#[cfg(feature = "kafka")]
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use tracing::info;
#[cfg(feature = "kafka")]
use tracing::warn;
use uuid::Uuid;

use xavyo_db::models::{
    CreateEscalationEvent, EscalationReason, EscalationTargetType, FinalFallbackAction,
    GovAccessRequest, GovApprovalGroup, GovApprovalStep, GovEscalationEvent, GovEscalationLevel,
    GovEscalationPolicy, GovEscalationRule, User,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::{
    events::{
        EscalationExhausted, EscalationOccurred, EscalationReason as EventEscalationReason,
        EscalationTargetTypeEvent as EventEscalationTargetType, EscalationWarning,
        FinalFallbackActionEvent as EventFallbackAction,
    },
    EventProducer,
};

/// Represents the resolved target(s) for an escalation.
#[derive(Debug, Clone)]
pub struct ResolvedEscalationTarget {
    /// The target type used for escalation.
    pub target_type: EscalationTargetType,
    /// Resolved user IDs who will receive the work item.
    pub user_ids: Vec<Uuid>,
    /// Optional group ID if escalated to a group.
    pub group_id: Option<Uuid>,
    /// Display name for audit purposes.
    pub display_name: String,
}

/// Result of cancelling an escalation (T067).
#[derive(Debug, Clone)]
pub struct CancelEscalationResult {
    /// Whether cancellation was successful.
    pub success: bool,
    /// The escalation level before cancellation.
    pub previous_level: i32,
    /// The current assignee who retains the work item.
    pub current_assignee_id: Uuid,
}

/// Result of resetting an escalation (T068).
#[derive(Debug, Clone)]
pub struct ResetEscalationResult {
    /// Whether reset was successful.
    pub success: bool,
    /// The escalation level before reset.
    pub previous_level: i32,
    /// The original approver who now has the work item again.
    pub original_approver_id: Uuid,
    /// New deadline for the original approver.
    pub new_deadline: Option<DateTime<Utc>>,
}

/// Result of executing an escalation.
#[derive(Debug, Clone)]
pub struct EscalationResult {
    /// Whether escalation was successfully executed.
    pub success: bool,
    /// The new escalation level.
    pub new_level: i32,
    /// The new deadline for the work item.
    pub new_deadline: Option<DateTime<Utc>>,
    /// Resolved targets who received the work item.
    pub targets: Vec<ResolvedEscalationTarget>,
    /// The escalation event record.
    pub event: Option<GovEscalationEvent>,
    /// Whether all levels are exhausted (final fallback triggered).
    pub levels_exhausted: bool,
    /// Final fallback action taken (if levels exhausted).
    pub fallback_action: Option<FinalFallbackAction>,
}

/// Service for escalation operations.
pub struct EscalationService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl EscalationService {
    /// Create a new escalation service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new escalation service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing escalation events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    /// Calculate the deadline for an access request step based on escalation configuration.
    ///
    /// Configuration precedence:
    /// 1. Step-specific escalation rule (if exists and enabled)
    /// 2. Tenant default escalation policy (if active)
    /// 3. No deadline (escalation disabled)
    pub async fn calculate_deadline(
        &self,
        tenant_id: Uuid,
        step: &GovApprovalStep,
        from_time: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        // Check if step has escalation enabled
        if !step.escalation_enabled {
            return Ok(None);
        }

        // First, check for step-specific rule
        if let Some(rule) = GovEscalationRule::find_by_step(&self.pool, tenant_id, step.id).await? {
            if rule.is_enabled {
                let timeout = rule.timeout_duration();
                return Ok(Some(from_time + timeout));
            }
        }

        // Fall back to tenant default policy
        if let Some(policy) =
            GovEscalationPolicy::find_active_default(&self.pool, tenant_id).await?
        {
            let timeout = policy.timeout_duration();
            return Ok(Some(from_time + timeout));
        }

        // No escalation configuration found
        Ok(None)
    }

    /// Resolve the escalation target for a given level.
    ///
    /// Returns the user IDs who should receive the escalated work item.
    pub async fn resolve_escalation_target(
        &self,
        tenant_id: Uuid,
        level: &GovEscalationLevel,
        original_approver_id: Option<Uuid>,
    ) -> Result<ResolvedEscalationTarget> {
        match level.target_type {
            EscalationTargetType::SpecificUser => {
                let target_id = level.target_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "target_id required for SpecificUser escalation".to_string(),
                    )
                })?;

                // Verify user exists (include tenant_id for defense-in-depth)
                let _user = User::find_by_id_in_tenant(&self.pool, tenant_id, target_id)
                    .await?
                    .ok_or(GovernanceError::UserNotFound(target_id))?;

                Ok(ResolvedEscalationTarget {
                    target_type: EscalationTargetType::SpecificUser,
                    user_ids: vec![target_id],
                    group_id: None,
                    display_name: format!("Specific user {}", target_id),
                })
            }

            EscalationTargetType::ApprovalGroup => {
                let group_id = level.target_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "target_id required for ApprovalGroup escalation".to_string(),
                    )
                })?;

                let group = GovApprovalGroup::find_by_id(&self.pool, tenant_id, group_id)
                    .await?
                    .ok_or(GovernanceError::ApprovalGroupNotFound(group_id))?;

                if !group.is_active {
                    return Err(GovernanceError::Validation(
                        "Cannot escalate to inactive approval group".to_string(),
                    ));
                }

                let member_ids = group.member_ids.clone();
                if member_ids.is_empty() {
                    return Err(GovernanceError::Validation(
                        "Cannot escalate to approval group with no members".to_string(),
                    ));
                }

                Ok(ResolvedEscalationTarget {
                    target_type: EscalationTargetType::ApprovalGroup,
                    user_ids: member_ids,
                    group_id: Some(group_id),
                    display_name: group.name,
                })
            }

            EscalationTargetType::Manager => {
                let approver_id = original_approver_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "Original approver required for Manager escalation".to_string(),
                    )
                })?;

                let manager = User::get_manager(&self.pool, tenant_id, approver_id)
                    .await?
                    .ok_or_else(|| {
                        GovernanceError::Validation(format!(
                            "Approver {} has no manager configured",
                            approver_id
                        ))
                    })?;

                Ok(ResolvedEscalationTarget {
                    target_type: EscalationTargetType::Manager,
                    user_ids: vec![*manager.user_id().as_uuid()],
                    group_id: None,
                    display_name: format!(
                        "Manager of {}",
                        original_approver_id.map_or("unknown".to_string(), |id| id.to_string())
                    ),
                })
            }

            EscalationTargetType::ManagerChain => {
                let approver_id = original_approver_id.ok_or_else(|| {
                    GovernanceError::Validation(
                        "Original approver required for ManagerChain escalation".to_string(),
                    )
                })?;

                let depth = level.manager_chain_depth.unwrap_or(1).clamp(1, 10);
                let chain =
                    User::get_manager_chain(&self.pool, tenant_id, approver_id, depth).await?;

                if chain.is_empty() {
                    return Err(GovernanceError::Validation(format!(
                        "Approver {} has no manager chain available",
                        approver_id
                    )));
                }

                Ok(ResolvedEscalationTarget {
                    target_type: EscalationTargetType::ManagerChain,
                    user_ids: chain,
                    group_id: None,
                    display_name: format!("Manager chain (depth {})", depth),
                })
            }

            EscalationTargetType::TenantAdmin => {
                // Get all users with admin role in the tenant
                // For now, we'll use a simple query - in a real system this would
                // check role assignments more thoroughly
                let admins = self.get_tenant_admins(tenant_id).await?;

                if admins.is_empty() {
                    return Err(GovernanceError::Validation(
                        "No tenant admins available for escalation".to_string(),
                    ));
                }

                Ok(ResolvedEscalationTarget {
                    target_type: EscalationTargetType::TenantAdmin,
                    user_ids: admins,
                    group_id: None,
                    display_name: "Tenant Administrators".to_string(),
                })
            }
        }
    }

    /// Execute escalation for an access request.
    ///
    /// This method:
    /// 1. Determines the next escalation level
    /// 2. Resolves the target users
    /// 3. Updates the access request escalation state
    /// 4. Records the escalation event for audit
    ///
    /// Note: The escalation targets are stored in the event for notification
    /// purposes. The actual approval flow continues to use the workflow's
    /// approver resolution logic - escalation adds additional approvers or
    /// changes the expected approver set.
    pub async fn execute_escalation(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        step: &GovApprovalStep,
        original_approver_id: Option<Uuid>,
        reason: EscalationReason,
    ) -> Result<EscalationResult> {
        let current_level = request.current_escalation_level;
        let new_level = current_level + 1;

        // Get escalation configuration
        let (levels, fallback) = self.get_escalation_config(tenant_id, step.id).await?;

        // Check if we have a level to escalate to
        let level = levels.iter().find(|l| l.level_order == new_level);

        match level {
            Some(level) => {
                // Resolve the target for this level
                let target = self
                    .resolve_escalation_target(tenant_id, level, original_approver_id)
                    .await?;

                // T076: Skip level if escalation target is the same as original approver
                // This prevents escalating to someone who already didn't respond
                if let Some(orig_id) = original_approver_id {
                    if target.user_ids.len() == 1 && target.user_ids[0] == orig_id {
                        info!(
                            request_id = %request.id,
                            level = new_level,
                            "Skipping escalation level - target is same as original approver"
                        );
                        // Recursively try next level
                        let mut request_copy = request.clone();
                        request_copy.current_escalation_level = new_level;
                        return Box::pin(self.execute_escalation(
                            tenant_id,
                            &request_copy,
                            step,
                            original_approver_id,
                            reason,
                        ))
                        .await;
                    }
                }

                // Calculate new deadline
                let new_deadline = Some(Utc::now() + level.timeout_duration());

                // Update request escalation state
                GovAccessRequest::update_escalation(
                    &self.pool,
                    tenant_id,
                    request.id,
                    new_level,
                    new_deadline,
                )
                .await?;

                // Record escalation event
                let event = GovEscalationEvent::create(
                    &self.pool,
                    tenant_id,
                    CreateEscalationEvent {
                        request_id: request.id,
                        step_order: step.step_order,
                        escalation_level: new_level,
                        original_approver_id,
                        escalation_target_type: target.target_type,
                        escalation_target_ids: target.user_ids.clone(),
                        reason,
                        previous_deadline: request.current_deadline,
                        new_deadline,
                        metadata: None,
                    },
                )
                .await?;

                // Emit Kafka event for escalation occurred
                #[cfg(feature = "kafka")]
                if let Some(producer) = &self.event_producer {
                    let kafka_event = EscalationOccurred {
                        request_id: request.id,
                        step_order: step.step_order,
                        escalation_level: new_level,
                        original_approver_id,
                        target_type: self.convert_target_type(&target.target_type),
                        target_ids: target.user_ids.clone(),
                        reason: self.convert_reason(&reason),
                        previous_deadline: request.current_deadline,
                        new_deadline,
                    };
                    if let Err(e) = producer.publish(kafka_event, tenant_id, None).await {
                        warn!(
                            request_id = %request.id,
                            error = %e,
                            "Failed to publish EscalationOccurred event"
                        );
                    }
                }

                Ok(EscalationResult {
                    success: true,
                    new_level,
                    new_deadline,
                    targets: vec![target],
                    event: Some(event),
                    levels_exhausted: false,
                    fallback_action: None,
                })
            }
            None => {
                // All levels exhausted - apply fallback action
                self.apply_fallback_action(tenant_id, request, step, fallback, reason)
                    .await
            }
        }
    }

    /// Get escalation configuration for a step.
    ///
    /// Returns the escalation levels and final fallback action.
    async fn get_escalation_config(
        &self,
        tenant_id: Uuid,
        step_id: Uuid,
    ) -> Result<(Vec<GovEscalationLevel>, FinalFallbackAction)> {
        // First check for step-specific rule
        if let Some(rule) = GovEscalationRule::find_by_step(&self.pool, tenant_id, step_id).await? {
            let levels = GovEscalationLevel::find_by_rule(&self.pool, tenant_id, rule.id).await?;
            let fallback = rule
                .final_fallback
                .unwrap_or(FinalFallbackAction::RemainPending);
            return Ok((levels, fallback));
        }

        // Fall back to tenant default policy
        if let Some(policy) =
            GovEscalationPolicy::find_active_default(&self.pool, tenant_id).await?
        {
            let levels =
                GovEscalationLevel::find_by_policy(&self.pool, tenant_id, policy.id).await?;
            return Ok((levels, policy.final_fallback));
        }

        // No configuration - return empty with default fallback
        Ok((vec![], FinalFallbackAction::RemainPending))
    }

    /// Apply the final fallback action when all escalation levels are exhausted.
    async fn apply_fallback_action(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        step: &GovApprovalStep,
        action: FinalFallbackAction,
        reason: EscalationReason,
    ) -> Result<EscalationResult> {
        match action {
            FinalFallbackAction::AutoApprove => {
                // Automatically approve the request
                GovAccessRequest::update_status(
                    &self.pool,
                    tenant_id,
                    request.id,
                    xavyo_db::models::GovRequestStatus::Approved,
                )
                .await?;

                // Record the event
                let event = self
                    .record_exhausted_event(tenant_id, request, step, reason, "auto_approve")
                    .await?;

                // Emit Kafka event for escalation exhausted
                #[cfg(feature = "kafka")]
                self.emit_exhausted_event(
                    tenant_id,
                    request,
                    step,
                    &FinalFallbackAction::AutoApprove,
                    "approved",
                )
                .await;

                Ok(EscalationResult {
                    success: true,
                    new_level: request.current_escalation_level,
                    new_deadline: None,
                    targets: vec![],
                    event: Some(event),
                    levels_exhausted: true,
                    fallback_action: Some(FinalFallbackAction::AutoApprove),
                })
            }

            FinalFallbackAction::AutoReject => {
                // Automatically reject the request
                GovAccessRequest::update_status(
                    &self.pool,
                    tenant_id,
                    request.id,
                    xavyo_db::models::GovRequestStatus::Rejected,
                )
                .await?;

                // Record the event
                let event = self
                    .record_exhausted_event(tenant_id, request, step, reason, "auto_reject")
                    .await?;

                // Emit Kafka event for escalation exhausted
                #[cfg(feature = "kafka")]
                self.emit_exhausted_event(
                    tenant_id,
                    request,
                    step,
                    &FinalFallbackAction::AutoReject,
                    "rejected",
                )
                .await;

                Ok(EscalationResult {
                    success: true,
                    new_level: request.current_escalation_level,
                    new_deadline: None,
                    targets: vec![],
                    event: Some(event),
                    levels_exhausted: true,
                    fallback_action: Some(FinalFallbackAction::AutoReject),
                })
            }

            FinalFallbackAction::EscalateAdmin => {
                // Escalate to tenant admins as final resort
                let admins = self.get_tenant_admins(tenant_id).await?;

                if admins.is_empty() {
                    // No admins available - remain pending (inline the logic to avoid recursion)
                    GovAccessRequest::cancel_escalation(&self.pool, tenant_id, request.id).await?;

                    let event = self
                        .record_exhausted_event(tenant_id, request, step, reason, "remain_pending")
                        .await?;

                    // Emit Kafka event for escalation exhausted (no admins available)
                    #[cfg(feature = "kafka")]
                    self.emit_exhausted_event(
                        tenant_id,
                        request,
                        step,
                        &FinalFallbackAction::RemainPending,
                        "pending",
                    )
                    .await;

                    return Ok(EscalationResult {
                        success: true,
                        new_level: request.current_escalation_level,
                        new_deadline: None,
                        targets: vec![],
                        event: Some(event),
                        levels_exhausted: true,
                        fallback_action: Some(FinalFallbackAction::RemainPending),
                    });
                }

                let new_level = request.current_escalation_level + 1;
                let new_deadline = Some(Utc::now() + Duration::hours(24));

                // Update request state
                GovAccessRequest::update_escalation(
                    &self.pool,
                    tenant_id,
                    request.id,
                    new_level,
                    new_deadline,
                )
                .await?;

                // Record the event
                let event = GovEscalationEvent::create(
                    &self.pool,
                    tenant_id,
                    CreateEscalationEvent {
                        request_id: request.id,
                        step_order: step.step_order,
                        escalation_level: new_level,
                        original_approver_id: None,
                        escalation_target_type: EscalationTargetType::TenantAdmin,
                        escalation_target_ids: admins.clone(),
                        reason,
                        previous_deadline: request.current_deadline,
                        new_deadline,
                        metadata: Some(serde_json::json!({
                            "fallback_action": "escalate_admin",
                            "levels_exhausted": true
                        })),
                    },
                )
                .await?;

                // Emit Kafka event for escalation to admin (this is both an escalation and exhausted)
                #[cfg(feature = "kafka")]
                if let Some(producer) = &self.event_producer {
                    // Emit EscalationOccurred for the admin escalation
                    let escalation_event = EscalationOccurred {
                        request_id: request.id,
                        step_order: step.step_order,
                        escalation_level: new_level,
                        original_approver_id: None,
                        target_type: EventEscalationTargetType::TenantAdmin,
                        target_ids: admins.clone(),
                        reason: self.convert_reason(&reason),
                        previous_deadline: request.current_deadline,
                        new_deadline,
                    };
                    if let Err(e) = producer.publish(escalation_event, tenant_id, None).await {
                        warn!(
                            request_id = %request.id,
                            error = %e,
                            "Failed to publish EscalationOccurred event for admin fallback"
                        );
                    }

                    // Also emit EscalationExhausted
                    let exhausted_event = EscalationExhausted {
                        request_id: request.id,
                        step_order: step.step_order,
                        final_escalation_level: new_level,
                        fallback_action: self.convert_fallback(&FinalFallbackAction::EscalateAdmin),
                        result_status: "escalated_to_admin".to_string(),
                    };
                    if let Err(e) = producer.publish(exhausted_event, tenant_id, None).await {
                        warn!(
                            request_id = %request.id,
                            error = %e,
                            "Failed to publish EscalationExhausted event for admin fallback"
                        );
                    }
                }

                Ok(EscalationResult {
                    success: true,
                    new_level,
                    new_deadline,
                    targets: vec![ResolvedEscalationTarget {
                        target_type: EscalationTargetType::TenantAdmin,
                        user_ids: admins,
                        group_id: None,
                        display_name: "Tenant Administrators (fallback)".to_string(),
                    }],
                    event: Some(event),
                    levels_exhausted: true,
                    fallback_action: Some(FinalFallbackAction::EscalateAdmin),
                })
            }

            FinalFallbackAction::RemainPending => {
                // Clear deadline but keep request pending
                GovAccessRequest::cancel_escalation(&self.pool, tenant_id, request.id).await?;

                // Record the event
                let event = self
                    .record_exhausted_event(tenant_id, request, step, reason, "remain_pending")
                    .await?;

                // Emit Kafka event for escalation exhausted
                #[cfg(feature = "kafka")]
                self.emit_exhausted_event(
                    tenant_id,
                    request,
                    step,
                    &FinalFallbackAction::RemainPending,
                    "pending",
                )
                .await;

                Ok(EscalationResult {
                    success: true,
                    new_level: request.current_escalation_level,
                    new_deadline: None,
                    targets: vec![],
                    event: Some(event),
                    levels_exhausted: true,
                    fallback_action: Some(FinalFallbackAction::RemainPending),
                })
            }
        }
    }

    /// Record an event when escalation levels are exhausted.
    async fn record_exhausted_event(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        step: &GovApprovalStep,
        reason: EscalationReason,
        action: &str,
    ) -> Result<GovEscalationEvent> {
        GovEscalationEvent::create(
            &self.pool,
            tenant_id,
            CreateEscalationEvent {
                request_id: request.id,
                step_order: step.step_order,
                escalation_level: request.current_escalation_level,
                original_approver_id: None,
                escalation_target_type: EscalationTargetType::TenantAdmin,
                escalation_target_ids: vec![],
                reason,
                previous_deadline: request.current_deadline,
                new_deadline: None,
                metadata: Some(serde_json::json!({
                    "fallback_action": action,
                    "levels_exhausted": true
                })),
            },
        )
        .await
        .map_err(GovernanceError::Database)
    }

    /// Get tenant administrators for escalation.
    async fn get_tenant_admins(&self, tenant_id: Uuid) -> Result<Vec<Uuid>> {
        // Query users with admin role in this tenant
        // This is a simplified implementation - in production, you'd check
        // role assignments more thoroughly
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT u.id
            FROM users u
            JOIN user_roles ur ON ur.user_id = u.id
            JOIN roles r ON r.id = ur.role_id
            WHERE u.tenant_id = $1
              AND r.name IN ('admin', 'tenant_admin', 'governance_admin')
              AND u.is_active = true
            ORDER BY u.id
            LIMIT 10
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Send warning notification before escalation deadline.
    pub async fn send_escalation_warning(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
    ) -> Result<()> {
        // Mark warning as sent
        GovAccessRequest::mark_warning_sent(&self.pool, tenant_id, request.id).await?;

        // Emit Kafka event for notification service to send email/push
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            if let Some(deadline) = request.current_deadline {
                let now = Utc::now();
                let seconds_remaining = (deadline - now).num_seconds().max(0);

                // Get the current approver for this step
                let approver_id = if let Some(workflow_id) = request.workflow_id {
                    // Get the step to find the approver
                    let step_order = request.current_step + 1;
                    if let Ok(Some(step)) = GovApprovalStep::find_by_workflow_and_order(
                        &self.pool,
                        workflow_id,
                        step_order,
                    )
                    .await
                    {
                        self.get_current_approver_id(tenant_id, request, &step)
                            .await
                            .ok()
                            .flatten()
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(approver_id) = approver_id {
                    let kafka_event = EscalationWarning {
                        request_id: request.id,
                        step_order: request.current_step + 1, // step_order is 1-indexed
                        approver_id,
                        deadline,
                        seconds_remaining,
                        escalation_level: request.current_escalation_level,
                    };
                    if let Err(e) = producer.publish(kafka_event, tenant_id, None).await {
                        warn!(
                            request_id = %request.id,
                            error = %e,
                            "Failed to publish EscalationWarning event"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Get the expected approver for a request's current step.
    /// This resolves the approver type to actual user IDs.
    pub async fn get_current_approver_id(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        step: &GovApprovalStep,
    ) -> Result<Option<Uuid>> {
        match step.approver_type {
            xavyo_db::models::GovApproverType::Manager => {
                // Get requester's manager
                let manager =
                    User::get_manager(&self.pool, tenant_id, request.requester_id).await?;
                Ok(manager.map(|m| *m.user_id().as_uuid()))
            }
            xavyo_db::models::GovApproverType::EntitlementOwner => {
                // Get entitlement owner
                let entitlement = xavyo_db::models::GovEntitlement::find_by_id(
                    &self.pool,
                    tenant_id,
                    request.entitlement_id,
                )
                .await?;
                Ok(entitlement.and_then(|e| e.owner_id))
            }
            xavyo_db::models::GovApproverType::SpecificUsers => {
                // Return first specific approver (or None if empty)
                Ok(step
                    .specific_approvers
                    .as_ref()
                    .and_then(|a| a.first().copied()))
            }
        }
    }

    /// Get reference to the database pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Convert database EscalationTargetType to event EscalationTargetType.
    #[cfg(feature = "kafka")]
    fn convert_target_type(&self, target: &EscalationTargetType) -> EventEscalationTargetType {
        match target {
            EscalationTargetType::SpecificUser => EventEscalationTargetType::SpecificUser,
            EscalationTargetType::ApprovalGroup => EventEscalationTargetType::ApprovalGroup,
            EscalationTargetType::Manager => EventEscalationTargetType::Manager,
            EscalationTargetType::ManagerChain => EventEscalationTargetType::ManagerChain,
            EscalationTargetType::TenantAdmin => EventEscalationTargetType::TenantAdmin,
        }
    }

    /// Convert database EscalationReason to event EscalationReason.
    #[cfg(feature = "kafka")]
    fn convert_reason(&self, reason: &EscalationReason) -> EventEscalationReason {
        match reason {
            EscalationReason::Timeout => EventEscalationReason::Timeout,
            EscalationReason::ManualEscalation => EventEscalationReason::ManualEscalation,
            EscalationReason::TargetUnavailable => EventEscalationReason::TargetUnavailable,
        }
    }

    /// Convert database FinalFallbackAction to event FinalFallbackAction.
    #[cfg(feature = "kafka")]
    fn convert_fallback(&self, action: &FinalFallbackAction) -> EventFallbackAction {
        match action {
            FinalFallbackAction::EscalateAdmin => EventFallbackAction::EscalateAdmin,
            FinalFallbackAction::AutoApprove => EventFallbackAction::AutoApprove,
            FinalFallbackAction::AutoReject => EventFallbackAction::AutoReject,
            FinalFallbackAction::RemainPending => EventFallbackAction::RemainPending,
        }
    }

    /// Cancel pending escalation for an access request (T067).
    ///
    /// This stops the escalation timer but keeps the current assignee.
    /// Useful when manual intervention resolves the situation.
    pub async fn cancel_escalation(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        cancelled_by: Uuid,
    ) -> Result<CancelEscalationResult> {
        let request = GovAccessRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::AccessRequestNotFound(request_id))?;

        // Can only cancel if there's an active escalation
        if request.current_escalation_level == 0 {
            return Err(GovernanceError::Validation(
                "Request has not been escalated".to_string(),
            ));
        }

        // Get current step for event metadata (used in kafka event)
        #[cfg(feature = "kafka")]
        let step = self.get_current_step(&request).await?;

        // Cancel the escalation (clear deadline but keep level for audit)
        GovAccessRequest::cancel_escalation(&self.pool, tenant_id, request_id).await?;

        // Get current escalation target for the event
        let events = GovEscalationEvent::find_by_request(&self.pool, tenant_id, request_id).await?;
        let current_assignee_id = events
            .last()
            .and_then(|e| e.escalation_target_ids.first().copied())
            .unwrap_or(cancelled_by);

        // Emit Kafka event for cancellation
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            use xavyo_events::events::EscalationCancelled;
            let kafka_event = EscalationCancelled {
                request_id,
                step_order: step.map(|s| s.step_order).unwrap_or(1),
                escalation_level: request.current_escalation_level,
                cancelled_by,
                current_assignee_id,
            };
            if let Err(e) = producer.publish(kafka_event, tenant_id, None).await {
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Failed to publish EscalationCancelled event"
                );
            }
        }

        Ok(CancelEscalationResult {
            success: true,
            previous_level: request.current_escalation_level,
            current_assignee_id,
        })
    }

    /// Reset escalation to original approver (T068).
    ///
    /// This returns the work item to the original approver and restarts
    /// the escalation timer from the beginning.
    #[allow(unused_variables)] // reset_by used in Kafka event under feature flag
    pub async fn reset_escalation(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        reset_by: Uuid,
    ) -> Result<ResetEscalationResult> {
        let request = GovAccessRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::AccessRequestNotFound(request_id))?;

        // Can only reset if there's been an escalation
        if request.current_escalation_level == 0 {
            return Err(GovernanceError::Validation(
                "Request has not been escalated".to_string(),
            ));
        }

        // Get the original approver from the first escalation event
        let events = GovEscalationEvent::find_by_request(&self.pool, tenant_id, request_id).await?;
        let original_approver_id = events
            .first()
            .and_then(|e| e.original_approver_id)
            .ok_or_else(|| {
                GovernanceError::Validation("Cannot determine original approver".to_string())
            })?;

        // Get current step for deadline calculation
        let step = self.get_current_step(&request).await?;

        // Calculate new deadline from now
        let new_deadline = if let Some(ref step) = step {
            self.calculate_deadline(tenant_id, step, Utc::now()).await?
        } else {
            None
        };

        // Reset escalation level to 0 and set new deadline
        GovAccessRequest::reset_escalation(&self.pool, tenant_id, request_id, new_deadline).await?;

        // Emit Kafka event for reset
        #[cfg(feature = "kafka")]
        if let Some(producer) = &self.event_producer {
            use xavyo_events::events::EscalationReset;
            let kafka_event = EscalationReset {
                request_id,
                step_order: step.as_ref().map(|s| s.step_order).unwrap_or(1),
                previous_escalation_level: request.current_escalation_level,
                reset_by,
                original_approver_id,
                new_deadline,
            };
            if let Err(e) = producer.publish(kafka_event, tenant_id, None).await {
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Failed to publish EscalationReset event"
                );
            }
        }

        Ok(ResetEscalationResult {
            success: true,
            previous_level: request.current_escalation_level,
            original_approver_id,
            new_deadline,
        })
    }

    /// Get the current approval step for a request.
    async fn get_current_step(
        &self,
        request: &GovAccessRequest,
    ) -> Result<Option<GovApprovalStep>> {
        if let Some(workflow_id) = request.workflow_id {
            let step_order = request.current_step + 1;
            GovApprovalStep::find_by_workflow_and_order(&self.pool, workflow_id, step_order)
                .await
                .map_err(GovernanceError::Database)
        } else {
            Ok(None)
        }
    }

    /// Emit EscalationExhausted Kafka event.
    #[cfg(feature = "kafka")]
    async fn emit_exhausted_event(
        &self,
        tenant_id: Uuid,
        request: &GovAccessRequest,
        step: &GovApprovalStep,
        fallback_action: &FinalFallbackAction,
        result_status: &str,
    ) {
        if let Some(producer) = &self.event_producer {
            let kafka_event = EscalationExhausted {
                request_id: request.id,
                step_order: step.step_order,
                final_escalation_level: request.current_escalation_level,
                fallback_action: self.convert_fallback(fallback_action),
                result_status: result_status.to_string(),
            };
            if let Err(e) = producer.publish(kafka_event, tenant_id, None).await {
                warn!(
                    request_id = %request.id,
                    error = %e,
                    "Failed to publish EscalationExhausted event"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_target() {
        let target = ResolvedEscalationTarget {
            target_type: EscalationTargetType::Manager,
            user_ids: vec![Uuid::new_v4()],
            group_id: None,
            display_name: "Manager of approver".to_string(),
        };

        assert_eq!(target.user_ids.len(), 1);
        assert!(target.group_id.is_none());
    }

    #[test]
    fn test_escalation_result_success() {
        let result = EscalationResult {
            success: true,
            new_level: 1,
            new_deadline: Some(Utc::now() + Duration::hours(24)),
            targets: vec![],
            event: None,
            levels_exhausted: false,
            fallback_action: None,
        };

        assert!(result.success);
        assert_eq!(result.new_level, 1);
        assert!(!result.levels_exhausted);
    }

    #[test]
    fn test_escalation_result_exhausted() {
        let result = EscalationResult {
            success: true,
            new_level: 3,
            new_deadline: None,
            targets: vec![],
            event: None,
            levels_exhausted: true,
            fallback_action: Some(FinalFallbackAction::AutoReject),
        };

        assert!(result.success);
        assert!(result.levels_exhausted);
        assert!(matches!(
            result.fallback_action,
            Some(FinalFallbackAction::AutoReject)
        ));
    }
}
