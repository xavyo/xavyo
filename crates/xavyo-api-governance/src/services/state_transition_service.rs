//! State transition service for Object Lifecycle States (F052).
//!
//! This service manages state transitions including validation, approval integration,
//! and audit record creation.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::{
    AuditActionType, CreateGovStateTransitionAudit, CreateGovStateTransitionRequest,
    EntitlementAction, FailedOperationType, GovLifecycleConfig, GovLifecycleState,
    GovLifecycleTransition, GovLifecycleTransitionWithStates, GovStateTransitionAudit,
    GovStateTransitionRequest, LifecycleObjectType, OutputFormat, TransitionAuditFilter,
    TransitionRequestFilter, TransitionRequestStatus, UpdateGovStateTransitionRequest, User,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::{
    events::{
        StateAccessRulesApplied, StateAccessRulesReversed, StateTransitionExecuted,
        StateTransitionRequested, StateTransitionRolledBack,
    },
    EventProducer,
};

use crate::models::{
    ExecuteTransitionRequest, LifecycleStateResponse, LifecycleTransitionResponse,
    ListTransitionAuditQuery, ListTransitionRequestsQuery, ObjectLifecycleStatusResponse,
    RollbackInfo, TransitionAuditListResponse, TransitionAuditResponse,
    TransitionRequestListResponse, TransitionRequestResponse, TransitionStateInfo,
};
use crate::services::failed_operation_service::{EntitlementActionPayload, FailedOperationService};
use crate::services::state_access_rule_service::StateAccessRuleService;

/// Service for state transition operations.
pub struct StateTransitionService {
    pool: PgPool,
    access_rule_service: Arc<StateAccessRuleService>,
    failed_operation_service: Option<Arc<FailedOperationService>>,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl StateTransitionService {
    /// Create a new state transition service.
    #[must_use]
    pub fn new(pool: PgPool, access_rule_service: Arc<StateAccessRuleService>) -> Self {
        Self {
            pool,
            access_rule_service,
            failed_operation_service: None,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new state transition service with failed operation retry support.
    #[must_use]
    pub fn with_retry_support(
        pool: PgPool,
        access_rule_service: Arc<StateAccessRuleService>,
        failed_operation_service: Arc<FailedOperationService>,
    ) -> Self {
        Self {
            pool,
            access_rule_service,
            failed_operation_service: Some(failed_operation_service),
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new state transition service with full feature support.
    #[cfg(feature = "kafka")]
    pub fn with_full_support(
        pool: PgPool,
        access_rule_service: Arc<StateAccessRuleService>,
        failed_operation_service: Arc<FailedOperationService>,
        event_producer: Arc<EventProducer>,
    ) -> Self {
        Self {
            pool,
            access_rule_service,
            failed_operation_service: Some(failed_operation_service),
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing lifecycle events.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(mut self, producer: Arc<EventProducer>) -> Self {
        self.event_producer = Some(producer);
        self
    }

    /// Execute a state transition.
    ///
    /// This is the main entry point for transitioning an object between states.
    /// It validates the transition, checks approval requirements, updates the object,
    /// and creates audit records.
    pub async fn execute_transition(
        &self,
        tenant_id: Uuid,
        requested_by: Uuid,
        request: ExecuteTransitionRequest,
    ) -> Result<(StatusCode, TransitionRequestResponse)> {
        // 1. Get the transition definition
        let transition =
            GovLifecycleTransition::find_by_id(&self.pool, tenant_id, request.transition_id)
                .await?
                .ok_or(GovernanceError::LifecycleTransitionNotFound(
                    request.transition_id,
                ))?;

        // 2. Get the lifecycle configuration
        let config = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, transition.config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(
                transition.config_id,
            ))?;

        // 3. Validate object type matches
        if config.object_type != request.object_type {
            return Err(GovernanceError::Validation(format!(
                "Transition is for {:?} objects, not {:?}",
                config.object_type, request.object_type
            )));
        }

        // 4. Validate configuration is active
        if !config.is_active {
            return Err(GovernanceError::Validation(
                "Lifecycle configuration is not active".to_string(),
            ));
        }

        // 5. Get object's current state and validate it matches from_state
        let current_state_id = self
            .get_object_current_state_id(tenant_id, &request.object_type, request.object_id)
            .await?;

        if current_state_id != Some(transition.from_state_id) {
            let from_state =
                GovLifecycleState::find_by_id(&self.pool, tenant_id, transition.from_state_id)
                    .await?
                    .map_or_else(|| "unknown".to_string(), |s| s.name);

            return Err(GovernanceError::InvalidTransition(format!(
                "Object is not in the required '{from_state}' state for this transition"
            )));
        }

        // 5a. Evaluate transition conditions (F-193)
        if transition.conditions.is_some() {
            let condition_evaluator =
                crate::services::condition_evaluator::ConditionEvaluator::new(self.pool.clone());
            let evaluation_result = condition_evaluator
                .evaluate(tenant_id, request.transition_id, request.object_id)
                .await?;

            if !evaluation_result.all_satisfied {
                let failed_count = evaluation_result
                    .conditions
                    .iter()
                    .filter(|c| !c.satisfied)
                    .count();
                return Err(GovernanceError::TransitionConditionsNotSatisfied {
                    failed_count,
                    total_count: evaluation_result.conditions.len(),
                    summary: evaluation_result.summary,
                });
            }
        }

        // 6. Get state names for response/audit
        let from_state =
            GovLifecycleState::find_by_id(&self.pool, tenant_id, transition.from_state_id)
                .await?
                .ok_or(GovernanceError::LifecycleStateNotFound(
                    transition.from_state_id,
                ))?;

        let to_state = GovLifecycleState::find_by_id(&self.pool, tenant_id, transition.to_state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(
                transition.to_state_id,
            ))?;

        // 7. Create the transition request record
        let create_request = CreateGovStateTransitionRequest {
            config_id: transition.config_id,
            transition_id: transition.id,
            object_id: request.object_id,
            object_type: request.object_type,
            from_state_id: transition.from_state_id,
            to_state_id: transition.to_state_id,
            requested_by,
            scheduled_for: request.scheduled_for,
        };

        let transition_request =
            GovStateTransitionRequest::create(&self.pool, tenant_id, &create_request).await?;

        // Emit StateTransitionRequested event
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event = StateTransitionRequested {
                request_id: transition_request.id,
                object_id: request.object_id,
                object_type: format!("{:?}", request.object_type).to_lowercase(),
                from_state: from_state.name.clone(),
                to_state: to_state.name.clone(),
                transition_name: transition.name.clone(),
                requested_by,
                requires_approval: transition.requires_approval,
                requested_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, Some(requested_by)).await {
                warn!(
                    request_id = %transition_request.id,
                    error = %e,
                    "Failed to publish StateTransitionRequested event"
                );
            }
        }

        // 8. Handle scheduled transitions
        if request.scheduled_for.is_some() {
            // TODO: Create scheduled transition record
            // For now, return the request as pending
            return Ok((
                StatusCode::ACCEPTED,
                self.build_transition_response(
                    &transition_request,
                    &transition.name,
                    &from_state.name,
                    &to_state.name,
                ),
            ));
        }

        // 9. Handle approval workflow
        if transition.requires_approval {
            // TODO: Create approval request and link it
            // For now, mark as pending approval
            let update = UpdateGovStateTransitionRequest {
                status: Some(TransitionRequestStatus::PendingApproval),
                approval_request_id: None, // Would be set when approval request created
                executed_at: None,
                grace_period_ends_at: None,
                rollback_available: None,
                error_message: None,
            };

            let updated_request = GovStateTransitionRequest::update(
                &self.pool,
                tenant_id,
                transition_request.id,
                &update,
            )
            .await?
            .ok_or(GovernanceError::StateTransitionRequestNotFound(
                transition_request.id,
            ))?;

            return Ok((
                StatusCode::ACCEPTED,
                self.build_transition_response(
                    &updated_request,
                    &transition.name,
                    &from_state.name,
                    &to_state.name,
                ),
            ));
        }

        // 10. Execute the transition immediately
        let (final_request, _audit) = self
            .perform_transition(
                tenant_id,
                &transition_request,
                &transition,
                &from_state,
                &to_state,
                requested_by,
            )
            .await?;

        Ok((
            StatusCode::OK,
            self.build_transition_response(
                &final_request,
                &transition.name,
                &from_state.name,
                &to_state.name,
            ),
        ))
    }

    /// Perform the actual state transition.
    ///
    /// This updates the object's state, applies access rules, creates audit records,
    /// and handles grace periods.
    async fn perform_transition(
        &self,
        tenant_id: Uuid,
        request: &GovStateTransitionRequest,
        transition: &GovLifecycleTransition,
        from_state: &GovLifecycleState,
        to_state: &GovLifecycleState,
        actor_id: Uuid,
    ) -> Result<(GovStateTransitionRequest, GovStateTransitionAudit)> {
        let now = Utc::now();
        let object_type_str = format!("{:?}", request.object_type).to_lowercase();

        // Calculate grace period end time
        let grace_period_ends_at = if transition.grace_period_hours > 0 {
            Some(now + Duration::hours(i64::from(transition.grace_period_hours)))
        } else {
            None
        };

        // 1. Capture entitlements before transition
        let entitlements_before_snapshot = self
            .access_rule_service
            .capture_access_snapshot(tenant_id, &object_type_str, request.object_id)
            .await?;

        // 1a. Execute exit actions on from_state (F-193)
        if from_state.exit_actions.is_some() {
            self.execute_state_actions(
                tenant_id,
                request.object_id,
                request.id, // Use request.id as we don't have audit yet
                from_state,
                actor_id,
                now,
                xavyo_db::ActionTriggerType::Exit,
            )
            .await?;
        }

        // 2. Update the object's lifecycle state
        self.update_object_lifecycle_state(
            tenant_id,
            &request.object_type,
            request.object_id,
            to_state.id,
        )
        .await?;

        // 2a. Execute entry actions on to_state (F-193)
        if to_state.entry_actions.is_some() {
            self.execute_state_actions(
                tenant_id,
                request.object_id,
                request.id, // Use request.id as we don't have audit yet
                to_state,
                actor_id,
                now,
                xavyo_db::ActionTriggerType::Entry,
            )
            .await?;
        }

        // 3. Apply state-based access rules
        let access_result = self
            .access_rule_service
            .apply_state_access_rules(tenant_id, &object_type_str, request.object_id, to_state)
            .await?;

        // 3a. Queue any failed entitlement actions for retry
        if !access_result.errors.is_empty() {
            if let Some(ref failed_op_service) = self.failed_operation_service {
                // Determine which action was being performed
                let action = match to_state.entitlement_action {
                    EntitlementAction::Pause => "pause",
                    EntitlementAction::Revoke => "revoke",
                    EntitlementAction::None => "none",
                };

                // Extract failed assignment IDs from error messages
                // Errors have format "Failed to X assignment {uuid}: error"
                let failed_ids: Vec<Uuid> = access_result
                    .errors
                    .iter()
                    .filter_map(|e| {
                        // Try to extract UUID from error message
                        let parts: Vec<&str> = e.split_whitespace().collect();
                        for (i, part) in parts.iter().enumerate() {
                            if *part == "assignment" && i + 1 < parts.len() {
                                let uuid_str = parts[i + 1].trim_end_matches(':');
                                return Uuid::parse_str(uuid_str).ok();
                            }
                        }
                        None
                    })
                    .collect();

                if !failed_ids.is_empty() {
                    let failed_count = failed_ids.len();
                    let payload = EntitlementActionPayload {
                        action: action.to_string(),
                        user_id: request.object_id,
                        assignment_ids: failed_ids,
                    };

                    let error_message = access_result.errors.join("; ");

                    if let Err(e) = failed_op_service
                        .queue_failed_operation(
                            tenant_id,
                            FailedOperationType::EntitlementAction,
                            Some(request.id),
                            request.object_id,
                            request.object_type,
                            serde_json::to_value(&payload).unwrap_or_default(),
                            error_message.clone(),
                        )
                        .await
                    {
                        warn!(
                            request_id = %request.id,
                            error = %e,
                            "Failed to queue entitlement action for retry"
                        );
                    } else {
                        info!(
                            request_id = %request.id,
                            failed_count = failed_count,
                            "Queued failed entitlement actions for retry"
                        );
                    }
                }
            }
        }

        // 4. Capture entitlements after transition
        let entitlements_after_snapshot = self
            .access_rule_service
            .capture_access_snapshot(tenant_id, &object_type_str, request.object_id)
            .await?;

        // 5. Update the transition request
        let update = UpdateGovStateTransitionRequest {
            status: Some(TransitionRequestStatus::Executed),
            approval_request_id: None,
            executed_at: Some(now),
            grace_period_ends_at,
            rollback_available: Some(transition.grace_period_hours > 0),
            error_message: None,
        };

        let final_request =
            GovStateTransitionRequest::update(&self.pool, tenant_id, request.id, &update)
                .await?
                .ok_or(GovernanceError::StateTransitionRequestNotFound(request.id))?;

        // 6. Create audit record with entitlement snapshots
        let entitlements_before =
            serde_json::to_value(&entitlements_before_snapshot).unwrap_or_else(|_| json!([]));
        let entitlements_after =
            serde_json::to_value(&entitlements_after_snapshot).unwrap_or_else(|_| json!([]));

        // Include access rule results in metadata
        let metadata = if !access_result.paused.is_empty()
            || !access_result.revoked.is_empty()
            || !access_result.errors.is_empty()
        {
            Some(json!({
                "entitlements_paused": access_result.paused.len(),
                "entitlements_revoked": access_result.revoked.len(),
                "access_rule_errors": access_result.errors
            }))
        } else {
            None
        };

        let audit_input = CreateGovStateTransitionAudit {
            request_id: request.id,
            object_id: request.object_id,
            object_type: request.object_type,
            from_state: from_state.name.clone(),
            to_state: to_state.name.clone(),
            transition_name: transition.name.clone(),
            actor_id,
            action_type: AuditActionType::Execute,
            approval_details: None,
            entitlements_before: entitlements_before.clone(),
            entitlements_after: entitlements_after.clone(),
            metadata: metadata.clone(),
        };

        // Try to create audit record, queue for retry on failure
        let audit = match GovStateTransitionAudit::create(&self.pool, tenant_id, &audit_input).await
        {
            Ok(audit) => audit,
            Err(e) => {
                // Queue the audit record creation for retry
                if let Some(ref failed_op_service) = self.failed_operation_service {
                    let payload = json!({
                        "request_id": request.id,
                        "object_id": request.object_id,
                        "object_type": format!("{:?}", request.object_type).to_lowercase(),
                        "from_state": from_state.name,
                        "to_state": to_state.name,
                        "transition_name": transition.name,
                        "actor_id": actor_id,
                        "action_type": "execute",
                        "entitlements_before": entitlements_before,
                        "entitlements_after": entitlements_after,
                        "metadata": metadata
                    });

                    if let Err(queue_err) = failed_op_service
                        .queue_failed_operation(
                            tenant_id,
                            FailedOperationType::AuditRecord,
                            Some(request.id),
                            request.object_id,
                            request.object_type,
                            payload,
                            e.to_string(),
                        )
                        .await
                    {
                        warn!(
                            request_id = %request.id,
                            error = %queue_err,
                            "Failed to queue audit record for retry"
                        );
                    } else {
                        info!(
                            request_id = %request.id,
                            "Queued failed audit record creation for retry"
                        );
                    }
                }

                // Re-throw the original error since audit is critical
                return Err(e.into());
            }
        };

        // Emit StateTransitionExecuted event
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event = StateTransitionExecuted {
                request_id: request.id,
                object_id: request.object_id,
                object_type: format!("{:?}", request.object_type).to_lowercase(),
                from_state: from_state.name.clone(),
                to_state: to_state.name.clone(),
                transition_name: transition.name.clone(),
                actor_id,
                has_grace_period: transition.grace_period_hours > 0,
                grace_period_ends_at,
                executed_at: now,
            };
            if let Err(e) = producer.publish(event, tenant_id, Some(actor_id)).await {
                warn!(
                    request_id = %request.id,
                    error = %e,
                    "Failed to publish StateTransitionExecuted event"
                );
            }

            // Emit StateAccessRulesApplied if entitlements were affected
            let affected_count = (access_result.paused.len() + access_result.revoked.len()) as u32;
            if affected_count > 0 {
                let action = match to_state.entitlement_action {
                    EntitlementAction::Pause => "pause",
                    EntitlementAction::Revoke => "revoke",
                    EntitlementAction::None => "none",
                };
                let access_event = StateAccessRulesApplied {
                    request_id: request.id,
                    object_id: request.object_id,
                    state: to_state.name.clone(),
                    action: action.to_string(),
                    entitlements_affected: affected_count,
                    applied_at: now,
                };
                if let Err(e) = producer
                    .publish(access_event, tenant_id, Some(actor_id))
                    .await
                {
                    warn!(
                        request_id = %request.id,
                        error = %e,
                        "Failed to publish StateAccessRulesApplied event"
                    );
                }
            }
        }

        Ok((final_request, audit))
    }

    /// Get an object's current lifecycle state ID.
    async fn get_object_current_state_id(
        &self,
        tenant_id: Uuid,
        object_type: &LifecycleObjectType,
        object_id: Uuid,
    ) -> Result<Option<Uuid>> {
        match object_type {
            LifecycleObjectType::User => {
                User::get_lifecycle_state_id(&self.pool, tenant_id, object_id)
                    .await
                    .map_err(GovernanceError::from)
            }
            LifecycleObjectType::Entitlement => {
                // TODO: Implement for entitlements
                Err(GovernanceError::Validation(
                    "Entitlement lifecycle states not yet implemented".to_string(),
                ))
            }
            LifecycleObjectType::Role => {
                // TODO: Implement for roles
                Err(GovernanceError::Validation(
                    "Role lifecycle states not yet implemented".to_string(),
                ))
            }
        }
    }

    /// Update an object's lifecycle state.
    async fn update_object_lifecycle_state(
        &self,
        tenant_id: Uuid,
        object_type: &LifecycleObjectType,
        object_id: Uuid,
        state_id: Uuid,
    ) -> Result<()> {
        match object_type {
            LifecycleObjectType::User => {
                User::update_lifecycle_state(&self.pool, tenant_id, object_id, Some(state_id))
                    .await?
                    .ok_or(GovernanceError::Validation(format!(
                        "User not found: {object_id}"
                    )))?;
                Ok(())
            }
            LifecycleObjectType::Entitlement => Err(GovernanceError::Validation(
                "Entitlement lifecycle states not yet implemented".to_string(),
            )),
            LifecycleObjectType::Role => Err(GovernanceError::Validation(
                "Role lifecycle states not yet implemented".to_string(),
            )),
        }
    }

    /// Get an object's current state and available transitions.
    pub async fn get_object_state(
        &self,
        tenant_id: Uuid,
        object_type: &str,
        object_id: Uuid,
    ) -> Result<ObjectLifecycleStatusResponse> {
        // Parse object type
        let obj_type = match object_type.to_lowercase().as_str() {
            "user" => LifecycleObjectType::User,
            "entitlement" => LifecycleObjectType::Entitlement,
            "role" => LifecycleObjectType::Role,
            _ => {
                return Err(GovernanceError::Validation(format!(
                    "Invalid object type: {object_type}"
                )))
            }
        };

        // Get lifecycle configuration for this object type
        let config = GovLifecycleConfig::find_by_object_type(&self.pool, tenant_id, obj_type)
            .await?
            .ok_or(GovernanceError::Validation(format!(
                "No lifecycle configuration exists for {obj_type:?}"
            )))?;

        // Get object's current state
        let current_state_id = self
            .get_object_current_state_id(tenant_id, &obj_type, object_id)
            .await?;

        // Get current state details
        let current_state = if let Some(state_id) = current_state_id {
            let state = GovLifecycleState::find_by_id(&self.pool, tenant_id, state_id).await?;
            if let Some(s) = state {
                let object_count =
                    GovLifecycleState::count_objects_in_state(&self.pool, tenant_id, state_id)
                        .await?;
                Some(LifecycleStateResponse::from_model(s, object_count))
            } else {
                None
            }
        } else {
            // Object has no state - get initial state
            let initial =
                GovLifecycleState::find_initial_state(&self.pool, tenant_id, config.id).await?;
            if let Some(s) = initial {
                let object_count =
                    GovLifecycleState::count_objects_in_state(&self.pool, tenant_id, s.id).await?;
                Some(LifecycleStateResponse::from_model(s, object_count))
            } else {
                None
            }
        };

        // Get available transitions from current state
        let available_transitions = if let Some(state_id) = current_state_id {
            let transitions: Vec<GovLifecycleTransitionWithStates> =
                GovLifecycleTransition::list_available_from_state(&self.pool, tenant_id, state_id)
                    .await?;
            transitions
                .into_iter()
                .map(LifecycleTransitionResponse::from)
                .collect()
        } else {
            Vec::new()
        };

        // Check for active rollback window
        let active_rollback = if let Some(request) =
            GovStateTransitionRequest::find_with_active_grace_period(
                &self.pool, tenant_id, object_id,
            )
            .await?
        {
            let from_state =
                GovLifecycleState::find_by_id(&self.pool, tenant_id, request.from_state_id).await?;
            Some(RollbackInfo {
                request_id: request.id,
                restore_to_state: from_state.map(|s| s.name).unwrap_or_default(),
                expires_at: request.grace_period_ends_at.unwrap_or_else(Utc::now),
            })
        } else {
            None
        };

        Ok(ObjectLifecycleStatusResponse {
            object_id,
            object_type: obj_type,
            current_state,
            available_transitions,
            active_rollback,
            pending_schedules: Vec::new(), // TODO: Get pending scheduled transitions
        })
    }

    /// List transition requests.
    pub async fn list_transition_requests(
        &self,
        tenant_id: Uuid,
        params: &ListTransitionRequestsQuery,
    ) -> Result<TransitionRequestListResponse> {
        let filter = TransitionRequestFilter {
            object_id: params.object_id,
            object_type: params.object_type,
            status: params.status,
            requested_by: params.requested_by,
            rollback_available: params.rollback_available,
        };

        let limit = params.limit.unwrap_or(50).min(100);
        let offset = params.offset.unwrap_or(0);

        let requests = GovStateTransitionRequest::list_by_tenant(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;
        let total =
            GovStateTransitionRequest::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let mut items = Vec::new();
        for request in requests {
            // Get state and transition names
            if let Some(with_states) =
                GovStateTransitionRequest::find_by_id_with_states(&self.pool, tenant_id, request.id)
                    .await?
            {
                items.push(TransitionRequestResponse::from(with_states));
            }
        }

        Ok(TransitionRequestListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a transition request by ID.
    pub async fn get_transition_request(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
    ) -> Result<TransitionRequestResponse> {
        let with_states =
            GovStateTransitionRequest::find_by_id_with_states(&self.pool, tenant_id, request_id)
                .await?
                .ok_or(GovernanceError::StateTransitionRequestNotFound(request_id))?;

        Ok(TransitionRequestResponse::from(with_states))
    }

    /// List transition audit records.
    pub async fn list_transition_audit(
        &self,
        tenant_id: Uuid,
        params: &ListTransitionAuditQuery,
    ) -> Result<TransitionAuditListResponse> {
        let filter = TransitionAuditFilter {
            object_id: params.object_id,
            object_type: params.object_type,
            actor_id: params.actor_id,
            action_type: params.action_type,
            from_date: params.from_date,
            to_date: params.to_date,
        };

        let limit = params.limit.unwrap_or(50).min(100);
        let offset = params.offset.unwrap_or(0);

        let records =
            GovStateTransitionAudit::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            GovStateTransitionAudit::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let items: Vec<TransitionAuditResponse> = records
            .into_iter()
            .map(TransitionAuditResponse::from)
            .collect();

        Ok(TransitionAuditListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a transition audit record by ID.
    pub async fn get_transition_audit(
        &self,
        tenant_id: Uuid,
        audit_id: Uuid,
    ) -> Result<TransitionAuditResponse> {
        let audit = GovStateTransitionAudit::find_by_id(&self.pool, tenant_id, audit_id)
            .await?
            .ok_or(GovernanceError::TransitionAuditNotFound(audit_id))?;

        Ok(TransitionAuditResponse::from(audit))
    }

    /// Rollback a transition within its grace period.
    pub async fn rollback_transition(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        actor_id: Uuid,
        reason: Option<String>,
    ) -> Result<TransitionRequestResponse> {
        // 1. Get the transition request
        let request = GovStateTransitionRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::StateTransitionRequestNotFound(request_id))?;

        let object_type_str = format!("{:?}", request.object_type).to_lowercase();

        // 2. Validate rollback is available
        if !request.rollback_available {
            return Err(GovernanceError::Validation(
                "Rollback is not available for this transition".to_string(),
            ));
        }

        if request.status != TransitionRequestStatus::Executed {
            return Err(GovernanceError::Validation(
                "Only executed transitions can be rolled back".to_string(),
            ));
        }

        if let Some(ends_at) = request.grace_period_ends_at {
            if Utc::now() > ends_at {
                return Err(GovernanceError::GracePeriodExpired(request_id));
            }
        }

        // 3. Get state names
        let from_state =
            GovLifecycleState::find_by_id(&self.pool, tenant_id, request.from_state_id)
                .await?
                .ok_or(GovernanceError::LifecycleStateNotFound(
                    request.from_state_id,
                ))?;

        let to_state = GovLifecycleState::find_by_id(&self.pool, tenant_id, request.to_state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(request.to_state_id))?;

        let transition =
            GovLifecycleTransition::find_by_id(&self.pool, tenant_id, request.transition_id)
                .await?
                .ok_or(GovernanceError::LifecycleTransitionNotFound(
                    request.transition_id,
                ))?;

        // 4. Capture entitlements before rollback
        let entitlements_before_snapshot = self
            .access_rule_service
            .capture_access_snapshot(tenant_id, &object_type_str, request.object_id)
            .await?;

        // 5. Restore object to previous state
        self.update_object_lifecycle_state(
            tenant_id,
            &request.object_type,
            request.object_id,
            from_state.id,
        )
        .await?;

        // 6. Restore entitlements based on from_state's action (reverse the effect)
        // If from_state has entitlement_action = None, we need to resume any paused entitlements
        let access_result = if from_state.entitlement_action == EntitlementAction::None
            && to_state.entitlement_action == EntitlementAction::Pause
        {
            // The transition paused entitlements, so rollback should resume them
            self.access_rule_service
                .resume_entitlements(tenant_id, request.object_id)
                .await?
        } else {
            // For other cases (like revoke), we can try to restore from the original audit
            // Get the original audit record to find entitlements_before
            let original_audits =
                GovStateTransitionAudit::find_by_request_id(&self.pool, tenant_id, request_id)
                    .await?;

            if let Some(original_audit) = original_audits
                .into_iter()
                .find(|a| a.action_type == AuditActionType::Execute)
            {
                // Try to parse the entitlements_before from the original audit
                if let Ok(snapshot) = serde_json::from_value::<
                    Vec<crate::services::state_access_rule_service::EntitlementSnapshot>,
                >(original_audit.entitlements_before.clone())
                {
                    self.access_rule_service
                        .restore_entitlements_from_snapshot(tenant_id, request.object_id, &snapshot)
                        .await?
                } else {
                    crate::services::state_access_rule_service::EntitlementActionResult::default()
                }
            } else {
                crate::services::state_access_rule_service::EntitlementActionResult::default()
            }
        };

        // 7. Capture entitlements after rollback
        let entitlements_after_snapshot = self
            .access_rule_service
            .capture_access_snapshot(tenant_id, &object_type_str, request.object_id)
            .await?;

        // 8. Update the transition request
        let update = UpdateGovStateTransitionRequest {
            status: Some(TransitionRequestStatus::RolledBack),
            approval_request_id: None,
            executed_at: None,
            grace_period_ends_at: None,
            rollback_available: Some(false),
            error_message: None,
        };

        let updated_request =
            GovStateTransitionRequest::update(&self.pool, tenant_id, request_id, &update)
                .await?
                .ok_or(GovernanceError::StateTransitionRequestNotFound(request_id))?;

        // 9. Create rollback audit record
        let entitlements_before =
            serde_json::to_value(&entitlements_before_snapshot).unwrap_or_else(|_| json!([]));
        let entitlements_after =
            serde_json::to_value(&entitlements_after_snapshot).unwrap_or_else(|_| json!([]));

        // Save the reason for event emission before moving into audit_metadata
        #[cfg(feature = "kafka")]
        let rollback_reason = reason.clone();

        let mut audit_metadata = json!({});
        if let Some(r) = reason {
            audit_metadata["reason"] = json!(r);
        }
        if !access_result.resumed.is_empty() || !access_result.errors.is_empty() {
            audit_metadata["entitlements_resumed"] = json!(access_result.resumed.len());
            audit_metadata["access_rule_errors"] = json!(access_result.errors);
        }

        let audit_input = CreateGovStateTransitionAudit {
            request_id,
            object_id: request.object_id,
            object_type: request.object_type,
            from_state: to_state.name.clone(), // We're rolling back FROM the to_state
            to_state: from_state.name.clone(), // TO the from_state
            transition_name: format!("rollback_{}", transition.name),
            actor_id,
            action_type: AuditActionType::Rollback,
            approval_details: None,
            entitlements_before,
            entitlements_after,
            metadata: if audit_metadata
                .as_object()
                .is_none_or(serde_json::Map::is_empty)
            {
                None
            } else {
                Some(audit_metadata)
            },
        };

        GovStateTransitionAudit::create(&self.pool, tenant_id, &audit_input).await?;

        // Emit StateTransitionRolledBack event
        #[cfg(feature = "kafka")]
        if let Some(ref producer) = self.event_producer {
            let event = StateTransitionRolledBack {
                request_id,
                object_id: request.object_id,
                object_type: format!("{:?}", request.object_type).to_lowercase(),
                restored_to_state: from_state.name.clone(),
                rolled_back_from_state: to_state.name.clone(),
                rolled_back_by: actor_id,
                reason: rollback_reason,
                rolled_back_at: Utc::now(),
            };
            if let Err(e) = producer.publish(event, tenant_id, Some(actor_id)).await {
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Failed to publish StateTransitionRolledBack event"
                );
            }

            // Emit StateAccessRulesReversed if entitlements were restored
            let restored_count = access_result.resumed.len() as u32;
            if restored_count > 0 {
                let access_event = StateAccessRulesReversed {
                    request_id,
                    object_id: request.object_id,
                    restored_to_state: from_state.name.clone(),
                    entitlements_restored: restored_count,
                    reversed_at: Utc::now(),
                };
                if let Err(e) = producer
                    .publish(access_event, tenant_id, Some(actor_id))
                    .await
                {
                    warn!(
                        request_id = %request_id,
                        error = %e,
                        "Failed to publish StateAccessRulesReversed event"
                    );
                }
            }
        }

        Ok(self.build_transition_response(
            &updated_request,
            &transition.name,
            &from_state.name,
            &to_state.name,
        ))
    }

    /// Complete an approved transition.
    ///
    /// Called when an approval workflow completes successfully.
    pub async fn complete_approved_transition(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        approver_id: Uuid,
    ) -> Result<TransitionRequestResponse> {
        // 1. Get the transition request
        let request = GovStateTransitionRequest::find_by_id(&self.pool, tenant_id, request_id)
            .await?
            .ok_or(GovernanceError::StateTransitionRequestNotFound(request_id))?;

        // 2. Validate status
        if request.status != TransitionRequestStatus::PendingApproval {
            return Err(GovernanceError::Validation(format!(
                "Cannot complete transition with status {:?}",
                request.status
            )));
        }

        // 3. Get transition and state details
        let transition =
            GovLifecycleTransition::find_by_id(&self.pool, tenant_id, request.transition_id)
                .await?
                .ok_or(GovernanceError::LifecycleTransitionNotFound(
                    request.transition_id,
                ))?;

        let from_state =
            GovLifecycleState::find_by_id(&self.pool, tenant_id, request.from_state_id)
                .await?
                .ok_or(GovernanceError::LifecycleStateNotFound(
                    request.from_state_id,
                ))?;

        let to_state = GovLifecycleState::find_by_id(&self.pool, tenant_id, request.to_state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(request.to_state_id))?;

        // 4. Mark as approved first
        let approved_update = UpdateGovStateTransitionRequest {
            status: Some(TransitionRequestStatus::Approved),
            approval_request_id: None,
            executed_at: None,
            grace_period_ends_at: None,
            rollback_available: None,
            error_message: None,
        };

        GovStateTransitionRequest::update(&self.pool, tenant_id, request_id, &approved_update)
            .await?;

        // 5. Perform the transition
        let (final_request, _audit) = self
            .perform_transition(
                tenant_id,
                &request,
                &transition,
                &from_state,
                &to_state,
                approver_id,
            )
            .await?;

        Ok(self.build_transition_response(
            &final_request,
            &transition.name,
            &from_state.name,
            &to_state.name,
        ))
    }

    /// Get entitlements that would be affected by a state transition.
    ///
    /// This is used for UI preview before executing a transition.
    pub async fn get_affected_entitlements(
        &self,
        tenant_id: Uuid,
        transition_id: Uuid,
        object_id: Uuid,
    ) -> Result<crate::services::state_access_rule_service::StateAffectedEntitlements> {
        // Get the transition to find the target state
        let transition = GovLifecycleTransition::find_by_id(&self.pool, tenant_id, transition_id)
            .await?
            .ok_or(GovernanceError::LifecycleTransitionNotFound(transition_id))?;

        // Get the config to determine object type
        let config = GovLifecycleConfig::find_by_id(&self.pool, tenant_id, transition.config_id)
            .await?
            .ok_or(GovernanceError::LifecycleConfigNotFound(
                transition.config_id,
            ))?;

        // Get the target state
        let to_state = GovLifecycleState::find_by_id(&self.pool, tenant_id, transition.to_state_id)
            .await?
            .ok_or(GovernanceError::LifecycleStateNotFound(
                transition.to_state_id,
            ))?;

        let object_type_str = format!("{:?}", config.object_type).to_lowercase();

        self.access_rule_service
            .get_state_affected_entitlements(tenant_id, &object_type_str, object_id, &to_state)
            .await
    }

    /// Execute state actions (entry or exit) for a lifecycle state (F-193).
    ///
    /// This method executes all configured actions for a state during a transition.
    async fn execute_state_actions(
        &self,
        tenant_id: Uuid,
        object_id: Uuid,
        transition_audit_id: Uuid,
        state: &GovLifecycleState,
        actor_id: Uuid,
        transition_started_at: chrono::DateTime<Utc>,
        trigger_type: xavyo_db::ActionTriggerType,
    ) -> Result<()> {
        use crate::models::lifecycle::LifecycleAction;
        use crate::services::action_executor::{ActionExecutionContext, ActionExecutor};

        // Get the appropriate actions based on trigger type
        let actions_json = match trigger_type {
            xavyo_db::ActionTriggerType::Entry => state.entry_actions.as_ref(),
            xavyo_db::ActionTriggerType::Exit => state.exit_actions.as_ref(),
        };

        let Some(actions_json) = actions_json else {
            return Ok(());
        };

        // Parse the actions
        let actions: Vec<LifecycleAction> =
            serde_json::from_value(actions_json.clone()).map_err(|e| {
                GovernanceError::ActionExecutionFailed(format!(
                    "Failed to parse {} actions for state {}: {}",
                    match trigger_type {
                        xavyo_db::ActionTriggerType::Entry => "entry",
                        xavyo_db::ActionTriggerType::Exit => "exit",
                    },
                    state.name,
                    e
                ))
            })?;

        if actions.is_empty() {
            return Ok(());
        }

        // Create executor context
        let context = ActionExecutionContext {
            tenant_id,
            object_id,
            transition_audit_id,
            state_id: state.id,
            actor_id,
            transition_started_at,
        };

        // Execute actions
        let executor = ActionExecutor::new(Arc::new(self.pool.clone()));
        let result = executor
            .execute_actions(&context, &actions, trigger_type)
            .await?;

        // Check for blocking failures
        if result.has_blocking_failure {
            let failed_action = result.results.iter().find(|r| !r.success);
            let error_msg = failed_action
                .and_then(|r| r.error_message.clone())
                .unwrap_or_else(|| "Unknown error".to_string());

            return Err(GovernanceError::ActionExecutionFailed(format!(
                "{} action {} failed: {}",
                match trigger_type {
                    xavyo_db::ActionTriggerType::Entry => "Entry",
                    xavyo_db::ActionTriggerType::Exit => "Exit",
                },
                failed_action
                    .map(|r| r.action_type.to_string())
                    .unwrap_or_default(),
                error_msg
            )));
        }

        info!(
            tenant_id = %tenant_id,
            object_id = %object_id,
            state_id = %state.id,
            trigger_type = ?trigger_type,
            success_count = result.success_count,
            failure_count = result.failure_count,
            "Executed state actions"
        );

        Ok(())
    }

    /// Build a transition response from a request.
    fn build_transition_response(
        &self,
        request: &GovStateTransitionRequest,
        transition_name: &str,
        from_state_name: &str,
        to_state_name: &str,
    ) -> TransitionRequestResponse {
        TransitionRequestResponse {
            id: request.id,
            object_id: request.object_id,
            object_type: request.object_type,
            transition_name: transition_name.to_string(),
            from_state: TransitionStateInfo {
                id: request.from_state_id,
                name: from_state_name.to_string(),
            },
            to_state: TransitionStateInfo {
                id: request.to_state_id,
                name: to_state_name.to_string(),
            },
            requested_by: request.requested_by,
            status: request.status,
            scheduled_for: request.scheduled_for,
            approval_request_id: request.approval_request_id,
            executed_at: request.executed_at,
            grace_period_ends_at: request.grace_period_ends_at,
            rollback_available: request.rollback_available,
            error_message: request.error_message.clone(),
            created_at: request.created_at,
            updated_at: request.updated_at,
        }
    }

    /// Export transition audit records to CSV or JSON format.
    pub async fn export_transition_audit(
        &self,
        tenant_id: Uuid,
        params: &ListTransitionAuditQuery,
        format: OutputFormat,
    ) -> Result<AuditExportResult> {
        let filter = TransitionAuditFilter {
            object_id: params.object_id,
            object_type: params.object_type,
            actor_id: params.actor_id,
            action_type: params.action_type,
            from_date: params.from_date,
            to_date: params.to_date,
        };

        // Get all records (up to 10000 for export)
        let records =
            GovStateTransitionAudit::list_by_tenant(&self.pool, tenant_id, &filter, 10000, 0)
                .await?;

        match format {
            OutputFormat::Json => {
                let json_records: Vec<TransitionAuditResponse> = records
                    .into_iter()
                    .map(TransitionAuditResponse::from)
                    .collect();

                let output = json!({
                    "exported_at": Utc::now().to_rfc3339(),
                    "total_count": json_records.len(),
                    "records": json_records
                });

                let content = serde_json::to_string_pretty(&output)
                    .map_err(GovernanceError::JsonSerialization)?;

                Ok(AuditExportResult {
                    content,
                    content_type: "application/json".to_string(),
                    file_extension: "json".to_string(),
                })
            }
            OutputFormat::Csv => {
                let mut csv_content = String::new();

                // CSV header
                csv_content.push_str(
                    "id,request_id,object_id,object_type,from_state,to_state,transition_name,action_type,actor_id,created_at\n",
                );

                // CSV rows
                for record in records {
                    csv_content.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{}\n",
                        record.id,
                        record.request_id,
                        record.object_id,
                        format!("{:?}", record.object_type).to_lowercase(),
                        escape_csv(&record.from_state),
                        escape_csv(&record.to_state),
                        escape_csv(&record.transition_name),
                        format!("{:?}", record.action_type).to_lowercase(),
                        record.actor_id,
                        record.created_at.to_rfc3339(),
                    ));
                }

                Ok(AuditExportResult {
                    content: csv_content,
                    content_type: "text/csv".to_string(),
                    file_extension: "csv".to_string(),
                })
            }
        }
    }
}

/// Result of exporting audit records.
#[derive(Debug, Clone)]
pub struct AuditExportResult {
    /// The exported content as a string.
    pub content: String,
    /// MIME type of the content.
    pub content_type: String,
    /// Suggested file extension.
    pub file_extension: String,
}

/// Statistics from expiring grace periods.
#[derive(Debug, Clone, Default)]
pub struct ExpirationStats {
    /// Total number of grace periods expired.
    pub expired: usize,
    /// Number of tenants processed.
    pub tenants_processed: usize,
}

impl StateTransitionService {
    /// Expire grace periods for a specific tenant.
    ///
    /// Marks all transition requests with expired grace periods as no longer rollbackable.
    /// Returns the number of records updated.
    #[cfg(not(feature = "kafka"))]
    pub async fn expire_grace_periods(&self, tenant_id: Uuid, batch_size: i32) -> Result<usize> {
        let expired = GovStateTransitionRequest::expire_grace_periods(
            &self.pool,
            tenant_id,
            i64::from(batch_size),
        )
        .await?;

        if expired > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                expired = expired,
                "Expired grace periods for tenant"
            );
        }

        Ok(expired as usize)
    }

    /// Expire grace periods for a specific tenant (with Kafka event emission).
    #[cfg(feature = "kafka")]
    pub async fn expire_grace_periods(&self, tenant_id: Uuid, batch_size: i32) -> Result<usize> {
        use xavyo_events::events::GracePeriodExpired;

        let expired_details = GovStateTransitionRequest::expire_grace_periods_with_details(
            &self.pool,
            tenant_id,
            batch_size as i64,
        )
        .await?;

        let expired_count = expired_details.len();

        if expired_count > 0 {
            tracing::info!(
                tenant_id = %tenant_id,
                expired = expired_count,
                "Expired grace periods for tenant"
            );

            // Emit GracePeriodExpired events for each expired request
            if let Some(ref producer) = self.event_producer {
                for (request_id, object_id, _object_type, to_state_id) in &expired_details {
                    // Get the state name for the event
                    let state_name = if let Ok(Some(state)) =
                        GovLifecycleState::find_by_id(&self.pool, tenant_id, *to_state_id).await
                    {
                        state.name
                    } else {
                        "unknown".to_string()
                    };

                    let event = GracePeriodExpired {
                        request_id: *request_id,
                        object_id: *object_id,
                        state: state_name,
                        expired_at: Utc::now(),
                    };

                    if let Err(e) = producer.publish(event, tenant_id, None).await {
                        warn!(
                            request_id = %request_id,
                            error = %e,
                            "Failed to publish GracePeriodExpired event"
                        );
                    }
                }
            }
        }

        Ok(expired_count)
    }

    /// Expire grace periods across all tenants.
    ///
    /// This is the primary method called by the background job.
    pub async fn expire_all_grace_periods(&self, batch_size: i32) -> Result<ExpirationStats> {
        let tenant_ids =
            GovStateTransitionRequest::get_tenants_with_expired_grace_periods(&self.pool).await?;

        let mut stats = ExpirationStats {
            tenants_processed: tenant_ids.len(),
            ..Default::default()
        };

        for tenant_id in tenant_ids {
            match self.expire_grace_periods(tenant_id, batch_size).await {
                Ok(count) => {
                    stats.expired += count;
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to expire grace periods for tenant"
                    );
                }
            }
        }

        Ok(stats)
    }
}

/// Escape a string value for CSV output.
fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
