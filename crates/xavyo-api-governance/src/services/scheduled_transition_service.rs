//! Scheduled transition service for Object Lifecycle States (F052).
//!
//! This service manages scheduled state transitions that execute at a future time.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateGovScheduledTransition, GovScheduleStatus, GovScheduledTransition,
    GovStateTransitionRequest, LifecycleObjectType, ScheduledTransitionFilter,
    TransitionRequestStatus, UpdateGovStateTransitionRequest, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ListScheduledTransitionsQuery, ScheduledTransitionListResponse, ScheduledTransitionResponse,
};

/// Service for scheduled transition operations.
pub struct ScheduledTransitionService {
    pool: PgPool,
}

impl ScheduledTransitionService {
    /// Create a new scheduled transition service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List scheduled transitions.
    pub async fn list_scheduled_transitions(
        &self,
        tenant_id: Uuid,
        params: &ListScheduledTransitionsQuery,
    ) -> Result<ScheduledTransitionListResponse> {
        let filter = ScheduledTransitionFilter {
            status: params.status,
            scheduled_before: params.scheduled_before,
            scheduled_after: params.scheduled_after,
        };

        let limit = params.limit.unwrap_or(50).min(100);
        let offset = params.offset.unwrap_or(0);

        let schedules =
            GovScheduledTransition::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovScheduledTransition::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let mut items = Vec::with_capacity(schedules.len());
        for schedule in schedules {
            // Get the associated transition request for more details
            if let Some(request) = GovStateTransitionRequest::find_by_id_with_states(
                &self.pool,
                tenant_id,
                schedule.transition_request_id,
            )
            .await?
            {
                items.push(ScheduledTransitionResponse {
                    id: schedule.id,
                    transition_request_id: schedule.transition_request_id,
                    object_id: request.object_id,
                    object_type: request.object_type,
                    transition_name: request.transition_name,
                    from_state: request.from_state_name,
                    to_state: request.to_state_name,
                    scheduled_for: schedule.scheduled_for,
                    status: schedule.status,
                    executed_at: schedule.executed_at,
                    cancelled_at: schedule.cancelled_at,
                    cancelled_by: schedule.cancelled_by,
                    error_message: schedule.error_message,
                    created_at: schedule.created_at,
                });
            }
        }

        Ok(ScheduledTransitionListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a scheduled transition by ID.
    pub async fn get_scheduled_transition(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
    ) -> Result<ScheduledTransitionResponse> {
        let schedule = GovScheduledTransition::find_by_id(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ScheduledTransitionNotFound(schedule_id))?;

        let request = GovStateTransitionRequest::find_by_id_with_states(
            &self.pool,
            tenant_id,
            schedule.transition_request_id,
        )
        .await?
        .ok_or(GovernanceError::StateTransitionRequestNotFound(
            schedule.transition_request_id,
        ))?;

        Ok(ScheduledTransitionResponse {
            id: schedule.id,
            transition_request_id: schedule.transition_request_id,
            object_id: request.object_id,
            object_type: request.object_type,
            transition_name: request.transition_name,
            from_state: request.from_state_name,
            to_state: request.to_state_name,
            scheduled_for: schedule.scheduled_for,
            status: schedule.status,
            executed_at: schedule.executed_at,
            cancelled_at: schedule.cancelled_at,
            cancelled_by: schedule.cancelled_by,
            error_message: schedule.error_message,
            created_at: schedule.created_at,
        })
    }

    /// Cancel a scheduled transition.
    pub async fn cancel_scheduled_transition(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        cancelled_by: Uuid,
    ) -> Result<ScheduledTransitionResponse> {
        // Check schedule exists and is pending
        let schedule = GovScheduledTransition::find_by_id(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ScheduledTransitionNotFound(schedule_id))?;

        if schedule.status != GovScheduleStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Cannot cancel schedule with status {:?}",
                schedule.status
            )));
        }

        // Cancel the schedule
        let cancelled =
            GovScheduledTransition::cancel(&self.pool, tenant_id, schedule_id, cancelled_by)
                .await?
                .ok_or(GovernanceError::ScheduledTransitionNotFound(schedule_id))?;

        // Also cancel the associated transition request
        let cancel_update = UpdateGovStateTransitionRequest {
            status: Some(TransitionRequestStatus::Cancelled),
            approval_request_id: None,
            executed_at: None,
            grace_period_ends_at: None,
            rollback_available: None,
            error_message: Some("Scheduled transition cancelled".to_string()),
        };

        GovStateTransitionRequest::update(
            &self.pool,
            tenant_id,
            schedule.transition_request_id,
            &cancel_update,
        )
        .await?;

        // Get full response with request details
        let request = GovStateTransitionRequest::find_by_id_with_states(
            &self.pool,
            tenant_id,
            cancelled.transition_request_id,
        )
        .await?
        .ok_or(GovernanceError::StateTransitionRequestNotFound(
            cancelled.transition_request_id,
        ))?;

        Ok(ScheduledTransitionResponse {
            id: cancelled.id,
            transition_request_id: cancelled.transition_request_id,
            object_id: request.object_id,
            object_type: request.object_type,
            transition_name: request.transition_name,
            from_state: request.from_state_name,
            to_state: request.to_state_name,
            scheduled_for: cancelled.scheduled_for,
            status: cancelled.status,
            executed_at: cancelled.executed_at,
            cancelled_at: cancelled.cancelled_at,
            cancelled_by: cancelled.cancelled_by,
            error_message: cancelled.error_message,
            created_at: cancelled.created_at,
        })
    }

    /// Reschedule a transition to a new time.
    pub async fn reschedule_transition(
        &self,
        tenant_id: Uuid,
        schedule_id: Uuid,
        new_scheduled_for: chrono::DateTime<chrono::Utc>,
    ) -> Result<ScheduledTransitionResponse> {
        // Validate the new time is in the future
        if new_scheduled_for <= Utc::now() {
            return Err(GovernanceError::ScheduledTimeInPast);
        }

        // Check schedule exists and is pending
        let schedule = GovScheduledTransition::find_by_id(&self.pool, tenant_id, schedule_id)
            .await?
            .ok_or(GovernanceError::ScheduledTransitionNotFound(schedule_id))?;

        if schedule.status != GovScheduleStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Cannot reschedule transition with status {:?}",
                schedule.status
            )));
        }

        // Update the schedule
        let rescheduled = GovScheduledTransition::reschedule(
            &self.pool,
            tenant_id,
            schedule_id,
            new_scheduled_for,
        )
        .await?
        .ok_or(GovernanceError::ScheduledTransitionNotFound(schedule_id))?;

        // Get full response with request details
        let request = GovStateTransitionRequest::find_by_id_with_states(
            &self.pool,
            tenant_id,
            rescheduled.transition_request_id,
        )
        .await?
        .ok_or(GovernanceError::StateTransitionRequestNotFound(
            rescheduled.transition_request_id,
        ))?;

        Ok(ScheduledTransitionResponse {
            id: rescheduled.id,
            transition_request_id: rescheduled.transition_request_id,
            object_id: request.object_id,
            object_type: request.object_type,
            transition_name: request.transition_name,
            from_state: request.from_state_name,
            to_state: request.to_state_name,
            scheduled_for: rescheduled.scheduled_for,
            status: rescheduled.status,
            executed_at: rescheduled.executed_at,
            cancelled_at: rescheduled.cancelled_at,
            cancelled_by: rescheduled.cancelled_by,
            error_message: rescheduled.error_message,
            created_at: rescheduled.created_at,
        })
    }

    /// Execute a single due schedule: apply the lifecycle change, then mark done.
    ///
    /// Returns `Ok(true)` when the transition was applied. Recorded failures
    /// return `Ok(false)` so callers can count them without aborting the batch.
    async fn execute_one(&self, schedule: &GovScheduledTransition) -> Result<bool> {
        let request = match GovStateTransitionRequest::find_by_id(
            &self.pool,
            schedule.tenant_id,
            schedule.transition_request_id,
        )
        .await
        {
            Ok(Some(req)) => req,
            Ok(None) => {
                let error = format!(
                    "Transition request {} not found",
                    schedule.transition_request_id
                );
                return self.fail_schedule(schedule, error).await;
            }
            Err(e) => {
                let error = format!("Failed to fetch transition request: {e}");
                return self.fail_schedule(schedule, error).await;
            }
        };

        if request.status != TransitionRequestStatus::Pending {
            let error = format!(
                "Transition request is no longer pending (status: {:?})",
                request.status
            );
            return self.fail_schedule(schedule, error).await;
        }

        match request.object_type {
            LifecycleObjectType::User => {
                match User::update_lifecycle_state(
                    &self.pool,
                    schedule.tenant_id,
                    request.object_id,
                    Some(request.to_state_id),
                )
                .await
                {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return self
                            .fail_schedule(schedule, "User not found".to_string())
                            .await;
                    }
                    Err(e) => {
                        let error = format!("Failed to update user lifecycle state: {e}");
                        return self.fail_schedule(schedule, error).await;
                    }
                }
            }
            other => {
                let error = format!("Unsupported object type for scheduled transition: {other:?}");
                return self.fail_schedule(schedule, error).await;
            }
        }

        let update = UpdateGovStateTransitionRequest {
            status: Some(TransitionRequestStatus::Executed),
            approval_request_id: None,
            executed_at: Some(Utc::now()),
            grace_period_ends_at: None,
            rollback_available: None,
            error_message: None,
        };
        match GovStateTransitionRequest::update(&self.pool, schedule.tenant_id, request.id, &update)
            .await
        {
            Ok(Some(_)) => {}
            Ok(None) => {
                return self
                    .fail_schedule(
                        schedule,
                        "Transition request could not be updated".to_string(),
                    )
                    .await;
            }
            Err(e) => {
                let error = format!("Failed to update transition request: {e}");
                return self.fail_schedule(schedule, error).await;
            }
        }

        GovScheduledTransition::mark_executed(&self.pool, schedule.tenant_id, schedule.id).await?;
        Ok(true)
    }

    async fn fail_schedule(
        &self,
        schedule: &GovScheduledTransition,
        error: String,
    ) -> Result<bool> {
        GovScheduledTransition::mark_failed(&self.pool, schedule.tenant_id, schedule.id, &error)
            .await?;
        Ok(false)
    }

    /// Process due scheduled transitions.
    ///
    /// This is called by a background job to execute scheduled transitions
    /// that are due.
    pub async fn process_due_transitions(&self, batch_size: i64) -> Result<ProcessDueResult> {
        let due_schedules =
            GovScheduledTransition::find_due_for_execution(&self.pool, batch_size).await?;

        let mut processed = 0;
        let mut succeeded = 0;
        let mut failed = 0;
        let mut errors = Vec::new();

        for schedule in due_schedules {
            processed += 1;
            if self.execute_one(&schedule).await? {
                succeeded += 1;
            } else {
                failed += 1;
                errors.push((schedule.id, "schedule recorded as failed".to_string()));
            }
        }

        Ok(ProcessDueResult {
            processed,
            succeeded,
            failed,
            errors,
        })
    }

    /// Create a scheduled transition for an existing transition request.
    ///
    /// This is called by `StateTransitionService` when a transition is requested
    /// with a `scheduled_for` time.
    pub async fn create_schedule(
        &self,
        tenant_id: Uuid,
        transition_request_id: Uuid,
        scheduled_for: chrono::DateTime<chrono::Utc>,
    ) -> Result<GovScheduledTransition> {
        // Validate the scheduled time is in the future
        if scheduled_for <= Utc::now() {
            return Err(GovernanceError::ScheduledTimeInPast);
        }

        // Create the schedule
        let input = CreateGovScheduledTransition {
            transition_request_id,
            scheduled_for,
        };

        let schedule = GovScheduledTransition::create(&self.pool, tenant_id, &input).await?;

        Ok(schedule)
    }
}

/// Result of processing due scheduled transitions.
#[derive(Debug, Clone)]
pub struct ProcessDueResult {
    /// Total schedules processed.
    pub processed: i64,
    /// Successfully executed transitions.
    pub succeeded: i64,
    /// Failed transitions.
    pub failed: i64,
    /// Error details for failed transitions.
    pub errors: Vec<(Uuid, String)>,
}

/// Statistics from processing scheduled transitions across all tenants.
#[derive(Debug, Clone, Default)]
pub struct ProcessingStats {
    /// Total number of transitions processed.
    pub processed: usize,
    /// Number of successfully executed transitions.
    pub successful: usize,
    /// Number of failed transitions.
    pub failed: usize,
    /// Number of tenants processed.
    pub tenants_processed: usize,
}

impl ScheduledTransitionService {
    /// Process due transitions for a specific tenant.
    ///
    /// Returns the number of transitions processed.
    pub async fn process_due_transitions_for_tenant(
        &self,
        tenant_id: Uuid,
        batch_size: i32,
    ) -> Result<usize> {
        let due_schedules = GovScheduledTransition::find_due_for_tenant(
            &self.pool,
            tenant_id,
            i64::from(batch_size),
        )
        .await?;

        let mut processed = 0;

        for schedule in due_schedules {
            if self.execute_one(&schedule).await? {
                processed += 1;
            }
        }

        Ok(processed)
    }

    /// Process all due transitions across all tenants.
    ///
    /// This is the primary method called by the background job.
    pub async fn process_all_due_transitions(&self, batch_size: i32) -> Result<ProcessingStats> {
        // Get all tenants with due schedules
        let tenant_ids = GovScheduledTransition::get_tenants_with_due_schedules(&self.pool).await?;

        let mut stats = ProcessingStats {
            tenants_processed: tenant_ids.len(),
            ..Default::default()
        };

        for tenant_id in tenant_ids {
            match self
                .process_due_transitions_for_tenant(tenant_id, batch_size)
                .await
            {
                Ok(count) => {
                    stats.processed += count;
                    stats.successful += count;
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        error = %e,
                        "Failed to process scheduled transitions for tenant"
                    );
                    stats.failed += 1;
                }
            }
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn execute_one_applies_lifecycle_and_scopes_status() {
        let src = include_str!("scheduled_transition_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        let execute = production
            .split("async fn execute_one")
            .nth(1)
            .expect("execute_one")
            .split("async fn fail_schedule")
            .next()
            .expect("execute_one body");
        assert!(
            execute.contains("User::update_lifecycle_state"),
            "execution must apply the user lifecycle change"
        );
        assert!(
            execute.contains("mark_executed(&self.pool, schedule.tenant_id, schedule.id)"),
            "mark_executed must pass tenant_id"
        );
        assert!(
            !execute.contains("let _ = GovStateTransitionRequest::update"),
            "must not swallow transition-request update errors"
        );
        assert!(
            execute.contains("Unsupported object type"),
            "unsupported object types must fail, not mark executed"
        );

        let for_tenant = production
            .split("fn process_due_transitions_for_tenant")
            .nth(1)
            .expect("process_due_transitions_for_tenant");
        assert!(
            for_tenant.contains("self.execute_one(&schedule)"),
            "tenant job path must actually execute the transition"
        );
        assert!(
            !for_tenant.contains("Mark as executed"),
            "must not mark executed without applying the lifecycle change"
        );
    }
}
