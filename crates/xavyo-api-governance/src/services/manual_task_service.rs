//! Manual Task Service for semi-manual resources (F064).
//!
//! Manages manual provisioning tasks for IT operators, including
//! claiming, confirming, rejecting tasks, and tracking SLA compliance.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateManualTaskAuditEvent, GovApplication, GovEntitlement, GovManualProvisioningTask,
    GovManualTaskAuditEvent, ManualTaskEventType, ManualTaskFilter, ManualTaskStatus, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ListManualTasksQuery, ManualTaskDashboardResponse, ManualTaskListResponse, ManualTaskResponse,
};

/// Service for managing manual provisioning tasks.
pub struct ManualTaskService {
    pool: PgPool,
}

impl ManualTaskService {
    /// Create a new manual task service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List manual tasks with filtering.
    pub async fn list_tasks(
        &self,
        tenant_id: Uuid,
        query: &ListManualTasksQuery,
    ) -> Result<ManualTaskListResponse> {
        let filter = ManualTaskFilter {
            status: query.status.clone(),
            application_id: query.application_id,
            user_id: query.user_id,
            assignment_id: None,
            sla_breached: query.sla_breached,
            assignee_id: query.assignee_id,
            operation: query.operation,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0).max(0);

        let tasks = GovManualProvisioningTask::list_by_tenant(
            &self.pool, tenant_id, &filter, limit, offset,
        )
        .await?;

        let total =
            GovManualProvisioningTask::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(ManualTaskListResponse {
            items: {
                let mut items = Vec::with_capacity(tasks.len());
                for task in tasks {
                    items.push(self.task_response(tenant_id, task).await?);
                }
                items
            },
            total,
            limit,
            offset,
        })
    }

    /// Get a task by ID.
    pub async fn get_task(&self, tenant_id: Uuid, id: Uuid) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        self.task_response(tenant_id, task).await
    }

    /// Claim a task (assign to a user).
    pub async fn claim_task(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        assignee_id: Uuid,
    ) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Check if already claimed by someone else
        if let Some(existing_assignee) = task.assignee_id {
            if existing_assignee != assignee_id {
                return Err(GovernanceError::Validation(
                    "Task is already claimed by another user".to_string(),
                ));
            }
        }

        // Update task with assignee
        let updated = sqlx::query_as::<_, GovManualProvisioningTask>(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET assignee_id = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(assignee_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Create audit event for task claimed (using StatusChanged with details)
        let details = serde_json::json!({
            "action": "claimed",
            "assignee_id": assignee_id
        });
        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id: id,
                event_type: ManualTaskEventType::StatusChanged,
                actor_id: Some(assignee_id),
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %id,
            assignee_id = %assignee_id,
            "Manual task claimed"
        );

        self.task_response(tenant_id, updated).await
    }

    /// Start working on a task.
    pub async fn start_task(&self, tenant_id: Uuid, id: Uuid) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Validate task can be started
        if task.status.is_terminal() {
            return Err(GovernanceError::Validation(
                "Cannot start a completed task".to_string(),
            ));
        }

        let updated = GovManualProvisioningTask::update_status(
            &self.pool,
            tenant_id,
            id,
            ManualTaskStatus::InProgress,
        )
        .await?
        .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Create audit event for status change
        let details = serde_json::json!({
            "action": "started",
            "new_status": "in_progress"
        });
        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id: id,
                event_type: ManualTaskEventType::StatusChanged,
                actor_id: task.assignee_id,
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %id,
            "Manual task started"
        );

        self.task_response(tenant_id, updated).await
    }

    /// Confirm a task as completed.
    pub async fn confirm_task(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        confirmed_by: Uuid,
        notes: Option<&str>,
    ) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Validate task can be confirmed
        if task.status.is_terminal() {
            return Err(GovernanceError::Validation(
                "Cannot confirm a completed task".to_string(),
            ));
        }

        let updated = GovManualProvisioningTask::confirm(&self.pool, tenant_id, id, notes)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Use the helper method for task confirmed audit event
        GovManualTaskAuditEvent::log_task_confirmed(&self.pool, tenant_id, id, confirmed_by, notes)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %id,
            confirmed_by = %confirmed_by,
            "Manual task confirmed"
        );

        self.task_response(tenant_id, updated).await
    }

    /// Reject a task.
    pub async fn reject_task(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        rejected_by: Uuid,
        reason: &str,
    ) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Validate task can be rejected
        if task.status.is_terminal() {
            return Err(GovernanceError::Validation(
                "Cannot reject a completed task".to_string(),
            ));
        }

        let updated = GovManualProvisioningTask::reject(&self.pool, tenant_id, id, reason)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Use the helper method for task rejected audit event
        GovManualTaskAuditEvent::log_task_rejected(&self.pool, tenant_id, id, rejected_by, reason)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %id,
            rejected_by = %rejected_by,
            reason = %reason,
            "Manual task rejected"
        );

        self.task_response(tenant_id, updated).await
    }

    /// Cancel a task.
    pub async fn cancel_task(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        cancelled_by: Uuid,
        reason: Option<&str>,
    ) -> Result<ManualTaskResponse> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Validate task can be cancelled
        if task.status.is_terminal() {
            return Err(GovernanceError::Validation(
                "Cannot cancel a completed task".to_string(),
            ));
        }

        let updated = GovManualProvisioningTask::cancel(&self.pool, tenant_id, id, reason)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(id))?;

        // Create audit event for task cancelled
        let details = reason.map(|r| serde_json::json!({ "reason": r }));
        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id: id,
                event_type: ManualTaskEventType::TaskCancelled,
                actor_id: Some(cancelled_by),
                details,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %id,
            cancelled_by = %cancelled_by,
            "Manual task cancelled"
        );

        self.task_response(tenant_id, updated).await
    }

    async fn task_response(
        &self,
        tenant_id: Uuid,
        task: GovManualProvisioningTask,
    ) -> Result<ManualTaskResponse> {
        let application_name =
            GovApplication::find_by_id(&self.pool, tenant_id, task.application_id)
                .await?
                .map(|app| app.name);
        let entitlement_name =
            GovEntitlement::find_by_id(&self.pool, tenant_id, task.entitlement_id)
                .await?
                .map(|entitlement| entitlement.name);
        let user_name = User::find_by_id_in_tenant(&self.pool, tenant_id, task.user_id)
            .await
            .map_err(GovernanceError::Database)?
            .map(|user| match user.display_name {
                Some(name) if !name.is_empty() => name,
                _ => user.email,
            });
        let assignee_name = if let Some(assignee_id) = task.assignee_id {
            User::find_by_id_in_tenant(&self.pool, tenant_id, assignee_id)
                .await
                .map_err(GovernanceError::Database)?
                .map(|user| match user.display_name {
                    Some(name) if !name.is_empty() => name,
                    _ => user.email,
                })
        } else {
            None
        };
        let mut response = ManualTaskResponse::from(task);
        response.application_name = application_name;
        response.entitlement_name = entitlement_name;
        response.user_name = user_name;
        response.assignee_name = assignee_name;
        Ok(response)
    }

    /// Get dashboard metrics for manual tasks.
    pub async fn get_dashboard_metrics(
        &self,
        tenant_id: Uuid,
    ) -> Result<ManualTaskDashboardResponse> {
        let metrics = GovManualProvisioningTask::get_dashboard_metrics(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(ManualTaskDashboardResponse {
            pending_count: metrics.pending_count,
            in_progress_count: metrics.in_progress_count,
            sla_at_risk_count: metrics.sla_at_risk_count,
            sla_breached_count: metrics.sla_breached_count,
            completed_today: metrics.completed_today,
            average_completion_time_seconds: metrics.average_completion_time_seconds,
        })
    }

    /// Get tasks pending retry (for background job).
    pub async fn get_tasks_pending_retry(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: i64,
    ) -> Result<Vec<GovManualProvisioningTask>> {
        let tasks = GovManualProvisioningTask::find_pending_retry(&self.pool, now, limit)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(tasks)
    }

    /// Retry ticket creation for a task (for background job).
    ///
    /// Returns result indicating success, rescheduling, or permanent failure.
    pub async fn retry_ticket_creation(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<RetryResult> {
        use crate::jobs::ticket_retry_job::{TicketRetryJob, MAX_RETRY_ATTEMPTS};

        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        // Check if we've exhausted retries
        if task.retry_count >= MAX_RETRY_ATTEMPTS {
            // Mark as permanently failed
            GovManualProvisioningTask::record_ticket_failure(
                &self.pool,
                tenant_id,
                task_id,
                "Maximum retry attempts exceeded",
                None, // No more retries
            )
            .await?;

            // Log audit event
            GovManualTaskAuditEvent::create(
                &self.pool,
                tenant_id,
                CreateManualTaskAuditEvent {
                    task_id,
                    event_type: ManualTaskEventType::TicketCreationFailed,
                    actor_id: None,
                    details: Some(serde_json::json!({
                        "reason": "maximum_retries_exceeded",
                        "retry_count": task.retry_count,
                        "last_error": task.error_message,
                    })),
                },
            )
            .await
            .map_err(GovernanceError::Database)?;

            tracing::warn!(
                tenant_id = %tenant_id,
                task_id = %task_id,
                retry_count = task.retry_count,
                "Task permanently failed - exhausted retries"
            );

            return Ok(RetryResult {
                ticket_created: false,
                exhausted_retries: true,
                retry_count: task.retry_count,
                next_retry_at: None,
            });
        }

        // Attempt to create the ticket
        let ticketing_service =
            crate::services::ticketing::TicketingService::new(self.pool.clone());

        match ticketing_service
            .create_ticket_for_task(tenant_id, task_id)
            .await
        {
            Ok(_ticket) => {
                tracing::info!(
                    tenant_id = %tenant_id,
                    task_id = %task_id,
                    "Ticket creation retry succeeded"
                );

                Ok(RetryResult {
                    ticket_created: true,
                    exhausted_retries: false,
                    retry_count: task.retry_count,
                    next_retry_at: None,
                })
            }
            Err(e) => {
                let next_retry = TicketRetryJob::calculate_next_retry(task.retry_count + 1);
                let error_message = e.to_string();

                // Record the failure and schedule next retry
                GovManualProvisioningTask::record_ticket_failure(
                    &self.pool,
                    tenant_id,
                    task_id,
                    &error_message,
                    next_retry,
                )
                .await?;

                tracing::warn!(
                    tenant_id = %tenant_id,
                    task_id = %task_id,
                    retry_count = task.retry_count + 1,
                    next_retry = ?next_retry,
                    error = %error_message,
                    "Ticket creation retry failed, rescheduled"
                );

                Ok(RetryResult {
                    ticket_created: false,
                    exhausted_retries: next_retry.is_none(),
                    retry_count: task.retry_count + 1,
                    next_retry_at: next_retry,
                })
            }
        }
    }
}

/// Result of a ticket creation retry.
#[derive(Debug)]
pub struct RetryResult {
    /// Whether the ticket was successfully created.
    pub ticket_created: bool,
    /// Whether all retries have been exhausted.
    pub exhausted_retries: bool,
    /// Current retry count.
    pub retry_count: i32,
    /// Next scheduled retry time (if applicable).
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_service_construction() {
        // This test verifies the types compile correctly
        // Actual service tests would require a database connection
    }

    #[test]
    fn manual_tasks_look_up_display_names() {
        let src = include_str!("manual_task_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("task_response(")
                && production.contains("GovApplication::find_by_id")
                && production.contains("GovEntitlement::find_by_id")
                && production.contains("find_by_id_in_tenant"),
            "manual task responses must look up application, entitlement, and user names"
        );
        let list = production
            .split("pub async fn list_tasks")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("list_tasks");
        assert!(
            list.contains("task_response(") && !list.contains("ManualTaskResponse::from(task)"),
            "GET /governance/manual-tasks must enrich names"
        );
        assert!(
            list.contains("operation: query.operation") && list.contains("status: query.status"),
            "GET /governance/manual-tasks must pass advertised operation and status filters"
        );
    }
}
