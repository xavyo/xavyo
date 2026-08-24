//! Semi-manual Provisioning Service for governance API (F064).
//!
//! Integrates access request approval workflow with semi-manual task creation.
//! When an access request is approved for a semi-manual resource with
//! `requires_approval_before_ticket = true`, this service creates the manual
//! provisioning task and triggers ticket creation.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateManualTask, CreateManualTaskAuditEvent, GovApplication, GovEntitlement,
    GovEntitlementAssignment, GovManualProvisioningTask, GovManualTaskAuditEvent, GovSlaPolicy,
    ManualTaskEventType, ManualTaskOperation,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::jobs::ticket_retry_job::TicketRetryJob;
use crate::services::ticketing::TicketingService;

/// Service for orchestrating semi-manual provisioning after approval.
pub struct SemiManualProvisioningService {
    pool: PgPool,
    ticketing_service: TicketingService,
}

impl SemiManualProvisioningService {
    /// Create a new semi-manual provisioning service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let ticketing_service = TicketingService::new(pool.clone());
        Self {
            pool,
            ticketing_service,
        }
    }

    /// Get the database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Process a newly provisioned assignment for semi-manual handling.
    ///
    /// This is called after an access request is approved and the entitlement
    /// assignment is created. If the application is semi-manual, this creates
    /// the manual provisioning task and optionally triggers ticket creation.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant ID
    /// * `assignment` - The newly created entitlement assignment
    ///
    /// # Returns
    /// * `Ok(Some(task))` if a manual task was created
    /// * `Ok(None)` if the application is not semi-manual
    /// * `Err` on failure
    pub async fn process_approved_assignment(
        &self,
        tenant_id: Uuid,
        assignment: &GovEntitlementAssignment,
    ) -> Result<Option<GovManualProvisioningTask>> {
        // Get the entitlement to find the application
        let entitlement =
            GovEntitlement::find_by_id(&self.pool, tenant_id, assignment.entitlement_id)
                .await?
                .ok_or(GovernanceError::EntitlementNotFound(
                    assignment.entitlement_id,
                ))?;

        // Get the application
        let application =
            GovApplication::find_by_id(&self.pool, tenant_id, entitlement.application_id)
                .await?
                .ok_or(GovernanceError::ApplicationNotFound(
                    entitlement.application_id,
                ))?;

        // Check if application is semi-manual
        if !application.is_semi_manual {
            tracing::debug!(
                tenant_id = %tenant_id,
                assignment_id = %assignment.id,
                application_id = %application.id,
                "Application is not semi-manual, skipping task creation"
            );
            return Ok(None);
        }

        // For semi-manual applications, create the manual provisioning task
        let task = self
            .create_manual_task_for_assignment(tenant_id, assignment, &entitlement, &application)
            .await?;

        tracing::info!(
            tenant_id = %tenant_id,
            assignment_id = %assignment.id,
            task_id = %task.id,
            application_id = %application.id,
            "Created manual provisioning task after approval"
        );

        // If the application has a ticketing configuration, create the ticket
        if application.ticketing_config_id.is_some() {
            match self
                .ticketing_service
                .create_ticket_for_task(tenant_id, task.id)
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        task_id = %task.id,
                        "Ticket created for manual task"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        task_id = %task.id,
                        error = %e,
                        "Failed to create ticket; scheduling retry"
                    );
                    ticket_retry_scheduled(
                        &self.pool,
                        tenant_id,
                        task.id,
                        &e.to_string(),
                        serde_json::json!({
                            "application_id": application.id,
                            "entitlement_id": entitlement.id,
                        }),
                    )
                    .await?;
                }
            }
        }

        // Reload the task to get any updates from ticket creation
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task.id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task.id))?;

        Ok(Some(task))
    }

    /// Create a manual provisioning task for an assignment.
    async fn create_manual_task_for_assignment(
        &self,
        tenant_id: Uuid,
        assignment: &GovEntitlementAssignment,
        entitlement: &GovEntitlement,
        application: &GovApplication,
    ) -> Result<GovManualProvisioningTask> {
        // Calculate SLA deadline if a policy is configured
        let sla_deadline = if let Some(policy_id) = application.sla_policy_id {
            if let Some(policy) = GovSlaPolicy::find_by_id(&self.pool, tenant_id, policy_id).await?
            {
                Some(Utc::now() + Duration::seconds(i64::from(policy.target_duration_seconds)))
            } else {
                None
            }
        } else {
            None
        };

        let input = CreateManualTask {
            assignment_id: assignment.id,
            application_id: application.id,
            user_id: assignment.target_id,
            entitlement_id: entitlement.id,
            operation_type: ManualTaskOperation::Grant,
            sla_deadline,
        };

        GovManualProvisioningTask::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Check if an application requires approval before ticket creation.
    ///
    /// Returns true if the application is semi-manual and has
    /// `requires_approval_before_ticket` set to true.
    pub async fn requires_approval_before_ticket(
        &self,
        tenant_id: Uuid,
        application_id: Uuid,
    ) -> Result<bool> {
        let application = GovApplication::find_by_id(&self.pool, tenant_id, application_id)
            .await?
            .ok_or(GovernanceError::ApplicationNotFound(application_id))?;

        Ok(application.is_semi_manual && application.requires_approval_before_ticket)
    }

    /// Check if an entitlement's application requires approval before ticket.
    pub async fn entitlement_requires_approval_before_ticket(
        &self,
        tenant_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<bool> {
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
            .await?
            .ok_or(GovernanceError::EntitlementNotFound(entitlement_id))?;

        self.requires_approval_before_ticket(tenant_id, entitlement.application_id)
            .await
    }

    /// Process a revocation for a semi-manual resource.
    ///
    /// Called when an entitlement assignment is being revoked/removed.
    pub async fn process_revocation(
        &self,
        tenant_id: Uuid,
        assignment: &GovEntitlementAssignment,
    ) -> Result<Option<GovManualProvisioningTask>> {
        // Get the entitlement to find the application
        let entitlement =
            GovEntitlement::find_by_id(&self.pool, tenant_id, assignment.entitlement_id)
                .await?
                .ok_or(GovernanceError::EntitlementNotFound(
                    assignment.entitlement_id,
                ))?;

        // Get the application
        let application =
            GovApplication::find_by_id(&self.pool, tenant_id, entitlement.application_id)
                .await?
                .ok_or(GovernanceError::ApplicationNotFound(
                    entitlement.application_id,
                ))?;

        // Check if application is semi-manual
        if !application.is_semi_manual {
            return Ok(None);
        }

        // Calculate SLA deadline if a policy is configured
        let sla_deadline = if let Some(policy_id) = application.sla_policy_id {
            if let Some(policy) = GovSlaPolicy::find_by_id(&self.pool, tenant_id, policy_id).await?
            {
                Some(Utc::now() + Duration::seconds(i64::from(policy.target_duration_seconds)))
            } else {
                None
            }
        } else {
            None
        };

        let input = CreateManualTask {
            assignment_id: assignment.id,
            application_id: application.id,
            user_id: assignment.target_id,
            entitlement_id: entitlement.id,
            operation_type: ManualTaskOperation::Revoke,
            sla_deadline,
        };

        let task = GovManualProvisioningTask::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            assignment_id = %assignment.id,
            task_id = %task.id,
            "Created revocation task for semi-manual resource"
        );

        // Create ticket if configured
        if application.ticketing_config_id.is_some() {
            match self
                .ticketing_service
                .create_ticket_for_task(tenant_id, task.id)
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        task_id = %task.id,
                        "Ticket created for revocation task"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        task_id = %task.id,
                        error = %e,
                        "Failed to create ticket for revocation; scheduling retry"
                    );
                    ticket_retry_scheduled(
                        &self.pool,
                        tenant_id,
                        task.id,
                        &e.to_string(),
                        serde_json::json!({
                            "application_id": application.id,
                            "entitlement_id": entitlement.id,
                            "operation_type": "revoke",
                        }),
                    )
                    .await?;
                }
            }
        }

        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task.id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task.id))?;

        Ok(Some(task))
    }
}

/// Persist a ticket-creation failure so the retry job can pick it up.
///
/// Must not claim `retry_scheduled` unless `next_retry_at` was written.
pub(crate) async fn ticket_retry_scheduled(
    pool: &PgPool,
    tenant_id: Uuid,
    task_id: Uuid,
    error: &str,
    extra: serde_json::Value,
) -> Result<()> {
    let next_retry = TicketRetryJob::calculate_next_retry(1);
    GovManualProvisioningTask::record_ticket_failure(pool, tenant_id, task_id, error, next_retry)
        .await
        .map_err(GovernanceError::Database)?
        .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

    let mut details = extra;
    if let Some(obj) = details.as_object_mut() {
        obj.insert("error".to_string(), serde_json::json!(error));
        obj.insert(
            "retry_scheduled".to_string(),
            serde_json::json!(next_retry.is_some()),
        );
        if let Some(at) = next_retry {
            obj.insert("next_retry_at".to_string(), serde_json::json!(at));
        }
    }

    GovManualTaskAuditEvent::create(
        pool,
        tenant_id,
        CreateManualTaskAuditEvent {
            task_id,
            event_type: ManualTaskEventType::TicketCreationFailed,
            actor_id: None,
            details: Some(details),
        },
    )
    .await
    .map_err(GovernanceError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_service_construction() {
        // This test verifies the types compile correctly
        // Actual service tests would require a database connection
    }

    #[test]
    fn ticket_failures_schedule_retry_instead_of_lying() {
        let src = include_str!("semi_manual_provisioning_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("ticket_retry_scheduled(")
                && production.contains("record_ticket_failure("),
            "ticket creation failures must persist a retry schedule"
        );
        assert!(
            !production.contains("retry_scheduled\": true")
                && !production.contains("don't fail - the retry mechanism will handle it"),
            "must not claim a retry was scheduled unless persist ran"
        );
        assert_eq!(
            production.matches("ticket_retry_scheduled(").count(),
            3,
            "grant, revoke, and helper definition"
        );
    }
}
