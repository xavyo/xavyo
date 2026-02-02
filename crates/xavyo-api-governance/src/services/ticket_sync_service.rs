//! Ticket Sync Service for semi-manual resources (F064).
//!
//! Handles synchronization between external ticketing systems and manual tasks.
//! Polls external systems for status updates and processes webhook callbacks.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CreateManualTaskAuditEvent, GovExternalTicket, GovManualProvisioningTask,
    GovManualTaskAuditEvent, ManualTaskEventType, TicketStatusCategory,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::ticketing::TicketStatus;
use crate::services::TicketingConfigService;

/// Service for synchronizing ticket status between external systems and governance.
pub struct TicketSyncService {
    pool: PgPool,
    ticketing_config_service: TicketingConfigService,
}

impl TicketSyncService {
    /// Create a new ticket sync service.
    pub fn new(pool: PgPool) -> Self {
        let ticketing_config_service = TicketingConfigService::new(pool.clone());
        Self {
            pool,
            ticketing_config_service,
        }
    }

    /// Get the database pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get tasks that need ticket status sync (for background job).
    ///
    /// Returns tasks with external tickets in non-terminal states.
    pub async fn get_tasks_needing_sync(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovManualProvisioningTask>> {
        let tasks = sqlx::query_as::<_, GovManualProvisioningTask>(
            r#"
            SELECT t.* FROM gov_manual_provisioning_tasks t
            INNER JOIN gov_external_tickets et ON t.external_ticket_id = et.id
            WHERE t.status IN ('ticket_created', 'in_progress', 'partially_completed')
            AND et.status_category NOT IN ('resolved', 'closed', 'rejected')
            ORDER BY t.created_at ASC
            LIMIT $1 OFFSET $2
            FOR UPDATE OF t SKIP LOCKED
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(tasks)
    }

    /// Sync a single task (for background job).
    ///
    /// Returns result indicating what happened.
    pub async fn sync_single_task(&self, tenant_id: Uuid, task_id: Uuid) -> Result<TaskSyncResult> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        let external_ticket_id = task.external_ticket_id.ok_or(GovernanceError::Validation(
            "Task has no external ticket".to_string(),
        ))?;

        let ticket = GovExternalTicket::find_by_id(&self.pool, tenant_id, external_ticket_id)
            .await?
            .ok_or(GovernanceError::ExternalTicketNotFound(external_ticket_id))?;

        // Sync the ticket - handle ticket not found (404) case
        match self
            .sync_single_ticket_internal(tenant_id, ticket.clone())
            .await
        {
            Ok(was_updated) => {
                // Check the updated task status
                let updated_task =
                    GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
                        .await?
                        .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

                Ok(TaskSyncResult {
                    was_updated,
                    task_completed: updated_task.status.is_terminal()
                        && updated_task.status == xavyo_db::ManualTaskStatus::Completed,
                    task_rejected: updated_task.status == xavyo_db::ManualTaskStatus::Rejected
                        || updated_task.status == xavyo_db::ManualTaskStatus::Cancelled,
                    ticket_missing: false,
                })
            }
            Err(GovernanceError::Validation(msg)) if msg.contains("Ticket not found") => {
                // Handle ticket deleted/missing in external system
                self.handle_missing_ticket(tenant_id, task_id, &ticket)
                    .await?;

                Ok(TaskSyncResult {
                    was_updated: true,
                    task_completed: false,
                    task_rejected: false,
                    ticket_missing: true,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Handle a ticket that was deleted/not found in the external system.
    async fn handle_missing_ticket(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        ticket: &GovExternalTicket,
    ) -> Result<()> {
        tracing::warn!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            external_reference = %ticket.external_reference,
            "Ticket not found in external system (404) - marking as missing"
        );

        // Update the external ticket status to indicate it's missing
        GovExternalTicket::update_status(
            &self.pool,
            tenant_id,
            ticket.id,
            Some("deleted"),
            TicketStatusCategory::Rejected, // Treat as rejected since ticket is gone
            Some(&serde_json::json!({
                "error": "ticket_not_found",
                "detected_at": chrono::Utc::now().to_rfc3339(),
            })),
        )
        .await?;

        // Create an audit event for the missing ticket
        let details = serde_json::json!({
            "event": "ticket_missing",
            "external_reference": ticket.external_reference,
            "external_url": ticket.external_url,
            "action": "ticket_deleted_in_external_system",
            "recovery_options": [
                "Create a new ticket manually",
                "Complete the task directly in the governance system",
                "Cancel the task if no longer needed"
            ],
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TicketStatusUpdated,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Update the task status to indicate manual intervention is needed
        // We set it back to pending so operators can recreate the ticket or handle manually
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        if !task.status.is_terminal() {
            // Clear the external ticket reference and set status back to pending
            sqlx::query(
                r#"
                UPDATE gov_manual_provisioning_tasks
                SET status = 'pending',
                    external_ticket_id = NULL,
                    error_message = $3,
                    updated_at = NOW()
                WHERE id = $1 AND tenant_id = $2
                "#,
            )
            .bind(task_id)
            .bind(tenant_id)
            .bind(format!(
                "Ticket {} was deleted in external system. Manual intervention required.",
                ticket.external_reference
            ))
            .execute(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;

            tracing::info!(
                tenant_id = %tenant_id,
                task_id = %task_id,
                "Task reset to pending due to missing ticket"
            );
        }

        Ok(())
    }

    /// Sync all pending tickets for a tenant.
    ///
    /// Returns the number of tickets synced and any errors encountered.
    pub async fn sync_all_pending_tickets(&self, tenant_id: Uuid) -> Result<TicketSyncResult> {
        let mut result = TicketSyncResult::default();

        // Get all external tickets that need syncing (not in terminal state)
        let tickets = sqlx::query_as::<_, GovExternalTicket>(
            r#"
            SELECT * FROM gov_external_tickets
            WHERE tenant_id = $1
            AND status_category NOT IN ('resolved', 'closed', 'rejected')
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        result.total_tickets = tickets.len();

        for ticket in tickets {
            let ticket_id = ticket.id;
            let task_id = ticket.task_id;
            match self
                .sync_single_ticket_internal(tenant_id, ticket.clone())
                .await
            {
                Ok(updated) => {
                    if updated {
                        result.synced_count += 1;
                    }
                }
                Err(GovernanceError::Validation(msg)) if msg.contains("Ticket not found") => {
                    // Handle ticket deleted/missing in external system
                    if let Err(e) = self
                        .handle_missing_ticket(tenant_id, task_id, &ticket)
                        .await
                    {
                        tracing::error!(
                            tenant_id = %tenant_id,
                            ticket_id = ?ticket_id,
                            error = %e,
                            "Failed to handle missing ticket"
                        );
                        result.errors.push(TicketSyncError {
                            ticket_id,
                            error: format!("Missing ticket handling failed: {}", e),
                        });
                    } else {
                        result.synced_count += 1; // Count as synced since we handled it
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        ticket_id = ?ticket_id,
                        error = %e,
                        "Failed to sync ticket"
                    );
                    result.errors.push(TicketSyncError {
                        ticket_id,
                        error: e.to_string(),
                    });
                }
            }
        }

        tracing::info!(
            tenant_id = %tenant_id,
            total = result.total_tickets,
            synced = result.synced_count,
            errors = result.errors.len(),
            "Ticket sync completed"
        );

        Ok(result)
    }

    /// Sync a single ticket by its ID.
    pub async fn sync_ticket_by_id(
        &self,
        tenant_id: Uuid,
        ticket_id: Uuid,
    ) -> Result<TicketSyncStatus> {
        let ticket = GovExternalTicket::find_by_id(&self.pool, tenant_id, ticket_id)
            .await?
            .ok_or(GovernanceError::ExternalTicketNotFound(ticket_id))?;

        let task_id = ticket.task_id;
        let updated = match self
            .sync_single_ticket_internal(tenant_id, ticket.clone())
            .await
        {
            Ok(updated) => updated,
            Err(GovernanceError::Validation(msg)) if msg.contains("Ticket not found") => {
                // Handle ticket deleted/missing in external system
                self.handle_missing_ticket(tenant_id, task_id, &ticket)
                    .await?;
                true // Treat as updated since we handled the missing ticket
            }
            Err(e) => return Err(e),
        };

        Ok(TicketSyncStatus {
            ticket_id,
            was_updated: updated,
            synced_at: chrono::Utc::now(),
        })
    }

    /// Sync a single external ticket (internal implementation).
    async fn sync_single_ticket_internal(
        &self,
        tenant_id: Uuid,
        ticket: GovExternalTicket,
    ) -> Result<bool> {
        // Get the provider for this ticket's configuration
        let provider = self
            .ticketing_config_service
            .get_provider(tenant_id, ticket.ticketing_config_id)
            .await?;

        // Poll the external system for status
        let status_response = provider
            .get_ticket_status(&ticket.external_reference)
            .await
            .map_err(|e| {
                GovernanceError::Validation(format!("Failed to get ticket status: {}", e))
            })?;

        // Map external status to our status category
        let new_category = map_ticket_status_to_category(&status_response.status);
        let old_category = ticket.status_category;

        // Check if status actually changed
        if new_category == old_category {
            // Update last_synced_at even if no status change
            sqlx::query(
                r#"
                UPDATE gov_external_tickets
                SET last_synced_at = NOW(), updated_at = NOW()
                WHERE id = $1 AND tenant_id = $2
                "#,
            )
            .bind(ticket.id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;

            return Ok(false);
        }

        // Update the external ticket
        GovExternalTicket::update_status(
            &self.pool,
            tenant_id,
            ticket.id,
            Some(status_response.status.as_str()),
            new_category,
            status_response.raw_response.as_ref(),
        )
        .await?;

        // Log the ticket status update
        let details = serde_json::json!({
            "old_status": format!("{:?}", old_category),
            "new_status": format!("{:?}", new_category),
            "external_status": status_response.status.as_str(),
            "resolution_notes": status_response.resolution_notes,
            "resolved_by": status_response.resolved_by,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id: ticket.task_id,
                event_type: ManualTaskEventType::TicketStatusUpdated,
                actor_id: None, // System sync
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            ticket_id = %ticket.id,
            external_reference = %ticket.external_reference,
            old_status = ?old_category,
            new_status = ?new_category,
            "Ticket status updated"
        );

        // If ticket is now resolved, update the manual task
        if new_category.is_completed() {
            self.complete_task_from_ticket(
                tenant_id,
                ticket.task_id,
                status_response.resolution_notes.as_deref(),
            )
            .await?;
        } else if new_category.is_rejected() {
            // Ticket was rejected/cancelled externally
            self.cancel_task_from_ticket(
                tenant_id,
                ticket.task_id,
                "Ticket cancelled in external system",
            )
            .await?;
        }

        Ok(true)
    }

    /// Complete a task when its ticket is resolved.
    async fn complete_task_from_ticket(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        notes: Option<&str>,
    ) -> Result<()> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        // Only update if task is not already completed
        if task.status.is_terminal() {
            return Ok(());
        }

        // Confirm the task
        GovManualProvisioningTask::confirm(&self.pool, tenant_id, task_id, notes).await?;

        // Log the completion
        let details = serde_json::json!({
            "action": "completed_from_ticket",
            "notes": notes,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TaskConfirmed,
                actor_id: None, // System
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            "Task completed from ticket resolution"
        );

        Ok(())
    }

    /// Cancel a task when its ticket is cancelled.
    async fn cancel_task_from_ticket(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        reason: &str,
    ) -> Result<()> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        if task.status.is_terminal() {
            return Ok(());
        }

        // Cancel the task
        GovManualProvisioningTask::cancel(&self.pool, tenant_id, task_id, Some(reason)).await?;

        // Log the cancellation
        let details = serde_json::json!({
            "action": "cancelled_from_ticket",
            "reason": reason,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::TaskCancelled,
                actor_id: None, // System
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            reason = %reason,
            "Task cancelled from ticket cancellation"
        );

        Ok(())
    }

    /// Process a webhook callback from an external ticketing system.
    pub async fn process_webhook_callback(
        &self,
        tenant_id: Uuid,
        configuration_id: Uuid,
        payload: &WebhookCallbackPayload,
    ) -> Result<WebhookCallbackResult> {
        // Find the ticket by external reference
        let ticket = GovExternalTicket::find_by_reference(
            &self.pool,
            tenant_id,
            configuration_id,
            &payload.ticket_id,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let ticket = match ticket {
            Some(t) => t,
            None => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    external_reference = %payload.ticket_id,
                    "Webhook received for unknown ticket"
                );
                return Ok(WebhookCallbackResult {
                    processed: false,
                    message: "Unknown ticket".to_string(),
                });
            }
        };

        // Map the webhook status to our status category
        let new_category = match payload.status.to_lowercase().as_str() {
            "open" | "new" | "pending" => TicketStatusCategory::Open,
            "in_progress" | "active" | "working" => TicketStatusCategory::InProgress,
            "resolved" | "done" | "completed" => TicketStatusCategory::Resolved,
            "closed" => TicketStatusCategory::Closed,
            "cancelled" | "canceled" | "rejected" => TicketStatusCategory::Rejected,
            _ => TicketStatusCategory::Open,
        };

        let old_category = ticket.status_category;

        // Update the ticket
        GovExternalTicket::update_status(
            &self.pool,
            tenant_id,
            ticket.id,
            Some(&payload.status),
            new_category,
            None,
        )
        .await?;

        // Log the update
        let details = serde_json::json!({
            "source": "webhook",
            "old_status": format!("{:?}", old_category),
            "new_status": format!("{:?}", new_category),
            "external_status": &payload.status,
            "resolution_notes": &payload.resolution_notes,
            "resolved_by": &payload.resolved_by,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id: ticket.task_id,
                event_type: ManualTaskEventType::WebhookReceived,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            ticket_id = %ticket.id,
            external_reference = %ticket.external_reference,
            old_status = ?old_category,
            new_status = ?new_category,
            "Ticket status updated from webhook"
        );

        // Update the task if ticket is resolved
        if new_category.is_completed() {
            self.complete_task_from_ticket(
                tenant_id,
                ticket.task_id,
                payload.resolution_notes.as_deref(),
            )
            .await?;
        } else if new_category.is_rejected() {
            self.cancel_task_from_ticket(
                tenant_id,
                ticket.task_id,
                payload
                    .resolution_notes
                    .as_deref()
                    .unwrap_or("Cancelled via webhook"),
            )
            .await?;
        }

        Ok(WebhookCallbackResult {
            processed: true,
            message: format!("Ticket {} updated to {:?}", payload.ticket_id, new_category),
        })
    }
}

/// Map our TicketStatus to TicketStatusCategory for storage.
fn map_ticket_status_to_category(status: &TicketStatus) -> TicketStatusCategory {
    match status {
        TicketStatus::Open => TicketStatusCategory::Open,
        TicketStatus::InProgress => TicketStatusCategory::InProgress,
        TicketStatus::Pending => TicketStatusCategory::Pending,
        TicketStatus::Resolved => TicketStatusCategory::Resolved,
        TicketStatus::Closed => TicketStatusCategory::Closed,
        TicketStatus::Cancelled => TicketStatusCategory::Rejected,
        TicketStatus::Unknown(_) => TicketStatusCategory::Open,
    }
}

/// Result of a ticket sync operation.
#[derive(Debug, Default)]
pub struct TicketSyncResult {
    /// Total number of tickets checked.
    pub total_tickets: usize,
    /// Number of tickets that were updated.
    pub synced_count: usize,
    /// Errors encountered during sync.
    pub errors: Vec<TicketSyncError>,
}

/// Error during ticket sync.
#[derive(Debug)]
pub struct TicketSyncError {
    pub ticket_id: Uuid,
    pub error: String,
}

/// Status of a single ticket sync.
#[derive(Debug)]
pub struct TicketSyncStatus {
    pub ticket_id: Uuid,
    pub was_updated: bool,
    pub synced_at: chrono::DateTime<chrono::Utc>,
}

/// Payload received from a webhook callback.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebhookCallbackPayload {
    /// External ticket ID/reference.
    pub ticket_id: String,
    /// New status from external system.
    pub status: String,
    /// Resolution notes if resolved.
    #[serde(default)]
    pub resolution_notes: Option<String>,
    /// Who resolved the ticket.
    #[serde(default)]
    pub resolved_by: Option<String>,
}

/// Result of processing a webhook callback.
#[derive(Debug)]
pub struct WebhookCallbackResult {
    pub processed: bool,
    pub message: String,
}

/// Result of syncing a single task.
#[derive(Debug, Default)]
pub struct TaskSyncResult {
    /// Whether the ticket status was updated.
    pub was_updated: bool,
    /// Whether the task was completed.
    pub task_completed: bool,
    /// Whether the task was rejected/cancelled.
    pub task_rejected: bool,
    /// Whether the ticket was missing (404).
    pub ticket_missing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_mapping() {
        assert_eq!(
            map_ticket_status_to_category(&TicketStatus::Open),
            TicketStatusCategory::Open
        );
        assert_eq!(
            map_ticket_status_to_category(&TicketStatus::InProgress),
            TicketStatusCategory::InProgress
        );
        assert_eq!(
            map_ticket_status_to_category(&TicketStatus::Resolved),
            TicketStatusCategory::Resolved
        );
        assert_eq!(
            map_ticket_status_to_category(&TicketStatus::Cancelled),
            TicketStatusCategory::Rejected
        );
    }

    #[test]
    fn test_webhook_payload_deserialization() {
        let json = r#"{"ticket_id": "INC123", "status": "resolved"}"#;
        let payload: WebhookCallbackPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.ticket_id, "INC123");
        assert_eq!(payload.status, "resolved");
        assert!(payload.resolution_notes.is_none());
    }

    #[test]
    fn test_task_sync_result_default() {
        let result = TaskSyncResult::default();
        assert!(!result.was_updated);
        assert!(!result.task_completed);
        assert!(!result.task_rejected);
        assert!(!result.ticket_missing);
    }

    #[test]
    fn test_task_sync_result_with_missing_ticket() {
        let result = TaskSyncResult {
            was_updated: true,
            task_completed: false,
            task_rejected: false,
            ticket_missing: true,
        };
        assert!(result.was_updated);
        assert!(result.ticket_missing);
        assert!(!result.task_completed);
    }
}
