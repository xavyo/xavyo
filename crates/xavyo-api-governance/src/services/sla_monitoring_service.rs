//! SLA Monitoring Service for semi-manual resources (F064).
//!
//! Monitors manual provisioning tasks for SLA compliance,
//! sending warnings before deadlines and marking breaches.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::{
    CreateManualTaskAuditEvent, GovApplication, GovEntitlement, GovManualProvisioningTask,
    GovManualTaskAuditEvent, GovSlaPolicy, ManualTaskEventType, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::sla_notification_service::{
    SlaBreachNotification, SlaNotificationConfig, SlaNotificationService, SlaWarningNotification,
};

/// Service for monitoring SLA compliance of manual tasks.
pub struct SlaMonitoringService {
    pool: PgPool,
    notification_service: Arc<SlaNotificationService>,
}

impl SlaMonitoringService {
    /// Create a new SLA monitoring service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        let notification_service = Arc::new(SlaNotificationService::with_defaults(pool.clone()));
        Self {
            pool,
            notification_service,
        }
    }

    /// Create with custom notification configuration.
    #[must_use] 
    pub fn with_notification_config(pool: PgPool, config: SlaNotificationConfig) -> Self {
        let notification_service = Arc::new(SlaNotificationService::new(pool.clone(), config));
        Self {
            pool,
            notification_service,
        }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Process tasks needing SLA warnings (for background job).
    ///
    /// Returns result with count of processed and warned tasks.
    pub async fn process_sla_warnings(&self, limit: i64) -> Result<SlaProcessingResult> {
        let mut result = SlaProcessingResult::default();
        let now = Utc::now();

        // Get tasks approaching SLA deadline that haven't received warning
        let tasks = sqlx::query_as::<_, TaskWithSla>(
            r"
            SELECT
                t.id as task_id,
                t.tenant_id,
                t.sla_deadline,
                t.sla_warning_sent,
                t.sla_breached,
                t.created_at as task_created_at,
                p.id as policy_id,
                p.name as policy_name,
                p.warning_threshold_percent,
                p.target_duration_seconds,
                p.escalation_contacts
            FROM gov_manual_provisioning_tasks t
            INNER JOIN gov_sla_policies p ON t.sla_policy_id = p.id
            WHERE t.status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')
            AND t.sla_deadline IS NOT NULL
            AND t.sla_warning_sent = false
            AND t.sla_breached = false
            AND t.sla_deadline > $1
            ORDER BY t.sla_deadline ASC
            LIMIT $2
            FOR UPDATE OF t SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        for task in tasks {
            result.checked += 1;

            // Calculate warning threshold
            let deadline = match task.sla_deadline {
                Some(d) => d,
                None => continue,
            };

            let warning_percent = task.warning_threshold_percent.unwrap_or(75);
            let target_seconds = task.target_duration_seconds.unwrap_or(3600);
            let warning_seconds = (i64::from(target_seconds) * i64::from(warning_percent)) / 100;
            let warning_time = deadline - Duration::seconds(warning_seconds);

            if now >= warning_time {
                match self
                    .send_warning(task.tenant_id, task.task_id, &task, deadline)
                    .await
                {
                    Ok(()) => result.warnings_sent += 1,
                    Err(e) => {
                        tracing::error!(task_id = %task.task_id, error = %e, "Failed to send SLA warning");
                        result.failed += 1;
                    }
                }
            }
        }

        Ok(result)
    }

    /// Process tasks that have breached SLA (for background job).
    ///
    /// Returns result with count of processed and breached tasks.
    pub async fn process_sla_breaches(&self, limit: i64) -> Result<SlaProcessingResult> {
        let mut result = SlaProcessingResult::default();
        let now = Utc::now();

        // Get tasks past SLA deadline that aren't marked as breached
        let tasks = sqlx::query_as::<_, TaskWithSla>(
            r"
            SELECT
                t.id as task_id,
                t.tenant_id,
                t.sla_deadline,
                t.sla_warning_sent,
                t.sla_breached,
                t.created_at as task_created_at,
                p.id as policy_id,
                p.name as policy_name,
                p.warning_threshold_percent,
                p.target_duration_seconds,
                p.escalation_contacts
            FROM gov_manual_provisioning_tasks t
            LEFT JOIN gov_sla_policies p ON t.sla_policy_id = p.id
            WHERE t.status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')
            AND t.sla_deadline IS NOT NULL
            AND t.sla_breached = false
            AND t.sla_deadline <= $1
            ORDER BY t.sla_deadline ASC
            LIMIT $2
            FOR UPDATE OF t SKIP LOCKED
            ",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        for task in tasks {
            result.checked += 1;

            match self.mark_breach(task.tenant_id, task.task_id, &task).await {
                Ok(()) => result.breaches_detected += 1,
                Err(e) => {
                    tracing::error!(task_id = %task.task_id, error = %e, "Failed to mark SLA breach");
                    result.failed += 1;
                }
            }
        }

        Ok(result)
    }

    /// Check all active tasks for SLA compliance.
    ///
    /// This should be called periodically (e.g., every 5 minutes) by a background job.
    pub async fn check_all_tasks(&self, tenant_id: Uuid) -> Result<SlaCheckResult> {
        let mut result = SlaCheckResult::default();

        // Get all active tasks with their SLA policies
        let tasks = sqlx::query_as::<_, TaskWithSla>(
            r"
            SELECT
                t.id as task_id,
                t.tenant_id,
                t.sla_deadline,
                t.sla_warning_sent,
                t.sla_breached,
                t.created_at as task_created_at,
                p.id as policy_id,
                p.name as policy_name,
                p.warning_threshold_percent,
                p.target_duration_seconds,
                p.escalation_contacts
            FROM gov_manual_provisioning_tasks t
            LEFT JOIN gov_sla_policies p ON t.sla_policy_id = p.id
            WHERE t.tenant_id = $1
            AND t.status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')
            AND t.sla_deadline IS NOT NULL
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        result.total_tasks = tasks.len();
        let now = Utc::now();

        for task in tasks {
            // Skip if no SLA deadline
            let deadline = match task.sla_deadline {
                Some(d) => d,
                None => continue,
            };

            // Check for breach
            if now > deadline && !task.sla_breached {
                match self.mark_breach(tenant_id, task.task_id, &task).await {
                    Ok(()) => result.breached_count += 1,
                    Err(e) => {
                        tracing::error!(
                            task_id = %task.task_id,
                            error = %e,
                            "Failed to mark SLA breach"
                        );
                        result.errors.push(SlaCheckError {
                            task_id: task.task_id,
                            error: e.to_string(),
                        });
                    }
                }
            }
            // Check for warning
            else if let (Some(warning_percent), Some(target_seconds)) =
                (task.warning_threshold_percent, task.target_duration_seconds)
            {
                // Warning when remaining time is less than warning_percent of total
                let warning_seconds = (i64::from(target_seconds) * i64::from(warning_percent)) / 100;
                let warning_time = deadline - Duration::seconds(warning_seconds);
                if now > warning_time && !task.sla_warning_sent {
                    match self
                        .send_warning(tenant_id, task.task_id, &task, deadline)
                        .await
                    {
                        Ok(()) => result.warned_count += 1,
                        Err(e) => {
                            tracing::error!(
                                task_id = %task.task_id,
                                error = %e,
                                "Failed to send SLA warning"
                            );
                            result.errors.push(SlaCheckError {
                                task_id: task.task_id,
                                error: e.to_string(),
                            });
                        }
                    }
                }
            }
        }

        tracing::info!(
            tenant_id = %tenant_id,
            total = result.total_tasks,
            breached = result.breached_count,
            warned = result.warned_count,
            errors = result.errors.len(),
            "SLA check completed"
        );

        Ok(result)
    }

    /// Mark a task as SLA breached.
    async fn mark_breach(&self, tenant_id: Uuid, task_id: Uuid, task: &TaskWithSla) -> Result<()> {
        // Update the task
        sqlx::query(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET sla_breached = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(task_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Log the breach event
        let details = serde_json::json!({
            "sla_deadline": task.sla_deadline,
            "policy_name": task.policy_name,
            "escalation_contacts": task.escalation_contacts,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::SlaBreached,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::warn!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            deadline = ?task.sla_deadline,
            policy = ?task.policy_name,
            "SLA breach detected"
        );

        // Send breach notifications
        if let Some(deadline) = task.sla_deadline {
            let overdue_minutes = (Utc::now() - deadline).num_minutes();

            // Extract escalation emails from contacts JSON
            let escalation_emails = self.extract_escalation_emails(&task.escalation_contacts);

            // Get task details for notification
            if let Ok(Some(full_task)) =
                GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id).await
            {
                let (app_name, ent_name) = self
                    .get_task_names(
                        tenant_id,
                        full_task.application_id,
                        full_task.entitlement_id,
                    )
                    .await
                    .unwrap_or_else(|_| ("Unknown".to_string(), "Unknown".to_string()));

                // Lookup assignee email if task is assigned
                let assignee_email = match full_task.assignee_id {
                    Some(assignee_id) => self.get_user_email(tenant_id, assignee_id).await,
                    None => None,
                };

                // Get user display name for the user receiving access
                let user_display_name = self
                    .get_user_display_name(tenant_id, full_task.user_id)
                    .await;

                let notification = SlaBreachNotification {
                    tenant_id,
                    task_id,
                    application_name: app_name,
                    entitlement_name: ent_name,
                    user_display_name,
                    sla_deadline: deadline,
                    overdue_minutes,
                    policy_name: task.policy_name.clone().unwrap_or_default(),
                    escalation_emails,
                    assignee_email,
                };

                if let Err(e) = self
                    .notification_service
                    .send_breach_notification(&notification)
                    .await
                {
                    tracing::error!(
                        task_id = %task_id,
                        error = %e,
                        "Failed to send breach notification"
                    );
                }
            }
        }

        Ok(())
    }

    /// Extract escalation emails from contacts JSON.
    fn extract_escalation_emails(&self, contacts: &Option<serde_json::Value>) -> Vec<String> {
        contacts
            .as_ref()
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get application and entitlement names for notification.
    async fn get_task_names(
        &self,
        tenant_id: Uuid,
        app_id: Uuid,
        ent_id: Uuid,
    ) -> Result<(String, String)> {
        let app = GovApplication::find_by_id(&self.pool, tenant_id, app_id)
            .await?.map_or_else(|| "Unknown".to_string(), |a| a.name);

        let ent = GovEntitlement::find_by_id(&self.pool, tenant_id, ent_id)
            .await?.map_or_else(|| "Unknown".to_string(), |e| e.name);

        Ok((app, ent))
    }

    /// Lookup user email by ID (include `tenant_id` for defense-in-depth).
    async fn get_user_email(&self, tenant_id: Uuid, user_id: Uuid) -> Option<String> {
        match User::find_by_id_in_tenant(&self.pool, tenant_id, user_id).await {
            Ok(Some(user)) => Some(user.email),
            Ok(None) => {
                tracing::warn!(user_id = %user_id, "User not found for email lookup");
                None
            }
            Err(e) => {
                tracing::error!(user_id = %user_id, error = %e, "Failed to lookup user email");
                None
            }
        }
    }

    /// Get user display name or fallback to email or ID (include `tenant_id` for defense-in-depth).
    async fn get_user_display_name(&self, tenant_id: Uuid, user_id: Uuid) -> String {
        match User::find_by_id_in_tenant(&self.pool, tenant_id, user_id).await {
            Ok(Some(user)) => user
                .display_name
                .or_else(|| {
                    // Build name from first + last
                    match (&user.first_name, &user.last_name) {
                        (Some(first), Some(last)) => Some(format!("{first} {last}")),
                        (Some(first), None) => Some(first.clone()),
                        (None, Some(last)) => Some(last.clone()),
                        (None, None) => None,
                    }
                })
                .unwrap_or_else(|| user.email.clone()),
            Ok(None) => user_id.to_string(),
            Err(_) => user_id.to_string(),
        }
    }

    /// Send a warning for an approaching SLA deadline.
    async fn send_warning(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
        task: &TaskWithSla,
        deadline: DateTime<Utc>,
    ) -> Result<()> {
        // Update the task
        sqlx::query(
            r"
            UPDATE gov_manual_provisioning_tasks
            SET sla_warning_sent = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(task_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Log the warning event
        let time_remaining = deadline - Utc::now();
        let details = serde_json::json!({
            "sla_deadline": deadline,
            "time_remaining_minutes": time_remaining.num_minutes(),
            "policy_name": task.policy_name,
            "warning_threshold_percent": task.warning_threshold_percent,
        });

        GovManualTaskAuditEvent::create(
            &self.pool,
            tenant_id,
            CreateManualTaskAuditEvent {
                task_id,
                event_type: ManualTaskEventType::SlaWarningSent,
                actor_id: None,
                details: Some(details),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            deadline = ?deadline,
            time_remaining_minutes = time_remaining.num_minutes(),
            "SLA warning sent"
        );

        // Send warning notifications
        // Get task details for notification
        if let Ok(Some(full_task)) =
            GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id).await
        {
            let (app_name, ent_name) = self
                .get_task_names(
                    tenant_id,
                    full_task.application_id,
                    full_task.entitlement_id,
                )
                .await
                .unwrap_or_else(|_| ("Unknown".to_string(), "Unknown".to_string()));

            // Extract recipient emails from escalation contacts
            let recipient_emails = self.extract_escalation_emails(&task.escalation_contacts);

            // Lookup assignee email if task is assigned
            let assignee_email = match full_task.assignee_id {
                Some(assignee_id) => self.get_user_email(tenant_id, assignee_id).await,
                None => None,
            };

            // Get user display name for the user receiving access
            let user_display_name = self
                .get_user_display_name(tenant_id, full_task.user_id)
                .await;

            let notification = SlaWarningNotification {
                tenant_id,
                task_id,
                application_name: app_name,
                entitlement_name: ent_name,
                user_display_name,
                sla_deadline: deadline,
                time_remaining_minutes: time_remaining.num_minutes(),
                warning_threshold_percent: task.warning_threshold_percent.unwrap_or(75),
                policy_name: task.policy_name.clone().unwrap_or_default(),
                recipient_emails,
                assignee_email,
            };

            if let Err(e) = self
                .notification_service
                .send_warning_notification(&notification)
                .await
            {
                tracing::error!(
                    task_id = %task_id,
                    error = %e,
                    "Failed to send warning notification"
                );
            }
        }

        Ok(())
    }

    /// Calculate SLA deadline for a new task based on policy.
    pub async fn calculate_deadline(
        &self,
        tenant_id: Uuid,
        policy_id: Uuid,
        created_at: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        let policy = GovSlaPolicy::find_by_id(&self.pool, tenant_id, policy_id)
            .await?
            .ok_or(GovernanceError::SlaPolicyNotFound(policy_id))?;

        Ok(Some(
            created_at + Duration::seconds(i64::from(policy.target_duration_seconds)),
        ))
    }

    /// Get SLA status for a specific task.
    pub async fn get_task_sla_status(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> Result<TaskSlaStatus> {
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await?
            .ok_or(GovernanceError::ManualProvisioningTaskNotFound(task_id))?;

        let now = Utc::now();
        let deadline = task.sla_deadline;

        let status = if task.sla_breached {
            SlaStatusLevel::Breached
        } else if let Some(d) = deadline {
            if now > d {
                SlaStatusLevel::Breached
            } else if task.sla_warning_sent {
                SlaStatusLevel::AtRisk
            } else {
                // Check if within warning threshold
                // We'd need to load the policy for this
                SlaStatusLevel::OnTrack
            }
        } else {
            SlaStatusLevel::NoSla
        };

        Ok(TaskSlaStatus {
            task_id,
            deadline,
            warning_sent: task.sla_warning_sent,
            breached: task.sla_breached,
            status,
            time_remaining: deadline.map(|d| (d - now).num_minutes()),
        })
    }

    /// Get summary of SLA compliance for a tenant.
    pub async fn get_compliance_summary(&self, tenant_id: Uuid) -> Result<SlaComplianceSummary> {
        let row = sqlx::query_as::<_, ComplianceRow>(
            r"
            SELECT
                COUNT(*) FILTER (WHERE sla_deadline IS NOT NULL AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as active_with_sla,
                COUNT(*) FILTER (WHERE sla_breached = true AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as currently_breached,
                COUNT(*) FILTER (WHERE sla_warning_sent = true AND sla_breached = false AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as at_risk,
                COUNT(*) FILTER (WHERE sla_breached = false AND sla_warning_sent = false AND sla_deadline IS NOT NULL AND status NOT IN ('completed', 'rejected', 'cancelled', 'failed_permanent')) as on_track,
                COUNT(*) FILTER (WHERE status = 'completed' AND sla_breached = false AND sla_deadline IS NOT NULL) as completed_on_time,
                COUNT(*) FILTER (WHERE status = 'completed' AND sla_breached = true AND sla_deadline IS NOT NULL) as completed_breached
            FROM gov_manual_provisioning_tasks
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let total_completed = row.completed_on_time + row.completed_breached;
        let compliance_rate = if total_completed > 0 {
            (row.completed_on_time as f64 / total_completed as f64) * 100.0
        } else {
            100.0
        };

        Ok(SlaComplianceSummary {
            active_with_sla: row.active_with_sla,
            currently_breached: row.currently_breached,
            at_risk: row.at_risk,
            on_track: row.on_track,
            completed_on_time: row.completed_on_time,
            completed_breached: row.completed_breached,
            compliance_rate,
        })
    }
}

/// Task data with SLA policy information.
#[derive(Debug, sqlx::FromRow)]
struct TaskWithSla {
    task_id: Uuid,
    #[allow(dead_code)]
    tenant_id: Uuid,
    sla_deadline: Option<DateTime<Utc>>,
    sla_warning_sent: bool,
    sla_breached: bool,
    #[allow(dead_code)]
    task_created_at: DateTime<Utc>,
    #[allow(dead_code)]
    policy_id: Option<Uuid>,
    policy_name: Option<String>,
    /// Warning threshold as percentage of target time.
    warning_threshold_percent: Option<i32>,
    /// Target duration in seconds.
    #[allow(dead_code)]
    target_duration_seconds: Option<i32>,
    /// Escalation contacts JSON.
    escalation_contacts: Option<serde_json::Value>,
}

/// Row for compliance query.
#[derive(Debug, sqlx::FromRow)]
struct ComplianceRow {
    active_with_sla: i64,
    currently_breached: i64,
    at_risk: i64,
    on_track: i64,
    completed_on_time: i64,
    completed_breached: i64,
}

/// Result of SLA processing (for background job).
#[derive(Debug, Default)]
pub struct SlaProcessingResult {
    /// Total tasks checked.
    pub checked: usize,
    /// Warnings sent.
    pub warnings_sent: usize,
    /// Breaches detected.
    pub breaches_detected: usize,
    /// Failed operations.
    pub failed: usize,
}

/// Result of an SLA check operation.
#[derive(Debug, Default)]
pub struct SlaCheckResult {
    /// Total number of active tasks checked.
    pub total_tasks: usize,
    /// Number of tasks that breached SLA during this check.
    pub breached_count: usize,
    /// Number of warning notifications sent.
    pub warned_count: usize,
    /// Errors encountered during check.
    pub errors: Vec<SlaCheckError>,
}

/// Error during SLA check.
#[derive(Debug)]
pub struct SlaCheckError {
    pub task_id: Uuid,
    pub error: String,
}

/// SLA status for a task.
#[derive(Debug)]
pub struct TaskSlaStatus {
    pub task_id: Uuid,
    pub deadline: Option<DateTime<Utc>>,
    pub warning_sent: bool,
    pub breached: bool,
    pub status: SlaStatusLevel,
    /// Time remaining in minutes (negative if breached).
    pub time_remaining: Option<i64>,
}

/// SLA status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaStatusLevel {
    /// No SLA configured for this task.
    NoSla,
    /// On track to meet SLA.
    OnTrack,
    /// Warning threshold reached, at risk of breach.
    AtRisk,
    /// SLA has been breached.
    Breached,
}

/// Summary of SLA compliance for a tenant.
#[derive(Debug)]
pub struct SlaComplianceSummary {
    /// Active tasks with SLA configured.
    pub active_with_sla: i64,
    /// Active tasks currently in breach.
    pub currently_breached: i64,
    /// Active tasks at risk (warning sent).
    pub at_risk: i64,
    /// Active tasks on track.
    pub on_track: i64,
    /// Completed tasks that met SLA.
    pub completed_on_time: i64,
    /// Completed tasks that breached SLA.
    pub completed_breached: i64,
    /// Overall compliance rate (percentage).
    pub compliance_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_status_level() {
        assert_ne!(SlaStatusLevel::OnTrack, SlaStatusLevel::Breached);
        assert_eq!(SlaStatusLevel::Breached, SlaStatusLevel::Breached);
    }

    #[test]
    fn test_sla_check_result_default() {
        let result = SlaCheckResult::default();
        assert_eq!(result.total_tasks, 0);
        assert_eq!(result.breached_count, 0);
        assert_eq!(result.warned_count, 0);
        assert!(result.errors.is_empty());
    }
}
