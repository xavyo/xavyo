//! Lifecycle action executor service (F-193).
//!
//! Executes entry and exit actions during state transitions.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_db::{ActionTriggerType, CreateGovLifecycleActionExecution, GovLifecycleActionExecution};
use xavyo_governance::GovernanceError;

use crate::models::lifecycle::{LifecycleAction, LifecycleActionType};

/// Context for action execution.
#[derive(Debug, Clone)]
pub struct ActionExecutionContext {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// User/object ID being transitioned.
    pub object_id: Uuid,
    /// Transition audit ID.
    pub transition_audit_id: Uuid,
    /// State ID where action is defined.
    pub state_id: Uuid,
    /// Actor performing the transition.
    pub actor_id: Uuid,
    /// When the transition started.
    pub transition_started_at: DateTime<Utc>,
}

/// Result of executing a single action.
#[derive(Debug, Clone)]
pub struct ActionExecutionResult {
    /// Action type that was executed.
    pub action_type: LifecycleActionType,
    /// Whether the action succeeded.
    pub success: bool,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// Execution ID in the database.
    pub execution_id: Uuid,
}

/// Result of executing all actions for a trigger.
#[derive(Debug, Clone)]
pub struct ActionBatchResult {
    /// Individual action results.
    pub results: Vec<ActionExecutionResult>,
    /// Number of successful actions.
    pub success_count: usize,
    /// Number of failed actions.
    pub failure_count: usize,
    /// Whether any action failed that didn't have continue_on_failure set.
    pub has_blocking_failure: bool,
}

impl ActionBatchResult {
    /// Check if all actions succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failure_count == 0
    }
}

/// Service for executing lifecycle actions.
pub struct ActionExecutor {
    pool: Arc<PgPool>,
}

impl ActionExecutor {
    /// Create a new action executor.
    #[must_use]
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Execute a batch of actions.
    pub async fn execute_actions(
        &self,
        context: &ActionExecutionContext,
        actions: &[LifecycleAction],
        trigger_type: ActionTriggerType,
    ) -> Result<ActionBatchResult, GovernanceError> {
        let mut results = Vec::new();
        let mut success_count = 0;
        let mut failure_count = 0;
        let mut has_blocking_failure = false;

        for action in actions {
            // Create execution record
            let execution = self
                .create_execution_record(context, action, trigger_type)
                .await?;

            // Execute the action
            let result = self.execute_single_action(context, action).await;

            match result {
                Ok(()) => {
                    // Mark as success
                    GovLifecycleActionExecution::mark_success(
                        &self.pool,
                        context.tenant_id,
                        execution.id,
                    )
                    .await?;
                    success_count += 1;
                    results.push(ActionExecutionResult {
                        action_type: action.action_type,
                        success: true,
                        error_message: None,
                        execution_id: execution.id,
                    });
                }
                Err(e) => {
                    // Mark as failed
                    let error_msg = e.to_string();
                    GovLifecycleActionExecution::mark_failed(
                        &self.pool,
                        context.tenant_id,
                        execution.id,
                        &error_msg,
                    )
                    .await?;
                    failure_count += 1;

                    if !action.continue_on_failure {
                        has_blocking_failure = true;
                    }

                    results.push(ActionExecutionResult {
                        action_type: action.action_type,
                        success: false,
                        error_message: Some(error_msg),
                        execution_id: execution.id,
                    });

                    // If this action blocks on failure, stop processing
                    if !action.continue_on_failure {
                        break;
                    }
                }
            }
        }

        Ok(ActionBatchResult {
            results,
            success_count,
            failure_count,
            has_blocking_failure,
        })
    }

    /// Create an execution record in the database.
    async fn create_execution_record(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
        trigger_type: ActionTriggerType,
    ) -> Result<GovLifecycleActionExecution, GovernanceError> {
        let input = CreateGovLifecycleActionExecution {
            transition_audit_id: context.transition_audit_id,
            state_id: context.state_id,
            action_type: action.action_type.to_string(),
            action_config: action.config.clone(),
            trigger_type,
        };

        GovLifecycleActionExecution::create(&self.pool, context.tenant_id, &input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Execute a single action.
    async fn execute_single_action(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
    ) -> Result<(), GovernanceError> {
        match action.action_type {
            LifecycleActionType::DisableAccess => self.execute_disable_access(context).await,
            LifecycleActionType::EnableAccess => self.execute_enable_access(context).await,
            LifecycleActionType::RevokeSessions => self.execute_revoke_sessions(context).await,
            LifecycleActionType::NotifyManager => {
                self.execute_notify_manager(context, action).await
            }
            LifecycleActionType::ScheduleAccessReview => {
                self.execute_schedule_access_review(context, action).await
            }
            LifecycleActionType::AnonymizeData => self.execute_anonymize_data(context).await,
            LifecycleActionType::SendNotification => {
                self.execute_send_notification(context, action).await
            }
            LifecycleActionType::Webhook => self.execute_webhook(context, action).await,
        }
    }

    /// T030: Disable user access (set user.is_active = false).
    async fn execute_disable_access(
        &self,
        context: &ActionExecutionContext,
    ) -> Result<(), GovernanceError> {
        sqlx::query(
            r"
            UPDATE users
            SET is_active = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(context.object_id)
        .bind(context.tenant_id)
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T031: Enable user access (set user.is_active = true).
    async fn execute_enable_access(
        &self,
        context: &ActionExecutionContext,
    ) -> Result<(), GovernanceError> {
        sqlx::query(
            r"
            UPDATE users
            SET is_active = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(context.object_id)
        .bind(context.tenant_id)
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T032: Revoke all active sessions for the user.
    async fn execute_revoke_sessions(
        &self,
        context: &ActionExecutionContext,
    ) -> Result<(), GovernanceError> {
        sqlx::query(
            r"
            DELETE FROM sessions
            WHERE user_id = $1 AND tenant_id = $2
            ",
        )
        .bind(context.object_id)
        .bind(context.tenant_id)
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T033: Notify the user's manager.
    async fn execute_notify_manager(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
    ) -> Result<(), GovernanceError> {
        // Get the user's manager_id
        let manager_id: Option<Option<Uuid>> = sqlx::query_scalar(
            r"
            SELECT manager_id FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(context.object_id)
        .bind(context.tenant_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        let Some(Some(manager_id)) = manager_id else {
            // No manager to notify - this is not an error
            return Ok(());
        };

        // Create a notification record
        let template = action
            .config
            .get("template")
            .and_then(|v| v.as_str())
            .unwrap_or("lifecycle_state_change");

        sqlx::query(
            r"
            INSERT INTO notifications (tenant_id, user_id, type, title, message, created_at)
            VALUES ($1, $2, 'lifecycle_notification', $3, $4, NOW())
            ",
        )
        .bind(context.tenant_id)
        .bind(manager_id)
        .bind(template)
        .bind(format!(
            "User {} lifecycle state changed",
            context.object_id
        ))
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T034: Schedule an access review (micro-certification).
    async fn execute_schedule_access_review(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
    ) -> Result<(), GovernanceError> {
        let deadline_days = action
            .config
            .get("deadline_days")
            .and_then(|v| v.as_i64())
            .unwrap_or(7);

        let scope = action
            .config
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or("all_entitlements");

        // Create a micro-certification for the user
        sqlx::query(
            r"
            INSERT INTO gov_micro_certifications (
                tenant_id, user_id, trigger_type, scope,
                deadline_at, status, created_at
            )
            VALUES ($1, $2, 'lifecycle_action', $3, NOW() + $4 * INTERVAL '1 day', 'pending', NOW())
            ",
        )
        .bind(context.tenant_id)
        .bind(context.object_id)
        .bind(scope)
        .bind(deadline_days as i32)
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T035: Anonymize PII data for the user.
    async fn execute_anonymize_data(
        &self,
        context: &ActionExecutionContext,
    ) -> Result<(), GovernanceError> {
        // Anonymize user PII fields
        let anonymized_email = format!("anonymized-{}@deleted.local", context.object_id);
        let anonymized_name = format!("Deleted User {}", &context.object_id.to_string()[..8]);

        sqlx::query(
            r"
            UPDATE users
            SET
                email = $3,
                name = $4,
                phone_number = NULL,
                custom_attributes = jsonb_strip_nulls(
                    custom_attributes - ARRAY['ssn', 'date_of_birth', 'address', 'phone', 'personal_email']
                ),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(context.object_id)
        .bind(context.tenant_id)
        .bind(anonymized_email)
        .bind(anonymized_name)
        .execute(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// T036: Send a notification.
    async fn execute_send_notification(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
    ) -> Result<(), GovernanceError> {
        let template = action
            .config
            .get("template")
            .and_then(|v| v.as_str())
            .unwrap_or("lifecycle_notification");

        let channel = action
            .config
            .get("channel")
            .and_then(|v| v.as_str())
            .unwrap_or("in_app");

        let recipients = action
            .config
            .get("recipients")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["user"]);

        // For each recipient type, create notification
        for recipient_type in recipients {
            let recipient_id = match recipient_type {
                "user" => Some(context.object_id),
                "manager" => sqlx::query_scalar::<_, Option<Uuid>>(
                    r"SELECT manager_id FROM users WHERE id = $1 AND tenant_id = $2",
                )
                .bind(context.object_id)
                .bind(context.tenant_id)
                .fetch_optional(self.pool.as_ref())
                .await
                .map_err(GovernanceError::Database)?
                .flatten(),
                _ => None,
            };

            if let Some(recipient_id) = recipient_id {
                sqlx::query(
                    r"
                    INSERT INTO notifications (tenant_id, user_id, type, title, message, channel, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, NOW())
                    ",
                )
                .bind(context.tenant_id)
                .bind(recipient_id)
                .bind(template)
                .bind("Lifecycle State Change")
                .bind(format!(
                    "User {} lifecycle state has changed",
                    context.object_id
                ))
                .bind(channel)
                .execute(self.pool.as_ref())
                .await
                .map_err(GovernanceError::Database)?;
            }
        }

        Ok(())
    }

    /// T037: Call an external webhook.
    async fn execute_webhook(
        &self,
        context: &ActionExecutionContext,
        action: &LifecycleAction,
    ) -> Result<(), GovernanceError> {
        let url = action
            .config
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                GovernanceError::ActionExecutionFailed("Webhook URL is required".to_string())
            })?;

        let method = action
            .config
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST");

        let timeout_seconds = action
            .config
            .get("timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(30);

        // Build the payload
        let payload = serde_json::json!({
            "event": "lifecycle_action",
            "tenant_id": context.tenant_id,
            "object_id": context.object_id,
            "transition_audit_id": context.transition_audit_id,
            "state_id": context.state_id,
            "actor_id": context.actor_id,
            "timestamp": context.transition_started_at,
        });

        // Create HTTP client
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|e| {
                GovernanceError::ActionExecutionFailed(format!(
                    "Failed to create HTTP client: {}",
                    e
                ))
            })?;

        // Build request
        let mut request_builder = match method.to_uppercase().as_str() {
            "POST" => client.post(url),
            "PUT" => client.put(url),
            "PATCH" => client.patch(url),
            _ => {
                return Err(GovernanceError::ActionExecutionFailed(format!(
                    "Unsupported HTTP method: {}",
                    method
                )));
            }
        };

        // Add custom headers if provided
        if let Some(headers) = action.config.get("headers").and_then(|v| v.as_object()) {
            for (key, value) in headers {
                if let Some(header_value) = value.as_str() {
                    request_builder = request_builder.header(key.as_str(), header_value);
                }
            }
        }

        // Send request
        let response: reqwest::Response = request_builder
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                GovernanceError::ActionExecutionFailed(format!("Webhook request failed: {}", e))
            })?;

        // Check response status
        if !response.status().is_success() {
            return Err(GovernanceError::ActionExecutionFailed(format!(
                "Webhook returned error status: {}",
                response.status()
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // T028: Unit tests for action executor
    // =========================================================================

    #[test]
    fn test_action_execution_context_creation() {
        let context = ActionExecutionContext {
            tenant_id: Uuid::new_v4(),
            object_id: Uuid::new_v4(),
            transition_audit_id: Uuid::new_v4(),
            state_id: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
            transition_started_at: Utc::now(),
        };
        assert_ne!(context.tenant_id, context.object_id);
    }

    #[test]
    fn test_action_batch_result_all_succeeded() {
        let result = ActionBatchResult {
            results: vec![
                ActionExecutionResult {
                    action_type: LifecycleActionType::DisableAccess,
                    success: true,
                    error_message: None,
                    execution_id: Uuid::new_v4(),
                },
                ActionExecutionResult {
                    action_type: LifecycleActionType::RevokeSessions,
                    success: true,
                    error_message: None,
                    execution_id: Uuid::new_v4(),
                },
            ],
            success_count: 2,
            failure_count: 0,
            has_blocking_failure: false,
        };
        assert!(result.all_succeeded());
    }

    #[test]
    fn test_action_batch_result_with_failures() {
        let result = ActionBatchResult {
            results: vec![
                ActionExecutionResult {
                    action_type: LifecycleActionType::DisableAccess,
                    success: true,
                    error_message: None,
                    execution_id: Uuid::new_v4(),
                },
                ActionExecutionResult {
                    action_type: LifecycleActionType::Webhook,
                    success: false,
                    error_message: Some("Connection refused".to_string()),
                    execution_id: Uuid::new_v4(),
                },
            ],
            success_count: 1,
            failure_count: 1,
            has_blocking_failure: true,
        };
        assert!(!result.all_succeeded());
        assert!(result.has_blocking_failure);
    }

    #[test]
    fn test_action_batch_result_with_continue_on_failure() {
        let result = ActionBatchResult {
            results: vec![
                ActionExecutionResult {
                    action_type: LifecycleActionType::NotifyManager,
                    success: false,
                    error_message: Some("No manager found".to_string()),
                    execution_id: Uuid::new_v4(),
                },
                ActionExecutionResult {
                    action_type: LifecycleActionType::DisableAccess,
                    success: true,
                    error_message: None,
                    execution_id: Uuid::new_v4(),
                },
            ],
            success_count: 1,
            failure_count: 1,
            has_blocking_failure: false, // continue_on_failure was true
        };
        assert!(!result.all_succeeded());
        assert!(!result.has_blocking_failure);
    }

    #[test]
    fn test_action_execution_result_success() {
        let result = ActionExecutionResult {
            action_type: LifecycleActionType::EnableAccess,
            success: true,
            error_message: None,
            execution_id: Uuid::new_v4(),
        };
        assert!(result.success);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_action_execution_result_failure() {
        let result = ActionExecutionResult {
            action_type: LifecycleActionType::AnonymizeData,
            success: false,
            error_message: Some("User not found".to_string()),
            execution_id: Uuid::new_v4(),
        };
        assert!(!result.success);
        assert_eq!(result.error_message, Some("User not found".to_string()));
    }

    #[test]
    fn test_lifecycle_action_type_coverage() {
        // Ensure all action types are handled
        let action_types = vec![
            LifecycleActionType::DisableAccess,
            LifecycleActionType::EnableAccess,
            LifecycleActionType::RevokeSessions,
            LifecycleActionType::NotifyManager,
            LifecycleActionType::ScheduleAccessReview,
            LifecycleActionType::AnonymizeData,
            LifecycleActionType::SendNotification,
            LifecycleActionType::Webhook,
        ];

        // Verify all types have a display implementation
        for action_type in action_types {
            let display = action_type.to_string();
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_webhook_config_extraction() {
        let config = serde_json::json!({
            "url": "https://example.com/webhook",
            "method": "POST",
            "timeout_seconds": 60,
            "headers": {
                "Authorization": "Bearer token"
            }
        });

        let url = config.get("url").and_then(|v| v.as_str());
        assert_eq!(url, Some("https://example.com/webhook"));

        let method = config.get("method").and_then(|v| v.as_str());
        assert_eq!(method, Some("POST"));

        let timeout = config.get("timeout_seconds").and_then(|v| v.as_u64());
        assert_eq!(timeout, Some(60));
    }

    #[test]
    fn test_notification_config_extraction() {
        let config = serde_json::json!({
            "template": "user_terminated",
            "channel": "email",
            "recipients": ["user", "manager"]
        });

        let template = config.get("template").and_then(|v| v.as_str());
        assert_eq!(template, Some("user_terminated"));

        let recipients = config
            .get("recipients")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>());
        assert_eq!(recipients, Some(vec!["user", "manager"]));
    }

    #[test]
    fn test_access_review_config_extraction() {
        let config = serde_json::json!({
            "deadline_days": 14,
            "scope": "high_risk_entitlements",
            "review_type": "micro_certification"
        });

        let deadline_days = config.get("deadline_days").and_then(|v| v.as_i64());
        assert_eq!(deadline_days, Some(14));

        let scope = config.get("scope").and_then(|v| v.as_str());
        assert_eq!(scope, Some("high_risk_entitlements"));
    }
}
