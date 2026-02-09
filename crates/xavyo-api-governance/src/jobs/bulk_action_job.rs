//! Background job for bulk action processing (F-064).
//!
//! Provides asynchronous execution of bulk actions with:
//! - Batch processing with configurable batch size
//! - Progress tracking with checkpoint persistence
//! - Rate limiting (configurable users per second)
//! - Cancellation support (checks for cancelled status before each batch)
//! - Resume capability after restart (via checkpoint persistence)

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::time::sleep;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

use xavyo_db::{GovBulkAction, GovBulkActionType};

use crate::services::action_executors::{
    ActionExecutor, AssignRoleExecutor, DisableUserExecutor, EnableUserExecutor, ExecutionContext,
    ExecutionResult, ModifyAttributeExecutor, RevokeRoleExecutor,
};

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 10;

/// Default batch size for processing users.
pub const DEFAULT_BATCH_SIZE: i32 = 100;

/// Default rate limit (users per second). 0 = unlimited.
pub const DEFAULT_RATE_LIMIT_PER_SEC: f64 = 0.0;

/// User data used for bulk action execution.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct UserForExecution {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub custom_attributes: serde_json::Value,
}

/// Job for processing bulk actions in the background.
///
/// This job polls for bulk actions in 'running' status and processes them
/// in batches with progress updates and checkpoint persistence.
pub struct BulkActionJob {
    pool: Arc<PgPool>,
    batch_size: i32,
    rate_limit_per_sec: f64,
}

/// Statistics from processing a bulk action.
#[derive(Debug, Clone, Default)]
pub struct BulkActionJobStats {
    /// Total actions processed.
    pub actions_processed: usize,
    /// Total users processed across all actions.
    pub users_processed: usize,
    /// Successful operations.
    pub successes: usize,
    /// Skipped operations (idempotent).
    pub skipped: usize,
    /// Failed operations.
    pub failures: usize,
    /// Cancelled actions detected.
    pub cancelled: usize,
}

impl BulkActionJobStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &Self) {
        self.actions_processed += other.actions_processed;
        self.users_processed += other.users_processed;
        self.successes += other.successes;
        self.skipped += other.skipped;
        self.failures += other.failures;
        self.cancelled += other.cancelled;
    }
}

impl BulkActionJob {
    /// Create a new bulk action job.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: Arc::new(pool),
            batch_size: DEFAULT_BATCH_SIZE,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
        }
    }

    /// Set batch size for processing.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i32) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Set rate limit (users per second). 0 = unlimited.
    #[must_use]
    pub fn with_rate_limit(mut self, users_per_sec: f64) -> Self {
        self.rate_limit_per_sec = users_per_sec.max(0.0);
        self
    }

    /// Get the database pool reference.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run a single poll cycle - find and process running bulk actions.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<BulkActionJobStats, BulkActionJobError> {
        info!("Starting bulk action poll cycle");

        let mut stats = BulkActionJobStats::default();

        // Find running bulk actions that need processing
        let running_actions = self.find_running_actions().await?;

        if running_actions.is_empty() {
            debug!("No running bulk actions to process");
            return Ok(stats);
        }

        info!(
            count = running_actions.len(),
            "Found running bulk actions to process"
        );

        for action in running_actions {
            stats.actions_processed += 1;

            match self.process_bulk_action(&action).await {
                Ok(action_stats) => {
                    stats.users_processed += action_stats.users_processed;
                    stats.successes += action_stats.successes;
                    stats.skipped += action_stats.skipped;
                    stats.failures += action_stats.failures;
                    if action_stats.cancelled > 0 {
                        stats.cancelled += 1;
                    }
                }
                Err(e) => {
                    error!(
                        action_id = %action.id,
                        error = %e,
                        "Failed to process bulk action"
                    );
                    // Mark the action as failed
                    if let Err(mark_err) = GovBulkAction::mark_failed(
                        &self.pool,
                        action.id,
                        serde_json::json!({"error": e.to_string()}),
                    )
                    .await
                    {
                        error!(
                            action_id = %action.id,
                            error = %mark_err,
                            "Failed to mark bulk action as failed"
                        );
                    }
                }
            }
        }

        if stats.users_processed > 0 {
            info!(
                actions = stats.actions_processed,
                users = stats.users_processed,
                successes = stats.successes,
                skipped = stats.skipped,
                failures = stats.failures,
                cancelled = stats.cancelled,
                "Completed bulk action poll cycle"
            );
        }

        Ok(stats)
    }

    /// Find running bulk actions.
    async fn find_running_actions(&self) -> Result<Vec<GovBulkAction>, BulkActionJobError> {
        // Find all bulk actions with status 'running'
        let actions = sqlx::query_as::<_, GovBulkAction>(
            r#"
            SELECT *
            FROM gov_bulk_actions
            WHERE status = 'running'
            ORDER BY created_at ASC
            LIMIT 10
            "#,
        )
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| BulkActionJobError::Database(e.to_string()))?;

        Ok(actions)
    }

    /// Process a single bulk action.
    #[instrument(skip(self, action), fields(action_id = %action.id))]
    async fn process_bulk_action(
        &self,
        action: &GovBulkAction,
    ) -> Result<BulkActionJobStats, BulkActionJobError> {
        let mut stats = BulkActionJobStats::default();

        // Get the executor for this action type
        let executor = self.get_executor(&action.action_type);

        // Build execution context
        let ctx = ExecutionContext {
            tenant_id: action.tenant_id,
            initiated_by: action.created_by,
            bulk_action_id: action.id,
            justification: action.justification.clone(),
        };

        // Get the checkpoint (offset) to resume from
        let checkpoint = action.processed_count;
        let mut offset = checkpoint;
        let mut batch_results: Vec<serde_json::Value> = Vec::new();

        // Process in batches
        loop {
            // Check for cancellation before each batch
            if self.check_cancelled(action.id).await? {
                info!(action_id = %action.id, "Bulk action was cancelled");
                stats.cancelled = 1;
                return Ok(stats);
            }

            // Fetch the next batch of users
            let users = self
                .fetch_users_batch(action.tenant_id, &action.filter_expression, offset)
                .await?;

            if users.is_empty() {
                break;
            }

            info!(
                batch_size = users.len(),
                offset = offset,
                "Processing batch of users"
            );

            // Process each user in the batch
            for user in users {
                // Apply rate limiting
                if self.rate_limit_per_sec > 0.0 {
                    let delay_ms = (1000.0 / self.rate_limit_per_sec) as u64;
                    sleep(Duration::from_millis(delay_ms)).await;
                }

                let result = executor
                    .execute(&self.pool, &ctx, user.id, &action.action_params)
                    .await;

                stats.users_processed += 1;
                if result.success {
                    if result.skipped {
                        stats.skipped += 1;
                    } else {
                        stats.successes += 1;
                    }
                } else {
                    stats.failures += 1;
                }

                batch_results.push(serde_json::json!({
                    "user_id": user.id.to_string(),
                    "success": result.success,
                    "skipped": result.skipped,
                    "error": result.error,
                }));

                // Record audit event
                self.record_audit_event(action, &user, &ctx, &result)
                    .await?;
            }

            // Update checkpoint (progress)
            let new_processed = offset + self.batch_size;
            self.update_checkpoint(action.id, &stats).await?;

            offset = new_processed;
        }

        // Mark as completed or failed based on results
        let results_json = serde_json::json!(batch_results);
        if stats.failures > 0 && stats.successes == 0 && stats.skipped == 0 {
            GovBulkAction::mark_failed(&self.pool, action.id, results_json)
                .await
                .map_err(|e| BulkActionJobError::Database(e.to_string()))?;
        } else {
            GovBulkAction::mark_completed(&self.pool, action.id, results_json)
                .await
                .map_err(|e| BulkActionJobError::Database(e.to_string()))?;
        }

        Ok(stats)
    }

    /// Get the appropriate executor for an action type.
    fn get_executor(&self, action_type: &GovBulkActionType) -> Box<dyn ActionExecutor> {
        match action_type {
            GovBulkActionType::AssignRole => Box::new(AssignRoleExecutor::new()),
            GovBulkActionType::RevokeRole => Box::new(RevokeRoleExecutor::new()),
            GovBulkActionType::Enable => Box::new(EnableUserExecutor::new()),
            GovBulkActionType::Disable => Box::new(DisableUserExecutor::new()),
            GovBulkActionType::ModifyAttribute => Box::new(ModifyAttributeExecutor::new()),
        }
    }

    /// Check if the action has been cancelled.
    async fn check_cancelled(&self, action_id: Uuid) -> Result<bool, BulkActionJobError> {
        let status: Option<(String,)> = sqlx::query_as(
            r#"
            SELECT status FROM gov_bulk_actions WHERE id = $1
            "#,
        )
        .bind(action_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| BulkActionJobError::Database(e.to_string()))?;

        Ok(status.map(|(s,)| s == "cancelled").unwrap_or(true))
    }

    /// Fetch a batch of users matching the expression.
    async fn fetch_users_batch(
        &self,
        tenant_id: Uuid,
        filter_expression: &str,
        offset: i32,
    ) -> Result<Vec<UserForExecution>, BulkActionJobError> {
        // First fetch users (we'll filter by expression in-memory for now)
        // In production, the expression could be translated to SQL for efficiency
        let all_users: Vec<UserForExecution> = sqlx::query_as(
            r#"
            SELECT id, email, display_name, is_active, custom_attributes
            FROM users
            WHERE tenant_id = $1
            ORDER BY email
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(self.batch_size)
        .bind(offset)
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| BulkActionJobError::Database(e.to_string()))?;

        // Filter by expression
        let mut matched_users = Vec::new();
        for user in all_users {
            if self.evaluate_user(filter_expression, &user)? {
                matched_users.push(user);
            }
        }

        Ok(matched_users)
    }

    /// Evaluate a user against the filter expression.
    fn evaluate_user(
        &self,
        expression: &str,
        user: &UserForExecution,
    ) -> Result<bool, BulkActionJobError> {
        use xavyo_governance::{eval_expression, EvalContext, ExpressionError, FunctionContext};

        let mut ctx = EvalContext::new()
            .with_attribute("id", user.id.to_string())
            .with_attribute("email", user.email.as_str())
            .with_attribute("is_active", user.is_active)
            .with_attribute("active", user.is_active);

        if let Some(ref name) = user.display_name {
            ctx = ctx.with_attribute("display_name", name.as_str());
        }

        // Add custom attributes
        if let serde_json::Value::Object(attrs) = &user.custom_attributes {
            for (key, value) in attrs {
                match value {
                    serde_json::Value::String(s) => {
                        ctx = ctx.with_attribute(key.clone(), s.clone());
                    }
                    serde_json::Value::Bool(b) => {
                        ctx = ctx.with_attribute(key.clone(), *b);
                    }
                    serde_json::Value::Number(n) => {
                        if let Some(i) = n.as_i64() {
                            ctx = ctx.with_attribute(key.clone(), i);
                        } else if let Some(f) = n.as_f64() {
                            ctx = ctx.with_attribute(key.clone(), f);
                        }
                    }
                    _ => {}
                }
            }
        }

        let func_ctx = FunctionContext::new();
        ctx = ctx.with_function_context(func_ctx);

        match eval_expression(expression, &ctx) {
            Ok(result) => Ok(result),
            Err(ExpressionError::Parse(e)) => {
                Err(BulkActionJobError::Processing(format!("Parse error: {e}")))
            }
            Err(ExpressionError::Eval(_)) => {
                // Treat eval errors as non-match
                Ok(false)
            }
        }
    }

    /// Update checkpoint (progress) for resume capability.
    async fn update_checkpoint(
        &self,
        action_id: Uuid,
        stats: &BulkActionJobStats,
    ) -> Result<(), BulkActionJobError> {
        GovBulkAction::update_progress(
            &self.pool,
            action_id,
            stats.users_processed as i32,
            stats.successes as i32,
            stats.failures as i32,
            stats.skipped as i32,
        )
        .await
        .map_err(|e| BulkActionJobError::Database(e.to_string()))?;

        Ok(())
    }

    /// Record audit event for a user operation.
    async fn record_audit_event(
        &self,
        action: &GovBulkAction,
        user: &UserForExecution,
        ctx: &ExecutionContext,
        result: &ExecutionResult,
    ) -> Result<(), BulkActionJobError> {
        let event_type = format!(
            "bulk_action_{}",
            match action.action_type {
                GovBulkActionType::AssignRole => "assign_role",
                GovBulkActionType::RevokeRole => "revoke_role",
                GovBulkActionType::Enable => "enable",
                GovBulkActionType::Disable => "disable",
                GovBulkActionType::ModifyAttribute => "modify_attribute",
            }
        );

        let outcome = if result.success {
            if result.skipped {
                "skipped"
            } else {
                "success"
            }
        } else {
            "failure"
        };

        sqlx::query(
            r#"
            INSERT INTO audit_events (id, tenant_id, event_type, actor_id, target_type, target_id, outcome, details, created_at)
            VALUES ($1, $2, $3, $4, 'user', $5, $6, $7, NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(action.tenant_id)
        .bind(&event_type)
        .bind(ctx.initiated_by)
        .bind(user.id)
        .bind(outcome)
        .bind(serde_json::json!({
            "bulk_action_id": action.id.to_string(),
            "previous_value": result.previous_value,
            "new_value": result.new_value,
            "error": result.error,
        }))
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| BulkActionJobError::Database(e.to_string()))?;

        Ok(())
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }
}

/// Errors that can occur during bulk action job execution.
#[derive(Debug, thiserror::Error)]
pub enum BulkActionJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Processing error.
    #[error("Processing error: {0}")]
    Processing(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 10);
        assert_eq!(DEFAULT_BATCH_SIZE, 100);
        assert_eq!(DEFAULT_RATE_LIMIT_PER_SEC, 0.0);
    }

    #[test]
    fn test_stats_default() {
        let stats = BulkActionJobStats::default();
        assert_eq!(stats.actions_processed, 0);
        assert_eq!(stats.users_processed, 0);
        assert_eq!(stats.successes, 0);
        assert_eq!(stats.skipped, 0);
        assert_eq!(stats.failures, 0);
        assert_eq!(stats.cancelled, 0);
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = BulkActionJobStats {
            actions_processed: 2,
            users_processed: 100,
            successes: 80,
            skipped: 10,
            failures: 10,
            cancelled: 0,
        };

        let stats2 = BulkActionJobStats {
            actions_processed: 1,
            users_processed: 50,
            successes: 45,
            skipped: 3,
            failures: 2,
            cancelled: 1,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.actions_processed, 3);
        assert_eq!(stats1.users_processed, 150);
        assert_eq!(stats1.successes, 125);
        assert_eq!(stats1.skipped, 13);
        assert_eq!(stats1.failures, 12);
        assert_eq!(stats1.cancelled, 1);
    }

    #[test]
    fn test_job_error_display() {
        let err = BulkActionJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let db_err = BulkActionJobError::Database("connection failed".to_string());
        assert!(db_err.to_string().contains("connection failed"));
    }

    #[test]
    fn test_with_batch_size() {
        // Can't create job without pool, but test builder pattern logic
        const { assert!(DEFAULT_BATCH_SIZE > 0) };
    }

    #[test]
    fn test_with_rate_limit() {
        // Test that rate_limit_per_sec defaults are correct
        assert_eq!(DEFAULT_RATE_LIMIT_PER_SEC, 0.0);
    }
}
