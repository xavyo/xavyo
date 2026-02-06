//! Governance Bulk Action model.
//!
//! Expression-based bulk actions for mass operations on identities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Type of bulk action to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_bulk_action_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum BulkActionType {
    /// Assign a role to matched users.
    AssignRole,
    /// Revoke a role from matched users.
    RevokeRole,
    /// Enable matched user accounts.
    Enable,
    /// Disable matched user accounts.
    Disable,
    /// Modify an attribute on matched users.
    ModifyAttribute,
}

impl std::fmt::Display for BulkActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkActionType::AssignRole => write!(f, "assign_role"),
            BulkActionType::RevokeRole => write!(f, "revoke_role"),
            BulkActionType::Enable => write!(f, "enable"),
            BulkActionType::Disable => write!(f, "disable"),
            BulkActionType::ModifyAttribute => write!(f, "modify_attribute"),
        }
    }
}

/// Status of a bulk action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_bulk_action_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BulkActionStatus {
    /// Action is pending execution.
    Pending,
    /// Action is currently being executed.
    Running,
    /// Action completed successfully.
    Completed,
    /// Action failed (all operations failed).
    Failed,
    /// Action was cancelled.
    Cancelled,
}

impl std::fmt::Display for BulkActionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BulkActionStatus::Pending => write!(f, "pending"),
            BulkActionStatus::Running => write!(f, "running"),
            BulkActionStatus::Completed => write!(f, "completed"),
            BulkActionStatus::Failed => write!(f, "failed"),
            BulkActionStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// A governance bulk action for mass operations on identities.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovBulkAction {
    /// Unique identifier for the action.
    pub id: Uuid,

    /// The tenant this action belongs to.
    pub tenant_id: Uuid,

    /// SQL-like filter expression.
    pub filter_expression: String,

    /// Type of action to perform.
    pub action_type: BulkActionType,

    /// Action-specific parameters (e.g., role_id, attribute_name).
    pub action_params: JsonValue,

    /// Current status of the action.
    pub status: BulkActionStatus,

    /// Audit justification for the action.
    pub justification: String,

    /// Total number of users matching the filter.
    pub total_matched: i32,

    /// Number of users processed so far.
    pub processed_count: i32,

    /// Number of successful operations.
    pub success_count: i32,

    /// Number of failed operations.
    pub failure_count: i32,

    /// Number of skipped operations (no change needed).
    pub skipped_count: i32,

    /// Per-user results with errors.
    pub results: Option<JsonValue>,

    /// User who created the action.
    pub created_by: Uuid,

    /// When the action was created.
    pub created_at: DateTime<Utc>,

    /// When processing started.
    pub started_at: Option<DateTime<Utc>>,

    /// When processing completed.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request to create a new bulk action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovBulkAction {
    /// SQL-like filter expression.
    pub filter_expression: String,
    /// Type of action to perform.
    pub action_type: BulkActionType,
    /// Action-specific parameters.
    pub action_params: JsonValue,
    /// Audit justification (minimum 10 characters).
    pub justification: String,
    /// User creating the action.
    pub created_by: Uuid,
}

/// Request to update a bulk action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovBulkAction {
    pub status: Option<BulkActionStatus>,
    pub total_matched: Option<i32>,
    pub processed_count: Option<i32>,
    pub success_count: Option<i32>,
    pub failure_count: Option<i32>,
    pub skipped_count: Option<i32>,
    pub results: Option<JsonValue>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Filter options for listing bulk actions.
#[derive(Debug, Clone, Default)]
pub struct BulkActionFilter {
    pub status: Option<BulkActionStatus>,
    pub action_type: Option<BulkActionType>,
    pub created_by: Option<Uuid>,
}

/// Result for a single user in a bulk action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkActionResultItem {
    pub user_id: Uuid,
    pub success: bool,
    pub skipped: bool,
    pub error: Option<String>,
}

/// Progress information for a bulk action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkActionProgress {
    pub total_matched: i32,
    pub processed_count: i32,
    pub success_count: i32,
    pub failure_count: i32,
    pub skipped_count: i32,
    pub progress_percent: u8,
}

/// Maximum number of users per bulk action.
pub const MAX_BULK_ACTION_SIZE: i32 = 100_000;

/// Minimum justification length.
pub const MIN_JUSTIFICATION_LENGTH: usize = 10;

impl GovBulkAction {
    /// Find a bulk action by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_bulk_actions
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pending or running actions that need processing (background job).
    pub async fn find_pending_or_running(
        pool: &sqlx::PgPool,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_bulk_actions
            WHERE status IN ('pending', 'running')
            ORDER BY created_at ASC
            LIMIT $1
            ",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List bulk actions for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BulkActionFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_bulk_actions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_num}"));
            param_num += 1;
        }

        if filter.created_by.is_some() {
            query.push_str(&format!(" AND created_by = ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(action_type) = &filter.action_type {
            db_query = db_query.bind(action_type);
        }

        if let Some(created_by) = filter.created_by {
            db_query = db_query.bind(created_by);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count bulk actions for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BulkActionFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_bulk_actions
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.action_type.is_some() {
            query.push_str(&format!(" AND action_type = ${param_num}"));
            param_num += 1;
        }

        if filter.created_by.is_some() {
            query.push_str(&format!(" AND created_by = ${param_num}"));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(action_type) = &filter.action_type {
            db_query = db_query.bind(action_type);
        }

        if let Some(created_by) = filter.created_by {
            db_query = db_query.bind(created_by);
        }

        db_query.fetch_one(pool).await
    }

    /// Count active (pending or running) actions for a tenant.
    pub async fn count_active(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_bulk_actions
            WHERE tenant_id = $1 AND status IN ('pending', 'running')
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new bulk action.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovBulkAction,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_bulk_actions (
                tenant_id, filter_expression, action_type, action_params,
                justification, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.filter_expression)
        .bind(input.action_type)
        .bind(&input.action_params)
        .bind(&input.justification)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Update a bulk action.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovBulkAction,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_bulk_actions
            SET
                status = COALESCE($3, status),
                total_matched = COALESCE($4, total_matched),
                processed_count = COALESCE($5, processed_count),
                success_count = COALESCE($6, success_count),
                failure_count = COALESCE($7, failure_count),
                skipped_count = COALESCE($8, skipped_count),
                results = COALESCE($9, results),
                started_at = COALESCE($10, started_at),
                completed_at = COALESCE($11, completed_at)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.total_matched)
        .bind(input.processed_count)
        .bind(input.success_count)
        .bind(input.failure_count)
        .bind(input.skipped_count)
        .bind(&input.results)
        .bind(input.started_at)
        .bind(input.completed_at)
        .fetch_optional(pool)
        .await
    }

    /// Set total matched users after preview.
    pub async fn set_total_matched(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        total_matched: i32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_actions
            SET total_matched = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(total_matched)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark action as running.
    pub async fn mark_running(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_actions
            SET status = 'running', started_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update progress counters.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        id: Uuid,
        processed_count: i32,
        success_count: i32,
        failure_count: i32,
        skipped_count: i32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_actions
            SET processed_count = $2, success_count = $3, failure_count = $4, skipped_count = $5
            WHERE id = $1 AND status = 'running'
            ",
        )
        .bind(id)
        .bind(processed_count)
        .bind(success_count)
        .bind(failure_count)
        .bind(skipped_count)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark action as completed.
    pub async fn mark_completed(
        pool: &sqlx::PgPool,
        id: Uuid,
        results: JsonValue,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_actions
            SET status = 'completed', results = $2, completed_at = NOW()
            WHERE id = $1 AND status = 'running'
            ",
        )
        .bind(id)
        .bind(&results)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark action as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        id: Uuid,
        results: JsonValue,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_actions
            SET status = 'failed', results = $2, completed_at = NOW()
            WHERE id = $1 AND status IN ('pending', 'running')
            ",
        )
        .bind(id)
        .bind(&results)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Cancel a pending or running action.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_bulk_actions
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'running')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a bulk action (only for completed, failed, or cancelled).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_bulk_actions
            WHERE id = $1 AND tenant_id = $2 AND status IN ('completed', 'failed', 'cancelled')
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get the progress of an action.
    #[must_use]
    pub fn get_progress(&self) -> BulkActionProgress {
        let progress_percent = if self.total_matched > 0 {
            ((f64::from(self.processed_count) / f64::from(self.total_matched)) * 100.0) as u8
        } else {
            0
        };

        BulkActionProgress {
            total_matched: self.total_matched,
            processed_count: self.processed_count,
            success_count: self.success_count,
            failure_count: self.failure_count,
            skipped_count: self.skipped_count,
            progress_percent,
        }
    }

    /// Check if the action can be executed.
    #[must_use]
    pub fn can_execute(&self) -> bool {
        self.status == BulkActionStatus::Pending
    }

    /// Check if the action can be cancelled.
    #[must_use]
    pub fn can_cancel(&self) -> bool {
        matches!(
            self.status,
            BulkActionStatus::Pending | BulkActionStatus::Running
        )
    }

    /// Check if the action can be deleted.
    #[must_use]
    pub fn can_delete(&self) -> bool {
        matches!(
            self.status,
            BulkActionStatus::Completed | BulkActionStatus::Failed | BulkActionStatus::Cancelled
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bulk_action_type_display() {
        assert_eq!(BulkActionType::AssignRole.to_string(), "assign_role");
        assert_eq!(BulkActionType::RevokeRole.to_string(), "revoke_role");
        assert_eq!(BulkActionType::Enable.to_string(), "enable");
        assert_eq!(BulkActionType::Disable.to_string(), "disable");
        assert_eq!(
            BulkActionType::ModifyAttribute.to_string(),
            "modify_attribute"
        );
    }

    #[test]
    fn test_bulk_action_status_display() {
        assert_eq!(BulkActionStatus::Pending.to_string(), "pending");
        assert_eq!(BulkActionStatus::Running.to_string(), "running");
        assert_eq!(BulkActionStatus::Completed.to_string(), "completed");
        assert_eq!(BulkActionStatus::Failed.to_string(), "failed");
        assert_eq!(BulkActionStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_progress_calculation() {
        let action = GovBulkAction {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            filter_expression: "department = 'engineering'".to_string(),
            action_type: BulkActionType::AssignRole,
            action_params: serde_json::json!({"role_id": Uuid::new_v4()}),
            status: BulkActionStatus::Running,
            justification: "Test justification for bulk action".to_string(),
            total_matched: 100,
            processed_count: 50,
            success_count: 48,
            failure_count: 2,
            skipped_count: 0,
            results: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: None,
        };

        let progress = action.get_progress();
        assert_eq!(progress.total_matched, 100);
        assert_eq!(progress.processed_count, 50);
        assert_eq!(progress.success_count, 48);
        assert_eq!(progress.failure_count, 2);
        assert_eq!(progress.progress_percent, 50);
    }

    #[test]
    fn test_progress_zero_total() {
        let action = GovBulkAction {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            filter_expression: "invalid_filter".to_string(),
            action_type: BulkActionType::Enable,
            action_params: serde_json::json!({}),
            status: BulkActionStatus::Pending,
            justification: "Test justification for bulk action".to_string(),
            total_matched: 0,
            processed_count: 0,
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            results: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        let progress = action.get_progress();
        assert_eq!(progress.progress_percent, 0);
    }

    #[test]
    fn test_can_execute() {
        let mut action = GovBulkAction {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            filter_expression: "test".to_string(),
            action_type: BulkActionType::Enable,
            action_params: serde_json::json!({}),
            status: BulkActionStatus::Pending,
            justification: "Test justification".to_string(),
            total_matched: 0,
            processed_count: 0,
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            results: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        assert!(action.can_execute());

        action.status = BulkActionStatus::Running;
        assert!(!action.can_execute());

        action.status = BulkActionStatus::Completed;
        assert!(!action.can_execute());
    }

    #[test]
    fn test_can_cancel() {
        let mut action = GovBulkAction {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            filter_expression: "test".to_string(),
            action_type: BulkActionType::Enable,
            action_params: serde_json::json!({}),
            status: BulkActionStatus::Pending,
            justification: "Test justification".to_string(),
            total_matched: 0,
            processed_count: 0,
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            results: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        assert!(action.can_cancel());

        action.status = BulkActionStatus::Running;
        assert!(action.can_cancel());

        action.status = BulkActionStatus::Completed;
        assert!(!action.can_cancel());

        action.status = BulkActionStatus::Cancelled;
        assert!(!action.can_cancel());
    }

    #[test]
    fn test_can_delete() {
        let mut action = GovBulkAction {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            filter_expression: "test".to_string(),
            action_type: BulkActionType::Enable,
            action_params: serde_json::json!({}),
            status: BulkActionStatus::Pending,
            justification: "Test justification".to_string(),
            total_matched: 0,
            processed_count: 0,
            success_count: 0,
            failure_count: 0,
            skipped_count: 0,
            results: None,
            created_by: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        assert!(!action.can_delete());

        action.status = BulkActionStatus::Running;
        assert!(!action.can_delete());

        action.status = BulkActionStatus::Completed;
        assert!(action.can_delete());

        action.status = BulkActionStatus::Failed;
        assert!(action.can_delete());

        action.status = BulkActionStatus::Cancelled;
        assert!(action.can_delete());
    }
}
