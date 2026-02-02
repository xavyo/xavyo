//! Governance Role Mining Job model.
//!
//! Represents mining jobs for discovering role patterns from access data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a mining job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "mining_job_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MiningJobStatus {
    /// Job is created but not started.
    Pending,
    /// Job is currently executing.
    Running,
    /// Job completed successfully.
    Completed,
    /// Job failed with an error.
    Failed,
    /// Job was cancelled by user.
    Cancelled,
}

impl MiningJobStatus {
    /// Check if job can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if job can be cancelled.
    pub fn can_cancel(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if job is terminal (completed, failed, or cancelled).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Parameters for a mining job.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MiningJobParameters {
    /// Minimum users required to form a candidate role.
    #[serde(default = "default_min_users")]
    pub min_users: i32,

    /// Minimum entitlements in a candidate role.
    #[serde(default = "default_min_entitlements")]
    pub min_entitlements: i32,

    /// Minimum confidence score for candidates.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f64,

    /// Whether to detect excessive privileges.
    #[serde(default)]
    pub include_excessive_privilege: bool,

    /// Whether to detect role consolidation opportunities.
    #[serde(default)]
    pub include_consolidation: bool,

    /// Attribute to use for peer grouping (e.g., "department").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_group_attribute: Option<String>,

    /// Minimum overlap percentage for consolidation suggestions.
    #[serde(default = "default_consolidation_threshold")]
    pub consolidation_threshold: f64,

    /// Deviation percentage threshold for excessive privilege detection.
    #[serde(default = "default_deviation_threshold")]
    pub deviation_threshold: f64,
}

fn default_min_users() -> i32 {
    3
}
fn default_min_entitlements() -> i32 {
    2
}
fn default_confidence_threshold() -> f64 {
    0.6
}
fn default_consolidation_threshold() -> f64 {
    70.0
}
fn default_deviation_threshold() -> f64 {
    50.0
}

/// A role mining job.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovRoleMiningJob {
    /// Unique identifier for the job.
    pub id: Uuid,

    /// The tenant this job belongs to.
    pub tenant_id: Uuid,

    /// Job display name.
    pub name: String,

    /// Job status.
    pub status: MiningJobStatus,

    /// Job parameters.
    pub parameters: serde_json::Value,

    /// When job execution started.
    pub started_at: Option<DateTime<Utc>>,

    /// When job execution completed.
    pub completed_at: Option<DateTime<Utc>>,

    /// Error message if job failed.
    pub error_message: Option<String>,

    /// User who created the job.
    pub created_by: Uuid,

    /// Progress percentage (0-100).
    pub progress_percent: i32,

    /// Number of role candidates discovered.
    pub candidate_count: i32,

    /// Number of excessive privilege flags.
    pub excessive_privilege_count: i32,

    /// Number of consolidation suggestions.
    pub consolidation_suggestion_count: i32,

    /// When the job was created.
    pub created_at: DateTime<Utc>,

    /// When the job was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new mining job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateMiningJob {
    pub name: String,
    pub parameters: MiningJobParameters,
    pub created_by: Uuid,
}

/// Request to update job progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateJobProgress {
    pub progress_percent: i32,
    pub candidate_count: Option<i32>,
    pub excessive_privilege_count: Option<i32>,
    pub consolidation_suggestion_count: Option<i32>,
}

/// Filter options for listing mining jobs.
#[derive(Debug, Clone, Default)]
pub struct MiningJobFilter {
    pub status: Option<MiningJobStatus>,
    pub created_by: Option<Uuid>,
}

impl GovRoleMiningJob {
    /// Find a job by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_role_mining_jobs
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a job is running for the tenant.
    pub async fn has_running_job(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_role_mining_jobs
            WHERE tenant_id = $1 AND status = 'running'
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// List jobs for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MiningJobFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_role_mining_jobs
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovRoleMiningJob>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count jobs for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MiningJobFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_role_mining_jobs
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.created_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_by = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(created_by) = filter.created_by {
            q = q.bind(created_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new mining job.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateMiningJob,
    ) -> Result<Self, sqlx::Error> {
        let parameters =
            serde_json::to_value(&input.parameters).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r#"
            INSERT INTO gov_role_mining_jobs (tenant_id, name, parameters, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&parameters)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Start a job (set status to running).
    pub async fn start(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_mining_jobs
            SET status = 'running', started_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update job progress.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateJobProgress,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec![
            "updated_at = NOW()".to_string(),
            "progress_percent = $3".to_string(),
        ];
        let mut param_idx = 4;

        if input.candidate_count.is_some() {
            updates.push(format!("candidate_count = ${}", param_idx));
            param_idx += 1;
        }
        if input.excessive_privilege_count.is_some() {
            updates.push(format!("excessive_privilege_count = ${}", param_idx));
            param_idx += 1;
        }
        if input.consolidation_suggestion_count.is_some() {
            updates.push(format!("consolidation_suggestion_count = ${}", param_idx));
            let _ = param_idx;
        }

        let query = format!(
            "UPDATE gov_role_mining_jobs SET {} WHERE id = $1 AND tenant_id = $2 AND status = 'running' RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovRoleMiningJob>(&query)
            .bind(id)
            .bind(tenant_id)
            .bind(input.progress_percent);

        if let Some(count) = input.candidate_count {
            q = q.bind(count);
        }
        if let Some(count) = input.excessive_privilege_count {
            q = q.bind(count);
        }
        if let Some(count) = input.consolidation_suggestion_count {
            q = q.bind(count);
        }

        q.fetch_optional(pool).await
    }

    /// Complete a job successfully.
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        candidate_count: i32,
        excessive_privilege_count: i32,
        consolidation_suggestion_count: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_mining_jobs
            SET status = 'completed', completed_at = NOW(), progress_percent = 100,
                candidate_count = $3, excessive_privilege_count = $4,
                consolidation_suggestion_count = $5, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(candidate_count)
        .bind(excessive_privilege_count)
        .bind(consolidation_suggestion_count)
        .fetch_optional(pool)
        .await
    }

    /// Fail a job with an error message.
    pub async fn fail(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_mining_jobs
            SET status = 'failed', completed_at = NOW(), error_message = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a job.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_role_mining_jobs
            SET status = 'cancelled', completed_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'running')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a job (only pending or cancelled jobs can be deleted).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_role_mining_jobs
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'cancelled')
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Parse the job parameters.
    pub fn parse_parameters(&self) -> MiningJobParameters {
        serde_json::from_value(self.parameters.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mining_job_status_methods() {
        assert!(MiningJobStatus::Pending.can_start());
        assert!(!MiningJobStatus::Running.can_start());
        assert!(!MiningJobStatus::Completed.can_start());

        assert!(MiningJobStatus::Running.can_cancel());
        assert!(!MiningJobStatus::Pending.can_cancel());
        assert!(!MiningJobStatus::Completed.can_cancel());

        assert!(MiningJobStatus::Completed.is_terminal());
        assert!(MiningJobStatus::Failed.is_terminal());
        assert!(MiningJobStatus::Cancelled.is_terminal());
        assert!(!MiningJobStatus::Pending.is_terminal());
        assert!(!MiningJobStatus::Running.is_terminal());
    }

    #[test]
    fn test_mining_job_status_serialization() {
        let pending = MiningJobStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let running = MiningJobStatus::Running;
        let json = serde_json::to_string(&running).unwrap();
        assert_eq!(json, "\"running\"");
    }

    #[test]
    fn test_mining_job_parameters_defaults() {
        let params: MiningJobParameters = serde_json::from_str("{}").unwrap();
        assert_eq!(params.min_users, 3);
        assert_eq!(params.min_entitlements, 2);
        assert!((params.confidence_threshold - 0.6).abs() < f64::EPSILON);
        assert!(!params.include_excessive_privilege);
        assert!(!params.include_consolidation);
    }

    #[test]
    fn test_mining_job_parameters_parsing() {
        let json = serde_json::json!({
            "min_users": 5,
            "min_entitlements": 3,
            "confidence_threshold": 0.75,
            "include_excessive_privilege": true,
            "include_consolidation": true,
            "peer_group_attribute": "department"
        });

        let params: MiningJobParameters = serde_json::from_value(json).unwrap();
        assert_eq!(params.min_users, 5);
        assert_eq!(params.min_entitlements, 3);
        assert!((params.confidence_threshold - 0.75).abs() < f64::EPSILON);
        assert!(params.include_excessive_privilege);
        assert!(params.include_consolidation);
        assert_eq!(params.peer_group_attribute, Some("department".to_string()));
    }
}
