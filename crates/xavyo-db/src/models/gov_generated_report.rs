//! Governance Generated Report model.
//!
//! Represents immutable instances of generated compliance reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of report generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_report_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Queued for generation.
    Pending,
    /// Currently generating.
    Generating,
    /// Successfully generated.
    Completed,
    /// Generation failed.
    Failed,
}

impl ReportStatus {
    /// Check if the report is complete.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Check if the report is in progress.
    #[must_use]
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Pending | Self::Generating)
    }

    /// Check if the report failed.
    #[must_use]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Check if the report is final (no more changes expected).
    #[must_use]
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

/// Output format for reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_output_format", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// JSON format.
    Json,
    /// CSV format.
    Csv,
}

impl OutputFormat {
    /// Get the MIME type for this format.
    #[must_use]
    pub fn mime_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Csv => "text/csv",
        }
    }

    /// Get the file extension for this format.
    #[must_use]
    pub fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

/// A generated compliance report.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovGeneratedReport {
    /// Unique identifier for the report.
    pub id: Uuid,

    /// The tenant this report belongs to.
    pub tenant_id: Uuid,

    /// Reference to template used.
    pub template_id: Uuid,

    /// Copy of template definition at generation time.
    pub template_snapshot: serde_json::Value,

    /// Report name (auto-generated or custom).
    pub name: String,

    /// Generation status.
    pub status: ReportStatus,

    /// Parameters used for generation.
    pub parameters: serde_json::Value,

    /// Report output data (for small reports).
    pub output_data: Option<serde_json::Value>,

    /// File path for large reports.
    pub output_file_path: Option<String>,

    /// Output format (json or csv).
    pub output_format: OutputFormat,

    /// Number of records in report.
    pub record_count: Option<i32>,

    /// Size of generated output in bytes.
    pub file_size_bytes: Option<i64>,

    /// Error details if failed.
    pub error_message: Option<String>,

    /// Generation progress (0-100).
    pub progress_percent: i32,

    /// When generation started.
    pub started_at: Option<DateTime<Utc>>,

    /// When generation completed.
    pub completed_at: Option<DateTime<Utc>>,

    /// User who generated the report.
    pub generated_by: Uuid,

    /// Reference to schedule if auto-generated.
    pub schedule_id: Option<Uuid>,

    /// When report can be deleted.
    pub retention_until: DateTime<Utc>,

    /// When the report was created.
    pub created_at: DateTime<Utc>,
}

/// Request to generate a new report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateReportRequest {
    pub template_id: Uuid,
    pub name: Option<String>,
    pub parameters: Option<serde_json::Value>,
    pub output_format: OutputFormat,
    pub generated_by: Uuid,
    pub schedule_id: Option<Uuid>,
}

/// Filter options for listing generated reports.
#[derive(Debug, Clone, Default)]
pub struct GeneratedReportFilter {
    pub template_id: Option<Uuid>,
    pub status: Option<ReportStatus>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub generated_by: Option<Uuid>,
    pub schedule_id: Option<Uuid>,
}

/// Default retention period in years.
pub const DEFAULT_RETENTION_YEARS: i32 = 7;

impl GovGeneratedReport {
    /// Find a report by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_generated_reports
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List reports for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GeneratedReportFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_generated_reports
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.generated_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND generated_by = ${param_count}"));
        }
        if filter.schedule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND schedule_id = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovGeneratedReport>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(generated_by) = filter.generated_by {
            q = q.bind(generated_by);
        }
        if let Some(schedule_id) = filter.schedule_id {
            q = q.bind(schedule_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count reports for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GeneratedReportFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_generated_reports
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.template_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }
        if filter.generated_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND generated_by = ${param_count}"));
        }
        if filter.schedule_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND schedule_id = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }
        if let Some(generated_by) = filter.generated_by {
            q = q.bind(generated_by);
        }
        if let Some(schedule_id) = filter.schedule_id {
            q = q.bind(schedule_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new report generation request.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        template_snapshot: serde_json::Value,
        input: GenerateReportRequest,
    ) -> Result<Self, sqlx::Error> {
        let name = input
            .name
            .unwrap_or_else(|| format!("Report {}", Utc::now().format("%Y-%m-%d %H:%M:%S")));
        let parameters = input.parameters.unwrap_or_else(|| serde_json::json!({}));
        let retention_until =
            Utc::now() + chrono::Duration::days(365 * i64::from(DEFAULT_RETENTION_YEARS));

        sqlx::query_as(
            r"
            INSERT INTO gov_generated_reports (
                tenant_id, template_id, template_snapshot, name, status,
                parameters, output_format, generated_by, schedule_id, retention_until
            )
            VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.template_id)
        .bind(&template_snapshot)
        .bind(&name)
        .bind(&parameters)
        .bind(input.output_format)
        .bind(input.generated_by)
        .bind(input.schedule_id)
        .bind(retention_until)
        .fetch_one(pool)
        .await
    }

    /// Start report generation.
    pub async fn start_generation(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_generated_reports
            SET status = 'generating', started_at = NOW(), progress_percent = 0
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update generation progress.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        progress_percent: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_generated_reports
            SET progress_percent = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'generating'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(progress_percent.clamp(0, 100))
        .fetch_optional(pool)
        .await
    }

    /// Complete report generation with inline data.
    pub async fn complete_with_data(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        output_data: serde_json::Value,
        record_count: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        let file_size = serde_json::to_string(&output_data)
            .map(|s| s.len() as i64)
            .unwrap_or(0);

        sqlx::query_as(
            r"
            UPDATE gov_generated_reports
            SET status = 'completed', completed_at = NOW(), progress_percent = 100,
                output_data = $3, record_count = $4, file_size_bytes = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'generating'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&output_data)
        .bind(record_count)
        .bind(file_size)
        .fetch_optional(pool)
        .await
    }

    /// Complete report generation with file path.
    pub async fn complete_with_file(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        file_path: &str,
        record_count: i32,
        file_size_bytes: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_generated_reports
            SET status = 'completed', completed_at = NOW(), progress_percent = 100,
                output_file_path = $3, record_count = $4, file_size_bytes = $5
            WHERE id = $1 AND tenant_id = $2 AND status = 'generating'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(file_path)
        .bind(record_count)
        .bind(file_size_bytes)
        .fetch_optional(pool)
        .await
    }

    /// Mark report generation as failed.
    pub async fn fail(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_generated_reports
            SET status = 'failed', completed_at = NOW(), error_message = $3
            WHERE id = $1 AND tenant_id = $2 AND status IN ('pending', 'generating')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Delete expired reports.
    pub async fn delete_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_generated_reports
            WHERE retention_until < NOW() AND status = 'completed'
            ",
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if the report can be downloaded.
    #[must_use]
    pub fn can_download(&self) -> bool {
        self.status.is_completed()
            && (self.output_data.is_some() || self.output_file_path.is_some())
    }

    /// Get the generation duration in seconds.
    #[must_use]
    pub fn generation_duration_secs(&self) -> Option<i64> {
        match (self.started_at, self.completed_at) {
            (Some(started), Some(completed)) => Some((completed - started).num_seconds()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_status_methods() {
        assert!(ReportStatus::Completed.is_completed());
        assert!(!ReportStatus::Pending.is_completed());

        assert!(ReportStatus::Pending.is_in_progress());
        assert!(ReportStatus::Generating.is_in_progress());
        assert!(!ReportStatus::Completed.is_in_progress());

        assert!(ReportStatus::Failed.is_failed());
        assert!(!ReportStatus::Completed.is_failed());

        assert!(ReportStatus::Completed.is_final());
        assert!(ReportStatus::Failed.is_final());
        assert!(!ReportStatus::Generating.is_final());
    }

    #[test]
    fn test_output_format_mime_types() {
        assert_eq!(OutputFormat::Json.mime_type(), "application/json");
        assert_eq!(OutputFormat::Csv.mime_type(), "text/csv");
    }

    #[test]
    fn test_output_format_extensions() {
        assert_eq!(OutputFormat::Json.extension(), "json");
        assert_eq!(OutputFormat::Csv.extension(), "csv");
    }

    #[test]
    fn test_report_status_serialization() {
        let pending = ReportStatus::Pending;
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(json, "\"pending\"");

        let completed = ReportStatus::Completed;
        let json = serde_json::to_string(&completed).unwrap();
        assert_eq!(json, "\"completed\"");
    }

    #[test]
    fn test_output_format_serialization() {
        let json_format = OutputFormat::Json;
        let json = serde_json::to_string(&json_format).unwrap();
        assert_eq!(json, "\"json\"");

        let csv_format = OutputFormat::Csv;
        let json = serde_json::to_string(&csv_format).unwrap();
        assert_eq!(json, "\"csv\"");
    }
}
