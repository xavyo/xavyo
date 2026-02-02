//! Report generation service for compliance reporting.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    GenerateReportRequest, GeneratedReportFilter, GovGeneratedReport, GovReportTemplate,
    OutputFormat, ReportStatus,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for report generation operations.
pub struct ReportService {
    pool: PgPool,
}

impl ReportService {
    /// Create a new report service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a generated report by ID.
    pub async fn get(&self, tenant_id: Uuid, report_id: Uuid) -> Result<GovGeneratedReport> {
        GovGeneratedReport::find_by_id(&self.pool, tenant_id, report_id)
            .await?
            .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// List generated reports with filtering and pagination.
    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        tenant_id: Uuid,
        template_id: Option<Uuid>,
        status: Option<ReportStatus>,
        from_date: Option<DateTime<Utc>>,
        to_date: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovGeneratedReport>, i64)> {
        let filter = GeneratedReportFilter {
            template_id,
            status,
            generated_by: None,
            from_date,
            to_date,
            schedule_id: None,
        };

        let reports =
            GovGeneratedReport::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovGeneratedReport::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((reports, total))
    }

    /// Generate a new report (creates a pending report record).
    #[allow(clippy::too_many_arguments)]
    pub async fn generate(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        name: Option<String>,
        parameters: Option<serde_json::Value>,
        output_format: OutputFormat,
        generated_by: Uuid,
        schedule_id: Option<Uuid>,
    ) -> Result<GovGeneratedReport> {
        // Validate template exists and is accessible
        let template = self.get_template(tenant_id, template_id).await?;

        // Create template snapshot for audit immutability
        let template_snapshot = serde_json::to_value(template.parse_definition())
            .map_err(GovernanceError::JsonSerialization)?;

        let input = GenerateReportRequest {
            template_id,
            name,
            parameters,
            output_format,
            generated_by,
            schedule_id,
        };

        let report = GovGeneratedReport::create(&self.pool, tenant_id, template_snapshot, input)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(report)
    }

    /// Start report generation (marks as generating).
    pub async fn start_generation(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
    ) -> Result<GovGeneratedReport> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Cannot start generation for report with status '{:?}'",
                report.status
            )));
        }

        GovGeneratedReport::start_generation(&self.pool, tenant_id, report_id)
            .await?
            .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// Update generation progress.
    pub async fn update_progress(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
        progress_percent: i32,
    ) -> Result<GovGeneratedReport> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Generating {
            return Err(GovernanceError::Validation(format!(
                "Cannot update progress for report with status '{:?}'",
                report.status
            )));
        }

        GovGeneratedReport::update_progress(&self.pool, tenant_id, report_id, progress_percent)
            .await?
            .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// Complete report generation with inline data (for small reports).
    pub async fn complete_with_data(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
        data: serde_json::Value,
        record_count: i32,
    ) -> Result<GovGeneratedReport> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Generating {
            return Err(GovernanceError::Validation(format!(
                "Cannot complete report with status '{:?}'",
                report.status
            )));
        }

        GovGeneratedReport::complete_with_data(&self.pool, tenant_id, report_id, data, record_count)
            .await?
            .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// Complete report generation with file path (for large reports).
    pub async fn complete_with_file(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
        file_path: &str,
        record_count: i32,
        file_size_bytes: i64,
    ) -> Result<GovGeneratedReport> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Generating {
            return Err(GovernanceError::Validation(format!(
                "Cannot complete report with status '{:?}'",
                report.status
            )));
        }

        GovGeneratedReport::complete_with_file(
            &self.pool,
            tenant_id,
            report_id,
            file_path,
            record_count,
            file_size_bytes,
        )
        .await?
        .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// Mark report generation as failed.
    pub async fn fail(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
        error_message: &str,
    ) -> Result<GovGeneratedReport> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Generating && report.status != ReportStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Cannot mark report as failed with status '{:?}'",
                report.status
            )));
        }

        GovGeneratedReport::fail(&self.pool, tenant_id, report_id, error_message)
            .await?
            .ok_or(GovernanceError::GeneratedReportNotFound(report_id))
    }

    /// Delete a report (only pending/failed reports can be deleted).
    pub async fn delete(&self, tenant_id: Uuid, report_id: Uuid) -> Result<()> {
        let report = self.get(tenant_id, report_id).await?;

        // Cannot delete completed reports (audit evidence)
        if report.status == ReportStatus::Completed {
            return Err(GovernanceError::CannotModifyCompletedReport(report_id));
        }

        // Cannot delete generating reports
        if report.status == ReportStatus::Generating {
            return Err(GovernanceError::ReportStillGenerating(report_id));
        }

        sqlx::query("DELETE FROM gov_generated_reports WHERE id = $1 AND tenant_id = $2")
            .bind(report_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// Get report output data (for completed reports).
    pub async fn get_output_data(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Completed {
            return Err(GovernanceError::Validation(format!(
                "Report is not completed, status: {:?}",
                report.status
            )));
        }

        Ok(report.output_data)
    }

    /// Get report file path (for file-based reports).
    pub async fn get_file_path(&self, tenant_id: Uuid, report_id: Uuid) -> Result<Option<String>> {
        let report = self.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Completed {
            return Err(GovernanceError::Validation(format!(
                "Report is not completed, status: {:?}",
                report.status
            )));
        }

        Ok(report.output_file_path)
    }

    /// Delete expired reports (no tenant filter - operates across all tenants).
    pub async fn delete_expired(&self, _tenant_id: Uuid) -> Result<i64> {
        let count = GovGeneratedReport::delete_expired(&self.pool)
            .await
            .map_err(GovernanceError::Database)?;
        Ok(count as i64)
    }

    /// Helper to get template (tenant-specific or system).
    async fn get_template(&self, tenant_id: Uuid, template_id: Uuid) -> Result<GovReportTemplate> {
        GovReportTemplate::find_by_id_for_tenant(&self.pool, tenant_id, template_id)
            .await?
            .ok_or(GovernanceError::ReportTemplateNotFound(template_id))
    }
}
