//! Report generator service that orchestrates the full report generation process.
//!
//! This service coordinates data collection, export formatting, and status updates.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GovGeneratedReport, GovReportTemplate, ReportStatus};
use xavyo_governance::error::{GovernanceError, Result};

use super::report_data_service::ReportDataService;
use super::report_export_service::ReportExportService;
use super::report_service::ReportService;

/// Service that orchestrates complete report generation.
pub struct ReportGeneratorService {
    report_service: ReportService,
    data_service: ReportDataService,
    export_service: ReportExportService,
}

impl ReportGeneratorService {
    /// Create a new report generator service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            report_service: ReportService::new(pool.clone()),
            data_service: ReportDataService::new(pool),
            export_service: ReportExportService::new(),
        }
    }

    /// Execute the full report generation workflow.
    ///
    /// This method:
    /// 1. Marks the report as generating
    /// 2. Collects data based on template type
    /// 3. Formats data according to output format
    /// 4. Stores the result
    /// 5. Marks the report as completed or failed
    pub async fn execute_generation(
        &self,
        tenant_id: Uuid,
        report_id: Uuid,
    ) -> Result<GovGeneratedReport> {
        // Get the report and template
        let report = self.report_service.get(tenant_id, report_id).await?;

        if report.status != ReportStatus::Pending {
            return Err(GovernanceError::Validation(format!(
                "Report is not pending, current status: {:?}",
                report.status
            )));
        }

        // Get the template
        let template = GovReportTemplate::find_by_id_for_tenant(
            self.get_pool(),
            tenant_id,
            report.template_id,
        )
        .await?
        .ok_or(GovernanceError::ReportTemplateNotFound(report.template_id))?;

        // Mark as generating
        let report = self
            .report_service
            .start_generation(tenant_id, report_id)
            .await?;

        // Generate data
        let definition = template.parse_definition();
        let data_result = self
            .data_service
            .generate_data(
                tenant_id,
                template.template_type,
                &definition,
                report.parameters.as_object().map(|_| &report.parameters),
            )
            .await;

        match data_result {
            Ok(data) => {
                // Update progress to 50%
                let _ = self
                    .report_service
                    .update_progress(tenant_id, report_id, 50)
                    .await;

                // Export to requested format
                let export_result = self.export_service.export(&data, report.output_format);

                match export_result {
                    Ok(exported) => {
                        // Update progress to 90%
                        let _ = self
                            .report_service
                            .update_progress(tenant_id, report_id, 90)
                            .await;

                        // Store as inline data (for small reports)
                        let output = serde_json::json!({
                            "content": exported.content,
                            "content_type": exported.content_type,
                            "file_extension": exported.file_extension
                        });

                        self.report_service
                            .complete_with_data(
                                tenant_id,
                                report_id,
                                output,
                                data.total_count as i32,
                            )
                            .await
                    }
                    Err(e) => {
                        // Export failed
                        self.report_service
                            .fail(tenant_id, report_id, &format!("Export failed: {e}"))
                            .await
                    }
                }
            }
            Err(e) => {
                // Data generation failed
                self.report_service
                    .fail(
                        tenant_id,
                        report_id,
                        &format!("Data generation failed: {e}"),
                    )
                    .await
            }
        }
    }

    /// Get a reference to the internal pool (for template lookup).
    fn get_pool(&self) -> &PgPool {
        // Access pool from report_service
        // This is a bit of a hack, ideally we'd store pool directly
        &self.data_service.pool
    }
}

// We need to expose the pool from ReportDataService
impl ReportDataService {
    /// Get a reference to the pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would go here, but require a real database
}
