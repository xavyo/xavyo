//! API models for compliance reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::models::{
    ComplianceStandard, OutputFormat, ReportStatus, ReportTemplateType, ScheduleFrequency,
    ScheduleStatus, TemplateDefinition, TemplateStatus,
};

// ============================================================================
// Report Template Models
// ============================================================================

/// Response for a report template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReportTemplateResponse {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub template_type: ReportTemplateType,
    pub compliance_standard: Option<ComplianceStandard>,
    pub definition: TemplateDefinition,
    pub is_system: bool,
    pub cloned_from: Option<Uuid>,
    pub status: TemplateStatus,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a custom report template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateReportTemplateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub template_type: ReportTemplateType,
    #[serde(default)]
    pub compliance_standard: Option<ComplianceStandard>,
    pub definition: TemplateDefinition,
}

/// Request to update a report template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateReportTemplateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub definition: Option<TemplateDefinition>,
}

/// Request to clone a report template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CloneReportTemplateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Query parameters for listing report templates.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListTemplatesQuery {
    pub template_type: Option<ReportTemplateType>,
    pub compliance_standard: Option<ComplianceStandard>,
    #[serde(default = "default_include_system")]
    pub include_system: bool,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_include_system() -> bool {
    true
}

/// List response for report templates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReportTemplateListResponse {
    pub items: Vec<ReportTemplateResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Generated Report Models
// ============================================================================

/// Response for a generated report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GeneratedReportResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub template_id: Uuid,
    pub name: String,
    pub status: ReportStatus,
    pub parameters: serde_json::Value,
    pub output_format: OutputFormat,
    pub record_count: Option<i32>,
    pub file_size_bytes: Option<i64>,
    pub error_message: Option<String>,
    pub progress_percent: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub generated_by: Uuid,
    pub schedule_id: Option<Uuid>,
    pub retention_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Request to generate a report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GenerateReportRequest {
    pub template_id: Uuid,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    pub output_format: OutputFormat,
}

/// Query parameters for listing generated reports.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListReportsQuery {
    pub template_id: Option<Uuid>,
    pub status: Option<ReportStatus>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for generated reports.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GeneratedReportListResponse {
    pub items: Vec<GeneratedReportResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Report Schedule Models
// ============================================================================

/// Response for a report schedule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReportScheduleResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub template_id: Uuid,
    pub name: String,
    pub frequency: ScheduleFrequency,
    pub schedule_hour: i32,
    pub schedule_day_of_week: Option<i32>,
    pub schedule_day_of_month: Option<i32>,
    pub parameters: serde_json::Value,
    pub recipients: Vec<String>,
    pub output_format: OutputFormat,
    pub status: ScheduleStatus,
    pub last_run_at: Option<DateTime<Utc>>,
    pub next_run_at: DateTime<Utc>,
    pub consecutive_failures: i32,
    pub last_error: Option<String>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a report schedule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateReportScheduleRequest {
    pub template_id: Uuid,
    pub name: String,
    pub frequency: ScheduleFrequency,
    pub schedule_hour: i32,
    #[serde(default)]
    pub schedule_day_of_week: Option<i32>,
    #[serde(default)]
    pub schedule_day_of_month: Option<i32>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    pub recipients: Vec<String>,
    pub output_format: OutputFormat,
}

/// Request to update a report schedule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateReportScheduleRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub frequency: Option<ScheduleFrequency>,
    #[serde(default)]
    pub schedule_hour: Option<i32>,
    #[serde(default)]
    pub schedule_day_of_week: Option<i32>,
    #[serde(default)]
    pub schedule_day_of_month: Option<i32>,
    #[serde(default)]
    pub parameters: Option<serde_json::Value>,
    #[serde(default)]
    pub recipients: Option<Vec<String>>,
    #[serde(default)]
    pub output_format: Option<OutputFormat>,
}

/// Query parameters for listing schedules.
#[derive(Debug, Clone, Deserialize, Default, utoipa::IntoParams)]
pub struct ListSchedulesQuery {
    pub template_id: Option<Uuid>,
    pub status: Option<ScheduleStatus>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

/// List response for schedules.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReportScheduleListResponse {
    pub items: Vec<ReportScheduleResponse>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

// ============================================================================
// Audit Export Models
// ============================================================================

/// Request to export audit trail data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditExportRequest {
    pub from_date: DateTime<Utc>,
    pub to_date: DateTime<Utc>,
    #[serde(default)]
    pub event_types: Option<Vec<String>>,
    pub output_format: OutputFormat,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn default_limit() -> i64 {
    50
}

// ============================================================================
// Conversions
// ============================================================================

impl From<xavyo_db::models::GovReportTemplate> for ReportTemplateResponse {
    fn from(t: xavyo_db::models::GovReportTemplate) -> Self {
        // Parse definition before moving fields
        let definition = t.parse_definition();
        Self {
            id: t.id,
            tenant_id: t.tenant_id,
            name: t.name,
            description: t.description,
            template_type: t.template_type,
            compliance_standard: t.compliance_standard,
            definition,
            is_system: t.is_system,
            cloned_from: t.cloned_from,
            status: t.status,
            created_by: t.created_by,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

impl From<xavyo_db::models::GovGeneratedReport> for GeneratedReportResponse {
    fn from(r: xavyo_db::models::GovGeneratedReport) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            template_id: r.template_id,
            name: r.name,
            status: r.status,
            parameters: r.parameters,
            output_format: r.output_format,
            record_count: r.record_count,
            file_size_bytes: r.file_size_bytes,
            error_message: r.error_message,
            progress_percent: r.progress_percent,
            started_at: r.started_at,
            completed_at: r.completed_at,
            generated_by: r.generated_by,
            schedule_id: r.schedule_id,
            retention_until: r.retention_until,
            created_at: r.created_at,
        }
    }
}

impl From<xavyo_db::models::GovReportSchedule> for ReportScheduleResponse {
    fn from(s: xavyo_db::models::GovReportSchedule) -> Self {
        // Parse recipients before moving fields
        let recipients = s.parse_recipients();
        Self {
            id: s.id,
            tenant_id: s.tenant_id,
            template_id: s.template_id,
            name: s.name,
            frequency: s.frequency,
            schedule_hour: s.schedule_hour,
            schedule_day_of_week: s.schedule_day_of_week,
            schedule_day_of_month: s.schedule_day_of_month,
            parameters: s.parameters,
            recipients,
            output_format: s.output_format,
            status: s.status,
            last_run_at: s.last_run_at,
            next_run_at: s.next_run_at,
            consecutive_failures: s.consecutive_failures,
            last_error: s.last_error,
            created_by: s.created_by,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}
