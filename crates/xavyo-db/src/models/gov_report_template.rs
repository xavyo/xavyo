//! Governance Report Template model.
//!
//! Represents report template definitions for compliance reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Type of report template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_report_template_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReportTemplateType {
    /// User access and entitlements review.
    AccessReview,
    /// Separation of duties violations.
    SodViolations,
    /// Certification campaign progress.
    CertificationStatus,
    /// Individual user access report.
    UserAccess,
    /// Audit event export.
    AuditTrail,
}

/// Compliance standard for the template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_compliance_standard", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStandard {
    /// Sarbanes-Oxley.
    Sox,
    /// General Data Protection Regulation.
    Gdpr,
    /// Health Insurance Portability and Accountability Act.
    Hipaa,
    /// Custom/other compliance.
    Custom,
}

/// Status for report templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateStatus {
    /// Template is active and available.
    Active,
    /// Template is archived (soft-deleted).
    Archived,
}

impl TemplateStatus {
    /// Check if the template is active.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A filter definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FilterDefinition {
    pub field: String,
    #[serde(rename = "type")]
    pub filter_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

/// A column definition within a template.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ColumnDefinition {
    pub field: String,
    pub label: String,
    #[serde(default)]
    pub sortable: bool,
}

/// Sort definition for default ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SortDefinition {
    pub field: String,
    pub direction: String,
}

/// Template definition structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TemplateDefinition {
    #[serde(default)]
    pub data_sources: Vec<String>,
    #[serde(default)]
    pub filters: Vec<FilterDefinition>,
    #[serde(default)]
    pub columns: Vec<ColumnDefinition>,
    #[serde(default)]
    pub grouping: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_sort: Option<SortDefinition>,
}

/// A governance report template.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovReportTemplate {
    /// Unique identifier for the template.
    pub id: Uuid,

    /// The tenant this template belongs to (NULL for system templates).
    pub tenant_id: Option<Uuid>,

    /// Template display name.
    pub name: String,

    /// Template description.
    pub description: Option<String>,

    /// Type of report this template generates.
    pub template_type: ReportTemplateType,

    /// Compliance standard this template supports.
    pub compliance_standard: Option<ComplianceStandard>,

    /// Template definition (data sources, filters, columns, etc.).
    pub definition: serde_json::Value,

    /// True for pre-built system templates.
    pub is_system: bool,

    /// Reference to parent template if cloned.
    pub cloned_from: Option<Uuid>,

    /// Template status.
    pub status: TemplateStatus,

    /// User who created the template.
    pub created_by: Option<Uuid>,

    /// When the template was created.
    pub created_at: DateTime<Utc>,

    /// When the template was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new report template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportTemplate {
    pub name: String,
    pub description: Option<String>,
    pub template_type: ReportTemplateType,
    pub compliance_standard: Option<ComplianceStandard>,
    pub definition: TemplateDefinition,
    pub created_by: Uuid,
}

/// Request to update a report template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReportTemplate {
    pub name: Option<String>,
    pub description: Option<String>,
    pub definition: Option<TemplateDefinition>,
}

/// Request to clone a report template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneReportTemplate {
    pub name: String,
    pub description: Option<String>,
    pub created_by: Uuid,
}

/// Filter options for listing report templates.
#[derive(Debug, Clone, Default)]
pub struct ReportTemplateFilter {
    pub template_type: Option<ReportTemplateType>,
    pub compliance_standard: Option<ComplianceStandard>,
    pub include_system: bool,
    pub status: Option<TemplateStatus>,
}

impl GovReportTemplate {
    /// Find a template by ID.
    pub async fn find_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_report_templates
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Find a template by ID within a tenant (includes system templates).
    pub async fn find_by_id_for_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_report_templates
            WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a template by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_report_templates
            WHERE name = $1 AND (tenant_id IS NULL OR tenant_id = $2)
            "#,
        )
        .bind(name)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List templates for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReportTemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_report_templates
            WHERE status = 'active'
            AND (tenant_id = $1 OR tenant_id IS NULL)
            "#,
        );
        let mut param_count = 1;

        if !filter.include_system {
            query.push_str(" AND tenant_id IS NOT NULL");
        }
        if filter.template_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_type = ${}", param_count));
        }
        if filter.compliance_standard.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND compliance_standard = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY is_system DESC, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovReportTemplate>(&query).bind(tenant_id);

        if let Some(template_type) = filter.template_type {
            q = q.bind(template_type);
        }
        if let Some(compliance_standard) = filter.compliance_standard {
            q = q.bind(compliance_standard);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count templates for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReportTemplateFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_report_templates
            WHERE status = 'active'
            AND (tenant_id = $1 OR tenant_id IS NULL)
            "#,
        );
        let mut param_count = 1;

        if !filter.include_system {
            query.push_str(" AND tenant_id IS NOT NULL");
        }
        if filter.template_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND template_type = ${}", param_count));
        }
        if filter.compliance_standard.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND compliance_standard = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(template_type) = filter.template_type {
            q = q.bind(template_type);
        }
        if let Some(compliance_standard) = filter.compliance_standard {
            q = q.bind(compliance_standard);
        }

        q.fetch_one(pool).await
    }

    /// Create a new custom template.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateReportTemplate,
    ) -> Result<Self, sqlx::Error> {
        let definition =
            serde_json::to_value(&input.definition).unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r#"
            INSERT INTO gov_report_templates (
                tenant_id, name, description, template_type, compliance_standard,
                definition, is_system, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, false, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.template_type)
        .bind(input.compliance_standard)
        .bind(&definition)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Clone a template.
    pub async fn clone(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        source_id: Uuid,
        input: CloneReportTemplate,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_report_templates (
                tenant_id, name, description, template_type, compliance_standard,
                definition, is_system, cloned_from, created_by
            )
            SELECT
                $1, $2, COALESCE($3, description), template_type, compliance_standard,
                definition, false, id, $4
            FROM gov_report_templates
            WHERE id = $5
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(input.created_by)
        .bind(source_id)
        .fetch_one(pool)
        .await
    }

    /// Update a template (only custom templates can be updated).
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateReportTemplate,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if input.definition.is_some() {
            updates.push(format!("definition = ${}", param_idx));
            let _ = param_idx;
        }

        let query = format!(
            r#"
            UPDATE gov_report_templates
            SET {}
            WHERE id = $1 AND tenant_id = $2 AND is_system = false
            RETURNING *
            "#,
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovReportTemplate>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref definition) = input.definition {
            let definition_json =
                serde_json::to_value(definition).unwrap_or_else(|_| serde_json::json!({}));
            q = q.bind(definition_json);
        }

        q.fetch_optional(pool).await
    }

    /// Archive a template (soft delete).
    pub async fn archive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_report_templates
            SET status = 'archived', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND is_system = false AND status = 'active'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all system templates.
    pub async fn list_system_templates(pool: &sqlx::PgPool) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_report_templates
            WHERE is_system = true AND status = 'active'
            ORDER BY compliance_standard, template_type, name
            "#,
        )
        .fetch_all(pool)
        .await
    }

    /// Parse the template definition.
    pub fn parse_definition(&self) -> TemplateDefinition {
        serde_json::from_value(self.definition.clone()).unwrap_or_default()
    }

    /// Check if this is a system template.
    pub fn is_system_template(&self) -> bool {
        self.is_system
    }

    /// Check if the template can be modified.
    pub fn can_modify(&self) -> bool {
        !self.is_system && self.status.is_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_status_methods() {
        assert!(TemplateStatus::Active.is_active());
        assert!(!TemplateStatus::Archived.is_active());
    }

    #[test]
    fn test_template_type_serialization() {
        let access_review = ReportTemplateType::AccessReview;
        let json = serde_json::to_string(&access_review).unwrap();
        assert_eq!(json, "\"access_review\"");

        let sod = ReportTemplateType::SodViolations;
        let json = serde_json::to_string(&sod).unwrap();
        assert_eq!(json, "\"sod_violations\"");
    }

    #[test]
    fn test_compliance_standard_serialization() {
        let sox = ComplianceStandard::Sox;
        let json = serde_json::to_string(&sox).unwrap();
        assert_eq!(json, "\"sox\"");

        let gdpr = ComplianceStandard::Gdpr;
        let json = serde_json::to_string(&gdpr).unwrap();
        assert_eq!(json, "\"gdpr\"");
    }

    #[test]
    fn test_template_definition_parsing() {
        let json = serde_json::json!({
            "data_sources": ["users", "entitlements"],
            "filters": [
                {"field": "date_range", "type": "date_range", "required": true}
            ],
            "columns": [
                {"field": "user_email", "label": "User", "sortable": true}
            ],
            "grouping": [],
            "default_sort": {"field": "user_email", "direction": "asc"}
        });

        let definition: TemplateDefinition = serde_json::from_value(json).unwrap();
        assert_eq!(definition.data_sources.len(), 2);
        assert_eq!(definition.filters.len(), 1);
        assert_eq!(definition.columns.len(), 1);
        assert!(definition.default_sort.is_some());
    }

    #[test]
    fn test_filter_definition_default_values() {
        let json = serde_json::json!({
            "field": "department",
            "type": "select"
        });

        let filter: FilterDefinition = serde_json::from_value(json).unwrap();
        assert_eq!(filter.field, "department");
        assert_eq!(filter.filter_type, "select");
        assert!(!filter.required);
        assert!(filter.options.is_none());
    }
}
