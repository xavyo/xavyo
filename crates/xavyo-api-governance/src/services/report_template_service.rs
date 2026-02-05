//! Report template service for compliance reporting.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CloneReportTemplate, ComplianceStandard, CreateReportTemplate, GovReportTemplate,
    ReportTemplateFilter, ReportTemplateType, TemplateDefinition, TemplateStatus,
    UpdateReportTemplate,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for report template operations.
pub struct ReportTemplateService {
    pool: PgPool,
}

impl ReportTemplateService {
    /// Create a new report template service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a report template by ID.
    pub async fn get(&self, tenant_id: Uuid, template_id: Uuid) -> Result<GovReportTemplate> {
        // Use find_by_id_for_tenant which includes system templates
        GovReportTemplate::find_by_id_for_tenant(&self.pool, tenant_id, template_id)
            .await?
            .ok_or(GovernanceError::ReportTemplateNotFound(template_id))
    }

    /// List report templates with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        template_type: Option<ReportTemplateType>,
        compliance_standard: Option<ComplianceStandard>,
        include_system: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovReportTemplate>, i64)> {
        let filter = ReportTemplateFilter {
            template_type,
            compliance_standard,
            status: Some(TemplateStatus::Active),
            include_system,
        };

        let templates =
            GovReportTemplate::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovReportTemplate::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((templates, total))
    }

    /// Create a new custom report template.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        template_type: ReportTemplateType,
        compliance_standard: Option<ComplianceStandard>,
        definition: TemplateDefinition,
        created_by: Uuid,
    ) -> Result<GovReportTemplate> {
        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Template name cannot be empty".to_string(),
            ));
        }

        if name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Template name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name in tenant
        if GovReportTemplate::find_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::ReportTemplateNameExists(name));
        }

        // Validate definition
        validate_definition(&definition)?;

        let input = CreateReportTemplate {
            name,
            description,
            template_type,
            compliance_standard,
            definition,
            created_by,
        };

        GovReportTemplate::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Clone a report template (system or custom).
    pub async fn clone_template(
        &self,
        tenant_id: Uuid,
        source_template_id: Uuid,
        name: String,
        description: Option<String>,
        created_by: Uuid,
    ) -> Result<GovReportTemplate> {
        // Get source template to verify it exists
        let _source = self.get(tenant_id, source_template_id).await?;

        // Validate name
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Template name cannot be empty".to_string(),
            ));
        }

        // Check for duplicate name in tenant
        if GovReportTemplate::find_by_name(&self.pool, tenant_id, &name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::ReportTemplateNameExists(name));
        }

        let input = CloneReportTemplate {
            name,
            description,
            created_by,
        };

        GovReportTemplate::clone(&self.pool, tenant_id, source_template_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a custom report template.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        name: Option<String>,
        description: Option<String>,
        definition: Option<TemplateDefinition>,
    ) -> Result<GovReportTemplate> {
        // Get existing template
        let existing = self.get(tenant_id, template_id).await?;

        // Cannot modify system templates
        if existing.is_system {
            return Err(GovernanceError::CannotModifySystemTemplate(template_id));
        }

        // Cannot modify archived templates
        if existing.status == TemplateStatus::Archived {
            return Err(GovernanceError::ReportTemplateAlreadyArchived(template_id));
        }

        // Validate name if provided
        if let Some(ref new_name) = name {
            if new_name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Template name cannot be empty".to_string(),
                ));
            }

            if new_name != &existing.name
                && GovReportTemplate::find_by_name(&self.pool, tenant_id, new_name)
                    .await?
                    .is_some()
            {
                return Err(GovernanceError::ReportTemplateNameExists(new_name.clone()));
            }
        }

        // Validate definition if provided
        if let Some(ref def) = definition {
            validate_definition(def)?;
        }

        let input = UpdateReportTemplate {
            name,
            description,
            definition,
        };

        GovReportTemplate::update(&self.pool, tenant_id, template_id, input)
            .await?
            .ok_or(GovernanceError::ReportTemplateNotFound(template_id))
    }

    /// Archive (soft-delete) a custom report template.
    pub async fn archive(&self, tenant_id: Uuid, template_id: Uuid) -> Result<GovReportTemplate> {
        // Get existing template
        let existing = self.get(tenant_id, template_id).await?;

        // Cannot archive system templates
        if existing.is_system {
            return Err(GovernanceError::CannotArchiveSystemTemplate(template_id));
        }

        // Already archived
        if existing.status == TemplateStatus::Archived {
            return Err(GovernanceError::ReportTemplateAlreadyArchived(template_id));
        }

        GovReportTemplate::archive(&self.pool, tenant_id, template_id)
            .await?
            .ok_or(GovernanceError::ReportTemplateNotFound(template_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::ColumnDefinition;

    #[test]
    fn test_validate_definition_empty_columns() {
        let definition = TemplateDefinition {
            columns: vec![],
            filters: vec![],
            default_sort: None,
            grouping: vec![],
            data_sources: vec![],
        };

        let result = validate_definition(&definition);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_definition_empty_field() {
        let definition = TemplateDefinition {
            columns: vec![ColumnDefinition {
                field: "".to_string(),
                label: "Test".to_string(),
                sortable: false,
            }],
            filters: vec![],
            default_sort: None,
            grouping: vec![],
            data_sources: vec![],
        };

        let result = validate_definition(&definition);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_definition_valid() {
        let definition = TemplateDefinition {
            columns: vec![ColumnDefinition {
                field: "user_email".to_string(),
                label: "User Email".to_string(),
                sortable: true,
            }],
            filters: vec![],
            default_sort: None,
            grouping: vec![],
            data_sources: vec!["users".to_string()],
        };

        let result = validate_definition(&definition);
        assert!(result.is_ok());
    }
}

/// Validate template definition.
fn validate_definition(definition: &TemplateDefinition) -> Result<()> {
    // Validate columns
    if definition.columns.is_empty() {
        return Err(GovernanceError::Validation(
            "Template must have at least one column".to_string(),
        ));
    }

    for col in &definition.columns {
        if col.field.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Column field cannot be empty".to_string(),
            ));
        }
        if col.label.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Column label cannot be empty".to_string(),
            ));
        }
    }

    Ok(())
}
