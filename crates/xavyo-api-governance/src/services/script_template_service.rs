//! Script Template Service (F066).
//! Pre-built and tenant-created reusable script patterns.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::gov_script_template::{
    CreateScriptTemplate, GovScriptTemplate, TemplateFilter, UpdateScriptTemplate,
};
use xavyo_db::models::gov_script_types::{TemplateCategory, MAX_SCRIPT_BODY_SIZE};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for managing pre-built and tenant-created script templates.
pub struct ScriptTemplateService {
    pool: PgPool,
}

impl ScriptTemplateService {
    /// Create a new script template service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new script template.
    ///
    /// Validates template body size before persisting.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_template(
        &self,
        tenant_id: Uuid,
        name: String,
        description: Option<String>,
        category: TemplateCategory,
        template_body: String,
        placeholder_annotations: Option<serde_json::Value>,
        is_system: bool,
        created_by: Uuid,
    ) -> Result<GovScriptTemplate> {
        // Validate name is not empty
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Template name cannot be empty".to_string(),
            ));
        }

        // Validate body size
        validate_body_size(&template_body)?;

        let params = CreateScriptTemplate {
            tenant_id,
            name,
            description,
            category,
            template_body,
            placeholder_annotations,
            is_system,
            created_by,
        };

        let template = GovScriptTemplate::create(&self.pool, params)
            .await
            .map_err(GovernanceError::Database)?;

        tracing::info!(
            tenant_id = %tenant_id,
            template_id = %template.id,
            category = ?template.category,
            "Script template created"
        );

        Ok(template)
    }

    /// Get a template by ID.
    ///
    /// Returns `GovernanceError::ScriptTemplateNotFound` if no matching template exists.
    pub async fn get_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<GovScriptTemplate> {
        GovScriptTemplate::get_by_id(&self.pool, template_id, tenant_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ScriptTemplateNotFound(template_id))
    }

    /// List templates with filters and pagination.
    ///
    /// Returns a tuple of `(templates, total_count)` for pagination support.
    pub async fn list_templates(
        &self,
        tenant_id: Uuid,
        category: Option<TemplateCategory>,
        search: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovScriptTemplate>, i64)> {
        let filter = TemplateFilter {
            category,
            is_system: None,
            search,
        };

        let (templates, total) =
            GovScriptTemplate::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        Ok((templates, total))
    }

    /// Update a template.
    ///
    /// System templates cannot be modified. If a new body is provided, its size
    /// is validated before persisting.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        name: Option<String>,
        description: Option<String>,
        category: Option<TemplateCategory>,
        template_body: Option<String>,
        placeholder_annotations: Option<serde_json::Value>,
    ) -> Result<GovScriptTemplate> {
        // Load existing template to check system flag
        let existing = self.get_template(tenant_id, template_id).await?;

        if existing.is_system {
            return Err(GovernanceError::CannotModifySystemScript(template_id));
        }

        // Validate name if provided
        if let Some(ref n) = name {
            if n.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Template name cannot be empty".to_string(),
                ));
            }
        }

        // Validate body size if provided
        if let Some(ref body) = template_body {
            validate_body_size(body)?;
        }

        let params = UpdateScriptTemplate {
            name,
            description,
            category,
            template_body,
            placeholder_annotations,
        };

        GovScriptTemplate::update(&self.pool, template_id, tenant_id, params)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::ScriptTemplateNotFound(template_id))
    }

    /// Delete a template.
    ///
    /// System templates cannot be deleted (`CannotModifySystemScript`).
    pub async fn delete_template(&self, tenant_id: Uuid, template_id: Uuid) -> Result<()> {
        // Load existing template to check system flag
        let existing = self.get_template(tenant_id, template_id).await?;

        if existing.is_system {
            return Err(GovernanceError::CannotModifySystemScript(template_id));
        }

        let deleted = GovScriptTemplate::delete(&self.pool, template_id, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::ScriptTemplateNotFound(template_id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            "Script template deleted"
        );

        Ok(())
    }

    /// Instantiate a template as a new provisioning script.
    ///
    /// Loads and returns the template so the caller can use its body content
    /// when creating a provisioning script.
    pub async fn instantiate_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<GovScriptTemplate> {
        self.get_template(tenant_id, template_id).await
    }

    /// List templates by category.
    pub async fn list_by_category(
        &self,
        tenant_id: Uuid,
        category: TemplateCategory,
    ) -> Result<Vec<GovScriptTemplate>> {
        GovScriptTemplate::list_by_category(&self.pool, tenant_id, category)
            .await
            .map_err(GovernanceError::Database)
    }
}

/// Validate that the template body does not exceed the maximum allowed size.
fn validate_body_size(body: &str) -> Result<()> {
    if body.len() > MAX_SCRIPT_BODY_SIZE {
        return Err(GovernanceError::Validation(format!(
            "Template body exceeds maximum size of {} bytes (got {} bytes)",
            MAX_SCRIPT_BODY_SIZE,
            body.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_body_size_within_limit() {
        let body = "a".repeat(1000);
        assert!(validate_body_size(&body).is_ok());
    }

    #[test]
    fn test_validate_body_size_at_limit() {
        let body = "a".repeat(MAX_SCRIPT_BODY_SIZE);
        assert!(validate_body_size(&body).is_ok());
    }

    #[test]
    fn test_validate_body_size_exceeds_limit() {
        let body = "a".repeat(MAX_SCRIPT_BODY_SIZE + 1);
        let result = validate_body_size(&body);
        assert!(result.is_err());
    }

    #[test]
    fn test_script_template_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests require a database connection.
    }
}
