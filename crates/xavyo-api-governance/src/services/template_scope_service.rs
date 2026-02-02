//! Template scope service for governance API (F058).
//!
//! Handles template scope matching and management. Scopes determine which objects
//! a template applies to based on global, organization, category, or condition filters.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovTemplateEvent, CreateGovTemplateScope, GovObjectTemplate, GovTemplateScope,
    TemplateEventType, TemplateObjectType, TemplateScopeType,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::template_expression_service::TemplateExpressionService;

/// Service for template scope operations and matching.
pub struct TemplateScopeService {
    pool: PgPool,
    expression_service: TemplateExpressionService,
}

impl TemplateScopeService {
    /// Create a new template scope service.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            expression_service: TemplateExpressionService::new(),
        }
    }

    // =========================================================================
    // Scope CRUD Operations
    // =========================================================================

    /// Get a scope by ID.
    pub async fn get(&self, tenant_id: Uuid, scope_id: Uuid) -> Result<GovTemplateScope> {
        GovTemplateScope::find_by_id(&self.pool, tenant_id, scope_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::TemplateScopeNotFound(scope_id))
    }

    /// List all scopes for a template.
    pub async fn list_by_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateScope>> {
        // Verify template exists
        self.verify_template_exists(tenant_id, template_id).await?;

        GovTemplateScope::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add a scope to a template.
    pub async fn add_scope(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        input: CreateGovTemplateScope,
    ) -> Result<GovTemplateScope> {
        let _template = self.verify_template_exists(tenant_id, template_id).await?;

        // Validate scope configuration
        self.validate_scope(&input)?;

        // Create the scope
        let scope = GovTemplateScope::create(&self.pool, tenant_id, template_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event
        self.record_scope_event(
            tenant_id,
            template_id,
            TemplateEventType::ScopeAdded,
            actor_id,
            Some(serde_json::to_value(&scope).unwrap_or_default()),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            scope_id = %scope.id,
            scope_type = ?scope.scope_type,
            "Template scope added"
        );

        Ok(scope)
    }

    /// Remove a scope from a template.
    pub async fn remove_scope(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        scope_id: Uuid,
        actor_id: Uuid,
    ) -> Result<()> {
        self.verify_template_exists(tenant_id, template_id).await?;

        let scope = self.get(tenant_id, scope_id).await?;

        // Verify scope belongs to this template
        if scope.template_id != template_id {
            return Err(GovernanceError::TemplateScopeNotFound(scope_id));
        }

        // Record audit event before deletion
        self.record_scope_event(
            tenant_id,
            template_id,
            TemplateEventType::ScopeRemoved,
            actor_id,
            Some(serde_json::to_value(&scope).unwrap_or_default()),
        )
        .await?;

        // Delete the scope
        let deleted = GovTemplateScope::delete(&self.pool, tenant_id, scope_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::TemplateScopeNotFound(scope_id));
        }

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            scope_id = %scope_id,
            "Template scope removed"
        );

        Ok(())
    }

    // =========================================================================
    // Scope Matching Operations
    // =========================================================================

    /// Find all active templates that apply to the given object.
    ///
    /// Returns templates in priority order (lower priority number = higher precedence).
    pub async fn find_applicable_templates(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_data: &JsonValue,
    ) -> Result<Vec<GovObjectTemplate>> {
        // Get all active templates of this type
        let templates = self.get_active_templates(tenant_id, object_type).await?;

        // Filter templates based on scope matching
        let mut applicable = Vec::new();

        for template in templates {
            if self
                .template_matches_object(tenant_id, template.id, object_data)
                .await?
            {
                applicable.push(template);
            }
        }

        // Sort by priority (lower number = higher precedence)
        applicable.sort_by_key(|t| t.priority);

        Ok(applicable)
    }

    /// Check if a specific template applies to the given object.
    pub async fn template_matches_object(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        object_data: &JsonValue,
    ) -> Result<bool> {
        let scopes = GovTemplateScope::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        // A template with no scopes doesn't match anything
        if scopes.is_empty() {
            return Ok(false);
        }

        // Check if ANY scope matches (scopes are OR'ed together)
        for scope in scopes {
            if self.scope_matches_object(&scope, object_data)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a single scope matches the object.
    pub fn scope_matches_object(
        &self,
        scope: &GovTemplateScope,
        object_data: &JsonValue,
    ) -> Result<bool> {
        match scope.scope_type {
            TemplateScopeType::Global => {
                // Global scope always matches
                Ok(true)
            }
            TemplateScopeType::Organization => {
                // Match organization ID
                let scope_value = scope.scope_value.as_ref().ok_or_else(|| {
                    GovernanceError::TemplateScopeInvalid(
                        "Organization scope requires a value".to_string(),
                    )
                })?;

                // Check multiple possible organization fields
                let object_org = object_data
                    .get("org_id")
                    .or_else(|| object_data.get("organization_id"))
                    .or_else(|| object_data.get("organization"))
                    .and_then(|v| v.as_str());

                Ok(object_org == Some(scope_value.as_str()))
            }
            TemplateScopeType::Category => {
                // Match category value
                let scope_value = scope.scope_value.as_ref().ok_or_else(|| {
                    GovernanceError::TemplateScopeInvalid(
                        "Category scope requires a value".to_string(),
                    )
                })?;

                // Check multiple possible category fields
                let object_category = object_data
                    .get("user_type")
                    .or_else(|| object_data.get("category"))
                    .or_else(|| object_data.get("type"))
                    .or_else(|| object_data.get("role_type"))
                    .and_then(|v| v.as_str());

                Ok(object_category == Some(scope_value.as_str()))
            }
            TemplateScopeType::Condition => {
                // Evaluate condition expression
                let condition = scope.condition.as_ref().ok_or_else(|| {
                    GovernanceError::TemplateScopeInvalid(
                        "Condition scope requires an expression".to_string(),
                    )
                })?;

                self.evaluate_scope_condition(condition, object_data)
            }
        }
    }

    /// Evaluate a scope condition expression against object data.
    fn evaluate_scope_condition(&self, condition: &str, object_data: &JsonValue) -> Result<bool> {
        // Convert JSON to attribute map
        let attributes = self.json_to_attribute_map(object_data);

        // Parse the expression
        let expr = self
            .expression_service
            .parse(condition)
            .map_err(|e| GovernanceError::TemplateScopeConditionError(e.to_string()))?;

        // Evaluate the expression
        let result = self
            .expression_service
            .evaluate(&expr, &attributes)
            .map_err(|e| GovernanceError::TemplateRuleExpressionError {
                rule_id: Uuid::nil(),
                message: e.to_string(),
            })?;

        // Convert result to boolean
        match result {
            JsonValue::Bool(b) => Ok(b),
            JsonValue::Null => Ok(false),
            _ => Err(GovernanceError::TemplateScopeInvalid(
                "Condition expression must evaluate to a boolean".to_string(),
            )),
        }
    }

    /// Convert JSON object to attribute map for expression evaluation.
    fn json_to_attribute_map(
        &self,
        data: &JsonValue,
    ) -> std::collections::HashMap<String, JsonValue> {
        let mut map = std::collections::HashMap::new();

        if let Some(obj) = data.as_object() {
            for (key, value) in obj {
                map.insert(key.clone(), value.clone());
            }
        }

        map
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Validate scope configuration.
    fn validate_scope(&self, input: &CreateGovTemplateScope) -> Result<()> {
        match input.scope_type {
            TemplateScopeType::Global => {
                // Global scope should not have a value or condition
                if input.scope_value.is_some() {
                    return Err(GovernanceError::TemplateScopeInvalid(
                        "Global scope should not have a scope value".to_string(),
                    ));
                }
                if input.condition.is_some() {
                    return Err(GovernanceError::TemplateScopeInvalid(
                        "Global scope should not have a condition".to_string(),
                    ));
                }
            }
            TemplateScopeType::Organization | TemplateScopeType::Category => {
                // Organization/Category scope requires a value
                if input.scope_value.is_none() {
                    return Err(GovernanceError::TemplateScopeInvalid(format!(
                        "{:?} scope requires a scope value",
                        input.scope_type
                    )));
                }
                if input.condition.is_some() {
                    return Err(GovernanceError::TemplateScopeInvalid(format!(
                        "{:?} scope should not have a condition",
                        input.scope_type
                    )));
                }
            }
            TemplateScopeType::Condition => {
                // Condition scope requires a condition expression
                if input.condition.is_none() {
                    return Err(GovernanceError::TemplateScopeInvalid(
                        "Condition scope requires a condition expression".to_string(),
                    ));
                }

                // Validate the condition expression
                if let Some(condition) = &input.condition {
                    self.expression_service.validate(condition).map_err(|e| {
                        GovernanceError::TemplateScopeInvalid(format!(
                            "Invalid condition expression: {}",
                            e
                        ))
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Get all active templates of a specific type.
    async fn get_active_templates(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
    ) -> Result<Vec<GovObjectTemplate>> {
        GovObjectTemplate::list_active_by_type(&self.pool, tenant_id, object_type)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Verify a template exists and return it.
    async fn verify_template_exists(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<GovObjectTemplate> {
        GovObjectTemplate::find_by_id(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(template_id))
    }

    /// Record a scope-related event.
    async fn record_scope_event(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        event_type: TemplateEventType,
        actor_id: Uuid,
        changes: Option<serde_json::Value>,
    ) -> Result<()> {
        use xavyo_db::models::GovTemplateEvent;

        GovTemplateEvent::create(
            &self.pool,
            tenant_id,
            CreateGovTemplateEvent {
                template_id: Some(template_id),
                event_type,
                actor_id: Some(actor_id),
                changes,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    // =========================================================================
    // Query Helpers
    // =========================================================================

    /// Get templates with global scope.
    pub async fn get_global_templates(&self, tenant_id: Uuid) -> Result<Vec<Uuid>> {
        GovTemplateScope::find_global_templates(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get templates for a specific organization.
    pub async fn get_templates_for_organization(
        &self,
        tenant_id: Uuid,
        organization_id: &str,
    ) -> Result<Vec<Uuid>> {
        GovTemplateScope::find_templates_for_organization(&self.pool, tenant_id, organization_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get templates for a specific category.
    pub async fn get_templates_for_category(
        &self,
        tenant_id: Uuid,
        category: &str,
    ) -> Result<Vec<Uuid>> {
        GovTemplateScope::find_templates_for_category(&self.pool, tenant_id, category)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get templates with condition-based scopes.
    pub async fn get_conditional_templates(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<GovTemplateScope>> {
        GovTemplateScope::find_conditional_templates(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Count scopes for a template.
    pub async fn count_by_template(&self, tenant_id: Uuid, template_id: Uuid) -> Result<i64> {
        GovTemplateScope::count_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_scope(
        scope_type: TemplateScopeType,
        scope_value: Option<String>,
        condition: Option<String>,
    ) -> GovTemplateScope {
        GovTemplateScope {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            template_id: Uuid::new_v4(),
            scope_type,
            scope_value,
            condition,
            created_at: chrono::Utc::now(),
        }
    }

    /// Helper struct for unit tests that doesn't require a pool.
    struct ScopeMatcher {
        expression_service: TemplateExpressionService,
    }

    impl ScopeMatcher {
        fn new() -> Self {
            Self {
                expression_service: TemplateExpressionService::new(),
            }
        }

        fn scope_matches_object(
            &self,
            scope: &GovTemplateScope,
            object_data: &JsonValue,
        ) -> Result<bool> {
            match scope.scope_type {
                TemplateScopeType::Global => Ok(true),
                TemplateScopeType::Organization => {
                    let scope_value = scope.scope_value.as_ref().ok_or_else(|| {
                        GovernanceError::TemplateScopeInvalid(
                            "Organization scope requires a value".to_string(),
                        )
                    })?;

                    let object_org = object_data
                        .get("org_id")
                        .or_else(|| object_data.get("organization_id"))
                        .or_else(|| object_data.get("organization"))
                        .and_then(|v| v.as_str());

                    Ok(object_org == Some(scope_value.as_str()))
                }
                TemplateScopeType::Category => {
                    let scope_value = scope.scope_value.as_ref().ok_or_else(|| {
                        GovernanceError::TemplateScopeInvalid(
                            "Category scope requires a value".to_string(),
                        )
                    })?;

                    let object_category = object_data
                        .get("user_type")
                        .or_else(|| object_data.get("category"))
                        .or_else(|| object_data.get("type"))
                        .or_else(|| object_data.get("role_type"))
                        .and_then(|v| v.as_str());

                    Ok(object_category == Some(scope_value.as_str()))
                }
                TemplateScopeType::Condition => {
                    let condition = scope.condition.as_ref().ok_or_else(|| {
                        GovernanceError::TemplateScopeInvalid(
                            "Condition scope requires an expression".to_string(),
                        )
                    })?;

                    self.evaluate_scope_condition(condition, object_data)
                }
            }
        }

        fn evaluate_scope_condition(
            &self,
            condition: &str,
            object_data: &JsonValue,
        ) -> Result<bool> {
            let mut attributes = std::collections::HashMap::new();
            if let Some(obj) = object_data.as_object() {
                for (key, value) in obj {
                    attributes.insert(key.clone(), value.clone());
                }
            }

            let expr = self
                .expression_service
                .parse(condition)
                .map_err(|e| GovernanceError::TemplateScopeConditionError(e.to_string()))?;

            let result = self
                .expression_service
                .evaluate(&expr, &attributes)
                .map_err(|e| GovernanceError::TemplateRuleExpressionError {
                    rule_id: Uuid::nil(),
                    message: e.to_string(),
                })?;

            match result {
                JsonValue::Bool(b) => Ok(b),
                JsonValue::Null => Ok(false),
                _ => Err(GovernanceError::TemplateScopeInvalid(
                    "Condition expression must evaluate to a boolean".to_string(),
                )),
            }
        }

        fn validate_scope(&self, input: &CreateGovTemplateScope) -> Result<()> {
            match input.scope_type {
                TemplateScopeType::Global => {
                    if input.scope_value.is_some() {
                        return Err(GovernanceError::TemplateScopeInvalid(
                            "Global scope should not have a scope value".to_string(),
                        ));
                    }
                    if input.condition.is_some() {
                        return Err(GovernanceError::TemplateScopeInvalid(
                            "Global scope should not have a condition".to_string(),
                        ));
                    }
                }
                TemplateScopeType::Organization | TemplateScopeType::Category => {
                    if input.scope_value.is_none() {
                        return Err(GovernanceError::TemplateScopeInvalid(format!(
                            "{:?} scope requires a scope value",
                            input.scope_type
                        )));
                    }
                    if input.condition.is_some() {
                        return Err(GovernanceError::TemplateScopeInvalid(format!(
                            "{:?} scope should not have a condition",
                            input.scope_type
                        )));
                    }
                }
                TemplateScopeType::Condition => {
                    if input.condition.is_none() {
                        return Err(GovernanceError::TemplateScopeInvalid(
                            "Condition scope requires a condition expression".to_string(),
                        ));
                    }

                    if let Some(condition) = &input.condition {
                        self.expression_service.validate(condition).map_err(|e| {
                            GovernanceError::TemplateScopeInvalid(format!(
                                "Invalid condition expression: {}",
                                e
                            ))
                        })?;
                    }
                }
            }

            Ok(())
        }
    }

    #[test]
    fn test_global_scope_matches_any_object() {
        let matcher = ScopeMatcher::new();

        let scope = create_test_scope(TemplateScopeType::Global, None, None);
        let obj = json!({"department": "Engineering", "name": "Test"});

        let result = matcher.scope_matches_object(&scope, &obj);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_organization_scope_matches() {
        let matcher = ScopeMatcher::new();

        let scope = create_test_scope(
            TemplateScopeType::Organization,
            Some("org-engineering".to_string()),
            None,
        );

        let obj_match = json!({"org_id": "org-engineering", "name": "Test"});
        let obj_no_match = json!({"org_id": "org-sales", "name": "Test"});

        assert!(matcher.scope_matches_object(&scope, &obj_match).unwrap());
        assert!(!matcher.scope_matches_object(&scope, &obj_no_match).unwrap());
    }

    #[test]
    fn test_category_scope_matches() {
        let matcher = ScopeMatcher::new();

        let scope = create_test_scope(
            TemplateScopeType::Category,
            Some("contractor".to_string()),
            None,
        );

        let obj_match = json!({"user_type": "contractor", "name": "Test"});
        let obj_no_match = json!({"user_type": "employee", "name": "Test"});

        assert!(matcher.scope_matches_object(&scope, &obj_match).unwrap());
        assert!(!matcher.scope_matches_object(&scope, &obj_no_match).unwrap());
    }

    #[test]
    fn test_condition_scope_simple_equality() {
        let matcher = ScopeMatcher::new();

        let scope = create_test_scope(
            TemplateScopeType::Condition,
            None,
            Some("${department} == \"Engineering\"".to_string()),
        );

        let obj_match = json!({"department": "Engineering", "name": "Test"});
        let obj_no_match = json!({"department": "Sales", "name": "Test"});

        assert!(matcher.scope_matches_object(&scope, &obj_match).unwrap());
        assert!(!matcher.scope_matches_object(&scope, &obj_no_match).unwrap());
    }

    #[test]
    fn test_validate_global_scope() {
        let matcher = ScopeMatcher::new();

        // Valid global scope
        let valid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Global,
            scope_value: None,
            condition: None,
        };
        assert!(matcher.validate_scope(&valid).is_ok());

        // Invalid: global with value
        let invalid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Global,
            scope_value: Some("something".to_string()),
            condition: None,
        };
        assert!(matcher.validate_scope(&invalid).is_err());
    }

    #[test]
    fn test_validate_organization_scope() {
        let matcher = ScopeMatcher::new();

        // Valid organization scope
        let valid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Organization,
            scope_value: Some("org-123".to_string()),
            condition: None,
        };
        assert!(matcher.validate_scope(&valid).is_ok());

        // Invalid: organization without value
        let invalid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Organization,
            scope_value: None,
            condition: None,
        };
        assert!(matcher.validate_scope(&invalid).is_err());
    }

    #[test]
    fn test_validate_condition_scope() {
        let matcher = ScopeMatcher::new();

        // Valid condition scope
        let valid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Condition,
            scope_value: None,
            condition: Some("${department} == \"Engineering\"".to_string()),
        };
        assert!(matcher.validate_scope(&valid).is_ok());

        // Invalid: condition without expression
        let invalid = CreateGovTemplateScope {
            scope_type: TemplateScopeType::Condition,
            scope_value: None,
            condition: None,
        };
        assert!(matcher.validate_scope(&invalid).is_err());
    }
}
