//! Template rule service for governance API (F058).
//!
//! Handles template rule CRUD operations, expression validation, and priority management.

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovTemplateEvent, CreateGovTemplateRule, GovObjectTemplate, GovTemplateRule,
    TemplateEventType, TemplateObjectType, TemplateRuleFilter, TemplateRuleType,
    UpdateGovTemplateRule, ENTITLEMENT_ATTRIBUTES, ROLE_ATTRIBUTES, USER_ATTRIBUTES,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::template_expression_service::TemplateExpressionService;

/// Service for template rule operations.
pub struct TemplateRuleService {
    pool: PgPool,
    expression_service: TemplateExpressionService,
}

impl TemplateRuleService {
    /// Create a new template rule service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            expression_service: TemplateExpressionService::new(),
        }
    }

    // =========================================================================
    // Template Rule CRUD operations
    // =========================================================================

    /// Get a rule by ID.
    pub async fn get(&self, tenant_id: Uuid, rule_id: Uuid) -> Result<GovTemplateRule> {
        GovTemplateRule::find_by_id(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::TemplateRuleNotFound(rule_id))
    }

    /// List rules for a template.
    pub async fn list_by_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        // Verify template exists
        self.verify_template_exists(tenant_id, template_id).await?;

        GovTemplateRule::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List rules with filtering.
    pub async fn list_with_filter(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        filter: &TemplateRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovTemplateRule>, i64)> {
        // Verify template exists
        self.verify_template_exists(tenant_id, template_id).await?;

        // Create filter with template_id set
        let mut full_filter = filter.clone();
        full_filter.template_id = Some(template_id);

        let items =
            GovTemplateRule::list_with_filter(&self.pool, tenant_id, &full_filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovTemplateRule::count_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((items, total))
    }

    /// Add a rule to a template.
    pub async fn add_rule(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
        input: CreateGovTemplateRule,
    ) -> Result<GovTemplateRule> {
        let template = self.verify_template_exists(tenant_id, template_id).await?;

        // Validate target attribute for the object type
        self.validate_target_attribute(&input.target_attribute, template.object_type)?;

        // Validate expression syntax
        if let Err(e) = self.expression_service.validate(&input.expression) {
            return Err(GovernanceError::TemplateRuleExpressionError {
                rule_id: Uuid::nil(),
                message: e.to_string(),
            });
        }

        // Validate condition expression if present
        if let Some(ref condition) = input.condition {
            if let Err(e) = self.expression_service.validate(condition) {
                return Err(GovernanceError::TemplateRuleExpressionError {
                    rule_id: Uuid::nil(),
                    message: format!("Invalid condition: {e}"),
                });
            }
        }

        // Validate time constraints if present
        if let (Some(from), Some(to)) = (input.time_from, input.time_to) {
            if from >= to {
                return Err(GovernanceError::TemplateRuleExpressionError {
                    rule_id: Uuid::nil(),
                    message: "time_from must be before time_to".to_string(),
                });
            }
        }

        // Check for exclusive mapping conflicts
        if input.exclusive.unwrap_or(false) {
            self.check_exclusive_conflict(tenant_id, template_id, &input.target_attribute, None)
                .await?;
        } else {
            // Check if an existing exclusive rule targets this attribute
            self.check_existing_exclusive_conflict(tenant_id, template_id, &input.target_attribute)
                .await?;
        }

        // Create the rule
        let rule = GovTemplateRule::create(&self.pool, tenant_id, template_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Check for circular dependencies (only for computed rules)
        if rule.rule_type == TemplateRuleType::Computed {
            self.check_circular_dependencies(tenant_id, template_id)
                .await?;
        }

        // Record audit event
        self.record_rule_event(
            tenant_id,
            template_id,
            TemplateEventType::RuleAdded,
            actor_id,
            Some(serde_json::to_value(&rule).unwrap_or_default()),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            rule_id = %rule.id,
            rule_type = ?rule.rule_type,
            target_attribute = %rule.target_attribute,
            "Template rule added"
        );

        Ok(rule)
    }

    /// Update a rule.
    pub async fn update_rule(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_id: Uuid,
        actor_id: Uuid,
        input: UpdateGovTemplateRule,
    ) -> Result<GovTemplateRule> {
        let _template = self.verify_template_exists(tenant_id, template_id).await?;
        let before = self.get(tenant_id, rule_id).await?;

        // Verify rule belongs to this template
        if before.template_id != template_id {
            return Err(GovernanceError::TemplateRuleNotFound(rule_id));
        }

        // Validate expression if being updated
        if let Some(ref expression) = input.expression {
            if let Err(e) = self.expression_service.validate(expression) {
                return Err(GovernanceError::TemplateRuleExpressionError {
                    rule_id,
                    message: e.to_string(),
                });
            }
        }

        // Validate condition expression if being updated
        if let Some(ref condition) = input.condition {
            if let Err(e) = self.expression_service.validate(condition) {
                return Err(GovernanceError::TemplateRuleExpressionError {
                    rule_id,
                    message: format!("Invalid condition: {e}"),
                });
            }
        }

        // Validate time constraints if being updated
        let time_from = input.time_from.or(before.time_from);
        let time_to = input.time_to.or(before.time_to);
        if let (Some(from), Some(to)) = (time_from, time_to) {
            if from >= to {
                return Err(GovernanceError::TemplateRuleExpressionError {
                    rule_id,
                    message: "time_from must be before time_to".to_string(),
                });
            }
        }

        // Check for exclusive mapping conflicts if becoming exclusive
        if let Some(true) = input.exclusive {
            if !before.exclusive {
                self.check_exclusive_conflict(
                    tenant_id,
                    template_id,
                    &before.target_attribute,
                    Some(rule_id),
                )
                .await?;
            }
        }

        let after = GovTemplateRule::update(&self.pool, tenant_id, rule_id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::TemplateRuleNotFound(rule_id))?;

        // Check for circular dependencies if expression was updated
        if before.rule_type == TemplateRuleType::Computed {
            self.check_circular_dependencies(tenant_id, template_id)
                .await?;
        }

        // Record audit event
        let changes = serde_json::json!({
            "before": before,
            "after": after
        });
        self.record_rule_event(
            tenant_id,
            template_id,
            TemplateEventType::RuleUpdated,
            actor_id,
            Some(changes),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            rule_id = %rule_id,
            "Template rule updated"
        );

        Ok(after)
    }

    /// Remove a rule from a template.
    pub async fn remove_rule(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_id: Uuid,
        actor_id: Uuid,
    ) -> Result<()> {
        self.verify_template_exists(tenant_id, template_id).await?;

        let rule = self.get(tenant_id, rule_id).await?;

        // Verify rule belongs to this template
        if rule.template_id != template_id {
            return Err(GovernanceError::TemplateRuleNotFound(rule_id));
        }

        // Record audit event before deletion
        self.record_rule_event(
            tenant_id,
            template_id,
            TemplateEventType::RuleRemoved,
            actor_id,
            Some(serde_json::to_value(&rule).unwrap_or_default()),
        )
        .await?;

        // Delete the rule
        let deleted = GovTemplateRule::delete(&self.pool, tenant_id, rule_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::TemplateRuleNotFound(rule_id));
        }

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            rule_id = %rule_id,
            "Template rule removed"
        );

        Ok(())
    }

    // =========================================================================
    // Validation helpers
    // =========================================================================

    /// Validate that the target attribute is valid for the given object type.
    fn validate_target_attribute(
        &self,
        attribute: &str,
        object_type: TemplateObjectType,
    ) -> Result<()> {
        let valid_attributes: &[&str] = match object_type {
            TemplateObjectType::User => USER_ATTRIBUTES,
            TemplateObjectType::Role => ROLE_ATTRIBUTES,
            TemplateObjectType::Entitlement => ENTITLEMENT_ATTRIBUTES,
            TemplateObjectType::Application => {
                // Application attributes - basic set
                &["name", "display_name", "description", "owner_id", "status"]
            }
        };

        // Allow custom attributes (any attribute starting with "custom_" or containing "metadata")
        if attribute.starts_with("custom_")
            || attribute.contains("metadata")
            || valid_attributes.contains(&attribute)
        {
            Ok(())
        } else {
            Err(GovernanceError::TemplateRuleInvalidAttribute {
                attribute: attribute.to_string(),
                object_type: format!("{object_type:?}"),
            })
        }
    }

    /// Check that adding an exclusive rule doesn't conflict with existing rules.
    async fn check_exclusive_conflict(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        target_attribute: &str,
        exclude_rule_id: Option<Uuid>,
    ) -> Result<()> {
        let existing_rules =
            GovTemplateRule::list_by_attribute(&self.pool, tenant_id, target_attribute)
                .await
                .map_err(GovernanceError::Database)?;

        // Filter to rules in this template (excluding the rule being updated if any)
        let conflicting_rules: Vec<_> = existing_rules
            .into_iter()
            .filter(|r| r.template_id == template_id && exclude_rule_id.is_none_or(|id| r.id != id))
            .collect();

        if !conflicting_rules.is_empty() {
            return Err(GovernanceError::TemplateRuleExpressionError {
                rule_id: conflicting_rules[0].id,
                message: format!(
                    "Cannot create exclusive rule: {} other rule(s) already target attribute '{}'",
                    conflicting_rules.len(),
                    target_attribute
                ),
            });
        }

        Ok(())
    }

    /// Check if an existing exclusive rule would prevent adding a new rule.
    async fn check_existing_exclusive_conflict(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        target_attribute: &str,
    ) -> Result<()> {
        let existing_rules =
            GovTemplateRule::list_by_attribute(&self.pool, tenant_id, target_attribute)
                .await
                .map_err(GovernanceError::Database)?;

        // Look for exclusive rules in this template
        let exclusive_conflict = existing_rules
            .iter()
            .find(|r| r.template_id == template_id && r.exclusive);

        if let Some(rule) = exclusive_conflict {
            return Err(GovernanceError::TemplateRuleExpressionError {
                rule_id: rule.id,
                message: format!(
                    "Cannot add rule: exclusive rule {} already targets attribute '{}'",
                    rule.id, target_attribute
                ),
            });
        }

        Ok(())
    }

    /// Check for circular dependencies among computed rules in a template.
    pub async fn check_circular_dependencies(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<()> {
        let rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Build map of computed rules: target_attribute -> expression
        let expressions: std::collections::HashMap<String, String> = rules
            .iter()
            .filter(|r| r.rule_type == TemplateRuleType::Computed)
            .map(|r| (r.target_attribute.clone(), r.expression.clone()))
            .collect();

        // Check for cycles using the expression service
        if let Err(e) = self.expression_service.detect_cycles(&expressions) {
            return Err(GovernanceError::TemplateRuleCircularDependency(
                e.to_string(),
            ));
        }

        Ok(())
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

    /// Record a rule-related event.
    async fn record_rule_event(
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
    // Rule evaluation helpers
    // =========================================================================

    /// Get rules by type for a template.
    pub async fn list_by_type(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_type: TemplateRuleType,
    ) -> Result<Vec<GovTemplateRule>> {
        let filter = TemplateRuleFilter {
            template_id: Some(template_id),
            rule_type: Some(rule_type),
            target_attribute: None,
            strength: None,
        };

        let items = GovTemplateRule::list_with_filter(&self.pool, tenant_id, &filter, 1000, 0)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(items)
    }

    /// Get all default rules for a template.
    pub async fn list_default_rules(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        self.list_by_type(tenant_id, template_id, TemplateRuleType::Default)
            .await
    }

    /// Get all computed rules for a template.
    pub async fn list_computed_rules(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        self.list_by_type(tenant_id, template_id, TemplateRuleType::Computed)
            .await
    }

    /// Get all validation rules for a template.
    pub async fn list_validation_rules(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        self.list_by_type(tenant_id, template_id, TemplateRuleType::Validation)
            .await
    }

    /// Get all normalization rules for a template.
    pub async fn list_normalization_rules(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        self.list_by_type(tenant_id, template_id, TemplateRuleType::Normalization)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        // Just verify the struct and impl are correctly defined
        let _ = std::mem::size_of::<TemplateRuleService>();
    }

    #[test]
    fn test_user_attributes_validation() {
        // Test that user attributes are available
        assert!(USER_ATTRIBUTES.contains(&"first_name"));
        assert!(USER_ATTRIBUTES.contains(&"last_name"));
        assert!(USER_ATTRIBUTES.contains(&"email"));
        assert!(USER_ATTRIBUTES.contains(&"department"));
    }

    #[test]
    fn test_role_attributes_validation() {
        // Test that role attributes are available
        assert!(ROLE_ATTRIBUTES.contains(&"name"));
        assert!(ROLE_ATTRIBUTES.contains(&"description"));
    }
}
