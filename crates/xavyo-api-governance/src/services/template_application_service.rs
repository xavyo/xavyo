//! Template application service for governance API (F058).
//!
//! Applies object templates during object creation and modification. This service
//! handles default values, computed values, validation rules, and normalization rules.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};
use uuid::Uuid;

use chrono::{DateTime, Utc};
use xavyo_db::models::{
    CreateGovTemplateApplicationEvent, GovObjectTemplate, GovTemplateApplicationEvent,
    GovTemplateRule, TemplateObjectType, TemplateOperation, TemplateRuleType, TemplateStrength,
    TemplateTimeReference,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::template_expression_service::TemplateExpressionService;
use super::template_rule_service::TemplateRuleService;
use super::template_scope_service::TemplateScopeService;

/// Result of applying templates to an object.
#[derive(Debug, Clone)]
pub struct ApplicationResult {
    /// The modified object data.
    pub data: JsonValue,
    /// Attributes that were set by templates (authoritative values).
    pub managed_attributes: HashSet<String>,
    /// Templates that were applied, in order.
    pub applied_templates: Vec<Uuid>,
    /// Validation errors encountered.
    pub validation_errors: Vec<ValidationError>,
    /// Whether the application was successful (no validation errors).
    pub success: bool,
}

/// A validation error from template rule application.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationError {
    /// The template that contained the validation rule.
    pub template_id: Uuid,
    /// The rule that failed.
    pub rule_id: Uuid,
    /// The attribute being validated.
    pub attribute: String,
    /// Error message to display.
    pub message: String,
}

/// Service for applying templates to objects.
pub struct TemplateApplicationService {
    pool: PgPool,
    scope_service: TemplateScopeService,
    rule_service: TemplateRuleService,
    expression_service: TemplateExpressionService,
}

impl TemplateApplicationService {
    /// Create a new template application service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            scope_service: TemplateScopeService::new(pool.clone()),
            rule_service: TemplateRuleService::new(pool.clone()),
            expression_service: TemplateExpressionService::new(),
            pool,
        }
    }

    /// Create with explicit dependencies (for testing).
    pub fn with_dependencies(
        pool: PgPool,
        scope_service: TemplateScopeService,
        rule_service: TemplateRuleService,
        expression_service: TemplateExpressionService,
    ) -> Self {
        Self {
            pool,
            scope_service,
            rule_service,
            expression_service,
        }
    }

    // =========================================================================
    // Template Application Operations
    // =========================================================================

    /// Apply templates during object creation.
    ///
    /// This method:
    /// 1. Finds all applicable templates based on scope matching
    /// 2. Sorts templates by priority
    /// 3. Applies rules in order: defaults, computed, validation, normalization
    /// 4. Returns the modified object data and any validation errors
    pub async fn apply_on_create(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_data: &JsonValue,
        _actor_id: Option<Uuid>,
    ) -> Result<ApplicationResult> {
        self.apply_on_create_with_time(tenant_id, object_type, object_data, _actor_id, None)
            .await
    }

    /// Apply templates during object creation with optional object creation time.
    ///
    /// The `object_created_at` parameter is used for time constraint evaluation.
    /// If None, the current time is used.
    pub async fn apply_on_create_with_time(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_data: &JsonValue,
        _actor_id: Option<Uuid>,
        object_created_at: Option<DateTime<Utc>>,
    ) -> Result<ApplicationResult> {
        // Find applicable templates
        let templates = self
            .scope_service
            .find_applicable_templates(tenant_id, object_type, object_data)
            .await?;

        if templates.is_empty() {
            return Ok(ApplicationResult {
                data: object_data.clone(),
                managed_attributes: HashSet::new(),
                applied_templates: vec![],
                validation_errors: vec![],
                success: true,
            });
        }

        // Apply templates with time context
        let result = self
            .apply_templates_with_time(tenant_id, &templates, object_data, false, object_created_at)
            .await?;

        info!(
            tenant_id = %tenant_id,
            object_type = ?object_type,
            templates_applied = templates.len(),
            success = result.success,
            "Templates applied on create"
        );

        Ok(result)
    }

    /// Record template application events after object creation.
    ///
    /// This should be called after the object is created and we have an object ID.
    pub async fn record_create_events(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
        result: &ApplicationResult,
        actor_id: Option<Uuid>,
    ) -> Result<()> {
        for template_id in &result.applied_templates {
            self.record_application_event(
                tenant_id,
                *template_id,
                object_type,
                object_id,
                TemplateOperation::Create,
                result,
                actor_id,
            )
            .await?;
        }
        Ok(())
    }

    /// Apply templates during object modification.
    ///
    /// Similar to `apply_on_create` but handles:
    /// - Authoritative flag for value removal
    /// - Re-evaluation of all rules on any attribute change
    pub async fn apply_on_update(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
        object_data: &JsonValue,
        actor_id: Option<Uuid>,
    ) -> Result<ApplicationResult> {
        self.apply_on_update_with_time(
            tenant_id,
            object_type,
            object_id,
            object_data,
            actor_id,
            None,
        )
        .await
    }

    /// Apply templates during object modification with optional object creation time.
    ///
    /// The `object_created_at` parameter is used for time constraint evaluation.
    /// If None, the current time is used.
    pub async fn apply_on_update_with_time(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
        object_data: &JsonValue,
        actor_id: Option<Uuid>,
        object_created_at: Option<DateTime<Utc>>,
    ) -> Result<ApplicationResult> {
        // Find applicable templates
        let templates = self
            .scope_service
            .find_applicable_templates(tenant_id, object_type, object_data)
            .await?;

        if templates.is_empty() {
            return Ok(ApplicationResult {
                data: object_data.clone(),
                managed_attributes: HashSet::new(),
                applied_templates: vec![],
                validation_errors: vec![],
                success: true,
            });
        }

        // Apply templates (with update flag and time context)
        let result = self
            .apply_templates_with_time(tenant_id, &templates, object_data, true, object_created_at)
            .await?;

        // Record application events
        for template_id in &result.applied_templates {
            self.record_application_event(
                tenant_id,
                *template_id,
                object_type,
                object_id,
                TemplateOperation::Update,
                &result,
                actor_id,
            )
            .await?;
        }

        info!(
            tenant_id = %tenant_id,
            object_type = ?object_type,
            object_id = %object_id,
            templates_applied = templates.len(),
            success = result.success,
            "Templates applied on update"
        );

        Ok(result)
    }

    /// Apply a list of templates to object data with time constraint filtering.
    async fn apply_templates_with_time(
        &self,
        tenant_id: Uuid,
        templates: &[GovObjectTemplate],
        object_data: &JsonValue,
        is_update: bool,
        object_created_at: Option<DateTime<Utc>>,
    ) -> Result<ApplicationResult> {
        let mut data = object_data.clone();
        let mut managed_attributes = HashSet::new();
        let mut applied_templates = Vec::new();
        let mut all_validation_errors = Vec::new();

        // Current time for time constraint evaluation
        let now = Utc::now();
        let created_at = object_created_at.unwrap_or(now);

        // Collect all rules from all templates, organized by type
        let mut default_rules = Vec::new();
        let mut computed_rules = Vec::new();
        let mut validation_rules = Vec::new();
        let mut normalization_rules = Vec::new();

        for template in templates {
            let rules = self
                .rule_service
                .list_by_template(tenant_id, template.id)
                .await?;

            for rule in rules {
                // Filter by time constraints
                if !self.is_rule_active_at_time(&rule, now, created_at) {
                    continue;
                }

                match rule.rule_type {
                    TemplateRuleType::Default => default_rules.push((template.id, rule)),
                    TemplateRuleType::Computed => computed_rules.push((template.id, rule)),
                    TemplateRuleType::Validation => validation_rules.push((template.id, rule)),
                    TemplateRuleType::Normalization => {
                        normalization_rules.push((template.id, rule));
                    }
                }
            }

            applied_templates.push(template.id);
        }

        // Phase 1: Apply default values
        self.apply_default_rules(
            &mut data,
            &default_rules,
            &mut managed_attributes,
            is_update,
        )?;

        // Phase 2: Apply computed values (may depend on defaults)
        self.apply_computed_rules(&mut data, &computed_rules, &mut managed_attributes)?;

        // Phase 3: Apply normalization
        self.apply_normalization_rules(&mut data, &normalization_rules)?;

        // Phase 4: Validate (after all transformations)
        let validation_errors = self.apply_validation_rules(&data, &validation_rules)?;
        all_validation_errors.extend(validation_errors);

        let success = all_validation_errors.is_empty();

        Ok(ApplicationResult {
            data,
            managed_attributes,
            applied_templates,
            validation_errors: all_validation_errors,
            success,
        })
    }

    /// Check if a rule is active at the given time.
    ///
    /// Supports both absolute time constraints and relative-to-creation constraints.
    fn is_rule_active_at_time(
        &self,
        rule: &GovTemplateRule,
        now: DateTime<Utc>,
        object_created_at: DateTime<Utc>,
    ) -> bool {
        // If no time constraints, rule is always active
        if rule.time_from.is_none() && rule.time_to.is_none() {
            return true;
        }

        let time_ref = rule
            .time_reference
            .unwrap_or(TemplateTimeReference::Absolute);

        // Calculate effective check time based on time reference
        let check_time = match time_ref {
            TemplateTimeReference::Absolute => now,
            TemplateTimeReference::RelativeToCreation => {
                // For relative time, we compare elapsed time since creation
                // The rule's time_from/time_to represent offsets from creation
                now
            }
        };

        // Check time_from constraint
        if let Some(time_from) = rule.time_from {
            let effective_from = match time_ref {
                TemplateTimeReference::Absolute => time_from,
                TemplateTimeReference::RelativeToCreation => {
                    // time_from is stored as an offset (e.g., 30 days from epoch)
                    // Add it to object creation time
                    let offset = time_from.signed_duration_since(DateTime::UNIX_EPOCH);
                    object_created_at + offset
                }
            };
            if check_time < effective_from {
                return false;
            }
        }

        // Check time_to constraint
        if let Some(time_to) = rule.time_to {
            let effective_to = match time_ref {
                TemplateTimeReference::Absolute => time_to,
                TemplateTimeReference::RelativeToCreation => {
                    // time_to is stored as an offset
                    let offset = time_to.signed_duration_since(DateTime::UNIX_EPOCH);
                    object_created_at + offset
                }
            };
            if check_time >= effective_to {
                return false;
            }
        }

        true
    }

    // =========================================================================
    // Rule Application Methods
    // =========================================================================

    /// Apply default value rules.
    fn apply_default_rules(
        &self,
        data: &mut JsonValue,
        rules: &[(Uuid, GovTemplateRule)],
        managed_attributes: &mut HashSet<String>,
        is_update: bool,
    ) -> Result<()> {
        for (_template_id, rule) in rules {
            // Check condition if present
            if !self.evaluate_condition(&rule.condition, data)? {
                continue;
            }

            let target = &rule.target_attribute;
            let current_value = data.get(target);

            // Determine if we should apply this default
            let should_apply = match rule.strength {
                TemplateStrength::Strong => {
                    // Strong always applies (overwrites)
                    true
                }
                TemplateStrength::Normal => {
                    // Normal applies if value is missing or null
                    current_value.is_none() || current_value == Some(&JsonValue::Null)
                }
                TemplateStrength::Weak => {
                    // Weak only applies if value is missing (not even null)
                    current_value.is_none()
                }
            };

            if should_apply {
                // Evaluate the expression
                let value = self.evaluate_expression(&rule.expression, data)?;

                // Set the value
                if let Some(obj) = data.as_object_mut() {
                    obj.insert(target.clone(), value);
                }

                // Track as managed if authoritative
                if rule.authoritative {
                    managed_attributes.insert(target.clone());
                }
            } else if is_update && rule.authoritative && current_value.is_some() {
                // On update: if authoritative and value was removed, we might need to re-apply
                // For now, we let the existing value stay
                managed_attributes.insert(target.clone());
            }
        }

        Ok(())
    }

    /// Apply computed value rules.
    fn apply_computed_rules(
        &self,
        data: &mut JsonValue,
        rules: &[(Uuid, GovTemplateRule)],
        managed_attributes: &mut HashSet<String>,
    ) -> Result<()> {
        // Sort rules by priority (lower number = first)
        let mut sorted_rules: Vec<_> = rules.iter().collect();
        sorted_rules.sort_by_key(|(_, r)| r.priority);

        // Track which attributes have been computed (for dependency ordering)
        let mut computed = HashSet::new();

        // We may need multiple passes for dependency resolution
        let max_iterations = sorted_rules.len() + 1;
        let mut iteration = 0;

        while computed.len() < sorted_rules.len() && iteration < max_iterations {
            let mut made_progress = false;

            for (template_id, rule) in &sorted_rules {
                if computed.contains(&rule.id) {
                    continue;
                }

                // Check condition if present
                if !self.evaluate_condition(&rule.condition, data)? {
                    computed.insert(rule.id);
                    continue;
                }

                // Try to evaluate the expression
                match self.evaluate_expression(&rule.expression, data) {
                    Ok(value) => {
                        let target = &rule.target_attribute;

                        // For computed, strength determines if we override
                        let current_value = data.get(target);
                        let should_apply = match rule.strength {
                            TemplateStrength::Strong => true,
                            TemplateStrength::Normal => {
                                current_value.is_none() || current_value == Some(&JsonValue::Null)
                            }
                            TemplateStrength::Weak => current_value.is_none(),
                        };

                        if should_apply {
                            if let Some(obj) = data.as_object_mut() {
                                obj.insert(target.clone(), value);
                            }
                        }

                        if rule.authoritative {
                            managed_attributes.insert(target.clone());
                        }

                        computed.insert(rule.id);
                        made_progress = true;
                    }
                    Err(e) => {
                        // If error is due to missing attribute, try again next iteration
                        if e.to_string().contains("Unknown attribute") {
                            // Skip for now, might be resolved after other rules run
                        } else {
                            warn!(
                                template_id = %template_id,
                                rule_id = %rule.id,
                                error = %e,
                                "Failed to evaluate computed rule"
                            );
                            computed.insert(rule.id); // Mark as processed to avoid infinite loop
                        }
                    }
                }
            }

            if !made_progress {
                break;
            }

            iteration += 1;
        }

        Ok(())
    }

    /// Apply normalization rules.
    fn apply_normalization_rules(
        &self,
        data: &mut JsonValue,
        rules: &[(Uuid, GovTemplateRule)],
    ) -> Result<()> {
        for (_template_id, rule) in rules {
            // Check condition if present
            if !self.evaluate_condition(&rule.condition, data)? {
                continue;
            }

            let target = &rule.target_attribute;

            // Only normalize if attribute exists
            if data.get(target).is_none() {
                continue;
            }

            // Evaluate the normalization expression
            match self.evaluate_expression(&rule.expression, data) {
                Ok(value) => {
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert(target.clone(), value);
                    }
                }
                Err(e) => {
                    warn!(
                        rule_id = %rule.id,
                        error = %e,
                        "Failed to apply normalization rule"
                    );
                }
            }
        }

        Ok(())
    }

    /// Apply validation rules and collect errors.
    fn apply_validation_rules(
        &self,
        data: &JsonValue,
        rules: &[(Uuid, GovTemplateRule)],
    ) -> Result<Vec<ValidationError>> {
        let mut errors = Vec::new();

        for (template_id, rule) in rules {
            // Check condition if present
            if !self.evaluate_condition(&rule.condition, data)? {
                continue;
            }

            // Evaluate the validation expression
            match self.evaluate_expression(&rule.expression, data) {
                Ok(result) => {
                    // Validation passes if result is truthy
                    let passes = match result {
                        JsonValue::Bool(b) => b,
                        JsonValue::Null => false,
                        JsonValue::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
                        JsonValue::String(s) => !s.is_empty(),
                        _ => true,
                    };

                    if !passes {
                        errors.push(ValidationError {
                            template_id: *template_id,
                            rule_id: rule.id,
                            attribute: rule.target_attribute.clone(),
                            message: rule.error_message.clone().unwrap_or_else(|| {
                                format!(
                                    "Validation failed for attribute '{}'",
                                    rule.target_attribute
                                )
                            }),
                        });
                    }
                }
                Err(e) => {
                    // Expression evaluation error is also a validation failure
                    errors.push(ValidationError {
                        template_id: *template_id,
                        rule_id: rule.id,
                        attribute: rule.target_attribute.clone(),
                        message: format!("Validation error: {e}"),
                    });
                }
            }
        }

        Ok(errors)
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Evaluate a condition expression.
    fn evaluate_condition(&self, condition: &Option<String>, data: &JsonValue) -> Result<bool> {
        match condition {
            None => Ok(true), // No condition means always apply
            Some(expr) => {
                let parsed = self.expression_service.parse(expr).map_err(|e| {
                    GovernanceError::TemplateRuleExpressionError {
                        rule_id: Uuid::nil(),
                        message: format!("Invalid condition: {e}"),
                    }
                })?;

                let context = self.json_to_context(data);
                let result = self
                    .expression_service
                    .evaluate(&parsed, &context)
                    .map_err(|e| GovernanceError::TemplateRuleExpressionError {
                        rule_id: Uuid::nil(),
                        message: format!("Condition evaluation error: {e}"),
                    })?;

                match result {
                    JsonValue::Bool(b) => Ok(b),
                    JsonValue::Null => Ok(false),
                    _ => Err(GovernanceError::TemplateRuleExpressionError {
                        rule_id: Uuid::nil(),
                        message: "Condition must evaluate to boolean".to_string(),
                    }),
                }
            }
        }
    }

    /// Evaluate an expression and return the result.
    fn evaluate_expression(&self, expression: &str, data: &JsonValue) -> Result<JsonValue> {
        let parsed = self.expression_service.parse(expression).map_err(|e| {
            GovernanceError::TemplateRuleExpressionError {
                rule_id: Uuid::nil(),
                message: format!("Invalid expression: {e}"),
            }
        })?;

        let context = self.json_to_context(data);
        self.expression_service
            .evaluate(&parsed, &context)
            .map_err(|e| GovernanceError::TemplateRuleExpressionError {
                rule_id: Uuid::nil(),
                message: e.to_string(),
            })
    }

    /// Convert JSON object to expression context.
    fn json_to_context(&self, data: &JsonValue) -> HashMap<String, JsonValue> {
        let mut context = HashMap::new();
        if let Some(obj) = data.as_object() {
            for (key, value) in obj {
                context.insert(key.clone(), value.clone());
            }
        }
        context
    }

    /// Record an application event.
    #[allow(clippy::too_many_arguments)]
    async fn record_application_event(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
        operation: TemplateOperation,
        result: &ApplicationResult,
        actor_id: Option<Uuid>,
    ) -> Result<()> {
        let validation_errors = if result.validation_errors.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&result.validation_errors).unwrap_or_default())
        };

        GovTemplateApplicationEvent::create(
            &self.pool,
            tenant_id,
            CreateGovTemplateApplicationEvent {
                template_id: Some(template_id),
                template_version_id: None,
                object_type,
                object_id,
                operation,
                rules_applied: serde_json::json!(result.applied_templates),
                changes_made: serde_json::json!(result
                    .managed_attributes
                    .iter()
                    .collect::<Vec<_>>()),
                validation_errors,
                actor_id,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// List application events for a template.
    pub async fn list_events_by_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateApplicationEvent>> {
        GovTemplateApplicationEvent::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List application events for an object.
    pub async fn list_events_by_object(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
        object_id: Uuid,
    ) -> Result<Vec<GovTemplateApplicationEvent>> {
        GovTemplateApplicationEvent::list_by_object(&self.pool, tenant_id, object_type, object_id)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_application_result_default() {
        let result = ApplicationResult {
            data: json!({}),
            managed_attributes: HashSet::new(),
            applied_templates: vec![],
            validation_errors: vec![],
            success: true,
        };

        assert!(result.success);
        assert!(result.applied_templates.is_empty());
        assert!(result.validation_errors.is_empty());
    }

    #[test]
    fn test_validation_error_structure() {
        let error = ValidationError {
            template_id: Uuid::new_v4(),
            rule_id: Uuid::new_v4(),
            attribute: "email".to_string(),
            message: "Invalid email format".to_string(),
        };

        assert_eq!(error.attribute, "email");
        assert!(!error.message.is_empty());
    }
}
