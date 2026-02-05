//! Template simulation service for governance API (F058).
//!
//! Simulates template application to preview what would happen when a template
//! is applied to a sample object, WITHOUT actually persisting any changes.
//! This allows administrators to test and validate template configurations
//! before deploying them.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use xavyo_db::models::{GovObjectTemplate, GovTemplateRule, TemplateRuleType};
use xavyo_governance::error::{GovernanceError, Result};

use super::template_expression_service::TemplateExpressionService;

// =========================================================================
// Simulation Result Types
// =========================================================================

/// Result of simulating a template application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// The template that was simulated.
    pub template_id: Uuid,
    /// Results for each rule that was evaluated.
    pub rules_applied: Vec<RuleSimResult>,
    /// Validation errors that would occur.
    pub validation_errors: Vec<SimValidationError>,
    /// Computed values that would be generated.
    pub computed_values: serde_json::Value,
    /// Number of rules that would affect the object.
    pub affected_count: i32,
}

/// Simulation result for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSimResult {
    /// The rule that was simulated.
    pub rule_id: Uuid,
    /// The attribute targeted by this rule.
    pub target_attribute: String,
    /// The type of rule.
    pub rule_type: TemplateRuleType,
    /// The value of the attribute before rule application.
    pub before_value: Option<serde_json::Value>,
    /// The value of the attribute after rule application.
    pub after_value: serde_json::Value,
    /// Whether the rule would be applied.
    pub applied: bool,
    /// Reason for skipping this rule, if not applied.
    pub skip_reason: Option<String>,
}

/// A validation error from simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimValidationError {
    /// The rule that produced the validation error.
    pub rule_id: Uuid,
    /// The attribute being validated.
    pub target_attribute: String,
    /// Human-readable error message.
    pub message: String,
    /// The expression that failed.
    pub expression: String,
}

// =========================================================================
// Template Simulation Service
// =========================================================================

/// Service for simulating template application without persisting changes.
pub struct TemplateSimulationService {
    pool: PgPool,
    expression_service: TemplateExpressionService,
}

impl TemplateSimulationService {
    /// Create a new template simulation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            expression_service: TemplateExpressionService::new(),
        }
    }

    // =========================================================================
    // Simulation Methods
    // =========================================================================

    /// Simulate applying a template to a sample object.
    ///
    /// Loads the template and its rules, then evaluates each rule against the
    /// sample object data without persisting any changes. Returns a detailed
    /// result showing what each rule would do.
    pub async fn simulate_template(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        sample_object: serde_json::Value,
        limit: i32,
    ) -> Result<SimulationResult> {
        // Verify template exists (tenant isolation).
        let _template = GovObjectTemplate::find_by_id(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(template_id))?;

        // Load template rules, sorted by priority.
        let rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Apply limit.
        let rules: Vec<GovTemplateRule> = rules.into_iter().take(limit.max(0) as usize).collect();

        // Run the simulation engine.
        self.simulate_rules(template_id, &rules, &sample_object)
    }

    /// Simulate what would happen if a specific rule were changed or added.
    ///
    /// If `rule_id` is provided with a `new_expression`, simulates modifying that
    /// rule's expression. The sample object is evaluated against all template rules
    /// with the specified change applied.
    pub async fn simulate_rule_change(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        rule_id: Option<Uuid>,
        new_expression: Option<String>,
        sample_object: serde_json::Value,
    ) -> Result<SimulationResult> {
        // Verify template exists (tenant isolation).
        let _template = GovObjectTemplate::find_by_id(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(template_id))?;

        // Load template rules.
        let mut rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Apply the rule change for simulation.
        if let Some(rid) = rule_id {
            if let Some(ref expr) = new_expression {
                let mut found = false;
                for rule in &mut rules {
                    if rule.id == rid {
                        rule.expression = expr.clone();
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(GovernanceError::TemplateRuleNotFound(rid));
                }
            }
        }

        // Run the simulation engine.
        self.simulate_rules(template_id, &rules, &sample_object)
    }

    // =========================================================================
    // Internal Simulation Logic
    // =========================================================================

    /// Simulate applying a set of rules to sample object data.
    ///
    /// Rules are processed in four phases matching template application order:
    /// 1. Default rules - fill in missing attribute values
    /// 2. Computed rules - derive values from expressions
    /// 3. Normalization rules - transform existing values
    /// 4. Validation rules - check constraints, collect errors
    fn simulate_rules(
        &self,
        template_id: Uuid,
        rules: &[GovTemplateRule],
        sample_object: &serde_json::Value,
    ) -> Result<SimulationResult> {
        let mut results = Vec::new();
        let mut validation_errors = Vec::new();
        let mut computed_values = serde_json::Map::new();
        let mut affected_count: i32 = 0;

        // Build a working copy of the object for simulation.
        let mut working_data = sample_object.clone();

        // Partition rules by type while preserving priority order within each group.
        let mut default_rules: Vec<&GovTemplateRule> = Vec::new();
        let mut computed_rules: Vec<&GovTemplateRule> = Vec::new();
        let mut normalization_rules: Vec<&GovTemplateRule> = Vec::new();
        let mut validation_rules: Vec<&GovTemplateRule> = Vec::new();

        for rule in rules {
            match rule.rule_type {
                TemplateRuleType::Default => default_rules.push(rule),
                TemplateRuleType::Computed => computed_rules.push(rule),
                TemplateRuleType::Normalization => normalization_rules.push(rule),
                TemplateRuleType::Validation => validation_rules.push(rule),
            }
        }

        // Phase 1: Default rules.
        for rule in &default_rules {
            self.simulate_default_rule(
                rule,
                &mut working_data,
                &mut results,
                &mut computed_values,
                &mut affected_count,
            );
        }

        // Phase 2: Computed rules.
        for rule in &computed_rules {
            self.simulate_computed_rule(
                rule,
                &mut working_data,
                &mut results,
                &mut computed_values,
                &mut affected_count,
            );
        }

        // Phase 3: Normalization rules.
        for rule in &normalization_rules {
            self.simulate_normalization_rule(
                rule,
                &mut working_data,
                &mut results,
                &mut computed_values,
                &mut affected_count,
            );
        }

        // Phase 4: Validation rules.
        for rule in &validation_rules {
            self.simulate_validation_rule(
                rule,
                &working_data,
                &mut results,
                &mut validation_errors,
            );
        }

        Ok(SimulationResult {
            template_id,
            rules_applied: results,
            validation_errors,
            computed_values: serde_json::Value::Object(computed_values),
            affected_count,
        })
    }

    /// Simulate a default value rule.
    ///
    /// Default rules set an attribute value when it is missing or null.
    /// The expression is parsed as JSON if possible, otherwise treated as a
    /// plain string value.
    fn simulate_default_rule(
        &self,
        rule: &GovTemplateRule,
        working_data: &mut serde_json::Value,
        results: &mut Vec<RuleSimResult>,
        computed_values: &mut serde_json::Map<String, serde_json::Value>,
        affected_count: &mut i32,
    ) {
        let before_value = working_data.get(&rule.target_attribute).cloned();

        // Check condition first.
        if !self.evaluate_condition_safe(&rule.condition, working_data) {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Default,
                before_value,
                after_value: working_data
                    .get(&rule.target_attribute)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                applied: false,
                skip_reason: Some("Condition evaluated to false".to_string()),
            });
            return;
        }

        // Default value applies only if attribute is missing or null.
        let is_missing_or_null =
            before_value.is_none() || before_value.as_ref() == Some(&serde_json::Value::Null);

        if !is_missing_or_null {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Default,
                before_value: before_value.clone(),
                after_value: before_value.unwrap_or(serde_json::Value::Null),
                applied: false,
                skip_reason: Some("Attribute already has a value".to_string()),
            });
            return;
        }

        // Parse the expression as the default value.
        let default_value = self.parse_default_value(&rule.expression);

        // Update working data so subsequent rules see this value.
        if let Some(obj) = working_data.as_object_mut() {
            obj.insert(rule.target_attribute.clone(), default_value.clone());
        }

        computed_values.insert(rule.target_attribute.clone(), default_value.clone());
        *affected_count += 1;

        results.push(RuleSimResult {
            rule_id: rule.id,
            target_attribute: rule.target_attribute.clone(),
            rule_type: TemplateRuleType::Default,
            before_value,
            after_value: default_value,
            applied: true,
            skip_reason: None,
        });
    }

    /// Simulate a computed value rule.
    ///
    /// Computed rules evaluate an expression using the current object data as
    /// context and set the target attribute to the result.
    fn simulate_computed_rule(
        &self,
        rule: &GovTemplateRule,
        working_data: &mut serde_json::Value,
        results: &mut Vec<RuleSimResult>,
        computed_values: &mut serde_json::Map<String, serde_json::Value>,
        affected_count: &mut i32,
    ) {
        let before_value = working_data.get(&rule.target_attribute).cloned();

        // Check condition first.
        if !self.evaluate_condition_safe(&rule.condition, working_data) {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Computed,
                before_value,
                after_value: working_data
                    .get(&rule.target_attribute)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                applied: false,
                skip_reason: Some("Condition evaluated to false".to_string()),
            });
            return;
        }

        let context = self.json_to_context(working_data);

        match self.evaluate_expression(&rule.expression, &context) {
            Ok(value) => {
                // Update working data so subsequent rules see this value.
                if let Some(obj) = working_data.as_object_mut() {
                    obj.insert(rule.target_attribute.clone(), value.clone());
                }

                computed_values.insert(rule.target_attribute.clone(), value.clone());
                *affected_count += 1;

                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Computed,
                    before_value,
                    after_value: value,
                    applied: true,
                    skip_reason: None,
                });
            }
            Err(e) => {
                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Computed,
                    before_value: before_value.clone(),
                    after_value: before_value.unwrap_or(serde_json::Value::Null),
                    applied: false,
                    skip_reason: Some(format!("Expression error: {e}")),
                });
            }
        }
    }

    /// Simulate a validation rule.
    ///
    /// Validation rules evaluate an expression against the object data. If the
    /// result is falsy (false, null, 0, empty string), a validation error is
    /// recorded.
    fn simulate_validation_rule(
        &self,
        rule: &GovTemplateRule,
        working_data: &serde_json::Value,
        results: &mut Vec<RuleSimResult>,
        validation_errors: &mut Vec<SimValidationError>,
    ) {
        let before_value = working_data.get(&rule.target_attribute).cloned();

        // Check condition first.
        if !self.evaluate_condition_safe(&rule.condition, working_data) {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Validation,
                before_value,
                after_value: serde_json::Value::Bool(true),
                applied: false,
                skip_reason: Some("Condition evaluated to false".to_string()),
            });
            return;
        }

        let context = self.json_to_context(working_data);

        match self.evaluate_expression(&rule.expression, &context) {
            Ok(result) => {
                // Validation passes if result is truthy.
                let passes = match &result {
                    serde_json::Value::Bool(b) => *b,
                    serde_json::Value::Null => false,
                    serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
                    serde_json::Value::String(s) => !s.is_empty(),
                    _ => true,
                };

                if !passes {
                    let message = rule.error_message.clone().unwrap_or_else(|| {
                        format!(
                            "Validation failed for attribute '{}'",
                            rule.target_attribute
                        )
                    });
                    validation_errors.push(SimValidationError {
                        rule_id: rule.id,
                        target_attribute: rule.target_attribute.clone(),
                        message,
                        expression: rule.expression.clone(),
                    });
                }

                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Validation,
                    before_value,
                    after_value: result,
                    applied: true,
                    skip_reason: None,
                });
            }
            Err(e) => {
                let message = format!("Validation expression error: {e}");
                validation_errors.push(SimValidationError {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    message,
                    expression: rule.expression.clone(),
                });

                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Validation,
                    before_value,
                    after_value: serde_json::Value::Null,
                    applied: false,
                    skip_reason: Some(format!("Expression error: {e}")),
                });
            }
        }
    }

    /// Simulate a normalization rule.
    ///
    /// Normalization rules transform an existing attribute value (e.g., trimming,
    /// lowercasing). They are only evaluated when the target attribute already
    /// exists in the object.
    fn simulate_normalization_rule(
        &self,
        rule: &GovTemplateRule,
        working_data: &mut serde_json::Value,
        results: &mut Vec<RuleSimResult>,
        computed_values: &mut serde_json::Map<String, serde_json::Value>,
        affected_count: &mut i32,
    ) {
        let before_value = working_data.get(&rule.target_attribute).cloned();

        // Only normalize if attribute exists.
        if before_value.is_none() {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Normalization,
                before_value: None,
                after_value: serde_json::Value::Null,
                applied: false,
                skip_reason: Some("Attribute does not exist, skipping normalization".to_string()),
            });
            return;
        }

        // Check condition.
        if !self.evaluate_condition_safe(&rule.condition, working_data) {
            results.push(RuleSimResult {
                rule_id: rule.id,
                target_attribute: rule.target_attribute.clone(),
                rule_type: TemplateRuleType::Normalization,
                before_value: before_value.clone(),
                after_value: before_value.unwrap_or(serde_json::Value::Null),
                applied: false,
                skip_reason: Some("Condition evaluated to false".to_string()),
            });
            return;
        }

        let context = self.json_to_context(working_data);

        match self.evaluate_expression(&rule.expression, &context) {
            Ok(value) => {
                // Update working data so subsequent rules see this value.
                if let Some(obj) = working_data.as_object_mut() {
                    obj.insert(rule.target_attribute.clone(), value.clone());
                }

                computed_values.insert(rule.target_attribute.clone(), value.clone());
                *affected_count += 1;

                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Normalization,
                    before_value,
                    after_value: value,
                    applied: true,
                    skip_reason: None,
                });
            }
            Err(e) => {
                results.push(RuleSimResult {
                    rule_id: rule.id,
                    target_attribute: rule.target_attribute.clone(),
                    rule_type: TemplateRuleType::Normalization,
                    before_value: before_value.clone(),
                    after_value: before_value.unwrap_or(serde_json::Value::Null),
                    applied: false,
                    skip_reason: Some(format!("Expression error: {e}")),
                });
            }
        }
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Parse a default value expression.
    ///
    /// Attempts to parse the expression as JSON first. If that fails,
    /// treats it as a plain string value.
    fn parse_default_value(&self, expression: &str) -> serde_json::Value {
        serde_json::from_str(expression)
            .unwrap_or_else(|_| serde_json::Value::String(expression.to_string()))
    }

    /// Evaluate a condition expression, returning `true` when there is no
    /// condition or when the condition evaluates to a truthy value.
    ///
    /// Expression errors are treated as `false` (i.e., the rule is skipped).
    fn evaluate_condition_safe(
        &self,
        condition: &Option<String>,
        data: &serde_json::Value,
    ) -> bool {
        let expr_str = match condition {
            None => return true,
            Some(s) if s.is_empty() => return true,
            Some(s) => s,
        };

        let parsed = match self.expression_service.parse(expr_str) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let context = self.json_to_context(data);
        match self.expression_service.evaluate(&parsed, &context) {
            Ok(serde_json::Value::Bool(b)) => b,
            Ok(serde_json::Value::Null) => false,
            _ => false,
        }
    }

    /// Evaluate an expression using the expression service.
    fn evaluate_expression(
        &self,
        expression: &str,
        context: &HashMap<String, serde_json::Value>,
    ) -> std::result::Result<serde_json::Value, String> {
        let parsed = self
            .expression_service
            .parse(expression)
            .map_err(|e| e.to_string())?;

        self.expression_service
            .evaluate(&parsed, context)
            .map_err(|e| e.to_string())
    }

    /// Convert a JSON object to an expression evaluation context.
    fn json_to_context(&self, data: &serde_json::Value) -> HashMap<String, serde_json::Value> {
        let mut context = HashMap::new();
        if let Some(obj) = data.as_object() {
            for (key, value) in obj {
                context.insert(key.clone(), value.clone());
            }
        }
        context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simulation_result_construction() {
        let template_id = Uuid::new_v4();
        let rule_id = Uuid::new_v4();

        let result = SimulationResult {
            template_id,
            rules_applied: vec![RuleSimResult {
                rule_id,
                target_attribute: "email".to_string(),
                rule_type: TemplateRuleType::Default,
                before_value: None,
                after_value: json!("user@example.com"),
                applied: true,
                skip_reason: None,
            }],
            validation_errors: vec![],
            computed_values: json!({"email": "user@example.com"}),
            affected_count: 1,
        };

        assert_eq!(result.template_id, template_id);
        assert_eq!(result.rules_applied.len(), 1);
        assert!(result.validation_errors.is_empty());
        assert_eq!(result.affected_count, 1);

        let rule_result = &result.rules_applied[0];
        assert_eq!(rule_result.rule_id, rule_id);
        assert_eq!(rule_result.target_attribute, "email");
        assert!(rule_result.applied);
        assert!(rule_result.skip_reason.is_none());
        assert_eq!(rule_result.before_value, None);
        assert_eq!(rule_result.after_value, json!("user@example.com"));
    }

    #[test]
    fn test_sim_validation_error_construction() {
        let rule_id = Uuid::new_v4();

        let error = SimValidationError {
            rule_id,
            target_attribute: "email".to_string(),
            message: "Email must contain @".to_string(),
            expression: "contains(${email}, \"@\")".to_string(),
        };

        assert_eq!(error.rule_id, rule_id);
        assert_eq!(error.target_attribute, "email");
        assert_eq!(error.message, "Email must contain @");
        assert_eq!(error.expression, "contains(${email}, \"@\")");

        // Verify serialization works.
        let serialized = serde_json::to_value(&error).unwrap();
        assert_eq!(serialized["target_attribute"], "email");
        assert_eq!(serialized["message"], "Email must contain @");
    }
}
