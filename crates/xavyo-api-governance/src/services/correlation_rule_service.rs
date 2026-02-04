//! Correlation Rule Service for the Correlation Engine (F067).
//!
//! Manages CRUD operations for correlation rules scoped to a connector,
//! including weight validation, match type mapping, and expression validation.

use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::{
    CorrelationRuleFilter, CreateGovCorrelationRule, GovCorrelationRule, GovFuzzyAlgorithm,
    GovMatchType, UpdateGovCorrelationRule,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::correlation::{
    CorrelationRuleListResponse, CorrelationRuleResponse, CreateCorrelationRuleRequest,
    ListCorrelationRulesQuery, UpdateCorrelationRuleRequest, ValidateExpressionRequest,
    ValidateExpressionResponse,
};

/// Service for managing correlation rules.
pub struct CorrelationRuleService {
    pool: PgPool,
}

impl CorrelationRuleService {
    /// Create a new correlation rule service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// List correlation rules for a connector with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        query: &ListCorrelationRulesQuery,
    ) -> Result<CorrelationRuleListResponse> {
        let match_type_filter = match &query.match_type {
            Some(mt) => Some(parse_match_type(mt)?),
            None => None,
        };

        let filter = CorrelationRuleFilter {
            match_type: match_type_filter,
            is_active: query.is_active,
            attribute: None,
            connector_id: Some(connector_id),
            tier: query.tier,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let rules = GovCorrelationRule::list_by_connector(
            &self.pool,
            tenant_id,
            connector_id,
            &filter,
            limit,
            offset,
        )
        .await?;

        let total =
            GovCorrelationRule::count_by_connector(&self.pool, tenant_id, connector_id, &filter)
                .await?;

        Ok(CorrelationRuleListResponse {
            items: rules.into_iter().map(rule_to_response).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Get a single correlation rule by ID, verifying it belongs to the connector.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        id: Uuid,
    ) -> Result<CorrelationRuleResponse> {
        let rule = GovCorrelationRule::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::CorrelationRuleNotFound(id))?;

        // Verify the rule belongs to the requested connector.
        if rule.connector_id != Some(connector_id) {
            return Err(GovernanceError::CorrelationRuleNotFound(id));
        }

        Ok(rule_to_response(rule))
    }

    /// Create a new correlation rule for a connector.
    ///
    /// Validates that the total weight of all active rules for the connector
    /// does not exceed 1.0 after adding the new rule.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        request: CreateCorrelationRuleRequest,
    ) -> Result<CorrelationRuleResponse> {
        let match_type = parse_match_type(&request.match_type)?;
        let algorithm = parse_algorithm(request.algorithm.as_deref(), match_type)?;

        let weight = Decimal::try_from(request.weight)
            .map_err(|_| GovernanceError::InvalidCorrelationWeight(request.weight))?;

        // Validate total weight does not exceed 1.0.
        let current_sum = GovCorrelationRule::total_weight_by_connector(
            &self.pool,
            tenant_id,
            connector_id,
            None,
        )
        .await?;

        let max_weight = Decimal::new(1, 0); // 1.0
        if current_sum + weight > max_weight {
            return Err(GovernanceError::Validation(format!(
                "Total weight for connector rules would exceed 1.0: current sum is {}, adding {} would make {}",
                current_sum, weight, current_sum + weight
            )));
        }

        let threshold = request
            .threshold
            .map(|t| {
                Decimal::try_from(t).map_err(|_| GovernanceError::InvalidCorrelationThreshold(t))
            })
            .transpose()?;

        let input = CreateGovCorrelationRule {
            name: request.name,
            attribute: request.source_attribute.clone(),
            match_type,
            algorithm,
            threshold,
            weight: Some(weight),
            priority: request.priority,
            connector_id: Some(connector_id),
            source_attribute: Some(request.source_attribute),
            target_attribute: Some(request.target_attribute),
            expression: request.expression,
            tier: request.tier,
            is_definitive: request.is_definitive,
            normalize: request.normalize,
        };

        let rule = GovCorrelationRule::create(&self.pool, tenant_id, input).await?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            rule_id = %rule.id,
            rule_name = %rule.name,
            match_type = ?rule.match_type,
            "Correlation rule created"
        );

        Ok(rule_to_response(rule))
    }

    /// Update an existing correlation rule.
    ///
    /// If the weight changes, validates that the total weight of all active rules
    /// for the connector does not exceed 1.0 (excluding the current rule).
    pub async fn update(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        id: Uuid,
        request: UpdateCorrelationRuleRequest,
    ) -> Result<CorrelationRuleResponse> {
        // Verify the rule exists and belongs to this connector.
        let existing = GovCorrelationRule::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::CorrelationRuleNotFound(id))?;

        if existing.connector_id != Some(connector_id) {
            return Err(GovernanceError::CorrelationRuleNotFound(id));
        }

        // Validate weight if it is being changed.
        let new_weight = if let Some(w) = request.weight {
            let weight =
                Decimal::try_from(w).map_err(|_| GovernanceError::InvalidCorrelationWeight(w))?;

            let current_sum_excluding = GovCorrelationRule::total_weight_by_connector(
                &self.pool,
                tenant_id,
                connector_id,
                Some(id),
            )
            .await?;

            let max_weight = Decimal::new(1, 0);
            if current_sum_excluding + weight > max_weight {
                return Err(GovernanceError::Validation(format!(
                    "Total weight for connector rules would exceed 1.0: current sum (excluding this rule) is {}, new weight {} would make {}",
                    current_sum_excluding, weight, current_sum_excluding + weight
                )));
            }

            Some(weight)
        } else {
            None
        };

        let threshold = request
            .threshold
            .map(|t| {
                Decimal::try_from(t).map_err(|_| GovernanceError::InvalidCorrelationThreshold(t))
            })
            .transpose()?;

        let input = UpdateGovCorrelationRule {
            name: request.name,
            algorithm: match &request.match_type {
                Some(mt) => {
                    let mt_parsed = parse_match_type(mt)?;
                    parse_algorithm(request.algorithm.as_deref(), mt_parsed)?
                }
                None => match request.algorithm.as_deref() {
                    Some(alg) => parse_algorithm_string(alg)?,
                    None => None,
                },
            },
            threshold,
            weight: new_weight,
            is_active: request.is_active,
            priority: request.priority,
            source_attribute: request.source_attribute,
            target_attribute: request.target_attribute,
            expression: request.expression,
            tier: request.tier,
            is_definitive: request.is_definitive,
            normalize: request.normalize,
        };

        let rule = GovCorrelationRule::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::CorrelationRuleNotFound(id))?;

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            rule_id = %id,
            "Correlation rule updated"
        );

        Ok(rule_to_response(rule))
    }

    /// Delete a correlation rule.
    pub async fn delete(&self, tenant_id: Uuid, connector_id: Uuid, id: Uuid) -> Result<()> {
        // Verify the rule exists and belongs to this connector.
        let existing = GovCorrelationRule::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::CorrelationRuleNotFound(id))?;

        if existing.connector_id != Some(connector_id) {
            return Err(GovernanceError::CorrelationRuleNotFound(id));
        }

        let deleted = GovCorrelationRule::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(GovernanceError::CorrelationRuleNotFound(id));
        }

        tracing::info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            rule_id = %id,
            "Correlation rule deleted"
        );

        Ok(())
    }

    /// Validate a correlation expression with optional test input evaluation.
    ///
    /// Performs syntax validation (balanced brackets/parentheses) and, if test
    /// input is provided, evaluates the expression against the test data to show
    /// the transformed output. This powers the POST /validate-expression endpoint.
    ///
    /// ## Test Input Format
    ///
    /// When `test_input` is provided, it should contain `source` and `target`
    /// string values:
    /// ```json
    /// {
    ///   "source": "alice@example.com",
    ///   "target": "alice"
    /// }
    /// ```
    ///
    /// The expression is evaluated using the built-in pattern matcher which
    /// supports common patterns like `source.split("@")[0]`, `source.replace("-", "")`,
    /// and `source.substring(0, N)`.
    pub fn validate_expression(
        &self,
        request: ValidateExpressionRequest,
    ) -> Result<ValidateExpressionResponse> {
        let expression = request.expression.trim();

        if expression.is_empty() {
            return Ok(ValidateExpressionResponse {
                valid: false,
                result: None,
                error: Some("Expression cannot be empty".to_string()),
            });
        }

        // Basic syntax validation: check balanced delimiters.
        if let Err(msg) = validate_expression_syntax(expression) {
            return Ok(ValidateExpressionResponse {
                valid: false,
                result: None,
                error: Some(msg),
            });
        }

        // If test_input is provided, evaluate the expression with test data.
        if let Some(test_input) = &request.test_input {
            let source = test_input
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let target = test_input
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if source.is_empty() && target.is_empty() {
                return Ok(ValidateExpressionResponse {
                    valid: true,
                    result: Some("Expression syntax is valid (no test data provided)".to_string()),
                    error: None,
                });
            }

            // Evaluate using the built-in expression evaluator.
            let score = evaluate_test_expression(expression, source, target);

            return Ok(ValidateExpressionResponse {
                valid: true,
                result: Some(format!(
                    "Expression evaluated successfully. Source: '{source}', Target: '{target}', Match score: {score:.4}"
                )),
                error: None,
            });
        }

        Ok(ValidateExpressionResponse {
            valid: true,
            result: Some("Expression syntax is valid".to_string()),
            error: None,
        })
    }
}

// =============================================================================
// Helper functions
// =============================================================================

/// Convert a `GovCorrelationRule` database model into a `CorrelationRuleResponse`.
fn rule_to_response(rule: GovCorrelationRule) -> CorrelationRuleResponse {
    CorrelationRuleResponse {
        id: rule.id,
        tenant_id: rule.tenant_id,
        connector_id: rule.connector_id,
        name: rule.name,
        source_attribute: rule.source_attribute,
        target_attribute: rule.target_attribute,
        match_type: format!("{:?}", rule.match_type).to_lowercase(),
        algorithm: rule.algorithm.map(|a| match a {
            GovFuzzyAlgorithm::Levenshtein => "levenshtein".to_string(),
            GovFuzzyAlgorithm::JaroWinkler => "jaro_winkler".to_string(),
            GovFuzzyAlgorithm::Soundex => "soundex".to_string(),
        }),
        threshold: rule
            .threshold
            .map(|t| t.to_string().parse::<f64>().unwrap_or(0.0)),
        weight: rule.weight.to_string().parse::<f64>().unwrap_or(0.0),
        expression: rule.expression,
        tier: rule.tier,
        is_definitive: rule.is_definitive,
        normalize: rule.normalize,
        is_active: rule.is_active,
        priority: rule.priority,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }
}

/// Parse a match type string into a `GovMatchType` enum value.
fn parse_match_type(s: &str) -> Result<GovMatchType> {
    match s.to_lowercase().as_str() {
        "exact" => Ok(GovMatchType::Exact),
        "fuzzy" => Ok(GovMatchType::Fuzzy),
        "phonetic" => Ok(GovMatchType::Phonetic),
        "expression" => Ok(GovMatchType::Expression),
        other => Err(GovernanceError::Validation(format!(
            "Invalid match type '{other}'. Must be one of: exact, fuzzy, phonetic, expression"
        ))),
    }
}

/// Parse an algorithm string into a `GovFuzzyAlgorithm` enum value.
///
/// Returns `None` if the input is `None` or empty. Only required for fuzzy match type.
fn parse_algorithm(
    algorithm: Option<&str>,
    match_type: GovMatchType,
) -> Result<Option<GovFuzzyAlgorithm>> {
    match algorithm {
        Some(alg) if !alg.is_empty() => parse_algorithm_string(alg),
        _ => {
            if match_type == GovMatchType::Fuzzy {
                // Fuzzy match type should have an algorithm, but it's not strictly required
                // at the DB level; the engine will default.
                Ok(None)
            } else {
                Ok(None)
            }
        }
    }
}

/// Parse an algorithm string into a `GovFuzzyAlgorithm`.
fn parse_algorithm_string(s: &str) -> Result<Option<GovFuzzyAlgorithm>> {
    match s.to_lowercase().as_str() {
        "levenshtein" => Ok(Some(GovFuzzyAlgorithm::Levenshtein)),
        "jaro_winkler" => Ok(Some(GovFuzzyAlgorithm::JaroWinkler)),
        "soundex" => Ok(Some(GovFuzzyAlgorithm::Soundex)),
        other => Err(GovernanceError::Validation(format!(
            "Invalid algorithm '{other}'. Must be one of: levenshtein, jaro_winkler, soundex"
        ))),
    }
}

/// Perform basic syntax validation on a correlation expression.
///
/// Checks for balanced parentheses, brackets, and braces, as well as
/// basic structural validity (non-empty, no dangling operators).
fn validate_expression_syntax(expression: &str) -> std::result::Result<(), String> {
    let mut stack: Vec<char> = Vec::new();

    for (i, ch) in expression.chars().enumerate() {
        match ch {
            '(' | '[' | '{' => stack.push(ch),
            ')' => {
                if stack.pop() != Some('(') {
                    return Err(format!(
                        "Unmatched closing parenthesis ')' at position {i}"
                    ));
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return Err(format!("Unmatched closing bracket ']' at position {i}"));
                }
            }
            '}' => {
                if stack.pop() != Some('{') {
                    return Err(format!("Unmatched closing brace '}}' at position {i}"));
                }
            }
            _ => {}
        }
    }

    if !stack.is_empty() {
        let unclosed: String = stack.into_iter().collect();
        return Err(format!("Unclosed delimiters: {unclosed}"));
    }

    // Check for obvious structural issues: expression ending with an operator.
    let trimmed = expression.trim();
    if trimmed.ends_with('+')
        || trimmed.ends_with('-')
        || trimmed.ends_with('*')
        || trimmed.ends_with('/')
        || trimmed.ends_with("==")
        || trimmed.ends_with("!=")
    {
        return Err("Expression ends with a dangling operator".to_string());
    }

    Ok(())
}

/// Evaluate a test expression against source and target values.
///
/// This is a simplified expression evaluator for the validate endpoint.
/// It supports common patterns like email local-part extraction, substring,
/// replace, and concatenation. Returns a match score (0.0 or 1.0).
fn evaluate_test_expression(expression: &str, source: &str, target: &str) -> f64 {
    let expr_lower = expression.to_lowercase();

    // Pattern: email local-part extraction
    if expr_lower.contains("split") && expression.contains('@') {
        let source_local = source.split('@').next().unwrap_or(source);
        let target_local = target.split('@').next().unwrap_or(target);
        return if source_local.eq_ignore_ascii_case(target_local) {
            1.0
        } else {
            0.0
        };
    }

    // Pattern: substring
    if expr_lower.contains("substring") {
        if let Some(len_str) = expression
            .split(',')
            .nth(1)
            .and_then(|s| s.trim().trim_end_matches(')').trim().parse::<usize>().ok())
        {
            let source_sub: String = source.chars().take(len_str).collect();
            let target_sub: String = target.chars().take(len_str).collect();
            return if source_sub.eq_ignore_ascii_case(&target_sub) {
                1.0
            } else {
                0.0
            };
        }
    }

    // Pattern: replace
    if expr_lower.contains("replace") {
        if let Some(start) = expression.find("replace(\"") {
            let after = &expression[start + 9..];
            if let Some(end) = after.find('"') {
                let to_remove = &after[..end];
                let source_clean = source.replace(to_remove, "");
                let target_clean = target.replace(to_remove, "");
                return if source_clean.eq_ignore_ascii_case(&target_clean) {
                    1.0
                } else {
                    0.0
                };
            }
        }
    }

    // Pattern: to_lower
    if expr_lower.contains("to_lower") || expr_lower.contains("tolower") {
        return if source.eq_ignore_ascii_case(target) {
            1.0
        } else {
            0.0
        };
    }

    // Fallback: exact comparison
    if source.eq_ignore_ascii_case(target) {
        1.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_match_type_valid() {
        assert_eq!(parse_match_type("exact").unwrap(), GovMatchType::Exact);
        assert_eq!(parse_match_type("fuzzy").unwrap(), GovMatchType::Fuzzy);
        assert_eq!(
            parse_match_type("phonetic").unwrap(),
            GovMatchType::Phonetic
        );
        assert_eq!(
            parse_match_type("expression").unwrap(),
            GovMatchType::Expression
        );
        // Case insensitive.
        assert_eq!(parse_match_type("Exact").unwrap(), GovMatchType::Exact);
        assert_eq!(parse_match_type("FUZZY").unwrap(), GovMatchType::Fuzzy);
    }

    #[test]
    fn test_parse_match_type_invalid() {
        assert!(parse_match_type("invalid").is_err());
        assert!(parse_match_type("").is_err());
    }

    #[test]
    fn test_parse_algorithm_string_valid() {
        assert_eq!(
            parse_algorithm_string("levenshtein").unwrap(),
            Some(GovFuzzyAlgorithm::Levenshtein)
        );
        assert_eq!(
            parse_algorithm_string("jaro_winkler").unwrap(),
            Some(GovFuzzyAlgorithm::JaroWinkler)
        );
        assert_eq!(
            parse_algorithm_string("soundex").unwrap(),
            Some(GovFuzzyAlgorithm::Soundex)
        );
    }

    #[test]
    fn test_parse_algorithm_string_invalid() {
        assert!(parse_algorithm_string("unknown").is_err());
    }

    #[test]
    fn test_parse_algorithm_none_for_exact() {
        let result = parse_algorithm(None, GovMatchType::Exact).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_algorithm_none_for_fuzzy() {
        let result = parse_algorithm(None, GovMatchType::Fuzzy).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_expression_syntax_valid() {
        assert!(validate_expression_syntax("source.email").is_ok());
        assert!(validate_expression_syntax("source.split(\"@\")[0]").is_ok());
        assert!(validate_expression_syntax("(a + b) * c").is_ok());
        assert!(validate_expression_syntax("{key: value}").is_ok());
    }

    #[test]
    fn test_validate_expression_syntax_unmatched() {
        assert!(validate_expression_syntax("(unclosed").is_err());
        assert!(validate_expression_syntax("[unclosed").is_err());
        assert!(validate_expression_syntax("{unclosed").is_err());
        assert!(validate_expression_syntax("extra)").is_err());
    }

    #[test]
    fn test_validate_expression_syntax_dangling_operator() {
        assert!(validate_expression_syntax("a +").is_err());
        assert!(validate_expression_syntax("a -").is_err());
        assert!(validate_expression_syntax("a ==").is_err());
    }

    #[test]
    fn test_rule_to_response_mapping() {
        let rule = GovCorrelationRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Email Match".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Exact,
            algorithm: None,
            threshold: None,
            weight: Decimal::new(50, 2), // 0.50
            is_active: true,
            priority: 100,
            connector_id: Some(Uuid::new_v4()),
            source_attribute: Some("email".to_string()),
            target_attribute: Some("mail".to_string()),
            expression: None,
            tier: Some(1),
            is_definitive: false,
            normalize: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let response = rule_to_response(rule.clone());

        assert_eq!(response.id, rule.id);
        assert_eq!(response.tenant_id, rule.tenant_id);
        assert_eq!(response.connector_id, rule.connector_id);
        assert_eq!(response.name, "Email Match");
        assert_eq!(response.source_attribute, Some("email".to_string()));
        assert_eq!(response.target_attribute, Some("mail".to_string()));
        assert_eq!(response.match_type, "exact");
        assert!(response.algorithm.is_none());
        assert!(response.threshold.is_none());
        assert!((response.weight - 0.50).abs() < f64::EPSILON);
        assert_eq!(response.tier, Some(1));
        assert!(!response.is_definitive);
        assert!(response.normalize);
        assert!(response.is_active);
        assert_eq!(response.priority, 100);
    }

    #[test]
    fn test_rule_to_response_with_algorithm() {
        let rule = GovCorrelationRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Name Fuzzy".to_string(),
            attribute: "display_name".to_string(),
            match_type: GovMatchType::Fuzzy,
            algorithm: Some(GovFuzzyAlgorithm::JaroWinkler),
            threshold: Some(Decimal::new(85, 2)), // 0.85
            weight: Decimal::new(30, 2),          // 0.30
            is_active: true,
            priority: 50,
            connector_id: Some(Uuid::new_v4()),
            source_attribute: Some("display_name".to_string()),
            target_attribute: Some("cn".to_string()),
            expression: None,
            tier: Some(2),
            is_definitive: false,
            normalize: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let response = rule_to_response(rule);

        assert_eq!(response.match_type, "fuzzy");
        assert_eq!(response.algorithm, Some("jaro_winkler".to_string()));
        assert!((response.threshold.unwrap() - 0.85).abs() < f64::EPSILON);
        assert!((response.weight - 0.30).abs() < f64::EPSILON);
    }

    #[test]
    fn test_correlation_rule_service_creation() {
        // Verifies the type compiles correctly.
        // Actual service tests would require a database connection.
    }
}
