//! Identity Correlation Rule Service (F062).
//!
//! Manages tenant-wide correlation rules for duplicate identity detection.
//! These rules are distinct from F067 connector-scoped correlation rules.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CorrelationRuleFilter, CreateGovCorrelationRule, GovCorrelationRule, GovFuzzyAlgorithm,
    GovMatchType, UpdateGovCorrelationRule,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::duplicate_detection_service::CorrelationRuleConfig;

/// Service for managing identity correlation rules (F062 duplicate detection).
pub struct IdentityCorrelationRuleService {
    pool: PgPool,
}

impl IdentityCorrelationRuleService {
    /// Create a new identity correlation rule service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List correlation rules for a tenant (tenant-wide rules only, no connector scope).
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &CorrelationRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovCorrelationRule>, i64)> {
        // Filter to only tenant-wide rules (connector_id IS NULL)
        let mut tenant_filter = filter.clone();
        tenant_filter.connector_id = None;

        let rules = GovCorrelationRule::list_by_tenant(
            &self.pool,
            tenant_id,
            &tenant_filter,
            limit,
            offset,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = GovCorrelationRule::count_by_tenant(&self.pool, tenant_id, &tenant_filter)
            .await
            .map_err(GovernanceError::Database)?;

        // Filter out connector-scoped rules (return only tenant-wide rules)
        let tenant_wide_rules: Vec<GovCorrelationRule> = rules
            .into_iter()
            .filter(|r| r.connector_id.is_none())
            .collect();

        Ok((tenant_wide_rules, total))
    }

    /// Get a correlation rule by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovCorrelationRule> {
        let rule = GovCorrelationRule::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::CorrelationRuleNotFound(id))?;

        // Ensure it's a tenant-wide rule (not connector-scoped)
        if rule.connector_id.is_some() {
            return Err(GovernanceError::CorrelationRuleNotFound(id));
        }

        Ok(rule)
    }

    /// Create a new correlation rule.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreateGovCorrelationRule,
    ) -> Result<GovCorrelationRule> {
        // Validate the input
        self.validate_rule(
            &input.name,
            input.match_type,
            input.algorithm,
            input.threshold,
            input.weight,
        )?;

        // Ensure connector_id is None (tenant-wide rule)
        let mut input = input;
        input.connector_id = None;

        GovCorrelationRule::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a correlation rule.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovCorrelationRule,
    ) -> Result<GovCorrelationRule> {
        // Ensure the rule exists and is tenant-wide
        let existing = self.get(tenant_id, id).await?;

        // Validate the update
        let name = input.name.as_ref().unwrap_or(&existing.name);
        let algorithm = input.algorithm.or(existing.algorithm);
        let threshold = input.threshold.or(existing.threshold);
        let weight = input.weight.or(Some(existing.weight));

        self.validate_rule(name, existing.match_type, algorithm, threshold, weight)?;

        GovCorrelationRule::update(&self.pool, tenant_id, id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::CorrelationRuleNotFound(id))
    }

    /// Delete a correlation rule.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<bool> {
        // Ensure the rule exists and is tenant-wide
        self.get(tenant_id, id).await?;

        GovCorrelationRule::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get active correlation rules as `CorrelationRuleConfig` for duplicate detection.
    pub async fn get_active_rules_for_detection(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<CorrelationRuleConfig>> {
        let rules = GovCorrelationRule::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        // Filter to only tenant-wide rules and convert to CorrelationRuleConfig
        let configs: Vec<CorrelationRuleConfig> = rules
            .into_iter()
            .filter(|r| r.connector_id.is_none())
            .map(|r| self.to_detection_config(&r))
            .collect();

        Ok(configs)
    }

    /// Convert a `GovCorrelationRule` to a `CorrelationRuleConfig` for detection.
    fn to_detection_config(&self, rule: &GovCorrelationRule) -> CorrelationRuleConfig {
        let fuzzy = matches!(
            rule.match_type,
            GovMatchType::Fuzzy | GovMatchType::Phonetic
        );

        CorrelationRuleConfig {
            id: rule.id,
            name: rule.name.clone(),
            source_field: rule.attribute.clone(),
            target_field: rule.attribute.clone(),
            weight: rule.weight.to_f64().unwrap_or(1.0),
            threshold: rule
                .threshold
                .map_or(0.7, |t| t.to_f64().unwrap_or(0.7)),
            fuzzy,
        }
    }

    /// Validate rule configuration.
    fn validate_rule(
        &self,
        name: &str,
        match_type: GovMatchType,
        algorithm: Option<GovFuzzyAlgorithm>,
        threshold: Option<Decimal>,
        weight: Option<Decimal>,
    ) -> Result<()> {
        // Name must not be empty
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Rule name cannot be empty".to_string(),
            ));
        }

        // Fuzzy rules must have an algorithm
        if matches!(match_type, GovMatchType::Fuzzy) && algorithm.is_none() {
            return Err(GovernanceError::Validation(
                "Fuzzy match rules must specify an algorithm".to_string(),
            ));
        }

        // Threshold must be between 0.0 and 1.0
        if let Some(t) = threshold {
            let t_f64 = t.to_f64().unwrap_or(0.0);
            if !(0.0..=1.0).contains(&t_f64) {
                return Err(GovernanceError::Validation(
                    "Threshold must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        // Weight must be positive
        if let Some(w) = weight {
            let w_f64 = w.to_f64().unwrap_or(0.0);
            if w_f64 <= 0.0 {
                return Err(GovernanceError::Validation(
                    "Weight must be a positive number".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to validate rules without needing a database pool
    fn validate_rule(
        name: &str,
        match_type: GovMatchType,
        algorithm: Option<GovFuzzyAlgorithm>,
        threshold: Option<Decimal>,
        weight: Option<Decimal>,
    ) -> Result<()> {
        // Name must not be empty
        if name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Rule name cannot be empty".to_string(),
            ));
        }

        // Fuzzy rules must have an algorithm
        if matches!(match_type, GovMatchType::Fuzzy) && algorithm.is_none() {
            return Err(GovernanceError::Validation(
                "Fuzzy match rules must specify an algorithm".to_string(),
            ));
        }

        // Threshold must be between 0.0 and 1.0
        if let Some(t) = threshold {
            let t_f64 = t.to_f64().unwrap_or(0.0);
            if !(0.0..=1.0).contains(&t_f64) {
                return Err(GovernanceError::Validation(
                    "Threshold must be between 0.0 and 1.0".to_string(),
                ));
            }
        }

        // Weight must be positive
        if let Some(w) = weight {
            let w_f64 = w.to_f64().unwrap_or(0.0);
            if w_f64 <= 0.0 {
                return Err(GovernanceError::Validation(
                    "Weight must be a positive number".to_string(),
                ));
            }
        }

        Ok(())
    }

    #[test]
    fn test_validate_rule_empty_name() {
        let result = validate_rule(
            "",
            GovMatchType::Exact,
            None,
            None,
            Some(Decimal::new(1, 0)),
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("name cannot be empty"));
    }

    #[test]
    fn test_validate_rule_fuzzy_without_algorithm() {
        let result = validate_rule(
            "test",
            GovMatchType::Fuzzy,
            None,
            Some(Decimal::new(8, 1)),
            Some(Decimal::new(1, 0)),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("algorithm"));
    }

    #[test]
    fn test_validate_rule_invalid_threshold() {
        let result = validate_rule(
            "test",
            GovMatchType::Exact,
            None,
            Some(Decimal::new(15, 1)), // 1.5 - invalid
            Some(Decimal::new(1, 0)),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Threshold"));
    }

    #[test]
    fn test_validate_rule_negative_weight() {
        let result = validate_rule(
            "test",
            GovMatchType::Exact,
            None,
            None,
            Some(Decimal::new(-1, 0)),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Weight"));
    }

    #[test]
    fn test_validate_rule_valid() {
        let result = validate_rule(
            "Email Exact Match",
            GovMatchType::Exact,
            None,
            Some(Decimal::new(9, 1)),  // 0.9
            Some(Decimal::new(50, 0)), // 50
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rule_valid_fuzzy() {
        let result = validate_rule(
            "Name Fuzzy Match",
            GovMatchType::Fuzzy,
            Some(GovFuzzyAlgorithm::JaroWinkler),
            Some(Decimal::new(85, 2)), // 0.85
            Some(Decimal::new(30, 0)), // 30
        );

        assert!(result.is_ok());
    }
}
