//! Governance Correlation Rule model.
//!
//! Represents rules for detecting potential duplicate identities (F062)
//! and for correlating target system accounts to identities (F067).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Match type for correlation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_match_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovMatchType {
    /// Exact string match.
    Exact,
    /// Fuzzy similarity match using algorithms.
    Fuzzy,
    /// Phonetic matching (e.g., Soundex).
    Phonetic,
    /// Expression-based matching via Rhai scripts (F067).
    Expression,
}

/// Fuzzy matching algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_fuzzy_algorithm", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum GovFuzzyAlgorithm {
    /// Levenshtein edit distance.
    Levenshtein,
    /// Jaro-Winkler similarity (favors prefix matches).
    JaroWinkler,
    /// Soundex phonetic encoding.
    Soundex,
}

/// A governance correlation rule for duplicate detection (F062) and
/// account-to-identity correlation (F067).
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCorrelationRule {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// Rule display name.
    pub name: String,

    /// Identity attribute to compare (F062 duplicate detection).
    pub attribute: String,

    /// Type of matching to apply.
    pub match_type: GovMatchType,

    /// For fuzzy matching: which algorithm to use.
    pub algorithm: Option<GovFuzzyAlgorithm>,

    /// Minimum similarity threshold (0.00-1.00) for fuzzy matches.
    pub threshold: Option<rust_decimal::Decimal>,

    /// Weight for confidence score calculation.
    pub weight: rust_decimal::Decimal,

    /// Whether the rule is active.
    pub is_active: bool,

    /// Processing priority (higher = first).
    pub priority: i32,

    // --- F067 fields ---
    /// Connector this rule is scoped to (NULL = tenant-wide F062 rule).
    pub connector_id: Option<Uuid>,

    /// Source attribute on the identity side (F067).
    pub source_attribute: Option<String>,

    /// Target attribute on the account side (F067).
    pub target_attribute: Option<String>,

    /// Rhai expression for expression-based matching (F067).
    pub expression: Option<String>,

    /// Evaluation tier for multi-pass correlation (F067).
    pub tier: Option<i32>,

    /// Whether a match on this rule definitively confirms identity (F067).
    pub is_definitive: bool,

    /// Whether to normalize attribute values before comparison (F067).
    pub normalize: bool,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovCorrelationRule {
    pub name: String,
    pub attribute: String,
    pub match_type: GovMatchType,
    pub algorithm: Option<GovFuzzyAlgorithm>,
    pub threshold: Option<rust_decimal::Decimal>,
    pub weight: Option<rust_decimal::Decimal>,
    pub priority: Option<i32>,
    // F067 fields
    pub connector_id: Option<Uuid>,
    pub source_attribute: Option<String>,
    pub target_attribute: Option<String>,
    pub expression: Option<String>,
    pub tier: Option<i32>,
    pub is_definitive: Option<bool>,
    pub normalize: Option<bool>,
}

/// Request to update a correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovCorrelationRule {
    pub name: Option<String>,
    pub algorithm: Option<GovFuzzyAlgorithm>,
    pub threshold: Option<rust_decimal::Decimal>,
    pub weight: Option<rust_decimal::Decimal>,
    pub is_active: Option<bool>,
    pub priority: Option<i32>,
    // F067 fields
    pub source_attribute: Option<String>,
    pub target_attribute: Option<String>,
    pub expression: Option<String>,
    pub tier: Option<i32>,
    pub is_definitive: Option<bool>,
    pub normalize: Option<bool>,
}

/// Filter options for listing correlation rules.
#[derive(Debug, Clone, Default)]
pub struct CorrelationRuleFilter {
    pub match_type: Option<GovMatchType>,
    pub is_active: Option<bool>,
    pub attribute: Option<String>,
    /// Filter by connector (F067). None = no filter, Some(None) = tenant-wide only.
    pub connector_id: Option<Uuid>,
    /// Filter by evaluation tier (F067).
    pub tier: Option<i32>,
}

impl GovCorrelationRule {
    /// Find a rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a rule by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List active rules for a tenant ordered by priority (F062 tenant-wide rules).
    pub async fn list_active(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE tenant_id = $1 AND is_active = true
            ORDER BY priority DESC, created_at ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// List active rules for a specific connector, ordered by tier then priority (F067).
    pub async fn list_active_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE tenant_id = $1 AND connector_id = $2 AND is_active = true
            ORDER BY COALESCE(tier, 0) ASC, priority DESC, created_at ASC
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_all(pool)
        .await
    }

    /// List rules for a specific connector with filtering and pagination (F067).
    pub async fn list_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        filter: &CorrelationRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.match_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND match_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.tier.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND tier = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY COALESCE(tier, 0) ASC, priority DESC, created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovCorrelationRule>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(match_type) = filter.match_type {
            q = q.bind(match_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(tier) = filter.tier {
            q = q.bind(tier);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count rules for a specific connector with filtering (F067).
    pub async fn count_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        filter: &CorrelationRuleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_correlation_rules
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        );
        let mut param_count = 2;

        if filter.match_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND match_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.tier.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND tier = ${param_count}"));
        }

        let _ = param_count;

        let mut q = sqlx::query_scalar::<_, i64>(&query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(match_type) = filter.match_type {
            q = q.bind(match_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(tier) = filter.tier {
            q = q.bind(tier);
        }

        q.fetch_one(pool).await
    }

    /// List rules for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_correlation_rules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.match_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND match_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.attribute.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attribute = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY priority DESC, created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovCorrelationRule>(&query).bind(tenant_id);

        if let Some(match_type) = filter.match_type {
            q = q.bind(match_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(ref attribute) = filter.attribute {
            q = q.bind(attribute);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count rules in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &CorrelationRuleFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_correlation_rules
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.match_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND match_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.attribute.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attribute = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(match_type) = filter.match_type {
            q = q.bind(match_type);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(ref attribute) = filter.attribute {
            q = q.bind(attribute);
        }

        q.fetch_one(pool).await
    }

    /// Create a new correlation rule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovCorrelationRule,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_correlation_rules (
                tenant_id, name, attribute, match_type, algorithm, threshold, weight, priority,
                connector_id, source_attribute, target_attribute, expression, tier,
                is_definitive, normalize
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, COALESCE($7, 1.0), COALESCE($8, 0),
                $9, $10, $11, $12, $13,
                COALESCE($14, false), COALESCE($15, true)
            )
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.attribute)
        .bind(input.match_type)
        .bind(input.algorithm)
        .bind(input.threshold)
        .bind(input.weight)
        .bind(input.priority)
        .bind(input.connector_id)
        .bind(&input.source_attribute)
        .bind(&input.target_attribute)
        .bind(&input.expression)
        .bind(input.tier)
        .bind(input.is_definitive)
        .bind(input.normalize)
        .fetch_one(pool)
        .await
    }

    /// Update a correlation rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGovCorrelationRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.algorithm.is_some() {
            updates.push(format!("algorithm = ${param_idx}"));
            param_idx += 1;
        }
        if input.threshold.is_some() {
            updates.push(format!("threshold = ${param_idx}"));
            param_idx += 1;
        }
        if input.weight.is_some() {
            updates.push(format!("weight = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${param_idx}"));
            param_idx += 1;
        }
        if input.priority.is_some() {
            updates.push(format!("priority = ${param_idx}"));
            param_idx += 1;
        }
        // F067 fields
        if input.source_attribute.is_some() {
            updates.push(format!("source_attribute = ${param_idx}"));
            param_idx += 1;
        }
        if input.target_attribute.is_some() {
            updates.push(format!("target_attribute = ${param_idx}"));
            param_idx += 1;
        }
        if input.expression.is_some() {
            updates.push(format!("expression = ${param_idx}"));
            param_idx += 1;
        }
        if input.tier.is_some() {
            updates.push(format!("tier = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_definitive.is_some() {
            updates.push(format!("is_definitive = ${param_idx}"));
            param_idx += 1;
        }
        if input.normalize.is_some() {
            updates.push(format!("normalize = ${param_idx}"));
        }

        let query = format!(
            "UPDATE gov_correlation_rules SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, GovCorrelationRule>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(algorithm) = input.algorithm {
            q = q.bind(algorithm);
        }
        if let Some(threshold) = input.threshold {
            q = q.bind(threshold);
        }
        if let Some(weight) = input.weight {
            q = q.bind(weight);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        // F067 fields
        if let Some(ref source_attribute) = input.source_attribute {
            q = q.bind(source_attribute);
        }
        if let Some(ref target_attribute) = input.target_attribute {
            q = q.bind(target_attribute);
        }
        if let Some(ref expression) = input.expression {
            q = q.bind(expression);
        }
        if let Some(tier) = input.tier {
            q = q.bind(tier);
        }
        if let Some(is_definitive) = input.is_definitive {
            q = q.bind(is_definitive);
        }
        if let Some(normalize) = input.normalize {
            q = q.bind(normalize);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a correlation rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_correlation_rules
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Sum of weights for all active rules of a specific connector (F067).
    pub async fn total_weight_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        exclude_rule_id: Option<Uuid>,
    ) -> Result<rust_decimal::Decimal, sqlx::Error> {
        let query = if exclude_rule_id.is_some() {
            r"
            SELECT COALESCE(SUM(weight), 0) FROM gov_correlation_rules
            WHERE tenant_id = $1 AND connector_id = $2 AND is_active = true AND id != $3
            "
        } else {
            r"
            SELECT COALESCE(SUM(weight), 0) FROM gov_correlation_rules
            WHERE tenant_id = $1 AND connector_id = $2 AND is_active = true
            "
        };

        let mut q = sqlx::query_scalar::<_, rust_decimal::Decimal>(query)
            .bind(tenant_id)
            .bind(connector_id);

        if let Some(exclude_id) = exclude_rule_id {
            q = q.bind(exclude_id);
        }

        q.fetch_one(pool).await
    }

    /// Check if rule is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.is_active
    }

    /// Check if this is a fuzzy match rule.
    #[must_use]
    pub fn is_fuzzy(&self) -> bool {
        matches!(self.match_type, GovMatchType::Fuzzy)
    }

    /// Check if this is an expression-based rule (F067).
    #[must_use]
    pub fn is_expression(&self) -> bool {
        matches!(self.match_type, GovMatchType::Expression)
    }

    /// Check if this is a connector-scoped rule (F067).
    #[must_use]
    pub fn is_connector_scoped(&self) -> bool {
        self.connector_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_exact_rule_request() {
        let request = CreateGovCorrelationRule {
            name: "Email Exact Match".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Exact,
            algorithm: None,
            threshold: None,
            weight: Some(rust_decimal::Decimal::new(500, 1)), // 50.0
            priority: Some(100),
            connector_id: None,
            source_attribute: None,
            target_attribute: None,
            expression: None,
            tier: None,
            is_definitive: None,
            normalize: None,
        };

        assert_eq!(request.match_type, GovMatchType::Exact);
        assert!(request.algorithm.is_none());
    }

    #[test]
    fn test_create_fuzzy_rule_request() {
        let request = CreateGovCorrelationRule {
            name: "Name Fuzzy Match".to_string(),
            attribute: "display_name".to_string(),
            match_type: GovMatchType::Fuzzy,
            algorithm: Some(GovFuzzyAlgorithm::JaroWinkler),
            threshold: Some(rust_decimal::Decimal::new(85, 2)), // 0.85
            weight: Some(rust_decimal::Decimal::new(300, 1)),   // 30.0
            priority: Some(50),
            connector_id: None,
            source_attribute: None,
            target_attribute: None,
            expression: None,
            tier: None,
            is_definitive: None,
            normalize: None,
        };

        assert_eq!(request.match_type, GovMatchType::Fuzzy);
        assert_eq!(request.algorithm, Some(GovFuzzyAlgorithm::JaroWinkler));
    }

    #[test]
    fn test_create_connector_scoped_rule() {
        let connector_id = Uuid::new_v4();
        let request = CreateGovCorrelationRule {
            name: "Email Exact - AD".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Exact,
            algorithm: None,
            threshold: None,
            weight: Some(rust_decimal::Decimal::new(50, 2)), // 0.50
            priority: Some(100),
            connector_id: Some(connector_id),
            source_attribute: Some("email".to_string()),
            target_attribute: Some("mail".to_string()),
            expression: None,
            tier: Some(1),
            is_definitive: Some(false),
            normalize: Some(true),
        };

        assert_eq!(request.connector_id, Some(connector_id));
        assert_eq!(request.source_attribute, Some("email".to_string()));
        assert_eq!(request.target_attribute, Some("mail".to_string()));
        assert_eq!(request.tier, Some(1));
    }

    #[test]
    fn test_create_expression_rule() {
        let request = CreateGovCorrelationRule {
            name: "Email Local Part".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Expression,
            algorithm: None,
            threshold: None,
            weight: Some(rust_decimal::Decimal::new(40, 2)), // 0.40
            priority: Some(80),
            connector_id: Some(Uuid::new_v4()),
            source_attribute: Some("email".to_string()),
            target_attribute: Some("sAMAccountName".to_string()),
            expression: Some(r#"source.split("@")[0]"#.to_string()),
            tier: Some(1),
            is_definitive: Some(false),
            normalize: Some(true),
        };

        assert_eq!(request.match_type, GovMatchType::Expression);
        assert!(request.expression.is_some());
    }

    #[test]
    fn test_match_type_serialization() {
        let exact = GovMatchType::Exact;
        let json = serde_json::to_string(&exact).unwrap();
        assert_eq!(json, "\"exact\"");

        let fuzzy = GovMatchType::Fuzzy;
        let json = serde_json::to_string(&fuzzy).unwrap();
        assert_eq!(json, "\"fuzzy\"");

        let expression = GovMatchType::Expression;
        let json = serde_json::to_string(&expression).unwrap();
        assert_eq!(json, "\"expression\"");

        // Roundtrip
        let deserialized: GovMatchType = serde_json::from_str("\"expression\"").unwrap();
        assert_eq!(deserialized, GovMatchType::Expression);
    }

    #[test]
    fn test_algorithm_serialization() {
        let jw = GovFuzzyAlgorithm::JaroWinkler;
        let json = serde_json::to_string(&jw).unwrap();
        assert_eq!(json, "\"jaro_winkler\"");
    }

    #[test]
    fn test_rule_helper_methods() {
        let rule = GovCorrelationRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            attribute: "email".to_string(),
            match_type: GovMatchType::Expression,
            algorithm: None,
            threshold: None,
            weight: rust_decimal::Decimal::new(50, 2),
            is_active: true,
            priority: 100,
            connector_id: Some(Uuid::new_v4()),
            source_attribute: Some("email".to_string()),
            target_attribute: Some("mail".to_string()),
            expression: Some("source".to_string()),
            tier: Some(1),
            is_definitive: false,
            normalize: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        assert!(rule.is_active());
        assert!(!rule.is_fuzzy());
        assert!(rule.is_expression());
        assert!(rule.is_connector_scoped());
    }

    #[test]
    fn test_filter_with_connector_and_tier() {
        let filter = CorrelationRuleFilter {
            match_type: Some(GovMatchType::Exact),
            is_active: Some(true),
            attribute: None,
            connector_id: Some(Uuid::new_v4()),
            tier: Some(1),
        };

        assert_eq!(filter.match_type, Some(GovMatchType::Exact));
        assert_eq!(filter.tier, Some(1));
        assert!(filter.connector_id.is_some());
    }
}
