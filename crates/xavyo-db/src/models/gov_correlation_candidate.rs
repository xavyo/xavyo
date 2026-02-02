//! Governance Correlation Candidate model.
//!
//! Represents candidate identity matches for a correlation case,
//! including per-attribute scoring details (F067).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Individual rule match score detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerAttributeScore {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub source_attribute: String,
    pub target_attribute: String,
    pub source_value: Option<String>,
    pub target_value: Option<String>,
    pub strategy: String,
    pub raw_similarity: f64,
    pub weight: f64,
    pub weighted_score: f64,
    pub normalized: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

/// Container for per-attribute scores with aggregate confidence.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerAttributeScores {
    pub scores: Vec<PerAttributeScore>,
    pub aggregate_confidence: f64,
}

/// A governance correlation candidate for a case.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovCorrelationCandidate {
    /// Unique identifier for the candidate.
    pub id: Uuid,

    /// The correlation case this candidate belongs to.
    pub case_id: Uuid,

    /// The matched identity ID.
    pub identity_id: Uuid,

    /// Display name of the matched identity (cached).
    pub identity_display_name: Option<String>,

    /// Attributes of the matched identity (JSONB snapshot).
    pub identity_attributes: serde_json::Value,

    /// Aggregate confidence score (0.00-100.00).
    pub aggregate_confidence: rust_decimal::Decimal,

    /// JSONB details of per-attribute scoring.
    pub per_attribute_scores: serde_json::Value,

    /// Whether the identity has been deactivated since detection.
    pub is_deactivated: bool,

    /// Whether this candidate is a definitive (auto-confirmed) match.
    pub is_definitive_match: bool,

    /// When the candidate was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new correlation candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovCorrelationCandidate {
    pub case_id: Uuid,
    pub identity_id: Uuid,
    pub identity_display_name: Option<String>,
    pub identity_attributes: serde_json::Value,
    pub aggregate_confidence: rust_decimal::Decimal,
    pub per_attribute_scores: PerAttributeScores,
    pub is_deactivated: bool,
    pub is_definitive_match: bool,
}

impl GovCorrelationCandidate {
    /// Create a new correlation candidate.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateGovCorrelationCandidate,
    ) -> Result<Self, sqlx::Error> {
        let per_attribute_scores_json = serde_json::to_value(&input.per_attribute_scores)
            .unwrap_or_else(|_| serde_json::json!({}));

        sqlx::query_as(
            r#"
            INSERT INTO gov_correlation_candidates (
                case_id, identity_id, identity_display_name, identity_attributes,
                aggregate_confidence, per_attribute_scores, is_deactivated, is_definitive_match
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            "#,
        )
        .bind(input.case_id)
        .bind(input.identity_id)
        .bind(&input.identity_display_name)
        .bind(&input.identity_attributes)
        .bind(input.aggregate_confidence)
        .bind(per_attribute_scores_json)
        .bind(input.is_deactivated)
        .bind(input.is_definitive_match)
        .fetch_one(pool)
        .await
    }

    /// Create multiple correlation candidates in a batch.
    pub async fn create_batch(
        pool: &sqlx::PgPool,
        inputs: Vec<CreateGovCorrelationCandidate>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let candidate = Self::create(pool, input).await?;
            results.push(candidate);
        }
        Ok(results)
    }

    /// List candidates for a correlation case, ordered by confidence descending.
    pub async fn list_by_case(
        pool: &sqlx::PgPool,
        case_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_correlation_candidates
            WHERE case_id = $1
            ORDER BY aggregate_confidence DESC
            "#,
        )
        .bind(case_id)
        .fetch_all(pool)
        .await
    }

    /// Find a candidate by its unique ID.
    pub async fn find_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_correlation_candidates
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Mark candidates as identity removed by setting display name to '[identity removed]'.
    /// Returns the number of rows affected.
    pub async fn mark_identity_removed(
        pool: &sqlx::PgPool,
        identity_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_correlation_candidates
            SET identity_display_name = '[identity removed]'
            WHERE identity_id = $1
            "#,
        )
        .bind(identity_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Get the per-attribute scores as structured data.
    pub fn get_per_attribute_scores(&self) -> Result<PerAttributeScores, serde_json::Error> {
        serde_json::from_value(self.per_attribute_scores.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_attribute_score_serialization() {
        let score = PerAttributeScore {
            rule_id: Uuid::new_v4(),
            rule_name: "Email Exact Match".to_string(),
            source_attribute: "email".to_string(),
            target_attribute: "email".to_string(),
            source_value: Some("alice@example.com".to_string()),
            target_value: Some("alice@example.com".to_string()),
            strategy: "exact".to_string(),
            raw_similarity: 1.0,
            weight: 0.5,
            weighted_score: 0.5,
            normalized: true,
            skipped: false,
            skip_reason: None,
        };

        let json = serde_json::to_string(&score).unwrap();
        assert!(json.contains("Email Exact Match"));
        assert!(json.contains("alice@example.com"));

        let deserialized: PerAttributeScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rule_name, "Email Exact Match");
        assert_eq!(deserialized.source_attribute, "email");
        assert_eq!(deserialized.raw_similarity, 1.0);
        assert!(!deserialized.skipped);
        assert!(deserialized.skip_reason.is_none());
    }

    #[test]
    fn test_per_attribute_scores_container() {
        let scores = PerAttributeScores {
            scores: vec![
                PerAttributeScore {
                    rule_id: Uuid::new_v4(),
                    rule_name: "Email Match".to_string(),
                    source_attribute: "email".to_string(),
                    target_attribute: "email".to_string(),
                    source_value: Some("test@example.com".to_string()),
                    target_value: Some("test@example.com".to_string()),
                    strategy: "exact".to_string(),
                    raw_similarity: 1.0,
                    weight: 0.6,
                    weighted_score: 0.6,
                    normalized: true,
                    skipped: false,
                    skip_reason: None,
                },
                PerAttributeScore {
                    rule_id: Uuid::new_v4(),
                    rule_name: "Name Fuzzy".to_string(),
                    source_attribute: "display_name".to_string(),
                    target_attribute: "display_name".to_string(),
                    source_value: Some("Alice Smith".to_string()),
                    target_value: Some("A. Smith".to_string()),
                    strategy: "levenshtein".to_string(),
                    raw_similarity: 0.7,
                    weight: 0.4,
                    weighted_score: 0.28,
                    normalized: true,
                    skipped: false,
                    skip_reason: None,
                },
            ],
            aggregate_confidence: 88.0,
        };

        let json = serde_json::to_string(&scores).unwrap();
        let deserialized: PerAttributeScores = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.scores.len(), 2);
        assert_eq!(deserialized.aggregate_confidence, 88.0);
        assert_eq!(deserialized.scores[0].rule_name, "Email Match");
        assert_eq!(deserialized.scores[1].rule_name, "Name Fuzzy");

        // Verify aggregate is the sum of weighted scores scaled
        let total_weighted: f64 = deserialized.scores.iter().map(|s| s.weighted_score).sum();
        assert!((total_weighted - 0.88).abs() < f64::EPSILON);
    }

    #[test]
    fn test_create_candidate_request() {
        let input = CreateGovCorrelationCandidate {
            case_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            identity_display_name: Some("Test User".to_string()),
            identity_attributes: serde_json::json!({"email": "test@example.com"}),
            aggregate_confidence: rust_decimal::Decimal::new(8500, 2),
            per_attribute_scores: PerAttributeScores {
                scores: vec![PerAttributeScore {
                    rule_id: Uuid::new_v4(),
                    rule_name: "Email".to_string(),
                    source_attribute: "email".to_string(),
                    target_attribute: "email".to_string(),
                    source_value: Some("test@example.com".to_string()),
                    target_value: Some("test@example.com".to_string()),
                    strategy: "exact".to_string(),
                    raw_similarity: 1.0,
                    weight: 1.0,
                    weighted_score: 1.0,
                    normalized: true,
                    skipped: false,
                    skip_reason: None,
                }],
                aggregate_confidence: 85.0,
            },
            is_deactivated: false,
            is_definitive_match: false,
        };

        // Verify serialization to JSON (for JSONB insert).
        let scores_json = serde_json::to_value(&input.per_attribute_scores).unwrap();
        assert!(scores_json.is_object());
        assert!(scores_json["scores"].is_array());
        assert_eq!(scores_json["aggregate_confidence"], 85.0);

        // Verify confidence decimal.
        assert_eq!(input.aggregate_confidence.to_string(), "85.00");

        // Verify display name.
        assert_eq!(input.identity_display_name, Some("Test User".to_string()));
    }
}
