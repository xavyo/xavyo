//! Inbound correlation for live synchronization.
//!
//! This module correlates inbound changes from external systems to internal
//! xavyo users. Unlike outbound correlation (finding accounts in target
//! systems), inbound correlation matches external accounts to existing users.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use super::change::{InboundCorrelationCandidate, InboundCorrelationResult};
use super::error::{SyncError, SyncResult};

/// Configuration for an inbound correlation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundCorrelationRule {
    /// Rule name for identification.
    pub name: String,
    /// Source attribute from inbound change (e.g., "mail").
    pub source_attribute: String,
    /// Target attribute on internal user (e.g., "email").
    pub target_attribute: String,
    /// Match type.
    pub match_type: InboundMatchType,
    /// Whether matching is case-sensitive.
    pub case_sensitive: bool,
    /// Weight for confidence scoring (default 1.0).
    pub weight: f64,
}

impl InboundCorrelationRule {
    /// Create a new exact match rule.
    #[must_use] 
    pub fn exact(name: &str, source: &str, target: &str) -> Self {
        Self {
            name: name.to_string(),
            source_attribute: source.to_string(),
            target_attribute: target.to_string(),
            match_type: InboundMatchType::Exact,
            case_sensitive: false,
            weight: 1.0,
        }
    }

    /// Create a case-sensitive exact match rule.
    #[must_use] 
    pub fn exact_case_sensitive(name: &str, source: &str, target: &str) -> Self {
        Self {
            name: name.to_string(),
            source_attribute: source.to_string(),
            target_attribute: target.to_string(),
            match_type: InboundMatchType::Exact,
            case_sensitive: true,
            weight: 1.0,
        }
    }

    /// Set the weight for confidence scoring.
    #[must_use] 
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }
}

/// Type of inbound matching to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundMatchType {
    /// Exact match.
    Exact,
    /// Case-insensitive match.
    CaseInsensitive,
    /// Prefix match.
    Prefix,
    /// Suffix match.
    Suffix,
    /// Contains match.
    Contains,
}

/// Configuration for inbound correlation behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundCorrelationConfig {
    /// Minimum confidence to consider a match valid (default: 0.8).
    pub min_confidence: f64,
    /// Whether to auto-link single confident matches (default: true).
    pub auto_link_single_match: bool,
    /// Maximum candidates to evaluate (default: 100).
    pub max_candidates: u32,
}

impl Default for InboundCorrelationConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.8,
            auto_link_single_match: true,
            max_candidates: 100,
        }
    }
}

/// Trait for inbound correlation services.
#[async_trait]
pub trait InboundCorrelator: Send + Sync {
    /// Correlate an inbound change to internal users.
    async fn correlate(
        &self,
        tenant_id: Uuid,
        attributes: &serde_json::Value,
        rules: &[InboundCorrelationRule],
    ) -> SyncResult<InboundCorrelationResult>;
}

/// Default inbound correlator using database queries.
pub struct DatabaseInboundCorrelator {
    pool: PgPool,
    config: InboundCorrelationConfig,
}

impl DatabaseInboundCorrelator {
    /// Create a new database-backed correlator.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: InboundCorrelationConfig::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use] 
    pub fn with_config(pool: PgPool, config: InboundCorrelationConfig) -> Self {
        Self { pool, config }
    }

    /// Extract attribute value from JSON.
    fn get_attribute_value(attrs: &serde_json::Value, attr_name: &str) -> Option<String> {
        match attrs.get(attr_name) {
            Some(serde_json::Value::String(s)) => Some(s.clone()),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            Some(serde_json::Value::Bool(b)) => Some(b.to_string()),
            Some(serde_json::Value::Array(arr)) => {
                arr.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
            }
            _ => None,
        }
    }

    /// Build search conditions for a rule.
    fn build_search_value(rule: &InboundCorrelationRule, value: &str) -> (String, String) {
        let search_value = if rule.case_sensitive {
            value.to_string()
        } else {
            value.to_lowercase()
        };

        let pattern = match rule.match_type {
            InboundMatchType::Exact | InboundMatchType::CaseInsensitive => search_value.clone(),
            InboundMatchType::Prefix => format!("{search_value}%"),
            InboundMatchType::Suffix => format!("%{search_value}"),
            InboundMatchType::Contains => format!("%{search_value}%"),
        };

        (search_value, pattern)
    }

    /// Score candidates against rules.
    fn score_candidates(
        &self,
        candidates: Vec<(Uuid, HashMap<String, String>)>,
        attributes: &serde_json::Value,
        rules: &[InboundCorrelationRule],
    ) -> Vec<InboundCorrelationCandidate> {
        let mut scored = Vec::new();
        let total_weight: f64 = rules.iter().map(|r| r.weight).sum();

        for (user_id, user_attrs) in candidates {
            let mut match_score = 0.0;
            let mut matched_rules = Vec::new();

            for rule in rules {
                let source_value =
                    match Self::get_attribute_value(attributes, &rule.source_attribute) {
                        Some(v) => v,
                        None => continue,
                    };

                let target_value = match user_attrs.get(&rule.target_attribute) {
                    Some(v) => v.clone(),
                    None => continue,
                };

                let matches = self.matches_rule(rule, &source_value, &target_value);
                if matches {
                    match_score += rule.weight;
                    matched_rules.push(rule.name.clone());
                }
            }

            if !matched_rules.is_empty() {
                let confidence = if total_weight > 0.0 {
                    match_score / total_weight
                } else {
                    0.0
                };

                if confidence >= self.config.min_confidence {
                    scored.push(InboundCorrelationCandidate {
                        user_id,
                        confidence,
                        matched_rules,
                    });
                }
            }
        }

        // Sort by confidence descending
        scored.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        scored
    }

    /// Check if a single rule matches.
    fn matches_rule(&self, rule: &InboundCorrelationRule, source: &str, target: &str) -> bool {
        let (s, t) = if rule.case_sensitive {
            (source.to_string(), target.to_string())
        } else {
            (source.to_lowercase(), target.to_lowercase())
        };

        match rule.match_type {
            InboundMatchType::Exact | InboundMatchType::CaseInsensitive => s == t,
            InboundMatchType::Prefix => t.starts_with(&s),
            InboundMatchType::Suffix => t.ends_with(&s),
            InboundMatchType::Contains => t.contains(&s),
        }
    }
}

#[async_trait]
impl InboundCorrelator for DatabaseInboundCorrelator {
    #[instrument(skip(self, attributes, rules))]
    async fn correlate(
        &self,
        tenant_id: Uuid,
        attributes: &serde_json::Value,
        rules: &[InboundCorrelationRule],
    ) -> SyncResult<InboundCorrelationResult> {
        if rules.is_empty() {
            debug!("No correlation rules defined");
            return Ok(InboundCorrelationResult::unmatched());
        }

        // Extract values for searchable attributes
        let mut search_conditions = Vec::new();
        for rule in rules {
            if let Some(value) = Self::get_attribute_value(attributes, &rule.source_attribute) {
                let (_, pattern) = Self::build_search_value(rule, &value);
                search_conditions.push((
                    rule.target_attribute.clone(),
                    pattern,
                    rule.case_sensitive,
                ));
            }
        }

        if search_conditions.is_empty() {
            debug!("No searchable attributes found in inbound change");
            return Ok(InboundCorrelationResult::unmatched());
        }

        // Build dynamic query for user search
        // Note: In a real implementation, this would use prepared statements
        // For now, we use email as the primary correlation attribute
        let email_condition = search_conditions
            .iter()
            .find(|(attr, _, _)| attr == "email");

        let candidates: Vec<(Uuid, HashMap<String, String>)> =
            if let Some((_, pattern, case_sensitive)) = email_condition {
                let rows = if *case_sensitive {
                    sqlx::query_as::<_, (Uuid, String)>(
                        r"
                    SELECT id, email
                    FROM users
                    WHERE tenant_id = $1 AND email LIKE $2
                    LIMIT $3
                    ",
                    )
                    .bind(tenant_id)
                    .bind(pattern)
                    .bind(i64::from(self.config.max_candidates))
                    .fetch_all(&self.pool)
                    .await
                } else {
                    sqlx::query_as::<_, (Uuid, String)>(
                        r"
                    SELECT id, email
                    FROM users
                    WHERE tenant_id = $1 AND LOWER(email) LIKE LOWER($2)
                    LIMIT $3
                    ",
                    )
                    .bind(tenant_id)
                    .bind(pattern)
                    .bind(i64::from(self.config.max_candidates))
                    .fetch_all(&self.pool)
                    .await
                };

                match rows {
                    Ok(users) => users
                        .into_iter()
                        .map(|(id, email)| {
                            let mut attrs = HashMap::new();
                            attrs.insert("email".to_string(), email);
                            (id, attrs)
                        })
                        .collect(),
                    Err(e) => {
                        return Err(SyncError::internal(format!(
                            "Database error during correlation: {e}"
                        )));
                    }
                }
            } else {
                // No email-based correlation, try other attributes
                // In production, this would support more attribute types
                Vec::new()
            };

        info!(
            candidate_count = candidates.len(),
            "Found correlation candidates"
        );

        if candidates.is_empty() {
            return Ok(InboundCorrelationResult::unmatched());
        }

        // Score candidates
        let scored = self.score_candidates(candidates, attributes, rules);

        match scored.len() {
            0 => Ok(InboundCorrelationResult::unmatched()),
            1 => {
                let candidate = &scored[0];
                Ok(InboundCorrelationResult::single_match(
                    candidate.user_id,
                    candidate.confidence,
                    candidate.matched_rules.clone(),
                ))
            }
            _ => Ok(InboundCorrelationResult::disputed(scored)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbound_correlation_rule_exact() {
        let rule = InboundCorrelationRule::exact("email-match", "mail", "email");
        assert_eq!(rule.source_attribute, "mail");
        assert_eq!(rule.target_attribute, "email");
        assert!(!rule.case_sensitive);
        assert_eq!(rule.weight, 1.0);
    }

    #[test]
    fn test_inbound_correlation_rule_with_weight() {
        let rule = InboundCorrelationRule::exact("email-match", "mail", "email").with_weight(2.0);
        assert_eq!(rule.weight, 2.0);
    }

    #[test]
    fn test_inbound_correlation_config_default() {
        let config = InboundCorrelationConfig::default();
        assert_eq!(config.min_confidence, 0.8);
        assert!(config.auto_link_single_match);
        assert_eq!(config.max_candidates, 100);
    }

    #[test]
    fn test_inbound_correlation_result_unmatched() {
        let result = InboundCorrelationResult::unmatched();
        assert!(result.matched_user_id.is_none());
        assert!(result.candidates.is_empty());
        assert!(!result.has_confident_match());
    }

    #[test]
    fn test_inbound_correlation_result_single_match() {
        let user_id = Uuid::new_v4();
        let result =
            InboundCorrelationResult::single_match(user_id, 0.95, vec!["email-match".to_string()]);
        assert_eq!(result.matched_user_id, Some(user_id));
        assert_eq!(result.candidates.len(), 1);
        assert!(result.has_confident_match());
        assert_eq!(result.confidence, 0.95);
    }

    #[test]
    fn test_inbound_correlation_result_disputed() {
        let candidates = vec![
            InboundCorrelationCandidate {
                user_id: Uuid::new_v4(),
                confidence: 0.9,
                matched_rules: vec!["rule1".to_string()],
            },
            InboundCorrelationCandidate {
                user_id: Uuid::new_v4(),
                confidence: 0.85,
                matched_rules: vec!["rule2".to_string()],
            },
        ];

        let result = InboundCorrelationResult::disputed(candidates);
        assert!(result.matched_user_id.is_none());
        assert_eq!(result.candidates.len(), 2);
        assert!(!result.has_confident_match());
    }

    #[test]
    fn test_get_attribute_value_string() {
        let attrs = serde_json::json!({"email": "john@example.com"});
        assert_eq!(
            DatabaseInboundCorrelator::get_attribute_value(&attrs, "email"),
            Some("john@example.com".to_string())
        );
    }

    #[test]
    fn test_get_attribute_value_array() {
        let attrs = serde_json::json!({"emails": ["primary@example.com", "secondary@example.com"]});
        assert_eq!(
            DatabaseInboundCorrelator::get_attribute_value(&attrs, "emails"),
            Some("primary@example.com".to_string())
        );
    }

    #[test]
    fn test_get_attribute_value_missing() {
        let attrs = serde_json::json!({"name": "John"});
        assert_eq!(
            DatabaseInboundCorrelator::get_attribute_value(&attrs, "email"),
            None
        );
    }

    #[test]
    fn test_build_search_value_exact() {
        let rule = InboundCorrelationRule::exact("test", "mail", "email");
        let (value, pattern) =
            DatabaseInboundCorrelator::build_search_value(&rule, "Test@Example.com");
        assert_eq!(value, "test@example.com");
        assert_eq!(pattern, "test@example.com");
    }

    #[test]
    fn test_build_search_value_prefix() {
        let mut rule = InboundCorrelationRule::exact("test", "mail", "email");
        rule.match_type = InboundMatchType::Prefix;
        let (_, pattern) = DatabaseInboundCorrelator::build_search_value(&rule, "john");
        assert_eq!(pattern, "john%");
    }

    #[test]
    fn test_build_search_value_contains() {
        let mut rule = InboundCorrelationRule::exact("test", "mail", "email");
        rule.match_type = InboundMatchType::Contains;
        let (_, pattern) = DatabaseInboundCorrelator::build_search_value(&rule, "example");
        assert_eq!(pattern, "%example%");
    }
}
