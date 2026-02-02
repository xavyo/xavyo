//! Correlation Engine
//!
//! Finds existing accounts in target systems by correlating identity attributes.
//!
//! This module provides:
//! - Correlation rule evaluation
//! - Exact and fuzzy matching
//! - Confidence scoring
//! - Multi-rule aggregation

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument};

use xavyo_connector::mapping::{CorrelationMatchType, CorrelationRule};
use xavyo_connector::operation::{AttributeSet, AttributeValue, Filter};
use xavyo_connector::prelude::Uid;
use xavyo_connector::traits::SearchOp;

/// Correlation errors.
#[derive(Debug, Error)]
pub enum CorrelationError {
    /// Missing required attribute for correlation.
    #[error("Missing attribute '{attribute}' required for correlation")]
    MissingAttribute { attribute: String },

    /// Search operation failed.
    #[error("Correlation search failed: {message}")]
    SearchFailed { message: String },

    /// Multiple matches found when expecting single.
    #[error("Multiple accounts found matching correlation criteria")]
    MultipleMatches,

    /// No matches found.
    #[error("No matching account found")]
    NoMatch,

    /// Connector error.
    #[error("Connector error: {0}")]
    Connector(#[from] xavyo_connector::error::ConnectorError),
}

/// Result type for correlation operations.
pub type CorrelationResult<T> = Result<T, CorrelationError>;

/// A correlation match with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    /// Unique identifier in the target system.
    pub uid: Uid,

    /// Confidence score (0.0 to 1.0).
    pub confidence: f64,

    /// Which rules matched.
    pub matched_rules: Vec<String>,

    /// Matched attribute values for verification.
    pub matched_attributes: HashMap<String, String>,
}

impl CorrelationMatch {
    /// Create a new correlation match.
    pub fn new(uid: Uid, confidence: f64) -> Self {
        Self {
            uid,
            confidence,
            matched_rules: Vec::new(),
            matched_attributes: HashMap::new(),
        }
    }

    /// Add a matched rule.
    pub fn with_rule(mut self, rule_name: &str) -> Self {
        self.matched_rules.push(rule_name.to_string());
        self
    }

    /// Add a matched attribute.
    pub fn with_attribute(mut self, name: &str, value: &str) -> Self {
        self.matched_attributes
            .insert(name.to_string(), value.to_string());
        self
    }
}

/// Configuration for correlation behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Minimum confidence threshold to consider a match (default: 0.8).
    pub min_confidence: f64,

    /// Whether to require all rules to match (default: false).
    pub require_all_rules: bool,

    /// Whether to allow multiple matches (default: false).
    pub allow_multiple_matches: bool,

    /// Maximum number of search results to evaluate (default: 100).
    pub max_candidates: u32,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.8,
            require_all_rules: false,
            allow_multiple_matches: false,
            max_candidates: 100,
        }
    }
}

/// The correlation service interface.
#[async_trait]
pub trait CorrelationService: Send + Sync {
    /// Find matching accounts in the target system.
    async fn correlate(
        &self,
        connector: &dyn SearchOp,
        object_class: &str,
        source_attrs: &HashMap<String, String>,
        rules: &[CorrelationRule],
    ) -> CorrelationResult<Option<CorrelationMatch>>;

    /// Find all matching accounts (when multiple matches are allowed).
    async fn correlate_all(
        &self,
        connector: &dyn SearchOp,
        object_class: &str,
        source_attrs: &HashMap<String, String>,
        rules: &[CorrelationRule],
    ) -> CorrelationResult<Vec<CorrelationMatch>>;
}

/// Default correlation service implementation.
#[derive(Clone)]
pub struct DefaultCorrelationService {
    config: CorrelationConfig,
}

impl DefaultCorrelationService {
    /// Create a new correlation service with default config.
    pub fn new() -> Self {
        Self {
            config: CorrelationConfig::default(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: CorrelationConfig) -> Self {
        Self { config }
    }

    /// Evaluate a single correlation rule against an attribute set.
    fn evaluate_rule(
        &self,
        rule: &CorrelationRule,
        source_attrs: &HashMap<String, String>,
        target_attrs: &AttributeSet,
    ) -> Option<f64> {
        // Get source attribute value
        let source_value = source_attrs.get(&rule.source_attribute)?;

        // Get target attribute value
        let target_value = target_attrs.get(&rule.target_attribute)?;
        let target_str = attribute_value_to_string(target_value)?;

        // Perform matching based on match type
        let matches = match rule.match_type {
            CorrelationMatchType::Exact => {
                if rule.case_sensitive {
                    source_value == &target_str
                } else {
                    source_value.to_lowercase() == target_str.to_lowercase()
                }
            }
            CorrelationMatchType::CaseInsensitive => {
                source_value.to_lowercase() == target_str.to_lowercase()
            }
            CorrelationMatchType::Prefix => {
                if rule.case_sensitive {
                    target_str.starts_with(source_value)
                } else {
                    target_str
                        .to_lowercase()
                        .starts_with(&source_value.to_lowercase())
                }
            }
            CorrelationMatchType::Suffix => {
                if rule.case_sensitive {
                    target_str.ends_with(source_value)
                } else {
                    target_str
                        .to_lowercase()
                        .ends_with(&source_value.to_lowercase())
                }
            }
            CorrelationMatchType::Contains => {
                if rule.case_sensitive {
                    target_str.contains(source_value)
                } else {
                    target_str
                        .to_lowercase()
                        .contains(&source_value.to_lowercase())
                }
            }
        };

        if matches {
            Some(1.0) // Each matching rule contributes weight of 1.0
        } else {
            None
        }
    }

    /// Build a search filter from correlation rules.
    fn build_search_filter(
        &self,
        rules: &[CorrelationRule],
        source_attrs: &HashMap<String, String>,
    ) -> Option<Filter> {
        let mut filters = Vec::new();

        for rule in rules {
            if let Some(value) = source_attrs.get(&rule.source_attribute) {
                let filter = match rule.match_type {
                    CorrelationMatchType::Exact | CorrelationMatchType::CaseInsensitive => {
                        Filter::eq(&rule.target_attribute, value)
                    }
                    CorrelationMatchType::Prefix => {
                        Filter::starts_with(&rule.target_attribute, value)
                    }
                    CorrelationMatchType::Suffix => Filter::EndsWith {
                        attribute: rule.target_attribute.clone(),
                        value: value.clone(),
                    },
                    CorrelationMatchType::Contains => {
                        Filter::contains(&rule.target_attribute, value)
                    }
                };
                filters.push(filter);
            }
        }

        if filters.is_empty() {
            return None;
        }

        // Combine with OR for broader candidate search
        Some(Filter::or(filters))
    }

    /// Score candidates against correlation rules.
    fn score_candidates(
        &self,
        candidates: Vec<AttributeSet>,
        source_attrs: &HashMap<String, String>,
        rules: &[CorrelationRule],
    ) -> Vec<CorrelationMatch> {
        let mut matches = Vec::new();

        for candidate in candidates {
            let mut total_score = 0.0;
            let max_score = rules.len() as f64;
            let mut matched_rules = Vec::new();
            let mut matched_attrs = HashMap::new();

            // Extract UID from candidate
            let uid = candidate
                .get("__uid__")
                .or_else(|| candidate.get("dn"))
                .or_else(|| candidate.get("id"))
                .and_then(attribute_value_to_string)
                .map(Uid::from_id)
                .unwrap_or_else(|| Uid::from_id("unknown"));

            for (idx, rule) in rules.iter().enumerate() {
                if let Some(score) = self.evaluate_rule(rule, source_attrs, &candidate) {
                    total_score += score;
                    matched_rules.push(format!("rule_{}", idx));

                    // Record matched attribute value
                    if let Some(value) = candidate.get(&rule.target_attribute) {
                        if let Some(value_str) = attribute_value_to_string(value) {
                            matched_attrs.insert(rule.target_attribute.clone(), value_str);
                        }
                    }
                }
            }

            // Calculate confidence as ratio of total score to max possible
            let confidence = if max_score > 0.0 {
                total_score / max_score
            } else {
                0.0
            };

            // Check if enough rules matched
            let rule_threshold = if self.config.require_all_rules {
                matched_rules.len() == rules.len()
            } else {
                !matched_rules.is_empty()
            };

            if rule_threshold && confidence >= self.config.min_confidence {
                let mut correlation_match = CorrelationMatch::new(uid, confidence);
                correlation_match.matched_rules = matched_rules;
                correlation_match.matched_attributes = matched_attrs;
                matches.push(correlation_match);
            }
        }

        // Sort by confidence descending
        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }
}

impl Default for DefaultCorrelationService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CorrelationService for DefaultCorrelationService {
    #[instrument(skip(self, connector, source_attrs, rules))]
    async fn correlate(
        &self,
        connector: &dyn SearchOp,
        object_class: &str,
        source_attrs: &HashMap<String, String>,
        rules: &[CorrelationRule],
    ) -> CorrelationResult<Option<CorrelationMatch>> {
        if rules.is_empty() {
            debug!("No correlation rules defined, skipping correlation");
            return Ok(None);
        }

        let matches = self
            .correlate_all(connector, object_class, source_attrs, rules)
            .await?;

        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches.into_iter().next().unwrap())),
            _ if self.config.allow_multiple_matches => {
                // Return highest confidence match
                Ok(Some(matches.into_iter().next().unwrap()))
            }
            _ => Err(CorrelationError::MultipleMatches),
        }
    }

    #[instrument(skip(self, connector, source_attrs, rules))]
    async fn correlate_all(
        &self,
        connector: &dyn SearchOp,
        object_class: &str,
        source_attrs: &HashMap<String, String>,
        rules: &[CorrelationRule],
    ) -> CorrelationResult<Vec<CorrelationMatch>> {
        if rules.is_empty() {
            return Ok(Vec::new());
        }

        // Build search filter
        let filter = self.build_search_filter(rules, source_attrs);

        debug!(?filter, "Searching for correlation candidates");

        // Search for candidates
        let page = xavyo_connector::operation::PageRequest::new(self.config.max_candidates);

        let result = connector
            .search(object_class, filter, None, Some(page))
            .await
            .map_err(|e| CorrelationError::SearchFailed {
                message: e.to_string(),
            })?;

        info!(
            candidate_count = result.objects.len(),
            "Found correlation candidates"
        );

        // Score candidates
        let matches = self.score_candidates(result.objects, source_attrs, rules);

        info!(match_count = matches.len(), "Correlation scoring complete");

        Ok(matches)
    }
}

/// Convert AttributeValue to string for comparison.
fn attribute_value_to_string(value: &AttributeValue) -> Option<String> {
    match value {
        AttributeValue::String(s) => Some(s.clone()),
        AttributeValue::Integer(i) => Some(i.to_string()),
        AttributeValue::Boolean(b) => Some(b.to_string()),
        AttributeValue::Float(f) => Some(f.to_string()),
        AttributeValue::Array(arr) => arr.first().and_then(attribute_value_to_string),
        _ => None,
    }
}

/// Create a correlation service with default settings.
pub fn default_correlation_service() -> Arc<dyn CorrelationService> {
    Arc::new(DefaultCorrelationService::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_match() {
        let uid = Uid::from_id("user123");
        let m = CorrelationMatch::new(uid.clone(), 0.95)
            .with_rule("email-match")
            .with_attribute("email", "john@example.com");

        assert_eq!(m.uid, uid);
        assert_eq!(m.confidence, 0.95);
        assert_eq!(m.matched_rules, vec!["email-match"]);
        assert_eq!(
            m.matched_attributes.get("email"),
            Some(&"john@example.com".to_string())
        );
    }

    #[test]
    fn test_correlation_config_default() {
        let config = CorrelationConfig::default();
        assert_eq!(config.min_confidence, 0.8);
        assert!(!config.require_all_rules);
        assert!(!config.allow_multiple_matches);
        assert_eq!(config.max_candidates, 100);
    }

    #[test]
    fn test_evaluate_rule_exact() {
        let service = DefaultCorrelationService::new();
        let rule = CorrelationRule {
            priority: 0,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: true,
        };

        let mut source = HashMap::new();
        source.insert("email".to_string(), "john@example.com".to_string());

        let mut target = AttributeSet::new();
        target.set("mail", "john@example.com");

        let score = service.evaluate_rule(&rule, &source, &target);
        assert_eq!(score, Some(1.0));
    }

    #[test]
    fn test_evaluate_rule_case_insensitive() {
        let service = DefaultCorrelationService::new();
        let rule = CorrelationRule {
            priority: 0,
            source_attribute: "username".to_string(),
            target_attribute: "uid".to_string(),
            match_type: CorrelationMatchType::CaseInsensitive,
            case_sensitive: false,
        };

        let mut source = HashMap::new();
        source.insert("username".to_string(), "JohnDoe".to_string());

        let mut target = AttributeSet::new();
        target.set("uid", "johndoe");

        let score = service.evaluate_rule(&rule, &source, &target);
        assert_eq!(score, Some(1.0));
    }

    #[test]
    fn test_evaluate_rule_no_match() {
        let service = DefaultCorrelationService::new();
        let rule = CorrelationRule {
            priority: 0,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: true,
        };

        let mut source = HashMap::new();
        source.insert("email".to_string(), "john@example.com".to_string());

        let mut target = AttributeSet::new();
        target.set("mail", "jane@example.com");

        let score = service.evaluate_rule(&rule, &source, &target);
        assert_eq!(score, None);
    }

    #[test]
    fn test_score_candidates() {
        let service = DefaultCorrelationService::new();
        let rules = vec![CorrelationRule {
            priority: 0,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: true,
        }];

        let mut source = HashMap::new();
        source.insert("email".to_string(), "john@example.com".to_string());

        let mut candidate1 = AttributeSet::new();
        candidate1.set("__uid__", "user1");
        candidate1.set("mail", "john@example.com");

        let mut candidate2 = AttributeSet::new();
        candidate2.set("__uid__", "user2");
        candidate2.set("mail", "jane@example.com");

        let candidates = vec![candidate1, candidate2];
        let matches = service.score_candidates(candidates, &source, &rules);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].uid.value(), "user1");
        assert_eq!(matches[0].confidence, 1.0);
    }

    #[test]
    fn test_build_search_filter_exact() {
        let service = DefaultCorrelationService::new();
        let rules = vec![CorrelationRule {
            priority: 0,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: true,
        }];

        let mut source = HashMap::new();
        source.insert("email".to_string(), "john@example.com".to_string());

        let filter = service.build_search_filter(&rules, &source);
        assert!(filter.is_some());
    }

    #[test]
    fn test_build_search_filter_no_value() {
        let service = DefaultCorrelationService::new();
        let rules = vec![CorrelationRule {
            priority: 0,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: true,
        }];

        let source = HashMap::new(); // Empty source

        let filter = service.build_search_filter(&rules, &source);
        assert!(filter.is_none());
    }
}
