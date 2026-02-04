//! Duplicate Detection Service (F062).
//!
//! Provides identity duplicate detection using configurable correlation rules:
//! - Field-based correlation (name, email, employee ID, etc.)
//! - Weighted confidence scoring
//! - Batch detection scans
//! - Integration with `FuzzyMatchingService`

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovDuplicateCandidate, DismissGovDuplicateCandidate, DuplicateCandidateFilter,
    GovDuplicateCandidate, GovDuplicateStatus, RuleMatch, RuleMatches,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::fuzzy_matching_service::{FuzzyMatchConfig, FuzzyMatchingService};

/// Result of a duplicate detection scan.
#[derive(Debug, Clone)]
pub struct DetectionScanResult {
    /// Scan identifier.
    pub scan_id: Uuid,
    /// Number of users processed.
    pub users_processed: usize,
    /// Number of duplicate pairs found.
    pub duplicates_found: usize,
    /// Number of new duplicates (not previously detected).
    pub new_duplicates: usize,
    /// Duration of the scan in milliseconds.
    pub duration_ms: u64,
}

/// A potential duplicate pair with confidence scoring.
#[derive(Debug, Clone)]
pub struct DuplicatePair {
    /// First user ID.
    pub identity_a_id: Uuid,
    /// Second user ID.
    pub identity_b_id: Uuid,
    /// Overall confidence score (0.0 to 100.0).
    pub confidence_score: Decimal,
    /// Breakdown of scores by field.
    pub field_scores: HashMap<String, f64>,
    /// Rules that matched.
    pub matched_rules: Vec<RuleMatch>,
}

/// Configuration for a correlation rule.
#[derive(Debug, Clone)]
pub struct CorrelationRuleConfig {
    /// Rule ID (for tracking).
    pub id: Uuid,
    /// Rule name/identifier.
    pub name: String,
    /// Source field to compare (e.g., "email", "`first_name`").
    pub source_field: String,
    /// Target field to compare against.
    pub target_field: String,
    /// Weight of this rule in overall scoring.
    pub weight: f64,
    /// Minimum similarity threshold for this rule to match.
    pub threshold: f64,
    /// Whether to use fuzzy matching (vs exact).
    pub fuzzy: bool,
}

/// Service for detecting duplicate identities.
pub struct DuplicateDetectionService {
    pool: PgPool,
    fuzzy_service: FuzzyMatchingService,
}

impl DuplicateDetectionService {
    /// Create a new duplicate detection service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            fuzzy_service: FuzzyMatchingService::new(),
        }
    }

    /// Create with custom fuzzy matching configuration.
    #[must_use] 
    pub fn with_fuzzy_config(pool: PgPool, fuzzy_config: FuzzyMatchConfig) -> Self {
        Self {
            pool,
            fuzzy_service: FuzzyMatchingService::with_config(fuzzy_config),
        }
    }

    /// Run a duplicate detection scan for a tenant.
    pub async fn run_detection_scan(
        &self,
        tenant_id: Uuid,
        rules: &[CorrelationRuleConfig],
        min_confidence: f64,
    ) -> Result<DetectionScanResult> {
        let start = std::time::Instant::now();
        let scan_id = Uuid::new_v4();

        // Get all active users for the tenant
        let users = self.get_users_for_scan(tenant_id).await?;
        let users_processed = users.len();

        // Find duplicates using correlation rules
        let mut duplicates_found = 0;
        let mut new_duplicates = 0;
        let mut processed_pairs: HashSet<(Uuid, Uuid)> = HashSet::new();

        // Convert min_confidence from 0.0-1.0 to 0-100 scale
        let min_confidence_decimal =
            Decimal::from_f64_retain(min_confidence * 100.0).unwrap_or_else(|| Decimal::new(70, 0));

        for i in 0..users.len() {
            for j in (i + 1)..users.len() {
                let user1 = &users[i];
                let user2 = &users[j];

                // Normalize pair order for deduplication
                let pair = if user1.id < user2.id {
                    (user1.id, user2.id)
                } else {
                    (user2.id, user1.id)
                };

                if processed_pairs.contains(&pair) {
                    continue;
                }
                processed_pairs.insert(pair);

                // Calculate confidence score
                let duplicate = self.compare_users(user1, user2, rules)?;

                if duplicate.confidence_score >= min_confidence_decimal {
                    duplicates_found += 1;

                    // Check if this duplicate already exists
                    let exists = self
                        .duplicate_exists(
                            tenant_id,
                            duplicate.identity_a_id,
                            duplicate.identity_b_id,
                        )
                        .await?;

                    if !exists {
                        // Create new duplicate candidate
                        self.create_duplicate_candidate(tenant_id, &duplicate)
                            .await?;
                        new_duplicates += 1;
                    }
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(DetectionScanResult {
            scan_id,
            users_processed,
            duplicates_found,
            new_duplicates,
            duration_ms,
        })
    }

    /// Compare two users using correlation rules.
    fn compare_users(
        &self,
        user1: &UserScanData,
        user2: &UserScanData,
        rules: &[CorrelationRuleConfig],
    ) -> Result<DuplicatePair> {
        let mut field_scores: HashMap<String, f64> = HashMap::new();
        let mut matched_rules: Vec<RuleMatch> = Vec::new();
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        for rule in rules {
            let value1 = user1.get_field(&rule.source_field);
            let value2 = user2.get_field(&rule.target_field);

            if let (Some(v1), Some(v2)) = (value1, value2) {
                if v1.is_empty() || v2.is_empty() {
                    continue;
                }

                let score = if rule.fuzzy {
                    let result = self.fuzzy_service.compare(v1, v2);
                    result.combined_score
                } else {
                    // Exact match (case-insensitive)
                    if v1.to_lowercase() == v2.to_lowercase() {
                        1.0
                    } else {
                        0.0
                    }
                };

                field_scores.insert(rule.source_field.clone(), score);

                if score >= rule.threshold {
                    let rule_match = RuleMatch {
                        rule_id: rule.id,
                        rule_name: rule.name.clone(),
                        attribute: rule.source_field.clone(),
                        value_a: Some(v1.to_string()),
                        value_b: Some(v2.to_string()),
                        similarity: score,
                        weighted_score: score * rule.weight * 100.0, // Scale to percentage
                    };
                    matched_rules.push(rule_match);
                }

                weighted_sum += score * rule.weight;
                total_weight += rule.weight;
            }
        }

        // Calculate confidence as percentage (0-100)
        let confidence = if total_weight > 0.0 {
            (weighted_sum / total_weight) * 100.0
        } else {
            0.0
        };

        let confidence_score =
            Decimal::from_f64_retain(confidence).unwrap_or_else(|| Decimal::new(0, 0));

        let _total_confidence: f64 = matched_rules.iter().map(|m| m.weighted_score).sum();

        Ok(DuplicatePair {
            identity_a_id: user1.id,
            identity_b_id: user2.id,
            confidence_score,
            field_scores,
            matched_rules,
        })
    }

    /// Get users for scanning.
    async fn get_users_for_scan(&self, tenant_id: Uuid) -> Result<Vec<UserScanData>> {
        let rows = sqlx::query_as!(
            UserScanRow,
            r#"
            SELECT
                id,
                email,
                display_name,
                custom_attributes
            FROM users
            WHERE tenant_id = $1 AND is_active = true
            ORDER BY created_at
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(rows.into_iter().map(UserScanData::from).collect())
    }

    /// Check if a duplicate already exists.
    async fn duplicate_exists(
        &self,
        tenant_id: Uuid,
        identity_a: Uuid,
        identity_b: Uuid,
    ) -> Result<bool> {
        let exists =
            GovDuplicateCandidate::find_by_pair(&self.pool, tenant_id, identity_a, identity_b)
                .await
                .map_err(GovernanceError::Database)?;

        Ok(exists.is_some())
    }

    /// Create a new duplicate candidate record.
    async fn create_duplicate_candidate(
        &self,
        tenant_id: Uuid,
        duplicate: &DuplicatePair,
    ) -> Result<GovDuplicateCandidate> {
        let total_confidence = duplicate
            .matched_rules
            .iter()
            .map(|m| m.weighted_score)
            .sum();

        let rule_matches = RuleMatches {
            matches: duplicate.matched_rules.clone(),
            total_confidence,
        };

        let create_data = CreateGovDuplicateCandidate {
            identity_a_id: duplicate.identity_a_id,
            identity_b_id: duplicate.identity_b_id,
            confidence_score: duplicate.confidence_score,
            rule_matches,
        };

        GovDuplicateCandidate::upsert(&self.pool, tenant_id, create_data)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get default correlation rules.
    ///
    /// These rules compare standard user fields. Additional custom fields
    /// can be compared by providing custom `CorrelationRuleConfig` entries
    /// that reference `custom_attributes` keys.
    #[must_use] 
    pub fn default_rules() -> Vec<CorrelationRuleConfig> {
        vec![
            CorrelationRuleConfig {
                id: Uuid::new_v4(),
                name: "email_exact".to_string(),
                source_field: "email".to_string(),
                target_field: "email".to_string(),
                weight: 1.0,
                threshold: 1.0,
                fuzzy: false,
            },
            CorrelationRuleConfig {
                id: Uuid::new_v4(),
                name: "email_fuzzy".to_string(),
                source_field: "email".to_string(),
                target_field: "email".to_string(),
                weight: 0.7,
                threshold: 0.9,
                fuzzy: true,
            },
            CorrelationRuleConfig {
                id: Uuid::new_v4(),
                name: "display_name_fuzzy".to_string(),
                source_field: "display_name".to_string(),
                target_field: "display_name".to_string(),
                weight: 0.8,
                threshold: 0.85,
                fuzzy: true,
            },
            // Custom attributes that may exist (employee_id is commonly used)
            CorrelationRuleConfig {
                id: Uuid::new_v4(),
                name: "employee_id_exact".to_string(),
                source_field: "employee_id".to_string(),
                target_field: "employee_id".to_string(),
                weight: 1.0,
                threshold: 1.0,
                fuzzy: false,
            },
            CorrelationRuleConfig {
                id: Uuid::new_v4(),
                name: "phone_exact".to_string(),
                source_field: "phone".to_string(),
                target_field: "phone".to_string(),
                weight: 0.9,
                threshold: 1.0,
                fuzzy: false,
            },
        ]
    }

    /// List duplicate candidates for a tenant.
    pub async fn list_duplicates(
        &self,
        tenant_id: Uuid,
        status_filter: Option<GovDuplicateStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovDuplicateCandidate>> {
        let filter = DuplicateCandidateFilter {
            status: status_filter,
            ..Default::default()
        };

        GovDuplicateCandidate::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Dismiss a duplicate candidate.
    pub async fn dismiss_duplicate(
        &self,
        tenant_id: Uuid,
        duplicate_id: Uuid,
        dismissed_by: Uuid,
        reason: String,
    ) -> Result<Option<GovDuplicateCandidate>> {
        let dismiss_input = DismissGovDuplicateCandidate {
            reason,
            dismissed_by,
        };

        GovDuplicateCandidate::dismiss(&self.pool, tenant_id, duplicate_id, dismiss_input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get duplicate statistics for a tenant.
    pub async fn get_statistics(&self, tenant_id: Uuid) -> Result<DuplicateStatistics> {
        // Count by status
        let pending_filter = DuplicateCandidateFilter {
            status: Some(GovDuplicateStatus::Pending),
            ..Default::default()
        };
        let merged_filter = DuplicateCandidateFilter {
            status: Some(GovDuplicateStatus::Merged),
            ..Default::default()
        };
        let dismissed_filter = DuplicateCandidateFilter {
            status: Some(GovDuplicateStatus::Dismissed),
            ..Default::default()
        };
        let total_filter = DuplicateCandidateFilter::default();

        let pending =
            GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, &pending_filter)
                .await
                .map_err(GovernanceError::Database)?;
        let merged = GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, &merged_filter)
            .await
            .map_err(GovernanceError::Database)?;
        let dismissed =
            GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, &dismissed_filter)
                .await
                .map_err(GovernanceError::Database)?;
        let total = GovDuplicateCandidate::count_by_tenant(&self.pool, tenant_id, &total_filter)
            .await
            .map_err(GovernanceError::Database)?;

        // Get average confidence from recent candidates
        let recent =
            GovDuplicateCandidate::list_by_tenant(&self.pool, tenant_id, &total_filter, 100, 0)
                .await
                .map_err(GovernanceError::Database)?;

        let avg_confidence = if recent.is_empty() {
            0.0
        } else {
            let sum: f64 = recent
                .iter()
                .filter_map(|c| c.confidence_score.to_f64())
                .sum();
            sum / recent.len() as f64
        };

        Ok(DuplicateStatistics {
            total_candidates: total as usize,
            pending: pending as usize,
            dismissed: dismissed as usize,
            merged: merged as usize,
            average_confidence: avg_confidence,
        })
    }
}

/// User data for scanning (minimal fields needed for comparison).
#[derive(Debug, Clone)]
struct UserScanData {
    id: Uuid,
    email: String,
    display_name: Option<String>,
    custom_attributes: serde_json::Value,
}

impl UserScanData {
    fn get_field(&self, field: &str) -> Option<&str> {
        match field {
            "email" => Some(&self.email),
            "display_name" => self.display_name.as_deref(),
            "full_name" => self.display_name.as_deref(), // Alias for display_name
            _ => {
                // Try to get from custom_attributes
                self.custom_attributes.get(field).and_then(|v| v.as_str())
            }
        }
    }

    /// Get a custom attribute value.
    #[allow(dead_code)]
    fn get_custom_attribute(&self, key: &str) -> Option<&str> {
        self.custom_attributes.get(key).and_then(|v| v.as_str())
    }
}

/// Database row for user scan query.
struct UserScanRow {
    id: Uuid,
    email: String,
    display_name: Option<String>,
    custom_attributes: serde_json::Value,
}

impl From<UserScanRow> for UserScanData {
    fn from(row: UserScanRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            display_name: row.display_name,
            custom_attributes: row.custom_attributes,
        }
    }
}

/// Statistics for duplicate detection.
#[derive(Debug, Clone)]
pub struct DuplicateStatistics {
    pub total_candidates: usize,
    pub pending: usize,
    pub dismissed: usize,
    pub merged: usize,
    pub average_confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_rules() {
        let rules = DuplicateDetectionService::default_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.name == "email_exact"));
        assert!(rules.iter().any(|r| r.name == "display_name_fuzzy"));
    }

    #[test]
    fn test_correlation_rule_config() {
        let rule = CorrelationRuleConfig {
            id: Uuid::new_v4(),
            name: "test_rule".to_string(),
            source_field: "email".to_string(),
            target_field: "email".to_string(),
            weight: 1.0,
            threshold: 1.0,
            fuzzy: false,
        };
        assert_eq!(rule.weight, 1.0);
        assert!(!rule.fuzzy);
    }

    #[test]
    fn test_user_scan_data_get_field() {
        let user = UserScanData {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            display_name: Some("John Smith".to_string()),
            custom_attributes: serde_json::json!({
                "employee_id": "EMP001",
                "phone": "+1234567890"
            }),
        };

        assert_eq!(user.get_field("email"), Some("test@example.com"));
        assert_eq!(user.get_field("display_name"), Some("John Smith"));
        assert_eq!(user.get_field("full_name"), Some("John Smith")); // Alias
        assert_eq!(user.get_field("employee_id"), Some("EMP001"));
        assert_eq!(user.get_field("phone"), Some("+1234567890"));
        assert_eq!(user.get_field("nonexistent"), None);
    }

    #[test]
    fn test_duplicate_statistics_default() {
        let stats = DuplicateStatistics {
            total_candidates: 0,
            pending: 0,
            dismissed: 0,
            merged: 0,
            average_confidence: 0.0,
        };
        assert_eq!(stats.total_candidates, 0);
    }
}
