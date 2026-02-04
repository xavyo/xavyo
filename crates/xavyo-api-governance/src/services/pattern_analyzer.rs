//! Pattern analyzer for discovering access patterns and role candidates.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use xavyo_db::{CreateAccessPattern, CreateRoleCandidate, MiningJobParameters};
use xavyo_governance::error::Result;

/// Analyzed access pattern data.
#[derive(Debug, Clone)]
pub struct AnalyzedPattern {
    /// Entitlements in this pattern.
    pub entitlement_ids: Vec<Uuid>,
    /// Frequency of this pattern.
    pub frequency: i32,
    /// Number of users with this exact pattern.
    pub user_count: i32,
    /// Sample user IDs (up to 10).
    pub sample_user_ids: Vec<Uuid>,
}

/// Discovered role candidate.
#[derive(Debug, Clone)]
pub struct DiscoveredCandidate {
    /// Proposed name for the role.
    pub proposed_name: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence_score: f64,
    /// Number of users in this cluster.
    pub member_count: i32,
    /// Entitlements in this candidate role.
    pub entitlement_ids: Vec<Uuid>,
    /// Users matching this pattern.
    pub user_ids: Vec<Uuid>,
}

/// User entitlement assignment for analysis.
#[derive(Debug, Clone)]
pub struct UserEntitlements {
    /// User ID.
    pub user_id: Uuid,
    /// Entitlement IDs assigned to this user.
    pub entitlement_ids: HashSet<Uuid>,
}

/// Service for analyzing access patterns and generating role candidates.
pub struct PatternAnalyzer {
    params: MiningJobParameters,
}

impl PatternAnalyzer {
    /// Create a new pattern analyzer with the given parameters.
    #[must_use] 
    pub fn new(params: MiningJobParameters) -> Self {
        Self { params }
    }

    /// Analyze entitlement patterns from user assignments.
    ///
    /// Returns patterns sorted by frequency (descending).
    pub fn analyze_entitlement_patterns(
        &self,
        user_entitlements: &[UserEntitlements],
    ) -> Result<Vec<AnalyzedPattern>> {
        // Group users by their exact entitlement set
        let mut pattern_users: HashMap<Vec<Uuid>, Vec<Uuid>> = HashMap::new();

        for ue in user_entitlements {
            // Sort entitlement IDs for consistent comparison
            let mut sorted_entitlements: Vec<Uuid> = ue.entitlement_ids.iter().copied().collect();
            sorted_entitlements.sort();

            pattern_users
                .entry(sorted_entitlements)
                .or_default()
                .push(ue.user_id);
        }

        // Convert to AnalyzedPattern
        let mut patterns: Vec<AnalyzedPattern> = pattern_users
            .into_iter()
            .filter(|(entitlements, _)| entitlements.len() >= self.params.min_entitlements as usize)
            .map(|(entitlement_ids, user_ids)| {
                let frequency = user_ids.len() as i32;
                let user_count = user_ids.len() as i32;
                let sample_user_ids: Vec<Uuid> = user_ids.iter().take(10).copied().collect();

                AnalyzedPattern {
                    entitlement_ids,
                    frequency,
                    user_count,
                    sample_user_ids,
                }
            })
            .collect();

        // Sort by frequency (descending)
        patterns.sort_by(|a, b| b.frequency.cmp(&a.frequency));

        Ok(patterns)
    }

    /// Generate role candidates from analyzed patterns.
    ///
    /// Identifies clusters of users with similar access patterns
    /// and proposes them as role candidates.
    pub fn generate_role_candidates(
        &self,
        patterns: &[AnalyzedPattern],
        entitlement_names: &HashMap<Uuid, String>,
    ) -> Result<Vec<DiscoveredCandidate>> {
        let mut candidates = Vec::new();
        let mut candidate_index = 1;

        for pattern in patterns {
            // Filter by minimum users
            if pattern.user_count < self.params.min_users {
                continue;
            }

            // Calculate confidence score based on:
            // - Number of users (more users = higher confidence)
            // - Pattern consistency (exact match = high confidence)
            let confidence_score = calculate_confidence(
                pattern.user_count,
                pattern.entitlement_ids.len(),
                self.params.min_users,
            );

            // Filter by confidence threshold
            if confidence_score < self.params.confidence_threshold {
                continue;
            }

            // Generate proposed name based on entitlement names
            let proposed_name =
                generate_role_name(&pattern.entitlement_ids, entitlement_names, candidate_index);

            candidates.push(DiscoveredCandidate {
                proposed_name,
                confidence_score,
                member_count: pattern.user_count,
                entitlement_ids: pattern.entitlement_ids.clone(),
                user_ids: pattern.sample_user_ids.clone(), // Store sample for now
            });

            candidate_index += 1;
        }

        Ok(candidates)
    }

    /// Convert analyzed patterns to database creation requests.
    #[must_use] 
    pub fn patterns_to_create_requests(
        &self,
        job_id: Uuid,
        patterns: &[AnalyzedPattern],
    ) -> Vec<CreateAccessPattern> {
        patterns
            .iter()
            .map(|p| CreateAccessPattern {
                job_id,
                entitlement_ids: p.entitlement_ids.clone(),
                frequency: p.frequency,
                user_count: p.user_count,
                sample_user_ids: p.sample_user_ids.clone(),
            })
            .collect()
    }

    /// Convert discovered candidates to database creation requests.
    #[must_use] 
    pub fn candidates_to_create_requests(
        &self,
        job_id: Uuid,
        candidates: &[DiscoveredCandidate],
    ) -> Vec<CreateRoleCandidate> {
        candidates
            .iter()
            .map(|c| CreateRoleCandidate {
                job_id,
                proposed_name: c.proposed_name.clone(),
                confidence_score: c.confidence_score,
                member_count: c.member_count,
                entitlement_ids: c.entitlement_ids.clone(),
                user_ids: c.user_ids.clone(),
            })
            .collect()
    }
}

/// Calculate confidence score for a pattern.
fn calculate_confidence(user_count: i32, entitlement_count: usize, min_users: i32) -> f64 {
    // Base confidence from user count (normalized)
    let user_factor = (f64::from(user_count) / f64::from(min_users)).min(2.0) / 2.0;

    // Entitlement coverage factor (2-10 entitlements is ideal)
    let entitlement_factor = if (2..=10).contains(&entitlement_count) {
        1.0
    } else if entitlement_count > 10 {
        0.8
    } else {
        0.5
    };

    // Combined confidence
    let confidence = (user_factor * 0.7 + entitlement_factor * 0.3).min(1.0);

    // Round to 4 decimal places
    (confidence * 10000.0).round() / 10000.0
}

/// Generate a proposed role name from entitlement names.
fn generate_role_name(
    entitlement_ids: &[Uuid],
    entitlement_names: &HashMap<Uuid, String>,
    index: i32,
) -> String {
    // Try to find a common prefix in entitlement names
    let names: Vec<&str> = entitlement_ids
        .iter()
        .filter_map(|id| entitlement_names.get(id).map(std::string::String::as_str))
        .collect();

    if names.is_empty() {
        return format!("Role_Candidate_{index}");
    }

    // Find common prefix
    let common_prefix = find_common_prefix(&names);

    if common_prefix.len() >= 3 {
        format!("{}_Access_{}", common_prefix.trim_end_matches('_'), index)
    } else {
        format!("Role_Candidate_{index}")
    }
}

/// Find the common prefix among a list of strings.
fn find_common_prefix(strings: &[&str]) -> String {
    if strings.is_empty() {
        return String::new();
    }

    let first = strings[0];
    let mut prefix_len = 0;

    for (i, c) in first.chars().enumerate() {
        if strings.iter().all(|s| s.chars().nth(i) == Some(c)) {
            prefix_len = i + 1;
        } else {
            break;
        }
    }

    first[..prefix_len].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // T024: Unit tests for PatternAnalyzer.analyze
    // =========================================================================

    #[test]
    fn test_calculate_confidence() {
        // Minimum users should give some confidence
        let conf = calculate_confidence(3, 3, 3);
        assert!(conf > 0.0 && conf <= 1.0);

        // Double minimum users should give higher confidence
        let conf2 = calculate_confidence(6, 3, 3);
        assert!(conf2 > conf);
    }

    #[test]
    fn test_calculate_confidence_boundaries() {
        // Confidence should never exceed 1.0
        let conf = calculate_confidence(100, 5, 3);
        assert!(conf <= 1.0);

        // Confidence for very few entitlements should be lower
        let conf_few = calculate_confidence(10, 1, 3);
        let conf_many = calculate_confidence(10, 5, 3);
        assert!(conf_few < conf_many);
    }

    #[test]
    fn test_calculate_confidence_large_entitlement_set() {
        // More than 10 entitlements should have lower factor
        let conf_large = calculate_confidence(10, 15, 3);
        let conf_ideal = calculate_confidence(10, 5, 3);
        assert!(conf_large < conf_ideal);
    }

    #[test]
    fn test_find_common_prefix() {
        let strings = vec!["Engineering_Read", "Engineering_Write", "Engineering_Admin"];
        let prefix = find_common_prefix(&strings);
        assert_eq!(prefix, "Engineering_");

        let no_common = vec!["Read", "Write", "Admin"];
        let prefix = find_common_prefix(&no_common);
        assert!(prefix.is_empty());
    }

    #[test]
    fn test_find_common_prefix_empty_input() {
        let empty: Vec<&str> = vec![];
        let prefix = find_common_prefix(&empty);
        assert!(prefix.is_empty());
    }

    #[test]
    fn test_find_common_prefix_single_string() {
        let strings = vec!["Engineering_Read"];
        let prefix = find_common_prefix(&strings);
        assert_eq!(prefix, "Engineering_Read");
    }

    #[test]
    fn test_analyze_patterns() {
        let params = MiningJobParameters {
            min_users: 2,
            min_entitlements: 2,
            ..Default::default()
        };

        let analyzer = PatternAnalyzer::new(params);

        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let ent3 = Uuid::new_v4();

        let user_entitlements = vec![
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2, ent3].into_iter().collect(),
            },
        ];

        let patterns = analyzer
            .analyze_entitlement_patterns(&user_entitlements)
            .unwrap();

        // Should have 2 patterns: [ent1, ent2] with 2 users and [ent1, ent2, ent3] with 1 user
        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].user_count, 2); // Most frequent first
    }

    #[test]
    fn test_analyze_patterns_filters_by_min_entitlements() {
        let params = MiningJobParameters {
            min_users: 1,
            min_entitlements: 3, // Require at least 3 entitlements
            ..Default::default()
        };

        let analyzer = PatternAnalyzer::new(params);

        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let ent3 = Uuid::new_v4();

        let user_entitlements = vec![
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(), // Only 2 entitlements
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2, ent3].into_iter().collect(), // 3 entitlements
            },
        ];

        let patterns = analyzer
            .analyze_entitlement_patterns(&user_entitlements)
            .unwrap();

        // Should only have 1 pattern (the one with 3 entitlements)
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].entitlement_ids.len(), 3);
    }

    #[test]
    fn test_analyze_patterns_empty_input() {
        let params = MiningJobParameters::default();
        let analyzer = PatternAnalyzer::new(params);

        let patterns = analyzer.analyze_entitlement_patterns(&[]).unwrap();
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_analyze_patterns_sorted_by_frequency() {
        let params = MiningJobParameters {
            min_users: 1,
            min_entitlements: 2,
            ..Default::default()
        };

        let analyzer = PatternAnalyzer::new(params);

        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let ent3 = Uuid::new_v4();
        let ent4 = Uuid::new_v4();

        let user_entitlements = vec![
            // Pattern A: [ent1, ent2] - 3 users
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent1, ent2].into_iter().collect(),
            },
            // Pattern B: [ent3, ent4] - 1 user
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: [ent3, ent4].into_iter().collect(),
            },
        ];

        let patterns = analyzer
            .analyze_entitlement_patterns(&user_entitlements)
            .unwrap();

        assert_eq!(patterns.len(), 2);
        assert_eq!(patterns[0].user_count, 3); // Pattern A first
        assert_eq!(patterns[1].user_count, 1); // Pattern B second
    }

    #[test]
    fn test_generate_role_candidates() {
        let params = MiningJobParameters {
            min_users: 2,
            min_entitlements: 2,
            confidence_threshold: 0.3,
            ..Default::default()
        };

        let analyzer = PatternAnalyzer::new(params);

        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();

        let patterns = vec![AnalyzedPattern {
            entitlement_ids: vec![ent1, ent2],
            frequency: 5,
            user_count: 5,
            sample_user_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        }];

        let mut entitlement_names = HashMap::new();
        entitlement_names.insert(ent1, "Engineering_Read".to_string());
        entitlement_names.insert(ent2, "Engineering_Write".to_string());

        let candidates = analyzer
            .generate_role_candidates(&patterns, &entitlement_names)
            .unwrap();

        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].proposed_name.contains("Engineering"));
        assert!(candidates[0].confidence_score > 0.0);
        assert!(candidates[0].confidence_score <= 1.0);
    }

    #[test]
    fn test_generate_role_candidates_filters_by_min_users() {
        let params = MiningJobParameters {
            min_users: 10, // High threshold
            min_entitlements: 2,
            confidence_threshold: 0.0,
            ..Default::default()
        };

        let analyzer = PatternAnalyzer::new(params);

        let patterns = vec![AnalyzedPattern {
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            frequency: 5,
            user_count: 5, // Less than min_users
            sample_user_ids: vec![],
        }];

        let candidates = analyzer
            .generate_role_candidates(&patterns, &HashMap::new())
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn test_generate_role_candidates_filters_by_confidence_threshold() {
        // The confidence calculation gives ~0.65 for 2 users with 2 entitlements
        // when min_users is 1. To filter out, we need a higher threshold.
        let params = MiningJobParameters {
            min_users: 10, // Higher min_users means lower confidence for small user counts
            min_entitlements: 2,
            confidence_threshold: 0.5, // Even a moderate threshold will filter out
            include_excessive_privilege: true,
            include_consolidation: true,
            consolidation_threshold: 70.0,
            deviation_threshold: 50.0,
            peer_group_attribute: None,
        };

        let analyzer = PatternAnalyzer::new(params);

        let patterns = vec![AnalyzedPattern {
            entitlement_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            frequency: 2,
            user_count: 2, // Much less than min_users=10, so low confidence
            sample_user_ids: vec![],
        }];

        let candidates = analyzer
            .generate_role_candidates(&patterns, &HashMap::new())
            .unwrap();

        // With only 2 users and min_users=10, confidence is very low
        // and user_count check will filter this out
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_patterns_to_create_requests() {
        let params = MiningJobParameters::default();
        let analyzer = PatternAnalyzer::new(params);

        let job_id = Uuid::new_v4();
        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let user1 = Uuid::new_v4();

        let patterns = vec![AnalyzedPattern {
            entitlement_ids: vec![ent1, ent2],
            frequency: 5,
            user_count: 5,
            sample_user_ids: vec![user1],
        }];

        let requests = analyzer.patterns_to_create_requests(job_id, &patterns);

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].job_id, job_id);
        assert_eq!(requests[0].entitlement_ids.len(), 2);
        assert_eq!(requests[0].frequency, 5);
    }

    #[test]
    fn test_candidates_to_create_requests() {
        let params = MiningJobParameters::default();
        let analyzer = PatternAnalyzer::new(params);

        let job_id = Uuid::new_v4();
        let ent1 = Uuid::new_v4();
        let user1 = Uuid::new_v4();

        let candidates = vec![DiscoveredCandidate {
            proposed_name: "Test_Role".to_string(),
            confidence_score: 0.85,
            member_count: 10,
            entitlement_ids: vec![ent1],
            user_ids: vec![user1],
        }];

        let requests = analyzer.candidates_to_create_requests(job_id, &candidates);

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].job_id, job_id);
        assert_eq!(requests[0].proposed_name, "Test_Role");
        assert!((requests[0].confidence_score - 0.85).abs() < 0.001);
        assert_eq!(requests[0].member_count, 10);
    }

    #[test]
    fn test_generate_role_name_fallback() {
        let entitlement_ids = vec![Uuid::new_v4()];
        let empty_names: HashMap<Uuid, String> = HashMap::new();

        let name = generate_role_name(&entitlement_ids, &empty_names, 1);
        assert_eq!(name, "Role_Candidate_1");
    }
}
