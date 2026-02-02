//! Consolidation analyzer for identifying overlapping roles.

use std::collections::HashSet;
use uuid::Uuid;

use xavyo_db::{CreateConsolidationSuggestion, MiningJobParameters};
use xavyo_governance::error::Result;

/// Role data for consolidation analysis.
#[derive(Debug, Clone)]
pub struct RoleData {
    /// Role ID.
    pub role_id: Uuid,
    /// Role name.
    pub name: String,
    /// Entitlements in this role.
    pub entitlement_ids: HashSet<Uuid>,
}

/// Consolidation suggestion for overlapping roles.
#[derive(Debug, Clone)]
pub struct ConsolidationSuggestionData {
    /// First role in the pair.
    pub role_a_id: Uuid,
    /// First role name.
    pub role_a_name: String,
    /// Second role in the pair.
    pub role_b_id: Uuid,
    /// Second role name.
    pub role_b_name: String,
    /// Percentage of overlap (Jaccard similarity * 100).
    pub overlap_percent: f64,
    /// Entitlements shared between both roles.
    pub shared_entitlements: Vec<Uuid>,
    /// Entitlements only in role A.
    pub unique_to_a: Vec<Uuid>,
    /// Entitlements only in role B.
    pub unique_to_b: Vec<Uuid>,
}

/// Service for analyzing role consolidation opportunities.
pub struct ConsolidationAnalyzer {
    params: MiningJobParameters,
}

impl ConsolidationAnalyzer {
    /// Create a new consolidation analyzer.
    pub fn new(params: MiningJobParameters) -> Self {
        Self { params }
    }

    /// Calculate Jaccard similarity between two sets.
    ///
    /// Jaccard(A, B) = |A ∩ B| / |A ∪ B|
    pub fn calculate_jaccard_similarity(set_a: &HashSet<Uuid>, set_b: &HashSet<Uuid>) -> f64 {
        if set_a.is_empty() && set_b.is_empty() {
            return 0.0;
        }

        let intersection: HashSet<_> = set_a.intersection(set_b).collect();
        let union: HashSet<_> = set_a.union(set_b).collect();

        intersection.len() as f64 / union.len() as f64
    }

    /// Find overlapping roles that could be consolidated.
    pub fn find_overlapping_roles(
        &self,
        roles: &[RoleData],
    ) -> Result<Vec<ConsolidationSuggestionData>> {
        let mut suggestions = Vec::new();
        let threshold = self.params.consolidation_threshold / 100.0; // Convert to 0-1 range

        // Compare each pair of roles
        for i in 0..roles.len() {
            for j in (i + 1)..roles.len() {
                let role_a = &roles[i];
                let role_b = &roles[j];

                let similarity = Self::calculate_jaccard_similarity(
                    &role_a.entitlement_ids,
                    &role_b.entitlement_ids,
                );

                if similarity >= threshold {
                    // Calculate set differences
                    let shared: Vec<Uuid> = role_a
                        .entitlement_ids
                        .intersection(&role_b.entitlement_ids)
                        .copied()
                        .collect();

                    let unique_to_a: Vec<Uuid> = role_a
                        .entitlement_ids
                        .difference(&role_b.entitlement_ids)
                        .copied()
                        .collect();

                    let unique_to_b: Vec<Uuid> = role_b
                        .entitlement_ids
                        .difference(&role_a.entitlement_ids)
                        .copied()
                        .collect();

                    suggestions.push(ConsolidationSuggestionData {
                        role_a_id: role_a.role_id,
                        role_a_name: role_a.name.clone(),
                        role_b_id: role_b.role_id,
                        role_b_name: role_b.name.clone(),
                        overlap_percent: (similarity * 100.0 * 100.0).round() / 100.0,
                        shared_entitlements: shared,
                        unique_to_a,
                        unique_to_b,
                    });
                }
            }
        }

        // Sort by overlap percentage (highest first)
        suggestions.sort_by(|a, b| {
            b.overlap_percent
                .partial_cmp(&a.overlap_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(suggestions)
    }

    /// Convert suggestions to database creation requests.
    pub fn suggestions_to_create_requests(
        &self,
        job_id: Uuid,
        suggestions: &[ConsolidationSuggestionData],
    ) -> Vec<CreateConsolidationSuggestion> {
        suggestions
            .iter()
            .map(|s| CreateConsolidationSuggestion {
                job_id,
                role_a_id: s.role_a_id,
                role_b_id: s.role_b_id,
                overlap_percent: s.overlap_percent,
                shared_entitlements: s.shared_entitlements.clone(),
                unique_to_a: s.unique_to_a.clone(),
                unique_to_b: s.unique_to_b.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jaccard_similarity_identical() {
        let set_a: HashSet<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let set_b = set_a.clone();

        let similarity = ConsolidationAnalyzer::calculate_jaccard_similarity(&set_a, &set_b);
        assert!((similarity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_similarity_disjoint() {
        let set_a: HashSet<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        let set_b: HashSet<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();

        let similarity = ConsolidationAnalyzer::calculate_jaccard_similarity(&set_a, &set_b);
        assert!((similarity - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_jaccard_similarity_partial_overlap() {
        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let ent3 = Uuid::new_v4();
        let ent4 = Uuid::new_v4();

        // set_a = {1, 2, 3}, set_b = {2, 3, 4}
        // intersection = {2, 3}, union = {1, 2, 3, 4}
        // Jaccard = 2/4 = 0.5
        let set_a: HashSet<Uuid> = [ent1, ent2, ent3].into_iter().collect();
        let set_b: HashSet<Uuid> = [ent2, ent3, ent4].into_iter().collect();

        let similarity = ConsolidationAnalyzer::calculate_jaccard_similarity(&set_a, &set_b);
        assert!((similarity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_find_overlapping_roles() {
        let params = MiningJobParameters {
            consolidation_threshold: 50.0, // 50% overlap threshold
            ..Default::default()
        };

        let analyzer = ConsolidationAnalyzer::new(params);

        let ent1 = Uuid::new_v4();
        let ent2 = Uuid::new_v4();
        let ent3 = Uuid::new_v4();
        let ent4 = Uuid::new_v4();

        let roles = vec![
            RoleData {
                role_id: Uuid::new_v4(),
                name: "Role_A".to_string(),
                entitlement_ids: [ent1, ent2, ent3].into_iter().collect(),
            },
            RoleData {
                role_id: Uuid::new_v4(),
                name: "Role_B".to_string(),
                entitlement_ids: [ent2, ent3, ent4].into_iter().collect(),
            },
            RoleData {
                role_id: Uuid::new_v4(),
                name: "Role_C".to_string(),
                entitlement_ids: [Uuid::new_v4()].into_iter().collect(), // Disjoint
            },
        ];

        let suggestions = analyzer.find_overlapping_roles(&roles).unwrap();

        // Only Role_A and Role_B should be suggested (50% overlap)
        assert_eq!(suggestions.len(), 1);
        assert!((suggestions[0].overlap_percent - 50.0).abs() < 0.01);
    }
}
