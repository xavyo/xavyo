//! Privilege detector for identifying users with excessive access.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use xavyo_db::{CreateExcessivePrivilege, MiningJobParameters};
use xavyo_governance::error::Result;

use super::pattern_analyzer::UserEntitlements;

/// Detected excessive privilege for a user.
#[derive(Debug, Clone)]
pub struct DetectedExcessivePrivilege {
    /// The user with excessive access.
    pub user_id: Uuid,
    /// The peer group used for comparison.
    pub peer_group_id: Option<Uuid>,
    /// Percentage above peer average.
    pub deviation_percent: f64,
    /// Specific entitlements that are excessive.
    pub excess_entitlements: Vec<Uuid>,
    /// Peer group's average entitlement count.
    pub peer_average: f64,
    /// User's entitlement count.
    pub user_count: i32,
}

/// Peer group data for comparison.
#[derive(Debug, Clone)]
pub struct PeerGroupData {
    /// Peer group ID (if from database).
    pub id: Option<Uuid>,
    /// Group attribute value (e.g., "Engineering").
    pub attribute_value: String,
    /// User IDs in this peer group.
    pub user_ids: Vec<Uuid>,
}

/// Service for detecting excessive privileges.
pub struct PrivilegeDetector {
    params: MiningJobParameters,
}

impl PrivilegeDetector {
    /// Create a new privilege detector.
    #[must_use]
    pub fn new(params: MiningJobParameters) -> Self {
        Self { params }
    }

    /// Calculate peer averages from user entitlements grouped by peer group.
    pub fn calculate_peer_averages(
        &self,
        user_entitlements: &[UserEntitlements],
        peer_groups: &[PeerGroupData],
    ) -> Result<HashMap<Option<Uuid>, PeerAverage>> {
        let mut averages: HashMap<Option<Uuid>, PeerAverage> = HashMap::new();

        // Create a map of user_id to entitlement count
        let user_counts: HashMap<Uuid, i32> = user_entitlements
            .iter()
            .map(|ue| (ue.user_id, ue.entitlement_ids.len() as i32))
            .collect();

        for group in peer_groups {
            // Get entitlement counts for users in this group
            let group_counts: Vec<i32> = group
                .user_ids
                .iter()
                .filter_map(|uid| user_counts.get(uid))
                .copied()
                .collect();

            if group_counts.is_empty() {
                continue;
            }

            let sum: i32 = group_counts.iter().sum();
            let count = group_counts.len() as f64;
            let average = f64::from(sum) / count;

            // Calculate standard deviation
            let variance: f64 = group_counts
                .iter()
                .map(|&c| (f64::from(c) - average).powi(2))
                .sum::<f64>()
                / count;
            let std_dev = variance.sqrt();

            averages.insert(
                group.id,
                PeerAverage {
                    group_id: group.id,
                    average,
                    std_dev,
                    user_count: group_counts.len() as i32,
                },
            );
        }

        // If no groups provided, calculate overall average
        if peer_groups.is_empty() && !user_counts.is_empty() {
            let all_counts: Vec<i32> = user_counts.values().copied().collect();
            let sum: i32 = all_counts.iter().sum();
            let count = all_counts.len() as f64;
            let average = f64::from(sum) / count;

            let variance: f64 = all_counts
                .iter()
                .map(|&c| (f64::from(c) - average).powi(2))
                .sum::<f64>()
                / count;
            let std_dev = variance.sqrt();

            averages.insert(
                None,
                PeerAverage {
                    group_id: None,
                    average,
                    std_dev,
                    user_count: all_counts.len() as i32,
                },
            );
        }

        Ok(averages)
    }

    /// Detect users with excessive privileges compared to their peers.
    pub fn detect_excessive_users(
        &self,
        user_entitlements: &[UserEntitlements],
        peer_groups: &[PeerGroupData],
        peer_averages: &HashMap<Option<Uuid>, PeerAverage>,
    ) -> Result<Vec<DetectedExcessivePrivilege>> {
        let mut detections = Vec::new();

        // Create a map of user_id to peer group
        let user_to_group: HashMap<Uuid, Option<Uuid>> = peer_groups
            .iter()
            .flat_map(|g| g.user_ids.iter().map(move |uid| (*uid, g.id)))
            .collect();

        // Build common entitlements per peer group (entitlements held by >50% of peers)
        let common_entitlements =
            self.calculate_common_entitlements(user_entitlements, peer_groups);

        for ue in user_entitlements {
            let user_count = ue.entitlement_ids.len() as i32;
            let group_id = user_to_group.get(&ue.user_id).copied().flatten();

            // Get the appropriate peer average
            let peer_avg = peer_averages
                .get(&group_id)
                .or_else(|| peer_averages.get(&None));

            let Some(avg) = peer_avg else {
                continue;
            };

            // Calculate deviation
            let deviation = ((f64::from(user_count) - avg.average) / avg.average) * 100.0;

            // Check if deviation exceeds threshold
            if deviation > self.params.deviation_threshold {
                // Find the excess entitlements: those NOT in common entitlements for the peer group
                let common_set = common_entitlements
                    .get(&group_id)
                    .cloned()
                    .unwrap_or_default();

                let excess_entitlements: Vec<Uuid> = ue
                    .entitlement_ids
                    .iter()
                    .filter(|ent_id| !common_set.contains(ent_id))
                    .copied()
                    .collect();

                // Only flag if there are actual excess entitlements
                if !excess_entitlements.is_empty() {
                    detections.push(DetectedExcessivePrivilege {
                        user_id: ue.user_id,
                        peer_group_id: group_id,
                        deviation_percent: (deviation * 100.0).round() / 100.0,
                        excess_entitlements,
                        peer_average: (avg.average * 100.0).round() / 100.0,
                        user_count,
                    });
                }
            }
        }

        // Sort by deviation (highest first)
        detections.sort_by(|a, b| {
            b.deviation_percent
                .partial_cmp(&a.deviation_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(detections)
    }

    /// Calculate common entitlements for each peer group.
    /// An entitlement is "common" if held by more than 50% of peers in the group.
    fn calculate_common_entitlements(
        &self,
        user_entitlements: &[UserEntitlements],
        peer_groups: &[PeerGroupData],
    ) -> HashMap<Option<Uuid>, HashSet<Uuid>> {
        let mut result: HashMap<Option<Uuid>, HashSet<Uuid>> = HashMap::new();

        // Create user_id -> entitlements map
        let user_ents: HashMap<Uuid, &HashSet<Uuid>> = user_entitlements
            .iter()
            .map(|ue| (ue.user_id, &ue.entitlement_ids))
            .collect();

        for group in peer_groups {
            if group.user_ids.len() < 2 {
                continue;
            }

            // Count how many users have each entitlement
            let mut ent_counts: HashMap<Uuid, usize> = HashMap::new();
            for user_id in &group.user_ids {
                if let Some(ents) = user_ents.get(user_id) {
                    for ent_id in *ents {
                        *ent_counts.entry(*ent_id).or_insert(0) += 1;
                    }
                }
            }

            // Entitlements held by >50% of users are "common"
            let threshold = group.user_ids.len() / 2;
            let common: HashSet<Uuid> = ent_counts
                .into_iter()
                .filter(|(_, count)| *count > threshold)
                .map(|(ent_id, _)| ent_id)
                .collect();

            result.insert(group.id, common);
        }

        // Handle "all users" group (no specific group id)
        if peer_groups.is_empty() && !user_entitlements.is_empty() {
            let mut ent_counts: HashMap<Uuid, usize> = HashMap::new();
            for ue in user_entitlements {
                for ent_id in &ue.entitlement_ids {
                    *ent_counts.entry(*ent_id).or_insert(0) += 1;
                }
            }

            let threshold = user_entitlements.len() / 2;
            let common: HashSet<Uuid> = ent_counts
                .into_iter()
                .filter(|(_, count)| *count > threshold)
                .map(|(ent_id, _)| ent_id)
                .collect();

            result.insert(None, common);
        }

        result
    }

    /// Convert detections to database creation requests.
    #[must_use]
    pub fn detections_to_create_requests(
        &self,
        job_id: Uuid,
        detections: &[DetectedExcessivePrivilege],
    ) -> Vec<CreateExcessivePrivilege> {
        detections
            .iter()
            .map(|d| CreateExcessivePrivilege {
                job_id,
                user_id: d.user_id,
                peer_group_id: d.peer_group_id,
                deviation_percent: d.deviation_percent,
                excess_entitlements: d.excess_entitlements.clone(),
                peer_average: d.peer_average,
                user_count: d.user_count,
            })
            .collect()
    }
}

/// Peer group average statistics.
#[derive(Debug, Clone)]
pub struct PeerAverage {
    /// Peer group ID.
    pub group_id: Option<Uuid>,
    /// Average entitlement count.
    pub average: f64,
    /// Standard deviation.
    pub std_dev: f64,
    /// Number of users in group.
    pub user_count: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_peer_averages() {
        let params = MiningJobParameters {
            deviation_threshold: 50.0,
            ..Default::default()
        };

        let detector = PrivilegeDetector::new(params);

        let user_entitlements = vec![
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: (0..3).map(|_| Uuid::new_v4()).collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: (0..5).map(|_| Uuid::new_v4()).collect(),
            },
            UserEntitlements {
                user_id: Uuid::new_v4(),
                entitlement_ids: (0..4).map(|_| Uuid::new_v4()).collect(),
            },
        ];

        let averages = detector
            .calculate_peer_averages(&user_entitlements, &[])
            .unwrap();

        // Should have one "global" average
        assert_eq!(averages.len(), 1);
        let avg = averages.get(&None).unwrap();
        assert!((avg.average - 4.0).abs() < 0.01); // (3+5+4)/3 = 4
    }

    #[test]
    fn test_detect_excessive_privileges() {
        let params = MiningJobParameters {
            deviation_threshold: 50.0, // 50% above average
            ..Default::default()
        };

        let detector = PrivilegeDetector::new(params);

        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let user3 = Uuid::new_v4();

        // user3 has 8 entitlements, average is 4, deviation is 100%
        let user_entitlements = vec![
            UserEntitlements {
                user_id: user1,
                entitlement_ids: (0..3).map(|_| Uuid::new_v4()).collect(),
            },
            UserEntitlements {
                user_id: user2,
                entitlement_ids: (0..3).map(|_| Uuid::new_v4()).collect(),
            },
            UserEntitlements {
                user_id: user3,
                entitlement_ids: (0..8).map(|_| Uuid::new_v4()).collect(),
            },
        ];

        let averages = detector
            .calculate_peer_averages(&user_entitlements, &[])
            .unwrap();

        let detections = detector
            .detect_excessive_users(&user_entitlements, &[], &averages)
            .unwrap();

        // Only user3 should be flagged (100% > 50% threshold)
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].user_id, user3);
    }
}
