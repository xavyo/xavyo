//! Peer group service for governance API.

use std::time::Instant;

use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

use xavyo_db::{
    CreateGovPeerGroup, GovAssignmentFilter, GovAssignmentTargetType, GovEntitlementAssignment,
    GovPeerGroup, GovPeerGroupMember, PeerGroupFilter, UpdateGovPeerGroupStats,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreatePeerGroupRequest, ListPeerGroupsQuery, PeerGroupComparison, PeerGroupListResponse,
    PeerGroupResponse, RefreshPeerGroupsResponse, RefreshStatsResponse, UserPeerComparisonResponse,
};

/// Minimum number of users required for a peer group to be statistically valid.
const MIN_PEER_GROUP_SIZE: i32 = 5;

/// Default threshold for outlier detection (2 standard deviations).
const DEFAULT_OUTLIER_THRESHOLD: f64 = 2.0;

/// Service for managing peer groups and outlier detection.
pub struct PeerGroupService {
    pool: PgPool,
}

impl PeerGroupService {
    /// Create a new peer group service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new peer group.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        request: CreatePeerGroupRequest,
    ) -> ApiResult<PeerGroupResponse> {
        request.validate()?;

        let input = CreateGovPeerGroup {
            name: request.name,
            group_type: request.group_type,
            attribute_key: request.attribute_key,
            attribute_value: request.attribute_value,
        };

        let group = GovPeerGroup::create(&self.pool, tenant_id, input).await?;

        Ok(PeerGroupResponse::from(group))
    }

    /// Get a peer group by ID.
    pub async fn get(&self, tenant_id: Uuid, group_id: Uuid) -> ApiResult<PeerGroupResponse> {
        let group = GovPeerGroup::find_by_id(&self.pool, tenant_id, group_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Peer group not found: {}",
                group_id
            )))?;

        Ok(PeerGroupResponse::from(group))
    }

    /// List peer groups with filtering.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        query: ListPeerGroupsQuery,
    ) -> ApiResult<PeerGroupListResponse> {
        let filter = PeerGroupFilter {
            group_type: query.group_type,
            attribute_key: query.attribute_key,
            min_user_count: query.min_user_count,
        };

        let limit = query.limit.unwrap_or(50).min(100);
        let offset = query.offset.unwrap_or(0);

        let groups =
            GovPeerGroup::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = GovPeerGroup::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok(PeerGroupListResponse {
            items: groups.into_iter().map(PeerGroupResponse::from).collect(),
            total,
            limit,
            offset,
        })
    }

    /// Delete a peer group.
    pub async fn delete(&self, tenant_id: Uuid, group_id: Uuid) -> ApiResult<()> {
        GovPeerGroup::find_by_id(&self.pool, tenant_id, group_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Peer group not found: {}",
                group_id
            )))?;

        // Clear all members first
        GovPeerGroupMember::clear_group(&self.pool, tenant_id, group_id).await?;

        // Delete the group
        GovPeerGroup::delete(&self.pool, tenant_id, group_id).await?;

        Ok(())
    }

    /// Refresh statistics for a specific peer group.
    pub async fn refresh_group_stats(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> ApiResult<RefreshStatsResponse> {
        // Verify group exists
        GovPeerGroup::find_by_id(&self.pool, tenant_id, group_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Peer group not found: {}",
                group_id
            )))?;

        // Get all member user IDs
        let member_ids = GovPeerGroupMember::list_members(&self.pool, tenant_id, group_id).await?;
        let member_count = member_ids.len() as i64;

        if member_ids.is_empty() {
            let stats = UpdateGovPeerGroupStats {
                user_count: 0,
                avg_entitlements: None,
                stddev_entitlements: None,
            };
            let updated = GovPeerGroup::update_stats(&self.pool, tenant_id, group_id, stats)
                .await?
                .ok_or(ApiGovernanceError::NotFound(format!(
                    "Peer group not found: {}",
                    group_id
                )))?;

            return Ok(RefreshStatsResponse {
                group: PeerGroupResponse::from(updated),
                member_count,
            });
        }

        // Calculate entitlement counts per user
        let mut entitlement_counts: Vec<f64> = Vec::new();

        for user_id in &member_ids {
            let filter = GovAssignmentFilter {
                target_type: Some(GovAssignmentTargetType::User),
                target_id: Some(*user_id),
                ..Default::default()
            };
            let count =
                GovEntitlementAssignment::count_by_tenant(&self.pool, tenant_id, &filter).await?;
            entitlement_counts.push(count as f64);
        }

        // Calculate statistics
        let (avg, stddev) = calculate_stats(&entitlement_counts);

        let stats = UpdateGovPeerGroupStats {
            user_count: member_ids.len() as i32,
            avg_entitlements: Some(avg),
            stddev_entitlements: Some(stddev),
        };

        let updated = GovPeerGroup::update_stats(&self.pool, tenant_id, group_id, stats)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Peer group not found: {}",
                group_id
            )))?;

        Ok(RefreshStatsResponse {
            group: PeerGroupResponse::from(updated),
            member_count,
        })
    }

    /// Refresh all peer groups (recalculate statistics).
    pub async fn refresh_all_groups(
        &self,
        tenant_id: Uuid,
    ) -> ApiResult<RefreshPeerGroupsResponse> {
        let start = Instant::now();

        // Get all groups
        let filter = PeerGroupFilter::default();
        let groups = GovPeerGroup::list_by_tenant(&self.pool, tenant_id, &filter, 1000, 0).await?;

        let mut groups_refreshed = 0i64;
        let mut users_processed = 0i64;

        for group in groups {
            let result = self.refresh_group_stats(tenant_id, group.id).await?;
            groups_refreshed += 1;
            users_processed += result.member_count;
        }

        Ok(RefreshPeerGroupsResponse {
            groups_refreshed,
            groups_created: 0,
            users_processed,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Get peer comparison for a user.
    pub async fn get_user_comparison(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> ApiResult<UserPeerComparisonResponse> {
        // Get user's entitlement count
        let filter = GovAssignmentFilter {
            target_type: Some(GovAssignmentTargetType::User),
            target_id: Some(user_id),
            ..Default::default()
        };
        let user_entitlement_count =
            GovEntitlementAssignment::count_by_tenant(&self.pool, tenant_id, &filter).await? as i32;

        // Get groups user belongs to
        let group_ids =
            GovPeerGroupMember::list_groups_for_user(&self.pool, tenant_id, user_id).await?;

        let mut comparisons = Vec::new();
        let mut is_outlier = false;

        for group_id in group_ids {
            if let Some(group) = GovPeerGroup::find_by_id(&self.pool, tenant_id, group_id).await? {
                // Only compare with statistically valid groups
                if group.user_count >= MIN_PEER_GROUP_SIZE {
                    if let Some(comparison) =
                        group.check_outlier(user_entitlement_count, DEFAULT_OUTLIER_THRESHOLD)
                    {
                        if comparison.is_outlier {
                            is_outlier = true;
                        }

                        comparisons.push(PeerGroupComparison {
                            group_id: comparison.group_id,
                            group_name: comparison.group_name,
                            group_type: comparison.group_type,
                            group_average: comparison.group_avg_entitlements,
                            group_stddev: comparison.group_stddev,
                            deviation_from_mean: comparison.deviation_from_mean,
                            is_outlier: comparison.is_outlier,
                            outlier_severity: comparison.outlier_severity,
                        });
                    }
                }
            }
        }

        Ok(UserPeerComparisonResponse {
            user_id,
            user_entitlement_count,
            comparisons,
            is_outlier,
        })
    }

    /// Add a user to a peer group.
    pub async fn add_user_to_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ApiResult<()> {
        // Verify group exists
        GovPeerGroup::find_by_id(&self.pool, tenant_id, group_id)
            .await?
            .ok_or(ApiGovernanceError::NotFound(format!(
                "Peer group not found: {}",
                group_id
            )))?;

        GovPeerGroupMember::add_member(&self.pool, tenant_id, group_id, user_id).await?;

        Ok(())
    }

    /// Remove a user from a peer group.
    pub async fn remove_user_from_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> ApiResult<()> {
        GovPeerGroupMember::remove_member(&self.pool, tenant_id, group_id, user_id).await?;
        Ok(())
    }

    /// Get the minimum peer group size required for statistical validity.
    pub fn min_peer_group_size() -> i32 {
        MIN_PEER_GROUP_SIZE
    }
}

/// Calculate mean and standard deviation.
fn calculate_stats(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }

    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;

    if values.len() == 1 {
        return (mean, 0.0);
    }

    let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let stddev = variance.sqrt();

    (mean, stddev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_stats_empty() {
        let (mean, stddev) = calculate_stats(&[]);
        assert_eq!(mean, 0.0);
        assert_eq!(stddev, 0.0);
    }

    #[test]
    fn test_calculate_stats_single_value() {
        let (mean, stddev) = calculate_stats(&[5.0]);
        assert_eq!(mean, 5.0);
        assert_eq!(stddev, 0.0);
    }

    #[test]
    fn test_calculate_stats_multiple_values() {
        let values = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let (mean, stddev) = calculate_stats(&values);
        assert!((mean - 6.0).abs() < 0.001);
        // Sample standard deviation of [2,4,6,8,10] is ~3.162
        assert!((stddev - 3.162).abs() < 0.01);
    }

    #[test]
    fn test_min_peer_group_size() {
        assert_eq!(PeerGroupService::min_peer_group_size(), 5);
    }

    #[test]
    fn test_outlier_threshold() {
        assert_eq!(DEFAULT_OUTLIER_THRESHOLD, 2.0);
    }
}
