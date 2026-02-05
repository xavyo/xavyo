//! Governance Peer Group models.
//!
//! Represents peer groups for outlier detection in risk scoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Peer group type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "peer_group_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PeerGroupType {
    /// Group by department.
    Department,
    /// Group by role.
    Role,
    /// Group by location.
    Location,
    /// Custom grouping.
    Custom,
}

/// A governance peer group.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPeerGroup {
    /// Unique identifier for the peer group.
    pub id: Uuid,

    /// The tenant this peer group belongs to.
    pub tenant_id: Uuid,

    /// Peer group display name.
    pub name: String,

    /// Type of grouping.
    pub group_type: PeerGroupType,

    /// Attribute key used for grouping.
    pub attribute_key: String,

    /// Attribute value for this group.
    pub attribute_value: String,

    /// Number of users in the group.
    pub user_count: i32,

    /// Average entitlement count for the group.
    pub avg_entitlements: Option<f64>,

    /// Standard deviation of entitlement counts.
    pub stddev_entitlements: Option<f64>,

    /// When the group was created.
    pub created_at: DateTime<Utc>,

    /// When the group statistics were last updated.
    pub updated_at: DateTime<Utc>,
}

/// A peer group member.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPeerGroupMember {
    /// Unique identifier for the membership.
    pub id: Uuid,

    /// The tenant this membership belongs to.
    pub tenant_id: Uuid,

    /// The peer group.
    pub group_id: Uuid,

    /// The user.
    pub user_id: Uuid,

    /// When the membership was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new peer group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovPeerGroup {
    pub name: String,
    pub group_type: PeerGroupType,
    pub attribute_key: String,
    pub attribute_value: String,
}

/// Statistics update for a peer group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovPeerGroupStats {
    pub user_count: i32,
    pub avg_entitlements: Option<f64>,
    pub stddev_entitlements: Option<f64>,
}

/// Filter options for listing peer groups.
#[derive(Debug, Clone, Default)]
pub struct PeerGroupFilter {
    pub group_type: Option<PeerGroupType>,
    pub attribute_key: Option<String>,
    pub min_user_count: Option<i32>,
}

/// Peer comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerComparison {
    pub group_id: Uuid,
    pub group_name: String,
    pub group_type: PeerGroupType,
    pub user_entitlement_count: i32,
    pub group_avg_entitlements: f64,
    pub group_stddev: f64,
    pub deviation_from_mean: f64,
    pub is_outlier: bool,
    pub outlier_severity: Option<OutlierSeverity>,
}

/// Outlier severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutlierSeverity {
    /// 2-3 standard deviations.
    Moderate,
    /// 3+ standard deviations.
    Severe,
}

impl GovPeerGroup {
    /// Find a peer group by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_peer_groups
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a peer group by attribute value.
    pub async fn find_by_attribute(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_type: PeerGroupType,
        attribute_value: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_peer_groups
            WHERE tenant_id = $1 AND group_type = $2 AND attribute_value = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_type)
        .bind(attribute_value)
        .fetch_optional(pool)
        .await
    }

    /// List peer groups by type.
    pub async fn list_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_type: PeerGroupType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_peer_groups
            WHERE tenant_id = $1 AND group_type = $2
            ORDER BY name ASC
            ",
        )
        .bind(tenant_id)
        .bind(group_type)
        .fetch_all(pool)
        .await
    }

    /// List peer groups with minimum user count (for statistical validity).
    pub async fn list_valid_for_comparison(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        min_user_count: i32,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_peer_groups
            WHERE tenant_id = $1 AND user_count >= $2
            ORDER BY group_type, name ASC
            ",
        )
        .bind(tenant_id)
        .bind(min_user_count)
        .fetch_all(pool)
        .await
    }

    /// List peer groups for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PeerGroupFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_peer_groups
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.group_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND group_type = ${param_count}"));
        }
        if filter.attribute_key.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attribute_key = ${param_count}"));
        }
        if filter.min_user_count.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_count >= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY group_type, name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovPeerGroup>(&query).bind(tenant_id);

        if let Some(group_type) = filter.group_type {
            q = q.bind(group_type);
        }
        if let Some(ref attribute_key) = filter.attribute_key {
            q = q.bind(attribute_key);
        }
        if let Some(min_user_count) = filter.min_user_count {
            q = q.bind(min_user_count);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count peer groups in a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PeerGroupFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_peer_groups
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.group_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND group_type = ${param_count}"));
        }
        if filter.attribute_key.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND attribute_key = ${param_count}"));
        }
        if filter.min_user_count.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_count >= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(group_type) = filter.group_type {
            q = q.bind(group_type);
        }
        if let Some(ref attribute_key) = filter.attribute_key {
            q = q.bind(attribute_key);
        }
        if let Some(min_user_count) = filter.min_user_count {
            q = q.bind(min_user_count);
        }

        q.fetch_one(pool).await
    }

    /// Create a new peer group.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovPeerGroup,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_peer_groups (
                tenant_id, name, group_type, attribute_key, attribute_value
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.group_type)
        .bind(&input.attribute_key)
        .bind(&input.attribute_value)
        .fetch_one(pool)
        .await
    }

    /// Create or update a peer group (upsert).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovPeerGroup,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_peer_groups (
                tenant_id, name, group_type, attribute_key, attribute_value
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id, group_type, attribute_value) DO UPDATE SET
                name = EXCLUDED.name,
                attribute_key = EXCLUDED.attribute_key,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.group_type)
        .bind(&input.attribute_key)
        .bind(&input.attribute_value)
        .fetch_one(pool)
        .await
    }

    /// Update peer group statistics.
    pub async fn update_stats(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        stats: UpdateGovPeerGroupStats,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_peer_groups
            SET user_count = $3, avg_entitlements = $4, stddev_entitlements = $5, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(stats.user_count)
        .bind(stats.avg_entitlements)
        .bind(stats.stddev_entitlements)
        .fetch_optional(pool)
        .await
    }

    /// Delete a peer group.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_peer_groups
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a user count is an outlier compared to group statistics.
    #[must_use]
    pub fn check_outlier(
        &self,
        user_entitlement_count: i32,
        threshold_stddev: f64,
    ) -> Option<PeerComparison> {
        let avg = self.avg_entitlements?;
        let stddev = self.stddev_entitlements?;

        if stddev == 0.0 {
            return None;
        }

        let user_count = f64::from(user_entitlement_count);
        let deviation = (user_count - avg) / stddev;
        let is_outlier = deviation.abs() >= threshold_stddev;

        let outlier_severity = if is_outlier {
            if deviation.abs() >= 3.0 {
                Some(OutlierSeverity::Severe)
            } else {
                Some(OutlierSeverity::Moderate)
            }
        } else {
            None
        };

        Some(PeerComparison {
            group_id: self.id,
            group_name: self.name.clone(),
            group_type: self.group_type,
            user_entitlement_count,
            group_avg_entitlements: avg,
            group_stddev: stddev,
            deviation_from_mean: deviation,
            is_outlier,
            outlier_severity,
        })
    }
}

impl GovPeerGroupMember {
    /// Find a membership by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_peer_group_members
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if a user is a member of a group.
    pub async fn is_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let exists: bool = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM gov_peer_group_members
                WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3
            )
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }

    /// List groups a user belongs to.
    pub async fn list_groups_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT group_id FROM gov_peer_group_members
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// List members of a group.
    pub async fn list_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT user_id FROM gov_peer_group_members
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(pool)
        .await
    }

    /// Count members in a group.
    pub async fn count_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_peer_group_members
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(pool)
        .await
    }

    /// Add a user to a group.
    pub async fn add_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_peer_group_members (tenant_id, group_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, group_id, user_id) DO NOTHING
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    /// Remove a user from a group.
    pub async fn remove_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_peer_group_members
            WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Remove all members from a group.
    pub async fn clear_group(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_peer_group_members
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Remove a user from all groups.
    pub async fn remove_user_from_all_groups(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_peer_group_members
            WHERE tenant_id = $1 AND user_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_group_type_serialization() {
        let dept = PeerGroupType::Department;
        let json = serde_json::to_string(&dept).unwrap();
        assert_eq!(json, "\"department\"");

        let role = PeerGroupType::Role;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"role\"");
    }

    #[test]
    fn test_outlier_severity_serialization() {
        let moderate = OutlierSeverity::Moderate;
        let json = serde_json::to_string(&moderate).unwrap();
        assert_eq!(json, "\"moderate\"");

        let severe = OutlierSeverity::Severe;
        let json = serde_json::to_string(&severe).unwrap();
        assert_eq!(json, "\"severe\"");
    }

    #[test]
    fn test_check_outlier() {
        let group = GovPeerGroup {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Engineering".to_string(),
            group_type: PeerGroupType::Department,
            attribute_key: "department".to_string(),
            attribute_value: "Engineering".to_string(),
            user_count: 10,
            avg_entitlements: Some(5.0),
            stddev_entitlements: Some(2.0),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Normal user (within 2 stddev)
        let comparison = group.check_outlier(7, 2.0).unwrap();
        assert!(!comparison.is_outlier);
        assert!(comparison.outlier_severity.is_none());

        // Moderate outlier (2-3 stddev)
        let comparison = group.check_outlier(10, 2.0).unwrap();
        assert!(comparison.is_outlier);
        assert_eq!(comparison.outlier_severity, Some(OutlierSeverity::Moderate));

        // Severe outlier (>3 stddev)
        let comparison = group.check_outlier(12, 2.0).unwrap();
        assert!(comparison.is_outlier);
        assert_eq!(comparison.outlier_severity, Some(OutlierSeverity::Severe));
    }
}
