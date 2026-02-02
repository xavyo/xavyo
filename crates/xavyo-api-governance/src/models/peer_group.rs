//! Request and response models for peer group endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovPeerGroup, OutlierSeverity, PeerGroupType};

/// Request to create a new peer group.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreatePeerGroupRequest {
    /// Display name for the group.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Type of grouping.
    pub group_type: PeerGroupType,

    /// Attribute key used for grouping.
    #[validate(length(min = 1, max = 100, message = "Attribute key must be 1-100 characters"))]
    pub attribute_key: String,

    /// Attribute value for this group.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Attribute value must be 1-255 characters"
    ))]
    pub attribute_value: String,
}

/// Query parameters for listing peer groups.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPeerGroupsQuery {
    /// Filter by group type.
    pub group_type: Option<PeerGroupType>,

    /// Filter by attribute key.
    pub attribute_key: Option<String>,

    /// Filter by minimum user count.
    #[param(minimum = 0)]
    pub min_user_count: Option<i32>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListPeerGroupsQuery {
    fn default() -> Self {
        Self {
            group_type: None,
            attribute_key: None,
            min_user_count: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Peer group response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerGroupResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Group type.
    pub group_type: PeerGroupType,

    /// Attribute key.
    pub attribute_key: String,

    /// Attribute value.
    pub attribute_value: String,

    /// Number of users in group.
    pub user_count: i32,

    /// Average entitlement count.
    pub avg_entitlements: Option<f64>,

    /// Standard deviation.
    pub stddev_entitlements: Option<f64>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovPeerGroup> for PeerGroupResponse {
    fn from(g: GovPeerGroup) -> Self {
        Self {
            id: g.id,
            name: g.name,
            group_type: g.group_type,
            attribute_key: g.attribute_key,
            attribute_value: g.attribute_value,
            user_count: g.user_count,
            avg_entitlements: g.avg_entitlements,
            stddev_entitlements: g.stddev_entitlements,
            created_at: g.created_at,
            updated_at: g.updated_at,
        }
    }
}

/// Paginated list of peer groups.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerGroupListResponse {
    /// List of groups.
    pub items: Vec<PeerGroupResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Peer comparison result for a user.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserPeerComparisonResponse {
    /// User ID.
    pub user_id: Uuid,

    /// User's entitlement count.
    pub user_entitlement_count: i32,

    /// Comparisons with peer groups.
    pub comparisons: Vec<PeerGroupComparison>,

    /// Whether user is an outlier in any group.
    pub is_outlier: bool,
}

/// Comparison with a single peer group.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PeerGroupComparison {
    /// Group ID.
    pub group_id: Uuid,

    /// Group name.
    pub group_name: String,

    /// Group type.
    pub group_type: PeerGroupType,

    /// Group average entitlements.
    pub group_average: f64,

    /// Group standard deviation.
    pub group_stddev: f64,

    /// User's deviation from mean (in standard deviations).
    pub deviation_from_mean: f64,

    /// Whether user is an outlier in this group.
    pub is_outlier: bool,

    /// Outlier severity (if outlier).
    pub outlier_severity: Option<OutlierSeverity>,
}

/// Response for refreshing peer groups.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RefreshPeerGroupsResponse {
    /// Number of groups refreshed.
    pub groups_refreshed: i64,

    /// Number of groups created.
    pub groups_created: i64,

    /// Total users processed.
    pub users_processed: i64,

    /// Time taken in milliseconds.
    pub duration_ms: u64,
}

/// Response for peer group statistics refresh.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RefreshStatsResponse {
    /// Group that was refreshed.
    pub group: PeerGroupResponse,

    /// Number of members found.
    pub member_count: i64,
}
