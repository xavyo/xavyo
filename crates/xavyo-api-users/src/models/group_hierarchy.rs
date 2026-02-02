//! Request and response models for the Group Hierarchy API (F071).

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use chrono::{DateTime, Utc};

// --- Request types ---

/// Request to move a group to a new parent (or make it a root group).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct MoveGroupRequest {
    /// New parent group ID. Set to null to make a root group.
    pub parent_id: Option<Uuid>,
}

/// Query parameters for hierarchy list endpoints.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct HierarchyPaginationParams {
    /// Maximum number of items to return (default: 50, max: 200).
    #[serde(default)]
    pub limit: Option<i64>,

    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: Option<i64>,
}

impl HierarchyPaginationParams {
    /// Default page size.
    pub const DEFAULT_LIMIT: i64 = 50;

    /// Maximum allowed page size.
    pub const MAX_LIMIT: i64 = 200;

    /// Get the limit, clamped to valid range.
    #[must_use]
    pub fn limit(&self) -> i64 {
        self.limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT)
    }

    /// Get the offset, defaulting to 0.
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

/// Query parameters for listing groups with optional type filter.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListGroupsQuery {
    /// Filter by group type.
    #[serde(default)]
    pub group_type: Option<String>,

    /// Maximum number of items to return (default: 50, max: 200).
    #[serde(default)]
    pub limit: Option<i64>,

    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: Option<i64>,
}

impl ListGroupsQuery {
    /// Default page size.
    pub const DEFAULT_LIMIT: i64 = 50;

    /// Maximum allowed page size.
    pub const MAX_LIMIT: i64 = 200;

    /// Get the limit, clamped to valid range.
    #[must_use]
    pub fn limit(&self) -> i64 {
        self.limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT)
    }

    /// Get the offset, defaulting to 0.
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.offset.unwrap_or(0).max(0)
    }
}

// --- Response types ---

/// Group detail with hierarchy information.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GroupDetail {
    /// Unique identifier for the group.
    pub id: Uuid,

    /// The tenant this group belongs to.
    pub tenant_id: Uuid,

    /// Group display name.
    pub display_name: String,

    /// External system ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Group description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Parent group ID (null for root groups).
    pub parent_id: Option<Uuid>,

    /// Group type classification.
    pub group_type: String,

    /// Ancestor names from root to this group's parent.
    pub path: Vec<String>,

    /// When the group was created.
    pub created_at: DateTime<Utc>,

    /// When the group was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Response for listing groups with pagination.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GroupListResponse {
    /// List of groups.
    pub groups: Vec<GroupDetail>,

    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Pagination metadata (without total count).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Pagination {
    /// Page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,

    /// Whether more records are available.
    pub has_more: bool,
}

/// An ancestor entry in the path from root to a group.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AncestorEntry {
    /// Ancestor group ID.
    pub id: Uuid,

    /// Ancestor group display name.
    pub display_name: String,

    /// Ancestor group type.
    pub group_type: String,

    /// Depth from root (root = 1).
    pub depth: i32,
}

/// Response for getting ancestor path.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AncestorPathResponse {
    /// The group ID that was queried.
    pub group_id: Uuid,

    /// Ancestors ordered from root to immediate parent.
    pub ancestors: Vec<AncestorEntry>,
}

/// A descendant entry in the subtree.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SubtreeEntry {
    /// Descendant group ID.
    pub id: Uuid,

    /// Descendant group display name.
    pub display_name: String,

    /// Descendant group type.
    pub group_type: String,

    /// Parent group ID.
    pub parent_id: Option<Uuid>,

    /// Depth relative to the queried group (direct child = 1).
    pub relative_depth: i32,
}

/// Response for getting a group's subtree.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SubtreeResponse {
    /// The root group ID that was queried.
    pub root_group_id: Uuid,

    /// All descendant groups.
    pub descendants: Vec<SubtreeEntry>,

    /// Pagination metadata.
    pub pagination: Pagination,
}

/// A user member in a subtree membership query.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SubtreeMember {
    /// User ID.
    pub user_id: Uuid,

    /// User email.
    pub email: String,

    /// User display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Response for subtree membership queries.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SubtreeMembershipResponse {
    /// The group ID that was queried.
    pub group_id: Uuid,

    /// All users in the group and its descendants.
    pub members: Vec<SubtreeMember>,

    /// Pagination metadata with total count.
    pub pagination: PaginationWithTotal,
}

/// Pagination metadata with total count.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginationWithTotal {
    /// Total number of matching records.
    pub total_count: i64,

    /// Page size.
    pub limit: i64,

    /// Current offset.
    pub offset: i64,

    /// Whether more records are available.
    pub has_more: bool,
}

impl PaginationWithTotal {
    /// Create pagination metadata with total count.
    #[must_use]
    pub fn new(total_count: i64, offset: i64, limit: i64) -> Self {
        Self {
            total_count,
            offset,
            limit,
            has_more: offset + limit < total_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hierarchy_pagination_defaults() {
        let params = HierarchyPaginationParams {
            limit: None,
            offset: None,
        };
        assert_eq!(params.limit(), 50);
        assert_eq!(params.offset(), 0);
    }

    #[test]
    fn test_hierarchy_pagination_clamping() {
        let params = HierarchyPaginationParams {
            limit: Some(500),
            offset: Some(-10),
        };
        assert_eq!(params.limit(), 200);
        assert_eq!(params.offset(), 0);
    }

    #[test]
    fn test_list_groups_query_defaults() {
        let query = ListGroupsQuery {
            group_type: None,
            limit: None,
            offset: None,
        };
        assert_eq!(query.limit(), 50);
        assert_eq!(query.offset(), 0);
        assert!(query.group_type.is_none());
    }

    #[test]
    fn test_pagination_with_total() {
        let p = PaginationWithTotal::new(100, 0, 50);
        assert!(p.has_more);
        assert_eq!(p.total_count, 100);

        let p = PaginationWithTotal::new(30, 0, 50);
        assert!(!p.has_more);
    }
}
