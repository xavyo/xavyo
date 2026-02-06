//! SCIM response schemas (RFC 7644).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::scim_group::ScimGroup;
use super::scim_user::ScimUser;

/// SCIM List Response (RFC 7644 Section 3.4.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    /// SCIM schemas.
    pub schemas: Vec<String>,

    /// Total number of results matching the query.
    pub total_results: i64,

    /// 1-based index of the first result in this page.
    pub start_index: i64,

    /// Number of items per page.
    pub items_per_page: i64,

    /// The resources in this page.
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    /// SCIM List Response schema URI.
    pub const SCHEMA: &'static str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    /// Create a new list response.
    #[must_use]
    pub fn new(
        resources: Vec<T>,
        total_results: i64,
        start_index: i64,
        items_per_page: i64,
    ) -> Self {
        Self {
            schemas: vec![Self::SCHEMA.to_string()],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}

/// Type alias for user list response.
pub type ScimUserListResponse = ScimListResponse<ScimUser>;

/// Type alias for group list response.
pub type ScimGroupListResponse = ScimListResponse<ScimGroup>;

/// SCIM PATCH operation (RFC 7644 Section 3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOp {
    /// Operation type: add, remove, or replace.
    pub op: String,

    /// Attribute path (e.g., "displayName", "members[value eq \"123\"]").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Value to set (for add/replace operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// SCIM PATCH request (RFC 7644 Section 3.5.2).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchRequest {
    /// SCIM schemas.
    pub schemas: Vec<String>,

    /// Operations to perform.
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOp>,
}

impl ScimPatchRequest {
    /// SCIM Patch Operation schema URI.
    pub const SCHEMA: &'static str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    /// Validate the patch request.
    pub fn validate(&self) -> Result<(), String> {
        if !self.schemas.contains(&Self::SCHEMA.to_string()) {
            return Err("Missing PatchOp schema".to_string());
        }

        for (i, op) in self.operations.iter().enumerate() {
            let op_lower = op.op.to_lowercase();
            if !["add", "remove", "replace"].contains(&op_lower.as_str()) {
                return Err(format!("Invalid operation '{}' at index {}", op.op, i));
            }

            // 'remove' requires a path
            if op_lower == "remove" && op.path.is_none() {
                return Err(format!("Remove operation at index {i} requires a path"));
            }

            // 'add' and 'replace' require a value (unless path specified for complex attrs)
            if (op_lower == "add" || op_lower == "replace")
                && op.value.is_none()
                && op.path.is_none()
            {
                return Err(format!(
                    "Operation '{}' at index {} requires a value",
                    op.op, i
                ));
            }
        }

        Ok(())
    }
}

/// Pagination parameters from query string.
#[derive(Debug, Clone, Default, ToSchema)]
pub struct ScimPagination {
    /// 1-based start index.
    pub start_index: i64,
    /// Items per page (max 100).
    pub count: i64,
    /// Sort by attribute.
    pub sort_by: Option<String>,
    /// Sort order (ascending/descending).
    pub sort_order: Option<String>,
}

impl ScimPagination {
    /// Default items per page.
    pub const DEFAULT_COUNT: i64 = 25;

    /// Maximum items per page.
    pub const MAX_COUNT: i64 = 100;

    /// Create pagination from query parameters.
    #[must_use]
    pub fn from_query(
        start_index: Option<i64>,
        count: Option<i64>,
        sort_by: Option<String>,
        sort_order: Option<String>,
    ) -> Self {
        Self {
            start_index: start_index.unwrap_or(1).max(1),
            count: count
                .unwrap_or(Self::DEFAULT_COUNT)
                .clamp(1, Self::MAX_COUNT),
            sort_by,
            sort_order,
        }
    }

    /// Get SQL offset (0-based).
    #[must_use]
    pub fn offset(&self) -> i64 {
        (self.start_index - 1).max(0)
    }

    /// Get SQL limit.
    #[must_use]
    pub fn limit(&self) -> i64 {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_response() {
        let users: Vec<ScimUser> = vec![];
        let response = ScimListResponse::new(users, 100, 1, 25);

        assert_eq!(response.schemas.len(), 1);
        assert_eq!(response.total_results, 100);
        assert_eq!(response.start_index, 1);
        assert_eq!(response.items_per_page, 25);
    }

    #[test]
    fn test_patch_request_validation() {
        let valid = ScimPatchRequest {
            schemas: vec![ScimPatchRequest::SCHEMA.to_string()],
            operations: vec![ScimPatchOp {
                op: "replace".to_string(),
                path: Some("displayName".to_string()),
                value: Some(serde_json::json!("New Name")),
            }],
        };
        assert!(valid.validate().is_ok());

        let invalid_op = ScimPatchRequest {
            schemas: vec![ScimPatchRequest::SCHEMA.to_string()],
            operations: vec![ScimPatchOp {
                op: "invalid".to_string(),
                path: None,
                value: None,
            }],
        };
        assert!(invalid_op.validate().is_err());

        let remove_no_path = ScimPatchRequest {
            schemas: vec![ScimPatchRequest::SCHEMA.to_string()],
            operations: vec![ScimPatchOp {
                op: "remove".to_string(),
                path: None,
                value: None,
            }],
        };
        assert!(remove_no_path.validate().is_err());
    }

    #[test]
    fn test_pagination() {
        let p = ScimPagination::from_query(Some(26), Some(25), None, None);
        assert_eq!(p.start_index, 26);
        assert_eq!(p.count, 25);
        assert_eq!(p.offset(), 25);

        // Test defaults
        let default = ScimPagination::from_query(None, None, None, None);
        assert_eq!(default.start_index, 1);
        assert_eq!(default.count, 25);
        assert_eq!(default.offset(), 0);

        // Test max count
        let max = ScimPagination::from_query(Some(1), Some(200), None, None);
        assert_eq!(max.count, 100);
    }
}
