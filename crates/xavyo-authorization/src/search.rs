//! Search operations for authorization policies.
//!
//! This module provides the [`SearchOp`] trait and supporting types for
//! querying policies based on filters, with safe SQL generation.
//!
//! # Overview
//!
//! The search system supports:
//! - Multiple filter operators: `eq`, `ne`, `contains`, `starts_with`, `in`
//! - Pagination with `limit` and `offset`
//! - Sorting by any searchable field
//! - Safe SQL generation with parameterized queries
//!
//! # Example
//!
//! ```rust
//! use xavyo_authorization::search::{SearchQuery, SearchFilter, FilterOp, SortDir};
//!
//! let query = SearchQuery {
//!     filters: vec![
//!         SearchFilter {
//!             field: "effect".to_string(),
//!             op: FilterOp::Eq,
//!             value: serde_json::json!("deny"),
//!         },
//!     ],
//!     sort_field: Some("priority".to_string()),
//!     sort_dir: SortDir::Asc,
//!     limit: Some(10),
//!     offset: Some(0),
//! };
//! ```
//!
//! # Multi-Tenant Isolation
//!
//! **CRITICAL**: All search operations automatically include `tenant_id` filtering.
//! The `tenant_id` parameter is required and cannot be omitted.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// FilterOp
// ---------------------------------------------------------------------------

/// Filter operator for search queries.
///
/// Each operator maps to a SQL comparison:
/// - `Eq` → `= $n`
/// - `Ne` → `!= $n`
/// - `Contains` → `ILIKE '%' || $n || '%'`
/// - `StartsWith` → `ILIKE $n || '%'`
/// - `In` → `= ANY($n)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    /// Exact equality match.
    Eq,
    /// Not equal.
    Ne,
    /// Case-insensitive substring match.
    Contains,
    /// Case-insensitive prefix match.
    StartsWith,
    /// Value is in a list.
    In,
}

impl FilterOp {
    /// Convert operator to SQL fragment.
    ///
    /// Returns the SQL operator and whether it needs special handling.
    #[must_use] 
    pub fn to_sql_fragment(&self, param_index: usize) -> String {
        match self {
            FilterOp::Eq => format!("= ${param_index}"),
            FilterOp::Ne => format!("!= ${param_index}"),
            FilterOp::Contains => format!("ILIKE '%' || ${param_index} || '%'"),
            FilterOp::StartsWith => format!("ILIKE ${param_index} || '%'"),
            FilterOp::In => format!("= ANY(${param_index})"),
        }
    }
}

impl fmt::Display for FilterOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterOp::Eq => write!(f, "eq"),
            FilterOp::Ne => write!(f, "ne"),
            FilterOp::Contains => write!(f, "contains"),
            FilterOp::StartsWith => write!(f, "starts_with"),
            FilterOp::In => write!(f, "in"),
        }
    }
}

// ---------------------------------------------------------------------------
// SearchFilter
// ---------------------------------------------------------------------------

/// A single search filter condition.
///
/// Combines a field name, operator, and value to create a WHERE clause condition.
///
/// # Example
///
/// ```rust
/// use xavyo_authorization::search::{SearchFilter, FilterOp};
///
/// let filter = SearchFilter {
///     field: "status".to_string(),
///     op: FilterOp::Eq,
///     value: serde_json::json!("active"),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchFilter {
    /// The field to filter on.
    pub field: String,
    /// The comparison operator.
    pub op: FilterOp,
    /// The value to compare against.
    pub value: serde_json::Value,
}

impl SearchFilter {
    /// Create a new equality filter.
    pub fn eq(field: impl Into<String>, value: impl Serialize) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::Eq,
            value: serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Create a new contains filter.
    pub fn contains(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::Contains,
            value: serde_json::Value::String(value.into()),
        }
    }

    /// Create a new `starts_with` filter.
    pub fn starts_with(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::StartsWith,
            value: serde_json::Value::String(value.into()),
        }
    }

    /// Create a new in filter.
    pub fn in_list(field: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            field: field.into(),
            op: FilterOp::In,
            value: serde_json::to_value(values).unwrap_or(serde_json::Value::Null),
        }
    }
}

// ---------------------------------------------------------------------------
// SortDir
// ---------------------------------------------------------------------------

/// Sort direction for search results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SortDir {
    /// Ascending order (A-Z, 0-9).
    #[default]
    Asc,
    /// Descending order (Z-A, 9-0).
    Desc,
}

impl fmt::Display for SortDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortDir::Asc => write!(f, "ASC"),
            SortDir::Desc => write!(f, "DESC"),
        }
    }
}

// ---------------------------------------------------------------------------
// SearchQuery
// ---------------------------------------------------------------------------

/// Search query parameters.
///
/// Combines filters, sorting, and pagination into a complete query specification.
///
/// # Example
///
/// ```rust
/// use xavyo_authorization::search::{SearchQuery, SearchFilter, FilterOp, SortDir};
///
/// let query = SearchQuery::default()
///     .with_filter(SearchFilter::eq("effect", "allow"))
///     .with_sort("priority", SortDir::Asc)
///     .with_pagination(10, 0);
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Filters to apply (AND-combined).
    pub filters: Vec<SearchFilter>,
    /// Field to sort by.
    pub sort_field: Option<String>,
    /// Sort direction.
    pub sort_dir: SortDir,
    /// Maximum number of results.
    pub limit: Option<i64>,
    /// Number of results to skip.
    pub offset: Option<i64>,
}

impl SearchQuery {
    /// Create a new empty search query.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter to the query.
    #[must_use] 
    pub fn with_filter(mut self, filter: SearchFilter) -> Self {
        self.filters.push(filter);
        self
    }

    /// Set the sort field and direction.
    pub fn with_sort(mut self, field: impl Into<String>, dir: SortDir) -> Self {
        self.sort_field = Some(field.into());
        self.sort_dir = dir;
        self
    }

    /// Set pagination parameters.
    #[must_use] 
    pub fn with_pagination(mut self, limit: i64, offset: i64) -> Self {
        self.limit = Some(limit);
        self.offset = Some(offset);
        self
    }

    /// Build the WHERE clause from filters.
    ///
    /// Returns the SQL WHERE clause (without "WHERE") and the parameter values.
    /// Always includes `tenant_id` as the first condition.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant ID (always required)
    /// * `allowed_fields` - List of fields that can be filtered
    ///
    /// # Returns
    ///
    /// A tuple of (SQL clause, parameter values as strings)
    pub fn build_where_clause(
        &self,
        tenant_id: Uuid,
        allowed_fields: &[&str],
    ) -> Result<(String, Vec<String>), SearchError> {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut params = vec![tenant_id.to_string()];
        let mut param_idx = 2;

        for filter in &self.filters {
            // Validate field is allowed
            if !allowed_fields.contains(&filter.field.as_str()) {
                return Err(SearchError::InvalidField(filter.field.clone()));
            }

            let sql_op = filter.op.to_sql_fragment(param_idx);
            conditions.push(format!("{} {}", filter.field, sql_op));

            // Extract value as string
            let value_str = match &filter.value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Array(arr) => {
                    // For IN operator, format as PostgreSQL array
                    let values: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    format!("{{{}}}", values.join(","))
                }
                _ => return Err(SearchError::InvalidValue(filter.field.clone())),
            };

            params.push(value_str);
            param_idx += 1;
        }

        Ok((conditions.join(" AND "), params))
    }

    /// Build the ORDER BY clause.
    ///
    /// # Arguments
    ///
    /// * `allowed_fields` - List of fields that can be sorted
    /// * `default_sort` - Default sort field if none specified
    pub fn build_order_clause(
        &self,
        allowed_fields: &[&str],
        default_sort: &str,
    ) -> Result<String, SearchError> {
        let field = self.sort_field.as_deref().unwrap_or(default_sort);

        if !allowed_fields.contains(&field) {
            return Err(SearchError::InvalidField(field.to_string()));
        }

        Ok(format!("ORDER BY {} {}", field, self.sort_dir))
    }

    /// Build the LIMIT/OFFSET clause.
    #[must_use] 
    pub fn build_pagination_clause(&self) -> String {
        let mut clause = String::new();

        if let Some(limit) = self.limit {
            clause.push_str(&format!(" LIMIT {}", limit.max(0)));
        }

        if let Some(offset) = self.offset {
            clause.push_str(&format!(" OFFSET {}", offset.max(0)));
        }

        clause
    }
}

// ---------------------------------------------------------------------------
// SearchResult
// ---------------------------------------------------------------------------

/// Search result with pagination info.
///
/// Contains the matching items along with metadata for pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult<T> {
    /// The matching items.
    pub items: Vec<T>,
    /// Total number of matching items (before pagination).
    pub total: i64,
    /// The limit that was applied.
    pub limit: Option<i64>,
    /// The offset that was applied.
    pub offset: Option<i64>,
}

impl<T> SearchResult<T> {
    /// Create a new search result.
    #[must_use] 
    pub fn new(items: Vec<T>, total: i64, limit: Option<i64>, offset: Option<i64>) -> Self {
        Self {
            items,
            total,
            limit,
            offset,
        }
    }

    /// Check if there are more results available.
    #[must_use] 
    pub fn has_more(&self) -> bool {
        let offset = self.offset.unwrap_or(0);
        let limit = self.limit.unwrap_or(i64::MAX);
        offset + limit < self.total
    }

    /// Get the number of items returned.
    #[must_use] 
    pub fn count(&self) -> usize {
        self.items.len()
    }
}

// ---------------------------------------------------------------------------
// SearchError
// ---------------------------------------------------------------------------

/// Errors that can occur during search operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchError {
    /// The specified field is not searchable.
    InvalidField(String),
    /// The filter value is invalid for the field type.
    InvalidValue(String),
    /// Pagination parameters are invalid.
    InvalidPagination(String),
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SearchError::InvalidField(field) => write!(f, "invalid search field: {field}"),
            SearchError::InvalidValue(field) => {
                write!(f, "invalid filter value for field: {field}")
            }
            SearchError::InvalidPagination(msg) => write!(f, "invalid pagination: {msg}"),
        }
    }
}

impl std::error::Error for SearchError {}

// ---------------------------------------------------------------------------
// SearchOp Trait
// ---------------------------------------------------------------------------

/// Trait for types that support search operations.
///
/// Implementors define which fields are searchable and how to build SQL queries.
///
/// # Example Implementation
///
/// ```rust,ignore
/// impl SearchOp for Policy {
///     fn table_name() -> &'static str {
///         "authorization_policies"
///     }
///
///     fn searchable_fields() -> &'static [&'static str] {
///         &["name", "effect", "status", "resource_type", "action", "priority"]
///     }
///
///     fn default_sort_field() -> &'static str {
///         "priority"
///     }
/// }
/// ```
pub trait SearchOp: Sized {
    /// The database table name for this type.
    fn table_name() -> &'static str;

    /// List of fields that can be used in filters and sorting.
    fn searchable_fields() -> &'static [&'static str];

    /// The default field to sort by.
    fn default_sort_field() -> &'static str;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_op_serialization_roundtrip() {
        let ops = [
            FilterOp::Eq,
            FilterOp::Ne,
            FilterOp::Contains,
            FilterOp::StartsWith,
            FilterOp::In,
        ];

        for op in ops {
            let json = serde_json::to_string(&op).unwrap();
            let parsed: FilterOp = serde_json::from_str(&json).unwrap();
            assert_eq!(op, parsed);
        }
    }

    #[test]
    fn test_filter_op_display() {
        assert_eq!(FilterOp::Eq.to_string(), "eq");
        assert_eq!(FilterOp::Ne.to_string(), "ne");
        assert_eq!(FilterOp::Contains.to_string(), "contains");
        assert_eq!(FilterOp::StartsWith.to_string(), "starts_with");
        assert_eq!(FilterOp::In.to_string(), "in");
    }

    #[test]
    fn test_filter_op_to_sql_fragment() {
        assert_eq!(FilterOp::Eq.to_sql_fragment(1), "= $1");
        assert_eq!(FilterOp::Ne.to_sql_fragment(2), "!= $2");
        assert_eq!(
            FilterOp::Contains.to_sql_fragment(3),
            "ILIKE '%' || $3 || '%'"
        );
        assert_eq!(FilterOp::StartsWith.to_sql_fragment(4), "ILIKE $4 || '%'");
        assert_eq!(FilterOp::In.to_sql_fragment(5), "= ANY($5)");
    }

    #[test]
    fn test_search_filter_construction() {
        let filter = SearchFilter::eq("status", "active");
        assert_eq!(filter.field, "status");
        assert_eq!(filter.op, FilterOp::Eq);
        assert_eq!(filter.value, serde_json::json!("active"));
    }

    #[test]
    fn test_search_filter_contains() {
        let filter = SearchFilter::contains("name", "admin");
        assert_eq!(filter.field, "name");
        assert_eq!(filter.op, FilterOp::Contains);
        assert_eq!(filter.value, serde_json::json!("admin"));
    }

    #[test]
    fn test_search_filter_starts_with() {
        let filter = SearchFilter::starts_with("name", "Policy_");
        assert_eq!(filter.field, "name");
        assert_eq!(filter.op, FilterOp::StartsWith);
    }

    #[test]
    fn test_search_filter_in_list() {
        let filter = SearchFilter::in_list("effect", vec!["allow".into(), "deny".into()]);
        assert_eq!(filter.field, "effect");
        assert_eq!(filter.op, FilterOp::In);
    }

    #[test]
    fn test_search_query_default() {
        let query = SearchQuery::default();
        assert!(query.filters.is_empty());
        assert!(query.sort_field.is_none());
        assert_eq!(query.sort_dir, SortDir::Asc);
        assert!(query.limit.is_none());
        assert!(query.offset.is_none());
    }

    #[test]
    fn test_search_query_builder() {
        let query = SearchQuery::new()
            .with_filter(SearchFilter::eq("effect", "allow"))
            .with_sort("priority", SortDir::Desc)
            .with_pagination(10, 20);

        assert_eq!(query.filters.len(), 1);
        assert_eq!(query.sort_field, Some("priority".to_string()));
        assert_eq!(query.sort_dir, SortDir::Desc);
        assert_eq!(query.limit, Some(10));
        assert_eq!(query.offset, Some(20));
    }

    #[test]
    fn test_sort_dir_display() {
        assert_eq!(SortDir::Asc.to_string(), "ASC");
        assert_eq!(SortDir::Desc.to_string(), "DESC");
    }

    #[test]
    fn test_build_where_clause_eq() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new().with_filter(SearchFilter::eq("effect", "deny"));

        let allowed = &["effect", "status", "name"];
        let (clause, params) = query.build_where_clause(tenant_id, allowed).unwrap();

        assert!(clause.contains("tenant_id = $1"));
        assert!(clause.contains("effect = $2"));
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], tenant_id.to_string());
        assert_eq!(params[1], "deny");
    }

    #[test]
    fn test_build_where_clause_contains() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new().with_filter(SearchFilter::contains("name", "admin"));

        let allowed = &["name"];
        let (clause, _) = query.build_where_clause(tenant_id, allowed).unwrap();

        assert!(clause.contains("ILIKE '%' || $2 || '%'"));
    }

    #[test]
    fn test_build_where_clause_starts_with() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new().with_filter(SearchFilter::starts_with("name", "Policy"));

        let allowed = &["name"];
        let (clause, _) = query.build_where_clause(tenant_id, allowed).unwrap();

        assert!(clause.contains("ILIKE $2 || '%'"));
    }

    #[test]
    fn test_build_where_clause_multiple_filters() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new()
            .with_filter(SearchFilter::eq("effect", "allow"))
            .with_filter(SearchFilter::eq("status", "active"));

        let allowed = &["effect", "status"];
        let (clause, params) = query.build_where_clause(tenant_id, allowed).unwrap();

        assert!(clause.contains("tenant_id = $1"));
        assert!(clause.contains("effect = $2"));
        assert!(clause.contains("status = $3"));
        assert!(clause.contains(" AND "));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn test_build_where_clause_invalid_field() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new().with_filter(SearchFilter::eq("invalid_field", "value"));

        let allowed = &["name", "status"];
        let result = query.build_where_clause(tenant_id, allowed);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SearchError::InvalidField(_)));
    }

    #[test]
    fn test_build_where_clause_empty_filters() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new();

        let allowed = &["name"];
        let (clause, params) = query.build_where_clause(tenant_id, allowed).unwrap();

        assert_eq!(clause, "tenant_id = $1");
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn test_build_order_clause() {
        let query = SearchQuery::new().with_sort("priority", SortDir::Asc);

        let allowed = &["priority", "name"];
        let clause = query.build_order_clause(allowed, "name").unwrap();

        assert_eq!(clause, "ORDER BY priority ASC");
    }

    #[test]
    fn test_build_order_clause_default() {
        let query = SearchQuery::new();

        let allowed = &["priority", "name"];
        let clause = query.build_order_clause(allowed, "name").unwrap();

        assert_eq!(clause, "ORDER BY name ASC");
    }

    #[test]
    fn test_build_order_clause_invalid_field() {
        let query = SearchQuery::new().with_sort("invalid", SortDir::Asc);

        let allowed = &["name"];
        let result = query.build_order_clause(allowed, "name");

        assert!(result.is_err());
    }

    #[test]
    fn test_build_pagination_clause() {
        let query = SearchQuery::new().with_pagination(10, 20);
        let clause = query.build_pagination_clause();

        assert_eq!(clause, " LIMIT 10 OFFSET 20");
    }

    #[test]
    fn test_build_pagination_clause_limit_only() {
        let query = SearchQuery {
            limit: Some(50),
            ..Default::default()
        };
        let clause = query.build_pagination_clause();

        assert_eq!(clause, " LIMIT 50");
    }

    #[test]
    fn test_build_pagination_clause_negative_values() {
        let query = SearchQuery {
            limit: Some(-10),
            offset: Some(-5),
            ..Default::default()
        };
        let clause = query.build_pagination_clause();

        // Negative values are clamped to 0
        assert_eq!(clause, " LIMIT 0 OFFSET 0");
    }

    #[test]
    fn test_search_result_new() {
        let result: SearchResult<String> =
            SearchResult::new(vec!["a".into(), "b".into()], 100, Some(10), Some(0));

        assert_eq!(result.count(), 2);
        assert_eq!(result.total, 100);
        assert!(result.has_more());
    }

    #[test]
    fn test_search_result_has_more() {
        // Has more
        let result: SearchResult<i32> = SearchResult::new(vec![1, 2, 3], 100, Some(10), Some(0));
        assert!(result.has_more());

        // No more - at end
        let result: SearchResult<i32> = SearchResult::new(vec![1, 2], 12, Some(10), Some(10));
        assert!(!result.has_more());

        // No more - exact fit
        let result: SearchResult<i32> = SearchResult::new(vec![1, 2], 2, Some(10), Some(0));
        assert!(!result.has_more());
    }

    #[test]
    fn test_search_error_display() {
        assert_eq!(
            SearchError::InvalidField("foo".into()).to_string(),
            "invalid search field: foo"
        );
        assert_eq!(
            SearchError::InvalidValue("bar".into()).to_string(),
            "invalid filter value for field: bar"
        );
        assert_eq!(
            SearchError::InvalidPagination("negative".into()).to_string(),
            "invalid pagination: negative"
        );
    }

    #[test]
    fn test_tenant_id_always_included() {
        let tenant_id = Uuid::new_v4();
        let query = SearchQuery::new();

        let allowed: &[&str] = &[];
        let (clause, params) = query.build_where_clause(tenant_id, allowed).unwrap();

        // Even with no filters, tenant_id is present
        assert!(clause.contains("tenant_id = $1"));
        assert_eq!(params[0], tenant_id.to_string());
    }
}
