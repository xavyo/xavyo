//! Request and response models for custom attribute definitions (F070).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ── Requests ──

/// Request to create a new attribute definition.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateAttributeDefinitionRequest {
    /// Attribute name (lowercase, alphanumeric + underscore, 1-64 chars).
    pub name: String,

    /// Human-readable display label.
    pub display_label: String,

    /// Data type: string, number, boolean, date, json.
    pub data_type: String,

    /// Whether this attribute is required on user creation/update.
    #[serde(default)]
    pub required: bool,

    /// Type-specific validation constraints (`max_length`, `min_length`, pattern, `allowed_values`, min, max).
    #[serde(default)]
    pub validation_rules: Option<serde_json::Value>,

    /// Default value when attribute is not provided.
    #[serde(default)]
    pub default_value: Option<serde_json::Value>,

    /// Display ordering (default: 0).
    #[serde(default)]
    pub sort_order: i32,
}

/// Request to update an existing attribute definition.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateAttributeDefinitionRequest {
    /// Updated display label.
    #[serde(default)]
    pub display_label: Option<String>,

    /// Updated required flag.
    #[serde(default)]
    pub required: Option<bool>,

    /// Updated validation rules. Pass `null` to clear.
    #[serde(default, deserialize_with = "deserialize_option_json")]
    pub validation_rules: Option<Option<serde_json::Value>>,

    /// Updated default value. Pass `null` to clear.
    #[serde(default, deserialize_with = "deserialize_option_json")]
    pub default_value: Option<Option<serde_json::Value>>,

    /// Updated display ordering.
    #[serde(default)]
    pub sort_order: Option<i32>,

    /// Updated active status (set to false to soft-delete).
    #[serde(default)]
    pub is_active: Option<bool>,
}

/// Query parameters for listing attribute definitions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAttributeDefinitionsQuery {
    /// Filter by active status.
    #[serde(default)]
    pub is_active: Option<bool>,

    /// Filter by data type (string, number, boolean, date, json).
    #[serde(default)]
    pub data_type: Option<String>,
}

/// Query parameters for deleting an attribute definition.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct DeleteAttributeDefinitionQuery {
    /// Force delete even if user data exists (default: false).
    #[serde(default)]
    pub force: Option<bool>,
}

/// Request to set (full replace) a user's custom attributes.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SetCustomAttributesRequest {
    /// The complete set of custom attributes to apply.
    pub attributes: serde_json::Value,
}

/// Request to patch (merge) a user's custom attributes.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PatchCustomAttributesRequest {
    /// Attributes to set or update (merged with existing).
    #[serde(default)]
    pub set: Option<serde_json::Value>,

    /// Attribute names to remove.
    #[serde(default)]
    pub unset: Option<Vec<String>>,
}

/// Request for bulk updating a custom attribute across users.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkUpdateRequest {
    /// Name of the attribute to update.
    pub attribute_name: String,

    /// New value to set for the attribute.
    pub new_value: serde_json::Value,

    /// Filter criteria for which users to update.
    pub filter: BulkUpdateFilter,
}

/// Filter criteria for bulk attribute updates.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkUpdateFilter {
    /// Only update users whose attribute currently has this value.
    #[serde(default)]
    pub current_value: Option<serde_json::Value>,

    /// Specific user IDs to update.
    #[serde(default)]
    pub user_ids: Option<Vec<Uuid>>,
}

// ── Responses ──

/// Single attribute definition response.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributeDefinitionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this definition belongs to.
    pub tenant_id: Uuid,

    /// Attribute name.
    pub name: String,

    /// Human-readable display label.
    pub display_label: String,

    /// Data type: string, number, boolean, date, json.
    pub data_type: String,

    /// Whether this attribute is required.
    pub required: bool,

    /// Type-specific validation constraints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_rules: Option<serde_json::Value>,

    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,

    /// Display ordering.
    pub sort_order: i32,

    /// Whether the definition is active.
    pub is_active: bool,

    /// Whether this attribute was seeded from the well-known catalog (F081).
    pub is_well_known: bool,

    /// Original well-known catalog slug for cross-tenant interoperability (F081).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub well_known_slug: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Response for listing attribute definitions.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttributeDefinitionListResponse {
    /// List of attribute definitions.
    pub definitions: Vec<AttributeDefinitionResponse>,

    /// Total count of matching definitions.
    pub total_count: i64,
}

/// Response for a user's custom attributes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserCustomAttributesResponse {
    /// User's unique identifier.
    pub user_id: Uuid,

    /// The user's custom attributes.
    pub custom_attributes: serde_json::Value,
}

/// Response for a bulk attribute update operation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkUpdateResponse {
    /// Number of users matched by the filter.
    pub total_matched: i64,

    /// Number of users successfully updated.
    pub total_updated: i64,

    /// Number of users that failed validation.
    pub total_failed: i64,

    /// Individual failure details.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<BulkUpdateFailure>,
}

/// Details about a single failure in a bulk update.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkUpdateFailure {
    /// User ID that failed.
    pub user_id: Uuid,

    /// Error description.
    pub error: String,
}

/// Response for missing attribute audit.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MissingAttributeAuditResponse {
    /// Users with missing required attributes.
    pub users: Vec<UserMissingAttributes>,

    /// Pagination metadata.
    pub pagination: super::responses::PaginationMeta,

    /// Total number of users missing required attributes.
    pub total_missing_count: i64,
}

/// A user with their missing required attributes.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserMissingAttributes {
    /// User's unique identifier.
    pub user_id: Uuid,

    /// User's email address.
    pub email: String,

    /// Names of missing required attributes.
    pub missing_attributes: Vec<String>,
}

/// Validation rules schema for documentation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidationRules {
    /// Maximum string length (string type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,

    /// Minimum string length (string type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u64>,

    /// Regex pattern to match (string type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Allowed values (string or number type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<serde_json::Value>>,

    /// Minimum numeric value (number type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,

    /// Maximum numeric value (number type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

/// Response for the seed-wellknown endpoint (F081).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SeedWellKnownResponse {
    /// Attributes that were newly seeded.
    pub seeded: Vec<SeededAttribute>,

    /// Attributes that were skipped (already exist or limit reached).
    pub skipped: Vec<SkippedAttribute>,

    /// Number of attributes seeded.
    pub total_seeded: usize,

    /// Number of attributes skipped.
    pub total_skipped: usize,
}

/// A single attribute that was seeded from the well-known catalog.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SeededAttribute {
    /// The new definition ID.
    pub id: Uuid,

    /// Well-known slug (e.g., "department", "`hire_date`").
    pub slug: String,

    /// Display label.
    pub display_label: String,

    /// Data type.
    pub data_type: String,
}

/// A single attribute that was skipped during seeding.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SkippedAttribute {
    /// Well-known slug that was skipped.
    pub slug: String,

    /// Reason for skipping.
    pub reason: String,
}

// ── Search/Filter models (US3) ──

/// Operator for filtering users by custom attribute values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOperator {
    /// Equality match.
    Eq,
    /// Less than.
    Lt,
    /// Greater than.
    Gt,
    /// Less than or equal.
    Lte,
    /// Greater than or equal.
    Gte,
}

/// A filter on a custom attribute for user search.
#[derive(Debug, Clone)]
pub struct CustomAttributeFilter {
    /// Name of the custom attribute to filter on.
    pub attribute_name: String,

    /// Comparison operator.
    pub operator: FilterOperator,

    /// Value to compare against (raw string from query param).
    pub value: String,
}

/// Parse custom attribute filters from a raw query string.
///
/// Extracts query parameters with the `custom_attr.` prefix:
/// - `custom_attr.department=Engineering` → equality filter
/// - `custom_attr.hire_date.lt=2024-01-01` → less-than filter
/// - `custom_attr.age.gte=18` → greater-than-or-equal filter
///
/// Supported operator suffixes: `.lt`, `.gt`, `.lte`, `.gte`
/// No suffix means equality (`.eq`).
#[must_use]
pub fn parse_custom_attr_filters(query: &str) -> Vec<CustomAttributeFilter> {
    let mut filters = Vec::new();
    let prefix = "custom_attr.";

    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };

        // URL-decode the value (basic: replace + with space, then percent-decode)
        let value = url_decode(value);

        if !key.starts_with(prefix) {
            continue;
        }

        let rest = &key[prefix.len()..];
        if rest.is_empty() {
            continue;
        }

        // Check for operator suffix
        if let Some(attr_name) = rest.strip_suffix(".lt") {
            if !attr_name.is_empty() {
                filters.push(CustomAttributeFilter {
                    attribute_name: attr_name.to_string(),
                    operator: FilterOperator::Lt,
                    value,
                });
            }
        } else if let Some(attr_name) = rest.strip_suffix(".gt") {
            if !attr_name.is_empty() {
                filters.push(CustomAttributeFilter {
                    attribute_name: attr_name.to_string(),
                    operator: FilterOperator::Gt,
                    value,
                });
            }
        } else if let Some(attr_name) = rest.strip_suffix(".lte") {
            if !attr_name.is_empty() {
                filters.push(CustomAttributeFilter {
                    attribute_name: attr_name.to_string(),
                    operator: FilterOperator::Lte,
                    value,
                });
            }
        } else if let Some(attr_name) = rest.strip_suffix(".gte") {
            if !attr_name.is_empty() {
                filters.push(CustomAttributeFilter {
                    attribute_name: attr_name.to_string(),
                    operator: FilterOperator::Gte,
                    value,
                });
            }
        } else {
            // No operator suffix → equality
            filters.push(CustomAttributeFilter {
                attribute_name: rest.to_string(),
                operator: FilterOperator::Eq,
                value,
            });
        }
    }

    filters
}

/// Basic URL decoding (replace + with space, decode percent-encoded bytes).
/// Handles multi-byte UTF-8 sequences correctly (e.g., %C3%A9 → "é").
fn url_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    bytes.push(byte);
                    continue;
                }
            }
            bytes.push(b'%');
            bytes.extend_from_slice(hex.as_bytes());
        } else {
            let mut buf = [0u8; 4];
            let encoded = c.encode_utf8(&mut buf);
            bytes.extend_from_slice(encoded.as_bytes());
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).to_string())
}

// ── Conversion helpers ──

impl From<xavyo_db::models::TenantAttributeDefinition> for AttributeDefinitionResponse {
    fn from(def: xavyo_db::models::TenantAttributeDefinition) -> Self {
        Self {
            id: def.id,
            tenant_id: def.tenant_id,
            name: def.name,
            display_label: def.display_label,
            data_type: def.data_type,
            required: def.required,
            validation_rules: def.validation_rules,
            default_value: def.default_value,
            sort_order: def.sort_order,
            is_active: def.is_active,
            is_well_known: def.is_well_known,
            well_known_slug: def.well_known_slug,
            created_at: def.created_at,
            updated_at: def.updated_at,
        }
    }
}

// ── Custom deserializer for Option<Option<Value>> ──

/// Deserializes a field that distinguishes between absent, null, and present:
/// - Field absent in JSON → outer Option is None (don't update)
/// - Field present as null → outer Option is Some(None) (clear the value)
/// - Field present with value → outer Option is Some(Some(value)) (set the value)
fn deserialize_option_json<'de, D>(
    deserializer: D,
) -> Result<Option<Option<serde_json::Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(Some(None)),       // explicit null → clear
        Some(v) => Ok(Some(Some(v))), // value present → set
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_equality_filter() {
        let filters = parse_custom_attr_filters("custom_attr.department=Engineering");
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].attribute_name, "department");
        assert_eq!(filters[0].operator, FilterOperator::Eq);
        assert_eq!(filters[0].value, "Engineering");
    }

    #[test]
    fn test_parse_range_filters() {
        let query = "custom_attr.age.gte=18&custom_attr.age.lt=65";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 2);

        assert_eq!(filters[0].attribute_name, "age");
        assert_eq!(filters[0].operator, FilterOperator::Gte);
        assert_eq!(filters[0].value, "18");

        assert_eq!(filters[1].attribute_name, "age");
        assert_eq!(filters[1].operator, FilterOperator::Lt);
        assert_eq!(filters[1].value, "65");
    }

    #[test]
    fn test_parse_all_operators() {
        let query = "custom_attr.a=1&custom_attr.b.lt=2&custom_attr.c.gt=3&custom_attr.d.lte=4&custom_attr.e.gte=5";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 5);
        assert_eq!(filters[0].operator, FilterOperator::Eq);
        assert_eq!(filters[1].operator, FilterOperator::Lt);
        assert_eq!(filters[2].operator, FilterOperator::Gt);
        assert_eq!(filters[3].operator, FilterOperator::Lte);
        assert_eq!(filters[4].operator, FilterOperator::Gte);
    }

    #[test]
    fn test_parse_ignores_non_custom_attr_params() {
        let query = "offset=0&limit=20&email=test&custom_attr.department=HR";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].attribute_name, "department");
    }

    #[test]
    fn test_parse_url_decoded_value() {
        let query = "custom_attr.department=Product+Engineering";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].value, "Product Engineering");
    }

    #[test]
    fn test_parse_percent_encoded_value() {
        let query = "custom_attr.department=R%26D";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].value, "R&D");
    }

    #[test]
    fn test_parse_empty_query() {
        let filters = parse_custom_attr_filters("");
        assert!(filters.is_empty());
    }

    #[test]
    fn test_parse_multiple_equality_filters() {
        let query = "custom_attr.department=Engineering&custom_attr.location=NYC";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].attribute_name, "department");
        assert_eq!(filters[0].value, "Engineering");
        assert_eq!(filters[1].attribute_name, "location");
        assert_eq!(filters[1].value, "NYC");
    }

    #[test]
    fn test_parse_skips_malformed_entries() {
        let query = "custom_attr.=val&custom_attr.ok=yes&noequals";
        let filters = parse_custom_attr_filters(query);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].attribute_name, "ok");
    }
}
