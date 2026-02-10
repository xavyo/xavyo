//! Catalog request/response models for Self-Service Request Catalog API (F-062).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{
    CartItemWithDetails, CatalogCategory, CatalogItem, CatalogItemType, FormField, RequestCart,
    RequestCartItem, RequestabilityRules,
};

// ============================================================================
// Category DTOs
// ============================================================================

/// Request to create a new catalog category.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateCategoryRequest {
    /// Category display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Category description.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// Parent category ID for hierarchy.
    pub parent_id: Option<Uuid>,

    /// Icon identifier for UI display.
    #[validate(length(max = 100, message = "Icon cannot exceed 100 characters"))]
    pub icon: Option<String>,

    /// Sort order within parent. Defaults to 0.
    #[serde(default)]
    pub display_order: i32,
}

/// Request to update a catalog category.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateCategoryRequest {
    /// New name for the category.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// New description for the category.
    #[validate(length(max = 2000, message = "Description cannot exceed 2000 characters"))]
    pub description: Option<String>,

    /// New parent category ID.
    pub parent_id: Option<Uuid>,

    /// New icon identifier.
    #[validate(length(max = 100, message = "Icon cannot exceed 100 characters"))]
    pub icon: Option<String>,

    /// New display order.
    pub display_order: Option<i32>,
}

/// Query parameters for listing categories.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCategoriesQuery {
    /// Filter by parent category ID. Use "null" for root categories.
    pub parent_id: Option<String>,

    /// Maximum number of results to return (clamped to 1-100).
    #[serde(
        default = "default_limit",
        deserialize_with = "deserialize_clamped_limit"
    )]
    pub limit: i64,

    /// Number of results to skip (non-negative).
    #[serde(default, deserialize_with = "deserialize_non_negative_offset")]
    pub offset: i64,
}

/// Catalog category response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CategoryResponse {
    /// Unique identifier for the category.
    pub id: Uuid,

    /// Category display name.
    pub name: String,

    /// Category description.
    pub description: Option<String>,

    /// Parent category ID.
    pub parent_id: Option<Uuid>,

    /// Icon identifier.
    pub icon: Option<String>,

    /// Sort order within parent.
    pub display_order: i32,

    /// When the category was created.
    pub created_at: DateTime<Utc>,

    /// When the category was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<CatalogCategory> for CategoryResponse {
    fn from(cat: CatalogCategory) -> Self {
        Self {
            id: cat.id,
            name: cat.name,
            description: cat.description,
            parent_id: cat.parent_id,
            icon: cat.icon,
            display_order: cat.display_order,
            created_at: cat.created_at,
            updated_at: cat.updated_at,
        }
    }
}

/// Paginated list of categories.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CategoryListResponse {
    /// List of categories.
    pub items: Vec<CategoryResponse>,

    /// Total count of matching categories.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

// ============================================================================
// Catalog Item DTOs
// ============================================================================

/// Request to create a new catalog item.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateCatalogItemRequest {
    /// Category for organization.
    pub category_id: Option<Uuid>,

    /// Type of item (role, entitlement, resource).
    pub item_type: CatalogItemType,

    /// Item display name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Item description.
    #[validate(length(max = 10000, message = "Description cannot exceed 10000 characters"))]
    pub description: Option<String>,

    /// Reference to the underlying role or entitlement.
    pub reference_id: Option<Uuid>,

    /// Requestability rules.
    #[serde(default)]
    pub requestability_rules: RequestabilityRules,

    /// Form field definitions.
    #[serde(default)]
    pub form_fields: Vec<FormField>,

    /// Searchable tags.
    #[validate(length(max = 50, message = "Cannot have more than 50 tags"))]
    #[serde(default)]
    pub tags: Vec<String>,

    /// Icon identifier for UI display.
    #[validate(length(max = 100, message = "Icon cannot exceed 100 characters"))]
    pub icon: Option<String>,
}

/// Request to update a catalog item.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateCatalogItemRequest {
    /// New category ID.
    pub category_id: Option<Uuid>,

    /// New name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    /// New description.
    #[validate(length(max = 10000, message = "Description cannot exceed 10000 characters"))]
    pub description: Option<String>,

    /// New requestability rules.
    pub requestability_rules: Option<RequestabilityRules>,

    /// New form field definitions.
    pub form_fields: Option<Vec<FormField>>,

    /// New tags.
    #[validate(length(max = 50, message = "Cannot have more than 50 tags"))]
    pub tags: Option<Vec<String>>,

    /// New icon.
    #[validate(length(max = 100, message = "Icon cannot exceed 100 characters"))]
    pub icon: Option<String>,
}

/// Query parameters for listing catalog items.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCatalogItemsQuery {
    /// Filter by category.
    pub category_id: Option<Uuid>,

    /// Filter by item type.
    pub item_type: Option<CatalogItemType>,

    /// Filter by enabled status (for admin view).
    pub enabled: Option<bool>,

    /// Full-text search query.
    pub search: Option<String>,

    /// Filter by tag.
    pub tag: Option<String>,

    /// Beneficiary ID for eligibility check.
    pub beneficiary_id: Option<Uuid>,

    /// Maximum number of results to return (clamped to 1-100).
    #[serde(
        default = "default_limit",
        deserialize_with = "deserialize_clamped_limit"
    )]
    pub limit: i64,

    /// Number of results to skip (non-negative).
    #[serde(default, deserialize_with = "deserialize_non_negative_offset")]
    pub offset: i64,
}

/// Catalog item response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CatalogItemResponse {
    /// Unique identifier for the item.
    pub id: Uuid,

    /// Category ID.
    pub category_id: Option<Uuid>,

    /// Type of item.
    pub item_type: CatalogItemType,

    /// Item display name.
    pub name: String,

    /// Item description.
    pub description: Option<String>,

    /// Reference to the underlying role or entitlement.
    pub reference_id: Option<Uuid>,

    /// Requestability rules.
    pub requestability_rules: RequestabilityRules,

    /// Form field definitions.
    pub form_fields: Vec<FormField>,

    /// Searchable tags.
    pub tags: Vec<String>,

    /// Icon identifier.
    pub icon: Option<String>,

    /// Whether item is enabled.
    pub enabled: bool,

    /// Version number.
    pub version: i32,

    /// When the item was created.
    pub created_at: DateTime<Utc>,

    /// When the item was last updated.
    pub updated_at: DateTime<Utc>,

    /// Whether the current user can request this item (populated by service).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_request: Option<bool>,

    /// Reason if cannot request (populated by service).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cannot_request_reason: Option<String>,
}

impl From<CatalogItem> for CatalogItemResponse {
    fn from(item: CatalogItem) -> Self {
        let requestability_rules = item.get_requestability_rules();
        let form_fields = item.get_form_fields();
        Self {
            id: item.id,
            category_id: item.category_id,
            item_type: item.item_type,
            name: item.name,
            description: item.description,
            reference_id: item.reference_id,
            requestability_rules,
            form_fields,
            tags: item.tags,
            icon: item.icon,
            enabled: item.enabled,
            version: item.version,
            created_at: item.created_at,
            updated_at: item.updated_at,
            can_request: None,
            cannot_request_reason: None,
        }
    }
}

impl CatalogItemResponse {
    /// Set requestability information.
    pub fn with_requestability(mut self, can_request: bool, reason: Option<String>) -> Self {
        self.can_request = Some(can_request);
        self.cannot_request_reason = reason;
        self
    }
}

/// Paginated list of catalog items.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CatalogItemListResponse {
    /// List of catalog items.
    pub items: Vec<CatalogItemResponse>,

    /// Total count of matching items.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

// ============================================================================
// Cart DTOs
// ============================================================================

/// Request to add an item to the cart.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct AddToCartRequest {
    /// The catalog item to add.
    pub catalog_item_id: Uuid,

    /// Beneficiary ID (for manager-initiated requests).
    pub beneficiary_id: Option<Uuid>,

    /// Parameters for parametric roles.
    #[serde(default)]
    pub parameters: serde_json::Value,

    /// Form field values.
    #[serde(default)]
    pub form_values: serde_json::Value,
}

/// Request to update a cart item.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateCartItemRequest {
    /// New parameters.
    pub parameters: Option<serde_json::Value>,

    /// New form field values.
    pub form_values: Option<serde_json::Value>,
}

/// Query parameters for cart operations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct CartQuery {
    /// Beneficiary ID (for manager-initiated requests).
    pub beneficiary_id: Option<Uuid>,
}

/// Cart item response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartItemResponse {
    /// Cart item ID.
    pub id: Uuid,

    /// Catalog item ID.
    pub catalog_item_id: Uuid,

    /// Catalog item name.
    pub item_name: String,

    /// Catalog item description.
    pub item_description: Option<String>,

    /// Catalog item type.
    pub item_type: String,

    /// Whether the catalog item is still enabled.
    pub item_enabled: bool,

    /// Parameters for parametric roles.
    pub parameters: serde_json::Value,

    /// Form field values.
    pub form_values: serde_json::Value,

    /// When added to cart.
    pub added_at: DateTime<Utc>,
}

impl From<CartItemWithDetails> for CartItemResponse {
    fn from(item: CartItemWithDetails) -> Self {
        Self {
            id: item.id,
            catalog_item_id: item.catalog_item_id,
            item_name: item.item_name,
            item_description: item.item_description,
            item_type: item.item_type,
            item_enabled: item.item_enabled,
            parameters: item.parameters,
            form_values: item.form_values,
            added_at: item.added_at,
        }
    }
}

impl From<RequestCartItem> for CartItemResponse {
    fn from(item: RequestCartItem) -> Self {
        Self {
            id: item.id,
            catalog_item_id: item.catalog_item_id,
            item_name: String::new(), // Will be populated from join
            item_description: None,
            item_type: String::new(),
            item_enabled: true,
            parameters: item.parameters,
            form_values: item.form_values,
            added_at: item.added_at,
        }
    }
}

/// Cart response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartResponse {
    /// Cart ID.
    pub id: Uuid,

    /// Requester ID.
    pub requester_id: Uuid,

    /// Beneficiary ID (None = self).
    pub beneficiary_id: Option<Uuid>,

    /// Items in the cart.
    pub items: Vec<CartItemResponse>,

    /// Total number of items in the cart.
    pub item_count: i64,

    /// When the cart was created.
    pub created_at: DateTime<Utc>,

    /// When the cart was last updated.
    pub updated_at: DateTime<Utc>,
}

impl CartResponse {
    /// Create from RequestCart with items.
    pub fn from_cart_with_items(cart: RequestCart, items: Vec<CartItemWithDetails>) -> Self {
        let item_count = items.len() as i64;
        Self {
            id: cart.id,
            requester_id: cart.requester_id,
            beneficiary_id: cart.beneficiary_id,
            items: items.into_iter().map(CartItemResponse::from).collect(),
            item_count,
            created_at: cart.created_at,
            updated_at: cart.updated_at,
        }
    }
}

// ============================================================================
// Cart Validation & Submission DTOs
// ============================================================================

/// SoD violation detected during cart validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartSodViolation {
    /// SoD rule that was violated.
    pub rule_id: Uuid,

    /// Rule name.
    pub rule_name: String,

    /// IDs of conflicting items in the cart.
    pub conflicting_item_ids: Vec<Uuid>,

    /// Description of the violation.
    pub description: String,
}

/// Cart validation issue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartValidationIssue {
    /// Cart item ID (if applicable).
    pub cart_item_id: Option<Uuid>,

    /// Issue code.
    pub code: String,

    /// Issue message.
    pub message: String,
}

/// Cart validation result.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartValidationResponse {
    /// Whether the cart is valid for submission.
    pub valid: bool,

    /// Validation issues found.
    pub issues: Vec<CartValidationIssue>,

    /// SoD violations found.
    pub sod_violations: Vec<CartSodViolation>,
}

/// Request to submit the cart.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SubmitCartRequest {
    /// Beneficiary ID (for manager-initiated requests).
    pub beneficiary_id: Option<Uuid>,

    /// Global justification for all items.
    #[validate(length(max = 5000, message = "Justification cannot exceed 5000 characters"))]
    pub global_justification: Option<String>,
}

/// Result of a single cart item submission.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubmittedItemResult {
    /// Cart item ID.
    pub cart_item_id: Uuid,

    /// Catalog item ID.
    pub catalog_item_id: Uuid,

    /// Created access request ID.
    pub access_request_id: Uuid,
}

/// Cart submission response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CartSubmissionResponse {
    /// Unique submission ID linking all requests.
    pub submission_id: Uuid,

    /// Individual item results.
    pub items: Vec<SubmittedItemResult>,

    /// Number of access requests created.
    pub request_count: i64,
}

// ============================================================================
// Request History DTOs
// ============================================================================

/// Query parameters for listing catalog requests.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListCatalogRequestsQuery {
    /// Filter by status.
    pub status: Option<String>,

    /// Filter by submission ID.
    pub submission_id: Option<Uuid>,

    /// Maximum number of results to return (clamped to 1-100).
    #[serde(
        default = "default_limit",
        deserialize_with = "deserialize_clamped_limit"
    )]
    pub limit: i64,

    /// Number of results to skip (non-negative).
    #[serde(default, deserialize_with = "deserialize_non_negative_offset")]
    pub offset: i64,
}

/// Catalog request response (access request originated from catalog).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CatalogRequestResponse {
    /// Access request ID.
    pub id: Uuid,

    /// Submission ID (groups items submitted together).
    pub submission_id: Option<Uuid>,

    /// Catalog item ID.
    pub catalog_item_id: Uuid,

    /// Catalog item name.
    pub catalog_item_name: String,

    /// Catalog item type.
    pub catalog_item_type: CatalogItemType,

    /// Requester ID.
    pub requester_id: Uuid,

    /// Beneficiary ID (None = self).
    pub beneficiary_id: Option<Uuid>,

    /// Request status.
    pub status: String,

    /// Justification.
    pub justification: Option<String>,

    /// When the request was created.
    pub created_at: DateTime<Utc>,

    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of catalog requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CatalogRequestListResponse {
    /// List of requests.
    pub items: Vec<CatalogRequestResponse>,

    /// Total count of matching requests.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

// ============================================================================
// Utility Functions
// ============================================================================

fn default_limit() -> i64 {
    50
}

/// Deserialize limit with clamping to [1, 100].
fn deserialize_clamped_limit<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = i64::deserialize(deserializer)?;
    Ok(v.clamp(1, 100))
}

/// Deserialize offset ensuring non-negative.
fn deserialize_non_negative_offset<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = i64::deserialize(deserializer)?;
    Ok(v.max(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_category_request_validation() {
        let request = CreateCategoryRequest {
            name: "Developer Tools".to_string(),
            description: Some("Access to development resources".to_string()),
            parent_id: None,
            icon: Some("tools".to_string()),
            display_order: 1,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_category_request_empty_name() {
        let request = CreateCategoryRequest {
            name: String::new(),
            description: None,
            parent_id: None,
            icon: None,
            display_order: 0,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_catalog_item_request_validation() {
        let request = CreateCatalogItemRequest {
            category_id: None,
            item_type: CatalogItemType::Role,
            name: "Developer Access".to_string(),
            description: Some("Standard developer role".to_string()),
            reference_id: Some(Uuid::new_v4()),
            requestability_rules: RequestabilityRules::default(),
            form_fields: vec![],
            tags: vec!["developer".to_string()],
            icon: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_catalog_item_response_with_requestability() {
        let item = CatalogItem {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            category_id: None,
            item_type: CatalogItemType::Role,
            name: "Test".to_string(),
            description: None,
            reference_id: None,
            requestability_rules: serde_json::json!({}),
            form_fields: serde_json::json!([]),
            tags: vec![],
            icon: None,
            enabled: true,
            version: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response = CatalogItemResponse::from(item)
            .with_requestability(false, Some("Not in eligible department".to_string()));

        assert_eq!(response.can_request, Some(false));
        assert!(response.cannot_request_reason.is_some());
    }

    #[test]
    fn test_add_to_cart_request_validation() {
        let request = AddToCartRequest {
            catalog_item_id: Uuid::new_v4(),
            beneficiary_id: None,
            parameters: serde_json::json!({}),
            form_values: serde_json::json!({}),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_cart_validation_response() {
        let response = CartValidationResponse {
            valid: false,
            issues: vec![CartValidationIssue {
                cart_item_id: Some(Uuid::new_v4()),
                code: "MISSING_FIELD".to_string(),
                message: "Required field 'justification' is missing".to_string(),
            }],
            sod_violations: vec![],
        };

        assert!(!response.valid);
        assert_eq!(response.issues.len(), 1);
    }
}
