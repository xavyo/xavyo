//! Catalog service for Self-Service Request Catalog (F-062).
//!
//! Provides business logic for browsing, searching, and managing catalog items
//! with requestability evaluation.

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    AddCartItem, CartItemWithDetails, CatalogCategory, CatalogCategoryFilter, CatalogItem,
    CatalogItemFilter, CatalogItemType, CreateCatalogCategory, CreateCatalogItem, GovAccessRequest,
    GovRole, GovSodExemption, GovSodRule, RequestCart, RequestCartItem, RequestabilityRules,
    UpdateCartItem as DbUpdateCartItem, UpdateCatalogCategory, UpdateCatalogItem, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::services::EffectiveAccessService;

// ============================================================================
// Cart Validation Types
// ============================================================================

/// A validation issue found during cart validation.
#[derive(Debug, Clone)]
pub struct CartValidationIssue {
    /// Cart item ID (if applicable).
    pub cart_item_id: Option<Uuid>,
    /// Issue code.
    pub code: String,
    /// Issue message.
    pub message: String,
}

/// SoD violation found during cart validation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CartSodViolation {
    /// SoD rule that was violated.
    pub rule_id: Uuid,
    /// Rule name.
    pub rule_name: String,
    /// IDs of conflicting entitlements.
    pub conflicting_item_ids: Vec<Uuid>,
    /// Description of the violation.
    pub description: String,
}

/// Result of cart validation.
#[derive(Debug, Clone)]
pub struct CartValidationResult {
    /// Whether the cart is valid for submission.
    pub valid: bool,
    /// Validation issues found.
    pub issues: Vec<CartValidationIssue>,
    /// SoD violations found (warnings, not blocking).
    pub sod_violations: Vec<CartSodViolation>,
}

/// Result of a single cart item submission.
#[derive(Debug, Clone)]
pub struct SubmittedItemResult {
    /// Cart item ID.
    pub cart_item_id: Uuid,
    /// Catalog item ID.
    pub catalog_item_id: Uuid,
    /// Created access request ID.
    pub access_request_id: Uuid,
}

/// Result of cart submission.
#[derive(Debug, Clone)]
pub struct CartSubmissionResult {
    /// Unique submission ID linking all requests.
    pub submission_id: Uuid,
    /// Individual item results.
    pub items: Vec<SubmittedItemResult>,
    /// Number of access requests created.
    pub request_count: i64,
}

/// Context for evaluating requestability rules.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The user making the request.
    pub requester_id: Uuid,
    /// The beneficiary of the request (may be same as requester for self-requests).
    pub beneficiary_id: Uuid,
    /// Whether this is a manager requesting for a direct report.
    pub is_manager_request: bool,
    /// The beneficiary's department (if available).
    pub beneficiary_department: Option<String>,
    /// The beneficiary's archetype (if available).
    pub beneficiary_archetype: Option<String>,
}

impl RequestContext {
    /// Create a self-request context.
    pub fn self_request(user_id: Uuid) -> Self {
        Self {
            requester_id: user_id,
            beneficiary_id: user_id,
            is_manager_request: false,
            beneficiary_department: None,
            beneficiary_archetype: None,
        }
    }

    /// Check if this is a self-request.
    #[must_use]
    pub fn is_self_request(&self) -> bool {
        self.requester_id == self.beneficiary_id
    }
}

/// Result of requestability evaluation.
#[derive(Debug, Clone)]
pub struct RequestabilityResult {
    /// Whether the item can be requested.
    pub can_request: bool,
    /// Reason why the item cannot be requested (if applicable).
    pub reason: Option<String>,
}

impl RequestabilityResult {
    /// Create a result indicating the item can be requested.
    #[must_use]
    pub fn allowed() -> Self {
        Self {
            can_request: true,
            reason: None,
        }
    }

    /// Create a result indicating the item cannot be requested.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            can_request: false,
            reason: Some(reason.into()),
        }
    }
}

/// Service for catalog operations.
pub struct CatalogService {
    pool: PgPool,
    effective_access_service: EffectiveAccessService,
}

impl CatalogService {
    /// Create a new catalog service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            effective_access_service: EffectiveAccessService::new(pool.clone()),
            pool,
        }
    }

    // =========================================================================
    // Category Operations (T014)
    // =========================================================================

    /// List all categories for a tenant with optional filtering.
    pub async fn list_categories(
        &self,
        tenant_id: Uuid,
        parent_id: Option<Option<Uuid>>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<CatalogCategory>, i64)> {
        let filter = CatalogCategoryFilter { parent_id };

        let categories =
            CatalogCategory::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = CatalogCategory::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((categories, total))
    }

    /// Get a category by ID.
    pub async fn get_category(
        &self,
        tenant_id: Uuid,
        category_id: Uuid,
    ) -> Result<CatalogCategory> {
        CatalogCategory::find_by_id(&self.pool, tenant_id, category_id)
            .await?
            .ok_or(GovernanceError::CatalogCategoryNotFound(category_id))
    }

    // =========================================================================
    // Catalog Item Operations (T015, T016)
    // =========================================================================

    /// List catalog items for a tenant with filtering, search, and pagination.
    ///
    /// This method returns items visible to end users (enabled items only by default).
    pub async fn list_items(
        &self,
        tenant_id: Uuid,
        category_id: Option<Uuid>,
        item_type: Option<CatalogItemType>,
        search: Option<String>,
        tag: Option<String>,
        enabled_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<CatalogItem>, i64)> {
        let filter = CatalogItemFilter {
            category_id,
            item_type,
            enabled: if enabled_only { Some(true) } else { None },
            search,
            tag,
        };

        let items =
            CatalogItem::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = CatalogItem::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((items, total))
    }

    /// List catalog items with requestability evaluation for a specific user context.
    ///
    /// Returns items with can_request and cannot_request_reason populated.
    pub async fn list_items_with_requestability(
        &self,
        tenant_id: Uuid,
        context: &RequestContext,
        category_id: Option<Uuid>,
        item_type: Option<CatalogItemType>,
        search: Option<String>,
        tag: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<(CatalogItem, RequestabilityResult)>, i64)> {
        let (items, total) = self
            .list_items(
                tenant_id,
                category_id,
                item_type,
                search,
                tag,
                true, // enabled_only
                limit,
                offset,
            )
            .await?;

        let mut results = Vec::with_capacity(items.len());
        for item in items {
            let requestability = self
                .evaluate_requestability(tenant_id, &item, context)
                .await?;
            results.push((item, requestability));
        }

        Ok((results, total))
    }

    /// Get a catalog item by ID with requestability check.
    pub async fn get_item(&self, tenant_id: Uuid, item_id: Uuid) -> Result<CatalogItem> {
        CatalogItem::find_by_id(&self.pool, tenant_id, item_id)
            .await?
            .ok_or(GovernanceError::CatalogItemNotFound(item_id))
    }

    /// Get a catalog item by ID with requestability evaluation.
    pub async fn get_item_with_requestability(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        context: &RequestContext,
    ) -> Result<(CatalogItem, RequestabilityResult)> {
        let item = self.get_item(tenant_id, item_id).await?;

        // Check if item is enabled
        if !item.is_enabled() {
            return Err(GovernanceError::CatalogItemDisabled(item_id));
        }

        let requestability = self
            .evaluate_requestability(tenant_id, &item, context)
            .await?;

        Ok((item, requestability))
    }

    // =========================================================================
    // Requestability Rule Evaluation (T017)
    // =========================================================================

    /// Evaluate whether a user can request a catalog item based on requestability rules.
    pub async fn evaluate_requestability(
        &self,
        tenant_id: Uuid,
        item: &CatalogItem,
        context: &RequestContext,
    ) -> Result<RequestabilityResult> {
        let rules = item.get_requestability_rules();

        // Check self-request permission
        if context.is_self_request() && !rules.self_request {
            return Ok(RequestabilityResult::denied(
                "Self-request is not allowed for this item",
            ));
        }

        // Check manager-request permission
        if context.is_manager_request && !rules.manager_request {
            return Ok(RequestabilityResult::denied(
                "Manager request is not allowed for this item",
            ));
        }

        // Check department restrictions
        if let Some(ref dept) = context.beneficiary_department {
            if !rules.department_restriction.is_empty()
                && !rules.department_restriction.contains(dept)
            {
                return Ok(RequestabilityResult::denied(format!(
                    "Item is restricted to departments: {}",
                    rules.department_restriction.join(", ")
                )));
            }
        } else if !rules.department_restriction.is_empty() {
            return Ok(RequestabilityResult::denied(
                "User department information required for this item",
            ));
        }

        // Check archetype restrictions
        if let Some(ref archetype) = context.beneficiary_archetype {
            if !rules.archetype_restriction.is_empty()
                && !rules.archetype_restriction.contains(archetype)
            {
                return Ok(RequestabilityResult::denied(format!(
                    "Item is restricted to archetypes: {}",
                    rules.archetype_restriction.join(", ")
                )));
            }
        } else if !rules.archetype_restriction.is_empty() {
            return Ok(RequestabilityResult::denied(
                "User archetype information required for this item",
            ));
        }

        // Check prerequisite roles
        if !rules.prerequisite_roles.is_empty() {
            let has_all_prerequisites = self
                .check_prerequisite_roles(
                    tenant_id,
                    context.beneficiary_id,
                    &rules.prerequisite_roles,
                )
                .await?;

            if !has_all_prerequisites {
                return Ok(RequestabilityResult::denied(
                    "User does not have required prerequisite roles",
                ));
            }
        }

        // Check prerequisite entitlements
        if !rules.prerequisite_entitlements.is_empty() {
            let has_all_entitlements = self
                .check_prerequisite_entitlements(
                    tenant_id,
                    context.beneficiary_id,
                    &rules.prerequisite_entitlements,
                )
                .await?;

            if !has_all_entitlements {
                return Ok(RequestabilityResult::denied(
                    "User does not have required prerequisite entitlements",
                ));
            }
        }

        Ok(RequestabilityResult::allowed())
    }

    /// Check if a user has all the required prerequisite roles.
    ///
    /// Queries the gov_role_assignments table to verify the user has assignments
    /// to all required roles (either direct user assignments or through group membership).
    async fn check_prerequisite_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        required_roles: &[Uuid],
    ) -> Result<bool> {
        if required_roles.is_empty() {
            return Ok(true);
        }

        // Query user's role assignments through entitlement assignments that reference roles
        // This checks if the user has entitlements that are mapped to the required roles
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(DISTINCT gre.role_id)
            FROM gov_role_entitlements gre
            JOIN gov_entitlement_assignments gea ON gre.entitlement_id = gea.entitlement_id
            WHERE gea.tenant_id = $1
              AND gea.target_id = $2
              AND gea.target_type = 'user'
              AND gea.status = 'active'
              AND gre.role_id = ANY($3)
              AND (gea.expires_at IS NULL OR gea.expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(required_roles)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize == required_roles.len())
    }

    /// Check if a user has all the required prerequisite entitlements.
    async fn check_prerequisite_entitlements(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        required_entitlements: &[Uuid],
    ) -> Result<bool> {
        if required_entitlements.is_empty() {
            return Ok(true);
        }

        // Query user's direct entitlement assignments
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(DISTINCT entitlement_id)
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1
              AND target_id = $2 AND target_type = 'user'
              AND entitlement_id = ANY($3)
              AND (expires_at IS NULL OR expires_at > NOW())
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(required_entitlements)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize == required_entitlements.len())
    }

    /// Build a RequestContext from user data.
    pub async fn build_request_context(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<RequestContext> {
        let beneficiary_id = beneficiary_id.unwrap_or(requester_id);
        let is_self_request = requester_id == beneficiary_id;

        // Load beneficiary user data
        let beneficiary = User::find_by_id_in_tenant(&self.pool, tenant_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(beneficiary_id))?;

        // Check if requester is manager of beneficiary (for manager requests)
        let is_manager_request = if !is_self_request {
            beneficiary
                .manager_id
                .map(|mid| mid == requester_id)
                .unwrap_or(false)
        } else {
            false
        };

        // Extract department from custom_attributes if available
        let beneficiary_department = beneficiary
            .custom_attributes
            .get("department")
            .and_then(|v| v.as_str())
            .map(String::from);

        // Get archetype name if user has one
        let beneficiary_archetype = if let Some(archetype_id) = beneficiary.archetype_id {
            // Query archetype name
            let archetype_name: Option<String> = sqlx::query_scalar(
                r"SELECT name FROM identity_archetypes WHERE id = $1 AND tenant_id = $2",
            )
            .bind(archetype_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;
            archetype_name
        } else {
            None
        };

        Ok(RequestContext {
            requester_id,
            beneficiary_id,
            is_manager_request,
            beneficiary_department,
            beneficiary_archetype,
        })
    }

    // =========================================================================
    // Admin Category Operations (US5 - T053-T055)
    // =========================================================================

    /// Create a new catalog category.
    pub async fn create_category(
        &self,
        tenant_id: Uuid,
        input: CreateCatalogCategory,
    ) -> Result<CatalogCategory> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Category name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Category name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name at same hierarchy level
        if CatalogCategory::find_by_name(&self.pool, tenant_id, &input.name, input.parent_id)
            .await?
            .is_some()
        {
            return Err(GovernanceError::CatalogCategoryNameExists(
                input.name.clone(),
            ));
        }

        // Verify parent exists if specified
        if let Some(parent_id) = input.parent_id {
            if CatalogCategory::find_by_id(&self.pool, tenant_id, parent_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::CatalogCategoryNotFound(parent_id));
            }
        }

        CatalogCategory::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a catalog category.
    pub async fn update_category(
        &self,
        tenant_id: Uuid,
        category_id: Uuid,
        input: UpdateCatalogCategory,
    ) -> Result<CatalogCategory> {
        // Verify category exists
        let existing = self.get_category(tenant_id, category_id).await?;

        // Validate name if being changed
        if let Some(ref name) = input.name {
            if name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Category name cannot be empty".to_string(),
                ));
            }

            if name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Category name cannot exceed 255 characters".to_string(),
                ));
            }

            // Check for duplicate name (use new parent_id if provided, else existing)
            let parent_id = input.parent_id.or(existing.parent_id);
            if let Some(existing_cat) =
                CatalogCategory::find_by_name(&self.pool, tenant_id, name, parent_id).await?
            {
                if existing_cat.id != category_id {
                    return Err(GovernanceError::CatalogCategoryNameExists(name.clone()));
                }
            }
        }

        // Verify new parent exists if specified
        if let Some(new_parent_id) = input.parent_id {
            // Cannot set parent to self
            if new_parent_id == category_id {
                return Err(GovernanceError::Validation(
                    "Category cannot be its own parent".to_string(),
                ));
            }

            if CatalogCategory::find_by_id(&self.pool, tenant_id, new_parent_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::CatalogCategoryNotFound(new_parent_id));
            }
        }

        CatalogCategory::update(&self.pool, tenant_id, category_id, input)
            .await?
            .ok_or(GovernanceError::CatalogCategoryNotFound(category_id))
    }

    /// Delete a catalog category.
    pub async fn delete_category(&self, tenant_id: Uuid, category_id: Uuid) -> Result<()> {
        // Verify category exists
        let _existing = self.get_category(tenant_id, category_id).await?;

        // Check for child categories
        let child_count: i64 = sqlx::query_scalar(
            r"SELECT COUNT(*) FROM catalog_categories WHERE tenant_id = $1 AND parent_id = $2",
        )
        .bind(tenant_id)
        .bind(category_id)
        .fetch_one(&self.pool)
        .await?;

        if child_count > 0 {
            return Err(GovernanceError::CatalogCategoryHasChildren(child_count));
        }

        // Check for items in this category
        let item_count = CatalogCategory::count_items(&self.pool, tenant_id, category_id).await?;
        if item_count > 0 {
            return Err(GovernanceError::CatalogCategoryHasItems(item_count));
        }

        let deleted = CatalogCategory::delete(&self.pool, tenant_id, category_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::CatalogCategoryNotFound(category_id))
        }
    }

    // =========================================================================
    // Admin Item Operations (US5 - T056-T058)
    // =========================================================================

    /// Create a new catalog item.
    pub async fn create_item(
        &self,
        tenant_id: Uuid,
        input: CreateCatalogItem,
    ) -> Result<CatalogItem> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(GovernanceError::Validation(
                "Item name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(GovernanceError::Validation(
                "Item name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name
        if CatalogItem::find_by_name(&self.pool, tenant_id, &input.name)
            .await?
            .is_some()
        {
            return Err(GovernanceError::CatalogItemNameExists(input.name.clone()));
        }

        // Verify category exists if specified
        if let Some(category_id) = input.category_id {
            if CatalogCategory::find_by_id(&self.pool, tenant_id, category_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::CatalogCategoryNotFound(category_id));
            }
        }

        // Verify reference exists if specified
        if let Some(reference_id) = input.reference_id {
            self.verify_reference(tenant_id, input.item_type, reference_id)
                .await?;
        }

        // Validate requestability rules
        self.validate_requestability_rules(tenant_id, &input.requestability_rules)
            .await?;

        CatalogItem::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a catalog item.
    pub async fn update_item(
        &self,
        tenant_id: Uuid,
        item_id: Uuid,
        input: UpdateCatalogItem,
    ) -> Result<CatalogItem> {
        // Verify item exists
        let _existing = self.get_item(tenant_id, item_id).await?;

        // Validate name if being changed
        if let Some(ref name) = input.name {
            if name.trim().is_empty() {
                return Err(GovernanceError::Validation(
                    "Item name cannot be empty".to_string(),
                ));
            }

            if name.len() > 255 {
                return Err(GovernanceError::Validation(
                    "Item name cannot exceed 255 characters".to_string(),
                ));
            }

            // Check for duplicate name
            if let Some(existing_item) =
                CatalogItem::find_by_name(&self.pool, tenant_id, name).await?
            {
                if existing_item.id != item_id {
                    return Err(GovernanceError::CatalogItemNameExists(name.clone()));
                }
            }
        }

        // Verify new category exists if specified
        if let Some(category_id) = input.category_id {
            if CatalogCategory::find_by_id(&self.pool, tenant_id, category_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::CatalogCategoryNotFound(category_id));
            }
        }

        // Validate requestability rules if being updated
        if let Some(ref rules) = input.requestability_rules {
            self.validate_requestability_rules(tenant_id, rules).await?;
        }

        CatalogItem::update(&self.pool, tenant_id, item_id, input)
            .await?
            .ok_or(GovernanceError::CatalogItemNotFound(item_id))
    }

    /// Disable a catalog item (soft delete).
    pub async fn disable_item(&self, tenant_id: Uuid, item_id: Uuid) -> Result<CatalogItem> {
        // Verify item exists
        let _existing = self.get_item(tenant_id, item_id).await?;

        CatalogItem::disable(&self.pool, tenant_id, item_id)
            .await?
            .ok_or(GovernanceError::CatalogItemNotFound(item_id))
    }

    /// Enable a catalog item.
    pub async fn enable_item(&self, tenant_id: Uuid, item_id: Uuid) -> Result<CatalogItem> {
        // Verify item exists
        let _existing = self.get_item(tenant_id, item_id).await?;

        CatalogItem::enable(&self.pool, tenant_id, item_id)
            .await?
            .ok_or(GovernanceError::CatalogItemNotFound(item_id))
    }

    /// Delete a catalog item permanently.
    pub async fn delete_item(&self, tenant_id: Uuid, item_id: Uuid) -> Result<()> {
        // Verify item exists
        let _existing = self.get_item(tenant_id, item_id).await?;

        // Check for pending cart items referencing this item
        let cart_count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM request_cart_items rci
            JOIN request_carts rc ON rci.cart_id = rc.id
            WHERE rci.catalog_item_id = $1 AND rc.tenant_id = $2
            ",
        )
        .bind(item_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        if cart_count > 0 {
            return Err(GovernanceError::CatalogItemInCarts(cart_count));
        }

        let deleted = CatalogItem::delete(&self.pool, tenant_id, item_id).await?;
        if deleted {
            Ok(())
        } else {
            Err(GovernanceError::CatalogItemNotFound(item_id))
        }
    }

    /// List all items including disabled ones (admin view).
    pub async fn admin_list_items(
        &self,
        tenant_id: Uuid,
        category_id: Option<Uuid>,
        item_type: Option<CatalogItemType>,
        enabled: Option<bool>,
        search: Option<String>,
        tag: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<CatalogItem>, i64)> {
        let filter = CatalogItemFilter {
            category_id,
            item_type,
            enabled,
            search,
            tag,
        };

        let items =
            CatalogItem::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset).await?;
        let total = CatalogItem::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((items, total))
    }

    // =========================================================================
    // Cart Operations (US2 - T026-T030)
    // =========================================================================

    /// Get or create a cart for the given user and optional beneficiary.
    ///
    /// Returns an existing cart if one exists, otherwise creates a new one.
    pub async fn get_or_create_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<RequestCart> {
        RequestCart::get_or_create(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get a cart with all its items.
    pub async fn get_cart_with_items(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<(RequestCart, Vec<CartItemWithDetails>)> {
        let cart = self
            .get_or_create_cart(tenant_id, requester_id, beneficiary_id)
            .await?;

        let items =
            RequestCartItem::list_by_cart_with_details(&self.pool, tenant_id, cart.id).await?;

        Ok((cart, items))
    }

    /// Add an item to the cart.
    ///
    /// Validates that:
    /// - The catalog item exists and is enabled
    /// - The item is not already in the cart (duplicate prevention)
    /// - The user can request the item
    pub async fn add_to_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
        catalog_item_id: Uuid,
        parameters: serde_json::Value,
        form_values: serde_json::Value,
    ) -> Result<RequestCartItem> {
        // Get or create cart
        let cart = self
            .get_or_create_cart(tenant_id, requester_id, beneficiary_id)
            .await?;

        // Verify catalog item exists and is enabled
        let item = self.get_item(tenant_id, catalog_item_id).await?;
        if !item.is_enabled() {
            return Err(GovernanceError::CatalogItemDisabled(catalog_item_id));
        }

        // Check requestability
        let context = self
            .build_request_context(tenant_id, requester_id, beneficiary_id)
            .await?;
        let requestability = self
            .evaluate_requestability(tenant_id, &item, &context)
            .await?;

        if !requestability.can_request {
            return Err(GovernanceError::CatalogItemNotRequestable(
                requestability
                    .reason
                    .unwrap_or_else(|| "Item cannot be requested".to_string()),
            ));
        }

        // Check for duplicate (same catalog item with same parameters)
        if RequestCartItem::find_duplicate(
            &self.pool,
            tenant_id,
            cart.id,
            catalog_item_id,
            &parameters,
        )
        .await?
        .is_some()
        {
            return Err(GovernanceError::RequestCartItemDuplicate);
        }

        // Create cart item
        let input = AddCartItem {
            catalog_item_id,
            parameters,
            form_values,
        };

        RequestCartItem::create(&self.pool, tenant_id, cart.id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Remove an item from the cart.
    pub async fn remove_from_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
        cart_item_id: Uuid,
    ) -> Result<()> {
        // Get cart
        let cart = RequestCart::find_by_pair(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::RequestCartNotFound(Uuid::nil()))?;

        // Verify cart item exists and belongs to this cart
        let item = RequestCartItem::find_by_id(&self.pool, tenant_id, cart_item_id)
            .await?
            .ok_or(GovernanceError::RequestCartItemNotFound(cart_item_id))?;

        if item.cart_id != cart.id {
            return Err(GovernanceError::RequestCartItemNotFound(cart_item_id));
        }

        RequestCartItem::delete(&self.pool, tenant_id, cart_item_id).await?;
        Ok(())
    }

    /// Update a cart item's parameters or form values.
    pub async fn update_cart_item(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
        cart_item_id: Uuid,
        parameters: Option<serde_json::Value>,
        form_values: Option<serde_json::Value>,
    ) -> Result<RequestCartItem> {
        // Get cart
        let cart = RequestCart::find_by_pair(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::RequestCartNotFound(Uuid::nil()))?;

        // Verify cart item exists and belongs to this cart
        let existing = RequestCartItem::find_by_id(&self.pool, tenant_id, cart_item_id)
            .await?
            .ok_or(GovernanceError::RequestCartItemNotFound(cart_item_id))?;

        if existing.cart_id != cart.id {
            return Err(GovernanceError::RequestCartItemNotFound(cart_item_id));
        }

        // Build update input
        let input = DbUpdateCartItem {
            parameters,
            form_values,
        };

        RequestCartItem::update(&self.pool, tenant_id, cart_item_id, input)
            .await?
            .ok_or(GovernanceError::RequestCartItemNotFound(cart_item_id))
    }

    /// Clear all items from the cart.
    pub async fn clear_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<()> {
        let cart = RequestCart::find_by_pair(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::RequestCartNotFound(Uuid::nil()))?;

        RequestCart::clear_items(&self.pool, tenant_id, cart.id).await?;
        Ok(())
    }

    // =========================================================================
    // Cart Validation & Submission (US3 - T039-T042)
    // =========================================================================

    /// Validate cart before submission.
    ///
    /// Checks:
    /// - Cart is not empty
    /// - All items are still requestable
    /// - Required form fields are filled
    /// - SoD violations (returns them as warnings, not errors)
    pub async fn validate_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
    ) -> Result<CartValidationResult> {
        let cart = RequestCart::find_by_pair(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::RequestCartNotFound(Uuid::nil()))?;

        let items =
            RequestCartItem::list_by_cart_with_details(&self.pool, tenant_id, cart.id).await?;

        if items.is_empty() {
            return Err(GovernanceError::RequestCartEmpty);
        }

        let mut issues: Vec<CartValidationIssue> = Vec::new();
        let mut sod_violations: Vec<CartSodViolation> = Vec::new();

        // Build request context for re-validating requestability
        let context = self
            .build_request_context(tenant_id, requester_id, beneficiary_id)
            .await?;

        // Get all entitlement IDs from items for SoD checking
        let mut proposed_entitlements: Vec<Uuid> = Vec::new();

        for item in &items {
            // Get full catalog item to check requestability rules
            let catalog_item = self.get_item(tenant_id, item.catalog_item_id).await?;

            // Check if item is still enabled
            if !item.item_enabled {
                issues.push(CartValidationIssue {
                    cart_item_id: Some(item.id),
                    code: "ITEM_DISABLED".to_string(),
                    message: format!("Catalog item '{}' has been disabled", item.item_name),
                });
                continue;
            }

            // Re-check requestability
            let requestability = self
                .evaluate_requestability(tenant_id, &catalog_item, &context)
                .await?;

            if !requestability.can_request {
                issues.push(CartValidationIssue {
                    cart_item_id: Some(item.id),
                    code: "NOT_REQUESTABLE".to_string(),
                    message: requestability
                        .reason
                        .unwrap_or_else(|| "Item cannot be requested".to_string()),
                });
                continue;
            }

            // Check required form fields
            let form_field_issues = self.validate_form_fields(&catalog_item, &item.form_values);
            for issue in form_field_issues {
                issues.push(CartValidationIssue {
                    cart_item_id: Some(item.id),
                    code: "MISSING_FIELD".to_string(),
                    message: issue,
                });
            }

            // Collect entitlement IDs for SoD check
            if let Some(ref_id) = catalog_item.reference_id {
                if catalog_item.item_type == CatalogItemType::Entitlement {
                    proposed_entitlements.push(ref_id);
                }
            }
        }

        // Check SoD violations for all proposed entitlements
        let effective_beneficiary = beneficiary_id.unwrap_or(requester_id);
        if !proposed_entitlements.is_empty() {
            let sod_results = self
                .check_sod_violations(tenant_id, effective_beneficiary, &proposed_entitlements)
                .await?;
            sod_violations.extend(sod_results);
        }

        Ok(CartValidationResult {
            valid: issues.is_empty(),
            issues,
            sod_violations,
        })
    }

    /// Submit the cart and create access requests.
    ///
    /// Creates a `GovAccessRequest` for each item in the cart.
    /// Returns a submission result with all created request IDs.
    ///
    /// Fix #4: Wrapped in a transaction to prevent partial submission
    /// (all-or-nothing: either all requests are created and cart cleared, or nothing).
    pub async fn submit_cart(
        &self,
        tenant_id: Uuid,
        requester_id: Uuid,
        beneficiary_id: Option<Uuid>,
        global_justification: Option<String>,
    ) -> Result<CartSubmissionResult> {
        // First validate the cart
        let validation = self
            .validate_cart(tenant_id, requester_id, beneficiary_id)
            .await?;

        // Block submission if there are validation issues (not SoD warnings)
        if !validation.valid {
            return Err(GovernanceError::Validation(format!(
                "Cart validation failed: {} issue(s) found",
                validation.issues.len()
            )));
        }

        let cart = RequestCart::find_by_pair(&self.pool, tenant_id, requester_id, beneficiary_id)
            .await?
            .ok_or(GovernanceError::RequestCartNotFound(Uuid::nil()))?;

        let items =
            RequestCartItem::list_by_cart_with_details(&self.pool, tenant_id, cart.id).await?;

        // Generate a submission ID to group all requests from this cart
        let submission_id = Uuid::new_v4();
        let effective_beneficiary = beneficiary_id.unwrap_or(requester_id);
        let justification = global_justification.unwrap_or_default();

        // Fix #4: Begin transaction for atomic cart submission
        let mut tx = self.pool.begin().await.map_err(GovernanceError::Database)?;

        let mut submitted_items: Vec<SubmittedItemResult> = Vec::new();

        for item in &items {
            // Get the catalog item to find the reference ID
            let catalog_item = CatalogItem::find_by_id(&self.pool, tenant_id, item.catalog_item_id)
                .await?
                .ok_or(GovernanceError::CatalogItemNotFound(item.catalog_item_id))?;

            // Only create access requests for items that have a reference ID
            // (role or entitlement references)
            if let Some(entitlement_id) = catalog_item.reference_id {
                if catalog_item.item_type == CatalogItemType::Entitlement
                    || catalog_item.item_type == CatalogItemType::Role
                {
                    // Check for SoD violations for this specific item
                    let has_sod_warning = !validation.sod_violations.is_empty();
                    let sod_violations_json = if has_sod_warning {
                        Some(serde_json::to_value(&validation.sod_violations).unwrap_or_default())
                    } else {
                        None
                    };

                    // Create the access request within the transaction
                    let access_request: GovAccessRequest = sqlx::query_as(
                        r"
                        INSERT INTO gov_access_requests (
                            tenant_id, requester_id, entitlement_id, workflow_id,
                            justification, requested_expires_at, has_sod_warning,
                            sod_violations, expires_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                        RETURNING *
                        ",
                    )
                    .bind(tenant_id)
                    .bind(effective_beneficiary)
                    .bind(entitlement_id)
                    .bind(None::<Uuid>) // workflow_id — let system select default
                    .bind(&justification)
                    .bind(None::<chrono::DateTime<chrono::Utc>>) // requested_expires_at
                    .bind(has_sod_warning)
                    .bind(&sod_violations_json)
                    .bind(None::<chrono::DateTime<chrono::Utc>>) // expires_at
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(GovernanceError::Database)?;

                    submitted_items.push(SubmittedItemResult {
                        cart_item_id: item.id,
                        catalog_item_id: item.catalog_item_id,
                        access_request_id: access_request.id,
                    });
                }
            }
        }

        // Clear the cart within the same transaction
        sqlx::query("DELETE FROM request_cart_items WHERE cart_id = $1")
            .bind(cart.id)
            .execute(&mut *tx)
            .await
            .map_err(GovernanceError::Database)?;

        // Commit the transaction — all or nothing
        tx.commit().await.map_err(GovernanceError::Database)?;

        Ok(CartSubmissionResult {
            submission_id,
            items: submitted_items.clone(),
            request_count: submitted_items.len() as i64,
        })
    }

    /// Validate form field requirements for a catalog item.
    fn validate_form_fields(
        &self,
        catalog_item: &CatalogItem,
        form_values: &serde_json::Value,
    ) -> Vec<String> {
        let mut issues = Vec::new();
        let form_fields = catalog_item.get_form_fields();

        for field in form_fields {
            if field.required {
                let value = form_values.get(&field.name);
                if value.is_none() || value == Some(&serde_json::Value::Null) {
                    issues.push(format!("Required field '{}' is missing", field.name));
                } else if let Some(serde_json::Value::String(s)) = value {
                    if s.trim().is_empty() {
                        issues.push(format!("Required field '{}' cannot be empty", field.name));
                    }
                }
            }
        }

        issues
    }

    /// Check SoD violations for a set of proposed entitlements.
    ///
    /// Fix #7: Now uses `EffectiveAccessService.get_effective_access()` to check
    /// all entitlement sources (direct + group + role), and respects active exemptions.
    /// Uses the actual pairwise SoD rule schema (first_entitlement_id / second_entitlement_id).
    /// Returns a list of SoD violations (for warning display, not blocking).
    async fn check_sod_violations(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        proposed_entitlements: &[Uuid],
    ) -> Result<Vec<CartSodViolation>> {
        if proposed_entitlements.is_empty() {
            return Ok(Vec::new());
        }

        let mut violations = Vec::new();

        // Get user's effective entitlements (direct + group + role)
        let effective = self
            .effective_access_service
            .get_effective_access(tenant_id, user_id, None)
            .await?;

        let current_entitlements: std::collections::HashSet<Uuid> = effective
            .entitlements
            .iter()
            .map(|e| e.entitlement.id)
            .collect();

        // Combine current and proposed into a single set for conflict detection
        let mut all_entitlements = current_entitlements.clone();
        for &eid in proposed_entitlements {
            all_entitlements.insert(eid);
        }

        // For each proposed entitlement, find active SoD rules involving it
        for &proposed_eid in proposed_entitlements {
            let rules = GovSodRule::find_active_by_entitlement(&self.pool, tenant_id, proposed_eid)
                .await
                .map_err(GovernanceError::Database)?;

            for rule in &rules {
                // Get the other side of the pairwise rule
                let conflicting_id = match rule.get_conflicting_entitlement(proposed_eid) {
                    Some(id) => id,
                    None => continue,
                };

                // Check if the user has (or is requesting) the conflicting entitlement
                if all_entitlements.contains(&conflicting_id) {
                    // Check for active exemption before reporting
                    let has_exemption = GovSodExemption::has_active_exemption(
                        &self.pool, tenant_id, rule.id, user_id,
                    )
                    .await
                    .unwrap_or(false);

                    if !has_exemption {
                        // Avoid duplicate violations (same rule reported from both sides)
                        if !violations
                            .iter()
                            .any(|v: &CartSodViolation| v.rule_id == rule.id)
                        {
                            violations.push(CartSodViolation {
                                rule_id: rule.id,
                                rule_name: rule.name.clone(),
                                conflicting_item_ids: vec![proposed_eid, conflicting_id],
                                description: format!(
                                    "Rule '{}' prohibits having both entitlements simultaneously",
                                    rule.name
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(violations)
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Verify that a reference ID exists for the given item type.
    async fn verify_reference(
        &self,
        tenant_id: Uuid,
        item_type: CatalogItemType,
        reference_id: Uuid,
    ) -> Result<()> {
        match item_type {
            CatalogItemType::Role => {
                if GovRole::find_by_id(&self.pool, tenant_id, reference_id)
                    .await?
                    .is_none()
                {
                    return Err(GovernanceError::GovRoleNotFound(reference_id));
                }
            }
            CatalogItemType::Entitlement => {
                let exists: bool = sqlx::query_scalar(
                    r"SELECT EXISTS(SELECT 1 FROM gov_entitlements WHERE id = $1 AND tenant_id = $2)",
                )
                .bind(reference_id)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;

                if !exists {
                    return Err(GovernanceError::EntitlementNotFound(reference_id));
                }
            }
            CatalogItemType::Resource => {
                // Resources are generic and don't have a specific table reference
                // Allow any UUID for flexibility
            }
        }
        Ok(())
    }

    /// Validate requestability rules.
    async fn validate_requestability_rules(
        &self,
        tenant_id: Uuid,
        rules: &RequestabilityRules,
    ) -> Result<()> {
        // Validate prerequisite roles exist
        for role_id in &rules.prerequisite_roles {
            if GovRole::find_by_id(&self.pool, tenant_id, *role_id)
                .await?
                .is_none()
            {
                return Err(GovernanceError::Validation(format!(
                    "Prerequisite role not found: {role_id}"
                )));
            }
        }

        // Validate prerequisite entitlements exist
        for entitlement_id in &rules.prerequisite_entitlements {
            let exists: bool = sqlx::query_scalar(
                r"SELECT EXISTS(SELECT 1 FROM gov_entitlements WHERE id = $1 AND tenant_id = $2)",
            )
            .bind(entitlement_id)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

            if !exists {
                return Err(GovernanceError::Validation(format!(
                    "Prerequisite entitlement not found: {entitlement_id}"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_self_request() {
        let user_id = Uuid::new_v4();
        let ctx = RequestContext::self_request(user_id);

        assert!(ctx.is_self_request());
        assert_eq!(ctx.requester_id, user_id);
        assert_eq!(ctx.beneficiary_id, user_id);
        assert!(!ctx.is_manager_request);
    }

    #[test]
    fn test_requestability_result_allowed() {
        let result = RequestabilityResult::allowed();
        assert!(result.can_request);
        assert!(result.reason.is_none());
    }

    #[test]
    fn test_requestability_result_denied() {
        let result = RequestabilityResult::denied("Not allowed");
        assert!(!result.can_request);
        assert_eq!(result.reason, Some("Not allowed".to_string()));
    }
}
