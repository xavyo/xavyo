//! Unit and integration tests for Self-Service Request Catalog (F-062).
//!
//! Tests cover:
//! - US1: Browse catalog items and categories
//! - US2: Cart operations (add, remove, update, clear)
//! - US3: Cart validation and submission
//! - US5: Admin catalog operations

mod common;

use common::*;
use serde_json::json;
use uuid::Uuid;
use xavyo_api_governance::services::{
    CartValidationResult, CatalogService, RequestContext, RequestabilityResult,
};
use xavyo_db::models::{
    AddCartItem, CatalogCategory, CatalogCategoryFilter, CatalogItem, CatalogItemFilter,
    CatalogItemType, CreateCatalogCategory, CreateCatalogItem, RequestCart, RequestCartItem,
    RequestabilityRules, UpdateCatalogCategory, UpdateCatalogItem,
};

// =============================================================================
// Helper functions
// =============================================================================

/// Create a test catalog category.
pub async fn create_test_category(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    name: &str,
    parent_id: Option<Uuid>,
) -> Uuid {
    let category_id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO catalog_categories (id, tenant_id, name, description, parent_id, display_order, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, 0, NOW(), NOW())
        ",
    )
    .bind(category_id)
    .bind(tenant_id)
    .bind(name)
    .bind(format!("Description for {name}"))
    .bind(parent_id)
    .execute(pool)
    .await
    .expect("Failed to create test category");

    category_id
}

/// Create a test catalog item.
pub async fn create_test_catalog_item(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    category_id: Option<Uuid>,
    name: &str,
    item_type: CatalogItemType,
    reference_id: Option<Uuid>,
) -> Uuid {
    let item_id = Uuid::new_v4();
    let rules = RequestabilityRules {
        self_request: true,
        manager_request: true,
        department_restriction: vec![],
        archetype_restriction: vec![],
        prerequisite_roles: vec![],
        prerequisite_entitlements: vec![],
    };

    // Use SQLx native type binding - it handles the enum conversion
    sqlx::query(
        r"
        INSERT INTO catalog_items (id, tenant_id, category_id, item_type, name, description, reference_id, requestability_rules, form_fields, tags, enabled, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '[]'::jsonb, '{}'::text[], true, NOW(), NOW())
        ",
    )
    .bind(item_id)
    .bind(tenant_id)
    .bind(category_id)
    .bind(item_type)  // SQLx handles the enum directly
    .bind(name)
    .bind(format!("Description for {name}"))
    .bind(reference_id)
    .bind(serde_json::to_value(&rules).unwrap())
    .execute(pool)
    .await
    .expect("Failed to create test catalog item");

    item_id
}

/// Create a test catalog item with custom requestability rules.
pub async fn create_test_catalog_item_with_rules(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    category_id: Option<Uuid>,
    name: &str,
    item_type: CatalogItemType,
    reference_id: Option<Uuid>,
    rules: &RequestabilityRules,
) -> Uuid {
    let item_id = Uuid::new_v4();

    // Use SQLx native type binding - it handles the enum conversion
    sqlx::query(
        r"
        INSERT INTO catalog_items (id, tenant_id, category_id, item_type, name, description, reference_id, requestability_rules, form_fields, tags, enabled, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '[]'::jsonb, '{}'::text[], true, NOW(), NOW())
        ",
    )
    .bind(item_id)
    .bind(tenant_id)
    .bind(category_id)
    .bind(item_type)  // SQLx handles the enum directly
    .bind(name)
    .bind(format!("Description for {name}"))
    .bind(reference_id)
    .bind(serde_json::to_value(rules).unwrap())
    .execute(pool)
    .await
    .expect("Failed to create test catalog item");

    item_id
}

/// Clean up catalog test data.
pub async fn cleanup_catalog_data(pool: &sqlx::PgPool, tenant_id: Uuid) {
    // Delete in order of dependencies
    let _ = sqlx::query("DELETE FROM request_cart_items WHERE cart_id IN (SELECT id FROM request_carts WHERE tenant_id = $1)")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM request_carts WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM catalog_items WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM catalog_categories WHERE tenant_id = $1")
        .bind(tenant_id)
        .execute(pool)
        .await;
}

// =============================================================================
// US1: Browse Catalog Tests (T012, T013)
// =============================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_categories_empty() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());
    let (categories, total) = service
        .list_categories(tenant_id, None, 50, 0)
        .await
        .unwrap();

    assert_eq!(categories.len(), 0);
    assert_eq!(total, 0);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_categories_with_data() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    // Create categories
    let cat1 = create_test_category(&pool, tenant_id, "IT Access", None).await;
    let _cat2 = create_test_category(&pool, tenant_id, "Finance Access", None).await;
    let _cat3 = create_test_category(&pool, tenant_id, "Development", Some(cat1)).await;

    let service = CatalogService::new(pool.clone());

    // List all categories
    let (categories, total) = service
        .list_categories(tenant_id, None, 50, 0)
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(categories.len(), 3);

    // List root categories only
    let (root_cats, root_total) = service
        .list_categories(tenant_id, Some(None), 50, 0)
        .await
        .unwrap();
    assert_eq!(root_total, 2);
    assert!(root_cats.iter().all(|c| c.parent_id.is_none()));

    // List children of IT Access
    let (children, child_total) = service
        .list_categories(tenant_id, Some(Some(cat1)), 50, 0)
        .await
        .unwrap();
    assert_eq!(child_total, 1);
    assert!(children.iter().all(|c| c.parent_id == Some(cat1)));

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_category_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());
    let result = service.get_category(tenant_id, Uuid::new_v4()).await;

    assert!(result.is_err());

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_items_empty() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());
    let (items, total) = service
        .list_items(tenant_id, None, None, None, None, true, 50, 0)
        .await
        .unwrap();

    assert_eq!(items.len(), 0);
    assert_eq!(total, 0);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_list_items_with_filtering() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let cat_id = create_test_category(&pool, tenant_id, "Apps", None).await;

    // Create items of different types
    create_test_catalog_item(
        &pool,
        tenant_id,
        Some(cat_id),
        "Developer Role",
        CatalogItemType::Role,
        None,
    )
    .await;
    create_test_catalog_item(
        &pool,
        tenant_id,
        Some(cat_id),
        "Admin Role",
        CatalogItemType::Role,
        None,
    )
    .await;
    create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "VPN Entitlement",
        CatalogItemType::Entitlement,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Filter by category
    let (_items, total) = service
        .list_items(tenant_id, Some(cat_id), None, None, None, true, 50, 0)
        .await
        .unwrap();
    assert_eq!(total, 2);

    // Filter by type
    let (_items, total) = service
        .list_items(
            tenant_id,
            None,
            Some(CatalogItemType::Role),
            None,
            None,
            true,
            50,
            0,
        )
        .await
        .unwrap();
    assert_eq!(total, 2);

    // Search by name
    let (items, total) = service
        .list_items(
            tenant_id,
            None,
            None,
            Some("Developer".to_string()),
            None,
            true,
            50,
            0,
        )
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(items[0].name, "Developer Role");

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_item_not_found() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());
    let result = service.get_item(tenant_id, Uuid::new_v4()).await;

    assert!(result.is_err());

    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_requestability_self_request_allowed() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let rules = RequestabilityRules {
        self_request: true,
        manager_request: false,
        department_restriction: vec![],
        archetype_restriction: vec![],
        prerequisite_roles: vec![],
        prerequisite_entitlements: vec![],
    };

    let item_id = create_test_catalog_item_with_rules(
        &pool,
        tenant_id,
        None,
        "Self Request Item",
        CatalogItemType::Role,
        None,
        &rules,
    )
    .await;

    let service = CatalogService::new(pool.clone());
    let item = service.get_item(tenant_id, item_id).await.unwrap();
    let context = RequestContext::self_request(user_id);

    let result = service
        .evaluate_requestability(tenant_id, &item, &context)
        .await
        .unwrap();

    assert!(result.can_request);
    assert!(result.reason.is_none());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_requestability_self_request_denied() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let rules = RequestabilityRules {
        self_request: false, // Self-request not allowed
        manager_request: true,
        department_restriction: vec![],
        archetype_restriction: vec![],
        prerequisite_roles: vec![],
        prerequisite_entitlements: vec![],
    };

    let item_id = create_test_catalog_item_with_rules(
        &pool,
        tenant_id,
        None,
        "Manager Only Item",
        CatalogItemType::Role,
        None,
        &rules,
    )
    .await;

    let service = CatalogService::new(pool.clone());
    let item = service.get_item(tenant_id, item_id).await.unwrap();
    let context = RequestContext::self_request(user_id);

    let result = service
        .evaluate_requestability(tenant_id, &item, &context)
        .await
        .unwrap();

    assert!(!result.can_request);
    assert!(result.reason.is_some());
    assert!(result.reason.unwrap().contains("Self-request"));

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =============================================================================
// US2: Cart Operations Tests (T024, T025)
// =============================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_get_or_create_cart() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = CatalogService::new(pool.clone());

    // First call creates the cart
    let cart1 = service
        .get_or_create_cart(tenant_id, user_id, None)
        .await
        .unwrap();
    assert_eq!(cart1.requester_id, user_id);
    assert!(cart1.beneficiary_id.is_none());

    // Second call returns the same cart
    let cart2 = service
        .get_or_create_cart(tenant_id, user_id, None)
        .await
        .unwrap();
    assert_eq!(cart1.id, cart2.id);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_to_cart_success() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    let cart_item = service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    assert_eq!(cart_item.catalog_item_id, item_id);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_add_to_cart_duplicate_prevention() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // First add succeeds
    service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Second add with same parameters fails
    let result = service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await;
    assert!(result.is_err());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_remove_from_cart() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add item
    let cart_item = service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Remove item
    service
        .remove_from_cart(tenant_id, user_id, None, cart_item.id)
        .await
        .unwrap();

    // Verify cart is empty
    let (_cart, items) = service
        .get_cart_with_items(tenant_id, user_id, None)
        .await
        .unwrap();
    assert!(items.is_empty());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_cart_item() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add item
    let cart_item = service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Update item
    let new_params = json!({"key": "value"});
    let updated = service
        .update_cart_item(
            tenant_id,
            user_id,
            None,
            cart_item.id,
            Some(new_params.clone()),
            None,
        )
        .await
        .unwrap();

    assert_eq!(updated.parameters, new_params);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_clear_cart() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item1 = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Item 1",
        CatalogItemType::Role,
        None,
    )
    .await;
    let item2 = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Item 2",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add items
    service
        .add_to_cart(tenant_id, user_id, None, item1, json!({}), json!({}))
        .await
        .unwrap();
    service
        .add_to_cart(tenant_id, user_id, None, item2, json!({}), json!({}))
        .await
        .unwrap();

    // Clear cart
    service.clear_cart(tenant_id, user_id, None).await.unwrap();

    // Verify cart is empty
    let (_cart, items) = service
        .get_cart_with_items(tenant_id, user_id, None)
        .await
        .unwrap();
    assert!(items.is_empty());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =============================================================================
// US3: Cart Validation & Submission Tests (T037, T038)
// =============================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validate_cart_empty() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let service = CatalogService::new(pool.clone());

    // Create empty cart
    service
        .get_or_create_cart(tenant_id, user_id, None)
        .await
        .unwrap();

    // Validation should fail
    let result = service.validate_cart(tenant_id, user_id, None).await;
    assert!(result.is_err());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validate_cart_valid() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Valid Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add item to cart
    service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Validate cart
    let result = service
        .validate_cart(tenant_id, user_id, None)
        .await
        .unwrap();

    assert!(result.valid);
    assert!(result.issues.is_empty());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_validate_cart_disabled_item() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add item to cart
    service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Disable the item
    service.disable_item(tenant_id, item_id).await.unwrap();

    // Validate cart - should have issues
    let result = service
        .validate_cart(tenant_id, user_id, None)
        .await
        .unwrap();

    assert!(!result.valid);
    assert!(!result.issues.is_empty());
    assert!(result.issues[0].code == "ITEM_DISABLED");

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_submit_cart_success() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;
    let user_id = create_test_user(&pool, tenant_id).await;
    let app_id = create_test_application(&pool, tenant_id).await;
    let entitlement_id = create_test_entitlement(&pool, tenant_id, app_id, None).await;

    // Create catalog item referencing the entitlement
    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Entitlement Item",
        CatalogItemType::Entitlement,
        Some(entitlement_id),
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Add item to cart
    service
        .add_to_cart(tenant_id, user_id, None, item_id, json!({}), json!({}))
        .await
        .unwrap();

    // Submit cart
    let result = service
        .submit_cart(
            tenant_id,
            user_id,
            None,
            Some("Test justification".to_string()),
        )
        .await
        .unwrap();

    assert_eq!(result.request_count, 1);
    assert!(!result.items.is_empty());

    // Verify cart is cleared after submission
    let (_, items) = service
        .get_cart_with_items(tenant_id, user_id, None)
        .await
        .unwrap();
    assert!(items.is_empty());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =============================================================================
// US5: Admin Operations Tests (T052)
// =============================================================================

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_category() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());

    let input = CreateCatalogCategory {
        name: "IT Access".to_string(),
        description: Some("Access to IT systems".to_string()),
        parent_id: None,
        icon: None,
        display_order: 0,
    };

    let category = service.create_category(tenant_id, input).await.unwrap();

    assert_eq!(category.name, "IT Access");
    assert_eq!(category.tenant_id, tenant_id);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_category_duplicate_name_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());

    let input = CreateCatalogCategory {
        name: "IT Access".to_string(),
        description: None,
        parent_id: None,
        icon: None,
        display_order: 0,
    };

    // First creation succeeds
    service
        .create_category(tenant_id, input.clone())
        .await
        .unwrap();

    // Second creation fails
    let result = service.create_category(tenant_id, input).await;
    assert!(result.is_err());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_update_category() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let category_id = create_test_category(&pool, tenant_id, "Original Name", None).await;

    let service = CatalogService::new(pool.clone());

    let input = UpdateCatalogCategory {
        name: Some("Updated Name".to_string()),
        description: Some("Updated description".to_string()),
        parent_id: None,
        icon: None,
        display_order: None,
    };

    let updated = service
        .update_category(tenant_id, category_id, input)
        .await
        .unwrap();

    assert_eq!(updated.name, "Updated Name");

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_category_success() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let category_id = create_test_category(&pool, tenant_id, "To Delete", None).await;

    let service = CatalogService::new(pool.clone());

    service
        .delete_category(tenant_id, category_id)
        .await
        .unwrap();

    // Verify deleted
    let result = service.get_category(tenant_id, category_id).await;
    assert!(result.is_err());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_delete_category_with_items_fails() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let category_id = create_test_category(&pool, tenant_id, "Category With Items", None).await;
    create_test_catalog_item(
        &pool,
        tenant_id,
        Some(category_id),
        "Item in Category",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    let result = service.delete_category(tenant_id, category_id).await;
    assert!(result.is_err());

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_create_item() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let service = CatalogService::new(pool.clone());

    let rules = RequestabilityRules::default();
    let input = CreateCatalogItem {
        category_id: None,
        item_type: CatalogItemType::Role,
        name: "Developer Role".to_string(),
        description: Some("Access for developers".to_string()),
        reference_id: None,
        requestability_rules: rules,
        form_fields: vec![],
        tags: vec!["developer".to_string()],
        icon: None,
    };

    let item = service.create_item(tenant_id, input).await.unwrap();

    assert_eq!(item.name, "Developer Role");
    assert!(item.enabled);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_disable_enable_item() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let item_id = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Test Item",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Disable
    let disabled = service.disable_item(tenant_id, item_id).await.unwrap();
    assert!(!disabled.enabled);

    // Enable
    let enabled = service.enable_item(tenant_id, item_id).await.unwrap();
    assert!(enabled.enabled);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

#[tokio::test]
#[ignore = "Requires database - run locally with DATABASE_URL"]
async fn test_admin_list_items_includes_disabled() {
    let pool = create_test_pool().await;
    let tenant_id = create_test_tenant(&pool).await;

    let _item1 = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "Enabled Item",
        CatalogItemType::Role,
        None,
    )
    .await;
    let item2 = create_test_catalog_item(
        &pool,
        tenant_id,
        None,
        "To Disable",
        CatalogItemType::Role,
        None,
    )
    .await;

    let service = CatalogService::new(pool.clone());

    // Disable one item
    service.disable_item(tenant_id, item2).await.unwrap();

    // Regular list (enabled only)
    let (_items, total) = service
        .list_items(tenant_id, None, None, None, None, true, 50, 0)
        .await
        .unwrap();
    assert_eq!(total, 1);

    // Admin list (all items)
    let (_all_items, all_total) = service
        .admin_list_items(tenant_id, None, None, None, None, None, 50, 0)
        .await
        .unwrap();
    assert_eq!(all_total, 2);

    cleanup_catalog_data(&pool, tenant_id).await;
    cleanup_test_tenant(&pool, tenant_id).await;
}

// =============================================================================
// Unit Tests (non-database)
// =============================================================================

#[test]
fn test_request_context_self_request() {
    let user_id = Uuid::new_v4();
    let context = RequestContext::self_request(user_id);

    assert!(context.is_self_request());
    assert_eq!(context.requester_id, user_id);
    assert_eq!(context.beneficiary_id, user_id);
    assert!(!context.is_manager_request);
}

#[test]
fn test_request_context_manager_request() {
    let manager_id = Uuid::new_v4();
    let employee_id = Uuid::new_v4();

    let context = RequestContext {
        requester_id: manager_id,
        beneficiary_id: employee_id,
        is_manager_request: true,
        beneficiary_department: Some("Engineering".to_string()),
        beneficiary_archetype: None,
    };

    assert!(!context.is_self_request());
    assert!(context.is_manager_request);
}

#[test]
fn test_requestability_result_allowed() {
    let result = RequestabilityResult::allowed();
    assert!(result.can_request);
    assert!(result.reason.is_none());
}

#[test]
fn test_requestability_result_denied() {
    let result = RequestabilityResult::denied("Not eligible");
    assert!(!result.can_request);
    assert_eq!(result.reason, Some("Not eligible".to_string()));
}

#[test]
fn test_catalog_item_type_variants() {
    // Test that the variants are distinct
    assert_ne!(CatalogItemType::Role, CatalogItemType::Entitlement);
    assert_ne!(CatalogItemType::Entitlement, CatalogItemType::Resource);
    assert_ne!(CatalogItemType::Role, CatalogItemType::Resource);

    // Test that the type can be serialized via serde
    let role_json = serde_json::to_string(&CatalogItemType::Role).unwrap();
    assert_eq!(role_json, "\"role\"");

    let entitlement_json = serde_json::to_string(&CatalogItemType::Entitlement).unwrap();
    assert_eq!(entitlement_json, "\"entitlement\"");

    let resource_json = serde_json::to_string(&CatalogItemType::Resource).unwrap();
    assert_eq!(resource_json, "\"resource\"");
}
