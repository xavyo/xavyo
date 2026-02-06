//! Catalog handlers for Self-Service Request Catalog (F-062).
//!
//! Provides HTTP handlers for browsing, searching, and managing catalog items.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AddToCartRequest, CartItemResponse, CartQuery, CartResponse, CartSubmissionResponse,
    CartValidationResponse, CatalogItemListResponse, CatalogItemResponse, CategoryListResponse,
    CategoryResponse, CreateCatalogItemRequest, CreateCategoryRequest, ListCatalogItemsQuery,
    ListCategoriesQuery, SubmitCartRequest, UpdateCartItemRequest, UpdateCatalogItemRequest,
    UpdateCategoryRequest,
};
use crate::router::GovernanceState;

// =============================================================================
// Category Handlers
// =============================================================================

/// List catalog categories with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/catalog/categories",
    tag = "Governance - Catalog",
    params(ListCategoriesQuery),
    responses(
        (status = 200, description = "List of categories", body = CategoryListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_catalog_categories(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCategoriesQuery>,
) -> ApiResult<Json<CategoryListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Parse parent_id: "null" or empty string means root categories, otherwise parse UUID
    let parent_id_filter = query.parent_id.as_ref().map(|pid| {
        if pid.is_empty() || pid.eq_ignore_ascii_case("null") {
            None // Root categories
        } else {
            Uuid::parse_str(pid).ok()
        }
    });

    let (categories, total) = state
        .catalog_service
        .list_categories(tenant_id, parent_id_filter, query.limit, query.offset)
        .await?;

    Ok(Json(CategoryListResponse {
        items: categories.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get a catalog category by ID.
#[utoipa::path(
    get,
    path = "/governance/catalog/categories/{id}",
    tag = "Governance - Catalog",
    params(
        ("id" = Uuid, Path, description = "Category ID")
    ),
    responses(
        (status = 200, description = "Category details", body = CategoryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Category not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_catalog_category(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CategoryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let category = state.catalog_service.get_category(tenant_id, id).await?;

    Ok(Json(category.into()))
}

// =============================================================================
// Catalog Item Handlers
// =============================================================================

/// List catalog items with filtering, search, and pagination.
#[utoipa::path(
    get,
    path = "/governance/catalog/items",
    tag = "Governance - Catalog",
    params(ListCatalogItemsQuery),
    responses(
        (status = 200, description = "List of catalog items", body = CatalogItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_catalog_items(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCatalogItemsQuery>,
) -> ApiResult<Json<CatalogItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Build request context for requestability evaluation
    let context = state
        .catalog_service
        .build_request_context(tenant_id, user_id, query.beneficiary_id)
        .await?;

    let (items_with_requestability, total) = state
        .catalog_service
        .list_items_with_requestability(
            tenant_id,
            &context,
            query.category_id,
            query.item_type,
            query.search.clone(),
            query.tag.clone(),
            query.limit,
            query.offset,
        )
        .await?;

    let items: Vec<CatalogItemResponse> = items_with_requestability
        .into_iter()
        .map(|(item, requestability)| {
            let mut response: CatalogItemResponse = item.into();
            response.can_request = Some(requestability.can_request);
            response.cannot_request_reason = requestability.reason;
            response
        })
        .collect();

    Ok(Json(CatalogItemListResponse {
        items,
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get a catalog item by ID with requestability check.
#[utoipa::path(
    get,
    path = "/governance/catalog/items/{id}",
    tag = "Governance - Catalog",
    params(
        ("id" = Uuid, Path, description = "Catalog item ID"),
        ("beneficiary_id" = Option<Uuid>, Query, description = "Optional beneficiary ID for manager requests")
    ),
    responses(
        (status = 200, description = "Catalog item details", body = CatalogItemResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<CartQuery>,
) -> ApiResult<Json<CatalogItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Build request context for requestability evaluation
    let context = state
        .catalog_service
        .build_request_context(tenant_id, user_id, query.beneficiary_id)
        .await?;

    let (item, requestability) = state
        .catalog_service
        .get_item_with_requestability(tenant_id, id, &context)
        .await?;

    let mut response: CatalogItemResponse = item.into();
    response.can_request = Some(requestability.can_request);
    response.cannot_request_reason = requestability.reason;

    Ok(Json(response))
}

// =============================================================================
// Admin Category Handlers
// =============================================================================

/// List all catalog categories including those with disabled items (admin).
#[utoipa::path(
    get,
    path = "/governance/admin/catalog/categories",
    tag = "Governance - Catalog Admin",
    params(ListCategoriesQuery),
    responses(
        (status = 200, description = "List of all categories", body = CategoryListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn admin_list_catalog_categories(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCategoriesQuery>,
) -> ApiResult<Json<CategoryListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Parse parent_id: "null" or empty string means root categories, otherwise parse UUID
    let parent_id_filter = query.parent_id.as_ref().map(|pid| {
        if pid.is_empty() || pid.eq_ignore_ascii_case("null") {
            None // Root categories
        } else {
            Uuid::parse_str(pid).ok()
        }
    });

    let (categories, total) = state
        .catalog_service
        .list_categories(tenant_id, parent_id_filter, query.limit, query.offset)
        .await?;

    Ok(Json(CategoryListResponse {
        items: categories.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Create a new catalog category (admin).
#[utoipa::path(
    post,
    path = "/governance/admin/catalog/categories",
    tag = "Governance - Catalog Admin",
    request_body = CreateCategoryRequest,
    responses(
        (status = 201, description = "Category created", body = CategoryResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Category name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_catalog_category(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateCategoryRequest>,
) -> ApiResult<(StatusCode, Json<CategoryResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = xavyo_db::models::CreateCatalogCategory {
        name: request.name,
        description: request.description,
        parent_id: request.parent_id,
        icon: request.icon,
        display_order: request.display_order,
    };

    let category = state
        .catalog_service
        .create_category(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(category.into())))
}

/// Update a catalog category (admin).
#[utoipa::path(
    put,
    path = "/governance/admin/catalog/categories/{id}",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Category ID")
    ),
    request_body = UpdateCategoryRequest,
    responses(
        (status = 200, description = "Category updated", body = CategoryResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Category not found"),
        (status = 409, description = "Category name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_catalog_category(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCategoryRequest>,
) -> ApiResult<Json<CategoryResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = xavyo_db::models::UpdateCatalogCategory {
        name: request.name,
        description: request.description,
        parent_id: request.parent_id,
        icon: request.icon,
        display_order: request.display_order,
    };

    let category = state
        .catalog_service
        .update_category(tenant_id, id, input)
        .await?;

    Ok(Json(category.into()))
}

/// Delete a catalog category (admin).
#[utoipa::path(
    delete,
    path = "/governance/admin/catalog/categories/{id}",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Category ID")
    ),
    responses(
        (status = 204, description = "Category deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Category not found"),
        (status = 409, description = "Category has children or items"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_catalog_category(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.catalog_service.delete_category(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Admin Item Handlers
// =============================================================================

/// List all catalog items including disabled (admin).
#[utoipa::path(
    get,
    path = "/governance/admin/catalog/items",
    tag = "Governance - Catalog Admin",
    params(ListCatalogItemsQuery),
    responses(
        (status = 200, description = "List of all catalog items", body = CatalogItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn admin_list_catalog_items(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCatalogItemsQuery>,
) -> ApiResult<Json<CatalogItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (items, total) = state
        .catalog_service
        .admin_list_items(
            tenant_id,
            query.category_id,
            query.item_type,
            query.enabled,
            query.search,
            query.tag,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(CatalogItemListResponse {
        items: items.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Create a new catalog item (admin).
#[utoipa::path(
    post,
    path = "/governance/admin/catalog/items",
    tag = "Governance - Catalog Admin",
    request_body = CreateCatalogItemRequest,
    responses(
        (status = 201, description = "Item created", body = CatalogItemResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Category or reference not found"),
        (status = 409, description = "Item name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateCatalogItemRequest>,
) -> ApiResult<(StatusCode, Json<CatalogItemResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = xavyo_db::models::CreateCatalogItem {
        category_id: request.category_id,
        item_type: request.item_type,
        name: request.name,
        description: request.description,
        reference_id: request.reference_id,
        requestability_rules: request.requestability_rules,
        form_fields: request.form_fields,
        tags: request.tags,
        icon: request.icon,
    };

    let item = state.catalog_service.create_item(tenant_id, input).await?;

    Ok((StatusCode::CREATED, Json(item.into())))
}

/// Update a catalog item (admin).
#[utoipa::path(
    put,
    path = "/governance/admin/catalog/items/{id}",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    request_body = UpdateCatalogItemRequest,
    responses(
        (status = 200, description = "Item updated", body = CatalogItemResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 409, description = "Item name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateCatalogItemRequest>,
) -> ApiResult<Json<CatalogItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = xavyo_db::models::UpdateCatalogItem {
        category_id: request.category_id,
        name: request.name,
        description: request.description,
        requestability_rules: request.requestability_rules,
        form_fields: request.form_fields,
        tags: request.tags,
        icon: request.icon,
    };

    let item = state
        .catalog_service
        .update_item(tenant_id, id, input)
        .await?;

    Ok(Json(item.into()))
}

/// Disable a catalog item (admin).
#[utoipa::path(
    post,
    path = "/governance/admin/catalog/items/{id}/disable",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    responses(
        (status = 200, description = "Item disabled", body = CatalogItemResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CatalogItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let item = state.catalog_service.disable_item(tenant_id, id).await?;

    Ok(Json(item.into()))
}

/// Enable a catalog item (admin).
#[utoipa::path(
    post,
    path = "/governance/admin/catalog/items/{id}/enable",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    responses(
        (status = 200, description = "Item enabled", body = CatalogItemResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CatalogItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let item = state.catalog_service.enable_item(tenant_id, id).await?;

    Ok(Json(item.into()))
}

/// Delete a catalog item (admin).
#[utoipa::path(
    delete,
    path = "/governance/admin/catalog/items/{id}",
    tag = "Governance - Catalog Admin",
    params(
        ("id" = Uuid, Path, description = "Item ID")
    ),
    responses(
        (status = 204, description = "Item deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Item not found"),
        (status = 409, description = "Item is referenced in carts"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_catalog_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state.catalog_service.delete_item(tenant_id, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Cart Handlers (US2)
// =============================================================================

/// Get the current user's cart.
#[utoipa::path(
    get,
    path = "/governance/catalog/cart",
    tag = "Governance - Catalog Cart",
    params(CartQuery),
    responses(
        (status = 200, description = "Cart contents", body = CartResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<CartQuery>,
) -> ApiResult<Json<CartResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let (cart, items) = state
        .catalog_service
        .get_cart_with_items(tenant_id, user_id, query.beneficiary_id)
        .await?;

    Ok(Json(CartResponse::from_cart_with_items(cart, items)))
}

/// Add an item to the cart.
#[utoipa::path(
    post,
    path = "/governance/catalog/cart/items",
    tag = "Governance - Catalog Cart",
    request_body = AddToCartRequest,
    responses(
        (status = 201, description = "Item added to cart", body = CartItemResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Catalog item not found"),
        (status = 409, description = "Item already in cart"),
        (status = 422, description = "Item cannot be requested"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_to_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<AddToCartRequest>,
) -> ApiResult<(StatusCode, Json<CartItemResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let cart_item = state
        .catalog_service
        .add_to_cart(
            tenant_id,
            user_id,
            request.beneficiary_id,
            request.catalog_item_id,
            request.parameters,
            request.form_values,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(cart_item.into())))
}

/// Remove an item from the cart.
#[utoipa::path(
    delete,
    path = "/governance/catalog/cart/items/{item_id}",
    tag = "Governance - Catalog Cart",
    params(
        ("item_id" = Uuid, Path, description = "Cart item ID"),
        CartQuery
    ),
    responses(
        (status = 204, description = "Item removed from cart"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Cart item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_from_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(item_id): Path<Uuid>,
    Query(query): Query<CartQuery>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .catalog_service
        .remove_from_cart(tenant_id, user_id, query.beneficiary_id, item_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Update a cart item's parameters or form values.
#[utoipa::path(
    put,
    path = "/governance/catalog/cart/items/{item_id}",
    tag = "Governance - Catalog Cart",
    params(
        ("item_id" = Uuid, Path, description = "Cart item ID")
    ),
    request_body = UpdateCartItemRequest,
    responses(
        (status = 200, description = "Cart item updated", body = CartItemResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Cart item not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_cart_item(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(item_id): Path<Uuid>,
    Query(query): Query<CartQuery>,
    Json(request): Json<UpdateCartItemRequest>,
) -> ApiResult<Json<CartItemResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let cart_item = state
        .catalog_service
        .update_cart_item(
            tenant_id,
            user_id,
            query.beneficiary_id,
            item_id,
            request.parameters,
            request.form_values,
        )
        .await?;

    Ok(Json(cart_item.into()))
}

/// Clear all items from the cart.
#[utoipa::path(
    delete,
    path = "/governance/catalog/cart",
    tag = "Governance - Catalog Cart",
    params(CartQuery),
    responses(
        (status = 204, description = "Cart cleared"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Cart not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn clear_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<CartQuery>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .catalog_service
        .clear_cart(tenant_id, user_id, query.beneficiary_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Cart Validation & Submission Handlers (US3)
// =============================================================================

/// Validate the cart before submission.
#[utoipa::path(
    post,
    path = "/governance/catalog/cart/validate",
    tag = "Governance - Catalog Cart",
    params(CartQuery),
    responses(
        (status = 200, description = "Cart validation result", body = CartValidationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Cart not found"),
        (status = 422, description = "Cart is empty"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<CartQuery>,
) -> ApiResult<Json<CartValidationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .catalog_service
        .validate_cart(tenant_id, user_id, query.beneficiary_id)
        .await?;

    // Convert service types to API response types
    let issues: Vec<crate::models::CartValidationIssue> = result
        .issues
        .into_iter()
        .map(|i| crate::models::CartValidationIssue {
            cart_item_id: i.cart_item_id,
            code: i.code,
            message: i.message,
        })
        .collect();

    let sod_violations: Vec<crate::models::CartSodViolation> = result
        .sod_violations
        .into_iter()
        .map(|v| crate::models::CartSodViolation {
            rule_id: v.rule_id,
            rule_name: v.rule_name,
            conflicting_item_ids: v.conflicting_item_ids,
            description: v.description,
        })
        .collect();

    Ok(Json(CartValidationResponse {
        valid: result.valid,
        issues,
        sod_violations,
    }))
}

/// Submit the cart and create access requests.
#[utoipa::path(
    post,
    path = "/governance/catalog/cart/submit",
    tag = "Governance - Catalog Cart",
    request_body = SubmitCartRequest,
    responses(
        (status = 201, description = "Cart submitted successfully", body = CartSubmissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Cart not found"),
        (status = 422, description = "Cart validation failed"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn submit_cart(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SubmitCartRequest>,
) -> ApiResult<(StatusCode, Json<CartSubmissionResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .catalog_service
        .submit_cart(
            tenant_id,
            user_id,
            request.beneficiary_id,
            request.global_justification,
        )
        .await?;

    // Convert service types to API response types
    let items: Vec<crate::models::SubmittedItemResult> = result
        .items
        .into_iter()
        .map(|i| crate::models::SubmittedItemResult {
            cart_item_id: i.cart_item_id,
            catalog_item_id: i.catalog_item_id,
            access_request_id: i.access_request_id,
        })
        .collect();

    Ok((
        StatusCode::CREATED,
        Json(CartSubmissionResponse {
            submission_id: result.submission_id,
            items,
            request_count: result.request_count,
        }),
    ))
}
