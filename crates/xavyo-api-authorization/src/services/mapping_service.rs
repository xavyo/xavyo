//! Mapping service for entitlement-action mapping CRUD (F083).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_authorization::MappingCache;
use xavyo_db::models::{CreateEntitlementActionMapping, EntitlementActionMapping};

use crate::error::{ApiAuthorizationError, ApiResult};
use crate::models::mapping::{
    CreateMappingRequest, ListMappingsQuery, MappingListResponse, MappingResponse,
};

/// Service for managing entitlement-action mappings.
pub struct MappingService {
    pool: PgPool,
    mapping_cache: std::sync::Arc<MappingCache>,
}

impl MappingService {
    /// Create a new mapping service.
    pub fn new(pool: PgPool, mapping_cache: std::sync::Arc<MappingCache>) -> Self {
        Self {
            pool,
            mapping_cache,
        }
    }

    /// Create a new entitlement-action mapping.
    pub async fn create_mapping(
        &self,
        tenant_id: Uuid,
        input: CreateMappingRequest,
        created_by: Uuid,
    ) -> ApiResult<MappingResponse> {
        // Validate input
        if input.action.trim().is_empty() {
            return Err(ApiAuthorizationError::Validation(
                "Action cannot be empty".to_string(),
            ));
        }
        if input.resource_type.trim().is_empty() {
            return Err(ApiAuthorizationError::Validation(
                "Resource type cannot be empty".to_string(),
            ));
        }

        let create_input = CreateEntitlementActionMapping {
            entitlement_id: input.entitlement_id,
            action: input.action,
            resource_type: input.resource_type,
            created_by: Some(created_by),
        };

        let mapping = EntitlementActionMapping::create(&self.pool, tenant_id, create_input)
            .await
            .map_err(|e| {
                // Check for unique constraint violation
                if let sqlx::Error::Database(ref db_err) = e {
                    if db_err.constraint().is_some() {
                        return ApiAuthorizationError::Conflict(
                            "A mapping with this entitlement, action, and resource type already exists".to_string(),
                        );
                    }
                }
                ApiAuthorizationError::Database(e)
            })?;

        // Invalidate cache
        self.mapping_cache.invalidate(tenant_id).await;

        Ok(MappingResponse::from(mapping))
    }

    /// List mappings with optional filters and pagination.
    pub async fn list_mappings(
        &self,
        tenant_id: Uuid,
        query: ListMappingsQuery,
    ) -> ApiResult<MappingListResponse> {
        let limit = query.limit.min(100);
        let offset = query.offset;

        let mappings = if let Some(entitlement_id) = query.entitlement_id {
            // Filter by entitlement - get all and apply pagination manually
            let all = EntitlementActionMapping::find_by_entitlement(
                &self.pool,
                tenant_id,
                entitlement_id,
            )
            .await?;
            let total = all.len() as i64;
            let items: Vec<MappingResponse> = all
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .map(MappingResponse::from)
                .collect();
            return Ok(MappingListResponse {
                items,
                total,
                limit,
                offset,
            });
        } else {
            EntitlementActionMapping::list_by_tenant(&self.pool, tenant_id, limit, offset).await?
        };

        let total = EntitlementActionMapping::count_by_tenant(&self.pool, tenant_id).await?;

        let items = mappings.into_iter().map(MappingResponse::from).collect();

        Ok(MappingListResponse {
            items,
            total,
            limit,
            offset,
        })
    }

    /// Get a single mapping by ID.
    pub async fn get_mapping(&self, tenant_id: Uuid, id: Uuid) -> ApiResult<MappingResponse> {
        let mapping = EntitlementActionMapping::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or_else(|| ApiAuthorizationError::NotFound(format!("Mapping not found: {}", id)))?;

        Ok(MappingResponse::from(mapping))
    }

    /// Delete a mapping by ID.
    pub async fn delete_mapping(&self, tenant_id: Uuid, id: Uuid) -> ApiResult<()> {
        let deleted = EntitlementActionMapping::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(ApiAuthorizationError::NotFound(format!(
                "Mapping not found: {}",
                id
            )));
        }

        // Invalidate cache
        self.mapping_cache.invalidate(tenant_id).await;

        Ok(())
    }
}
