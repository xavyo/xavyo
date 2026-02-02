//! Handlers for API key management.
//!
//! F-KEY-ROTATE: These endpoints allow tenants to manage and rotate their API keys.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::{
    bootstrap::SYSTEM_TENANT_ID,
    models::{
        AdminAction, AdminAuditLog, AdminResourceType, ApiKey, CreateApiKey, CreateAuditLogEntry,
    },
};

use crate::error::TenantError;
use crate::models::{ApiKeyInfo, ApiKeyListResponse, RotateApiKeyRequest, RotateApiKeyResponse};
use crate::router::TenantAppState;
use crate::services::ApiKeyService;

/// POST /tenants/{tenant_id}/api-keys/{key_id}/rotate
///
/// Rotate an API key, generating a new key to replace the old one.
///
/// The new key is returned in plaintext (once only). The old key can optionally
/// be kept active for a grace period before being deactivated.
#[utoipa::path(
    post,
    path = "/tenants/{tenant_id}/api-keys/{key_id}/rotate",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("key_id" = Uuid, Path, description = "API Key ID to rotate")
    ),
    request_body = RotateApiKeyRequest,
    responses(
        (status = 200, description = "API key rotated successfully", body = RotateApiKeyResponse),
        (status = 400, description = "Validation error", body = crate::error::ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = crate::error::ErrorResponse),
        (status = 404, description = "API key not found", body = crate::error::ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn rotate_api_key_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, key_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<RotateApiKeyRequest>,
) -> Result<Json<RotateApiKeyResponse>, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    // Allow system tenant admins or the tenant's own users
    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's API keys".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Find the existing API key
    let old_key = ApiKey::find_by_id(&state.pool, tenant_id, key_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("API key {} not found", key_id)))?;

    if !old_key.is_active {
        return Err(TenantError::Validation(
            "Cannot rotate an inactive API key".to_string(),
        ));
    }

    // Generate the new API key
    let api_key_service = ApiKeyService::new();
    let (plaintext_key, key_hash, key_prefix) = api_key_service.create_key_pair();

    // Determine expiration for new key (inherit from old if not specified)
    let expires_at = request.expires_at.or(old_key.expires_at);

    // Calculate when old key should expire (grace period)
    let grace_period_hours = request.grace_period_hours.unwrap_or(24);
    let old_key_expires = if request.deactivate_old_immediately.unwrap_or(false) {
        None // Will be deactivated immediately
    } else {
        Some(Utc::now() + Duration::hours(grace_period_hours.into()))
    };

    // Create new key name
    let new_name = format!("{} (rotated)", old_key.name);

    let new_key_data = CreateApiKey {
        tenant_id,
        user_id: old_key.user_id,
        name: new_name.clone(),
        key_prefix,
        key_hash,
        scopes: old_key.scopes.clone(),
        expires_at,
    };

    // Create the new key
    let new_key = ApiKey::create(&state.pool, new_key_data)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Handle old key based on request
    let old_key_status = if request.deactivate_old_immediately.unwrap_or(false) {
        ApiKey::deactivate(&state.pool, tenant_id, key_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?;
        "deactivated".to_string()
    } else {
        format!(
            "active until {} (grace period: {} hours)",
            old_key_expires.map(|t| t.to_rfc3339()).unwrap_or_default(),
            grace_period_hours
        )
    };

    // Audit log - note: we don't log the plaintext key, only the key_id
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id,
            action: AdminAction::Update,
            resource_type: AdminResourceType::ApiKey,
            resource_id: Some(key_id),
            old_value: Some(serde_json::json!({
                "key_id": key_id,
                "name": old_key.name,
                "key_prefix": old_key.key_prefix,
            })),
            new_value: Some(serde_json::json!({
                "new_key_id": new_key.id,
                "name": new_name,
                "key_prefix": new_key.key_prefix,
                "old_key_status": old_key_status.clone(),
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        old_key_id = %key_id,
        new_key_id = %new_key.id,
        admin_user_id = %admin_user_id,
        "API key rotated"
    );

    Ok(Json(RotateApiKeyResponse {
        new_key_id: new_key.id,
        new_key_prefix: new_key.key_prefix,
        new_api_key: plaintext_key, // Shown only once!
        old_key_id: key_id,
        old_key_status,
        rotated_at: Utc::now(),
    }))
}

/// GET /tenants/{tenant_id}/api-keys
///
/// List all API keys for a tenant.
#[utoipa::path(
    get,
    path = "/tenants/{tenant_id}/api-keys",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "List of API keys", body = ApiKeyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = crate::error::ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_api_keys_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
) -> Result<Json<ApiKeyListResponse>, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's API keys".to_string(),
        ));
    }

    let keys = ApiKey::list_by_tenant(&state.pool, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    let api_keys: Vec<ApiKeyInfo> = keys
        .into_iter()
        .map(|k| ApiKeyInfo {
            id: k.id,
            name: k.name,
            key_prefix: k.key_prefix,
            scopes: k.scopes,
            is_active: k.is_active,
            last_used_at: k.last_used_at,
            expires_at: k.expires_at,
            created_at: k.created_at,
        })
        .collect();

    let total = api_keys.len();
    Ok(Json(ApiKeyListResponse { api_keys, total }))
}

/// DELETE /tenants/{tenant_id}/api-keys/{key_id}
///
/// Deactivate an API key.
#[utoipa::path(
    delete,
    path = "/tenants/{tenant_id}/api-keys/{key_id}",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("key_id" = Uuid, Path, description = "API Key ID")
    ),
    responses(
        (status = 204, description = "API key deactivated"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = crate::error::ErrorResponse),
        (status = 404, description = "API key not found", body = crate::error::ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn deactivate_api_key_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, key_id)): Path<(Uuid, Uuid)>,
) -> Result<axum::http::StatusCode, TenantError> {
    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != SYSTEM_TENANT_ID && caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to this tenant's API keys".to_string(),
        ));
    }

    let admin_user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Find the existing API key
    let old_key = ApiKey::find_by_id(&state.pool, tenant_id, key_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("API key {} not found", key_id)))?;

    // Deactivate the key
    ApiKey::deactivate(&state.pool, tenant_id, key_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Audit log
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id,
            action: AdminAction::Delete,
            resource_type: AdminResourceType::ApiKey,
            resource_id: Some(key_id),
            old_value: Some(serde_json::json!({
                "key_id": key_id,
                "name": old_key.name,
                "is_active": old_key.is_active,
            })),
            new_value: Some(serde_json::json!({
                "is_active": false,
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        key_id = %key_id,
        admin_user_id = %admin_user_id,
        "API key deactivated"
    );

    Ok(axum::http::StatusCode::NO_CONTENT)
}
