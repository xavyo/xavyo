//! Handlers for API key management.
//!
//! F-KEY-ROTATE: These endpoints allow tenants to manage and rotate their API keys.
//! F-049: API key creation endpoint for self-service key generation.
//! F-054: API key usage statistics endpoint for monitoring and quota management.
//! F-055: API key introspection endpoint for viewing key metadata and scopes.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    AdminAction, AdminAuditLog, AdminResourceType, ApiKey, ApiKeyUsage, ApiKeyUsageDaily,
    ApiKeyUsageHourly, CreateApiKey, CreateAuditLogEntry,
};

// Note: AdminAction::Read doesn't exist, so we skip audit logging for read-only usage queries.

use crate::error::TenantError;
use crate::models::get_scope_info;
use crate::models::{
    ApiKeyInfo, ApiKeyListResponse, ApiKeyUsageDailyEntry, ApiKeyUsageHourlyEntry,
    ApiKeyUsageResponse, ApiKeyUsageSummary, CreateApiKeyRequest, CreateApiKeyResponse,
    GetApiKeyUsageQuery, IntrospectApiKeyResponse, RotateApiKeyRequest, RotateApiKeyResponse,
};
use crate::router::TenantAppState;
use crate::services::ApiKeyService;

// ============================================================================
// F-049: API Key Creation Endpoint
// ============================================================================

/// POST /tenants/{tenant_id}/api-keys
///
/// Create a new API key for the specified tenant.
///
/// The plaintext API key is returned ONLY ONCE in the response - it cannot be
/// retrieved later. The key is stored as a SHA-256 hash.
///
/// ## Authorization
/// - Tenant users can create keys for their own tenant only
#[utoipa::path(
    post,
    path = "/tenants/{tenant_id}/api-keys",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID to create the key for")
    ),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created successfully", body = CreateApiKeyResponse),
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - user cannot create keys for this tenant", body = ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_api_key_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path(tenant_id): Path<Uuid>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(axum::http::StatusCode, Json<CreateApiKeyResponse>), TenantError> {
    // Validate the request
    if let Some(error) = request.validate() {
        return Err(TenantError::Validation(error));
    }

    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "You don't have access to create API keys for this tenant".to_string(),
        ));
    }

    // Get the user ID from claims
    let user_id = claims
        .sub
        .parse::<Uuid>()
        .map_err(|_| TenantError::Unauthorized("Invalid user ID in claims".to_string()))?;

    // Generate the new API key
    let api_key_service = ApiKeyService::new();
    let (plaintext_key, key_hash, key_prefix) = api_key_service.create_key_pair();

    // Create the API key in the database
    let new_key_data = CreateApiKey {
        tenant_id,
        user_id,
        name: request.name.clone(),
        key_prefix: key_prefix.clone(),
        key_hash,
        scopes: request.scopes.clone(),
        expires_at: request.expires_at,
    };

    let new_key = ApiKey::create(&state.pool, new_key_data)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Create audit log entry
    let _ = AdminAuditLog::create(
        &state.pool,
        CreateAuditLogEntry {
            tenant_id,
            admin_user_id: user_id,
            action: AdminAction::Create,
            resource_type: AdminResourceType::ApiKey,
            resource_id: Some(new_key.id),
            old_value: None,
            new_value: Some(serde_json::json!({
                "key_id": new_key.id,
                "name": request.name,
                "key_prefix": key_prefix,
                "scopes": request.scopes,
                "expires_at": request.expires_at,
            })),
            ip_address: None,
            user_agent: None,
        },
    )
    .await;

    tracing::info!(
        tenant_id = %tenant_id,
        key_id = %new_key.id,
        user_id = %user_id,
        key_name = %request.name,
        "API key created"
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            id: new_key.id,
            name: new_key.name,
            key_prefix: new_key.key_prefix,
            api_key: plaintext_key, // Shown only once!
            scopes: new_key.scopes,
            expires_at: new_key.expires_at,
            created_at: new_key.created_at,
        }),
    ))
}

// ============================================================================
// F-KEY-ROTATE: API Key Rotation Endpoint (existing)
// ============================================================================

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
        (status = 400, description = "Validation error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
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

    if caller_tenant_id != tenant_id {
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
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("API key {key_id} not found")))?;

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
        (status = 403, description = "Forbidden", body = ErrorResponse),
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

    if caller_tenant_id != tenant_id {
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
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
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

    if caller_tenant_id != tenant_id {
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
        .ok_or_else(|| TenantError::NotFoundWithMessage(format!("API key {key_id} not found")))?;

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

// ============================================================================
// F-054: API Key Usage Statistics Endpoint
// ============================================================================

/// GET /tenants/{tenant_id}/api-keys/{key_id}/usage
///
/// Retrieve usage statistics for a specific API key.
///
/// Returns request counts, error rates, and optionally time-series data
/// based on the granularity parameter.
///
/// ## Authorization
/// - Tenant users can view usage for API keys in their own tenant only
#[utoipa::path(
    get,
    path = "/tenants/{tenant_id}/api-keys/{key_id}/usage",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
        ("key_id" = Uuid, Path, description = "API Key ID"),
        ("start_date" = Option<String>, Query, description = "Start date (YYYY-MM-DD)"),
        ("end_date" = Option<String>, Query, description = "End date (YYYY-MM-DD)"),
        ("granularity" = Option<String>, Query, description = "Level of detail: summary, hourly, or daily")
    ),
    responses(
        (status = 200, description = "Usage statistics retrieved", body = ApiKeyUsageResponse),
        (status = 400, description = "Invalid query parameters", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Access denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("bearerAuth" = []),
        ("apiKeyAuth" = [])
    )
)]
pub async fn get_api_key_usage_handler(
    State(state): State<TenantAppState>,
    Extension(claims): Extension<JwtClaims>,
    Path((tenant_id, key_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<GetApiKeyUsageQuery>,
) -> Result<Json<ApiKeyUsageResponse>, TenantError> {
    // Validate query parameters
    if let Some(error) = query.validate() {
        return Err(TenantError::Validation(error));
    }

    // Verify caller has access to this tenant
    let caller_tenant_id = claims
        .tid
        .ok_or_else(|| TenantError::Unauthorized("JWT claims missing tenant_id".to_string()))?;

    if caller_tenant_id != tenant_id {
        return Err(TenantError::Forbidden(
            "Access denied to this tenant's resources".to_string(),
        ));
    }

    // Verify the API key exists
    let api_key = ApiKey::find_by_id(&state.pool, tenant_id, key_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?
        .ok_or_else(|| TenantError::NotFoundWithMessage("API key not found".to_string()))?;

    // Get usage statistics
    let usage = ApiKeyUsage::get_by_key_id(&state.pool, key_id, tenant_id)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

    // Build the summary
    let summary = if let Some(ref u) = usage {
        ApiKeyUsageSummary {
            total_requests: u.total_requests,
            success_count: u.success_count,
            client_error_count: u.client_error_count,
            server_error_count: u.server_error_count,
            error_rate: ApiKeyUsageSummary::calculate_error_rate(
                u.total_requests,
                u.client_error_count,
                u.server_error_count,
            ),
            first_used_at: u.first_used_at,
            last_used_at: u.last_used_at,
        }
    } else {
        // No usage record yet - key has never been used
        ApiKeyUsageSummary {
            total_requests: 0,
            success_count: 0,
            client_error_count: 0,
            server_error_count: 0,
            error_rate: 0.0,
            first_used_at: None,
            last_used_at: None,
        }
    };

    // Get time-series data based on granularity
    let granularity = query.granularity.as_deref().unwrap_or("summary");

    let hourly = if granularity == "hourly" {
        let hourly_data = ApiKeyUsageHourly::get_range(
            &state.pool,
            key_id,
            tenant_id,
            query.start_date,
            query.end_date,
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        Some(
            hourly_data
                .into_iter()
                .map(|h| ApiKeyUsageHourlyEntry {
                    hour: h.hour,
                    request_count: h.request_count,
                    success_count: h.success_count,
                    client_error_count: h.client_error_count,
                    server_error_count: h.server_error_count,
                })
                .collect(),
        )
    } else {
        None
    };

    let daily = if granularity == "daily" {
        let daily_data = ApiKeyUsageDaily::get_range(
            &state.pool,
            key_id,
            tenant_id,
            query.start_date,
            query.end_date,
        )
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        Some(
            daily_data
                .into_iter()
                .map(|d| ApiKeyUsageDailyEntry {
                    date: d.date,
                    request_count: d.request_count,
                    success_count: d.success_count,
                    client_error_count: d.client_error_count,
                    server_error_count: d.server_error_count,
                })
                .collect(),
        )
    } else {
        None
    };

    // Note: Read operations are not audit logged to avoid log noise.
    // Usage queries are idempotent read-only operations.

    tracing::debug!(
        tenant_id = %tenant_id,
        key_id = %key_id,
        granularity = %granularity,
        "API key usage queried"
    );

    Ok(Json(ApiKeyUsageResponse {
        key_id,
        key_name: api_key.name,
        summary,
        hourly,
        daily,
    }))
}

// ============================================================================
// F-055: API Key Introspection Endpoint
// ============================================================================

/// GET /api-keys/introspect
///
/// Introspect the current API key to view its metadata, scopes, and allowed operations.
///
/// This endpoint uses the API key from the Authorization header. No additional
/// parameters are needed - the key introspects itself.
///
/// ## Response
///
/// Returns:
/// - Key metadata (id, name, prefix, timestamps)
/// - Whether the key has full access (empty scopes)
/// - Detailed scope information with descriptions and operations
///
/// ## Authorization
///
/// Requires a valid API key in the Authorization header.
/// The key must be active and not expired.
#[utoipa::path(
    get,
    path = "/api-keys/introspect",
    responses(
        (status = 200, description = "API key introspection successful", body = IntrospectApiKeyResponse),
        (status = 401, description = "Unauthorized - invalid, expired, or revoked API key", body = ErrorResponse),
    ),
    tag = "API Keys",
    security(
        ("apiKeyAuth" = [])
    )
)]
pub async fn introspect_api_key_handler(
    Extension(api_key): Extension<ApiKey>,
) -> Result<Json<IntrospectApiKeyResponse>, TenantError> {
    // The API key is already validated by the api_key_auth_middleware
    // and injected into request extensions

    // Check if key has full access (empty scopes = full access)
    let has_full_access = api_key.scopes.is_empty();

    // Build scope info with descriptions and operations
    let scopes = api_key
        .scopes
        .iter()
        .map(|scope| get_scope_info(scope))
        .collect();

    tracing::debug!(
        key_id = %api_key.id,
        key_name = %api_key.name,
        scopes_count = api_key.scopes.len(),
        has_full_access = has_full_access,
        "API key introspected"
    );

    Ok(Json(IntrospectApiKeyResponse {
        key_id: api_key.id,
        name: api_key.name,
        key_prefix: api_key.key_prefix,
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        is_active: api_key.is_active,
        has_full_access,
        scopes,
    }))
}
