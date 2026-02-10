//! Admin audit handlers for tenant-wide login attempt queries.

use crate::error::ApiAuthError;
use crate::models::{
    AdminLoginAttemptsQuery, AdminLoginAttemptsResponse, LoginAttemptResponse,
    LoginAttemptStatsQuery, LoginAttemptStatsResponse,
};
use crate::services::AuditService;
use axum::{extract::Query, Extension, Json};
use std::sync::Arc;
use xavyo_core::TenantId;

/// GET /admin/audit/login-attempts
///
/// Returns paginated login attempts for the entire tenant (admin only).
#[utoipa::path(
    get,
    path = "/admin/audit/login-attempts",
    params(AdminLoginAttemptsQuery),
    responses(
        (status = 200, description = "Login attempts retrieved", body = AdminLoginAttemptsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Audit"
)]
pub async fn get_admin_login_attempts(
    Extension(audit_service): Extension<Arc<AuditService>>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<AdminLoginAttemptsQuery>,
) -> Result<Json<AdminLoginAttemptsResponse>, ApiAuthError> {
    // Clamp limit to valid range
    let limit = query.limit.clamp(1, 100);

    let (attempts, total) = audit_service
        .get_tenant_login_attempts(
            *tenant_id.as_uuid(),
            query.user_id,
            query.email.as_deref(),
            query.success,
            query.auth_method.as_deref(),
            query.start_date,
            query.end_date,
            query.cursor,
            limit,
        )
        .await?;

    // Calculate next cursor if there are more results
    let next_cursor = if attempts.len() as i32 == limit && !attempts.is_empty() {
        attempts.last().map(|a| a.created_at)
    } else {
        None
    };

    let items: Vec<LoginAttemptResponse> = attempts.into_iter().map(Into::into).collect();

    Ok(Json(AdminLoginAttemptsResponse {
        items,
        total,
        next_cursor,
    }))
}

/// GET /admin/audit/login-attempts/stats
///
/// Returns aggregated statistics for login attempts in the tenant.
#[utoipa::path(
    get,
    path = "/admin/audit/login-attempts/stats",
    params(LoginAttemptStatsQuery),
    responses(
        (status = 200, description = "Login attempt statistics", body = LoginAttemptStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    ),
    tag = "Audit"
)]
pub async fn get_login_attempt_stats(
    Extension(audit_service): Extension<Arc<AuditService>>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<LoginAttemptStatsQuery>,
) -> Result<Json<LoginAttemptStatsResponse>, ApiAuthError> {
    let stats = audit_service
        .get_login_attempt_stats(*tenant_id.as_uuid(), query.start_date, query.end_date)
        .await?;

    Ok(Json(stats.into()))
}
