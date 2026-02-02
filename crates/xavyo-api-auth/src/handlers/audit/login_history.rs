//! Login history handler for user audit endpoint.

use crate::error::ApiAuthError;
use crate::models::{LoginAttemptResponse, LoginHistoryQuery, LoginHistoryResponse};
use crate::services::AuditService;
use axum::{extract::Query, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_core::TenantId;

/// GET /audit/login-history
///
/// Returns paginated login history for the authenticated user.
pub async fn get_login_history(
    Extension(audit_service): Extension<Arc<AuditService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<Uuid>,
    Query(query): Query<LoginHistoryQuery>,
) -> Result<Json<LoginHistoryResponse>, ApiAuthError> {
    // Clamp limit to valid range
    let limit = query.limit.clamp(1, 100);

    let (attempts, total) = audit_service
        .get_user_login_history(
            *tenant_id.as_uuid(),
            user_id,
            query.success,
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

    Ok(Json(LoginHistoryResponse {
        items,
        total,
        next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_limit_clamping() {
        let too_low = 0i32.clamp(1, 100);
        assert_eq!(too_low, 1);

        let too_high = 200i32.clamp(1, 100);
        assert_eq!(too_high, 100);

        let valid = 50i32.clamp(1, 100);
        assert_eq!(valid, 50);
    }
}
