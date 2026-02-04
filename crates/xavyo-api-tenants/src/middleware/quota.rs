//! Middleware for enforcing tenant quotas.
//!
//! F-QUOTA-ENFORCE: This middleware checks if a tenant has exceeded their
//! plan limits and rejects requests with 429 Too Many Requests if so.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::bootstrap::SYSTEM_TENANT_ID;

use crate::services::{QuotaCheck, QuotaService, QuotaType};

/// Error response for quota exceeded.
#[derive(Debug, Serialize)]
pub struct QuotaExceededError {
    pub error: String,
    pub message: String,
    pub details: QuotaDetails,
}

/// Details about the exceeded quota.
#[derive(Debug, Serialize)]
pub struct QuotaDetails {
    pub quota_type: QuotaType,
    pub current: i64,
    pub limit: i64,
    pub reset_at: String,
}

/// Middleware function that checks API call quota before processing requests.
///
/// This middleware should be applied to tenant-scoped routes after JWT authentication.
/// It extracts the `tenant_id` from JWT claims and checks the API call quota.
///
/// ## Behavior
///
/// - If no JWT claims present: passes through (let auth middleware handle it)
/// - If `tenant_id` missing in claims: passes through (let other middleware handle it)
/// - If tenant is system tenant: always passes through (system tenant is unlimited)
/// - If tenant has no limit configured: passes through
/// - If quota not exceeded: passes through
/// - If quota exceeded: returns 429 Too Many Requests with quota details
///
/// ## Example
///
/// ```rust,ignore
/// use axum::{middleware, Router};
/// use xavyo_api_tenants::middleware::api_quota_middleware;
///
/// let app = Router::new()
///     .route("/api/resource", get(handler))
///     .layer(middleware::from_fn_with_state(pool, api_quota_middleware));
/// ```
pub async fn api_quota_middleware(
    State(pool): State<PgPool>,
    claims: Option<Extension<JwtClaims>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If no claims, pass through (auth middleware will handle)
    let claims = match claims {
        Some(Extension(c)) => c,
        None => return next.run(request).await,
    };

    // Extract tenant_id from claims
    let tenant_id = match claims.tid {
        Some(tid) => tid,
        None => return next.run(request).await,
    };

    // System tenant is never quota-limited
    if tenant_id == SYSTEM_TENANT_ID {
        return next.run(request).await;
    }

    // Check API call quota
    let quota_service = QuotaService::new(pool);
    match quota_service.check_api_calls(tenant_id).await {
        Ok(check) if check.exceeded => {
            tracing::warn!(
                tenant_id = %tenant_id,
                current = %check.current,
                limit = ?check.limit,
                "Request rejected: API call quota exceeded"
            );
            quota_exceeded_response(check)
        }
        Ok(_) => next.run(request).await,
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                error = %e,
                "Failed to check API call quota"
            );
            // On error, fail open to avoid blocking legitimate requests
            next.run(request).await
        }
    }
}

/// Middleware function that checks agent invocation quota.
///
/// Same behavior as `api_quota_middleware` but checks agent invocation limits.
pub async fn agent_quota_middleware(
    State(pool): State<PgPool>,
    claims: Option<Extension<JwtClaims>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let claims = match claims {
        Some(Extension(c)) => c,
        None => return next.run(request).await,
    };

    let tenant_id = match claims.tid {
        Some(tid) => tid,
        None => return next.run(request).await,
    };

    if tenant_id == SYSTEM_TENANT_ID {
        return next.run(request).await;
    }

    let quota_service = QuotaService::new(pool);
    match quota_service.check_agent_invocations(tenant_id).await {
        Ok(check) if check.exceeded => {
            tracing::warn!(
                tenant_id = %tenant_id,
                current = %check.current,
                limit = ?check.limit,
                "Request rejected: Agent invocation quota exceeded"
            );
            quota_exceeded_response(check)
        }
        Ok(_) => next.run(request).await,
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                error = %e,
                "Failed to check agent quota"
            );
            next.run(request).await
        }
    }
}

/// Check MAU quota during login.
///
/// This function should be called from the authentication handler
/// before creating a new active user record.
pub async fn check_mau_quota(pool: &PgPool, tenant_id: Uuid) -> Result<(), Response> {
    if tenant_id == SYSTEM_TENANT_ID {
        return Ok(());
    }

    let quota_service = QuotaService::new(pool.clone());
    match quota_service.check_mau(tenant_id).await {
        Ok(check) if check.exceeded => {
            tracing::warn!(
                tenant_id = %tenant_id,
                current = %check.current,
                limit = ?check.limit,
                "Login rejected: MAU quota exceeded"
            );
            Err(mau_quota_exceeded_response(check))
        }
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                error = %e,
                "Failed to check MAU quota"
            );
            // Fail open on error
            Ok(())
        }
    }
}

/// Create a 429 Too Many Requests response for quota exceeded.
fn quota_exceeded_response(check: QuotaCheck) -> Response {
    let message = match check.quota_type {
        QuotaType::ApiCalls => "Monthly API call limit exceeded",
        QuotaType::AgentInvocations => "Monthly agent invocation limit exceeded",
        QuotaType::Mau => "Monthly active user limit exceeded",
    };

    let body = QuotaExceededError {
        error: "quota_exceeded".to_string(),
        message: message.to_string(),
        details: QuotaDetails {
            quota_type: check.quota_type,
            current: check.current,
            limit: check.limit.unwrap_or(0),
            reset_at: check.reset_at.to_rfc3339(),
        },
    };

    (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response()
}

/// Create a 403 Forbidden response for MAU quota exceeded.
///
/// MAU quota returns 403 instead of 429 because it blocks authentication,
/// not just rate limiting.
fn mau_quota_exceeded_response(check: QuotaCheck) -> Response {
    let body = QuotaExceededError {
        error: "quota_exceeded".to_string(),
        message: "Monthly active user limit exceeded. Please upgrade your plan.".to_string(),
        details: QuotaDetails {
            quota_type: check.quota_type,
            current: check.current,
            limit: check.limit.unwrap_or(0),
            reset_at: check.reset_at.to_rfc3339(),
        },
    };

    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_exceeded_response_status() {
        let check = QuotaCheck {
            exceeded: true,
            quota_type: QuotaType::ApiCalls,
            current: 100500,
            limit: Some(100000),
            reset_at: chrono::Utc::now(),
        };

        let response = quota_exceeded_response(check);
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_mau_quota_exceeded_response_status() {
        let check = QuotaCheck {
            exceeded: true,
            quota_type: QuotaType::Mau,
            current: 550,
            limit: Some(500),
            reset_at: chrono::Utc::now(),
        };

        let response = mau_quota_exceeded_response(check);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_quota_details_serialization() {
        let details = QuotaDetails {
            quota_type: QuotaType::ApiCalls,
            current: 100500,
            limit: 100000,
            reset_at: "2024-02-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"quota_type\":\"api_calls\""));
        assert!(json.contains("\"current\":100500"));
        assert!(json.contains("\"limit\":100000"));
    }

    #[test]
    fn test_quota_exceeded_error_serialization() {
        let error = QuotaExceededError {
            error: "quota_exceeded".to_string(),
            message: "Monthly API call limit exceeded".to_string(),
            details: QuotaDetails {
                quota_type: QuotaType::ApiCalls,
                current: 100500,
                limit: 100000,
                reset_at: "2024-02-01T00:00:00Z".to_string(),
            },
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("\"error\":\"quota_exceeded\""));
        assert!(json.contains("Monthly API call limit exceeded"));
        assert!(json.contains("\"details\""));
    }
}
