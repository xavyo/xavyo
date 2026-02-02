//! Middleware for enforcing tenant access status (suspension and deletion).
//!
//! F-SUSPEND: This middleware checks if a tenant is suspended and rejects
//! requests with a 403 Forbidden status if so.
//!
//! F-DELETE: This middleware also checks if a tenant is deleted (soft delete)
//! and rejects requests with a 403 Forbidden status if so.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::bootstrap::SYSTEM_TENANT_ID;

/// RFC 7807 Problem Details error response for tenant access issues.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7807>
#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    /// A URI reference that identifies the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// A short, human-readable summary of the problem type.
    pub title: String,
    /// The HTTP status code.
    pub status: u16,
    /// A human-readable explanation specific to this occurrence of the problem.
    pub detail: String,
    /// A URI reference that identifies the specific occurrence of the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// Legacy error response for backwards compatibility.
/// Use ProblemDetails for new code.
#[derive(Debug, Serialize)]
pub struct TenantAccessError {
    pub error: String,
    pub message: String,
}

/// Tenant access status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantStatus {
    /// Tenant is active and accessible.
    Active,
    /// Tenant is suspended.
    Suspended,
    /// Tenant is soft deleted.
    Deleted,
    /// Tenant not found.
    NotFound,
}

/// Middleware function that checks if the tenant (from JWT claims) is accessible.
///
/// This middleware should be applied to tenant-scoped routes after JWT authentication.
/// It extracts the tenant_id from JWT claims and checks the database for suspension
/// and deletion status.
///
/// ## Behavior
///
/// - If no JWT claims present: passes through (let auth middleware handle it)
/// - If tenant_id missing in claims: passes through (let other middleware handle it)
/// - If tenant is system tenant: always passes through (system tenant cannot be suspended/deleted)
/// - If tenant is active: passes through
/// - If tenant is suspended: returns 403 Forbidden with suspension message
/// - If tenant is deleted: returns 403 Forbidden with deletion message
///
/// ## Example
///
/// ```rust,ignore
/// use axum::{middleware, Router};
/// use xavyo_api_tenants::middleware::suspension_check_middleware;
///
/// let app = Router::new()
///     .route("/api/resource", get(handler))
///     .layer(middleware::from_fn_with_state(pool, suspension_check_middleware));
/// ```
pub async fn suspension_check_middleware(
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

    // System tenant is never suspended or deleted
    if tenant_id == SYSTEM_TENANT_ID {
        return next.run(request).await;
    }

    // Capture request URI for RFC 7807 instance field
    let request_uri = request.uri().clone();

    // Check tenant access status
    match check_tenant_access_status(&pool, tenant_id).await {
        Ok(TenantStatus::Active) => next.run(request).await,
        Ok(TenantStatus::Suspended) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                "Request rejected: tenant is suspended"
            );
            suspended_response(&request_uri)
        }
        Ok(TenantStatus::Deleted) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                "Request rejected: tenant is deleted"
            );
            deleted_response(&request_uri)
        }
        Ok(TenantStatus::NotFound) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                "Request rejected: tenant not found"
            );
            not_found_response(&request_uri)
        }
        Err(e) => {
            tracing::error!(
                tenant_id = %tenant_id,
                error = %e,
                "Failed to check tenant access status"
            );
            // On error, fail open to avoid blocking legitimate requests
            // This is a trade-off: prefer availability over strict enforcement
            // The access check is a secondary control, not a primary one
            next.run(request).await
        }
    }
}

/// Tenant timestamps for access status check.
type TenantTimestamps = (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// Check if a tenant is accessible (not suspended or deleted).
async fn check_tenant_access_status(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<TenantStatus, sqlx::Error> {
    let result: Option<TenantTimestamps> = sqlx::query_as(
        r#"
        SELECT suspended_at, deleted_at
        FROM tenants
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    Ok(match result {
        Some((suspended_at, deleted_at)) => {
            if deleted_at.is_some() {
                TenantStatus::Deleted
            } else if suspended_at.is_some() {
                TenantStatus::Suspended
            } else {
                TenantStatus::Active
            }
        }
        None => TenantStatus::NotFound,
    })
}

/// Base URL for problem type URIs.
const PROBLEM_TYPE_BASE: &str = "https://api.xavyo.net/problems";

/// Create a 403 Forbidden response for suspended tenants using RFC 7807 Problem Details.
fn suspended_response(request_uri: &Uri) -> Response {
    let body = ProblemDetails {
        problem_type: format!("{}/tenant-suspended", PROBLEM_TYPE_BASE),
        title: "Tenant Suspended".to_string(),
        status: 403,
        detail:
            "Your organization has been suspended. Please contact support for more information."
                .to_string(),
        instance: Some(request_uri.path().to_string()),
    };
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(body),
    )
        .into_response()
}

/// Create a 403 Forbidden response for deleted tenants using RFC 7807 Problem Details.
fn deleted_response(request_uri: &Uri) -> Response {
    let body = ProblemDetails {
        problem_type: format!("{}/tenant-deleted", PROBLEM_TYPE_BASE),
        title: "Tenant Deleted".to_string(),
        status: 403,
        detail: "Your organization has been deleted. Please contact support if you believe this is an error.".to_string(),
        instance: Some(request_uri.path().to_string()),
    };
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(body),
    )
        .into_response()
}

/// Create a 404 Not Found response for unknown tenants using RFC 7807 Problem Details.
fn not_found_response(request_uri: &Uri) -> Response {
    let body = ProblemDetails {
        problem_type: format!("{}/tenant-not-found", PROBLEM_TYPE_BASE),
        title: "Tenant Not Found".to_string(),
        status: 404,
        detail: "Organization not found.".to_string(),
        instance: Some(request_uri.path().to_string()),
    };
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        "/api/test/resource".parse().unwrap()
    }

    #[test]
    fn test_suspended_response_format() {
        let response = suspended_response(&test_uri());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_deleted_response_format() {
        let response = deleted_response(&test_uri());
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_not_found_response_format() {
        let response = not_found_response(&test_uri());
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_tenant_status_equality() {
        assert_eq!(TenantStatus::Active, TenantStatus::Active);
        assert_ne!(TenantStatus::Suspended, TenantStatus::Deleted);
        assert_ne!(TenantStatus::Active, TenantStatus::NotFound);
    }

    #[test]
    fn test_problem_details_serialization() {
        let problem = ProblemDetails {
            problem_type: format!("{}/tenant-suspended", PROBLEM_TYPE_BASE),
            title: "Tenant Suspended".to_string(),
            status: 403,
            detail: "Test detail".to_string(),
            instance: Some("/api/test".to_string()),
        };
        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"type\":"));
        assert!(json.contains("tenant-suspended"));
        assert!(json.contains("\"title\":\"Tenant Suspended\""));
        assert!(json.contains("\"status\":403"));
        assert!(json.contains("\"detail\":\"Test detail\""));
        assert!(json.contains("\"instance\":\"/api/test\""));
    }
}
