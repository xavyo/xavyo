//! Admin role guard middleware.
//!
//! This middleware checks that the authenticated user has the "admin" role
//! before allowing access to protected endpoints.

use crate::error::ApiUsersError;
use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use xavyo_auth::JwtClaims;

/// Required role for admin operations.
pub const ADMIN_ROLE: &str = "admin";

/// Super admin role (has all admin privileges).
pub const SUPER_ADMIN_ROLE: &str = "super_admin";

/// Middleware that requires the authenticated user to have the "admin" or "`super_admin`" role.
///
/// This middleware extracts `JwtClaims` from request extensions and verifies
/// the user has either the "admin" or "`super_admin`" role. If the claims are missing
/// (not authenticated) or the user doesn't have an admin role, an appropriate error is returned.
///
/// # Usage
///
/// ```rust,ignore
/// use axum::{Router, routing::get, middleware};
/// use xavyo_api_users::middleware::admin_guard;
///
/// let router = Router::new()
///     .route("/admin/users", get(list_users))
///     .layer(middleware::from_fn(admin_guard));
/// ```
///
/// # Requirements
///
/// This middleware requires a prior JWT authentication middleware to have
/// inserted `JwtClaims` into the request extensions. If no claims are found,
/// it returns 401 Unauthorized.
///
/// # Errors
///
/// - `ApiUsersError::Unauthorized` (401): No JWT claims in request extensions
/// - `ApiUsersError::Forbidden` (403): User doesn't have the "admin" or "`super_admin`" role
pub async fn admin_guard(request: Request<Body>, next: Next) -> Result<Response, ApiUsersError> {
    // Extract JWT claims from extensions
    let claims = request
        .extensions()
        .get::<JwtClaims>()
        .ok_or(ApiUsersError::Unauthorized)?;

    // L-5: Verify tenant_id is present — a token without a tenant context
    // should never reach admin handlers (defense-in-depth).
    if claims.tenant_id().is_none() {
        tracing::warn!(
            user_id = %claims.sub,
            "Access denied: missing tenant_id in claims"
        );
        return Err(ApiUsersError::Unauthorized);
    }

    // Check for admin or super_admin role
    let is_admin = claims.has_role(ADMIN_ROLE) || claims.has_role(SUPER_ADMIN_ROLE);
    if !is_admin {
        tracing::warn!(
            user_id = %claims.sub,
            roles = ?claims.roles,
            "Access denied: admin role required"
        );
        return Err(ApiUsersError::Forbidden);
    }

    tracing::debug!(
        user_id = %claims.sub,
        "Admin access granted"
    );

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::util::ServiceExt;
    use xavyo_core::TenantId;

    async fn test_handler() -> &'static str {
        "OK"
    }

    fn create_claims_with_roles(roles: Vec<&str>) -> JwtClaims {
        JwtClaims::builder()
            .subject("user-123")
            .issuer("xavyo")
            .tenant_id(TenantId::new())
            .roles(roles)
            .expires_in_secs(3600)
            .build()
    }

    #[tokio::test]
    async fn test_admin_guard_allows_admin() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let claims = create_claims_with_roles(vec!["admin"]);

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(claims);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_guard_allows_admin_with_other_roles() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let claims = create_claims_with_roles(vec!["user", "admin", "editor"]);

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(claims);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_guard_allows_super_admin() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let claims = create_claims_with_roles(vec!["super_admin"]);

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(claims);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_guard_denies_non_admin() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let claims = create_claims_with_roles(vec!["user"]);

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(claims);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_admin_guard_denies_no_roles() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let claims = create_claims_with_roles(vec![]);

        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(claims);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_admin_guard_denies_no_claims() {
        let app = Router::new()
            .route("/", get(test_handler))
            .layer(middleware::from_fn(admin_guard));

        let request = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
