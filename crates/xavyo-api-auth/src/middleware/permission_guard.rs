//! Permission guard middleware for delegated administration.
//!
//! Enforces permission checks on admin endpoints before allowing access.

use crate::error::ApiAuthError;
use crate::services::DelegatedAdminService;
use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

/// Check if the user is a super admin based on their JWT claims.
pub fn is_super_admin(claims: &JwtClaims) -> bool {
    claims.roles.contains(&"super_admin".to_string())
}

/// Permission guard configuration.
#[derive(Clone)]
pub struct PermissionGuard {
    /// Required permission for the endpoint.
    pub required_permission: String,
}

impl PermissionGuard {
    /// Create a new permission guard with the required permission.
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            required_permission: permission.into(),
        }
    }
}

/// Middleware that checks if the user has the required permission.
///
/// This middleware expects:
/// - JwtClaims extension (from authentication middleware)
/// - DelegatedAdminService in state or extension
/// - Tenant ID from claims
///
/// Super admins bypass permission checks entirely.
pub async fn permission_guard_middleware(
    State(state): State<PermissionGuardState>,
    Extension(claims): Extension<JwtClaims>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Super admins bypass all permission checks
    if is_super_admin(&claims) {
        return next.run(request).await;
    }

    // Extract tenant_id from claims (tid field)
    let tenant_id = match claims.tid {
        Some(id) => id,
        None => {
            warn!("Missing tenant_id in claims");
            return ApiAuthError::Unauthorized.into_response();
        }
    };

    // Extract user_id from claims (sub field)
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            warn!("Invalid user_id in claims");
            return ApiAuthError::Unauthorized.into_response();
        }
    };

    // Check if user has the required permission
    match state
        .service
        .has_permission(tenant_id, user_id, &state.required_permission)
        .await
    {
        Ok(true) => next.run(request).await,
        Ok(false) => {
            warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                required_permission = %state.required_permission,
                "Permission denied"
            );
            ApiAuthError::PermissionDenied(format!(
                "You do not have the '{}' permission",
                state.required_permission
            ))
            .into_response()
        }
        Err(e) => {
            warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                error = %e,
                "Error checking permission"
            );
            e.into_response()
        }
    }
}

/// State for the permission guard middleware.
#[derive(Clone)]
pub struct PermissionGuardState {
    /// The delegated admin service.
    pub service: Arc<DelegatedAdminService>,
    /// The required permission.
    pub required_permission: String,
}

/// Create a permission guard layer for a specific permission.
///
/// # Example
///
/// ```ignore
/// let router = Router::new()
///     .route("/users", get(list_users))
///     .layer(permission_guard_layer("users:read", service.clone()));
/// ```
#[allow(clippy::type_complexity)]
pub fn permission_guard_layer(
    permission: impl Into<String>,
    service: Arc<DelegatedAdminService>,
) -> axum::middleware::FromFnLayer<
    fn(
        State<PermissionGuardState>,
        Extension<JwtClaims>,
        Request<Body>,
        Next,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>,
    PermissionGuardState,
    (),
> {
    let state = PermissionGuardState {
        service,
        required_permission: permission.into(),
    };

    axum::middleware::from_fn_with_state(state, |state, claims, request, next| {
        Box::pin(permission_guard_middleware(state, claims, request, next))
    })
}

/// Scope check result.
pub enum ScopeCheckResult {
    /// Access allowed (either global or within scope).
    Allowed,
    /// Access denied due to scope violation.
    Denied {
        allowed_scopes: Vec<String>,
        resource_scope: String,
    },
}

/// Check if a resource is within the user's scope.
///
/// This is typically called from service layer after loading a resource.
pub async fn check_resource_scope(
    service: &DelegatedAdminService,
    tenant_id: Uuid,
    user_id: Uuid,
    scope_type: &str,
    resource_scope: &str,
) -> Result<ScopeCheckResult, ApiAuthError> {
    let effective = service
        .get_user_effective_permissions(tenant_id, user_id)
        .await?;

    // If user has no scopes, they have global access
    if effective.scopes.is_empty() {
        return Ok(ScopeCheckResult::Allowed);
    }

    // Check if resource is in user's scopes
    for scope in &effective.scopes {
        if scope.scope_type == scope_type && scope.scope_value.contains(&resource_scope.to_string())
        {
            return Ok(ScopeCheckResult::Allowed);
        }
    }

    // Collect allowed scopes for error message
    let allowed_scopes: Vec<String> = effective
        .scopes
        .iter()
        .filter(|s| s.scope_type == scope_type)
        .flat_map(|s| s.scope_value.clone())
        .collect();

    Ok(ScopeCheckResult::Denied {
        allowed_scopes,
        resource_scope: resource_scope.to_string(),
    })
}

/// Require a specific permission or return an error.
///
/// Convenience function for use in handlers.
pub async fn require_permission(
    service: &DelegatedAdminService,
    tenant_id: Uuid,
    user_id: Uuid,
    is_super_admin: bool,
    required_permission: &str,
) -> Result<(), ApiAuthError> {
    // Super admins bypass all permission checks
    if is_super_admin {
        return Ok(());
    }

    let has_perm = service
        .has_permission(tenant_id, user_id, required_permission)
        .await?;

    if has_perm {
        Ok(())
    } else {
        Err(ApiAuthError::PermissionDenied(format!(
            "You do not have the '{}' permission",
            required_permission
        )))
    }
}

/// Require a resource to be within scope or return an error.
///
/// Convenience function for use in handlers.
pub async fn require_scope(
    service: &DelegatedAdminService,
    tenant_id: Uuid,
    user_id: Uuid,
    is_super_admin: bool,
    scope_type: &str,
    resource_scope: &str,
) -> Result<(), ApiAuthError> {
    // Super admins bypass scope checks
    if is_super_admin {
        return Ok(());
    }

    match check_resource_scope(service, tenant_id, user_id, scope_type, resource_scope).await? {
        ScopeCheckResult::Allowed => Ok(()),
        ScopeCheckResult::Denied {
            allowed_scopes,
            resource_scope,
        } => Err(ApiAuthError::ScopeViolation(format!(
            "Resource '{}' is outside your allowed {} scopes: {:?}",
            resource_scope, scope_type, allowed_scopes
        ))),
    }
}

/// Middleware that requires the super_admin role.
///
/// This middleware should be applied to admin endpoints that require
/// super_admin access. It rejects requests from non-super_admin users
/// with a 403 Forbidden response.
pub async fn require_super_admin_middleware(
    Extension(claims): Extension<JwtClaims>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if is_super_admin(&claims) {
        next.run(request).await
    } else {
        warn!(
            user_id = %claims.sub,
            "Non-super_admin attempted to access super_admin endpoint"
        );
        ApiAuthError::PermissionDenied("This endpoint requires super_admin role".to_string())
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_core::TenantId;

    #[test]
    fn test_is_super_admin_true() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["super_admin"])
            .build();

        assert!(is_super_admin(&claims));
    }

    #[test]
    fn test_is_super_admin_false() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .roles(vec!["user"])
            .build();

        assert!(!is_super_admin(&claims));
    }

    #[test]
    fn test_is_super_admin_empty_roles() {
        let claims = JwtClaims::builder()
            .subject(Uuid::new_v4().to_string())
            .tenant_id(TenantId::new())
            .build();

        assert!(!is_super_admin(&claims));
    }
}
