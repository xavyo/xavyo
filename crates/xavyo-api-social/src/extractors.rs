//! Axum extractors for social authentication handlers.

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{header::HeaderMap, request::Parts},
};
use uuid::Uuid;

use crate::error::SocialError;

/// Tenant ID extracted from request headers.
///
/// Extracts `tenant_id` from X-Tenant-ID header.
/// For public social login routes, this is required to identify the tenant configuration.
#[derive(Debug, Clone, Copy)]
pub struct TenantId(pub Uuid);

#[async_trait]
impl<S> FromRequestParts<S> for TenantId
where
    S: Send + Sync,
{
    type Rejection = SocialError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        extract_tenant_id(&parts.headers)
    }
}

fn extract_tenant_id(headers: &HeaderMap) -> Result<TenantId, SocialError> {
    let tenant_id_str = headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SocialError::InvalidCallback {
            reason: "Missing X-Tenant-ID header".to_string(),
        })?;

    let tenant_id = tenant_id_str
        .parse::<Uuid>()
        .map_err(|_| SocialError::InvalidCallback {
            reason: "Invalid X-Tenant-ID header".to_string(),
        })?;

    Ok(TenantId(tenant_id))
}

/// User context extracted from authenticated request.
///
/// This extractor gets `user_id` and `tenant_id` from JWT claims in request extensions.
/// Used for routes that require authentication.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = SocialError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Try to get user context from extensions (set by xavyo-auth JWT middleware)
        if let Some(claims) = parts.extensions.get::<xavyo_auth::JwtClaims>() {
            let user_id = Uuid::parse_str(&claims.sub).map_err(|_| SocialError::InternalError {
                message: "Invalid user ID in JWT claims".to_string(),
            })?;
            let tenant_id = claims.tenant_id().map(|tid| *tid.as_uuid()).ok_or_else(|| SocialError::InternalError {
                message: "Tenant ID not found in JWT claims".to_string(),
            })?;
            return Ok(AuthenticatedUser {
                user_id,
                tenant_id,
            });
        }

        // Fallback: try to get from typed extensions
        let user_id = parts
            .extensions
            .get::<UserId>()
            .map(|u| u.0)
            .ok_or_else(|| SocialError::InternalError {
                message: "User ID not found in request extensions".to_string(),
            })?;

        let tenant_id = parts
            .extensions
            .get::<xavyo_core::TenantId>()
            .map(|t| *t.as_uuid())
            .ok_or_else(|| SocialError::InternalError {
                message: "Tenant ID not found in request extensions".to_string(),
            })?;

        Ok(AuthenticatedUser { user_id, tenant_id })
    }
}

/// JWT claims from xavyo-auth.
#[derive(Debug, Clone)]
pub struct JwtClaims {
    pub sub: Uuid,
    pub tenant_id: Uuid,
}

/// User ID wrapper for extension storage.
#[derive(Debug, Clone, Copy)]
pub struct UserId(pub Uuid);
