//! Session activity middleware.
//!
//! Updates session `last_activity_at` on authenticated requests.

use axum::{body::Body, extract::Request, middleware::Next, response::Response, Extension};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::services::SessionService;

/// Middleware that updates session activity on authenticated requests.
///
/// This middleware should be applied after JWT authentication middleware
/// and before handlers. It updates `last_activity_at` for the current session.
pub async fn session_activity_middleware(
    Extension(session_service): Extension<Arc<SessionService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Extract session ID from JWT jti
    if let Ok(session_id) = Uuid::parse_str(&claims.jti) {
        // Update activity in background (don't block the request)
        let service = session_service.clone();
        let tenant = *tenant_id.as_uuid();
        tokio::spawn(async move {
            // This is fire-and-forget - we don't want to fail the request if this fails
            let _ = service.update_activity(session_id, tenant).await;
        });
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_middleware_exists() {
        // Placeholder test - full testing requires integration setup
    }
}
