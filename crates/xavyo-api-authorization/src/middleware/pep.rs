//! Policy Enforcement Point (PEP) middleware (F083).
//!
//! Axum middleware that automatically enforces authorization on configured routes.
//! Extracts the subject from JWT claims, maps HTTP methods to actions, and
//! calls the PDP to evaluate. Returns 403 on deny or error (fail-closed).

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_authorization::{AuthorizationRequest, PolicyDecisionPoint};

/// Configuration for the PEP middleware on a specific route group.
///
/// Attach this as an Extension to routes that need enforcement.
#[derive(Clone, Debug)]
pub struct PepConfig {
    /// The resource type for this route group (e.g., "report", "user").
    pub resource_type: String,
}

/// PEP enforcement middleware.
///
/// Must be used with an `Extension<PepConfig>` and `Extension<JwtClaims>` in the request.
/// Also requires `Extension<Arc<PolicyDecisionPoint>>` and `Extension<sqlx::PgPool>`.
///
/// Behavior:
/// 1. Extract `PepConfig`, `JwtClaims` from extensions
/// 2. Map HTTP method to action (GET->read, POST->create, etc.)
/// 3. Build `AuthorizationRequest`
/// 4. Call `PDP.evaluate()`
/// 5. If denied, return 403 JSON response
/// 6. If allowed, pass through to next handler
/// 7. On error, fail-closed (403)
pub async fn pep_enforcement_middleware(request: Request<Body>, next: Next) -> Response {
    // 1. Extract PepConfig (if not present, pass through - PEP is opt-in)
    let pep_config = request.extensions().get::<PepConfig>().cloned();
    let Some(pep_config) = pep_config else {
        return next.run(request).await;
    };

    // 2. Extract JwtClaims
    let claims = request.extensions().get::<JwtClaims>().cloned();
    let Some(claims) = claims else {
        return unauthorized_response("Missing authentication");
    };

    // 3. Extract tenant_id from claims
    let tenant_id = match claims.tenant_id() {
        Some(tid) => *tid.as_uuid(),
        None => return unauthorized_response("Missing tenant context"),
    };

    // 4. Extract user_id from claims.sub
    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(uid) => uid,
        Err(_) => return unauthorized_response("Invalid user ID"),
    };

    // 5. Map HTTP method to action
    let action = method_to_action(request.method());

    // 6. Extract resource_id from path if available
    // Try to extract the last path segment as resource_id for GET/PUT/DELETE on specific resources
    let path = request.uri().path().to_string();
    let resource_id = extract_resource_id(&path);

    // 7. Extract PDP from extensions
    let pdp = request
        .extensions()
        .get::<Arc<PolicyDecisionPoint>>()
        .cloned();
    let pool = request.extensions().get::<sqlx::PgPool>().cloned();

    let Some(pdp) = pdp else {
        // No PDP available, fail-closed
        tracing::error!(target: "authorization", "PEP: No PDP configured, fail-closed");
        return forbidden_response("Authorization service unavailable");
    };

    let Some(pool) = pool else {
        tracing::error!(target: "authorization", "PEP: No database pool configured, fail-closed");
        return forbidden_response("Authorization service unavailable");
    };

    // 8. Build and evaluate request
    let auth_request = AuthorizationRequest {
        subject_id: user_id,
        tenant_id,
        action: action.to_string(),
        resource_type: pep_config.resource_type,
        resource_id,
        delegation: None,
    };

    let decision = pdp.evaluate(&pool, auth_request, &claims.roles, None).await;

    // 9. Return decision
    if decision.allowed {
        next.run(request).await
    } else {
        tracing::info!(
            target: "authorization",
            decision_id = %decision.decision_id,
            user_id = %user_id,
            action = action,
            reason = %decision.reason,
            "PEP: Access denied"
        );
        forbidden_response(&decision.reason)
    }
}

/// Map an HTTP method to an authorization action.
fn method_to_action(method: &Method) -> &'static str {
    match *method {
        Method::GET => "read",
        Method::POST => "create",
        Method::PUT => "update",
        Method::PATCH => "update",
        Method::DELETE => "delete",
        _ => "unknown",
    }
}

/// Extract a potential `resource_id` from the last path segment.
///
/// Returns None if the last segment doesn't look like a UUID or specific ID.
fn extract_resource_id(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() >= 2 {
        let last = segments.last()?;
        // Only extract if it looks like a UUID
        if Uuid::parse_str(last).is_ok() {
            return Some(last.to_string());
        }
    }
    None
}

/// Build a 401 Unauthorized JSON response.
fn unauthorized_response(message: &str) -> Response {
    let body = json!({ "error": "unauthorized", "message": message });
    let mut response = Response::new(Body::from(serde_json::to_string(&body).unwrap()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
}

/// Build a 403 Forbidden JSON response.
fn forbidden_response(message: &str) -> Response {
    let body = json!({ "error": "forbidden", "message": message });
    let mut response = Response::new(Body::from(serde_json::to_string(&body).unwrap()));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_to_action() {
        assert_eq!(method_to_action(&Method::GET), "read");
        assert_eq!(method_to_action(&Method::POST), "create");
        assert_eq!(method_to_action(&Method::PUT), "update");
        assert_eq!(method_to_action(&Method::PATCH), "update");
        assert_eq!(method_to_action(&Method::DELETE), "delete");
        assert_eq!(method_to_action(&Method::OPTIONS), "unknown");
    }

    #[test]
    fn test_extract_resource_id_uuid() {
        let id = Uuid::new_v4();
        let path = format!("/api/resources/{id}");
        assert_eq!(extract_resource_id(&path), Some(id.to_string()));
    }

    #[test]
    fn test_extract_resource_id_non_uuid() {
        assert_eq!(extract_resource_id("/api/resources"), None);
        assert_eq!(extract_resource_id("/api/resources/list"), None);
    }

    #[test]
    fn test_extract_resource_id_root() {
        assert_eq!(extract_resource_id("/"), None);
    }

    #[test]
    fn test_pep_config() {
        let config = PepConfig {
            resource_type: "report".to_string(),
        };
        assert_eq!(config.resource_type, "report");
    }
}
