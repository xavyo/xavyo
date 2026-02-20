//! SCIM Bearer token authentication middleware.

use axum::{
    body::Body,
    http::{header, Request},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tower::{Layer, Service};
use uuid::Uuid;

use sqlx::PgPool;
use xavyo_db::models::ScimToken;

use crate::error::ScimError;
use crate::services::TokenService;

/// SCIM authentication context extracted from Bearer token.
#[derive(Debug, Clone)]
pub struct ScimAuthContext {
    /// The validated token.
    pub token: ScimToken,
    /// Tenant ID from the token.
    pub tenant_id: Uuid,
}

/// Layer for SCIM Bearer token authentication.
#[derive(Clone)]
pub struct ScimAuthLayer {
    _marker: (),
}

impl ScimAuthLayer {
    /// Create a new auth layer.
    #[must_use]
    pub fn new() -> Self {
        Self { _marker: () }
    }
}

impl Default for ScimAuthLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for ScimAuthLayer {
    type Service = ScimAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ScimAuthService { inner }
    }
}

/// SCIM authentication service wrapper.
#[derive(Clone)]
pub struct ScimAuthService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for ScimAuthService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move {
            // Extract Bearer token from Authorization header
            let auth_header = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok());

            let bearer_token = match auth_header {
                Some(h) if h.starts_with("Bearer ") => &h[7..],
                _ => {
                    tracing::warn!("SCIM auth failed: missing or malformed Authorization header");
                    return Ok(ScimError::Unauthorized.into_response());
                }
            };

            // Get token service from extensions
            let token_service = if let Some(svc) = req.extensions().get::<Arc<TokenService>>() {
                svc.clone()
            } else {
                tracing::error!("TokenService not found in request extensions");
                return Ok(
                    ScimError::Internal("Auth service unavailable".to_string()).into_response()
                );
            };

            // Validate token
            match token_service.validate_token(bearer_token).await {
                Ok(token) => {
                    let tenant_id = token.tenant_id;

                    // SECURITY: Set RLS tenant context (defense-in-depth).
                    // All queries also use WHERE tenant_id = $N, but RLS provides
                    // an additional isolation layer if a query misses the filter.
                    //
                    // NOTE: `true` = transaction-local scope (reset at end of transaction).
                    // With a connection pool, each `pool.execute()` may use a different
                    // connection, so this set_config only affects queries on the same
                    // connection within the same transaction. Handler queries that use
                    // `pool.fetch_*()` may get a different connection and thus not see
                    // this setting. The primary tenant isolation is therefore the
                    // explicit `WHERE tenant_id = $N` on every query.
                    if let Some(pool) = req.extensions().get::<PgPool>() {
                        if let Err(e) =
                            sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
                                .bind(tenant_id.to_string())
                                .execute(pool)
                                .await
                        {
                            tracing::error!("Failed to set RLS tenant context: {e}");
                            return Ok(ScimError::Internal(
                                "Failed to initialize request context".to_string(),
                            )
                            .into_response());
                        }
                    }

                    let ctx = ScimAuthContext { token, tenant_id };
                    req.extensions_mut().insert(ctx);
                    inner.call(req).await
                }
                Err(_) => {
                    tracing::warn!("SCIM auth failed: invalid or revoked bearer token");
                    Ok(ScimError::Unauthorized.into_response())
                }
            }
        })
    }
}

/// Extract SCIM auth context from request extensions.
pub fn extract_scim_auth(req: &Request<Body>) -> Option<&ScimAuthContext> {
    req.extensions().get::<ScimAuthContext>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_layer_creation() {
        let _layer = ScimAuthLayer::new();
        // Layer created successfully
    }

    #[test]
    fn test_extract_bearer_token() {
        // Test the token extraction logic
        let auth_header = "Bearer xscim_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk";
        let token = auth_header.strip_prefix("Bearer ");

        assert_eq!(token, Some("xscim_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"));
    }
}
