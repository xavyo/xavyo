//! Tenant context extraction middleware.

use axum::{body::Body, extract::Request, http::HeaderValue, response::Response};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::config::GatewayConfig;
use crate::middleware::auth::AuthClaims;

/// Header name for tenant ID.
pub const TENANT_ID_HEADER: &str = "X-Tenant-ID";

/// Extracted tenant context.
#[derive(Debug, Clone)]
pub struct TenantContext {
    pub tenant_id: String,
}

/// Layer for tenant context extraction.
#[derive(Debug, Clone)]
pub struct TenantLayer {
    config: Arc<GatewayConfig>,
}

impl TenantLayer {
    /// Create a new tenant layer with the given configuration.
    pub fn new(config: Arc<GatewayConfig>) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for TenantLayer {
    type Service = TenantService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantService {
            inner,
            _config: self.config.clone(),
        }
    }
}

/// Tenant context service wrapper.
#[derive(Debug, Clone)]
pub struct TenantService<S> {
    inner: S,
    _config: Arc<GatewayConfig>,
}

impl<S> Service<Request<Body>> for TenantService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Try to get tenant ID from multiple sources (in priority order):
            // 1. JWT claims (from AuthClaims extension)
            // 2. X-Tenant-ID header

            let tenant_id = request
                .extensions()
                .get::<AuthClaims>()
                .and_then(|claims| claims.tenant_id.clone())
                .or_else(|| {
                    request
                        .headers()
                        .get(TENANT_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                });

            if let Some(tenant_id) = tenant_id {
                // Add tenant context as extension
                request.extensions_mut().insert(TenantContext {
                    tenant_id: tenant_id.clone(),
                });

                // Ensure X-Tenant-ID header is set for backend propagation
                if let Ok(header_value) = HeaderValue::from_str(&tenant_id) {
                    request.headers_mut().insert(TENANT_ID_HEADER, header_value);
                }
            }

            inner.call(request).await
        })
    }
}

/// Extract tenant ID from request (for use in handlers).
#[allow(dead_code)]
pub fn extract_tenant_id(request: &Request<Body>) -> Option<String> {
    request
        .extensions()
        .get::<TenantContext>()
        .map(|ctx| ctx.tenant_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_context() {
        let ctx = TenantContext {
            tenant_id: "test-tenant".to_string(),
        };
        assert_eq!(ctx.tenant_id, "test-tenant");
    }
}
