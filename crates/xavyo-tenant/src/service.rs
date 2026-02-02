//! Tower Service implementation for tenant middleware.
//!
//! Provides `TenantService` that wraps inner services with tenant extraction.

use crate::config::TenantConfig;
use crate::error::TenantError;
use crate::extract::{extract_tenant_id, TenantContext};
use axum::response::IntoResponse;
use http::{Method, Request, Response};
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;

/// Tower Service that extracts and validates tenant context.
///
/// This service wraps an inner service and:
/// 1. Extracts tenant ID from request headers or JWT claims
/// 2. Validates the tenant ID format
/// 3. Inserts the TenantId into request extensions
/// 4. Rejects requests without valid tenant context (if required)
///
/// # Type Parameters
///
/// * `S` - The inner service type
#[derive(Debug, Clone)]
pub struct TenantService<S> {
    inner: S,
    config: Arc<TenantConfig>,
}

impl<S> TenantService<S> {
    /// Create a new TenantService.
    pub fn new(inner: S, config: Arc<TenantConfig>) -> Self {
        Self { inner, config }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TenantService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = TenantServiceFuture<S, ReqBody, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Skip tenant validation for OPTIONS requests (CORS preflight)
        if req.method() == Method::OPTIONS {
            let inner = self.inner.clone();
            let mut inner = std::mem::replace(&mut self.inner, inner);
            return TenantServiceFuture::Inner {
                future: inner.call(req),
            };
        }

        // Extract tenant ID
        match extract_tenant_id(&req, &self.config) {
            Ok(tenant_id) => {
                // Insert TenantId and TenantContext into extensions
                req.extensions_mut().insert(tenant_id);
                req.extensions_mut().insert(TenantContext::new(tenant_id));

                tracing::debug!(tenant_id = %tenant_id, "Tenant context extracted");

                let inner = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, inner);
                TenantServiceFuture::Inner {
                    future: inner.call(req),
                }
            }
            Err(err) => {
                if self.config.require_tenant {
                    tracing::warn!(error = %err, "Tenant context extraction failed");
                    TenantServiceFuture::Error { error: Some(err) }
                } else {
                    // Tenant not required, proceed without context
                    tracing::debug!("Tenant context not required, proceeding without");
                    let inner = self.inner.clone();
                    let mut inner = std::mem::replace(&mut self.inner, inner);
                    TenantServiceFuture::Inner {
                        future: inner.call(req),
                    }
                }
            }
        }
    }
}

pin_project! {
    /// Future for TenantService.
    #[project = TenantServiceFutureProj]
    pub enum TenantServiceFuture<S, ReqBody, ResBody>
    where
        S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    {
        /// Inner service future (tenant extraction succeeded or not required)
        Inner {
            #[pin]
            future: S::Future,
        },
        /// Error response (tenant extraction failed and required)
        Error {
            error: Option<TenantError>,
        },
    }
}

impl<S, ReqBody, ResBody> Future for TenantServiceFuture<S, ReqBody, ResBody>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Output = Result<Response<ResBody>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            TenantServiceFutureProj::Inner { future } => future.poll(cx),
            TenantServiceFutureProj::Error { error } => {
                let err = error.take().unwrap_or(TenantError::Missing);
                let response = err.into_response();
                // Convert axum Response<Body> to Response<ResBody>
                // For error responses, we need to create a proper response
                let (parts, _body) = response.into_parts();
                let response = Response::from_parts(parts, ResBody::default());
                Poll::Ready(Ok(response))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::convert::Infallible;
    use tower::ServiceExt;
    use xavyo_core::TenantId;

    // Mock service that always returns 200 OK
    #[derive(Clone)]
    struct MockService;

    impl Service<Request<Body>> for MockService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Response<Body>, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            // Check if TenantId was inserted
            let has_tenant = req.extensions().get::<TenantId>().is_some();
            let body = if has_tenant {
                "tenant_found"
            } else {
                "no_tenant"
            };
            std::future::ready(Ok(Response::new(Body::from(body))))
        }
    }

    #[tokio::test]
    async fn test_service_with_valid_header() {
        let config = Arc::new(TenantConfig::default());
        let service = TenantService::new(MockService, config);

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let req = Request::builder()
            .header("X-Tenant-ID", uuid)
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_service_missing_header_required() {
        let config = Arc::new(TenantConfig::default()); // require_tenant = true
        let service = TenantService::new(MockService, config);

        let req = Request::builder().body(Body::empty()).unwrap();

        let response = service.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_service_missing_header_not_required() {
        let config = Arc::new(TenantConfig::builder().require_tenant(false).build());
        let service = TenantService::new(MockService, config);

        let req = Request::builder().body(Body::empty()).unwrap();

        let response = service.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_service_invalid_uuid() {
        let config = Arc::new(TenantConfig::default());
        let service = TenantService::new(MockService, config);

        let req = Request::builder()
            .header("X-Tenant-ID", "not-a-uuid")
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_service_options_request_bypasses_validation() {
        let config = Arc::new(TenantConfig::default()); // require_tenant = true
        let service = TenantService::new(MockService, config);

        let req = Request::builder()
            .method(Method::OPTIONS)
            .body(Body::empty())
            .unwrap();

        let response = service.oneshot(req).await.unwrap();
        assert_eq!(response.status(), 200);
    }
}
