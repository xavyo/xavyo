//! Reverse proxy handler for routing requests to backend services.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::error::{ErrorResponse, GatewayError};
use crate::middleware::request_id::{RequestId, REQUEST_ID_HEADER};
use crate::middleware::tenant::TENANT_ID_HEADER;
use crate::proxy::{BackendRouter, ProxyClient};

/// Shared state for the proxy handler.
#[derive(Clone)]
pub struct ProxyState {
    pub router: BackendRouter,
    pub client: ProxyClient,
}

/// Main proxy handler that routes requests to appropriate backends.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(|s| s.to_string());
    let method = request.method().clone();

    // Get request ID from extensions
    let request_id = request.extensions().get::<RequestId>().copied();

    // Find matching backend
    let backend = match state.router.find_backend(&path) {
        Some(b) => b,
        None => {
            warn!(path = %path, "No backend found for path");
            return error_response(
                GatewayError::NotFound { path: path.clone() },
                request_id.map(|r| r.inner()),
            );
        }
    };

    // Build target URL
    let target_url = state
        .router
        .build_target_url(backend, &path, query.as_deref());

    info!(
        backend = %backend.name,
        path = %path,
        target = %target_url,
        method = %method,
        "Proxying request"
    );

    // Extract headers to forward
    let headers = extract_forward_headers(request.headers());

    // Get request body for methods that have one
    let body = match method {
        Method::POST | Method::PUT | Method::PATCH => {
            match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
                Ok(bytes) => bytes.to_vec(),
                Err(e) => {
                    error!(error = %e, "Failed to read request body");
                    return error_response(
                        GatewayError::BadRequest {
                            message: "Failed to read request body".to_string(),
                        },
                        request_id.map(|r| r.inner()),
                    );
                }
            }
        }
        _ => Vec::new(),
    };

    // Forward request to backend with headers
    let result = match method {
        Method::GET => state.client.get(&target_url, &headers).await,
        Method::POST => state.client.post(&target_url, body, &headers).await,
        Method::PUT => state.client.put(&target_url, body, &headers).await,
        Method::DELETE => state.client.delete(&target_url, &headers).await,
        Method::PATCH => state.client.patch(&target_url, body, &headers).await,
        _ => {
            return error_response(
                GatewayError::BadRequest {
                    message: format!("Unsupported method: {}", method),
                },
                request_id.map(|r| r.inner()),
            );
        }
    };

    match result {
        Ok(response) => {
            // Convert reqwest response to axum response
            convert_response(response, request_id.map(|r| r.inner())).await
        }
        Err(e) => {
            error!(error = %e, backend = %backend.name, "Backend request failed");
            match e {
                GatewayError::GatewayTimeout => error_response(e, request_id.map(|r| r.inner())),
                GatewayError::ServiceUnavailable { .. } => error_response(
                    GatewayError::ServiceUnavailable {
                        backend: backend.name.clone(),
                    },
                    request_id.map(|r| r.inner()),
                ),
                _ => error_response(e, request_id.map(|r| r.inner())),
            }
        }
    }
}

/// Extract headers that should be forwarded to the backend.
fn extract_forward_headers(headers: &HeaderMap) -> HeaderMap {
    let mut forward_headers = HeaderMap::new();

    // Headers to forward
    let forward_list = [
        "content-type",
        "accept",
        "accept-language",
        "accept-encoding",
        "authorization",
        REQUEST_ID_HEADER,
        TENANT_ID_HEADER,
    ];

    for name in forward_list {
        if let Some(value) = headers.get(name) {
            if let Ok(header_name) = HeaderName::try_from(name) {
                forward_headers.insert(header_name, value.clone());
            }
        }
    }

    forward_headers
}

/// Convert a reqwest response to an axum response.
async fn convert_response(response: reqwest::Response, request_id: Option<uuid::Uuid>) -> Response {
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(status);

    // Copy headers from backend response
    for (name, value) in response.headers() {
        // Skip hop-by-hop headers
        let name_str = name.as_str().to_lowercase();
        if name_str == "transfer-encoding" || name_str == "connection" {
            continue;
        }

        if let Ok(header_name) = HeaderName::try_from(name.as_str()) {
            // Convert reqwest HeaderValue to axum HeaderValue
            if let Ok(value_str) = value.to_str() {
                if let Ok(axum_value) = HeaderValue::from_str(value_str) {
                    builder = builder.header(header_name, axum_value);
                }
            }
        }
    }

    // Add request ID header
    if let Some(id) = request_id {
        if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
            builder = builder.header(REQUEST_ID_HEADER, value);
        }
    }

    // Get response body
    match response.bytes().await {
        Ok(bytes) => builder
            .body(Body::from(bytes.to_vec()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        Err(e) => {
            error!(error = %e, "Failed to read backend response body");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Create an error response.
fn error_response(error: GatewayError, request_id: Option<uuid::Uuid>) -> Response {
    let status = error.status_code();
    let body = ErrorResponse {
        error: error.error_code().to_string(),
        message: error.to_string(),
        request_id,
    };

    let mut response = (status, Json(body)).into_response();

    // Add request ID header
    if let Some(id) = request_id {
        if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
            response.headers_mut().insert(REQUEST_ID_HEADER, value);
        }
    }

    // Add Retry-After for rate limiting
    if let GatewayError::RateLimited { retry_after } = error {
        response
            .headers_mut()
            .insert("Retry-After", retry_after.to_string().parse().unwrap());
    }

    response
}
