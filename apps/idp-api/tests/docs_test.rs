//! Integration tests for API documentation endpoint.
//!
//! These tests verify the /docs endpoint serves Swagger UI.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Minimal OpenAPI doc for testing.
#[derive(OpenApi)]
#[openapi(info(title = "Test API", version = "1.0.0"))]
struct TestApiDoc;

/// Create a test router with Swagger UI.
fn test_docs_router() -> Router {
    Router::new().merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", TestApiDoc::openapi()))
}

#[tokio::test]
async fn test_docs_endpoint_returns_html() {
    let app = test_docs_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/docs/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Swagger UI redirects or returns HTML
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::MOVED_PERMANENTLY,
        "Expected 200 OK or 301 redirect, got {}",
        response.status()
    );
}

#[tokio::test]
async fn test_openapi_json_endpoint_exists() {
    let app = test_docs_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-doc/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");

    assert!(
        content_type.contains("application/json"),
        "Expected JSON content type, got: {}",
        content_type
    );
}

#[tokio::test]
async fn test_openapi_json_contains_info() {
    let app = test_docs_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api-doc/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Verify OpenAPI structure
    assert!(
        json.get("openapi").is_some(),
        "Expected openapi version field"
    );
    assert!(json.get("info").is_some(), "Expected info section");
    assert_eq!(json["info"]["title"], "Test API");
}
