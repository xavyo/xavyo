//! Integration tests for request tracing.
//!
//! These tests verify request ID generation and propagation.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use tower::ServiceExt;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

/// Create a test router with request ID middleware.
/// Note: `PropagateRequestIdLayer` must be outermost to propagate the ID to response.
fn test_router_with_request_id() -> Router {
    Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

#[tokio::test]
async fn test_request_id_generated_when_not_provided() {
    let app = test_router_with_request_id();

    let response = app
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check that X-Request-Id header is present in response
    let request_id = response.headers().get("x-request-id");
    assert!(
        request_id.is_some(),
        "Expected X-Request-Id header in response"
    );

    // Verify it's a valid UUID format
    let id_str = request_id.unwrap().to_str().unwrap();
    assert!(
        uuid::Uuid::parse_str(id_str).is_ok(),
        "Expected valid UUID, got: {id_str}"
    );
}

#[tokio::test]
async fn test_request_id_propagated_when_provided() {
    let app = test_router_with_request_id();
    let custom_id = "custom-request-id-12345";

    let response = app
        .oneshot(
            Request::builder()
                .uri("/test")
                .header("x-request-id", custom_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check that the provided X-Request-Id is propagated
    let request_id = response.headers().get("x-request-id");
    assert!(
        request_id.is_some(),
        "Expected X-Request-Id header in response"
    );
    assert_eq!(request_id.unwrap().to_str().unwrap(), custom_id);
}

#[tokio::test]
async fn test_different_requests_get_different_ids() {
    let app = test_router_with_request_id();

    let response1 = app
        .clone()
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let response2 = app
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let id1 = response1
        .headers()
        .get("x-request-id")
        .expect("Expected X-Request-Id in response1")
        .to_str()
        .unwrap();
    let id2 = response2
        .headers()
        .get("x-request-id")
        .expect("Expected X-Request-Id in response2")
        .to_str()
        .unwrap();

    // Different requests should get different IDs
    assert_ne!(
        id1, id2,
        "Expected different request IDs for different requests"
    );
}
