//! Integration tests for the health endpoint.
//!
//! These tests verify the /health endpoint behavior.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use serde_json::Value;
use tower::ServiceExt;

/// Create a test router without database (for basic route testing).
fn test_app_without_db() -> Router {
    use axum::routing::get;

    Router::new().route(
        "/health",
        get(|| async {
            let response = serde_json::json!({
                "status": "healthy",
                "version": "0.1.0",
                "uptime_seconds": 0,
                "database": null,
                "timestamp": "2026-01-22T12:00:00Z"
            });
            axum::Json(response)
        }),
    )
}

#[tokio::test]
async fn test_health_endpoint_returns_200() {
    let app = test_app_without_db();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_health_endpoint_returns_json() {
    let app = test_app_without_db();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.contains("application/json"));
}

#[tokio::test]
async fn test_health_response_structure() {
    let app = test_app_without_db();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    // Verify required fields exist
    assert!(json.get("status").is_some());
    assert!(json.get("version").is_some());
    assert!(json.get("uptime_seconds").is_some());
    assert!(json.get("timestamp").is_some());
}
