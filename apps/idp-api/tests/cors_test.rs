//! Integration tests for CORS configuration.
//!
//! These tests verify CORS preflight handling.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    routing::post,
    Router,
};
use std::time::Duration;
use tower::ServiceExt;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

/// Create a test router with CORS allowing specific origins.
fn test_router_with_specific_origins(allowed: &[&str]) -> Router {
    let origins: Vec<_> = allowed.iter().filter_map(|o| o.parse().ok()).collect();

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(Any)
        .allow_headers(Any)
        .max_age(Duration::from_secs(3600));

    Router::new()
        .route("/test", post(|| async { "ok" }))
        .layer(cors)
}

/// Create a test router with CORS allowing all origins.
fn test_router_with_any_origin() -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods(Any)
        .allow_headers(Any)
        .max_age(Duration::from_secs(3600));

    Router::new()
        .route("/test", post(|| async { "ok" }))
        .layer(cors)
}

#[tokio::test]
async fn test_cors_preflight_allowed_origin() {
    let app = test_router_with_specific_origins(&["http://localhost:3000"]);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/test")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Check CORS headers
    let allow_origin = response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    assert!(
        allow_origin.is_some(),
        "Expected Access-Control-Allow-Origin header"
    );
    assert_eq!(
        allow_origin.unwrap().to_str().unwrap(),
        "http://localhost:3000"
    );
}

#[tokio::test]
async fn test_cors_preflight_disallowed_origin() {
    let app = test_router_with_specific_origins(&["http://localhost:3000"]);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/test")
                .header(header::ORIGIN, "http://evil.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The request should succeed but without CORS headers for disallowed origin
    // tower-http CORS returns 200 but without Access-Control-Allow-Origin
    let allow_origin = response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN);

    // For disallowed origins, the header should either be missing or not match
    if let Some(origin) = allow_origin {
        assert_ne!(
            origin.to_str().unwrap(),
            "http://evil.com",
            "Should not allow evil.com origin"
        );
    }
}

#[tokio::test]
async fn test_cors_any_origin_allows_all() {
    let app = test_router_with_any_origin();

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/test")
                .header(header::ORIGIN, "http://any-site.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let allow_origin = response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    assert!(allow_origin.is_some());

    // With any() origin, the header is "*"
    assert_eq!(allow_origin.unwrap().to_str().unwrap(), "*");
}

#[tokio::test]
async fn test_cors_preflight_includes_max_age() {
    let app = test_router_with_specific_origins(&["http://localhost:3000"]);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/test")
                .header(header::ORIGIN, "http://localhost:3000")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let max_age = response.headers().get(header::ACCESS_CONTROL_MAX_AGE);
    assert!(max_age.is_some(), "Expected Access-Control-Max-Age header");
    assert_eq!(max_age.unwrap().to_str().unwrap(), "3600");
}
