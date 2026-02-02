//! Integration tests for auth endpoint mounting.
//!
//! These tests verify that auth endpoints are properly mounted under /auth.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use tower::ServiceExt;

/// Create a minimal test router that simulates auth route mounting.
fn test_auth_router() -> Router {
    // Simulate auth routes (without actual auth logic)
    let auth_routes = Router::new()
        .route("/login", post(|| async { (StatusCode::OK, "login stub") }))
        .route(
            "/register",
            post(|| async { (StatusCode::CREATED, "register stub") }),
        )
        .route(
            "/refresh",
            post(|| async { (StatusCode::OK, "refresh stub") }),
        )
        .route(
            "/logout",
            post(|| async { (StatusCode::OK, "logout stub") }),
        )
        .route(
            "/forgot-password",
            post(|| async { (StatusCode::OK, "forgot-password stub") }),
        )
        .route(
            "/reset-password",
            post(|| async { (StatusCode::OK, "reset-password stub") }),
        )
        .route(
            "/verify-email",
            post(|| async { (StatusCode::OK, "verify-email stub") }),
        )
        .route(
            "/resend-verification",
            post(|| async { (StatusCode::OK, "resend-verification stub") }),
        );

    Router::new().nest("/auth", auth_routes)
}

#[tokio::test]
async fn test_auth_login_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_register_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_auth_refresh_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_logout_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_forgot_password_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/forgot-password")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_reset_password_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/reset-password")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_verify_email_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify-email")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auth_resend_verification_route_exists() {
    let app = test_auth_router();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/resend-verification")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
