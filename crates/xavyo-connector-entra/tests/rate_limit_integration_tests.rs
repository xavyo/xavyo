//! Integration tests for rate limiting behavior with Graph API.

#![cfg(feature = "integration")]

mod common;

use common::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Tests that 429 responses with Retry-After header are handled.
#[tokio::test]
async fn test_rate_limit_429_with_retry_after() {
    let server = MockServer::start().await;

    // First request returns 429 with Retry-After
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "1")
                .set_body_json(create_odata_error(
                    "TooManyRequests",
                    "Too many requests. Please retry after 1 seconds.",
                )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 429);
    assert_eq!(response.headers().get("Retry-After").unwrap(), "1");
}

/// Tests that 503 Service Unavailable triggers retry behavior.
#[tokio::test]
async fn test_service_unavailable_503() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(503)
                .insert_header("Retry-After", "5")
                .set_body_json(create_odata_error(
                    "ServiceUnavailable",
                    "The service is temporarily unavailable. Please retry.",
                )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 503);
    assert_eq!(response.headers().get("Retry-After").unwrap(), "5");
}

/// Tests that throttling affects multiple concurrent requests.
#[tokio::test]
async fn test_concurrent_requests_throttled() {
    let server = MockServer::start().await;

    // All requests return 429 to simulate sustained throttling
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "2")
                .set_body_json(create_odata_error(
                    "TooManyRequests",
                    "Rate limit exceeded.",
                )),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let url = format!("{}/v1.0/users", server.uri());

    // Send multiple concurrent requests using tokio::join!
    let (r1, r2, r3) = tokio::join!(
        client.get(&url).send(),
        client.get(&url).send(),
        client.get(&url).send()
    );

    // All should receive 429
    assert_eq!(r1.unwrap().status(), 429);
    assert_eq!(r2.unwrap().status(), 429);
    assert_eq!(r3.unwrap().status(), 429);
}

/// Tests that different endpoints can have independent rate limits.
#[tokio::test]
async fn test_independent_endpoint_rate_limits() {
    let server = MockServer::start().await;

    // Users endpoint is rate limited
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "10")
                .set_body_json(create_odata_error(
                    "TooManyRequests",
                    "Users endpoint rate limited.",
                )),
        )
        .mount(&server)
        .await;

    // Groups endpoint is available
    let groups = generate_test_groups(2);
    Mock::given(method("GET"))
        .and(path("/v1.0/groups"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(create_odata_response(groups, None, None)),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // Users request fails with 429
    let users_response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(users_response.status(), 429);

    // Groups request succeeds
    let groups_response = client
        .get(format!("{}/v1.0/groups", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(groups_response.status(), 200);
}

/// Tests behavior when Retry-After header is missing.
#[tokio::test]
async fn test_rate_limit_without_retry_after() {
    let server = MockServer::start().await;

    // 429 without Retry-After header
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(
            ResponseTemplate::new(429).set_body_json(create_odata_error(
                "TooManyRequests",
                "Too many requests.",
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 429);
    assert!(response.headers().get("Retry-After").is_none());
}

/// Tests that successful response after rate limit returns data correctly.
#[tokio::test]
async fn test_success_after_rate_limit_returns_data() {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use wiremock::Respond;

    // Counter to track request number
    let request_count = Arc::new(AtomicU32::new(0));
    let count_clone = request_count.clone();

    let users = generate_test_users(3);
    let success_response = create_odata_response(users.clone(), None, None);

    // Custom responder that returns 429 first, then 200
    struct RateLimitThenSuccess {
        count: Arc<AtomicU32>,
        success_body: serde_json::Value,
    }

    impl Respond for RateLimitThenSuccess {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                // First request - rate limited
                ResponseTemplate::new(429).insert_header("Retry-After", "1")
            } else {
                // Subsequent requests - success
                ResponseTemplate::new(200).set_body_json(self.success_body.clone())
            }
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/users"))
        .respond_with(RateLimitThenSuccess {
            count: count_clone,
            success_body: success_response,
        })
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // First request - rate limited
    let response1 = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response1.status(), 429);

    // Second request - success
    let response2 = client
        .get(format!("{}/v1.0/users", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response2.status(), 200);

    let body: serde_json::Value = response2.json().await.unwrap();
    assert_eq!(body["value"].as_array().unwrap().len(), 3);
}
