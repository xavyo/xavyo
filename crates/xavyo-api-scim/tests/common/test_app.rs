//! Test application builder for SCIM endpoint testing.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Router,
};
use serde_json::Value;
use tower::ServiceExt;

/// Test application wrapper for making SCIM requests.
pub struct TestApp {
    router: Router,
    bearer_token: String,
}

impl TestApp {
    /// Create a new test application with the given router and bearer token.
    pub fn new(router: Router, bearer_token: impl Into<String>) -> Self {
        Self {
            router,
            bearer_token: bearer_token.into(),
        }
    }

    /// Make a GET request to the given path.
    pub async fn get(&self, path: &str) -> TestResponse {
        self.request(Method::GET, path, None).await
    }

    /// Make a POST request with JSON body.
    pub async fn post(&self, path: &str, body: Value) -> TestResponse {
        self.request(Method::POST, path, Some(body)).await
    }

    /// Make a PUT request with JSON body.
    pub async fn put(&self, path: &str, body: Value) -> TestResponse {
        self.request(Method::PUT, path, Some(body)).await
    }

    /// Make a PATCH request with JSON body.
    pub async fn patch(&self, path: &str, body: Value) -> TestResponse {
        self.request(Method::PATCH, path, Some(body)).await
    }

    /// Make a DELETE request.
    pub async fn delete(&self, path: &str) -> TestResponse {
        self.request(Method::DELETE, path, None).await
    }

    /// Make a request with custom headers (for IdP-specific testing).
    pub async fn request_with_headers(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        headers: Vec<(&str, &str)>,
    ) -> TestResponse {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("Authorization", format!("Bearer {}", self.bearer_token))
            .header("Content-Type", "application/scim+json");

        for (key, value) in headers {
            builder = builder.header(key, value);
        }

        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let request = builder.body(Body::from(body_str)).unwrap();

        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to execute request");

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");
        let body: Value = serde_json::from_slice(&body_bytes).unwrap_or_else(|_| Value::Null);

        TestResponse { status, body }
    }

    async fn request(&self, method: Method, path: &str, body: Option<Value>) -> TestResponse {
        self.request_with_headers(method, path, body, vec![]).await
    }
}

/// Response from a test request.
#[derive(Debug)]
pub struct TestResponse {
    pub status: StatusCode,
    pub body: Value,
}

impl TestResponse {
    /// Assert the response status is OK (200).
    pub fn assert_ok(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::OK,
            "Expected 200 OK, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Assert the response status is Created (201).
    pub fn assert_created(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::CREATED,
            "Expected 201 Created, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Assert the response status is No Content (204).
    pub fn assert_no_content(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::NO_CONTENT,
            "Expected 204 No Content, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Assert the response status is Bad Request (400).
    pub fn assert_bad_request(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "Expected 400 Bad Request, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Assert the response status is Not Found (404).
    pub fn assert_not_found(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::NOT_FOUND,
            "Expected 404 Not Found, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Assert the response status is Conflict (409).
    pub fn assert_conflict(&self) -> &Self {
        assert_eq!(
            self.status,
            StatusCode::CONFLICT,
            "Expected 409 Conflict, got {}: {:?}",
            self.status,
            self.body
        );
        self
    }

    /// Get the response body as a reference.
    pub fn json(&self) -> &Value {
        &self.body
    }

    /// Get a field from the response body.
    pub fn get(&self, field: &str) -> &Value {
        &self.body[field]
    }

    /// Get the ID from a SCIM resource response.
    pub fn id(&self) -> Option<&str> {
        self.body["id"].as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_assertions() {
        let response = TestResponse {
            status: StatusCode::OK,
            body: serde_json::json!({"id": "123"}),
        };
        response.assert_ok();
        assert_eq!(response.id(), Some("123"));
    }
}
