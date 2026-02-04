//! HTTP client for backend services with connection pooling.

use axum::http::HeaderMap;
use reqwest::{Client, Response};
use std::time::Duration;

use crate::config::BackendConfig;
use crate::error::{GatewayError, GatewayResult};

/// HTTP client for proxying requests to backend services.
#[derive(Debug, Clone)]
pub struct ProxyClient {
    client: Client,
}

impl ProxyClient {
    /// Create a new proxy client with default settings.
    pub fn new() -> GatewayResult<Self> {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new proxy client with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> GatewayResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| GatewayError::Internal(e.into()))?;

        Ok(Self { client })
    }

    /// Convert axum `HeaderMap` to reqwest headers.
    fn convert_headers(&self, headers: &HeaderMap) -> reqwest::header::HeaderMap {
        let mut reqwest_headers = reqwest::header::HeaderMap::new();
        for (name, value) in headers {
            if let Ok(reqwest_name) = reqwest::header::HeaderName::try_from(name.as_str()) {
                if let Ok(value_str) = value.to_str() {
                    if let Ok(reqwest_value) = reqwest::header::HeaderValue::from_str(value_str) {
                        reqwest_headers.insert(reqwest_name, reqwest_value);
                    }
                }
            }
        }
        reqwest_headers
    }

    /// Send a GET request to a backend service.
    pub async fn get(&self, url: &str, headers: &HeaderMap) -> GatewayResult<Response> {
        self.client
            .get(url)
            .headers(self.convert_headers(headers))
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))
    }

    /// Send a POST request with body to a backend service.
    pub async fn post(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &HeaderMap,
    ) -> GatewayResult<Response> {
        self.client
            .post(url)
            .headers(self.convert_headers(headers))
            .body(body)
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))
    }

    /// Send a PUT request with body to a backend service.
    pub async fn put(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &HeaderMap,
    ) -> GatewayResult<Response> {
        self.client
            .put(url)
            .headers(self.convert_headers(headers))
            .body(body)
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))
    }

    /// Send a DELETE request to a backend service.
    pub async fn delete(&self, url: &str, headers: &HeaderMap) -> GatewayResult<Response> {
        self.client
            .delete(url)
            .headers(self.convert_headers(headers))
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))
    }

    /// Send a PATCH request with body to a backend service.
    pub async fn patch(
        &self,
        url: &str,
        body: Vec<u8>,
        headers: &HeaderMap,
    ) -> GatewayResult<Response> {
        self.client
            .patch(url)
            .headers(self.convert_headers(headers))
            .body(body)
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))
    }

    /// Perform a health check on a backend service (no header forwarding needed).
    pub async fn health_check(&self, backend: &BackendConfig) -> Result<Duration, String> {
        let url = format!("{}{}", backend.url, backend.health_path);
        let start = std::time::Instant::now();

        match self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => Ok(start.elapsed()),
            Ok(response) => Err(format!(
                "Health check returned status {}",
                response.status()
            )),
            Err(e) => Err(format!("Health check failed: {e}")),
        }
    }

    /// Fetch `OpenAPI` spec from a backend service.
    pub async fn fetch_openapi(&self, backend: &BackendConfig) -> GatewayResult<String> {
        let url = format!("{}{}", backend.url, backend.openapi_path);

        let response = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| self.map_reqwest_error(e))?;

        if !response.status().is_success() {
            return Err(GatewayError::ServiceUnavailable {
                backend: backend.name.clone(),
            });
        }

        response
            .text()
            .await
            .map_err(|e| GatewayError::Internal(e.into()))
    }

    /// Map reqwest errors to gateway errors.
    fn map_reqwest_error(&self, error: reqwest::Error) -> GatewayError {
        if error.is_timeout() {
            GatewayError::GatewayTimeout
        } else if error.is_connect() {
            GatewayError::ServiceUnavailable {
                backend: "unknown".to_string(),
            }
        } else {
            GatewayError::Internal(error.into())
        }
    }
}

// Note: Default impl removed intentionally - ProxyClient::new() returns Result
// and should be handled explicitly by callers.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_client_new() {
        let client = ProxyClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_proxy_client_with_timeout() {
        let client = ProxyClient::with_timeout(Duration::from_secs(60));
        assert!(client.is_ok());
    }
}
