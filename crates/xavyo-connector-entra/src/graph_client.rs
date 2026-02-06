//! Microsoft Graph API HTTP client with pagination and rate limiting.

use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, instrument, warn};

use crate::metrics::RateLimitMetrics;
use crate::rate_limit::{RateLimitConfig, RateLimiter};
use crate::{EntraCloudEnvironment, EntraError, EntraResult, TokenCache};

/// `OData` error response from Microsoft Graph.
#[derive(Debug, Deserialize)]
pub struct ODataError {
    pub error: ODataErrorBody,
}

/// `OData` error body.
#[derive(Debug, Deserialize)]
pub struct ODataErrorBody {
    pub code: String,
    pub message: String,
    #[serde(rename = "innerError")]
    pub inner_error: Option<serde_json::Value>,
}

/// Response wrapper for paginated Graph API responses.
#[derive(Debug, Deserialize)]
pub struct ODataResponse<T> {
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.deltaLink")]
    pub delta_link: Option<String>,
}

/// Microsoft Graph API client.
#[derive(Debug)]
pub struct GraphClient {
    http_client: reqwest::Client,
    token_cache: Arc<TokenCache>,
    cloud_environment: EntraCloudEnvironment,
    api_version: String,
    max_retries: u32,
    rate_limiter: Arc<RateLimiter>,
}

impl GraphClient {
    /// Creates a new Graph client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(
        token_cache: Arc<TokenCache>,
        cloud_environment: EntraCloudEnvironment,
        api_version: String,
    ) -> EntraResult<Self> {
        Self::with_rate_limit_config(
            token_cache,
            cloud_environment,
            api_version,
            RateLimitConfig::default(),
        )
    }

    /// Creates a new Graph client with custom rate limit configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created or rate limit config is invalid.
    pub fn with_rate_limit_config(
        token_cache: Arc<TokenCache>,
        cloud_environment: EntraCloudEnvironment,
        api_version: String,
        rate_limit_config: RateLimitConfig,
    ) -> EntraResult<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| EntraError::Config(format!("Failed to create HTTP client: {e}")))?;

        let rate_limiter = RateLimiter::new(rate_limit_config)
            .map_err(|e| EntraError::Config(format!("Invalid rate limit config: {e}")))?;

        Ok(Self {
            http_client,
            token_cache,
            cloud_environment,
            api_version,
            max_retries: 5,
            rate_limiter: Arc::new(rate_limiter),
        })
    }

    /// Returns the rate limiter for direct access.
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<RateLimiter> {
        &self.rate_limiter
    }

    /// Returns current rate limit metrics.
    pub async fn rate_limit_metrics(&self) -> RateLimitMetrics {
        self.rate_limiter.get_metrics().await
    }

    /// Returns the base URL for Graph API requests.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!(
            "{}/{}",
            self.cloud_environment.graph_endpoint(),
            self.api_version
        )
    }

    /// Performs a GET request with automatic token injection and retry handling.
    #[instrument(skip(self))]
    pub async fn get<T: DeserializeOwned>(&self, url: &str) -> EntraResult<T> {
        self.request_with_retry(reqwest::Method::GET, url, None::<&()>)
            .await
    }

    /// Performs a POST request with automatic token injection and retry handling.
    #[instrument(skip(self, body))]
    pub async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> EntraResult<T> {
        self.request_with_retry(reqwest::Method::POST, url, Some(body))
            .await
    }

    /// Performs a PATCH request with automatic token injection and retry handling.
    #[instrument(skip(self, body))]
    pub async fn patch<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> EntraResult<T> {
        self.request_with_retry(reqwest::Method::PATCH, url, Some(body))
            .await
    }

    /// Performs a DELETE request with automatic token injection and retry handling.
    #[instrument(skip(self))]
    pub async fn delete(&self, url: &str) -> EntraResult<()> {
        self.request_with_retry_no_body(reqwest::Method::DELETE, url)
            .await
    }

    /// Internal method that performs the request with retry logic.
    async fn request_with_retry<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&B>,
    ) -> EntraResult<T> {
        // Check circuit breaker before attempting request
        self.rate_limiter.should_allow_request().await?;

        let mut retries = 0;
        let mut rate_limit_attempts = 0u32;
        let mut delay = Duration::from_secs(1);

        loop {
            let token = self.token_cache.get_token().await?;

            let mut request = self
                .http_client
                .request(method.clone(), url)
                .bearer_auth(&token);

            if let Some(b) = body {
                request = request.json(b);
            }

            let response = request.send().await?;
            let status = response.status();

            // Handle rate limiting (429) using RateLimiter
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok());

                // Use rate limiter to handle with exponential backoff and jitter
                self.rate_limiter
                    .handle_rate_limit_response(retry_after, rate_limit_attempts)
                    .await?;

                rate_limit_attempts += 1;
                continue;
            }

            // Handle transient errors (502, 503, 504)
            if matches!(
                status,
                reqwest::StatusCode::BAD_GATEWAY
                    | reqwest::StatusCode::SERVICE_UNAVAILABLE
                    | reqwest::StatusCode::GATEWAY_TIMEOUT
            ) && retries < self.max_retries
            {
                retries += 1;
                warn!(
                    "Transient error {}, retry {}/{} after {:?}",
                    status, retries, self.max_retries, delay
                );
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
                continue;
            }

            // Handle success
            if status.is_success() {
                self.rate_limiter.record_success().await;
                return response.json().await.map_err(EntraError::from);
            }

            // Handle errors
            let error_body = response.text().await.unwrap_or_default();
            if let Ok(odata_error) = serde_json::from_str::<ODataError>(&error_body) {
                return Err(EntraError::GraphApi {
                    code: odata_error.error.code,
                    message: odata_error.error.message,
                    inner_error: odata_error.error.inner_error.map(|v| v.to_string()),
                });
            }

            return Err(EntraError::GraphApi {
                code: status.to_string(),
                message: error_body,
                inner_error: None,
            });
        }
    }

    /// Internal method for DELETE requests that don't return a body.
    async fn request_with_retry_no_body(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> EntraResult<()> {
        // Check circuit breaker before attempting request
        self.rate_limiter.should_allow_request().await?;

        let mut retries = 0;
        let mut rate_limit_attempts = 0u32;
        let mut delay = Duration::from_secs(1);

        loop {
            let token = self.token_cache.get_token().await?;

            let response = self
                .http_client
                .request(method.clone(), url)
                .bearer_auth(&token)
                .send()
                .await?;

            let status = response.status();

            // Handle rate limiting using RateLimiter
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry_after = response
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok());

                // Use rate limiter to handle with exponential backoff and jitter
                self.rate_limiter
                    .handle_rate_limit_response(retry_after, rate_limit_attempts)
                    .await?;

                rate_limit_attempts += 1;
                continue;
            }

            // Handle transient errors
            if matches!(
                status,
                reqwest::StatusCode::BAD_GATEWAY
                    | reqwest::StatusCode::SERVICE_UNAVAILABLE
                    | reqwest::StatusCode::GATEWAY_TIMEOUT
            ) && retries < self.max_retries
            {
                retries += 1;
                warn!(
                    "Transient error {}, retry {}/{} after {:?}",
                    status, retries, self.max_retries, delay
                );
                tokio::time::sleep(delay).await;
                delay *= 2;
                continue;
            }

            // Success (usually 204 No Content for DELETE)
            if status.is_success() {
                self.rate_limiter.record_success().await;
                return Ok(());
            }

            // Handle errors
            let error_body = response.text().await.unwrap_or_default();
            if let Ok(odata_error) = serde_json::from_str::<ODataError>(&error_body) {
                return Err(EntraError::GraphApi {
                    code: odata_error.error.code,
                    message: odata_error.error.message,
                    inner_error: odata_error.error.inner_error.map(|v| v.to_string()),
                });
            }

            return Err(EntraError::GraphApi {
                code: status.to_string(),
                message: error_body,
                inner_error: None,
            });
        }
    }

    /// Fetches all pages of a paginated response, processing each page via callback.
    #[instrument(skip(self, callback))]
    pub async fn get_paginated<T, F>(
        &self,
        initial_url: &str,
        mut callback: F,
    ) -> EntraResult<Option<String>>
    where
        T: DeserializeOwned,
        F: FnMut(Vec<T>) -> EntraResult<()>,
    {
        let mut url = initial_url.to_string();

        loop {
            debug!("Fetching page: {}", url);
            let response: ODataResponse<T> = self.get(&url).await?;

            callback(response.value)?;

            if let Some(next) = response.next_link {
                url = next;
            } else {
                return Ok(response.delta_link);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_odata_error_parsing() {
        let json = r#"{
            "error": {
                "code": "Request_ResourceNotFound",
                "message": "Resource not found",
                "innerError": {"date": "2024-01-15"}
            }
        }"#;

        let error: ODataError = serde_json::from_str(json).unwrap();
        assert_eq!(error.error.code, "Request_ResourceNotFound");
        assert_eq!(error.error.message, "Resource not found");
        assert!(error.error.inner_error.is_some());
    }

    #[test]
    fn test_odata_response_parsing() {
        let json = r#"{
            "value": [{"id": "1"}, {"id": "2"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=xxx"
        }"#;

        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct TestItem {
            id: String,
        }

        let response: ODataResponse<TestItem> = serde_json::from_str(json).unwrap();
        assert_eq!(response.value.len(), 2);
        assert!(response.next_link.is_some());
        assert!(response.delta_link.is_none());
    }
}
