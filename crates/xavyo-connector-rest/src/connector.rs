//! REST Connector implementation
//!
//! Implements the Connector trait for generic REST APIs.

use async_trait::async_trait;
use reqwest::{header, Client, Response, StatusCode};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, trace, warn};

use xavyo_connector::config::{AuthConfig, ConnectorConfig};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{
    AttributeDelta, AttributeSet, AttributeValue, Filter, PageRequest, SearchResult, Uid,
};
use xavyo_connector::schema::{AttributeDataType, ObjectClass, Schema, SchemaAttribute};
use xavyo_connector::traits::{Connector, CreateOp, DeleteOp, SchemaDiscovery, SearchOp, UpdateOp};
use xavyo_connector::types::ConnectorType;

use crate::config::{HttpMethod, PaginationStyle, RestConfig};
use crate::rate_limit::{parse_retry_after, RateLimiter};

/// REST Connector for provisioning to REST APIs.
pub struct RestConnector {
    /// Configuration.
    config: RestConfig,

    /// Display name for this connector instance.
    display_name: String,

    /// HTTP client.
    client: Arc<Client>,

    /// Cached `OAuth2` token (if using `OAuth2` auth).
    oauth_token: Arc<RwLock<Option<String>>>,

    /// Whether the connector has been disposed.
    disposed: Arc<RwLock<bool>>,

    /// Rate limiter for request throttling.
    rate_limiter: Arc<RateLimiter>,
}

impl std::fmt::Debug for RestConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestConnector")
            .field("config", &self.config.redacted())
            .field("display_name", &self.display_name)
            .finish()
    }
}

impl RestConnector {
    /// Create a new REST connector with the given configuration.
    pub fn new(config: RestConfig) -> ConnectorResult<Self> {
        config.validate()?;

        let display_name = format!("REST: {}", config.base_url);

        // Build HTTP client
        let client = Self::build_client(&config)?;

        // Create rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit.clone()));

        Ok(Self {
            config,
            display_name,
            client: Arc::new(client),
            oauth_token: Arc::new(RwLock::new(None)),
            disposed: Arc::new(RwLock::new(false)),
            rate_limiter,
        })
    }

    /// Build the reqwest client with configuration.
    fn build_client(config: &RestConfig) -> ConnectorResult<Client> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.connection.read_timeout_secs))
            .connect_timeout(Duration::from_secs(
                config.connection.connection_timeout_secs,
            ));

        // Configure TLS
        if !config.tls.verify_certificate {
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder
            .build()
            .map_err(|e| ConnectorError::InvalidConfiguration {
                message: format!("Failed to build HTTP client: {e}"),
            })
    }

    /// Check if disposed.
    async fn check_disposed(&self) -> ConnectorResult<()> {
        if *self.disposed.read().await {
            return Err(ConnectorError::InvalidConfiguration {
                message: "Connector has been disposed".to_string(),
            });
        }
        Ok(())
    }

    /// Get authentication header value.
    async fn get_auth_header(&self) -> ConnectorResult<Option<String>> {
        match &self.config.auth {
            AuthConfig::None => Ok(None),
            AuthConfig::Basic { username, password } => {
                let credentials = format!("{}:{}", username, password.as_deref().unwrap_or(""));
                let encoded = base64_encode(&credentials);
                Ok(Some(format!("Basic {encoded}")))
            }
            AuthConfig::Bearer { token } => Ok(Some(format!("Bearer {token}"))),
            AuthConfig::ApiKey {
                key: _,
                header_name,
            } => {
                // API key is typically set as a header, not Authorization
                // We'll handle this specially in add_auth_headers
                debug!(header_name = %header_name, "Using API key authentication");
                Ok(None)
            }
            AuthConfig::OAuth2 {
                token_url,
                client_id,
                client_secret,
                scopes,
            } => {
                // Check for cached token
                {
                    let token_guard = self.oauth_token.read().await;
                    if let Some(ref token) = *token_guard {
                        return Ok(Some(format!("Bearer {token}")));
                    }
                }

                // Fetch new token
                let token = self
                    .fetch_oauth_token(token_url, client_id, client_secret.as_deref(), scopes)
                    .await?;

                // Cache the token
                {
                    let mut token_guard = self.oauth_token.write().await;
                    *token_guard = Some(token.clone());
                }

                Ok(Some(format!("Bearer {token}")))
            }
        }
    }

    /// Fetch `OAuth2` token using client credentials flow.
    async fn fetch_oauth_token(
        &self,
        token_url: &str,
        client_id: &str,
        client_secret: Option<&str>,
        scopes: &[String],
    ) -> ConnectorResult<String> {
        let mut params = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.to_string()),
        ];

        if let Some(secret) = client_secret {
            params.push(("client_secret", secret.to_string()));
        }

        if !scopes.is_empty() {
            params.push(("scope", scopes.join(" ")));
        }

        let response = self
            .client
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|_e| ConnectorError::AuthenticationFailed)?;

        if !response.status().is_success() {
            return Err(ConnectorError::AuthenticationFailed);
        }

        let body: Value = response.json().await.map_err(|e| {
            ConnectorError::connection_failed_with_source("Failed to parse OAuth response", e)
        })?;

        body.get("access_token")
            .and_then(|v| v.as_str())
            .map(std::string::ToString::to_string)
            .ok_or(ConnectorError::AuthenticationFailed)
    }

    /// Add authentication headers to a request.
    fn add_auth_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth {
            AuthConfig::ApiKey { key, header_name } => builder.header(header_name, key),
            _ => builder,
        }
    }

    /// Add default headers to a request.
    fn add_default_headers(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        builder = builder
            .header(header::CONTENT_TYPE, &self.config.content_type)
            .header(header::ACCEPT, &self.config.accept);

        for (name, value) in &self.config.default_headers {
            builder = builder.header(name, value);
        }

        builder
    }

    /// Build a request with all configured headers.
    async fn build_request(
        &self,
        method: HttpMethod,
        url: &str,
    ) -> ConnectorResult<reqwest::RequestBuilder> {
        self.check_disposed().await?;

        let builder = match method {
            HttpMethod::Get => self.client.get(url),
            HttpMethod::Post => self.client.post(url),
            HttpMethod::Put => self.client.put(url),
            HttpMethod::Patch => self.client.patch(url),
            HttpMethod::Delete => self.client.delete(url),
        };

        let mut builder = self.add_default_headers(builder);
        builder = self.add_auth_headers(builder);

        // Add authorization header
        if let Some(auth_value) = self.get_auth_header().await? {
            builder = builder.header(header::AUTHORIZATION, auth_value);
        }

        Ok(builder)
    }

    /// Send a request with rate limiting and retry logic.
    ///
    /// This method handles:
    /// 1. Rate limit acquisition (blocking until allowed)
    /// 2. Request logging based on verbosity
    /// 3. Automatic retry with exponential backoff for transient errors
    /// 4. Retry-After header parsing for 429 responses
    async fn send_with_retry(
        &self,
        method: HttpMethod,
        url: &str,
        body: Option<&Value>,
    ) -> ConnectorResult<Response> {
        let retry_config = &self.config.retry;
        let verbosity = &self.config.log_verbosity;
        let mut attempt = 0;

        loop {
            attempt += 1;

            // Acquire rate limit permit
            let _guard = self.rate_limiter.acquire(url).await.map_err(|e| {
                ConnectorError::TargetUnavailable {
                    message: format!("Rate limit error: {e}"),
                }
            })?;

            // Build the request
            let mut request = self.build_request(method, url).await?;
            if let Some(json_body) = body {
                request = request.json(json_body);
            }

            // Log request if verbosity allows
            if verbosity.is_enabled() {
                debug!(
                    url = %url,
                    method = %method.as_str(),
                    attempt = attempt,
                    "Sending REST request"
                );
            }
            if verbosity.log_bodies() {
                if let Some(json_body) = body {
                    trace!(body = %json_body, "Request body");
                }
            }

            // Send the request
            let response = request.send().await;

            match response {
                Ok(resp) => {
                    let status = resp.status();

                    // Log response
                    if verbosity.is_enabled() {
                        debug!(
                            url = %url,
                            status = %status,
                            attempt = attempt,
                            "Received REST response"
                        );
                    }

                    // Check if we should retry
                    if retry_config.should_retry(status.as_u16())
                        && attempt <= retry_config.max_retries
                    {
                        // Handle rate limit response specially
                        if status == StatusCode::TOO_MANY_REQUESTS {
                            // Try to parse Retry-After header
                            let retry_after = resp
                                .headers()
                                .get(header::RETRY_AFTER)
                                .and_then(|v| v.to_str().ok())
                                .and_then(parse_retry_after);

                            let wait = retry_after
                                .unwrap_or_else(|| retry_config.calculate_backoff(attempt));

                            warn!(
                                url = %url,
                                attempt = attempt,
                                wait_ms = wait.as_millis(),
                                "Rate limited (429), waiting before retry"
                            );

                            tokio::time::sleep(wait).await;
                            continue;
                        }

                        // Calculate exponential backoff
                        let backoff = retry_config.calculate_backoff(attempt);
                        warn!(
                            url = %url,
                            status = %status,
                            attempt = attempt,
                            wait_ms = backoff.as_millis(),
                            "Transient error, retrying with backoff"
                        );

                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    return Ok(resp);
                }
                Err(e) => {
                    // Network errors - retry if within limits
                    if attempt <= retry_config.max_retries {
                        let backoff = retry_config.calculate_backoff(attempt);
                        warn!(
                            url = %url,
                            error = %e,
                            attempt = attempt,
                            wait_ms = backoff.as_millis(),
                            "Request failed, retrying with backoff"
                        );

                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    return Err(ConnectorError::connection_failed_with_source(
                        format!("Request failed after {attempt} attempts: {url}"),
                        e,
                    ));
                }
            }
        }
    }

    /// Get rate limiter statistics.
    pub async fn rate_limit_stats(&self) -> crate::rate_limit::RateLimitStats {
        self.rate_limiter.stats().await
    }

    /// Handle API response errors.
    fn handle_response_error(&self, status: StatusCode, body: &str) -> ConnectorError {
        // Try to extract error message from response
        let error_message = if let Ok(json) = serde_json::from_str::<Value>(body) {
            json.get(&self.config.response.error_message_path)
                .and_then(|v| v.as_str())
                .map_or_else(|| body.to_string(), std::string::ToString::to_string)
        } else {
            body.to_string()
        };

        match status {
            StatusCode::UNAUTHORIZED => ConnectorError::AuthenticationFailed,
            StatusCode::FORBIDDEN => ConnectorError::AuthorizationFailed {
                operation: "API call".to_string(),
            },
            StatusCode::NOT_FOUND => ConnectorError::ObjectNotFound {
                identifier: "unknown".to_string(),
            },
            StatusCode::CONFLICT => ConnectorError::ObjectAlreadyExists {
                identifier: "unknown".to_string(),
            },
            StatusCode::TOO_MANY_REQUESTS => ConnectorError::TargetUnavailable {
                message: format!("Rate limited: {error_message}"),
            },
            StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::BAD_GATEWAY
            | StatusCode::GATEWAY_TIMEOUT => ConnectorError::TargetUnavailable {
                message: error_message,
            },
            _ => ConnectorError::operation_failed(format!("HTTP {status}: {error_message}")),
        }
    }

    /// Parse JSON response and extract results.
    fn extract_results(&self, body: &Value) -> Vec<Value> {
        if let Some(ref path) = self.config.response.results_path {
            // Extract from nested path
            body.pointer(&format!("/{}", path.replace('.', "/")))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        } else if let Some(arr) = body.as_array() {
            // Response is already an array
            arr.clone()
        } else {
            // Single object response
            vec![body.clone()]
        }
    }

    /// Extract total count from response.
    fn extract_total_count(&self, body: &Value) -> Option<u64> {
        self.config
            .response
            .total_count_path
            .as_ref()
            .and_then(|path| {
                body.pointer(&format!("/{}", path.replace('.', "/")))
                    .and_then(serde_json::Value::as_u64)
            })
    }

    /// Extract next cursor from response.
    fn extract_next_cursor(&self, body: &Value) -> Option<String> {
        self.config
            .response
            .next_cursor_path
            .as_ref()
            .and_then(|path| {
                body.pointer(&format!("/{}", path.replace('.', "/")))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string)
            })
    }

    /// Convert JSON value to `AttributeSet`.
    fn json_to_attribute_set(&self, value: &Value) -> AttributeSet {
        let mut attrs = AttributeSet::new();

        if let Some(obj) = value.as_object() {
            for (key, val) in obj {
                attrs.set(key.clone(), Self::json_to_attribute_value(val));
            }
        }

        attrs
    }

    /// Convert JSON value to `AttributeValue`.
    fn json_to_attribute_value(value: &Value) -> AttributeValue {
        match value {
            Value::Null => AttributeValue::Null,
            Value::Bool(b) => AttributeValue::Boolean(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    AttributeValue::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    AttributeValue::Float(f)
                } else {
                    AttributeValue::String(n.to_string())
                }
            }
            Value::String(s) => AttributeValue::String(s.clone()),
            Value::Array(arr) => {
                AttributeValue::Array(arr.iter().map(Self::json_to_attribute_value).collect())
            }
            Value::Object(map) => AttributeValue::Object(map.clone()),
        }
    }

    /// Convert `AttributeSet` to JSON object.
    fn attribute_set_to_json(&self, attrs: &AttributeSet) -> Value {
        let mut obj = serde_json::Map::new();

        for (key, value) in attrs.iter() {
            obj.insert(key.clone(), Self::attribute_value_to_json(value));
        }

        Value::Object(obj)
    }

    /// Convert `AttributeValue` to JSON value.
    fn attribute_value_to_json(value: &AttributeValue) -> Value {
        match value {
            AttributeValue::Null => Value::Null,
            AttributeValue::String(s) => Value::String(s.clone()),
            AttributeValue::Integer(i) => Value::Number(serde_json::Number::from(*i)),
            AttributeValue::Boolean(b) => Value::Bool(*b),
            AttributeValue::Float(f) => {
                serde_json::Number::from_f64(*f).map_or(Value::Null, Value::Number)
            }
            AttributeValue::Binary(b) => Value::String(base64_encode(b)),
            AttributeValue::Array(arr) => {
                Value::Array(arr.iter().map(Self::attribute_value_to_json).collect())
            }
            AttributeValue::Object(obj) => Value::Object(obj.clone()),
        }
    }

    /// Convert `AttributeDelta` to JSON for update operations.
    fn delta_to_json(&self, changes: &AttributeDelta) -> Value {
        let mut obj = serde_json::Map::new();

        // Add replace operations
        for (key, value) in &changes.replace {
            obj.insert(key.clone(), Self::attribute_value_to_json(value));
        }

        // Add add operations (for simple fields, same as replace)
        for (key, value) in &changes.add {
            obj.insert(key.clone(), Self::attribute_value_to_json(value));
        }

        // Clear operations become null
        for key in &changes.clear {
            obj.insert(key.clone(), Value::Null);
        }

        Value::Object(obj)
    }

    /// Get endpoint and method for an object class operation.
    fn get_endpoint(
        &self,
        object_class: &str,
        operation: &str,
        id: Option<&str>,
    ) -> (String, HttpMethod) {
        let endpoints = &self.config.endpoints;

        match (object_class.to_lowercase().as_str(), operation, id) {
            ("user" | "users", "list", _) => {
                (self.config.url(&endpoints.list_users), HttpMethod::Get)
            }
            ("user" | "users", "get", Some(uid)) => {
                let path = endpoints.endpoint_for_id(&endpoints.get_user, uid);
                (self.config.url(&path), HttpMethod::Get)
            }
            ("user" | "users", "create", _) => {
                (self.config.url(&endpoints.create_user), HttpMethod::Post)
            }
            ("user" | "users", "update", Some(uid)) => {
                let path = endpoints.endpoint_for_id(&endpoints.update_user, uid);
                (self.config.url(&path), endpoints.update_method)
            }
            ("user" | "users", "delete", Some(uid)) => {
                let path = endpoints.endpoint_for_id(&endpoints.delete_user, uid);
                (self.config.url(&path), HttpMethod::Delete)
            }
            ("group" | "groups", "list", _) => {
                (self.config.url(&endpoints.list_groups), HttpMethod::Get)
            }
            ("group" | "groups", "get", Some(uid)) => {
                let path = endpoints.endpoint_for_id(&endpoints.get_group, uid);
                (self.config.url(&path), HttpMethod::Get)
            }
            // Default to treating object class as resource path
            (_, "list", _) => (
                self.config.url(&format!("/{object_class}")),
                HttpMethod::Get,
            ),
            (_, "get", Some(uid)) => (
                self.config.url(&format!("/{object_class}/{uid}")),
                HttpMethod::Get,
            ),
            (_, "create", _) => (
                self.config.url(&format!("/{object_class}")),
                HttpMethod::Post,
            ),
            (_, "update", Some(uid)) => (
                self.config.url(&format!("/{object_class}/{uid}")),
                endpoints.update_method,
            ),
            (_, "delete", Some(uid)) => (
                self.config.url(&format!("/{object_class}/{uid}")),
                HttpMethod::Delete,
            ),
            _ => (
                self.config.url(&format!("/{object_class}")),
                HttpMethod::Get,
            ),
        }
    }

    /// Build pagination query parameters.
    fn build_pagination_params(&self, page: &PageRequest) -> Vec<(String, String)> {
        let pagination = &self.config.pagination;
        let mut params = Vec::new();

        match pagination.style {
            PaginationStyle::PageBased => {
                let page_num = (page.offset / page.page_size) + 1;
                params.push((pagination.page_param.clone(), page_num.to_string()));
                params.push((pagination.size_param.clone(), page.page_size.to_string()));
            }
            PaginationStyle::OffsetBased => {
                params.push((pagination.offset_param.clone(), page.offset.to_string()));
                params.push((pagination.size_param.clone(), page.page_size.to_string()));
            }
            PaginationStyle::CursorBased => {
                if let Some(ref cursor) = page.cursor {
                    params.push(("cursor".to_string(), cursor.clone()));
                }
                params.push((pagination.size_param.clone(), page.page_size.to_string()));
            }
            PaginationStyle::None => {
                // No pagination params
            }
        }

        params
    }
}

/// Base64 encode bytes to string.
fn base64_encode(data: impl AsRef<[u8]>) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

#[async_trait]
impl Connector for RestConnector {
    fn connector_type(&self) -> ConnectorType {
        ConnectorType::Rest
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    #[instrument(skip(self))]
    async fn test_connection(&self) -> ConnectorResult<()> {
        self.check_disposed().await?;

        // Try to fetch the base URL or a health endpoint
        let (url, method) = self.get_endpoint("user", "list", None);

        debug!(url = %url, "Testing REST connection");

        // Use send_with_retry for automatic rate limiting and retry
        let response = self.send_with_retry(method, &url, None).await?;

        let status = response.status();
        if status.is_client_error() || status.is_server_error() {
            let body = response.text().await.unwrap_or_default();

            // 401/403 means we connected but auth failed - still a valid connection
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                warn!(status = %status, "Authentication issue during connection test");
                return Err(ConnectorError::AuthenticationFailed);
            }

            return Err(self.handle_response_error(status, &body));
        }

        info!(
            base_url = %self.config.base_url,
            "REST connection test successful"
        );

        Ok(())
    }

    async fn dispose(&self) -> ConnectorResult<()> {
        *self.disposed.write().await = true;

        // Clear cached OAuth token
        *self.oauth_token.write().await = None;

        info!("REST connector disposed");
        Ok(())
    }
}

#[async_trait]
impl SchemaDiscovery for RestConnector {
    #[instrument(skip(self))]
    async fn discover_schema(&self) -> ConnectorResult<Schema> {
        // Try to discover from OpenAPI spec if URL is provided
        if let Some(ref openapi_url) = self.config.openapi_url {
            if let Ok(schema) = self.discover_from_openapi(openapi_url).await {
                return Ok(schema);
            }
            warn!("Failed to discover schema from OpenAPI, falling back to generic schema");
        }

        // REST APIs don't have a standard schema discovery mechanism.
        // We return a generic schema based on common patterns.
        let mut object_classes = Vec::new();

        // User object class with common attributes
        let user_oc = ObjectClass::new("user", "user")
            .with_display_name("User")
            .with_attribute(SchemaAttribute::new("id", "id", AttributeDataType::String).required())
            .with_attribute(SchemaAttribute::new(
                "username",
                "username",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "email",
                "email",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "firstName",
                "firstName",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "lastName",
                "lastName",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "displayName",
                "displayName",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "active",
                "active",
                AttributeDataType::Boolean,
            ));

        object_classes.push(user_oc);

        // Group object class
        let group_oc = ObjectClass::new("group", "group")
            .with_display_name("Group")
            .with_attribute(SchemaAttribute::new("id", "id", AttributeDataType::String).required())
            .with_attribute(SchemaAttribute::new(
                "name",
                "name",
                AttributeDataType::String,
            ))
            .with_attribute(SchemaAttribute::new(
                "description",
                "description",
                AttributeDataType::String,
            ))
            .with_attribute(
                SchemaAttribute::new("members", "members", AttributeDataType::String)
                    .multi_valued(),
            );

        object_classes.push(group_oc);

        let schema = Schema::with_object_classes(object_classes);

        info!(
            object_class_count = schema.object_classes.len(),
            "REST schema discovery complete (generic schema)"
        );

        Ok(schema)
    }
}

impl RestConnector {
    /// Validate a URL to prevent SSRF attacks.
    ///
    /// SECURITY: This function blocks requests to:
    /// - Private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)
    /// - Link-local addresses (169.254.x)
    /// - Cloud metadata endpoints (169.254.169.254)
    /// - IPv6 loopback and link-local
    /// - File and other non-HTTP schemes
    fn validate_url_for_ssrf(url_str: &str) -> ConnectorResult<()> {
        use std::net::{IpAddr, Ipv4Addr};

        let url = url::Url::parse(url_str).map_err(|e| ConnectorError::InvalidConfiguration {
            message: format!("Invalid URL: {e}"),
        })?;

        // Only allow HTTP and HTTPS
        match url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!("URL scheme '{scheme}' not allowed; only HTTP(S) permitted"),
                });
            }
        }

        // Get the host
        let host = url
            .host_str()
            .ok_or_else(|| ConnectorError::InvalidConfiguration {
                message: "URL must have a host".to_string(),
            })?;

        // Check if it's an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            // Block private and special IP ranges
            let is_blocked = match ip {
                IpAddr::V4(ipv4) => {
                    ipv4.is_loopback()                              // 127.0.0.0/8
                    || ipv4.is_private()                            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    || ipv4.is_link_local()                         // 169.254.0.0/16
                    || ipv4.is_broadcast()                          // 255.255.255.255
                    || ipv4.is_documentation()                      // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                    || ipv4.is_unspecified()                        // 0.0.0.0
                    || ipv4 == Ipv4Addr::new(169, 254, 169, 254) // AWS/GCP/Azure metadata
                }
                IpAddr::V6(ipv6) => {
                    ipv6.is_loopback()                              // ::1
                    || ipv6.is_unspecified()                        // ::
                    || ipv6.segments()[0] == 0xfe80                 // Link-local
                    || ipv6.segments()[0] == 0xfc00                 // Unique local
                    || ipv6.segments()[0] == 0xfd00                 // Unique local
                    || (ipv6.segments()[0..6] == [0, 0, 0, 0, 0, 0xffff]
                        && Self::is_blocked_ipv4_mapped(&ipv6)) // IPv4-mapped IPv6
                }
            };

            if is_blocked {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!("URL host '{host}' is not allowed (internal/private address)"),
                });
            }
        } else {
            // It's a hostname - block localhost and common internal names
            let host_lower = host.to_lowercase();
            let blocked_hosts = [
                "localhost",
                "127.0.0.1",
                "::1",
                "metadata.google.internal",
                "metadata.goog",
                "169.254.169.254",
            ];

            if blocked_hosts
                .iter()
                .any(|&h| host_lower == h || host_lower.ends_with(&format!(".{h}")))
            {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!("URL host '{host}' is not allowed"),
                });
            }
        }

        Ok(())
    }

    /// Check if an IPv4-mapped IPv6 address maps to a blocked IPv4 range.
    fn is_blocked_ipv4_mapped(ipv6: &std::net::Ipv6Addr) -> bool {
        // Extract the IPv4 portion from ::ffff:a.b.c.d
        if let Some(ipv4) = ipv6.to_ipv4_mapped() {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_unspecified()
        } else {
            false
        }
    }

    /// Discover schema from `OpenAPI` specification.
    async fn discover_from_openapi(&self, openapi_url: &str) -> ConnectorResult<Schema> {
        // SECURITY: Validate URL to prevent SSRF attacks
        Self::validate_url_for_ssrf(openapi_url)?;

        // Fetch OpenAPI spec
        let response = self.client.get(openapi_url).send().await.map_err(|e| {
            ConnectorError::SchemaDiscoveryFailed {
                message: format!("Failed to fetch OpenAPI spec from {openapi_url}: {e}"),
            }
        })?;

        if !response.status().is_success() {
            return Err(ConnectorError::SchemaDiscoveryFailed {
                message: format!(
                    "OpenAPI fetch failed with status {}: {}",
                    response.status(),
                    openapi_url
                ),
            });
        }

        let spec: Value =
            response
                .json()
                .await
                .map_err(|e| ConnectorError::SchemaDiscoveryFailed {
                    message: format!("Failed to parse OpenAPI spec: {e}"),
                })?;

        // Parse schemas from OpenAPI components
        let object_classes = self.parse_openapi_schemas(&spec)?;

        info!(
            object_class_count = object_classes.len(),
            "REST schema discovery from OpenAPI complete"
        );

        Ok(Schema::with_object_classes(object_classes))
    }

    /// Parse `OpenAPI` schemas into object classes with property validations.
    fn parse_openapi_schemas(&self, spec: &Value) -> ConnectorResult<Vec<ObjectClass>> {
        let mut object_classes = Vec::new();

        // Get schemas from components (OpenAPI 3.x) or definitions (Swagger 2.x)
        let schemas = spec
            .pointer("/components/schemas")
            .or_else(|| spec.pointer("/definitions"))
            .and_then(|s| s.as_object());

        if let Some(schemas) = schemas {
            for (name, schema) in schemas {
                if let Some(oc) = self.parse_openapi_schema(name, schema) {
                    object_classes.push(oc);
                }
            }
        }

        Ok(object_classes)
    }

    /// Parse a single `OpenAPI` schema into an `ObjectClass`.
    fn parse_openapi_schema(&self, name: &str, schema: &Value) -> Option<ObjectClass> {
        let properties = schema.get("properties")?.as_object()?;
        let required_props: Vec<&str> = schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let mut oc = ObjectClass::new(name, name);

        if let Some(desc) = schema.get("description").and_then(|d| d.as_str()) {
            oc = oc.with_description(desc);
        }

        for (prop_name, prop_schema) in properties {
            let attr = self.parse_openapi_property(
                prop_name,
                prop_schema,
                required_props.contains(&prop_name.as_str()),
            );
            oc = oc.with_attribute(attr);
        }

        Some(oc)
    }

    /// Parse an `OpenAPI` property into a `SchemaAttribute` with validations.
    fn parse_openapi_property(&self, name: &str, prop: &Value, required: bool) -> SchemaAttribute {
        // Determine data type from JSON Schema type
        let json_type = prop
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("string");
        let format = prop.get("format").and_then(|f| f.as_str());

        let data_type = self.json_schema_type_to_attribute_type(json_type, format);

        let mut attr = SchemaAttribute::new(name, name, data_type);

        if required {
            attr = attr.required();
        }

        // Handle array type (multi-valued)
        if json_type == "array" {
            attr = attr.multi_valued();
        }

        // Extract validation constraints (T058 - property validations)

        // minLength / maxLength for strings
        if let Some(min) = prop.get("minLength").and_then(serde_json::Value::as_u64) {
            attr = attr.with_min_length(min as usize);
        }
        if let Some(max) = prop.get("maxLength").and_then(serde_json::Value::as_u64) {
            attr = attr.with_max_length(max as usize);
        }

        // pattern (regex) for strings
        if let Some(pattern) = prop.get("pattern").and_then(|p| p.as_str()) {
            attr = attr.with_pattern(pattern);
        }

        // enum values
        if let Some(enum_values) = prop.get("enum").and_then(|e| e.as_array()) {
            let allowed: Vec<String> = enum_values
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !allowed.is_empty() {
                attr = attr.with_allowed_values(allowed);
            }
        }

        // description
        if let Some(desc) = prop.get("description").and_then(|d| d.as_str()) {
            attr = attr.with_description(desc);
        }

        // readOnly
        if prop
            .get("readOnly")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            attr = attr.read_only();
        }

        // writeOnly (not readable)
        if prop
            .get("writeOnly")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            attr.readable = false;
        }

        attr
    }

    /// Convert JSON Schema type to `AttributeDataType`.
    fn json_schema_type_to_attribute_type(
        &self,
        json_type: &str,
        format: Option<&str>,
    ) -> AttributeDataType {
        match (json_type, format) {
            ("string", Some("uuid")) => AttributeDataType::Uuid,
            ("string", Some("date-time")) => AttributeDataType::DateTime,
            ("string", Some("date")) => AttributeDataType::Date,
            ("string", Some("time")) => AttributeDataType::Timestamp,
            ("string", Some("email")) => AttributeDataType::String,
            ("string", Some("uri")) => AttributeDataType::String,
            ("string", Some("binary")) => AttributeDataType::Binary,
            ("string", Some("byte")) => AttributeDataType::Binary,
            ("string", _) => AttributeDataType::String,
            ("integer", Some("int64")) => AttributeDataType::Long,
            ("integer", _) => AttributeDataType::Integer,
            ("number", Some("float")) => AttributeDataType::Long, // No Float variant
            ("number", Some("double")) => AttributeDataType::Long,
            ("number", _) => AttributeDataType::Long,
            ("boolean", _) => AttributeDataType::Boolean,
            ("array", _) => AttributeDataType::String, // Array items handled separately
            ("object", _) => AttributeDataType::String, // Nested objects as JSON string
            _ => AttributeDataType::String,
        }
    }
}

#[async_trait]
impl CreateOp for RestConnector {
    #[instrument(skip(self, attrs))]
    async fn create(&self, object_class: &str, attrs: AttributeSet) -> ConnectorResult<Uid> {
        let (url, method) = self.get_endpoint(object_class, "create", None);

        debug!(url = %url, object_class = %object_class, "Creating REST object");

        let body = self.attribute_set_to_json(&attrs);

        // Use send_with_retry for automatic rate limiting and retry
        let response = self.send_with_retry(method, &url, Some(&body)).await?;

        let status = response.status();
        if status == StatusCode::CONFLICT {
            return Err(ConnectorError::ObjectAlreadyExists {
                identifier: "unknown".to_string(),
            });
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(self.handle_response_error(status, &body));
        }

        let response_body: Value = response.json().await.map_err(|e| {
            ConnectorError::operation_failed_with_source("Failed to parse create response", e)
        })?;

        // Extract ID from response
        let id = response_body
            .pointer(&format!(
                "/{}",
                self.config.response.id_path.replace('.', "/")
            ))
            .and_then(|v| v.as_str())
            .or_else(|| response_body.get("id").and_then(|v| v.as_str()))
            .map(std::string::ToString::to_string)
            .ok_or_else(|| ConnectorError::InvalidData {
                message: "Response did not contain an ID".to_string(),
            })?;

        info!(object_class = %object_class, id = %id, "REST object created successfully");

        Ok(Uid::from_id(id))
    }
}

#[async_trait]
impl UpdateOp for RestConnector {
    #[instrument(skip(self, changes))]
    async fn update(
        &self,
        object_class: &str,
        uid: &Uid,
        changes: AttributeDelta,
    ) -> ConnectorResult<Uid> {
        let (url, method) = self.get_endpoint(object_class, "update", Some(uid.value()));

        debug!(url = %url, object_class = %object_class, id = %uid.value(), "Updating REST object");

        if changes.is_empty() {
            return Ok(uid.clone());
        }

        let body = self.delta_to_json(&changes);

        // Use send_with_retry for automatic rate limiting and retry
        let response = self.send_with_retry(method, &url, Some(&body)).await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ConnectorError::ObjectNotFound {
                identifier: uid.value().to_string(),
            });
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(self.handle_response_error(status, &body));
        }

        info!(object_class = %object_class, id = %uid.value(), "REST object updated successfully");

        Ok(uid.clone())
    }
}

#[async_trait]
impl DeleteOp for RestConnector {
    #[instrument(skip(self))]
    async fn delete(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        let (url, method) = self.get_endpoint(object_class, "delete", Some(uid.value()));

        debug!(url = %url, object_class = %object_class, id = %uid.value(), "Deleting REST object");

        // Use send_with_retry for automatic rate limiting and retry
        let response = self.send_with_retry(method, &url, None).await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ConnectorError::ObjectNotFound {
                identifier: uid.value().to_string(),
            });
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(self.handle_response_error(status, &body));
        }

        info!(object_class = %object_class, id = %uid.value(), "REST object deleted successfully");

        Ok(())
    }
}

#[async_trait]
impl SearchOp for RestConnector {
    #[instrument(skip(self))]
    async fn search(
        &self,
        object_class: &str,
        filter: Option<Filter>,
        _attributes_to_get: Option<Vec<String>>,
        page: Option<PageRequest>,
    ) -> ConnectorResult<SearchResult> {
        let (url, method) = self.get_endpoint(object_class, "list", None);

        debug!(url = %url, object_class = %object_class, "Searching REST objects");

        let page_info = page.unwrap_or_default();
        let pagination_params = self.build_pagination_params(&page_info);
        let filter_params = filter
            .as_ref()
            .map(|f| self.filter_to_query_params(f))
            .unwrap_or_default();

        let retry_config = &self.config.retry;
        let verbosity = &self.config.log_verbosity;
        let mut attempt = 0;

        let response = loop {
            attempt += 1;

            // Acquire rate limit permit
            let _guard = self.rate_limiter.acquire(&url).await.map_err(|e| {
                ConnectorError::TargetUnavailable {
                    message: format!("Rate limit error: {e}"),
                }
            })?;

            // Build query with pagination
            let mut request = self.build_request(method, &url).await?;
            if !pagination_params.is_empty() {
                request = request.query(&pagination_params);
            }
            if !filter_params.is_empty() {
                request = request.query(&filter_params);
            }

            // Log request if verbosity allows
            if verbosity.is_enabled() {
                debug!(
                    url = %url,
                    method = %method.as_str(),
                    attempt = attempt,
                    "Sending REST search request"
                );
            }

            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();

                    if verbosity.is_enabled() {
                        debug!(url = %url, status = %status, attempt = attempt, "Received search response");
                    }

                    // Check if we should retry
                    if retry_config.should_retry(status.as_u16())
                        && attempt <= retry_config.max_retries
                    {
                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let retry_after = resp
                                .headers()
                                .get(header::RETRY_AFTER)
                                .and_then(|v| v.to_str().ok())
                                .and_then(parse_retry_after);

                            let wait = retry_after
                                .unwrap_or_else(|| retry_config.calculate_backoff(attempt));
                            warn!(url = %url, attempt = attempt, wait_ms = wait.as_millis(), "Rate limited, waiting");
                            tokio::time::sleep(wait).await;
                            continue;
                        }

                        let backoff = retry_config.calculate_backoff(attempt);
                        warn!(url = %url, status = %status, attempt = attempt, wait_ms = backoff.as_millis(), "Retrying search");
                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    break resp;
                }
                Err(e) => {
                    if attempt <= retry_config.max_retries {
                        let backoff = retry_config.calculate_backoff(attempt);
                        warn!(url = %url, error = %e, attempt = attempt, wait_ms = backoff.as_millis(), "Search failed, retrying");
                        tokio::time::sleep(backoff).await;
                        continue;
                    }

                    return Err(ConnectorError::connection_failed_with_source(
                        format!("Search failed after {attempt} attempts"),
                        e,
                    ));
                }
            }
        };

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(self.handle_response_error(status, &body));
        }

        let response_body: Value = response.json().await.map_err(|e| {
            ConnectorError::operation_failed_with_source("Failed to parse search response", e)
        })?;

        // Extract results
        let results = self.extract_results(&response_body);
        let total_count = self.extract_total_count(&response_body);
        let next_cursor = self.extract_next_cursor(&response_body);

        // Convert to AttributeSet
        let objects: Vec<AttributeSet> = results
            .iter()
            .map(|v| {
                let mut attrs = self.json_to_attribute_set(v);

                // Add special attributes
                if let Some(id) = v
                    .get(&self.config.response.id_path)
                    .and_then(|v| v.as_str())
                {
                    attrs.set("__uid__", id.to_string());
                }
                attrs.set("__object_class__", object_class.to_string());

                attrs
            })
            .collect();

        let has_more = next_cursor.is_some()
            || total_count
                .is_some_and(|total| (page_info.offset + objects.len() as u32) < total as u32);

        info!(
            object_class = %object_class,
            result_count = objects.len(),
            total_count = ?total_count,
            "REST search complete"
        );

        Ok(SearchResult {
            objects,
            total_count,
            next_cursor,
            has_more,
        })
    }
}

impl RestConnector {
    /// Convert filter to query parameters (basic implementation).
    fn filter_to_query_params(&self, filter: &Filter) -> Vec<(String, String)> {
        match filter {
            Filter::Equals { attribute, value } => {
                vec![(attribute.clone(), value.clone())]
            }
            Filter::Contains { attribute, value } => {
                // Some APIs support search parameter
                vec![(format!("{attribute}_contains"), value.clone())]
            }
            Filter::And { filters } => filters
                .iter()
                .flat_map(|f| self.filter_to_query_params(f))
                .collect(),
            // Other filter types would need API-specific handling
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rest_connector_new() {
        let config = RestConfig::new("https://api.example.com/v1").with_bearer_token("token123");

        let connector = RestConnector::new(config);
        assert!(connector.is_ok());

        let connector = connector.unwrap();
        assert!(connector.display_name().contains("api.example.com"));
    }

    #[test]
    fn test_rest_connector_invalid_config() {
        let config = RestConfig::new("");

        let connector = RestConnector::new(config);
        assert!(connector.is_err());
    }

    #[test]
    fn test_connector_type() {
        let config = RestConfig::new("https://api.example.com/v1");
        let connector = RestConnector::new(config).unwrap();
        assert_eq!(connector.connector_type(), ConnectorType::Rest);
    }

    #[test]
    fn test_get_endpoint_users() {
        let config = RestConfig::new("https://api.example.com/v1");
        let connector = RestConnector::new(config).unwrap();

        let (url, method) = connector.get_endpoint("user", "list", None);
        assert_eq!(url, "https://api.example.com/v1/users");
        assert_eq!(method, HttpMethod::Get);

        let (url, method) = connector.get_endpoint("user", "get", Some("123"));
        assert_eq!(url, "https://api.example.com/v1/users/123");
        assert_eq!(method, HttpMethod::Get);

        let (url, method) = connector.get_endpoint("user", "create", None);
        assert_eq!(url, "https://api.example.com/v1/users");
        assert_eq!(method, HttpMethod::Post);
    }

    #[test]
    fn test_get_endpoint_groups() {
        let config = RestConfig::new("https://api.example.com/v1");
        let connector = RestConnector::new(config).unwrap();

        let (url, method) = connector.get_endpoint("group", "list", None);
        assert_eq!(url, "https://api.example.com/v1/groups");
        assert_eq!(method, HttpMethod::Get);
    }

    #[test]
    fn test_get_endpoint_custom_resource() {
        let config = RestConfig::new("https://api.example.com/v1");
        let connector = RestConnector::new(config).unwrap();

        let (url, method) = connector.get_endpoint("applications", "list", None);
        assert_eq!(url, "https://api.example.com/v1/applications");
        assert_eq!(method, HttpMethod::Get);
    }

    #[test]
    fn test_json_to_attribute_value() {
        assert_eq!(
            RestConnector::json_to_attribute_value(&Value::Null),
            AttributeValue::Null
        );
        assert_eq!(
            RestConnector::json_to_attribute_value(&Value::Bool(true)),
            AttributeValue::Boolean(true)
        );
        assert_eq!(
            RestConnector::json_to_attribute_value(&Value::Number(42.into())),
            AttributeValue::Integer(42)
        );
        assert_eq!(
            RestConnector::json_to_attribute_value(&Value::String("test".into())),
            AttributeValue::String("test".into())
        );
    }

    #[test]
    fn test_attribute_value_to_json() {
        assert_eq!(
            RestConnector::attribute_value_to_json(&AttributeValue::Null),
            Value::Null
        );
        assert_eq!(
            RestConnector::attribute_value_to_json(&AttributeValue::Boolean(true)),
            Value::Bool(true)
        );
        assert_eq!(
            RestConnector::attribute_value_to_json(&AttributeValue::Integer(42)),
            Value::Number(42.into())
        );
        assert_eq!(
            RestConnector::attribute_value_to_json(&AttributeValue::String("test".into())),
            Value::String("test".into())
        );
    }

    #[test]
    fn test_pagination_params_page_based() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let page = PageRequest::new(50).with_offset(100);
        let params = connector.build_pagination_params(&page);

        assert!(params.iter().any(|(k, v)| k == "page" && v == "3")); // 100/50 + 1
        assert!(params.iter().any(|(k, v)| k == "pageSize" && v == "50"));
    }

    #[test]
    fn test_filter_to_query_params() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let filter = Filter::Equals {
            attribute: "username".to_string(),
            value: "john".to_string(),
        };

        let params = connector.filter_to_query_params(&filter);
        assert_eq!(params, vec![("username".to_string(), "john".to_string())]);
    }

    #[test]
    fn test_extract_results_with_path() {
        let config = RestConfig::new("https://api.example.com");
        let mut connector = RestConnector::new(config).unwrap();

        // Modify config to have results_path
        connector.config.response.results_path = Some("data".to_string());

        let body = serde_json::json!({
            "data": [
                {"id": "1", "name": "User 1"},
                {"id": "2", "name": "User 2"}
            ],
            "total": 2
        });

        let results = connector.extract_results(&body);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_extract_results_array() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let body = serde_json::json!([
            {"id": "1", "name": "User 1"},
            {"id": "2", "name": "User 2"}
        ]);

        let results = connector.extract_results(&body);
        assert_eq!(results.len(), 2);
    }

    // =========================================================================
    // Schema Discovery Tests (T016 - REST default schema structure)
    // =========================================================================

    #[tokio::test]
    async fn test_rest_schema_discovery_default_structure() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let schema = connector.discover_schema().await.unwrap();

        // REST provides a default schema with user and group object classes
        assert_eq!(schema.object_classes.len(), 2);

        // Find user object class
        let user_oc = schema.object_classes.iter().find(|oc| oc.name == "user");
        assert!(user_oc.is_some(), "user object class should exist");
        let user_oc = user_oc.unwrap();

        // Verify user attributes exist
        let user_attrs: Vec<&str> = user_oc.attributes.iter().map(|a| a.name.as_str()).collect();
        assert!(user_attrs.contains(&"id"));
        assert!(user_attrs.contains(&"username"));
        assert!(user_attrs.contains(&"email"));
        assert!(user_attrs.contains(&"firstName"));
        assert!(user_attrs.contains(&"lastName"));
        assert!(user_attrs.contains(&"displayName"));
        assert!(user_attrs.contains(&"active"));

        // Verify id is required
        let id_attr = user_oc.attributes.iter().find(|a| a.name == "id").unwrap();
        assert!(id_attr.required);
    }

    #[tokio::test]
    async fn test_rest_schema_discovery_group_object_class() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let schema = connector.discover_schema().await.unwrap();

        // Find group object class
        let group_oc = schema.object_classes.iter().find(|oc| oc.name == "group");
        assert!(group_oc.is_some(), "group object class should exist");
        let group_oc = group_oc.unwrap();

        // Verify group attributes
        let group_attrs: Vec<&str> = group_oc
            .attributes
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert!(group_attrs.contains(&"id"));
        assert!(group_attrs.contains(&"name"));
        assert!(group_attrs.contains(&"description"));
        assert!(group_attrs.contains(&"members"));

        // Verify id is required
        let id_attr = group_oc.attributes.iter().find(|a| a.name == "id").unwrap();
        assert!(id_attr.required);

        // Verify members is multi-valued
        let members_attr = group_oc
            .attributes
            .iter()
            .find(|a| a.name == "members")
            .unwrap();
        assert!(members_attr.multi_valued);
    }

    #[tokio::test]
    async fn test_rest_schema_attribute_data_types() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let schema = connector.discover_schema().await.unwrap();
        let user_oc = schema
            .object_classes
            .iter()
            .find(|oc| oc.name == "user")
            .unwrap();

        // id should be String type
        let id_attr = user_oc.attributes.iter().find(|a| a.name == "id").unwrap();
        assert_eq!(id_attr.data_type, AttributeDataType::String);

        // active should be Boolean type
        let active_attr = user_oc
            .attributes
            .iter()
            .find(|a| a.name == "active")
            .unwrap();
        assert_eq!(active_attr.data_type, AttributeDataType::Boolean);
    }

    // =========================================================================
    // T058 - OpenAPI Property Validation Tests
    // =========================================================================

    #[test]
    fn test_json_schema_type_to_attribute_type() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        // String types
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", None),
            AttributeDataType::String
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("email")),
            AttributeDataType::String
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("uri")),
            AttributeDataType::String
        );

        // UUID format
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("uuid")),
            AttributeDataType::Uuid
        );

        // Date/Time formats
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("date-time")),
            AttributeDataType::DateTime
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("date")),
            AttributeDataType::Date
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("time")),
            AttributeDataType::Timestamp
        );

        // Binary formats
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("binary")),
            AttributeDataType::Binary
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("string", Some("byte")),
            AttributeDataType::Binary
        );

        // Integer types
        assert_eq!(
            connector.json_schema_type_to_attribute_type("integer", None),
            AttributeDataType::Integer
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("integer", Some("int32")),
            AttributeDataType::Integer
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("integer", Some("int64")),
            AttributeDataType::Long
        );

        // Number types (mapped to Long)
        assert_eq!(
            connector.json_schema_type_to_attribute_type("number", None),
            AttributeDataType::Long
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("number", Some("float")),
            AttributeDataType::Long
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("number", Some("double")),
            AttributeDataType::Long
        );

        // Boolean
        assert_eq!(
            connector.json_schema_type_to_attribute_type("boolean", None),
            AttributeDataType::Boolean
        );

        // Complex types default to String
        assert_eq!(
            connector.json_schema_type_to_attribute_type("array", None),
            AttributeDataType::String
        );
        assert_eq!(
            connector.json_schema_type_to_attribute_type("object", None),
            AttributeDataType::String
        );
    }

    #[test]
    fn test_parse_openapi_property_basic() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "description": "User's email address"
        });

        let attr = connector.parse_openapi_property("email", &prop, false);

        assert_eq!(attr.name, "email");
        assert_eq!(attr.data_type, AttributeDataType::String);
        assert!(!attr.required);
        assert_eq!(attr.description, Some("User's email address".to_string()));
    }

    #[test]
    fn test_parse_openapi_property_required() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string"
        });

        let attr = connector.parse_openapi_property("id", &prop, true);

        assert!(attr.required);
    }

    #[test]
    fn test_parse_openapi_property_min_max_length() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "minLength": 3,
            "maxLength": 50
        });

        let attr = connector.parse_openapi_property("username", &prop, false);

        assert_eq!(attr.min_length, Some(3));
        assert_eq!(attr.max_length, Some(50));
    }

    #[test]
    fn test_parse_openapi_property_pattern() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "pattern": "^[a-zA-Z0-9]+$"
        });

        let attr = connector.parse_openapi_property("code", &prop, false);

        assert_eq!(attr.pattern, Some("^[a-zA-Z0-9]+$".to_string()));
    }

    #[test]
    fn test_parse_openapi_property_enum() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "enum": ["active", "inactive", "pending", "suspended"]
        });

        let attr = connector.parse_openapi_property("status", &prop, false);

        assert_eq!(attr.allowed_values.len(), 4);
        assert!(attr.allowed_values.contains(&"active".to_string()));
        assert!(attr.allowed_values.contains(&"inactive".to_string()));
        assert!(attr.allowed_values.contains(&"pending".to_string()));
        assert!(attr.allowed_values.contains(&"suspended".to_string()));
    }

    #[test]
    fn test_parse_openapi_property_read_only() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "readOnly": true
        });

        let attr = connector.parse_openapi_property("id", &prop, false);

        assert!(!attr.writable);
        assert!(attr.readable);
    }

    #[test]
    fn test_parse_openapi_property_write_only() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "string",
            "writeOnly": true
        });

        let attr = connector.parse_openapi_property("password", &prop, false);

        assert!(!attr.readable);
        assert!(attr.writable);
    }

    #[test]
    fn test_parse_openapi_property_array_multi_valued() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let prop = serde_json::json!({
            "type": "array",
            "items": {
                "type": "string"
            }
        });

        let attr = connector.parse_openapi_property("tags", &prop, false);

        assert!(attr.multi_valued);
    }

    #[test]
    fn test_parse_openapi_schema_complete() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let schema = serde_json::json!({
            "description": "User account",
            "required": ["id", "email"],
            "properties": {
                "id": {
                    "type": "string",
                    "format": "uuid",
                    "readOnly": true
                },
                "email": {
                    "type": "string",
                    "format": "email",
                    "minLength": 5,
                    "maxLength": 255,
                    "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "inactive"],
                    "description": "Account status"
                },
                "roles": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        });

        let oc = connector.parse_openapi_schema("User", &schema);
        assert!(oc.is_some());

        let oc = oc.unwrap();
        assert_eq!(oc.name, "User");
        assert_eq!(oc.description, Some("User account".to_string()));
        assert_eq!(oc.attributes.len(), 4);

        // Check id attribute
        let id = oc.get_attribute("id").unwrap();
        assert!(id.required);
        assert!(!id.writable);
        assert_eq!(id.data_type, AttributeDataType::Uuid);

        // Check email attribute
        let email = oc.get_attribute("email").unwrap();
        assert!(email.required);
        assert_eq!(email.min_length, Some(5));
        assert_eq!(email.max_length, Some(255));
        assert!(email.pattern.is_some());

        // Check status attribute
        let status = oc.get_attribute("status").unwrap();
        assert!(!status.required);
        assert_eq!(status.allowed_values.len(), 2);
        assert_eq!(status.description, Some("Account status".to_string()));

        // Check roles attribute
        let roles = oc.get_attribute("roles").unwrap();
        assert!(roles.multi_valued);
    }

    #[test]
    fn test_parse_openapi_schemas() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        let spec = serde_json::json!({
            "openapi": "3.0.0",
            "info": { "title": "Test API", "version": "1.0" },
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    },
                    "Group": {
                        "type": "object",
                        "properties": {
                            "id": { "type": "string" },
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        });

        let object_classes = connector.parse_openapi_schemas(&spec).unwrap();

        assert_eq!(object_classes.len(), 2);
        assert!(object_classes.iter().any(|oc| oc.name == "User"));
        assert!(object_classes.iter().any(|oc| oc.name == "Group"));
    }

    #[test]
    fn test_parse_swagger_2_definitions() {
        let config = RestConfig::new("https://api.example.com");
        let connector = RestConnector::new(config).unwrap();

        // Swagger 2.0 uses "definitions" instead of "components/schemas"
        let spec = serde_json::json!({
            "swagger": "2.0",
            "info": { "title": "Test API", "version": "1.0" },
            "definitions": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" }
                    }
                }
            }
        });

        let object_classes = connector.parse_openapi_schemas(&spec).unwrap();

        assert_eq!(object_classes.len(), 1);
        assert_eq!(object_classes[0].name, "User");
    }
}
