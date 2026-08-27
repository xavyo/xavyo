//! Webhook ticketing provider (F064).
//!
//! Sends provisioning requests to a custom webhook endpoint,
//! allowing integration with any ticketing system that can receive HTTP POST requests.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use xavyo_db::{GovTicketingConfiguration, TicketingType};

use super::{
    ConnectivityTestResponse, CreateTicketRequest, CreateTicketResponse, TicketStatus,
    TicketStatusResponse, TicketingError, TicketingProvider, TicketingResult,
};

/// Webhook provider for custom integrations.
pub struct WebhookProvider {
    client: Client,
    /// URL to POST ticket creation requests to.
    create_url: String,
    /// Optional URL to GET ticket status from (with {`ticket_id`} placeholder).
    status_url: Option<String>,
    /// Authentication method.
    auth: WebhookAuth,
    /// Custom headers to include.
    custom_headers: Vec<(String, String)>,
}

fn optional_config_string(
    mappings: Option<&serde_json::Value>,
    key: &str,
) -> TicketingResult<Option<String>> {
    match mappings.and_then(|c| c.get(key)) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| TicketingError::InvalidConfiguration(format!("{key} must be a string"))),
    }
}

fn json_string_field(value: &serde_json::Value, field: &str) -> TicketingResult<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            TicketingError::InvalidConfiguration(format!("{field} must be a non-empty string"))
        })
}

fn parse_webhook_auth(credentials: &serde_json::Value) -> TicketingResult<WebhookAuth> {
    if credentials.get("bearer_token").is_some() {
        return Ok(WebhookAuth::Bearer(json_string_field(
            credentials,
            "bearer_token",
        )?));
    }
    if credentials.get("username").is_some() || credentials.get("password").is_some() {
        return Ok(WebhookAuth::Basic {
            username: json_string_field(credentials, "username")?,
            password: json_string_field(credentials, "password")?,
        });
    }
    if credentials.get("api_key").is_some() || credentials.get("api_key_header").is_some() {
        return Ok(WebhookAuth::ApiKey {
            header: json_string_field(credentials, "api_key_header")?,
            value: json_string_field(credentials, "api_key")?,
        });
    }
    Ok(WebhookAuth::None)
}

fn parse_custom_headers(
    mappings: Option<&serde_json::Value>,
) -> TicketingResult<Vec<(String, String)>> {
    match mappings.and_then(|c| c.get("headers")) {
        None | Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(v) => {
            let obj = v.as_object().ok_or_else(|| {
                TicketingError::InvalidConfiguration("headers must be an object".into())
            })?;
            obj.iter()
                .map(|(k, val)| {
                    val.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                        .ok_or_else(|| {
                            TicketingError::InvalidConfiguration(format!(
                                "header '{k}' must be a string"
                            ))
                        })
                })
                .collect()
        }
    }
}

/// Webhook authentication methods.
enum WebhookAuth {
    None,
    Bearer(String),
    Basic { username: String, password: String },
    ApiKey { header: String, value: String },
}

impl WebhookProvider {
    /// Create a new webhook provider from configuration.
    pub fn new(
        config: &GovTicketingConfiguration,
        credentials: &serde_json::Value,
    ) -> TicketingResult<Self> {
        let create_url = config.endpoint_url.clone();

        let status_url = optional_config_string(config.field_mappings.as_ref(), "status_url")?;
        let auth = parse_webhook_auth(credentials)?;
        let custom_headers = parse_custom_headers(config.field_mappings.as_ref())?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                TicketingError::InvalidConfiguration(format!("Failed to build HTTP client: {e}"))
            })?;

        Ok(Self {
            client,
            create_url,
            status_url,
            auth,
            custom_headers,
        })
    }

    /// Apply authentication to a request builder.
    fn apply_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            WebhookAuth::None => builder,
            WebhookAuth::Bearer(token) => builder.bearer_auth(token),
            WebhookAuth::Basic { username, password } => {
                builder.basic_auth(username, Some(password))
            }
            WebhookAuth::ApiKey { header, value } => builder.header(header, value),
        }
    }

    /// Apply custom headers to a request builder.
    fn apply_headers(&self, mut builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for (key, value) in &self.custom_headers {
            builder = builder.header(key, value);
        }
        builder
    }
}

/// Standardized webhook request payload.
#[derive(Debug, Serialize)]
struct WebhookCreatePayload {
    /// Unique task identifier.
    task_id: String,
    /// Operation type (grant, revoke, modify).
    operation: String,
    /// User information.
    user: WebhookUser,
    /// Resource information.
    resource: WebhookResource,
    /// Priority level (1-4).
    priority: i32,
    /// Summary/title.
    summary: String,
    /// Detailed description.
    description: String,
    /// Timestamp of the request.
    timestamp: String,
    /// Any custom fields from configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    custom_fields: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct WebhookUser {
    display_name: String,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebhookResource {
    application_name: String,
    entitlement_name: String,
}

/// Expected response from webhook ticket creation.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
struct WebhookCreateResponse {
    /// External ticket ID/reference.
    ticket_id: String,
    /// Optional URL to view the ticket.
    #[serde(default)]
    ticket_url: Option<String>,
    /// Optional status (defaults to "open").
    #[serde(default)]
    status: Option<String>,
}

/// Expected response from webhook status check.
#[derive(Debug, Deserialize, Serialize)]
struct WebhookStatusResponse {
    /// Current status of the ticket.
    status: String,
    /// Resolution notes.
    #[serde(default)]
    resolution_notes: Option<String>,
    /// Who resolved the ticket.
    #[serde(default)]
    resolved_by: Option<String>,
    /// Last update timestamp (ISO 8601).
    #[serde(default)]
    last_updated: Option<String>,
}

#[async_trait]
impl TicketingProvider for WebhookProvider {
    fn provider_type(&self) -> TicketingType {
        TicketingType::Webhook
    }

    async fn test_connectivity(&self) -> TicketingResult<ConnectivityTestResponse> {
        // Send a HEAD or GET request to verify the endpoint is reachable
        let builder = self.client.head(&self.create_url);
        let builder = self.apply_auth(builder);
        let builder = self.apply_headers(builder);

        match builder.send().await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() || status == StatusCode::METHOD_NOT_ALLOWED {
                    // METHOD_NOT_ALLOWED is acceptable - means endpoint exists but only accepts POST
                    Ok(ConnectivityTestResponse {
                        success: true,
                        error_message: None,
                        details: Some(serde_json::json!({
                            "url": self.create_url,
                            "status_code": status.as_u16()
                        })),
                    })
                } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                    Ok(ConnectivityTestResponse {
                        success: false,
                        error_message: Some("Authentication failed".to_string()),
                        details: None,
                    })
                } else {
                    Ok(ConnectivityTestResponse {
                        success: false,
                        error_message: Some(format!("Endpoint returned status {status}")),
                        details: None,
                    })
                }
            }
            Err(e) => Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(format!("Connection failed: {e}")),
                details: None,
            }),
        }
    }

    async fn create_ticket(
        &self,
        request: CreateTicketRequest,
    ) -> TicketingResult<CreateTicketResponse> {
        let payload = WebhookCreatePayload {
            task_id: request.task_id.to_string(),
            operation: request.operation_type,
            user: WebhookUser {
                display_name: request.user_display_name,
                email: request.user_email,
            },
            resource: WebhookResource {
                application_name: request.application_name,
                entitlement_name: request.entitlement_name,
            },
            priority: request.priority,
            summary: request.summary,
            description: request.description,
            timestamp: chrono::Utc::now().to_rfc3339(),
            custom_fields: request.custom_fields,
        };

        let builder = self.client.post(&self.create_url);
        let builder = self.apply_auth(builder);
        let builder = self.apply_headers(builder);

        let response = builder
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let response_text = response.text().await?;
            parse_webhook_create_body(status.as_u16(), &response_text)
        } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            Err(TicketingError::AuthenticationFailed(
                "Webhook authentication failed".to_string(),
            ))
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            Err(TicketingError::RateLimited {
                retry_after_seconds: retry_after,
            })
        } else if status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::GATEWAY_TIMEOUT
        {
            Err(TicketingError::ProviderUnavailable(format!(
                "Webhook endpoint unavailable: {status}"
            )))
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(TicketingError::ApiError {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn get_ticket_status(
        &self,
        external_reference: &str,
    ) -> TicketingResult<TicketStatusResponse> {
        let status_url = self.status_url.as_ref().ok_or_else(|| {
            TicketingError::InvalidConfiguration(
                "No status_url configured for webhook provider".to_string(),
            )
        })?;

        // Replace {ticket_id} placeholder
        let url = status_url.replace("{ticket_id}", external_reference);

        let builder = self.client.get(&url);
        let builder = self.apply_auth(builder);
        let builder = self.apply_headers(builder);

        let response = builder.header("Accept", "application/json").send().await?;

        let status = response.status();

        if status.is_success() {
            let webhook_response: WebhookStatusResponse = response.json().await?;
            let raw_response = webhook_status_raw_response(&webhook_response)?;

            let ticket_status = match webhook_response.status.to_lowercase().as_str() {
                "open" | "new" | "pending" => TicketStatus::Open,
                "in_progress" | "in progress" | "active" => TicketStatus::InProgress,
                "waiting" | "on_hold" | "on hold" => TicketStatus::Pending,
                "resolved" | "done" | "completed" | "closed" => TicketStatus::Resolved,
                "cancelled" | "canceled" | "rejected" => TicketStatus::Cancelled,
                other => TicketStatus::Unknown(other.to_string()),
            };

            Ok(TicketStatusResponse {
                status: ticket_status,
                resolution_notes: webhook_response.resolution_notes,
                resolved_by: webhook_response.resolved_by,
                last_updated: super::parse_optional_rfc3339(
                    webhook_response.last_updated.as_deref(),
                )?,
                raw_response: Some(raw_response),
            })
        } else if status == StatusCode::NOT_FOUND {
            Err(TicketingError::TicketNotFound(
                external_reference.to_string(),
            ))
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(TicketingError::ApiError {
                status: status.as_u16(),
                message: error_text,
            })
        }
    }

    async fn add_comment(&self, _external_reference: &str, _comment: &str) -> TicketingResult<()> {
        Err(reject_unsupported_webhook_comment())
    }
}

/// Parse a webhook create body. Missing `ticket_id` is an error, not a fake
/// success that substitutes the local task id. Non-JSON bodies are errors,
/// not `raw_response: None`.
fn parse_webhook_create_body(status: u16, body: &str) -> TicketingResult<CreateTicketResponse> {
    let parsed: WebhookCreateResponse =
        serde_json::from_str(body).map_err(|e| TicketingError::ApiError {
            status,
            message: format!("Webhook response did not include ticket_id: {e}"),
        })?;
    if parsed.ticket_id.trim().is_empty() {
        return Err(TicketingError::ApiError {
            status,
            message: "Webhook response did not include ticket_id".to_string(),
        });
    }
    let raw_response = serde_json::from_str(body)?;
    Ok(CreateTicketResponse {
        external_reference: parsed.ticket_id,
        external_url: parsed.ticket_url,
        raw_response: Some(raw_response),
    })
}

/// Webhook comments are not implemented; callers must not see success.
fn reject_unsupported_webhook_comment() -> TicketingError {
    TicketingError::NotSupported("Webhook provider does not support adding comments".to_string())
}

/// Persist the provider body as `raw_response` instead of dropping it.
fn webhook_status_raw_response(body: &WebhookStatusResponse) -> TicketingResult<serde_json::Value> {
    serde_json::to_value(body).map_err(TicketingError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GovTicketingConfiguration {
        GovTicketingConfiguration {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            name: "Test".to_string(),
            ticketing_type: TicketingType::Webhook,
            endpoint_url: "https://example.com/webhook".to_string(),
            credentials: vec![],
            field_mappings: None,
            default_assignee: None,
            default_assignment_group: None,
            project_key: None,
            issue_type: None,
            polling_interval_seconds: 300,
            webhook_callback_secret: None,
            status_field_mapping: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_webhook_auth_none() {
        let config = test_config();
        let credentials = serde_json::json!({});

        let provider = WebhookProvider::new(&config, &credentials).unwrap();
        assert!(matches!(provider.auth, WebhookAuth::None));
    }

    #[test]
    fn test_webhook_auth_bearer() {
        let config = test_config();
        let credentials = serde_json::json!({
            "bearer_token": "my-secret-token"
        });

        let provider = WebhookProvider::new(&config, &credentials).unwrap();
        assert!(matches!(provider.auth, WebhookAuth::Bearer(_)));
    }

    #[test]
    fn test_webhook_custom_headers() {
        let mut config = test_config();
        config.field_mappings = Some(serde_json::json!({
            "headers": {
                "X-Custom-Header": "custom-value",
                "X-Tenant-Id": "123"
            }
        }));

        let credentials = serde_json::json!({});

        let provider = WebhookProvider::new(&config, &credentials).unwrap();
        assert_eq!(provider.custom_headers.len(), 2);
    }

    #[test]
    fn webhook_headers_reject_non_strings() {
        let mut config = test_config();
        config.field_mappings = Some(serde_json::json!({
            "headers": { "X-Custom-Header": 1 }
        }));
        let err = WebhookProvider::new(&config, &serde_json::json!({}))
            .err()
            .expect("non-string header");
        assert!(matches!(err, TicketingError::InvalidConfiguration(_)));
        let src = include_str!("webhook.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("filter_map(|(k, v)| v.as_str()"),
            "webhook headers must not drop non-string values"
        );
    }

    #[test]
    fn webhook_auth_does_not_fail_open_on_typed_credentials() {
        let config = test_config();
        assert!(WebhookProvider::new(&config, &serde_json::json!({"bearer_token": true})).is_err());
        assert!(WebhookProvider::new(&config, &serde_json::json!({"username": "alice"})).is_err());
        let src = include_str!("webhook.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_webhook_auth("),
            "webhook auth must fail closed when credential types are wrong"
        );
    }

    #[test]
    fn webhook_status_url_must_be_a_string() {
        let mut config = test_config();
        config.field_mappings = Some(serde_json::json!({ "status_url": 1 }));
        assert!(WebhookProvider::new(&config, &serde_json::json!({})).is_err());
        config.field_mappings = Some(serde_json::json!({
            "status_url": "https://example.com/tickets/{ticket_id}"
        }));
        let provider = WebhookProvider::new(&config, &serde_json::json!({})).unwrap();
        assert!(provider.status_url.is_some());
    }

    #[test]
    fn webhook_create_requires_ticket_id() {
        let parsed = parse_webhook_create_body(
            200,
            r#"{"ticket_id":"INC-99","ticket_url":"https://example.com/INC-99"}"#,
        )
        .expect("valid body");
        assert_eq!(parsed.external_reference, "INC-99");
        assert_eq!(
            parsed.external_url.as_deref(),
            Some("https://example.com/INC-99")
        );
        assert!(parsed.raw_response.is_some());

        let missing = parse_webhook_create_body(200, r#"{"ok":true}"#)
            .expect_err("must not substitute the local task id");
        assert!(
            matches!(missing, TicketingError::ApiError { status: 200, ref message } if message.contains("ticket_id")),
            "got {missing:?}"
        );

        let not_json = parse_webhook_create_body(200, "thanks")
            .expect_err("non-JSON body must not be a fake success");
        assert!(matches!(
            not_json,
            TicketingError::ApiError { status: 200, .. }
        ));
    }

    #[test]
    fn webhook_add_comment_is_not_success() {
        let err = reject_unsupported_webhook_comment();
        assert!(
            matches!(err, TicketingError::NotSupported(ref msg) if msg.contains("comments")),
            "got {err:?}"
        );
        let src = include_str!("webhook.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("reject_unsupported_webhook_comment()"),
            "add_comment must fail closed when comments are unsupported"
        );
        assert!(
            !production.contains("using task_id as reference"),
            "create_ticket must not fake an external ticket id"
        );
    }

    #[test]
    fn webhook_status_keeps_raw_response() {
        let body = WebhookStatusResponse {
            status: "resolved".to_string(),
            resolution_notes: Some("done".to_string()),
            resolved_by: Some("alice".to_string()),
            last_updated: Some("2024-01-15T10:30:00Z".to_string()),
        };
        let raw = webhook_status_raw_response(&body).expect("serialize");
        assert_eq!(raw["status"], "resolved");
        assert_eq!(raw["resolution_notes"], "done");
        let src = include_str!("webhook.rs");
        let production = src.split("mod tests").next().expect("production source");
        let get_status = production
            .split("async fn get_ticket_status")
            .nth(1)
            .and_then(|s| s.split("async fn add_comment").next())
            .expect("get_ticket_status body");
        assert!(
            !get_status.contains("raw_response: None"),
            "status checks must persist the provider body"
        );
        assert!(
            !get_status.contains("parse_from_rfc3339(&s)\n                        .ok()"),
            "unparseable last_updated must not be dropped"
        );
        assert!(
            get_status.contains("parse_optional_rfc3339"),
            "webhook status must fail closed on invalid last_updated"
        );
    }
}
