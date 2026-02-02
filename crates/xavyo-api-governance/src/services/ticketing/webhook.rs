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
    /// Optional URL to GET ticket status from (with {ticket_id} placeholder).
    status_url: Option<String>,
    /// Authentication method.
    auth: WebhookAuth,
    /// Custom headers to include.
    custom_headers: Vec<(String, String)>,
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

        let status_url = config
            .field_mappings
            .as_ref()
            .and_then(|c| c.get("status_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Determine authentication method
        let auth = if let Some(bearer) = credentials.get("bearer_token").and_then(|v| v.as_str()) {
            WebhookAuth::Bearer(bearer.to_string())
        } else if let (Some(username), Some(password)) = (
            credentials.get("username").and_then(|v| v.as_str()),
            credentials.get("password").and_then(|v| v.as_str()),
        ) {
            WebhookAuth::Basic {
                username: username.to_string(),
                password: password.to_string(),
            }
        } else if let (Some(header), Some(value)) = (
            credentials.get("api_key_header").and_then(|v| v.as_str()),
            credentials.get("api_key").and_then(|v| v.as_str()),
        ) {
            WebhookAuth::ApiKey {
                header: header.to_string(),
                value: value.to_string(),
            }
        } else {
            WebhookAuth::None
        };

        // Parse custom headers from field_mappings
        let custom_headers = config
            .field_mappings
            .as_ref()
            .and_then(|c| c.get("headers"))
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                TicketingError::InvalidConfiguration(format!("Failed to build HTTP client: {}", e))
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
#[derive(Debug, Deserialize)]
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
                        error_message: Some(format!("Endpoint returned status {}", status)),
                        details: None,
                    })
                }
            }
            Err(e) => Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(format!("Connection failed: {}", e)),
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
            // Try to parse the response
            let response_text = response.text().await?;

            match serde_json::from_str::<WebhookCreateResponse>(&response_text) {
                Ok(webhook_response) => Ok(CreateTicketResponse {
                    external_reference: webhook_response.ticket_id,
                    external_url: webhook_response.ticket_url,
                    raw_response: serde_json::from_str(&response_text).ok(),
                }),
                Err(_) => {
                    // If response doesn't match expected format, use task_id as reference
                    tracing::warn!(
                        "Webhook response didn't match expected format, using task_id as reference"
                    );
                    Ok(CreateTicketResponse {
                        external_reference: request.task_id.to_string(),
                        external_url: None,
                        raw_response: serde_json::from_str(&response_text).ok(),
                    })
                }
            }
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
                "Webhook endpoint unavailable: {}",
                status
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
                last_updated: webhook_response.last_updated.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                raw_response: None,
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
        // Webhook provider doesn't support adding comments
        // Could be extended with a comment_url configuration
        tracing::warn!("Webhook provider does not support adding comments");
        Ok(())
    }
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
}
