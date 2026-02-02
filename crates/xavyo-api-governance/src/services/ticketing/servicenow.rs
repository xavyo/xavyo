//! ServiceNow ticketing provider (F064).
//!
//! Integrates with ServiceNow's REST API to create incidents/requests
//! and track their status.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use xavyo_db::{GovTicketingConfiguration, TicketingType};

use super::{
    ConnectivityTestResponse, CreateTicketRequest, CreateTicketResponse, TicketStatus,
    TicketStatusResponse, TicketingError, TicketingProvider, TicketingResult,
};

/// ServiceNow API client.
pub struct ServiceNowProvider {
    client: Client,
    instance_url: String,
    username: String,
    password: String,
    /// Table to create records in (default: incident).
    table_name: String,
    /// Default assignment group for tickets.
    assignment_group: Option<String>,
    /// Custom field mappings from config.
    field_mappings: Option<serde_json::Value>,
}

impl ServiceNowProvider {
    /// Create a new ServiceNow provider from configuration.
    pub fn new(
        config: &GovTicketingConfiguration,
        credentials: &serde_json::Value,
    ) -> TicketingResult<Self> {
        let instance_url = config.endpoint_url.trim_end_matches('/').to_string();

        let username = credentials
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration("Missing username in credentials".to_string())
            })?
            .to_string();

        let password = credentials
            .get("password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration("Missing password in credentials".to_string())
            })?
            .to_string();

        // Get table name from field_mappings or default to "incident"
        let table_name = config
            .field_mappings
            .as_ref()
            .and_then(|c| c.get("table_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("incident")
            .to_string();

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                TicketingError::InvalidConfiguration(format!("Failed to build HTTP client: {}", e))
            })?;

        Ok(Self {
            client,
            instance_url,
            username,
            password,
            table_name,
            assignment_group: config.default_assignment_group.clone(),
            field_mappings: config.field_mappings.clone(),
        })
    }

    /// Build the API URL for a given path.
    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/now/{}",
            self.instance_url,
            path.trim_start_matches('/')
        )
    }

    /// Map priority to ServiceNow urgency/impact.
    fn map_priority(&self, priority: i32) -> (i32, i32) {
        // ServiceNow uses urgency (1-3) and impact (1-3)
        // Priority 1 (Critical) -> urgency=1, impact=1
        // Priority 2 (High) -> urgency=2, impact=2
        // Priority 3 (Medium) -> urgency=2, impact=3
        // Priority 4 (Low) -> urgency=3, impact=3
        match priority {
            1 => (1, 1),
            2 => (2, 2),
            3 => (2, 3),
            _ => (3, 3),
        }
    }

    /// Map ServiceNow state to our ticket status.
    fn map_state_to_status(&self, state: i32) -> TicketStatus {
        // ServiceNow incident states:
        // 1 = New, 2 = In Progress, 3 = On Hold
        // 4 = Pending, 6 = Resolved, 7 = Closed, 8 = Cancelled
        match state {
            1 => TicketStatus::Open,
            2 => TicketStatus::InProgress,
            3 | 4 => TicketStatus::Pending,
            6 => TicketStatus::Resolved,
            7 => TicketStatus::Closed,
            8 => TicketStatus::Cancelled,
            _ => TicketStatus::Unknown(format!("state={}", state)),
        }
    }
}

/// ServiceNow incident creation request.
#[derive(Debug, Serialize)]
struct ServiceNowCreateRequest {
    short_description: String,
    description: String,
    urgency: i32,
    impact: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subcategory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    correlation_id: Option<String>,
}

/// ServiceNow API response wrapper.
#[derive(Debug, Deserialize)]
struct ServiceNowResponse<T> {
    result: T,
}

/// ServiceNow incident record.
#[derive(Debug, Deserialize)]
struct ServiceNowIncident {
    sys_id: String,
    number: String,
    state: String,
    #[serde(default)]
    close_notes: Option<String>,
    #[serde(default)]
    closed_by: Option<ServiceNowUser>,
    #[serde(default)]
    sys_updated_on: Option<String>,
}

/// ServiceNow user reference.
#[derive(Debug, Deserialize)]
struct ServiceNowUser {
    #[serde(default)]
    display_value: Option<String>,
}

/// ServiceNow error response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Reserved for error handling
struct ServiceNowError {
    error: ServiceNowErrorDetail,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Reserved for error handling
struct ServiceNowErrorDetail {
    message: String,
    #[serde(default)]
    detail: Option<String>,
}

#[async_trait]
impl TicketingProvider for ServiceNowProvider {
    fn provider_type(&self) -> TicketingType {
        TicketingType::ServiceNow
    }

    async fn test_connectivity(&self) -> TicketingResult<ConnectivityTestResponse> {
        // Try to access the table API to verify credentials
        let url = self.api_url(&format!("table/{}?sysparm_limit=1", self.table_name));

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            Ok(ConnectivityTestResponse {
                success: true,
                error_message: None,
                details: Some(serde_json::json!({
                    "instance_url": self.instance_url,
                    "table_name": self.table_name,
                    "status_code": status.as_u16()
                })),
            })
        } else if status == StatusCode::UNAUTHORIZED {
            Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(
                    "Authentication failed - check username and password".to_string(),
                ),
                details: None,
            })
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(format!("API returned status {}: {}", status, error_text)),
                details: None,
            })
        }
    }

    async fn create_ticket(
        &self,
        request: CreateTicketRequest,
    ) -> TicketingResult<CreateTicketResponse> {
        let url = self.api_url(&format!("table/{}", self.table_name));

        let (urgency, impact) = self.map_priority(request.priority);

        // Build description with all relevant details
        let description = format!(
            "{}\n\n---\nUser: {} ({})\nApplication: {}\nEntitlement: {}\nOperation: {}\nTask ID: {}",
            request.description,
            request.user_display_name,
            request.user_email.as_deref().unwrap_or("N/A"),
            request.application_name,
            request.entitlement_name,
            request.operation_type,
            request.task_id
        );

        // Get optional fields from field mappings
        let category = self
            .field_mappings
            .as_ref()
            .and_then(|m| m.get("category"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let subcategory = self
            .field_mappings
            .as_ref()
            .and_then(|m| m.get("subcategory"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let assignment_group = self.assignment_group.clone();

        let snow_request = ServiceNowCreateRequest {
            short_description: request.summary,
            description,
            urgency,
            impact,
            caller_id: request.user_email,
            category,
            subcategory,
            assignment_group,
            correlation_id: Some(request.task_id.to_string()),
        };

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&snow_request)
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let snow_response: ServiceNowResponse<ServiceNowIncident> = response.json().await?;

            Ok(CreateTicketResponse {
                external_reference: snow_response.result.number.clone(),
                external_url: Some(format!(
                    "{}/nav_to.do?uri=incident.do?sys_id={}",
                    self.instance_url, snow_response.result.sys_id
                )),
                raw_response: Some(serde_json::json!({
                    "sys_id": snow_response.result.sys_id,
                    "number": snow_response.result.number
                })),
            })
        } else if status == StatusCode::UNAUTHORIZED {
            Err(TicketingError::AuthenticationFailed(
                "ServiceNow authentication failed".to_string(),
            ))
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            // Extract retry-after header if present
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            Err(TicketingError::RateLimited {
                retry_after_seconds: retry_after,
            })
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
        let url = self.api_url(&format!(
            "table/{}?sysparm_query=number={}&sysparm_display_value=true",
            self.table_name, external_reference
        ));

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let snow_response: ServiceNowResponse<Vec<ServiceNowIncident>> =
                response.json().await?;

            let incident =
                snow_response.result.into_iter().next().ok_or_else(|| {
                    TicketingError::TicketNotFound(external_reference.to_string())
                })?;

            let state: i32 = incident.state.parse().unwrap_or(1);
            let ticket_status = self.map_state_to_status(state);

            Ok(TicketStatusResponse {
                status: ticket_status,
                resolution_notes: incident.close_notes,
                resolved_by: incident.closed_by.and_then(|u| u.display_value),
                last_updated: incident.sys_updated_on.and_then(|s| {
                    // ServiceNow returns dates like "2024-01-15 10:30:00"
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%d %H:%M:%S")
                        .ok()
                        .map(|dt| dt.and_utc())
                }),
                raw_response: Some(serde_json::json!({
                    "state": incident.state,
                })),
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

    async fn add_comment(&self, external_reference: &str, comment: &str) -> TicketingResult<()> {
        // First, get the sys_id for the incident
        let query_url = self.api_url(&format!(
            "table/{}?sysparm_query=number={}&sysparm_fields=sys_id",
            self.table_name, external_reference
        ));

        let query_response = self
            .client
            .get(&query_url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Accept", "application/json")
            .send()
            .await?;

        if !query_response.status().is_success() {
            return Err(TicketingError::TicketNotFound(
                external_reference.to_string(),
            ));
        }

        let query_result: ServiceNowResponse<Vec<serde_json::Value>> =
            query_response.json().await?;
        let sys_id = query_result
            .result
            .first()
            .and_then(|r| r.get("sys_id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| TicketingError::TicketNotFound(external_reference.to_string()))?;

        // Now update the incident with the comment
        let update_url = self.api_url(&format!("table/{}/{}", self.table_name, sys_id));

        let response = self
            .client
            .patch(&update_url)
            .basic_auth(&self.username, Some(&self.password))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "comments": comment
            }))
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(TicketingError::ApiError {
                status: status.as_u16(),
                message: error_text,
            })
        }
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
            ticketing_type: TicketingType::ServiceNow,
            endpoint_url: "https://test.service-now.com".to_string(),
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
    fn test_priority_mapping() {
        let config = test_config();
        let credentials = serde_json::json!({
            "username": "test",
            "password": "test"
        });

        let provider = ServiceNowProvider::new(&config, &credentials).unwrap();

        assert_eq!(provider.map_priority(1), (1, 1));
        assert_eq!(provider.map_priority(2), (2, 2));
        assert_eq!(provider.map_priority(3), (2, 3));
        assert_eq!(provider.map_priority(4), (3, 3));
    }

    #[test]
    fn test_state_mapping() {
        let config = test_config();
        let credentials = serde_json::json!({
            "username": "test",
            "password": "test"
        });

        let provider = ServiceNowProvider::new(&config, &credentials).unwrap();

        assert_eq!(provider.map_state_to_status(1), TicketStatus::Open);
        assert_eq!(provider.map_state_to_status(2), TicketStatus::InProgress);
        assert_eq!(provider.map_state_to_status(6), TicketStatus::Resolved);
        assert_eq!(provider.map_state_to_status(7), TicketStatus::Closed);
        assert_eq!(provider.map_state_to_status(8), TicketStatus::Cancelled);
    }
}
