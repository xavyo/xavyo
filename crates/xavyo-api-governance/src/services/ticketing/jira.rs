//! Jira ticketing provider (F064).
//!
//! Integrates with Jira's REST API to create issues and track their status.

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use xavyo_db::{GovTicketingConfiguration, TicketingType};

use super::{
    ConnectivityTestResponse, CreateTicketRequest, CreateTicketResponse, TicketStatus,
    TicketStatusResponse, TicketingError, TicketingProvider, TicketingResult,
};

/// Jira API client.
pub struct JiraProvider {
    client: Client,
    base_url: String,
    email: String,
    api_token: String,
    /// Jira project key (e.g., "PROJ").
    project_key: String,
    /// Issue type (e.g., "Task", "Story", "Bug").
    issue_type: String,
    /// Custom field mappings from config.
    field_mappings: Option<serde_json::Value>,
}

impl JiraProvider {
    /// Create a new Jira provider from configuration.
    pub fn new(
        config: &GovTicketingConfiguration,
        credentials: &serde_json::Value,
    ) -> TicketingResult<Self> {
        let base_url = config.endpoint_url.trim_end_matches('/').to_string();

        let email = credentials
            .get("email")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration("Missing email in credentials".to_string())
            })?
            .to_string();

        let api_token = credentials
            .get("api_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration("Missing api_token in credentials".to_string())
            })?
            .to_string();

        let project_key = config
            .project_key
            .as_ref()
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration(
                    "Missing project_key in configuration".to_string(),
                )
            })?
            .clone();

        let issue_type = config
            .issue_type
            .clone()
            .unwrap_or_else(|| "Task".to_string());

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                TicketingError::InvalidConfiguration(format!("Failed to build HTTP client: {}", e))
            })?;

        Ok(Self {
            client,
            base_url,
            email,
            api_token,
            project_key,
            issue_type,
            field_mappings: config.field_mappings.clone(),
        })
    }

    /// Build the API URL for a given path.
    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/rest/api/3/{}",
            self.base_url,
            path.trim_start_matches('/')
        )
    }

    /// Map priority to Jira priority name.
    fn map_priority(&self, priority: i32) -> &'static str {
        // Jira default priorities: Highest, High, Medium, Low, Lowest
        match priority {
            1 => "Highest",
            2 => "High",
            3 => "Medium",
            4 => "Low",
            _ => "Medium",
        }
    }

    /// Map Jira status category to our ticket status.
    fn map_status_category(&self, category_key: &str, status_name: &str) -> TicketStatus {
        // Jira status categories: new, indeterminate, done
        match category_key {
            "new" => TicketStatus::Open,
            "indeterminate" => {
                // Could be "In Progress" or "Pending"
                if status_name.to_lowercase().contains("progress") {
                    TicketStatus::InProgress
                } else {
                    TicketStatus::Pending
                }
            }
            "done" => {
                // Check if it's cancelled vs resolved
                if status_name.to_lowercase().contains("cancel")
                    || status_name.to_lowercase().contains("won't")
                {
                    TicketStatus::Cancelled
                } else {
                    TicketStatus::Resolved
                }
            }
            _ => TicketStatus::Unknown(format!("{}:{}", category_key, status_name)),
        }
    }
}

/// Jira issue creation request.
#[derive(Debug, Serialize)]
struct JiraCreateRequest {
    fields: JiraIssueFields,
}

#[derive(Debug, Serialize)]
struct JiraIssueFields {
    project: JiraProject,
    summary: String,
    description: JiraDescription,
    issuetype: JiraIssueType,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<JiraPriority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignee: Option<JiraUser>,
}

#[derive(Debug, Serialize)]
struct JiraProject {
    key: String,
}

#[derive(Debug, Serialize)]
struct JiraIssueType {
    name: String,
}

#[derive(Debug, Serialize)]
struct JiraPriority {
    name: String,
}

#[derive(Debug, Serialize)]
struct JiraUser {
    #[serde(rename = "accountId")]
    account_id: String,
}

/// Jira Atlassian Document Format (ADF) description.
#[derive(Debug, Serialize)]
struct JiraDescription {
    #[serde(rename = "type")]
    doc_type: String,
    version: i32,
    content: Vec<JiraDocContent>,
}

#[derive(Debug, Serialize)]
struct JiraDocContent {
    #[serde(rename = "type")]
    content_type: String,
    content: Vec<JiraTextContent>,
}

#[derive(Debug, Serialize)]
struct JiraTextContent {
    #[serde(rename = "type")]
    text_type: String,
    text: String,
}

impl JiraDescription {
    fn from_text(text: &str) -> Self {
        JiraDescription {
            doc_type: "doc".to_string(),
            version: 1,
            content: vec![JiraDocContent {
                content_type: "paragraph".to_string(),
                content: vec![JiraTextContent {
                    text_type: "text".to_string(),
                    text: text.to_string(),
                }],
            }],
        }
    }
}

/// Jira issue creation response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
struct JiraCreateResponse {
    id: String,
    key: String,
    #[serde(rename = "self")]
    self_url: String,
}

/// Jira issue response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
struct JiraIssue {
    key: String,
    fields: JiraIssueFieldsResponse,
}

#[derive(Debug, Deserialize)]
struct JiraIssueFieldsResponse {
    status: JiraStatus,
    #[serde(default)]
    resolution: Option<JiraResolution>,
    #[serde(default)]
    updated: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JiraStatus {
    name: String,
    #[serde(rename = "statusCategory")]
    status_category: JiraStatusCategory,
}

#[derive(Debug, Deserialize)]
struct JiraStatusCategory {
    key: String,
}

#[derive(Debug, Deserialize)]
struct JiraResolution {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

/// Jira error response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields used for deserialization
struct JiraErrorResponse {
    #[serde(rename = "errorMessages")]
    error_messages: Vec<String>,
    #[serde(default)]
    errors: serde_json::Value,
}

#[async_trait]
impl TicketingProvider for JiraProvider {
    fn provider_type(&self) -> TicketingType {
        TicketingType::Jira
    }

    async fn test_connectivity(&self) -> TicketingResult<ConnectivityTestResponse> {
        // Try to get project info to verify credentials
        let url = self.api_url(&format!("project/{}", self.project_key));

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.email, Some(&self.api_token))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            Ok(ConnectivityTestResponse {
                success: true,
                error_message: None,
                details: Some(serde_json::json!({
                    "base_url": self.base_url,
                    "project_key": self.project_key,
                    "issue_type": self.issue_type
                })),
            })
        } else if status == StatusCode::UNAUTHORIZED {
            Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(
                    "Authentication failed - check email and API token".to_string(),
                ),
                details: None,
            })
        } else if status == StatusCode::NOT_FOUND {
            Ok(ConnectivityTestResponse {
                success: false,
                error_message: Some(format!("Project '{}' not found", self.project_key)),
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
        let url = self.api_url("issue");

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

        // Get labels from field mappings
        let labels = self
            .field_mappings
            .as_ref()
            .and_then(|m| m.get("labels"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            });

        let jira_request = JiraCreateRequest {
            fields: JiraIssueFields {
                project: JiraProject {
                    key: self.project_key.clone(),
                },
                summary: request.summary,
                description: JiraDescription::from_text(&description),
                issuetype: JiraIssueType {
                    name: self.issue_type.clone(),
                },
                priority: Some(JiraPriority {
                    name: self.map_priority(request.priority).to_string(),
                }),
                labels,
                assignee: None, // Would need account ID lookup
            },
        };

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.email, Some(&self.api_token))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&jira_request)
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let jira_response: JiraCreateResponse = response.json().await?;

            Ok(CreateTicketResponse {
                external_reference: jira_response.key.clone(),
                external_url: Some(format!("{}/browse/{}", self.base_url, jira_response.key)),
                raw_response: Some(serde_json::json!({
                    "id": jira_response.id,
                    "key": jira_response.key
                })),
            })
        } else if status == StatusCode::UNAUTHORIZED {
            Err(TicketingError::AuthenticationFailed(
                "Jira authentication failed".to_string(),
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
        } else {
            let error_response: Result<JiraErrorResponse, _> = response.json().await;
            let message = error_response
                .map(|e| e.error_messages.join(", "))
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(TicketingError::ApiError {
                status: status.as_u16(),
                message,
            })
        }
    }

    async fn get_ticket_status(
        &self,
        external_reference: &str,
    ) -> TicketingResult<TicketStatusResponse> {
        let url = self.api_url(&format!("issue/{}", external_reference));

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.email, Some(&self.api_token))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = response.status();

        if status.is_success() {
            let issue: JiraIssue = response.json().await?;

            let ticket_status = self.map_status_category(
                &issue.fields.status.status_category.key,
                &issue.fields.status.name,
            );

            let resolution_notes = issue
                .fields
                .resolution
                .map(|r| r.description.unwrap_or(r.name));

            Ok(TicketStatusResponse {
                status: ticket_status,
                resolution_notes,
                resolved_by: None, // Would need to query transitions/changelog
                last_updated: issue.fields.updated.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                raw_response: Some(serde_json::json!({
                    "status": issue.fields.status.name,
                    "status_category": issue.fields.status.status_category.key
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
        let url = self.api_url(&format!("issue/{}/comment", external_reference));

        let body = serde_json::json!({
            "body": JiraDescription::from_text(comment)
        });

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.email, Some(&self.api_token))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GovTicketingConfiguration {
        GovTicketingConfiguration {
            id: uuid::Uuid::new_v4(),
            tenant_id: uuid::Uuid::new_v4(),
            name: "Test".to_string(),
            ticketing_type: TicketingType::Jira,
            endpoint_url: "https://test.atlassian.net".to_string(),
            credentials: vec![],
            field_mappings: None,
            default_assignee: None,
            default_assignment_group: None,
            project_key: Some("TEST".to_string()),
            issue_type: Some("Task".to_string()),
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
            "email": "test@example.com",
            "api_token": "token"
        });

        let provider = JiraProvider::new(&config, &credentials).unwrap();

        assert_eq!(provider.map_priority(1), "Highest");
        assert_eq!(provider.map_priority(2), "High");
        assert_eq!(provider.map_priority(3), "Medium");
        assert_eq!(provider.map_priority(4), "Low");
    }

    #[test]
    fn test_status_category_mapping() {
        let config = test_config();
        let credentials = serde_json::json!({
            "email": "test@example.com",
            "api_token": "token"
        });

        let provider = JiraProvider::new(&config, &credentials).unwrap();

        assert_eq!(
            provider.map_status_category("new", "Open"),
            TicketStatus::Open
        );
        assert_eq!(
            provider.map_status_category("indeterminate", "In Progress"),
            TicketStatus::InProgress
        );
        assert_eq!(
            provider.map_status_category("done", "Done"),
            TicketStatus::Resolved
        );
        assert_eq!(
            provider.map_status_category("done", "Cancelled"),
            TicketStatus::Cancelled
        );
    }
}
