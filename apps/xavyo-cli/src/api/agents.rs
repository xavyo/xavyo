//! Agent API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::agent::{
    AgentListResponse, AgentResponse, CreateAgentRequest, UpdateAgentRequest,
};
use uuid::Uuid;

impl ApiClient {
    /// List all agents for the current tenant with optional filters
    pub async fn list_agents(
        &self,
        limit: i32,
        offset: i32,
        type_filter: Option<&str>,
        status_filter: Option<&str>,
    ) -> CliResult<AgentListResponse> {
        let mut url = format!(
            "{}/nhi/agents?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );

        // Add optional filters
        if let Some(agent_type) = type_filter {
            url.push_str(&format!("&type={}", agent_type));
        }
        if let Some(status) = status_filter {
            url.push_str(&format!("&status={}", status));
        }

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a single agent by ID
    pub async fn get_agent(&self, id: Uuid) -> CliResult<AgentResponse> {
        let url = format!("{}/nhi/agents/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Agent not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new agent
    pub async fn create_agent(&self, request: CreateAgentRequest) -> CliResult<AgentResponse> {
        let url = format!("{}/nhi/agents", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::CONFLICT {
            Err(CliError::Conflict(format!(
                "Agent name already exists: {}",
                request.name
            )))
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Validation(body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Delete an agent by ID
    pub async fn delete_agent(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/nhi/agents/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Agent not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Update an existing agent (F-051)
    pub async fn update_agent(
        &self,
        id: Uuid,
        request: UpdateAgentRequest,
    ) -> CliResult<AgentResponse> {
        let url = format!("{}/nhi/agents/{}", self.config().api_url, id);

        let response = self.patch_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Agent not found: {id}")))
        } else if response.status() == reqwest::StatusCode::CONFLICT {
            Err(CliError::Conflict("Agent name already exists".to_string()))
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Validation(body))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }
}
