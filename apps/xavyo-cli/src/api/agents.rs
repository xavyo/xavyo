//! Agent API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::agent::{
    AgentListResponse, AgentResponse, CreateAgentRequest, NhiCredentialCreatedResponse,
    NhiCredentialListResponse, NhiCredentialResponse, RevokeCredentialRequest,
    RotateCredentialsRequest,
};
use uuid::Uuid;

impl ApiClient {
    /// List all agents for the current tenant
    pub async fn list_agents(&self, limit: i32, offset: i32) -> CliResult<AgentListResponse> {
        let url = format!(
            "{}/nhi/agents?limit={}&offset={}",
            self.config().api_url,
            limit,
            offset
        );

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

    // =========================================================================
    // Agent Credential Methods (F110)
    // =========================================================================

    /// List credentials for an agent
    pub async fn list_agent_credentials(
        &self,
        agent_id: Uuid,
        active_only: bool,
    ) -> CliResult<NhiCredentialListResponse> {
        let url = format!(
            "{}/nhi/agents/{}/credentials?active_only={}",
            self.config().api_url,
            agent_id,
            active_only
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Agent not found: {agent_id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get a specific credential for an agent
    pub async fn get_agent_credential(
        &self,
        agent_id: Uuid,
        credential_id: Uuid,
    ) -> CliResult<NhiCredentialResponse> {
        let url = format!(
            "{}/nhi/agents/{}/credentials/{}",
            self.config().api_url,
            agent_id,
            credential_id
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Credential not found: {credential_id}"
            )))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Rotate credentials for an agent
    pub async fn rotate_agent_credentials(
        &self,
        agent_id: Uuid,
        request: RotateCredentialsRequest,
    ) -> CliResult<NhiCredentialCreatedResponse> {
        let url = format!(
            "{}/nhi/agents/{}/credentials/rotate",
            self.config().api_url,
            agent_id
        );

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Agent not found: {agent_id}")))
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

    /// Revoke a credential for an agent
    pub async fn revoke_agent_credential(
        &self,
        agent_id: Uuid,
        credential_id: Uuid,
        request: RevokeCredentialRequest,
    ) -> CliResult<NhiCredentialResponse> {
        let url = format!(
            "{}/nhi/agents/{}/credentials/{}/revoke",
            self.config().api_url,
            agent_id,
            credential_id
        );

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Credential not found: {credential_id}"
            )))
        } else if response.status() == reqwest::StatusCode::BAD_REQUEST {
            let body = response.text().await.unwrap_or_default();
            // Check if it's already revoked
            if body.contains("already revoked") {
                Err(CliError::Validation(
                    "Credential is already revoked".to_string(),
                ))
            } else {
                Err(CliError::Validation(body))
            }
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
