//! Tool API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::tool::{CreateToolRequest, ToolListResponse, ToolResponse};
use uuid::Uuid;

impl ApiClient {
    /// List all tools for the current tenant
    pub async fn list_tools(&self, limit: i32, offset: i32) -> CliResult<ToolListResponse> {
        let url = format!(
            "{}/nhi/tools?limit={}&offset={}",
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

    /// Get a single tool by ID
    pub async fn get_tool(&self, id: Uuid) -> CliResult<ToolResponse> {
        let url = format!("{}/nhi/tools/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Tool not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new tool
    pub async fn create_tool(&self, request: CreateToolRequest) -> CliResult<ToolResponse> {
        let url = format!("{}/nhi/tools", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::CONFLICT {
            Err(CliError::Conflict(format!(
                "Tool name already exists: {}",
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

    /// Delete a tool by ID
    pub async fn delete_tool(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/nhi/tools/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Tool not found: {id}")))
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
