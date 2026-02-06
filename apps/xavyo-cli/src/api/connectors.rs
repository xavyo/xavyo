//! Connector API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::connector::{ConnectorListResponse, ConnectorResponse, CreateConnectorRequest};
use uuid::Uuid;

impl ApiClient {
    /// List connectors
    pub async fn list_connectors(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<ConnectorListResponse> {
        let url = format!(
            "{}/connectors?limit={}&offset={}",
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

    /// Get a single connector
    pub async fn get_connector(&self, id: Uuid) -> CliResult<ConnectorResponse> {
        let url = format!("{}/connectors/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Connector not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new connector
    pub async fn create_connector(
        &self,
        request: CreateConnectorRequest,
    ) -> CliResult<ConnectorResponse> {
        let url = format!("{}/connectors", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

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

    /// Delete a connector
    pub async fn delete_connector(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/connectors/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Connector not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Test a connector
    pub async fn test_connector(&self, id: Uuid) -> CliResult<serde_json::Value> {
        let url = format!("{}/connectors/{}/test", self.config().api_url, id);

        let response = self.post_json(&url, &serde_json::json!({})).await?;

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
}
