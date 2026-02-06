//! Service account API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::service_account::{
    CreateServiceAccountRequest, ServiceAccountListResponse, ServiceAccountResponse,
    UpdateServiceAccountRequest,
};
use uuid::Uuid;

impl ApiClient {
    /// List service accounts
    pub async fn list_service_accounts(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<ServiceAccountListResponse> {
        let url = format!(
            "{}/nhi/service-accounts?limit={}&offset={}",
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

    /// Get a single service account by ID
    pub async fn get_service_account(&self, id: Uuid) -> CliResult<ServiceAccountResponse> {
        let url = format!("{}/nhi/service-accounts/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Service account not found: {id}"
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

    /// Create a new service account
    pub async fn create_service_account(
        &self,
        request: CreateServiceAccountRequest,
    ) -> CliResult<ServiceAccountResponse> {
        let url = format!("{}/nhi/service-accounts", self.config().api_url);

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

    /// Update a service account
    pub async fn update_service_account(
        &self,
        id: Uuid,
        request: UpdateServiceAccountRequest,
    ) -> CliResult<ServiceAccountResponse> {
        let url = format!("{}/nhi/service-accounts/{}", self.config().api_url, id);

        let response = self.put_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Service account not found: {id}"
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

    /// Delete a service account
    pub async fn delete_service_account(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/nhi/service-accounts/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Service account not found: {id}"
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

    /// Suspend a service account
    pub async fn suspend_service_account(&self, id: Uuid) -> CliResult<ServiceAccountResponse> {
        let url = format!(
            "{}/nhi/service-accounts/{}/suspend",
            self.config().api_url,
            id
        );

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

    /// Reactivate a service account
    pub async fn reactivate_service_account(&self, id: Uuid) -> CliResult<ServiceAccountResponse> {
        let url = format!(
            "{}/nhi/service-accounts/{}/reactivate",
            self.config().api_url,
            id
        );

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
