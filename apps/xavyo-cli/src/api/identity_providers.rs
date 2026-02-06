//! Identity provider API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::identity_provider::{
    CreateIdentityProviderRequest, IdentityProviderListResponse, IdentityProviderResponse,
};
use uuid::Uuid;

impl ApiClient {
    /// List identity providers
    pub async fn list_identity_providers(
        &self,
        limit: i32,
        offset: i32,
    ) -> CliResult<IdentityProviderListResponse> {
        let url = format!(
            "{}/admin/federation/identity-providers?limit={}&offset={}",
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

    /// Get a single identity provider
    pub async fn get_identity_provider(&self, id: Uuid) -> CliResult<IdentityProviderResponse> {
        let url = format!(
            "{}/admin/federation/identity-providers/{}",
            self.config().api_url,
            id
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Identity provider not found: {id}"
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

    /// Create a new identity provider
    pub async fn create_identity_provider(
        &self,
        request: CreateIdentityProviderRequest,
    ) -> CliResult<IdentityProviderResponse> {
        let url = format!(
            "{}/admin/federation/identity-providers",
            self.config().api_url
        );

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

    /// Delete an identity provider
    pub async fn delete_identity_provider(&self, id: Uuid) -> CliResult<()> {
        let url = format!(
            "{}/admin/federation/identity-providers/{}",
            self.config().api_url,
            id
        );

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Identity provider not found: {id}"
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
}
