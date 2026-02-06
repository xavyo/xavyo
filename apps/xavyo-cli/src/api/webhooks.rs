//! Webhook API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::webhook::{
    CreateWebhookRequest, UpdateWebhookRequest, WebhookListResponse, WebhookResponse,
};
use uuid::Uuid;

impl ApiClient {
    /// List webhook subscriptions
    pub async fn list_webhooks(&self, limit: i32, offset: i32) -> CliResult<WebhookListResponse> {
        let url = format!(
            "{}/webhooks/subscriptions?limit={}&offset={}",
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

    /// Get a single webhook subscription
    pub async fn get_webhook(&self, id: Uuid) -> CliResult<WebhookResponse> {
        let url = format!("{}/webhooks/subscriptions/{}", self.config().api_url, id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Webhook not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Create a new webhook subscription
    pub async fn create_webhook(
        &self,
        request: CreateWebhookRequest,
    ) -> CliResult<WebhookResponse> {
        let url = format!("{}/webhooks/subscriptions", self.config().api_url);

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

    /// Update a webhook subscription
    pub async fn update_webhook(
        &self,
        id: Uuid,
        request: UpdateWebhookRequest,
    ) -> CliResult<WebhookResponse> {
        let url = format!("{}/webhooks/subscriptions/{}", self.config().api_url, id);

        let response = self.patch_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Webhook not found: {id}")))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Delete a webhook subscription
    pub async fn delete_webhook(&self, id: Uuid) -> CliResult<()> {
        let url = format!("{}/webhooks/subscriptions/{}", self.config().api_url, id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() || response.status() == reqwest::StatusCode::NO_CONTENT {
            Ok(())
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!("Webhook not found: {id}")))
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
