//! Security policy API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use uuid::Uuid;

impl ApiClient {
    /// Get a security policy for an organization/tenant
    pub async fn get_policy(
        &self,
        tenant_id: Uuid,
        policy_type: &str,
    ) -> CliResult<serde_json::Value> {
        let url = format!(
            "{}/organizations/{}/security-policies/{}",
            self.config().api_url,
            tenant_id,
            policy_type
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

    /// Update a security policy for an organization/tenant
    pub async fn update_policy(
        &self,
        tenant_id: Uuid,
        policy_type: &str,
        policy: &serde_json::Value,
    ) -> CliResult<serde_json::Value> {
        let url = format!(
            "{}/organizations/{}/security-policies/{}",
            self.config().api_url,
            tenant_id,
            policy_type
        );

        let response = self.put_json(&url, policy).await?;

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
