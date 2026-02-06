//! Group API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::group::GroupListResponse;

impl ApiClient {
    /// List groups for the current tenant
    pub async fn list_groups(&self, limit: i32, offset: i32) -> CliResult<GroupListResponse> {
        let url = format!(
            "{}/admin/groups?limit={}&offset={}",
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
}
