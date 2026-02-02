//! Authorization API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::authorize::{AuthorizeRequest, AuthorizeResponse};

impl ApiClient {
    /// Authorize an agent action
    pub async fn authorize(&self, request: AuthorizeRequest) -> CliResult<AuthorizeResponse> {
        let url = format!("{}/nhi/agents/authorize", self.config().api_url);

        let response = self.post_json(&url, &request).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
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
