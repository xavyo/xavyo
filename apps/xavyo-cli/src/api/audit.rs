//! Audit log API client for the xavyo CLI

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::audit::{AuditFilter, AuditListResponse};

impl ApiClient {
    /// List login history entries with optional filtering
    pub async fn list_audit_logs(&self, filter: &AuditFilter) -> CliResult<AuditListResponse> {
        let url = format!(
            "{}/audit/login-history?{}",
            self.config().api_url,
            filter.to_query_string()
        );

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::NotAuthenticated)
        } else if response.status() == reqwest::StatusCode::FORBIDDEN {
            Err(CliError::AuthorizationDenied)
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
