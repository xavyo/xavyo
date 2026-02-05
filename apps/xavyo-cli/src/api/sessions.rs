//! Sessions API client methods

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use crate::models::api_session::{ApiSession, RevokeResponse, SessionListResponse};
use uuid::Uuid;

impl ApiClient {
    /// List all active sessions for the current user
    ///
    /// # Arguments
    /// * `limit` - Maximum number of sessions to return (default 50, max 100)
    /// * `cursor` - Pagination cursor from previous response
    pub async fn list_sessions(
        &self,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> CliResult<SessionListResponse> {
        let mut url = format!("{}/users/me/sessions", self.config().api_url);

        // Add query parameters
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(cursor) = cursor {
            params.push(format!("cursor={}", cursor));
        }
        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::AuthenticationFailed(
                "Not authenticated. Please run 'xavyo login' first.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Get details of a specific session
    ///
    /// # Arguments
    /// * `session_id` - The session ID to retrieve
    pub async fn get_session(&self, session_id: Uuid) -> CliResult<ApiSession> {
        let url = format!("{}/users/me/sessions/{}", self.config().api_url, session_id);

        let response = self.get_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Session not found: {}",
                session_id
            )))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::AuthenticationFailed(
                "Not authenticated. Please run 'xavyo login' first.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Revoke a specific session
    ///
    /// # Arguments
    /// * `session_id` - The session ID to revoke
    pub async fn revoke_session(&self, session_id: Uuid) -> CliResult<RevokeResponse> {
        let url = format!("{}/users/me/sessions/{}", self.config().api_url, session_id);

        let response = self.delete_authenticated(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            Err(CliError::NotFound(format!(
                "Session not found: {}",
                session_id
            )))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::AuthenticationFailed(
                "Not authenticated. Please run 'xavyo login' first.".to_string(),
            ))
        } else {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            Err(CliError::Api {
                status: status.as_u16(),
                message: body,
            })
        }
    }

    /// Revoke all sessions except the current one
    pub async fn revoke_all_sessions(&self) -> CliResult<RevokeResponse> {
        let url = format!("{}/users/me/sessions/revoke-all", self.config().api_url);

        let response = self.post_empty(&url).await?;

        if response.status().is_success() {
            response.json().await.map_err(Into::into)
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(CliError::AuthenticationFailed(
                "Not authenticated. Please run 'xavyo login' first.".to_string(),
            ))
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
