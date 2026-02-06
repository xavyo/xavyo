//! Profile API - Get current user profile

use crate::api::ApiClient;
use crate::error::{CliError, CliResult};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

/// User profile response from GET /me/profile
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

/// Get the current user's profile
pub async fn get_profile(api_client: &ApiClient) -> CliResult<ProfileResponse> {
    let url = api_client.config().profile_url();
    let response = api_client.get_authenticated(&url).await?;

    if response.status().is_success() {
        let profile: ProfileResponse = response.json().await.map_err(|e| CliError::Api {
            status: 200,
            message: format!("Unexpected response format: {e}"),
        })?;
        return Ok(profile);
    }

    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(CliError::NotAuthenticated);
    }

    let body = response.text().await.unwrap_or_default();
    Err(CliError::Api {
        status: status.as_u16(),
        message: format!("Failed to get profile: {body}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_response_deserialization() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "email": "test@example.com",
            "display_name": "Test User",
            "first_name": "Test",
            "last_name": "User",
            "avatar_url": null,
            "email_verified": true,
            "created_at": "2026-01-01T00:00:00Z"
        }"#;

        let profile: ProfileResponse = serde_json::from_str(json).unwrap();
        assert_eq!(profile.email, "test@example.com");
        assert!(profile.email_verified);
        assert_eq!(profile.display_name.as_deref(), Some("Test User"));
    }

    #[test]
    fn test_profile_response_unverified() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000002",
            "email": "new@example.com",
            "display_name": null,
            "first_name": null,
            "last_name": null,
            "avatar_url": null,
            "email_verified": false,
            "created_at": "2026-02-01T00:00:00Z"
        }"#;

        let profile: ProfileResponse = serde_json::from_str(json).unwrap();
        assert!(!profile.email_verified);
    }
}
