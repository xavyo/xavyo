//! SSO API client functions
//!
//! API functions for SSO authentication:
//! - IdP discovery by email domain
//! - SSO session creation
//! - SSO status polling
//! - Entity ID resolution
//!
//! Note: These functions are prepared for Phase 3 integration with the login command.

#![allow(dead_code)]

use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};

// Use the internal binary-side modules
use super::super::config::Config;
use super::super::error::{CliError, CliResult};

// Re-define the SSO types locally to avoid circular dependencies
// These match the types in sso/session.rs but are used only in the binary

/// SSO session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SSOState {
    Pending,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

/// SSO protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SSOProtocol {
    #[default]
    Saml,
    Oidc,
}

impl std::fmt::Display for SSOProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSOProtocol::Saml => write!(f, "SAML"),
            SSOProtocol::Oidc => write!(f, "OIDC"),
        }
    }
}

/// Identity Provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdPInfo {
    pub idp_url: String,
    pub entity_id: String,
    pub display_name: String,
    #[serde(default)]
    pub protocol: SSOProtocol,
}

/// SSO session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSession {
    pub session_id: String,
    pub state: String,
    pub verification_url: String,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,
}

/// SSO session status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSessionStatus {
    pub state: SSOState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
}

impl SSOSessionStatus {
    pub fn error_message(&self) -> Option<String> {
        match (&self.error, &self.error_description) {
            (Some(err), Some(desc)) => Some(format!("{}: {}", err, desc)),
            (Some(err), None) => Some(err.clone()),
            (None, Some(desc)) => Some(desc.clone()),
            (None, None) => None,
        }
    }

    pub fn expired() -> Self {
        Self {
            state: SSOState::Expired,
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: None,
            error_description: None,
            device_token: None,
        }
    }
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/// Request to discover IdP by email
#[derive(Debug, Serialize)]
struct DiscoverRequest {
    email: String,
}

/// Response from IdP discovery
#[derive(Debug, Deserialize)]
struct DiscoverResponse {
    idp_url: String,
    entity_id: String,
    display_name: String,
    #[serde(default)]
    protocol: String,
}

impl From<DiscoverResponse> for IdPInfo {
    fn from(resp: DiscoverResponse) -> Self {
        let protocol = match resp.protocol.to_lowercase().as_str() {
            "oidc" | "openid" => SSOProtocol::Oidc,
            _ => SSOProtocol::Saml,
        };
        IdPInfo {
            idp_url: resp.idp_url,
            entity_id: resp.entity_id,
            display_name: resp.display_name,
            protocol,
        }
    }
}

/// Request to start SSO session
#[derive(Debug, Serialize)]
struct StartSSORequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idp_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idp_entity_id: Option<String>,
}

/// Response from starting SSO session
#[derive(Debug, Deserialize)]
struct StartSSOResponse {
    session_id: String,
    state: String,
    verification_url: String,
    expires_in: u64,
    #[serde(default = "default_poll_interval")]
    poll_interval: u64,
}

fn default_poll_interval() -> u64 {
    2
}

/// Response from polling SSO status
#[derive(Debug, Deserialize)]
struct PollStatusResponse {
    state: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    device_token: Option<String>,
}

impl From<PollStatusResponse> for SSOSessionStatus {
    fn from(resp: PollStatusResponse) -> Self {
        let state = match resp.state.to_lowercase().as_str() {
            "pending" => SSOState::Pending,
            "completed" => SSOState::Completed,
            "failed" => SSOState::Failed,
            "expired" => SSOState::Expired,
            "cancelled" => SSOState::Cancelled,
            _ => SSOState::Pending,
        };

        SSOSessionStatus {
            state,
            access_token: resp.access_token,
            refresh_token: resp.refresh_token,
            expires_in: resp.expires_in,
            error: resp.error,
            error_description: resp.error_description,
            device_token: resp.device_token,
        }
    }
}

/// Request to resolve entity ID
#[derive(Debug, Serialize)]
struct ResolveEntityIdRequest {
    entity_id: String,
}

/// Response from entity ID resolution
#[derive(Debug, Deserialize)]
struct ResolveEntityIdResponse {
    idp_url: String,
    entity_id: String,
    display_name: String,
    #[serde(default)]
    protocol: String,
}

/// API error response
#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

// ============================================================================
// API Functions
// ============================================================================

/// Discover IdP by email domain
///
/// Calls `GET /auth/sso/discover?email=...` to find the SSO provider
/// for the user's email domain.
pub async fn discover_idp(client: &Client, config: &Config, email: &str) -> CliResult<IdPInfo> {
    let url = format!(
        "{}?email={}",
        config.sso_discover_url(),
        urlencoding::encode(email)
    );

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::Network(format!("Failed to discover IdP: {}", e)))?;

    let status = response.status();

    if status.is_success() {
        let discover_response: DiscoverResponse = response
            .json()
            .await
            .map_err(|e| CliError::Network(format!("Invalid discovery response: {}", e)))?;

        Ok(discover_response.into())
    } else if status == reqwest::StatusCode::NOT_FOUND {
        // Extract domain from email for error message
        let domain = email.split('@').nth(1).unwrap_or(email);
        Err(CliError::SsoNotConfigured(domain.to_string()))
    } else {
        let error_response: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
            error: "unknown_error".to_string(),
            error_description: Some(format!("HTTP {}", status)),
        });

        Err(CliError::SsoFailed(
            error_response
                .error_description
                .unwrap_or(error_response.error),
        ))
    }
}

/// Start an SSO session
///
/// Calls `POST /auth/sso/start` to create a new SSO session.
/// Returns the session ID and verification URL for browser handoff.
pub async fn start_sso_session(
    client: &Client,
    config: &Config,
    email: Option<&str>,
    idp_url: Option<&str>,
    idp_entity_id: Option<&str>,
) -> CliResult<SSOSession> {
    let request = StartSSORequest {
        email: email.map(String::from),
        idp_url: idp_url.map(String::from),
        idp_entity_id: idp_entity_id.map(String::from),
    };

    let response = client
        .post(config.sso_start_url())
        .json(&request)
        .send()
        .await
        .map_err(|e| CliError::Network(format!("Failed to start SSO session: {}", e)))?;

    let status = response.status();

    if status.is_success() {
        let start_response: StartSSOResponse = response
            .json()
            .await
            .map_err(|e| CliError::Network(format!("Invalid SSO start response: {}", e)))?;

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(start_response.expires_in as i64);

        Ok(SSOSession {
            session_id: start_response.session_id,
            state: start_response.state,
            verification_url: start_response.verification_url,
            created_at: now,
            expires_at,
            poll_interval: start_response.poll_interval,
        })
    } else {
        let error_response: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
            error: "unknown_error".to_string(),
            error_description: Some(format!("HTTP {}", status)),
        });

        Err(CliError::SsoFailed(
            error_response
                .error_description
                .unwrap_or(error_response.error),
        ))
    }
}

/// Poll SSO session status
///
/// Calls `GET /auth/sso/status/{session_id}` to check authentication status.
pub async fn poll_sso_status(
    client: &Client,
    config: &Config,
    session_id: &str,
) -> CliResult<SSOSessionStatus> {
    let url = config.sso_status_url(session_id);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::Network(format!("Failed to poll SSO status: {}", e)))?;

    let status = response.status();

    if status.is_success() {
        let poll_response: PollStatusResponse = response
            .json()
            .await
            .map_err(|e| CliError::Network(format!("Invalid SSO status response: {}", e)))?;

        Ok(poll_response.into())
    } else if status == reqwest::StatusCode::NOT_FOUND {
        // Session not found = expired
        Ok(SSOSessionStatus::expired())
    } else {
        let error_response: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
            error: "unknown_error".to_string(),
            error_description: Some(format!("HTTP {}", status)),
        });

        Err(CliError::SsoFailed(
            error_response
                .error_description
                .unwrap_or(error_response.error),
        ))
    }
}

/// Resolve IdP entity ID to URL
///
/// Calls `POST /auth/sso/resolve` to resolve an entity ID to an IdP URL.
pub async fn resolve_entity_id(
    client: &Client,
    config: &Config,
    entity_id: &str,
) -> CliResult<IdPInfo> {
    let request = ResolveEntityIdRequest {
        entity_id: entity_id.to_string(),
    };

    let response = client
        .post(config.sso_resolve_url())
        .json(&request)
        .send()
        .await
        .map_err(|e| CliError::Network(format!("Failed to resolve entity ID: {}", e)))?;

    let status = response.status();

    if status.is_success() {
        let resolve_response: ResolveEntityIdResponse = response
            .json()
            .await
            .map_err(|e| CliError::Network(format!("Invalid resolve response: {}", e)))?;

        let protocol = match resolve_response.protocol.to_lowercase().as_str() {
            "oidc" | "openid" => SSOProtocol::Oidc,
            _ => SSOProtocol::Saml,
        };

        Ok(IdPInfo {
            idp_url: resolve_response.idp_url,
            entity_id: resolve_response.entity_id,
            display_name: resolve_response.display_name,
            protocol,
        })
    } else if status == reqwest::StatusCode::NOT_FOUND {
        Err(CliError::SsoNotConfigured(entity_id.to_string()))
    } else {
        let error_response: ApiErrorResponse = response.json().await.unwrap_or(ApiErrorResponse {
            error: "unknown_error".to_string(),
            error_description: Some(format!("HTTP {}", status)),
        });

        Err(CliError::SsoFailed(
            error_response
                .error_description
                .unwrap_or(error_response.error),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_response_to_idp_info_saml() {
        let resp = DiscoverResponse {
            idp_url: "https://idp.example.com".to_string(),
            entity_id: "urn:example".to_string(),
            display_name: "Example Corp".to_string(),
            protocol: "saml".to_string(),
        };

        let info: IdPInfo = resp.into();
        assert_eq!(info.idp_url, "https://idp.example.com");
        assert_eq!(info.entity_id, "urn:example");
        assert_eq!(info.display_name, "Example Corp");
        assert_eq!(info.protocol, SSOProtocol::Saml);
    }

    #[test]
    fn test_discover_response_to_idp_info_oidc() {
        let resp = DiscoverResponse {
            idp_url: "https://idp.example.com".to_string(),
            entity_id: "https://example.com".to_string(),
            display_name: "Example Corp".to_string(),
            protocol: "oidc".to_string(),
        };

        let info: IdPInfo = resp.into();
        assert_eq!(info.protocol, SSOProtocol::Oidc);
    }

    #[test]
    fn test_poll_status_response_to_session_status_pending() {
        let resp = PollStatusResponse {
            state: "pending".to_string(),
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: None,
            error_description: None,
            device_token: None,
        };

        let status: SSOSessionStatus = resp.into();
        assert_eq!(status.state, SSOState::Pending);
        assert!(status.access_token.is_none());
    }

    #[test]
    fn test_poll_status_response_to_session_status_completed() {
        let resp = PollStatusResponse {
            state: "completed".to_string(),
            access_token: Some("token".to_string()),
            refresh_token: Some("refresh".to_string()),
            expires_in: Some(3600),
            error: None,
            error_description: None,
            device_token: None,
        };

        let status: SSOSessionStatus = resp.into();
        assert_eq!(status.state, SSOState::Completed);
        assert_eq!(status.access_token, Some("token".to_string()));
        assert_eq!(status.refresh_token, Some("refresh".to_string()));
        assert_eq!(status.expires_in, Some(3600));
    }

    #[test]
    fn test_poll_status_response_to_session_status_failed() {
        let resp = PollStatusResponse {
            state: "failed".to_string(),
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some("auth_error".to_string()),
            error_description: Some("User denied".to_string()),
            device_token: None,
        };

        let status: SSOSessionStatus = resp.into();
        assert_eq!(status.state, SSOState::Failed);
        assert_eq!(status.error, Some("auth_error".to_string()));
        assert_eq!(status.error_description, Some("User denied".to_string()));
    }

    #[test]
    fn test_start_sso_request_serialization() {
        let request = StartSSORequest {
            email: Some("user@example.com".to_string()),
            idp_url: None,
            idp_entity_id: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("user@example.com"));
        assert!(!json.contains("idp_url"));
        assert!(!json.contains("idp_entity_id"));
    }
}
