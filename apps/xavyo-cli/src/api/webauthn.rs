//! WebAuthn API client functions for xavyo-cli
//!
//! Provides functions to interact with the WebAuthn endpoints on the server.

use crate::config::Config;
use crate::error::{CliError, CliResult};
use crate::models::webauthn::{
    BrowserHandoffRequest, BrowserHandoffSession, BrowserHandoffStatus, PasskeyChallenge,
    PasskeyInfo, PasskeyVerifyRequest, PasskeyVerifyResponse, WebAuthnError,
};

/// Get a passkey authentication challenge from the server
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration with API endpoints
/// * `device_token` - Optional device trust token to skip MFA
#[allow(dead_code)]
pub async fn get_passkey_challenge(
    client: &reqwest::Client,
    config: &Config,
    device_token: Option<&str>,
) -> CliResult<PasskeyChallenge> {
    let url = config.webauthn_challenge_url();

    let mut request = client.get(&url);

    if let Some(token) = device_token {
        request = request.header("X-Device-Trust-Token", token);
    }

    let response = request.send().await?;

    if response.status().is_success() {
        let challenge: PasskeyChallenge = response.json().await?;
        Ok(challenge)
    } else if response.status().as_u16() == 404 {
        Err(CliError::PasskeyNotConfigured)
    } else {
        let error: WebAuthnError = response.json().await.unwrap_or_else(|_| WebAuthnError {
            error: "unknown".to_string(),
            error_description: Some("Failed to get passkey challenge".to_string()),
            retries_remaining: None,
        });
        Err(CliError::PasskeyError(error.message()))
    }
}

/// Verify a passkey assertion with the server
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration with API endpoints
/// * `request` - Passkey verification request with assertion data
#[allow(dead_code)]
pub async fn verify_passkey(
    client: &reqwest::Client,
    config: &Config,
    request: &PasskeyVerifyRequest,
) -> CliResult<PasskeyVerifyResponse> {
    let url = config.webauthn_verify_url();

    let response = client.post(&url).json(request).send().await?;

    if response.status().is_success() {
        let verify_response: PasskeyVerifyResponse = response.json().await?;
        Ok(verify_response)
    } else {
        let error: WebAuthnError = response.json().await.unwrap_or_else(|_| WebAuthnError {
            error: "unknown".to_string(),
            error_description: Some("Passkey verification failed".to_string()),
            retries_remaining: None,
        });

        if error.is_timeout() {
            Err(CliError::PasskeyTimeout)
        } else if error.is_credential_not_found() {
            Err(CliError::PasskeyError(
                "Credential not recognized. You may need to re-register your passkey.".to_string(),
            ))
        } else {
            Err(CliError::PasskeyError(error.message()))
        }
    }
}

/// Create a browser handoff session for platform authenticator
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration with API endpoints
/// * `challenge_id` - The challenge ID to create handoff for
#[allow(dead_code)]
pub async fn create_browser_handoff(
    client: &reqwest::Client,
    config: &Config,
    challenge_id: &str,
) -> CliResult<BrowserHandoffSession> {
    let url = config.webauthn_handoff_url();

    let request = BrowserHandoffRequest {
        challenge_id: challenge_id.to_string(),
    };

    let response = client.post(&url).json(&request).send().await?;

    if response.status().is_success() {
        let session: BrowserHandoffSession = response.json().await?;
        Ok(session)
    } else {
        let error: WebAuthnError = response.json().await.unwrap_or_else(|_| WebAuthnError {
            error: "unknown".to_string(),
            error_description: Some("Failed to create browser handoff session".to_string()),
            retries_remaining: None,
        });
        Err(CliError::PasskeyError(error.message()))
    }
}

/// Poll the status of a browser handoff session
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration with API endpoints
/// * `session_id` - The handoff session ID to poll
#[allow(dead_code)]
pub async fn poll_handoff_status(
    client: &reqwest::Client,
    config: &Config,
    session_id: &str,
) -> CliResult<BrowserHandoffStatus> {
    let url = format!("{}/{}", config.webauthn_handoff_url(), session_id);

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let status: BrowserHandoffStatus = response.json().await?;
        Ok(status)
    } else if response.status().as_u16() == 404 {
        Err(CliError::PasskeyTimeout)
    } else {
        let error: WebAuthnError = response.json().await.unwrap_or_else(|_| WebAuthnError {
            error: "unknown".to_string(),
            error_description: Some("Failed to get handoff status".to_string()),
            retries_remaining: None,
        });
        Err(CliError::PasskeyError(error.message()))
    }
}

/// Get the user's registered passkeys
///
/// # Arguments
/// * `client` - HTTP client
/// * `config` - CLI configuration with API endpoints
/// * `access_token` - Bearer token for authentication
#[allow(dead_code)]
pub async fn get_user_passkeys(
    client: &reqwest::Client,
    config: &Config,
    access_token: &str,
) -> CliResult<PasskeyInfo> {
    let url = config.user_passkeys_url();

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?;

    if response.status().is_success() {
        let info: PasskeyInfo = response.json().await?;
        Ok(info)
    } else if response.status().as_u16() == 401 {
        Err(CliError::NotAuthenticated)
    } else {
        // Return empty passkey info on error (non-critical)
        Ok(PasskeyInfo {
            count: 0,
            passkeys: vec![],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> Config {
        Config {
            api_url: "https://api.test.xavyo.io".to_string(),
            auth_url: "https://auth.test.xavyo.io".to_string(),
            client_id: "test-client".to_string(),
            timeout_secs: 30,
        }
    }

    #[test]
    fn test_config_webauthn_urls() {
        let config = create_test_config();
        assert!(config
            .webauthn_challenge_url()
            .contains("/auth/webauthn/challenge"));
        assert!(config
            .webauthn_verify_url()
            .contains("/auth/webauthn/verify"));
        assert!(config
            .webauthn_handoff_url()
            .contains("/auth/webauthn/browser-handoff"));
        assert!(config.user_passkeys_url().contains("/users/me/passkeys"));
    }
}
