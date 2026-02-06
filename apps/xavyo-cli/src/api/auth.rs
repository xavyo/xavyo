//! Authentication APIs - Device code OAuth and signup

use crate::config::Config;
use crate::error::{CliError, CliResult};
use crate::models::token::OAuthError;
use crate::models::{DeviceCodeResponse, SignupResponse, TokenResponse};
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// Request a device code for authentication
pub async fn request_device_code(
    client: &Client,
    config: &Config,
) -> CliResult<DeviceCodeResponse> {
    let response = client
        .post(config.device_code_url())
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("scope", "openid profile email"),
        ])
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(CliError::AuthenticationFailed(format!(
            "Failed to request device code: {status} - {body}"
        )));
    }

    let device_code: DeviceCodeResponse = response.json().await.map_err(|e| {
        CliError::AuthenticationFailed(format!("Invalid device code response: {e}"))
    })?;

    Ok(device_code)
}

/// Poll for device token after user authentication
///
/// Returns Ok(Some(token)) when authentication is complete,
/// Ok(None) when still pending, or Err on failure.
pub async fn poll_device_token(
    client: &Client,
    config: &Config,
    device_code: &str,
) -> CliResult<Option<TokenResponse>> {
    let response = client
        .post(config.device_token_url())
        .form(&[
            ("client_id", config.client_id.as_str()),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await?;

    if response.status().is_success() {
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|e| CliError::AuthenticationFailed(format!("Invalid token response: {e}")))?;
        return Ok(Some(token));
    }

    // Check for expected error responses
    let error: OAuthError = response
        .json()
        .await
        .map_err(|e| CliError::AuthenticationFailed(format!("Invalid error response: {e}")))?;

    if error.is_authorization_pending() || error.is_slow_down() {
        // Still waiting for user to authenticate
        return Ok(None);
    }

    if error.is_access_denied() {
        return Err(CliError::AuthorizationDenied);
    }

    if error.is_expired_token() {
        return Err(CliError::DeviceCodeExpired);
    }

    // Other error
    Err(CliError::AuthenticationFailed(
        error
            .error_description
            .unwrap_or_else(|| error.error.clone()),
    ))
}

/// Resend verification request payload
#[derive(Debug, Serialize)]
struct ResendVerificationRequest<'a> {
    email: &'a str,
}

/// Resend verification response
#[derive(Debug, Deserialize)]
pub struct ResendVerificationResponse {
    pub message: String,
}

/// Resend email verification for an unverified account
pub async fn resend_verification(
    client: &Client,
    config: &Config,
    email: &str,
    tenant_id: &str,
) -> CliResult<ResendVerificationResponse> {
    let request = ResendVerificationRequest { email };

    let response = client
        .post(config.resend_verification_url())
        .header("X-Tenant-ID", tenant_id)
        .json(&request)
        .send()
        .await?;

    if response.status().is_success() {
        let resend_response: ResendVerificationResponse = response.json().await.map_err(|e| {
            CliError::AuthenticationFailed(format!("Invalid resend verification response: {e}"))
        })?;
        return Ok(resend_response);
    }

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(CliError::Validation(
            "Too many requests. Please wait a moment and try again.".to_string(),
        ));
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(CliError::AuthenticationFailed(format!(
        "Resend verification failed: {status} - {body}"
    )))
}

/// Signup request payload
#[derive(Debug, Serialize)]
struct SignupRequest<'a> {
    email: &'a str,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<&'a str>,
}

/// Create a new account in the system tenant
pub async fn signup(
    client: &Client,
    config: &Config,
    email: &str,
    password: &str,
    display_name: Option<&str>,
) -> CliResult<SignupResponse> {
    let request = SignupRequest {
        email,
        password,
        display_name,
    };

    let response = client
        .post(config.signup_url())
        .json(&request)
        .send()
        .await?;

    if response.status().is_success() {
        let signup_response: SignupResponse = response
            .json()
            .await
            .map_err(|e| CliError::AuthenticationFailed(format!("Invalid signup response: {e}")))?;
        return Ok(signup_response);
    }

    // Handle error response
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    // Try to parse error JSON
    if let Ok(error) = serde_json::from_str::<serde_json::Value>(&body) {
        let message = error
            .get("message")
            .or_else(|| error.get("error"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        return Err(CliError::AuthenticationFailed(message.to_string()));
    }

    Err(CliError::AuthenticationFailed(format!(
        "Signup failed: {status} - {body}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_error_parsing() {
        let json = r#"{"error": "authorization_pending", "error_description": "Waiting for user"}"#;
        let error: OAuthError = serde_json::from_str(json).unwrap();
        assert!(error.is_authorization_pending());
    }

    #[test]
    fn test_signup_request_serialization() {
        let request = SignupRequest {
            email: "test@example.com",
            password: "password123",
            display_name: Some("Test User"),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test@example.com"));
        assert!(json.contains("password123"));
        assert!(json.contains("Test User"));
    }

    #[test]
    fn test_signup_request_without_display_name() {
        let request = SignupRequest {
            email: "test@example.com",
            password: "password123",
            display_name: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("display_name"));
    }

    #[test]
    fn test_resend_verification_request_serialization() {
        let request = ResendVerificationRequest {
            email: "user@example.com",
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(json, r#"{"email":"user@example.com"}"#);
    }

    #[test]
    fn test_resend_verification_response_deserialization() {
        let json = r#"{"message":"If an unverified account exists with this email, you will receive a verification link."}"#;
        let response: ResendVerificationResponse = serde_json::from_str(json).unwrap();
        assert!(response.message.contains("verification link"));
    }
}
