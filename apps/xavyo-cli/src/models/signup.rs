//! Signup response model

use serde::Deserialize;
use uuid::Uuid;

/// Response from the signup API endpoint
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SignupResponse {
    /// UUID of the created user
    pub user_id: Uuid,

    /// Normalized email address
    pub email: String,

    /// Whether email has been verified (always false on signup)
    pub email_verified: bool,

    /// JWT access token for immediate use
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Access token validity in seconds
    pub expires_in: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signup_response_deserialization() {
        let json = r#"{
            "user_id": "00000000-0000-0000-0000-000000000001",
            "email": "test@example.com",
            "email_verified": false,
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;

        let response: SignupResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.email, "test@example.com");
        assert!(!response.email_verified);
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
    }
}
