//! Common test utilities and fixtures for provider integration tests

use serde::{Deserialize, Serialize};

/// Mock user data returned by social providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockUser {
    pub id: String,
    pub email: String,
    pub name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub provider_id: String,
    pub avatar_url: Option<String>,
    pub email_verified: bool,
    pub is_private_email: bool,
}

impl MockUser {
    #[must_use]
    pub fn google() -> Self {
        Self {
            id: "google-test-user".to_string(),
            email: "testuser@gmail.com".to_string(),
            name: "Google Test User".to_string(),
            first_name: Some("Google".to_string()),
            last_name: Some("User".to_string()),
            provider_id: "117730572023847612345".to_string(),
            avatar_url: Some("https://example.com/avatar.jpg".to_string()),
            email_verified: true,
            is_private_email: false,
        }
    }

    #[must_use]
    pub fn microsoft() -> Self {
        Self {
            id: "microsoft-test-user".to_string(),
            email: "testuser@outlook.com".to_string(),
            name: "Microsoft Test User".to_string(),
            first_name: Some("Microsoft".to_string()),
            last_name: Some("User".to_string()),
            provider_id: "00000000-0000-0000-0000-000000000001".to_string(),
            avatar_url: None,
            email_verified: true,
            is_private_email: false,
        }
    }

    #[must_use]
    pub fn apple() -> Self {
        Self {
            id: "apple-test-user".to_string(),
            email: "testuser@privaterelay.appleid.com".to_string(),
            name: "Apple Test User".to_string(),
            first_name: Some("Apple".to_string()),
            last_name: Some("User".to_string()),
            provider_id: "001234.abcdef1234567890.1234".to_string(),
            avatar_url: None,
            email_verified: true,
            is_private_email: true,
        }
    }

    #[must_use]
    pub fn apple_real_email() -> Self {
        Self {
            id: "apple-test-user-real".to_string(),
            email: "realuser@example.com".to_string(),
            name: "Apple Real Email User".to_string(),
            first_name: Some("Apple".to_string()),
            last_name: Some("Real".to_string()),
            provider_id: "001235.bcdef01234567890.5678".to_string(),
            avatar_url: None,
            email_verified: true,
            is_private_email: false,
        }
    }

    #[must_use]
    pub fn github() -> Self {
        Self {
            id: "github-test-user".to_string(),
            email: "testuser@github.com".to_string(),
            name: "GitHub Test User".to_string(),
            first_name: None,
            last_name: None,
            provider_id: "12345678".to_string(),
            avatar_url: Some("https://avatars.githubusercontent.com/u/12345678".to_string()),
            email_verified: true,
            is_private_email: false,
        }
    }

    #[must_use]
    pub fn github_private_email() -> Self {
        Self {
            id: "github-test-user-private".to_string(),
            email: "12345678+testuser@users.noreply.github.com".to_string(),
            name: "GitHub Private User".to_string(),
            first_name: None,
            last_name: None,
            provider_id: "12345679".to_string(),
            avatar_url: Some("https://avatars.githubusercontent.com/u/12345679".to_string()),
            email_verified: true,
            is_private_email: true,
        }
    }
}

/// Mock `OAuth2` tokens returned by providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockToken {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: String,
    pub id_token: Option<String>,
}

impl MockToken {
    #[must_use]
    pub fn google() -> Self {
        Self {
            access_token: "ya29.mock_google_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("1//mock_google_refresh".to_string()),
            scope: "openid email profile".to_string(),
            id_token: Some("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.mock_google_id_token".to_string()),
        }
    }

    #[must_use]
    pub fn microsoft() -> Self {
        Self {
            access_token: "eyJ0mock_ms_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("mock_ms_refresh_token".to_string()),
            scope: "openid profile email User.Read".to_string(),
            // Valid JWT structure: header.payload.signature
            id_token: Some("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.mock_signature".to_string()),
        }
    }

    #[must_use]
    pub fn apple() -> Self {
        Self {
            access_token: "mock_apple_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("mock_apple_refresh_token".to_string()),
            scope: "name email".to_string(),
            id_token: None, // Will be set dynamically with proper JWT
        }
    }

    #[must_use]
    pub fn github() -> Self {
        Self {
            access_token: "gho_mock_github_token".to_string(),
            token_type: "bearer".to_string(),
            expires_in: 0, // GitHub tokens don't expire
            refresh_token: None,
            scope: "user:email,read:user".to_string(),
            id_token: None, // GitHub doesn't use OIDC
        }
    }
}

/// Provider type for test configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Google,
    Microsoft,
    Apple,
    GitHub,
}

/// Provider-specific test configuration
#[derive(Debug, Clone)]
pub struct ProviderTestFixture {
    pub provider_type: ProviderType,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub mock_user: MockUser,
    pub mock_tokens: MockToken,
}

impl ProviderTestFixture {
    #[must_use]
    pub fn google() -> Self {
        Self {
            provider_type: ProviderType::Google,
            client_id: "test-google-client-id.apps.googleusercontent.com".to_string(),
            client_secret: "test-google-client-secret".to_string(),
            redirect_uri: "http://localhost:3000/callback/google".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            mock_user: MockUser::google(),
            mock_tokens: MockToken::google(),
        }
    }

    #[must_use]
    pub fn microsoft() -> Self {
        Self {
            provider_type: ProviderType::Microsoft,
            client_id: "test-microsoft-client-id".to_string(),
            client_secret: "test-microsoft-client-secret".to_string(),
            redirect_uri: "http://localhost:3000/callback/microsoft".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "User.Read".to_string(),
            ],
            mock_user: MockUser::microsoft(),
            mock_tokens: MockToken::microsoft(),
        }
    }

    #[must_use]
    pub fn apple() -> Self {
        Self {
            provider_type: ProviderType::Apple,
            client_id: "com.example.app".to_string(),
            client_secret: "test-apple-client-secret".to_string(),
            redirect_uri: "http://localhost:3000/callback/apple".to_string(),
            scopes: vec!["name".to_string(), "email".to_string()],
            mock_user: MockUser::apple(),
            mock_tokens: MockToken::apple(),
        }
    }

    #[must_use]
    pub fn github() -> Self {
        Self {
            provider_type: ProviderType::GitHub,
            client_id: "test-github-client-id".to_string(),
            client_secret: "test-github-client-secret".to_string(),
            redirect_uri: "http://localhost:3000/callback/github".to_string(),
            scopes: vec!["user:email".to_string(), "read:user".to_string()],
            mock_user: MockUser::github(),
            mock_tokens: MockToken::github(),
        }
    }
}

/// Test constants
pub const TEST_STATE: &str = "test_csrf_state_abc123";
pub const TEST_NONCE: &str = "test_nonce_xyz789";
pub const TEST_CODE_VERIFIER: &str = "test_code_verifier_0123456789abcdefghijklmnop";
pub const TEST_CODE_CHALLENGE: &str = "KVy9qVZBPvZQMdNGhtW4V8FQ8kXe4_YfMIYvwGxl8gE";
pub const TEST_AUTH_CODE: &str = "mock_authorization_code_12345";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_fixture() {
        let fixture = ProviderTestFixture::google();
        assert_eq!(fixture.provider_type, ProviderType::Google);
        assert!(fixture.client_id.contains("googleusercontent.com"));
        assert!(fixture.mock_user.email.contains("gmail.com"));
    }

    #[test]
    fn test_microsoft_fixture() {
        let fixture = ProviderTestFixture::microsoft();
        assert_eq!(fixture.provider_type, ProviderType::Microsoft);
        assert!(fixture.mock_user.email.contains("outlook.com"));
    }

    #[test]
    fn test_apple_fixture() {
        let fixture = ProviderTestFixture::apple();
        assert_eq!(fixture.provider_type, ProviderType::Apple);
        assert!(fixture.mock_user.is_private_email);
        assert!(fixture.mock_user.email.contains("privaterelay.appleid.com"));
    }

    #[test]
    fn test_github_fixture() {
        let fixture = ProviderTestFixture::github();
        assert_eq!(fixture.provider_type, ProviderType::GitHub);
        assert!(fixture.mock_tokens.id_token.is_none()); // GitHub doesn't use OIDC
    }

    #[test]
    fn test_apple_real_email_user() {
        let user = MockUser::apple_real_email();
        assert!(!user.is_private_email);
        assert!(!user.email.contains("privaterelay"));
    }

    #[test]
    fn test_github_private_email_user() {
        let user = MockUser::github_private_email();
        assert!(user.is_private_email);
        assert!(user.email.contains("noreply.github.com"));
    }
}
