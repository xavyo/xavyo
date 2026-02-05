//! Sensitive data redaction for CLI verbose/debug output
//!
//! This module provides pattern-based redaction of sensitive information
//! such as tokens, passwords, and API keys.

use regex::Regex;
use std::borrow::Cow;
use std::sync::LazyLock;

/// The replacement string used for redacted values
#[allow(dead_code)]
pub const REDACTED: &str = "[REDACTED]";

/// Built-in redaction patterns for sensitive data
static REDACTION_PATTERNS: LazyLock<Vec<RedactionPattern>> = LazyLock::new(|| {
    vec![
        // Authorization header with Bearer token
        RedactionPattern::new(r"(Authorization:\s*Bearer\s+)\S+", |caps| {
            format!("{}[REDACTED]", &caps[1])
        }),
        // Password fields in JSON
        RedactionPattern::new(r#"("password"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Access token in JSON
        RedactionPattern::new(r#"("access_token"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Refresh token in JSON
        RedactionPattern::new(r#"("refresh_token"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // API key in JSON
        RedactionPattern::new(r#"("api_key"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Client secret in JSON
        RedactionPattern::new(r#"("client_secret"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Device code in JSON
        RedactionPattern::new(r#"("device_code"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Credentials in URLs (user:password@host)
        RedactionPattern::new(r"(://[^:]+:)[^@]+(@)", |caps| {
            format!("{}[REDACTED]{}", &caps[1], &caps[2])
        }),
        // Bearer token in form data
        RedactionPattern::new(r"(device_code=)[^&\s]+", |caps| {
            format!("{}[REDACTED]", &caps[1])
        }),
        // Secret key pattern (common naming)
        RedactionPattern::new(r#"("secret_key"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // SSO session ID in JSON (contains sensitive CSRF state)
        RedactionPattern::new(r#"("session_id"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // Device trust token in JSON
        RedactionPattern::new(r#"("device_token"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // SAML assertion (base64 encoded XML)
        RedactionPattern::new(r#"("saml_assertion"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
        // SSO state/CSRF token in JSON
        RedactionPattern::new(r#"("state"\s*:\s*")[^"]*""#, |caps| {
            format!("{}[REDACTED]\"", &caps[1])
        }),
    ]
});

/// A pattern for detecting and redacting sensitive data
pub struct RedactionPattern {
    regex: Regex,
    replacer: Box<dyn Fn(&regex::Captures) -> String + Send + Sync>,
}

impl RedactionPattern {
    /// Create a new redaction pattern
    fn new<F>(pattern: &str, replacer: F) -> Self
    where
        F: Fn(&regex::Captures) -> String + Send + Sync + 'static,
    {
        Self {
            regex: Regex::new(pattern).expect("Invalid redaction pattern"),
            replacer: Box::new(replacer),
        }
    }

    /// Apply this pattern to the input string
    fn apply<'a>(&self, input: &'a str) -> Cow<'a, str> {
        self.regex
            .replace_all(input, |caps: &regex::Captures| (self.replacer)(caps))
    }
}

impl std::fmt::Debug for RedactionPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedactionPattern")
            .field("regex", &self.regex.as_str())
            .finish()
    }
}

/// Redactor for sensitive data in strings
#[derive(Debug, Default)]
pub struct Redactor;

#[allow(dead_code)]
impl Redactor {
    /// Create a new Redactor
    pub fn new() -> Self {
        Self
    }

    /// Redact sensitive data from the input string
    ///
    /// Applies all built-in redaction patterns to find and mask
    /// sensitive information such as:
    /// - Authorization headers
    /// - Tokens (access, refresh, device)
    /// - Passwords
    /// - API keys
    /// - Client secrets
    /// - URL credentials
    pub fn redact<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result: Cow<str> = Cow::Borrowed(input);

        for pattern in REDACTION_PATTERNS.iter() {
            match &result {
                Cow::Borrowed(s) => {
                    let redacted = pattern.apply(s);
                    if let Cow::Owned(owned) = redacted {
                        result = Cow::Owned(owned);
                    }
                }
                Cow::Owned(s) => {
                    let redacted = pattern.apply(s);
                    if let Cow::Owned(owned) = redacted {
                        result = Cow::Owned(owned);
                    }
                }
            }
        }

        result
    }

    /// Redact and return an owned String
    pub fn redact_string(&self, input: &str) -> String {
        self.redact(input).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_bearer_token() {
        let redactor = Redactor::new();
        let input = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";
        let result = redactor.redact(input);
        assert_eq!(result, "Authorization: Bearer [REDACTED]");
    }

    #[test]
    fn test_redact_password_json() {
        let redactor = Redactor::new();
        let input = r#"{"username": "user", "password": "secret123"}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"username": "user", "password": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_access_token_json() {
        let redactor = Redactor::new();
        let input = r#"{"access_token": "abc123xyz", "token_type": "Bearer"}"#;
        let result = redactor.redact(input);
        assert_eq!(
            result,
            r#"{"access_token": "[REDACTED]", "token_type": "Bearer"}"#
        );
    }

    #[test]
    fn test_redact_refresh_token_json() {
        let redactor = Redactor::new();
        let input = r#"{"refresh_token": "refresh_abc123"}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"refresh_token": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_api_key_json() {
        let redactor = Redactor::new();
        let input = r#"{"api_key": "sk-1234567890abcdef"}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"api_key": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_client_secret_json() {
        let redactor = Redactor::new();
        let input = r#"{"client_id": "app", "client_secret": "very-secret"}"#;
        let result = redactor.redact(input);
        assert_eq!(
            result,
            r#"{"client_id": "app", "client_secret": "[REDACTED]"}"#
        );
    }

    #[test]
    fn test_redact_url_credentials() {
        let redactor = Redactor::new();
        let input = "https://user:password123@api.example.com/v1";
        let result = redactor.redact(input);
        assert_eq!(result, "https://user:[REDACTED]@api.example.com/v1");
    }

    #[test]
    fn test_redact_device_code_form() {
        let redactor = Redactor::new();
        let input = "grant_type=device_code&device_code=abc123&client_id=cli";
        let result = redactor.redact(input);
        assert_eq!(
            result,
            "grant_type=device_code&device_code=[REDACTED]&client_id=cli"
        );
    }

    #[test]
    fn test_redact_multiple_patterns() {
        let redactor = Redactor::new();
        let input =
            r#"{"access_token": "token1", "refresh_token": "token2", "password": "secret"}"#;
        let result = redactor.redact(input);
        assert_eq!(
            result,
            r#"{"access_token": "[REDACTED]", "refresh_token": "[REDACTED]", "password": "[REDACTED]"}"#
        );
    }

    #[test]
    fn test_redact_no_sensitive_data() {
        let redactor = Redactor::new();
        let input = r#"{"name": "test", "count": 42}"#;
        let result = redactor.redact(input);
        // Should return borrowed Cow (unchanged)
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, input);
    }

    #[test]
    fn test_redact_string_method() {
        let redactor = Redactor::new();
        let input = r#"{"password": "secret"}"#;
        let result = redactor.redact_string(input);
        assert_eq!(result, r#"{"password": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_empty_input() {
        let redactor = Redactor::new();
        let result = redactor.redact("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_redact_secret_key() {
        let redactor = Redactor::new();
        let input = r#"{"secret_key": "sk_live_12345"}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"secret_key": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_sso_session_id() {
        let redactor = Redactor::new();
        let input = r#"{"session_id": "sso-session-abc123", "expires_in": 300}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"session_id": "[REDACTED]", "expires_in": 300}"#);
    }

    #[test]
    fn test_redact_device_token() {
        let redactor = Redactor::new();
        let input = r#"{"device_token": "trust-token-xyz789"}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"device_token": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_saml_assertion() {
        let redactor = Redactor::new();
        let input = r#"{"saml_assertion": "PHNhbWxwOkF1dGhu...base64..."}"#;
        let result = redactor.redact(input);
        assert_eq!(result, r#"{"saml_assertion": "[REDACTED]"}"#);
    }

    #[test]
    fn test_redact_sso_state() {
        let redactor = Redactor::new();
        let input =
            r#"{"state": "csrf-token-abc123", "verification_url": "https://auth.example.com"}"#;
        let result = redactor.redact(input);
        assert_eq!(
            result,
            r#"{"state": "[REDACTED]", "verification_url": "https://auth.example.com"}"#
        );
    }
}
