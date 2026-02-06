//! SSO Configuration types
//!
//! Configuration for initiating SSO authentication flows.

use serde::{Deserialize, Serialize};

/// Default SSO timeout in seconds (5 minutes)
pub const DEFAULT_SSO_TIMEOUT_SECS: u64 = 300;

/// Minimum SSO timeout in seconds
pub const MIN_SSO_TIMEOUT_SECS: u64 = 30;

/// Maximum SSO timeout in seconds
pub const MAX_SSO_TIMEOUT_SECS: u64 = 600;

/// SSO configuration for initiating authentication
///
/// At least one of `idp_url`, `idp_entity_id`, or `email` must be provided.
/// `idp_url` and `idp_entity_id` are mutually exclusive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOConfig {
    /// Explicit IdP URL (bypasses discovery)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_url: Option<String>,

    /// IdP entity identifier for resolution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_entity_id: Option<String>,

    /// Email for IdP discovery (extracts domain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// SSO timeout in seconds (30-600, default 300)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Skip automatic browser opening
    #[serde(default)]
    pub no_browser: bool,
}

fn default_timeout() -> u64 {
    DEFAULT_SSO_TIMEOUT_SECS
}

impl Default for SSOConfig {
    fn default() -> Self {
        Self {
            idp_url: None,
            idp_entity_id: None,
            email: None,
            timeout_secs: DEFAULT_SSO_TIMEOUT_SECS,
            no_browser: false,
        }
    }
}

impl SSOConfig {
    /// Create a new SSO config with email for IdP discovery
    pub fn with_email(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
            ..Default::default()
        }
    }

    /// Create a new SSO config with explicit IdP URL
    pub fn with_idp_url(url: impl Into<String>) -> Self {
        Self {
            idp_url: Some(url.into()),
            ..Default::default()
        }
    }

    /// Create a new SSO config with IdP entity ID
    pub fn with_entity_id(entity_id: impl Into<String>) -> Self {
        Self {
            idp_entity_id: Some(entity_id.into()),
            ..Default::default()
        }
    }

    /// Set the timeout
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs.clamp(MIN_SSO_TIMEOUT_SECS, MAX_SSO_TIMEOUT_SECS);
        self
    }

    /// Set no-browser mode
    pub fn no_browser(mut self, value: bool) -> Self {
        self.no_browser = value;
        self
    }

    /// Validate the configuration
    ///
    /// Returns an error if:
    /// - No identification method is provided
    /// - Both idp_url and idp_entity_id are provided
    /// - idp_url is invalid
    pub fn validate(&self) -> Result<(), SSOConfigError> {
        // At least one identification method required
        if self.idp_url.is_none() && self.idp_entity_id.is_none() && self.email.is_none() {
            return Err(SSOConfigError::NoIdentification);
        }

        // idp_url and idp_entity_id are mutually exclusive
        if self.idp_url.is_some() && self.idp_entity_id.is_some() {
            return Err(SSOConfigError::ConflictingFlags);
        }

        // Validate idp_url if provided
        if let Some(ref url) = self.idp_url {
            validate_idp_url(url)?;
        }

        // Validate email format if provided
        if let Some(ref email) = self.email {
            if !email.contains('@') {
                return Err(SSOConfigError::InvalidEmail(email.clone()));
            }
        }

        Ok(())
    }

    /// Extract the domain from the email address
    pub fn email_domain(&self) -> Option<&str> {
        self.email.as_ref().and_then(|email| {
            let parts: Vec<&str> = email.split('@').collect();
            if parts.len() == 2 {
                Some(parts[1])
            } else {
                None
            }
        })
    }

    /// Check if IdP discovery is needed
    pub fn needs_discovery(&self) -> bool {
        self.idp_url.is_none() && self.idp_entity_id.is_none()
    }
}

/// Validate IdP URL format
pub fn validate_idp_url(url: &str) -> Result<(), SSOConfigError> {
    // Must be a valid URL
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(SSOConfigError::InvalidIdpUrl(
            url.to_string(),
            "URL must start with http:// or https://".to_string(),
        ));
    }

    // Parse URL to validate format using reqwest::Url
    match reqwest::Url::parse(url) {
        Ok(parsed) => {
            // Must have a host
            if parsed.host_str().is_none() {
                return Err(SSOConfigError::InvalidIdpUrl(
                    url.to_string(),
                    "URL must have a valid host".to_string(),
                ));
            }
            Ok(())
        }
        Err(e) => Err(SSOConfigError::InvalidIdpUrl(
            url.to_string(),
            e.to_string(),
        )),
    }
}

/// SSO configuration errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SSOConfigError {
    /// No identification method provided
    NoIdentification,
    /// Both --idp-url and --idp-entity-id provided
    ConflictingFlags,
    /// Invalid IdP URL
    InvalidIdpUrl(String, String),
    /// Invalid email format
    InvalidEmail(String),
}

impl std::fmt::Display for SSOConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSOConfigError::NoIdentification => {
                write!(
                    f,
                    "At least one of --email, --idp-url, or --idp-entity-id must be provided"
                )
            }
            SSOConfigError::ConflictingFlags => {
                write!(f, "--idp-url and --idp-entity-id are mutually exclusive")
            }
            SSOConfigError::InvalidIdpUrl(url, reason) => {
                write!(f, "Invalid IdP URL '{}': {}", url, reason)
            }
            SSOConfigError::InvalidEmail(email) => {
                write!(f, "Invalid email format: '{}'", email)
            }
        }
    }
}

impl std::error::Error for SSOConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sso_config_default() {
        let config = SSOConfig::default();
        assert!(config.idp_url.is_none());
        assert!(config.idp_entity_id.is_none());
        assert!(config.email.is_none());
        assert_eq!(config.timeout_secs, DEFAULT_SSO_TIMEOUT_SECS);
        assert!(!config.no_browser);
    }

    #[test]
    fn test_sso_config_with_email() {
        let config = SSOConfig::with_email("user@acme.corp");
        assert_eq!(config.email, Some("user@acme.corp".to_string()));
        assert!(config.idp_url.is_none());
    }

    #[test]
    fn test_sso_config_with_idp_url() {
        let config = SSOConfig::with_idp_url("https://idp.acme.corp/sso");
        assert_eq!(
            config.idp_url,
            Some("https://idp.acme.corp/sso".to_string())
        );
        assert!(config.email.is_none());
    }

    #[test]
    fn test_sso_config_with_entity_id() {
        let config = SSOConfig::with_entity_id("urn:okta:acme");
        assert_eq!(config.idp_entity_id, Some("urn:okta:acme".to_string()));
    }

    #[test]
    fn test_sso_config_timeout_clamping() {
        let config = SSOConfig::default().timeout(10); // Below min
        assert_eq!(config.timeout_secs, MIN_SSO_TIMEOUT_SECS);

        let config = SSOConfig::default().timeout(1000); // Above max
        assert_eq!(config.timeout_secs, MAX_SSO_TIMEOUT_SECS);

        let config = SSOConfig::default().timeout(120);
        assert_eq!(config.timeout_secs, 120);
    }

    #[test]
    fn test_sso_config_validate_no_identification() {
        let config = SSOConfig::default();
        assert_eq!(config.validate(), Err(SSOConfigError::NoIdentification));
    }

    #[test]
    fn test_sso_config_validate_conflicting_flags() {
        let config = SSOConfig {
            idp_url: Some("https://idp.example.com".to_string()),
            idp_entity_id: Some("urn:example".to_string()),
            ..Default::default()
        };
        assert_eq!(config.validate(), Err(SSOConfigError::ConflictingFlags));
    }

    #[test]
    fn test_sso_config_validate_valid_email() {
        let config = SSOConfig::with_email("user@example.com");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sso_config_validate_valid_idp_url() {
        let config = SSOConfig::with_idp_url("https://idp.example.com/sso/saml");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sso_config_validate_invalid_idp_url() {
        let config = SSOConfig::with_idp_url("not-a-url");
        let result = config.validate();
        assert!(matches!(result, Err(SSOConfigError::InvalidIdpUrl(_, _))));
    }

    #[test]
    fn test_sso_config_validate_invalid_email() {
        let config = SSOConfig::with_email("invalid-email");
        let result = config.validate();
        assert!(matches!(result, Err(SSOConfigError::InvalidEmail(_))));
    }

    #[test]
    fn test_email_domain_extraction() {
        let config = SSOConfig::with_email("user@acme.corp");
        assert_eq!(config.email_domain(), Some("acme.corp"));

        let config = SSOConfig::with_email("invalid");
        assert!(config.email_domain().is_none());

        let config = SSOConfig::default();
        assert!(config.email_domain().is_none());
    }

    #[test]
    fn test_needs_discovery() {
        let config = SSOConfig::with_email("user@example.com");
        assert!(config.needs_discovery());

        let config = SSOConfig::with_idp_url("https://idp.example.com");
        assert!(!config.needs_discovery());

        let config = SSOConfig::with_entity_id("urn:example");
        assert!(!config.needs_discovery());
    }

    #[test]
    fn test_validate_idp_url_valid() {
        assert!(validate_idp_url("https://idp.example.com").is_ok());
        assert!(validate_idp_url("https://idp.example.com/sso/saml").is_ok());
        assert!(validate_idp_url("http://localhost:8080/sso").is_ok());
    }

    #[test]
    fn test_validate_idp_url_invalid() {
        assert!(validate_idp_url("ftp://example.com").is_err());
        assert!(validate_idp_url("not-a-url").is_err());
        assert!(validate_idp_url("").is_err());
    }

    #[test]
    fn test_sso_config_error_display() {
        assert!(SSOConfigError::NoIdentification
            .to_string()
            .contains("--email"));
        assert!(SSOConfigError::ConflictingFlags
            .to_string()
            .contains("mutually exclusive"));
        assert!(
            SSOConfigError::InvalidIdpUrl("url".to_string(), "reason".to_string())
                .to_string()
                .contains("url")
        );
    }
}
