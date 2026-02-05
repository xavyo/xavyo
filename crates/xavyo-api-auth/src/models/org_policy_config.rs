//! Organization security policy configuration types (F-066).
//!
//! Type-safe configuration structures for each policy type.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Password policy configuration for an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordPolicyConfig {
    /// Minimum password length (8-128).
    #[serde(default = "default_min_length")]
    pub min_length: i32,

    /// Maximum password length (8-128).
    #[serde(default = "default_max_length")]
    pub max_length: i32,

    /// Require at least one uppercase letter.
    #[serde(default)]
    pub require_uppercase: bool,

    /// Require at least one lowercase letter.
    #[serde(default)]
    pub require_lowercase: bool,

    /// Require at least one digit.
    #[serde(default)]
    pub require_digit: bool,

    /// Require at least one special character.
    #[serde(default)]
    pub require_special: bool,

    /// Days until password expires (0 = never).
    #[serde(default)]
    pub expiration_days: i32,

    /// Number of previous passwords to remember (0-24).
    #[serde(default)]
    pub history_count: i32,

    /// Minimum hours before password can be changed again.
    #[serde(default)]
    pub min_age_hours: i32,
}

fn default_min_length() -> i32 {
    8
}

fn default_max_length() -> i32 {
    128
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_special: false,
            expiration_days: 0,
            history_count: 0,
            min_age_hours: 0,
        }
    }
}

impl PasswordPolicyConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.min_length < 8 || self.min_length > 128 {
            errors.push("min_length must be between 8 and 128".to_string());
        }
        if self.max_length < self.min_length || self.max_length > 128 {
            errors.push("max_length must be >= min_length and <= 128".to_string());
        }
        if self.expiration_days < 0 {
            errors.push("expiration_days must be >= 0".to_string());
        }
        if self.history_count < 0 || self.history_count > 24 {
            errors.push("history_count must be between 0 and 24".to_string());
        }
        if self.min_age_hours < 0 {
            errors.push("min_age_hours must be >= 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Compare restrictiveness: returns true if self is more restrictive than other.
    #[must_use]
    pub fn is_more_restrictive_than(&self, other: &Self) -> bool {
        self.min_length > other.min_length
            || self.require_uppercase && !other.require_uppercase
            || self.require_lowercase && !other.require_lowercase
            || self.require_digit && !other.require_digit
            || self.require_special && !other.require_special
            || (self.expiration_days > 0
                && (other.expiration_days == 0 || self.expiration_days < other.expiration_days))
            || self.history_count > other.history_count
    }

    /// Get the most restrictive combination of two policies.
    #[must_use]
    pub fn most_restrictive(&self, other: &Self) -> Self {
        Self {
            min_length: self.min_length.max(other.min_length),
            max_length: self.max_length.min(other.max_length),
            require_uppercase: self.require_uppercase || other.require_uppercase,
            require_lowercase: self.require_lowercase || other.require_lowercase,
            require_digit: self.require_digit || other.require_digit,
            require_special: self.require_special || other.require_special,
            expiration_days: match (self.expiration_days, other.expiration_days) {
                (0, 0) => 0,
                (0, d) | (d, 0) => d,
                (a, b) => a.min(b),
            },
            history_count: self.history_count.max(other.history_count),
            min_age_hours: self.min_age_hours.max(other.min_age_hours),
        }
    }
}

/// MFA policy configuration for an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MfaPolicyConfig {
    /// Whether MFA is required for all users in this organization.
    #[serde(default)]
    pub required: bool,

    /// Allowed MFA methods (totp, webauthn, email, sms).
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    /// Grace period in hours for new users to set up MFA.
    #[serde(default)]
    pub grace_period_hours: i32,

    /// Days to remember device before requiring MFA again.
    #[serde(default)]
    pub remember_device_days: i32,
}

fn default_allowed_methods() -> Vec<String> {
    vec!["totp".to_string(), "webauthn".to_string()]
}

impl Default for MfaPolicyConfig {
    fn default() -> Self {
        Self {
            required: false,
            allowed_methods: vec!["totp".to_string(), "webauthn".to_string()],
            grace_period_hours: 0,
            remember_device_days: 0,
        }
    }
}

impl MfaPolicyConfig {
    /// Valid MFA methods.
    pub const VALID_METHODS: &'static [&'static str] = &["totp", "webauthn", "email", "sms"];

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for method in &self.allowed_methods {
            if !Self::VALID_METHODS.contains(&method.as_str()) {
                errors.push(format!("Invalid MFA method: {method}"));
            }
        }

        if self.grace_period_hours < 0 {
            errors.push("grace_period_hours must be >= 0".to_string());
        }
        if self.remember_device_days < 0 {
            errors.push("remember_device_days must be >= 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Compare restrictiveness: returns true if self is more restrictive.
    #[must_use]
    pub fn is_more_restrictive_than(&self, other: &Self) -> bool {
        (self.required && !other.required)
            || (self.allowed_methods.len() < other.allowed_methods.len())
            || (self.grace_period_hours < other.grace_period_hours && other.grace_period_hours > 0)
            || (self.remember_device_days < other.remember_device_days
                && other.remember_device_days > 0)
    }

    /// Get the most restrictive combination of two policies.
    #[must_use]
    pub fn most_restrictive(&self, other: &Self) -> Self {
        // Intersection of allowed methods
        let methods: Vec<String> = self
            .allowed_methods
            .iter()
            .filter(|m| other.allowed_methods.contains(m))
            .cloned()
            .collect();

        Self {
            required: self.required || other.required,
            allowed_methods: if methods.is_empty() {
                self.allowed_methods.clone()
            } else {
                methods
            },
            grace_period_hours: match (self.grace_period_hours, other.grace_period_hours) {
                (0, 0) => 0,
                (0, h) | (h, 0) => h,
                (a, b) => a.min(b),
            },
            remember_device_days: match (self.remember_device_days, other.remember_device_days) {
                (0, 0) => 0,
                (0, d) | (d, 0) => d,
                (a, b) => a.min(b),
            },
        }
    }
}

/// Session policy configuration for an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionPolicyConfig {
    /// Maximum session duration in hours.
    #[serde(default = "default_max_duration_hours")]
    pub max_duration_hours: i32,

    /// Idle timeout in minutes (0 = no timeout).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_minutes: i32,

    /// Maximum concurrent sessions (0 = unlimited).
    #[serde(default)]
    pub concurrent_session_limit: i32,

    /// Require re-authentication for sensitive operations.
    #[serde(default)]
    pub require_reauth_sensitive: bool,
}

fn default_max_duration_hours() -> i32 {
    24
}

fn default_idle_timeout() -> i32 {
    30
}

impl Default for SessionPolicyConfig {
    fn default() -> Self {
        Self {
            max_duration_hours: 24,
            idle_timeout_minutes: 30,
            concurrent_session_limit: 0,
            require_reauth_sensitive: false,
        }
    }
}

impl SessionPolicyConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.max_duration_hours < 1 {
            errors.push("max_duration_hours must be >= 1".to_string());
        }
        if self.idle_timeout_minutes < 0 {
            errors.push("idle_timeout_minutes must be >= 0".to_string());
        }
        if self.concurrent_session_limit < 0 {
            errors.push("concurrent_session_limit must be >= 0".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Compare restrictiveness: returns true if self is more restrictive.
    #[must_use]
    pub fn is_more_restrictive_than(&self, other: &Self) -> bool {
        self.max_duration_hours < other.max_duration_hours
            || (self.idle_timeout_minutes > 0
                && (other.idle_timeout_minutes == 0
                    || self.idle_timeout_minutes < other.idle_timeout_minutes))
            || (self.concurrent_session_limit > 0
                && (other.concurrent_session_limit == 0
                    || self.concurrent_session_limit < other.concurrent_session_limit))
            || (self.require_reauth_sensitive && !other.require_reauth_sensitive)
    }

    /// Get the most restrictive combination of two policies.
    #[must_use]
    pub fn most_restrictive(&self, other: &Self) -> Self {
        Self {
            max_duration_hours: self.max_duration_hours.min(other.max_duration_hours),
            idle_timeout_minutes: match (self.idle_timeout_minutes, other.idle_timeout_minutes) {
                (0, 0) => 0,
                (0, m) | (m, 0) => m,
                (a, b) => a.min(b),
            },
            concurrent_session_limit: match (
                self.concurrent_session_limit,
                other.concurrent_session_limit,
            ) {
                (0, 0) => 0,
                (0, l) | (l, 0) => l,
                (a, b) => a.min(b),
            },
            require_reauth_sensitive: self.require_reauth_sensitive
                || other.require_reauth_sensitive,
        }
    }
}

/// IP restriction policy configuration for an organization.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IpRestrictionPolicyConfig {
    /// Allowed IP/CIDR ranges.
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,

    /// Denied IP/CIDR ranges (blacklist).
    #[serde(default)]
    pub denied_cidrs: Vec<String>,

    /// Action on violation: deny, warn, log.
    #[serde(default = "default_action")]
    pub action_on_violation: String,
}

fn default_action() -> String {
    "deny".to_string()
}

impl Default for IpRestrictionPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            denied_cidrs: Vec::new(),
            action_on_violation: "deny".to_string(),
        }
    }
}

impl IpRestrictionPolicyConfig {
    /// Valid violation actions.
    pub const VALID_ACTIONS: &'static [&'static str] = &["deny", "warn", "log"];

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate action
        if !Self::VALID_ACTIONS.contains(&self.action_on_violation.as_str()) {
            errors.push(format!(
                "Invalid action_on_violation: {}. Must be one of: deny, warn, log",
                self.action_on_violation
            ));
        }

        // Validate CIDR formats
        for cidr in &self.allowed_cidrs {
            if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
                errors.push(format!("Invalid CIDR in allowed_cidrs: {cidr}"));
            }
        }

        for cidr in &self.denied_cidrs {
            if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
                errors.push(format!("Invalid CIDR in denied_cidrs: {cidr}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if an IP address is allowed by this policy.
    /// Returns true if allowed, false if denied.
    pub fn is_ip_allowed(&self, ip: std::net::IpAddr) -> bool {
        // First check denied list
        for cidr in &self.denied_cidrs {
            if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
                if network.contains(ip) {
                    return false;
                }
            }
        }

        // If allowed list is empty, allow all
        if self.allowed_cidrs.is_empty() {
            return true;
        }

        // Check allowed list
        for cidr in &self.allowed_cidrs {
            if let Ok(network) = cidr.parse::<ipnetwork::IpNetwork>() {
                if network.contains(ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Returns true if this policy has any restrictions.
    #[must_use]
    pub fn has_restrictions(&self) -> bool {
        !self.allowed_cidrs.is_empty() || !self.denied_cidrs.is_empty()
    }

    /// Get the most restrictive combination (union of denied, intersection of allowed).
    #[must_use]
    pub fn most_restrictive(&self, other: &Self) -> Self {
        // Union of denied CIDRs
        let mut denied: Vec<String> = self.denied_cidrs.clone();
        for cidr in &other.denied_cidrs {
            if !denied.contains(cidr) {
                denied.push(cidr.clone());
            }
        }

        // Intersection of allowed CIDRs (if both have restrictions)
        let allowed = if self.allowed_cidrs.is_empty() {
            other.allowed_cidrs.clone()
        } else if other.allowed_cidrs.is_empty() {
            self.allowed_cidrs.clone()
        } else {
            self.allowed_cidrs
                .iter()
                .filter(|c| other.allowed_cidrs.contains(c))
                .cloned()
                .collect()
        };

        // Use more restrictive action
        let action = if self.action_on_violation == "deny" || other.action_on_violation == "deny" {
            "deny".to_string()
        } else if self.action_on_violation == "warn" || other.action_on_violation == "warn" {
            "warn".to_string()
        } else {
            "log".to_string()
        };

        Self {
            allowed_cidrs: allowed,
            denied_cidrs: denied,
            action_on_violation: action,
        }
    }
}

/// Policy conflict warning for validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyConflictWarning {
    /// Warning severity: warning or error.
    pub severity: String,
    /// Description of the conflict.
    pub message: String,
    /// ID of the related organization.
    pub related_org_id: uuid::Uuid,
    /// Name of the related organization.
    pub related_org_name: String,
    /// Specific field causing the conflict (optional).
    pub field: Option<String>,
}

/// Result of policy validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyValidationResult {
    /// Whether the policy is valid.
    pub valid: bool,
    /// List of conflict warnings.
    pub warnings: Vec<PolicyConflictWarning>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_policy_validation() {
        let valid = PasswordPolicyConfig {
            min_length: 12,
            max_length: 128,
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid = PasswordPolicyConfig {
            min_length: 5, // Too short
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_password_policy_most_restrictive() {
        let p1 = PasswordPolicyConfig {
            min_length: 8,
            require_uppercase: true,
            expiration_days: 90,
            ..Default::default()
        };
        let p2 = PasswordPolicyConfig {
            min_length: 12,
            require_digit: true,
            expiration_days: 60,
            ..Default::default()
        };

        let combined = p1.most_restrictive(&p2);
        assert_eq!(combined.min_length, 12);
        assert!(combined.require_uppercase);
        assert!(combined.require_digit);
        assert_eq!(combined.expiration_days, 60);
    }

    #[test]
    fn test_mfa_policy_validation() {
        let valid = MfaPolicyConfig::default();
        assert!(valid.validate().is_ok());

        let invalid = MfaPolicyConfig {
            allowed_methods: vec!["invalid".to_string()],
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_session_policy_validation() {
        let valid = SessionPolicyConfig::default();
        assert!(valid.validate().is_ok());

        let invalid = SessionPolicyConfig {
            max_duration_hours: 0,
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_ip_policy_validation() {
        let valid = IpRestrictionPolicyConfig {
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            ..Default::default()
        };
        assert!(valid.validate().is_ok());

        let invalid = IpRestrictionPolicyConfig {
            allowed_cidrs: vec!["not-a-cidr".to_string()],
            ..Default::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_ip_allowed_check() {
        let policy = IpRestrictionPolicyConfig {
            allowed_cidrs: vec!["10.0.0.0/8".to_string()],
            denied_cidrs: vec!["10.1.0.0/16".to_string()],
            ..Default::default()
        };

        // 10.0.0.1 should be allowed
        assert!(policy.is_ip_allowed("10.0.0.1".parse().unwrap()));

        // 10.1.0.1 should be denied (in denied list)
        assert!(!policy.is_ip_allowed("10.1.0.1".parse().unwrap()));

        // 192.168.0.1 should be denied (not in allowed list)
        assert!(!policy.is_ip_allowed("192.168.0.1".parse().unwrap()));
    }
}
