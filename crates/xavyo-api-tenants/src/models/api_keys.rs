//! DTOs for API key management operations.
//!
//! F-KEY-ROTATE: Request and response types for API key rotation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Request to rotate an API key.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RotateApiKeyRequest {
    /// If true, the old key is immediately deactivated.
    /// If false (default), the old key remains active for a grace period.
    #[serde(default)]
    #[schema(example = false)]
    pub deactivate_old_immediately: Option<bool>,

    /// Grace period in hours before the old key is deactivated.
    /// Default: 24 hours. Only applies if deactivate_old_immediately is false.
    #[serde(default)]
    #[schema(example = 24)]
    pub grace_period_hours: Option<u32>,

    /// Optional expiration date for the new key.
    /// If not specified, inherits from the old key.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl RotateApiKeyRequest {
    /// Validate the request.
    pub fn validate(&self) -> Option<String> {
        if let Some(hours) = self.grace_period_hours {
            if hours == 0 {
                return Some("grace_period_hours must be at least 1 if specified".to_string());
            }
            if hours > 720 {
                // Max 30 days
                return Some("grace_period_hours cannot exceed 720 (30 days)".to_string());
            }
        }
        None
    }
}

/// Response after rotating an API key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RotateApiKeyResponse {
    /// ID of the newly created API key.
    pub new_key_id: Uuid,

    /// Prefix of the new key for identification.
    pub new_key_prefix: String,

    /// The new API key in plaintext.
    /// SECURITY: This is shown only once and cannot be retrieved later.
    #[schema(example = "xavyo_sk_live_a1b2c3d4e5f6789012345678")]
    pub new_api_key: String,

    /// ID of the old (rotated) key.
    pub old_key_id: Uuid,

    /// Status of the old key after rotation.
    #[schema(example = "active until 2024-01-02T12:00:00Z (grace period: 24 hours)")]
    pub old_key_status: String,

    /// Timestamp when the rotation occurred.
    pub rotated_at: DateTime<Utc>,
}

/// Information about an API key (without the key itself).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyInfo {
    /// Unique identifier for the API key.
    pub id: Uuid,

    /// Human-readable name for the API key.
    pub name: String,

    /// Prefix of the key for identification.
    pub key_prefix: String,

    /// Allowed API scopes.
    pub scopes: Vec<String>,

    /// Whether the API key is active.
    pub is_active: bool,

    /// When the API key was last used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// When the API key expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// When the API key was created.
    pub created_at: DateTime<Utc>,
}

/// Response containing a list of API keys.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyListResponse {
    /// List of API keys.
    pub api_keys: Vec<ApiKeyInfo>,

    /// Total number of API keys.
    pub total: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotate_request_valid_defaults() {
        let request = RotateApiKeyRequest {
            deactivate_old_immediately: None,
            grace_period_hours: None,
            expires_at: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_rotate_request_valid_with_grace_period() {
        let request = RotateApiKeyRequest {
            deactivate_old_immediately: Some(false),
            grace_period_hours: Some(48),
            expires_at: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_rotate_request_invalid_zero_grace_period() {
        let request = RotateApiKeyRequest {
            deactivate_old_immediately: Some(false),
            grace_period_hours: Some(0),
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("at least 1"));
    }

    #[test]
    fn test_rotate_request_invalid_too_long_grace_period() {
        let request = RotateApiKeyRequest {
            deactivate_old_immediately: Some(false),
            grace_period_hours: Some(1000), // More than 30 days
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("720"));
    }
}
