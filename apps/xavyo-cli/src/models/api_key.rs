//! API key data transfer objects for CLI
//!
//! These DTOs mirror the F-049 API request/response types for API key management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// Request DTOs
// =============================================================================

/// Request to create a new API key.
/// Sent to POST `/tenants/{tenant_id}/api-keys`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateApiKeyRequest {
    /// Human-readable name (1-100 chars)
    pub name: String,
    /// Permission scopes (empty = full access)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// Optional expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl CreateApiKeyRequest {
    /// Create a new API key request with just a name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scopes: Vec::new(),
            expires_at: None,
        }
    }

    /// Add scopes to the request
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Set expiration timestamp
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// Request to rotate an API key.
/// Sent to POST `/tenants/{tenant_id}/api-keys/{key_id}/rotate`.
#[derive(Debug, Clone, Serialize)]
pub struct RotateApiKeyRequest {
    /// Immediately revoke old key (default: false, uses grace period)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivate_old_immediately: Option<bool>,
    /// Hours before old key expires (default: 24)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_hours: Option<u32>,
}

impl Default for RotateApiKeyRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl RotateApiKeyRequest {
    /// Create a new rotate request with defaults
    pub fn new() -> Self {
        Self {
            deactivate_old_immediately: None,
            grace_period_hours: None,
        }
    }

    /// Set immediate deactivation of old key
    pub fn with_deactivate_old(mut self, deactivate: bool) -> Self {
        self.deactivate_old_immediately = Some(deactivate);
        self
    }

    /// Set custom grace period in hours
    pub fn with_grace_period(mut self, hours: u32) -> Self {
        self.grace_period_hours = Some(hours);
        self
    }
}

// =============================================================================
// Response DTOs
// =============================================================================

/// Response after creating an API key.
/// Received from POST `/tenants/{tenant_id}/api-keys`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CreateApiKeyResponse {
    /// Key identifier
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// Prefix for identification (e.g., "xavyo_sk_live_abc")
    pub key_prefix: String,
    /// **SECURITY: Plaintext key shown only once!**
    pub api_key: String,
    /// Granted permission scopes
    pub scopes: Vec<String>,
    /// When key expires (None = never)
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Information about an existing API key (without plaintext secret).
/// Received from GET `/tenants/{tenant_id}/api-keys` (in list response).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeyInfo {
    /// Key identifier
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// Prefix for identification
    pub key_prefix: String,
    /// Granted permission scopes
    pub scopes: Vec<String>,
    /// Whether key is active
    pub is_active: bool,
    /// Last usage timestamp
    pub last_used_at: Option<DateTime<Utc>>,
    /// When key expires (None = never)
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Response from listing API keys.
/// Received from GET `/tenants/{tenant_id}/api-keys`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeyListResponse {
    /// List of API keys
    pub api_keys: Vec<ApiKeyInfo>,
    /// Total count
    pub total: usize,
}

/// Response after rotating an API key.
/// Received from POST `/tenants/{tenant_id}/api-keys/{key_id}/rotate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RotateApiKeyResponse {
    /// New key identifier
    pub new_key_id: Uuid,
    /// New key prefix
    pub new_key_prefix: String,
    /// **SECURITY: New plaintext key shown only once!**
    pub new_api_key: String,
    /// Old key identifier
    pub old_key_id: Uuid,
    /// Status of old key (e.g., "active until 2026-02-05T12:00:00Z")
    pub old_key_status: String,
    /// When rotation occurred
    pub rotated_at: DateTime<Utc>,
    /// When old key grace period ends (if applicable)
    pub old_key_expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_api_key_request_new() {
        let req = CreateApiKeyRequest::new("my-key");
        assert_eq!(req.name, "my-key");
        assert!(req.scopes.is_empty());
        assert!(req.expires_at.is_none());
    }

    #[test]
    fn test_create_api_key_request_with_scopes() {
        let req = CreateApiKeyRequest::new("my-key")
            .with_scopes(vec!["nhi:agents:*".to_string(), "audit:*".to_string()]);
        assert_eq!(req.scopes.len(), 2);
        assert_eq!(req.scopes[0], "nhi:agents:*");
    }

    #[test]
    fn test_create_api_key_request_serialization() {
        let req = CreateApiKeyRequest::new("test");
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        // Empty scopes should not be serialized
        assert!(!json.contains("scopes"));
    }

    #[test]
    fn test_rotate_api_key_request_default() {
        let req = RotateApiKeyRequest::default();
        assert!(req.deactivate_old_immediately.is_none());
        assert!(req.grace_period_hours.is_none());
    }

    #[test]
    fn test_rotate_api_key_request_with_options() {
        let req = RotateApiKeyRequest::new()
            .with_deactivate_old(true)
            .with_grace_period(48);
        assert_eq!(req.deactivate_old_immediately, Some(true));
        assert_eq!(req.grace_period_hours, Some(48));
    }
}
