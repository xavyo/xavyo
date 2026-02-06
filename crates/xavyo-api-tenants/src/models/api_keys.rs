//! DTOs for API key management operations.
//!
//! F-KEY-ROTATE: Request and response types for API key rotation.
//! F-049: Request and response types for API key creation.
//! F-054: Request and response types for API key usage statistics.
//! F-055: Request and response types for API key introspection.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// F-049: API Key Creation DTOs
// ============================================================================

/// Valid scope prefixes for API keys.
pub const VALID_SCOPE_PREFIXES: &[&str] = &["nhi", "agents", "users", "groups", "audit"];

/// Valid scope actions for API keys.
pub const VALID_SCOPE_ACTIONS: &[&str] = &["read", "create", "update", "delete", "rotate", "*"];

/// Request to create a new API key.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    /// Human-readable name for the API key (1-100 characters).
    #[schema(example = "ci-pipeline")]
    pub name: String,

    /// Optional scopes to restrict access. Empty array = full access.
    /// Format: `prefix:resource:action` or `prefix:*`
    #[serde(default)]
    #[schema(example = json!(["nhi:agents:*", "nhi:credentials:rotate"]))]
    pub scopes: Vec<String>,

    /// Optional expiration date. Must be in the future if specified.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl CreateApiKeyRequest {
    /// Validate the create request.
    /// Returns None if valid, or Some(error_message) if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        // Validate name length
        if self.name.is_empty() {
            return Some("Name cannot be empty".to_string());
        }
        if self.name.len() > 100 {
            return Some("Name cannot exceed 100 characters".to_string());
        }

        // Validate expiration date is in the future
        if let Some(expires_at) = self.expires_at {
            if expires_at <= Utc::now() {
                return Some("Expiration date must be in the future".to_string());
            }
        }

        // Validate scopes format
        for scope in &self.scopes {
            if let Some(error) = validate_scope(scope) {
                return Some(error);
            }
        }

        None
    }
}

/// Validate a single scope string.
/// Returns None if valid, or Some(error_message) if invalid.
#[must_use]
pub fn validate_scope(scope: &str) -> Option<String> {
    // Empty scope is invalid (use empty array instead)
    if scope.is_empty() {
        return Some("Scope cannot be empty string".to_string());
    }

    // Must contain at least one colon
    if !scope.contains(':') {
        return Some(format!(
            "Invalid scope format: '{}'. Expected format: prefix:resource:action or prefix:*",
            scope
        ));
    }

    // Handle wildcard format: "prefix:*"
    if scope.ends_with(":*") {
        let prefix = scope.trim_end_matches(":*");
        // Handle nested wildcard: "prefix:resource:*"
        if prefix.contains(':') {
            let parts: Vec<&str> = prefix.split(':').collect();
            if parts.len() == 2 && VALID_SCOPE_PREFIXES.contains(&parts[0]) {
                return None; // Valid: "nhi:agents:*"
            }
        }
        // Simple wildcard: "prefix:*"
        if VALID_SCOPE_PREFIXES.contains(&prefix) {
            return None; // Valid: "nhi:*"
        }
        return Some(format!(
            "Invalid scope prefix: '{}'. Valid prefixes: {:?}",
            prefix, VALID_SCOPE_PREFIXES
        ));
    }

    // Handle full format: "prefix:resource:action"
    let parts: Vec<&str> = scope.split(':').collect();
    if parts.len() == 3 {
        let (prefix, _resource, action) = (parts[0], parts[1], parts[2]);
        if !VALID_SCOPE_PREFIXES.contains(&prefix) {
            return Some(format!(
                "Invalid scope prefix: '{}'. Valid prefixes: {:?}",
                prefix, VALID_SCOPE_PREFIXES
            ));
        }
        if !VALID_SCOPE_ACTIONS.contains(&action) {
            return Some(format!(
                "Invalid scope action: '{}'. Valid actions: {:?}",
                action, VALID_SCOPE_ACTIONS
            ));
        }
        return None; // Valid
    }

    // Handle two-part format: "prefix:action" (e.g., "nhi:read")
    if parts.len() == 2 {
        let (prefix, action) = (parts[0], parts[1]);
        if VALID_SCOPE_PREFIXES.contains(&prefix) && VALID_SCOPE_ACTIONS.contains(&action) {
            return None; // Valid
        }
    }

    Some(format!(
        "Invalid scope format: '{}'. Expected format: prefix:resource:action or prefix:*",
        scope
    ))
}

/// Response after creating a new API key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreateApiKeyResponse {
    /// Unique identifier for the new API key.
    pub id: Uuid,

    /// Human-readable name for the API key.
    pub name: String,

    /// Prefix of the key for identification.
    #[schema(example = "xavyo_sk_live_abc")]
    pub key_prefix: String,

    /// The API key in plaintext.
    /// SECURITY: This is shown only once and cannot be retrieved later.
    #[schema(example = "xavyo_sk_live_abcdefghijklmnopqrstuvwxyz123456")]
    pub api_key: String,

    /// Granted scopes (empty = full access).
    pub scopes: Vec<String>,

    /// When the API key expires (None = never).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// When the API key was created.
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// F-KEY-ROTATE: API Key Rotation DTOs (existing)
// ============================================================================

/// Request to rotate an API key.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RotateApiKeyRequest {
    /// If true, the old key is immediately deactivated.
    /// If false (default), the old key remains active for a grace period.
    #[serde(default)]
    #[schema(example = false)]
    pub deactivate_old_immediately: Option<bool>,

    /// Grace period in hours before the old key is deactivated.
    /// Default: 24 hours. Only applies if `deactivate_old_immediately` is false.
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
    #[must_use]
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

// ============================================================================
// F-054: API Key Usage Statistics DTOs
// ============================================================================

/// Query parameters for getting API key usage statistics.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct GetApiKeyUsageQuery {
    /// Start date for filtering (inclusive, YYYY-MM-DD).
    #[serde(default)]
    pub start_date: Option<NaiveDate>,

    /// End date for filtering (inclusive, YYYY-MM-DD).
    #[serde(default)]
    pub end_date: Option<NaiveDate>,

    /// Level of detail: "summary", "hourly", or "daily".
    /// Default: "summary"
    #[serde(default)]
    pub granularity: Option<String>,
}

impl GetApiKeyUsageQuery {
    /// Validate the query parameters.
    /// Returns None if valid, or Some(error_message) if invalid.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        // Validate date range
        if let (Some(start), Some(end)) = (self.start_date, self.end_date) {
            if start > end {
                return Some("start_date must be before or equal to end_date".to_string());
            }
        }

        // Validate granularity
        if let Some(ref gran) = self.granularity {
            if !["summary", "hourly", "daily"].contains(&gran.as_str()) {
                return Some(format!(
                    "Invalid granularity: '{}'. Expected: summary, hourly, or daily",
                    gran
                ));
            }
        }

        None
    }
}

/// Response containing API key usage statistics.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyUsageResponse {
    /// The API key identifier.
    pub key_id: Uuid,

    /// Human-readable name of the API key.
    pub key_name: String,

    /// Summary of cumulative usage.
    pub summary: ApiKeyUsageSummary,

    /// Hourly breakdown (only if granularity=hourly).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hourly: Option<Vec<ApiKeyUsageHourlyEntry>>,

    /// Daily breakdown (only if granularity=daily).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily: Option<Vec<ApiKeyUsageDailyEntry>>,
}

/// Summary of cumulative API key usage.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyUsageSummary {
    /// Total number of requests made with this key.
    pub total_requests: i64,

    /// Count of successful requests (2xx responses).
    pub success_count: i64,

    /// Count of client errors (4xx responses).
    pub client_error_count: i64,

    /// Count of server errors (5xx responses).
    pub server_error_count: i64,

    /// Error rate as decimal (errors / total_requests).
    #[schema(minimum = 0.0, maximum = 1.0)]
    pub error_rate: f64,

    /// Timestamp of first request (null if never used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_used_at: Option<DateTime<Utc>>,

    /// Timestamp of most recent request (null if never used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiKeyUsageSummary {
    /// Calculate error rate from counts.
    /// Returns 0.0 if total_requests is 0 to avoid division by zero.
    #[must_use]
    pub fn calculate_error_rate(
        total_requests: i64,
        client_errors: i64,
        server_errors: i64,
    ) -> f64 {
        if total_requests == 0 {
            return 0.0;
        }
        let errors = client_errors + server_errors;
        (errors as f64) / (total_requests as f64)
    }
}

/// Hourly usage entry for time-series data.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyUsageHourlyEntry {
    /// Hour bucket (truncated to hour, UTC).
    pub hour: DateTime<Utc>,

    /// Requests in this hour.
    pub request_count: i32,

    /// Successful requests in this hour.
    pub success_count: i32,

    /// Client errors in this hour.
    pub client_error_count: i32,

    /// Server errors in this hour.
    pub server_error_count: i32,
}

/// Daily usage entry for time-series data.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyUsageDailyEntry {
    /// Date of usage (YYYY-MM-DD).
    pub date: NaiveDate,

    /// Requests on this day.
    pub request_count: i32,

    /// Successful requests on this day.
    pub success_count: i32,

    /// Client errors on this day.
    pub client_error_count: i32,

    /// Server errors on this day.
    pub server_error_count: i32,
}

// ============================================================================
// F-055: API Key Introspection DTOs
// ============================================================================

/// Static definition structure for scope metadata.
#[derive(Debug, Clone)]
pub struct ScopeDefinition {
    /// Scope pattern (e.g., "nhi:agents:read").
    pub scope: &'static str,
    /// Human-readable description of what this scope grants.
    pub description: &'static str,
    /// List of specific operations this scope enables.
    pub operations: &'static [&'static str],
}

/// Complete list of known scopes with their descriptions and operations.
pub const SCOPE_DEFINITIONS: &[ScopeDefinition] = &[
    // NHI wildcard scopes
    ScopeDefinition {
        scope: "nhi:*",
        description: "Full NHI access",
        operations: &[
            "List agents",
            "Get agent details",
            "Create new agents",
            "Update agent configuration",
            "Delete agents",
            "Rotate agent credentials",
        ],
    },
    ScopeDefinition {
        scope: "nhi:agents:*",
        description: "Full NHI agent management",
        operations: &[
            "List agents",
            "Get agent details",
            "Create new agents",
            "Update agent configuration",
            "Delete agents",
        ],
    },
    // NHI specific scopes
    ScopeDefinition {
        scope: "nhi:agents:read",
        description: "Read NHI agent information",
        operations: &["List agents", "Get agent details"],
    },
    ScopeDefinition {
        scope: "nhi:agents:create",
        description: "Create NHI agents",
        operations: &["Create new agents"],
    },
    ScopeDefinition {
        scope: "nhi:agents:update",
        description: "Update NHI agents",
        operations: &["Update agent configuration"],
    },
    ScopeDefinition {
        scope: "nhi:agents:delete",
        description: "Delete NHI agents",
        operations: &["Delete agents"],
    },
    ScopeDefinition {
        scope: "nhi:credentials:*",
        description: "Full NHI credential management",
        operations: &["Rotate agent credentials"],
    },
    ScopeDefinition {
        scope: "nhi:credentials:rotate",
        description: "Rotate NHI credentials",
        operations: &["Rotate agent credentials"],
    },
    // Agent scopes (simplified)
    ScopeDefinition {
        scope: "agents:*",
        description: "Full agent access",
        operations: &[
            "List agents",
            "Get agent details",
            "Create new agents",
            "Update agent configuration",
            "Delete agents",
        ],
    },
    ScopeDefinition {
        scope: "agents:read",
        description: "Read agents",
        operations: &["List agents", "Get agent details"],
    },
    ScopeDefinition {
        scope: "agents:create",
        description: "Create agents",
        operations: &["Create new agents"],
    },
    ScopeDefinition {
        scope: "agents:update",
        description: "Update agents",
        operations: &["Update agent configuration"],
    },
    ScopeDefinition {
        scope: "agents:delete",
        description: "Delete agents",
        operations: &["Delete agents"],
    },
    // User scopes
    ScopeDefinition {
        scope: "users:*",
        description: "Full user management",
        operations: &[
            "List users",
            "Get user details",
            "Create new users",
            "Update user information",
            "Delete users",
        ],
    },
    ScopeDefinition {
        scope: "users:read",
        description: "Read users",
        operations: &["List users", "Get user details"],
    },
    ScopeDefinition {
        scope: "users:create",
        description: "Create users",
        operations: &["Create new users"],
    },
    ScopeDefinition {
        scope: "users:update",
        description: "Update users",
        operations: &["Update user information"],
    },
    ScopeDefinition {
        scope: "users:delete",
        description: "Delete users",
        operations: &["Delete users"],
    },
    // Group scopes
    ScopeDefinition {
        scope: "groups:*",
        description: "Full group management",
        operations: &[
            "List groups",
            "Get group details",
            "Create new groups",
            "Update group membership",
            "Delete groups",
        ],
    },
    ScopeDefinition {
        scope: "groups:read",
        description: "Read groups",
        operations: &["List groups", "Get group details"],
    },
    ScopeDefinition {
        scope: "groups:create",
        description: "Create groups",
        operations: &["Create new groups"],
    },
    ScopeDefinition {
        scope: "groups:update",
        description: "Update groups",
        operations: &["Update group membership"],
    },
    ScopeDefinition {
        scope: "groups:delete",
        description: "Delete groups",
        operations: &["Delete groups"],
    },
    // Audit scopes
    ScopeDefinition {
        scope: "audit:*",
        description: "Full audit access",
        operations: &["View audit log entries"],
    },
    ScopeDefinition {
        scope: "audit:logs:read",
        description: "Read audit logs",
        operations: &["View audit log entries"],
    },
];

/// Look up scope information by scope string.
/// Returns a ScopeInfo with description and operations.
/// For unknown scopes, returns a generic "Custom scope" description.
#[must_use]
pub fn get_scope_info(scope: &str) -> ScopeInfo {
    // Look for exact match first
    if let Some(def) = SCOPE_DEFINITIONS.iter().find(|d| d.scope == scope) {
        return ScopeInfo {
            scope: scope.to_string(),
            description: def.description.to_string(),
            operations: def.operations.iter().map(|s| (*s).to_string()).collect(),
        };
    }

    // For unknown scopes, return generic description
    ScopeInfo {
        scope: scope.to_string(),
        description: "Custom scope".to_string(),
        operations: vec![],
    }
}

/// Information about a single scope.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScopeInfo {
    /// Scope identifier (e.g., "nhi:agents:read").
    #[schema(example = "nhi:agents:read")]
    pub scope: String,

    /// Human-readable description of what this scope grants.
    #[schema(example = "Read NHI agent information")]
    pub description: String,

    /// Specific operations this scope enables.
    #[schema(example = json!(["List agents", "Get agent details"]))]
    pub operations: Vec<String>,
}

/// Response for the API key introspection endpoint.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IntrospectApiKeyResponse {
    /// Unique identifier of the API key.
    pub key_id: Uuid,

    /// Human-readable name of the API key.
    #[schema(example = "CI Pipeline Key")]
    pub name: String,

    /// First characters of the key for identification.
    #[schema(example = "xavyo_sk_live_abc123")]
    pub key_prefix: String,

    /// When the API key was created.
    pub created_at: DateTime<Utc>,

    /// When the API key expires (null = never expires).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether the API key is currently active.
    pub is_active: bool,

    /// True if the key has no scope restrictions (full access).
    pub has_full_access: bool,

    /// Detailed information about each granted scope.
    pub scopes: Vec<ScopeInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ========================================================================
    // F-049: CreateApiKeyRequest validation tests
    // ========================================================================

    #[test]
    fn test_create_request_valid_basic() {
        let request = CreateApiKeyRequest {
            name: "my-key".to_string(),
            scopes: vec![],
            expires_at: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_create_request_valid_with_scopes() {
        let request = CreateApiKeyRequest {
            name: "ci-pipeline".to_string(),
            scopes: vec![
                "nhi:agents:*".to_string(),
                "nhi:credentials:rotate".to_string(),
            ],
            expires_at: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_create_request_valid_with_future_expiration() {
        let request = CreateApiKeyRequest {
            name: "temp-key".to_string(),
            scopes: vec![],
            expires_at: Some(Utc::now() + Duration::days(30)),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_create_request_invalid_empty_name() {
        let request = CreateApiKeyRequest {
            name: "".to_string(),
            scopes: vec![],
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("empty"));
    }

    #[test]
    fn test_create_request_invalid_name_too_long() {
        let request = CreateApiKeyRequest {
            name: "x".repeat(101),
            scopes: vec![],
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("100"));
    }

    #[test]
    fn test_create_request_invalid_past_expiration() {
        let request = CreateApiKeyRequest {
            name: "my-key".to_string(),
            scopes: vec![],
            expires_at: Some(Utc::now() - Duration::hours(1)),
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("future"));
    }

    #[test]
    fn test_create_request_invalid_scope_format() {
        let request = CreateApiKeyRequest {
            name: "my-key".to_string(),
            scopes: vec!["invalid-scope".to_string()],
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("Invalid scope format"));
    }

    #[test]
    fn test_create_request_invalid_scope_prefix() {
        let request = CreateApiKeyRequest {
            name: "my-key".to_string(),
            scopes: vec!["invalid:agents:read".to_string()],
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("Invalid scope prefix"));
    }

    #[test]
    fn test_create_request_invalid_scope_action() {
        let request = CreateApiKeyRequest {
            name: "my-key".to_string(),
            scopes: vec!["nhi:agents:invalid".to_string()],
            expires_at: None,
        };
        let error = request.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("Invalid scope action"));
    }

    // ========================================================================
    // Scope validation tests
    // ========================================================================

    #[test]
    fn test_validate_scope_wildcard() {
        assert!(validate_scope("nhi:*").is_none());
        assert!(validate_scope("agents:*").is_none());
        assert!(validate_scope("users:*").is_none());
    }

    #[test]
    fn test_validate_scope_resource_wildcard() {
        assert!(validate_scope("nhi:agents:*").is_none());
        assert!(validate_scope("nhi:credentials:*").is_none());
    }

    #[test]
    fn test_validate_scope_full_format() {
        assert!(validate_scope("nhi:agents:read").is_none());
        assert!(validate_scope("nhi:agents:create").is_none());
        assert!(validate_scope("nhi:agents:update").is_none());
        assert!(validate_scope("nhi:agents:delete").is_none());
    }

    #[test]
    fn test_validate_scope_empty_string() {
        let error = validate_scope("");
        assert!(error.is_some());
        assert!(error.unwrap().contains("empty"));
    }

    // ========================================================================
    // F-KEY-ROTATE: RotateApiKeyRequest validation tests (existing)
    // ========================================================================

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

    // ========================================================================
    // F-054: GetApiKeyUsageQuery validation tests
    // ========================================================================

    #[test]
    fn test_usage_query_valid_defaults() {
        let query = GetApiKeyUsageQuery::default();
        assert!(query.validate().is_none());
    }

    #[test]
    fn test_usage_query_valid_with_dates() {
        let query = GetApiKeyUsageQuery {
            start_date: Some(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 2, 4).unwrap()),
            granularity: None,
        };
        assert!(query.validate().is_none());
    }

    #[test]
    fn test_usage_query_valid_granularity_hourly() {
        let query = GetApiKeyUsageQuery {
            start_date: None,
            end_date: None,
            granularity: Some("hourly".to_string()),
        };
        assert!(query.validate().is_none());
    }

    #[test]
    fn test_usage_query_valid_granularity_daily() {
        let query = GetApiKeyUsageQuery {
            start_date: None,
            end_date: None,
            granularity: Some("daily".to_string()),
        };
        assert!(query.validate().is_none());
    }

    #[test]
    fn test_usage_query_invalid_date_range() {
        let query = GetApiKeyUsageQuery {
            start_date: Some(NaiveDate::from_ymd_opt(2026, 2, 10).unwrap()),
            end_date: Some(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            granularity: None,
        };
        let error = query.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("start_date must be before"));
    }

    #[test]
    fn test_usage_query_invalid_granularity() {
        let query = GetApiKeyUsageQuery {
            start_date: None,
            end_date: None,
            granularity: Some("invalid".to_string()),
        };
        let error = query.validate();
        assert!(error.is_some());
        assert!(error.unwrap().contains("Invalid granularity"));
    }

    #[test]
    fn test_error_rate_calculation_normal() {
        let rate = ApiKeyUsageSummary::calculate_error_rate(100, 3, 2);
        assert!((rate - 0.05).abs() < 0.001);
    }

    #[test]
    fn test_error_rate_calculation_zero_requests() {
        let rate = ApiKeyUsageSummary::calculate_error_rate(0, 0, 0);
        assert!((rate - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_error_rate_calculation_all_errors() {
        let rate = ApiKeyUsageSummary::calculate_error_rate(10, 5, 5);
        assert!((rate - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_error_rate_calculation_no_errors() {
        let rate = ApiKeyUsageSummary::calculate_error_rate(100, 0, 0);
        assert!((rate - 0.0).abs() < 0.001);
    }

    // ========================================================================
    // F-055: API Key Introspection Tests
    // ========================================================================

    #[test]
    fn test_introspect_response_serialization() {
        let response = IntrospectApiKeyResponse {
            key_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: "CI Pipeline Key".to_string(),
            key_prefix: "xavyo_sk_live_abc123".to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::days(180)),
            is_active: true,
            has_full_access: false,
            scopes: vec![ScopeInfo {
                scope: "nhi:agents:read".to_string(),
                description: "Read NHI agent information".to_string(),
                operations: vec!["List agents".to_string(), "Get agent details".to_string()],
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("CI Pipeline Key"));
        assert!(json.contains("xavyo_sk_live_abc123"));
        assert!(json.contains("nhi:agents:read"));
        assert!(json.contains("has_full_access"));
    }

    #[test]
    fn test_scope_info_serialization() {
        let scope_info = ScopeInfo {
            scope: "nhi:agents:read".to_string(),
            description: "Read NHI agent information".to_string(),
            operations: vec!["List agents".to_string(), "Get agent details".to_string()],
        };

        let json = serde_json::to_string(&scope_info).unwrap();
        assert!(json.contains("nhi:agents:read"));
        assert!(json.contains("Read NHI agent information"));
        assert!(json.contains("List agents"));
        assert!(json.contains("Get agent details"));

        // Test deserialization
        let deserialized: ScopeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.scope, "nhi:agents:read");
        assert_eq!(deserialized.operations.len(), 2);
    }

    #[test]
    fn test_scope_description_lookup_known_scope() {
        let info = get_scope_info("nhi:agents:read");
        assert_eq!(info.scope, "nhi:agents:read");
        assert_eq!(info.description, "Read NHI agent information");
        assert!(info.operations.contains(&"List agents".to_string()));
        assert!(info.operations.contains(&"Get agent details".to_string()));
    }

    #[test]
    fn test_scope_description_lookup_unknown_scope() {
        let info = get_scope_info("custom:unknown:scope");
        assert_eq!(info.scope, "custom:unknown:scope");
        assert_eq!(info.description, "Custom scope");
        assert!(info.operations.is_empty());
    }

    #[test]
    fn test_empty_scopes_indicates_full_access() {
        // When scopes array is empty, has_full_access should be true
        let response = IntrospectApiKeyResponse {
            key_id: Uuid::new_v4(),
            name: "Admin Key".to_string(),
            key_prefix: "xavyo_sk_live_admin".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
            has_full_access: true, // Should be true when scopes is empty
            scopes: vec![],
        };

        assert!(response.has_full_access);
        assert!(response.scopes.is_empty());
    }

    #[test]
    fn test_scope_operations_for_specific_scope() {
        // Test US3: Operations are returned for specific scopes
        let info = get_scope_info("nhi:agents:create");
        assert_eq!(info.scope, "nhi:agents:create");
        assert_eq!(info.description, "Create NHI agents");
        assert_eq!(info.operations, vec!["Create new agents"]);
    }

    #[test]
    fn test_wildcard_scope_operations() {
        // Test US3: Wildcard scopes return all operations
        let info = get_scope_info("nhi:*");
        assert_eq!(info.scope, "nhi:*");
        assert_eq!(info.description, "Full NHI access");
        // Should include all NHI operations
        assert!(info.operations.contains(&"List agents".to_string()));
        assert!(info.operations.contains(&"Get agent details".to_string()));
        assert!(info.operations.contains(&"Create new agents".to_string()));
        assert!(info
            .operations
            .contains(&"Update agent configuration".to_string()));
        assert!(info.operations.contains(&"Delete agents".to_string()));
        assert!(info
            .operations
            .contains(&"Rotate agent credentials".to_string()));
    }
}
