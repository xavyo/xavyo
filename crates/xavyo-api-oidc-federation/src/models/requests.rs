//! Request models for OIDC Federation API.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Request to discover authentication realm for an email.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DiscoverRequest {
    pub email: String,
}

/// Request to create a new identity provider.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateIdentityProviderRequest {
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_scopes")]
    pub scopes: String,
    #[serde(default)]
    pub claim_mapping: Option<ClaimMappingConfig>,
    #[serde(default = "default_true")]
    pub sync_on_login: bool,
    /// Initial domains to configure for HRD.
    #[serde(default)]
    pub domains: Vec<String>,
}

fn default_scopes() -> String {
    "openid profile email".to_string()
}

fn default_true() -> bool {
    true
}

/// Request to update an identity provider.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateIdentityProviderRequest {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    /// Only include to update the secret.
    pub client_secret: Option<String>,
    pub scopes: Option<String>,
    pub claim_mapping: Option<ClaimMappingConfig>,
    pub sync_on_login: Option<bool>,
}

/// Request to toggle identity provider enabled status.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ToggleIdentityProviderRequest {
    pub is_enabled: bool,
}

/// Request to add a domain to an identity provider.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateDomainRequest {
    pub domain: String,
    #[serde(default)]
    pub priority: i32,
}

/// Claim mapping configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ClaimMappingConfig {
    #[serde(default)]
    pub mappings: Vec<ClaimMappingEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_id: Option<NameIdConfig>,
}

/// A single claim mapping entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClaimMappingEntry {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_mapping: Option<std::collections::HashMap<String, String>>,
}

/// `NameID` configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NameIdConfig {
    pub source: String,
    #[serde(default = "default_persistent")]
    pub format: String,
}

fn default_persistent() -> String {
    "persistent".to_string()
}

/// Maximum allowed pagination limit.
const MAX_PAGINATION_LIMIT: i64 = 100;

/// Pagination parameters.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PaginationParams {
    #[serde(default)]
    pub offset: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Filter by enabled status.
    pub is_enabled: Option<bool>,
}

impl PaginationParams {
    /// Clamp limit to the maximum allowed value.
    #[must_use]
    pub fn clamped_limit(&self) -> i64 {
        self.limit.clamp(1, MAX_PAGINATION_LIMIT)
    }
}

fn default_limit() -> i64 {
    20
}

/// Query parameters for federation authorization.
///
/// At least one of `idp_id` or `login_hint` must be provided.
/// When `login_hint` is given (an email address), the server performs
/// HRD lookup internally to resolve the IdP — avoiding the need to
/// expose IdP UUIDs to unauthenticated callers.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AuthorizeParams {
    pub idp_id: Option<Uuid>,
    pub login_hint: Option<String>,
    pub redirect_uri: Option<String>,
}

/// Callback parameters from `IdP`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

impl ClaimMappingConfig {
    /// Convert to JSON value.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Create default claim mapping.
    #[must_use]
    pub fn default_mapping() -> Self {
        Self {
            mappings: vec![
                ClaimMappingEntry {
                    source: "email".to_string(),
                    target: "email".to_string(),
                    required: true,
                    default: None,
                    transform: None,
                    group_mapping: None,
                },
                ClaimMappingEntry {
                    source: "name".to_string(),
                    target: "display_name".to_string(),
                    required: false,
                    default: None,
                    transform: None,
                    group_mapping: None,
                },
            ],
            name_id: Some(NameIdConfig {
                source: "sub".to_string(),
                format: "persistent".to_string(),
            }),
        }
    }
}
