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
///
/// Accepts both the canonical `{ "mappings": [...] }` shape and the flat
/// `{ "email": "email", "given_name": "first_name" }` map advertised by the
/// admin UI. A flat object must not deserialize as an empty `mappings` list —
/// that would persist a silent no-op instead of `default_mapping()`.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct ClaimMappingConfig {
    #[serde(default)]
    pub mappings: Vec<ClaimMappingEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_id: Option<NameIdConfig>,
}

impl<'de> Deserialize<'de> for ClaimMappingConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        claim_mapping_from_value(value).map_err(serde::de::Error::custom)
    }
}

/// Parse canonical `{mappings: [...]}` or a flat source→target object.
pub(crate) fn claim_mapping_from_value(
    value: serde_json::Value,
) -> Result<ClaimMappingConfig, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "claim_mapping must be a JSON object".to_string())?;

    if obj.contains_key("mappings") {
        #[derive(Deserialize)]
        struct Canonical {
            #[serde(default)]
            mappings: Vec<ClaimMappingEntry>,
            #[serde(default)]
            name_id: Option<NameIdConfig>,
        }
        let canonical: Canonical =
            serde_json::from_value(value).map_err(|e| format!("invalid claim_mapping: {e}"))?;
        return Ok(ClaimMappingConfig {
            mappings: canonical.mappings,
            name_id: canonical.name_id,
        });
    }

    let mut mappings = Vec::with_capacity(obj.len());
    for (source, target) in obj {
        let Some(target) = target.as_str() else {
            return Err(format!(
                "claim_mapping value for '{source}' must be a string"
            ));
        };
        if source.is_empty() || target.is_empty() {
            return Err("claim_mapping source and target cannot be empty".to_string());
        }
        mappings.push(ClaimMappingEntry {
            source: source.clone(),
            target: target.to_string(),
            required: false,
            default: None,
            transform: None,
            group_mapping: None,
        });
    }
    Ok(ClaimMappingConfig {
        mappings,
        name_id: None,
    })
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
    /// Convert to JSON value. Serialization errors must not persist an empty mapping.
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Create default claim mapping.
    #[must_use]
    pub fn default_mapping() -> Self {
        Self {
            mappings: vec![
                mapping_entry("email", "email", true),
                mapping_entry("name", "display_name", false),
                mapping_entry("given_name", "first_name", false),
                mapping_entry("family_name", "last_name", false),
                mapping_entry("picture", "avatar_url", false),
            ],
            name_id: Some(NameIdConfig {
                source: "sub".to_string(),
                format: "persistent".to_string(),
            }),
        }
    }
}

fn mapping_entry(source: &str, target: &str, required: bool) -> ClaimMappingEntry {
    ClaimMappingEntry {
        source: source.to_string(),
        target: target.to_string(),
        required,
        default: None,
        transform: None,
        group_mapping: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_claim_mapping_deserializes_to_entries() {
        let mapping: ClaimMappingConfig = serde_json::from_str(
            r#"{"email":"email","given_name":"first_name","family_name":"last_name","picture":"avatar_url"}"#,
        )
        .unwrap();
        assert_eq!(mapping.mappings.len(), 4);
        assert!(mapping
            .mappings
            .iter()
            .any(|m| m.source == "given_name" && m.target == "first_name"));
        assert!(mapping
            .mappings
            .iter()
            .any(|m| m.source == "family_name" && m.target == "last_name"));
        assert!(mapping
            .mappings
            .iter()
            .any(|m| m.source == "picture" && m.target == "avatar_url"));
        assert!(mapping.name_id.is_none());
    }

    #[test]
    fn canonical_claim_mapping_still_deserializes() {
        let mapping: ClaimMappingConfig = serde_json::from_str(
            r#"{"mappings":[{"source":"email","target":"email","required":true}],"name_id":{"source":"sub"}}"#,
        )
        .unwrap();
        assert_eq!(mapping.mappings.len(), 1);
        assert_eq!(mapping.mappings[0].source, "email");
        assert_eq!(mapping.mappings[0].target, "email");
        assert!(mapping.mappings[0].required);
        assert_eq!(mapping.name_id.as_ref().unwrap().source, "sub");
    }

    #[test]
    fn create_request_flat_claim_mapping_is_not_empty() {
        let req: CreateIdentityProviderRequest = serde_json::from_str(
            r#"{
                "name":"okta",
                "provider_type":"okta",
                "issuer_url":"https://example.okta.com",
                "client_id":"cid",
                "client_secret":"secret",
                "claim_mapping":{"email":"email","name":"display_name"}
            }"#,
        )
        .unwrap();
        let mapping = req.claim_mapping.expect("claim_mapping present");
        assert_eq!(mapping.mappings.len(), 2);
        assert!(mapping
            .mappings
            .iter()
            .any(|m| m.source == "name" && m.target == "display_name"));
    }

    #[test]
    fn update_request_flat_claim_mapping_is_not_empty() {
        let req: UpdateIdentityProviderRequest = serde_json::from_str(
            r#"{"claim_mapping":{"given_name":"first_name","family_name":"last_name"}}"#,
        )
        .unwrap();
        let mapping = req.claim_mapping.expect("claim_mapping present");
        assert_eq!(mapping.mappings.len(), 2);
        assert!(mapping
            .mappings
            .iter()
            .any(|m| m.source == "given_name" && m.target == "first_name"));
    }

    #[test]
    fn non_string_flat_claim_mapping_value_is_rejected() {
        let err = serde_json::from_str::<ClaimMappingConfig>(r#"{"email":["not","a","string"]}"#)
            .unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn default_mapping_includes_profile_claims() {
        let mapping = ClaimMappingConfig::default_mapping();
        let pairs: Vec<(&str, &str)> = mapping
            .mappings
            .iter()
            .map(|m| (m.source.as_str(), m.target.as_str()))
            .collect();
        assert!(pairs.contains(&("email", "email")));
        assert!(pairs.contains(&("name", "display_name")));
        assert!(pairs.contains(&("given_name", "first_name")));
        assert!(pairs.contains(&("family_name", "last_name")));
        assert!(pairs.contains(&("picture", "avatar_url")));
        assert_eq!(mapping.name_id.as_ref().unwrap().source, "sub");
    }
}
