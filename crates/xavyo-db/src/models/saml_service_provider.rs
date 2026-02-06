//! SAML Service Provider model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Represents a registered SAML Service Provider
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SamlServiceProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub entity_id: String,
    pub name: String,
    pub acs_urls: Vec<String>,
    pub certificate: Option<String>,
    pub attribute_mapping: serde_json::Value,
    pub name_id_format: String,
    pub sign_assertions: bool,
    pub validate_signatures: bool,
    pub assertion_validity_seconds: i32,
    pub enabled: bool,
    pub metadata_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Group configuration fields (F-039)
    /// Custom SAML attribute name for groups (default: "groups")
    #[serde(default)]
    pub group_attribute_name: Option<String>,
    /// How to format group values: "name", "id", or "dn"
    #[serde(default = "default_group_value_format")]
    pub group_value_format: String,
    /// JSON filter config for which groups to include
    #[serde(default)]
    pub group_filter: Option<serde_json::Value>,
    /// Whether to include groups in assertions
    #[serde(default = "default_true")]
    pub include_groups: bool,
    /// Whether to omit groups attribute when user has no groups
    #[serde(default = "default_true")]
    pub omit_empty_groups: bool,
    /// Base DN for DN format
    #[serde(default)]
    pub group_dn_base: Option<String>,
}

/// Request to create a new Service Provider
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateServiceProviderRequest {
    pub entity_id: String,
    pub name: String,
    pub acs_urls: Vec<String>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub attribute_mapping: Option<serde_json::Value>,
    #[serde(default = "default_name_id_format")]
    pub name_id_format: String,
    #[serde(default = "default_true")]
    pub sign_assertions: bool,
    #[serde(default)]
    pub validate_signatures: bool,
    #[serde(default = "default_assertion_validity")]
    pub assertion_validity_seconds: i32,
    #[serde(default)]
    pub metadata_url: Option<String>,
}

/// Request to update a Service Provider
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateServiceProviderRequest {
    pub name: Option<String>,
    pub acs_urls: Option<Vec<String>>,
    pub certificate: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub name_id_format: Option<String>,
    pub sign_assertions: Option<bool>,
    pub validate_signatures: Option<bool>,
    pub assertion_validity_seconds: Option<i32>,
    pub enabled: Option<bool>,
    pub metadata_url: Option<String>,
}

/// Attribute mapping configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    #[serde(default = "default_name_id_source")]
    pub name_id_source: String,
    #[serde(default)]
    pub attributes: Vec<AttributeMap>,
}

/// Single attribute mapping entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMap {
    pub source: String,
    pub target_name: String,
    #[serde(default)]
    pub target_friendly_name: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub multi_value: bool,
}

fn default_name_id_format() -> String {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
}

fn default_group_value_format() -> String {
    "name".to_string()
}

fn default_true() -> bool {
    true
}

fn default_assertion_validity() -> i32 {
    300
}

fn default_name_id_source() -> String {
    "email".to_string()
}

impl Default for AttributeMapping {
    fn default() -> Self {
        Self {
            name_id_source: default_name_id_source(),
            attributes: vec![
                AttributeMap {
                    source: "email".to_string(),
                    target_name:
                        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
                            .to_string(),
                    target_friendly_name: Some("email".to_string()),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: false,
                },
                AttributeMap {
                    source: "display_name".to_string(),
                    target_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
                        .to_string(),
                    target_friendly_name: Some("name".to_string()),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: false,
                },
            ],
        }
    }
}

/// Group filter configuration (matches `xavyo-api-saml::models::GroupFilter`)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpGroupFilter {
    /// Type of filter: "none", "pattern", or "allowlist"
    #[serde(default)]
    pub filter_type: String,
    /// Patterns for pattern-based filtering
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Explicit list of allowed group names
    #[serde(default)]
    pub allowlist: Vec<String>,
}

/// Group attribute configuration for SP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpGroupConfig {
    /// SAML attribute name for groups
    pub attribute_name: String,
    /// Format: "name", "id", or "dn"
    pub value_format: String,
    /// Filter configuration
    pub filter: Option<SpGroupFilter>,
    /// Whether to include groups
    pub include_groups: bool,
    /// Whether to omit empty groups attribute
    pub omit_empty_groups: bool,
    /// Base DN for DN format
    pub dn_base: Option<String>,
}

impl Default for SpGroupConfig {
    fn default() -> Self {
        Self {
            attribute_name: "groups".to_string(),
            value_format: "name".to_string(),
            filter: None,
            include_groups: true,
            omit_empty_groups: true,
            dn_base: None,
        }
    }
}

impl SamlServiceProvider {
    /// Parse attribute mapping from JSONB value
    #[must_use]
    pub fn get_attribute_mapping(&self) -> AttributeMapping {
        serde_json::from_value(self.attribute_mapping.clone()).unwrap_or_default()
    }

    /// Get group configuration for this SP
    #[must_use]
    pub fn get_group_config(&self) -> SpGroupConfig {
        SpGroupConfig {
            attribute_name: self
                .group_attribute_name
                .clone()
                .unwrap_or_else(|| "groups".to_string()),
            value_format: self.group_value_format.clone(),
            filter: self
                .group_filter
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            include_groups: self.include_groups,
            omit_empty_groups: self.omit_empty_groups,
            dn_base: self.group_dn_base.clone(),
        }
    }
}
