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
    /// Single Logout URL for this SP
    #[serde(default)]
    pub slo_url: Option<String>,
    /// Single Logout binding (default: HTTP-POST)
    #[serde(default = "default_slo_binding")]
    pub slo_binding: String,
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
    #[serde(default)]
    pub slo_url: Option<String>,
    #[serde(default = "default_slo_binding")]
    pub slo_binding: String,
    /// Nested F-039 group assertion config (alias for the flat fields below).
    #[serde(default)]
    pub group_config: Option<SpGroupConfig>,
    #[serde(default)]
    pub group_attribute_name: Option<String>,
    #[serde(default)]
    pub group_value_format: Option<String>,
    #[serde(default)]
    pub group_filter: Option<serde_json::Value>,
    #[serde(default)]
    pub include_groups: Option<bool>,
    #[serde(default)]
    pub omit_empty_groups: Option<bool>,
    #[serde(default)]
    pub group_dn_base: Option<String>,
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
    pub slo_url: Option<String>,
    pub slo_binding: Option<String>,
    /// Nested F-039 group assertion config (alias for the flat fields below).
    #[serde(default)]
    pub group_config: Option<SpGroupConfig>,
    #[serde(default)]
    pub group_attribute_name: Option<String>,
    #[serde(default)]
    pub group_value_format: Option<String>,
    #[serde(default)]
    pub group_filter: Option<serde_json::Value>,
    #[serde(default)]
    pub include_groups: Option<bool>,
    #[serde(default)]
    pub omit_empty_groups: Option<bool>,
    #[serde(default)]
    pub group_dn_base: Option<String>,
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
    /// Static value to emit instead of resolving from user fields.
    /// When set, `source` is ignored and this value is used directly.
    #[serde(default)]
    pub static_value: Option<String>,
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

fn default_slo_binding() -> String {
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()
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
                    static_value: None,
                },
                AttributeMap {
                    source: "display_name".to_string(),
                    target_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
                        .to_string(),
                    target_friendly_name: Some("name".to_string()),
                    format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:uri".to_string()),
                    multi_value: false,
                    static_value: None,
                },
            ],
        }
    }
}

/// Group filter configuration (matches `xavyo-api-saml::models::GroupFilter`)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
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
    pub fn get_attribute_mapping(&self) -> Result<AttributeMapping, serde_json::Error> {
        serde_json::from_value(self.attribute_mapping.clone())
    }

    /// Get group configuration for this SP
    pub fn get_group_config(&self) -> Result<SpGroupConfig, serde_json::Error> {
        let filter = match self.group_filter.as_ref() {
            None => None,
            Some(v) => Some(serde_json::from_value(v.clone())?),
        };
        Ok(SpGroupConfig {
            attribute_name: self
                .group_attribute_name
                .clone()
                .unwrap_or_else(|| "groups".to_string()),
            value_format: self.group_value_format.clone(),
            filter,
            include_groups: self.include_groups,
            omit_empty_groups: self.omit_empty_groups,
            dn_base: self.group_dn_base.clone(),
        })
    }
}

fn overlay_group_config(
    mut base: SpGroupConfig,
    nested: Option<SpGroupConfig>,
    group_attribute_name: Option<String>,
    group_value_format: Option<String>,
    group_filter: Option<serde_json::Value>,
    include_groups: Option<bool>,
    omit_empty_groups: Option<bool>,
    group_dn_base: Option<String>,
) -> Result<SpGroupConfig, serde_json::Error> {
    if let Some(nested) = nested {
        base = nested;
    }
    if let Some(name) = group_attribute_name {
        base.attribute_name = name;
    }
    if let Some(format) = group_value_format {
        base.value_format = format;
    }
    if let Some(filter) = group_filter {
        base.filter = Some(serde_json::from_value(filter)?);
    }
    if let Some(include) = include_groups {
        base.include_groups = include;
    }
    if let Some(omit) = omit_empty_groups {
        base.omit_empty_groups = omit;
    }
    if let Some(dn_base) = group_dn_base {
        base.dn_base = if dn_base.is_empty() {
            None
        } else {
            Some(dn_base)
        };
    }
    Ok(base)
}

impl CreateServiceProviderRequest {
    /// Resolve F-039 group config from nested `group_config` and/or flat fields.
    pub fn resolved_group_config(&self) -> Result<SpGroupConfig, serde_json::Error> {
        overlay_group_config(
            SpGroupConfig::default(),
            self.group_config.clone(),
            self.group_attribute_name.clone(),
            self.group_value_format.clone(),
            self.group_filter.clone(),
            self.include_groups,
            self.omit_empty_groups,
            self.group_dn_base.clone(),
        )
    }
}

impl UpdateServiceProviderRequest {
    /// Overlay advertised group-config fields onto the existing SP.
    pub fn resolved_group_config(
        &self,
        existing: &SamlServiceProvider,
    ) -> Result<SpGroupConfig, serde_json::Error> {
        overlay_group_config(
            existing.get_group_config()?,
            self.group_config.clone(),
            self.group_attribute_name.clone(),
            self.group_value_format.clone(),
            self.group_filter.clone(),
            self.include_groups,
            self.omit_empty_groups,
            self.group_dn_base.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_request_accepts_flat_group_config() {
        let req: CreateServiceProviderRequest = serde_json::from_value(json!({
            "name": "app",
            "entity_id": "https://sp.example",
            "acs_urls": ["https://sp.example/acs"],
            "group_attribute_name": "memberOf",
            "group_value_format": "id",
            "include_groups": false,
            "omit_empty_groups": false,
            "group_dn_base": "ou=Groups,dc=example,dc=com",
            "group_filter": {"filter_type": "allowlist", "allowlist": ["admins"]}
        }))
        .unwrap();

        let cfg = req.resolved_group_config().unwrap();
        assert_eq!(cfg.attribute_name, "memberOf");
        assert_eq!(cfg.value_format, "id");
        assert!(!cfg.include_groups);
        assert!(!cfg.omit_empty_groups);
        assert_eq!(cfg.dn_base.as_deref(), Some("ou=Groups,dc=example,dc=com"));
        let filter = cfg.filter.expect("filter");
        assert_eq!(filter.filter_type, "allowlist");
        assert_eq!(filter.allowlist, vec!["admins".to_string()]);
    }

    #[test]
    fn create_request_accepts_nested_group_config() {
        let req: CreateServiceProviderRequest = serde_json::from_value(json!({
            "name": "app",
            "entity_id": "https://sp.example",
            "acs_urls": ["https://sp.example/acs"],
            "group_config": {
                "attribute_name": "Roles",
                "value_format": "dn",
                "include_groups": true,
                "omit_empty_groups": true,
                "dn_base": "ou=Groups,dc=example,dc=com",
                "filter": {"filter_type": "pattern", "patterns": ["app-*"]}
            }
        }))
        .unwrap();

        let cfg = req.resolved_group_config().unwrap();
        assert_eq!(cfg.attribute_name, "Roles");
        assert_eq!(cfg.value_format, "dn");
        assert_eq!(cfg.filter.unwrap().patterns, vec!["app-*".to_string()]);
    }

    #[test]
    fn create_request_omitting_group_config_keeps_defaults() {
        let req: CreateServiceProviderRequest = serde_json::from_value(json!({
            "name": "app",
            "entity_id": "https://sp.example",
            "acs_urls": ["https://sp.example/acs"]
        }))
        .unwrap();

        let cfg = req.resolved_group_config().unwrap();
        assert_eq!(cfg, SpGroupConfig::default());
    }

    #[test]
    fn update_request_accepts_flat_group_config() {
        let req: UpdateServiceProviderRequest = serde_json::from_value(json!({
            "include_groups": false,
            "group_attribute_name": "Roles"
        }))
        .unwrap();

        assert_eq!(req.group_attribute_name.as_deref(), Some("Roles"));
        assert_eq!(req.include_groups, Some(false));
    }

    #[test]
    fn update_request_accepts_nested_group_config() {
        let req: UpdateServiceProviderRequest = serde_json::from_value(json!({
            "group_config": {
                "attribute_name": "groups",
                "value_format": "name",
                "include_groups": false,
                "omit_empty_groups": true,
                "filter": null,
                "dn_base": null
            }
        }))
        .unwrap();

        let cfg = req.group_config.expect("nested group_config");
        assert!(!cfg.include_groups);
        assert_eq!(cfg.attribute_name, "groups");
    }
}
