//! Request and response models for tenant settings API.
//!
//! F-SETTINGS-API: Allows system admins to update tenant settings.
//! F-056: Extends access to tenant users for limited settings updates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use utoipa::ToSchema;
use uuid::Uuid;

// ============================================================================
// F-056: Restricted Fields Constants
// ============================================================================

/// Fields that tenant users are NOT allowed to modify.
/// These are controlled by system administrators only.
pub const RESTRICTED_SETTINGS_FIELDS: &[&str] =
    &["plan_tier", "limits", "security_settings", "features"];

// ============================================================================
// F-056: Tenant User Update Request
// ============================================================================

/// Request for tenant users to update modifiable settings.
///
/// Unlike `UpdateSettingsRequest` (for system admins), this request
/// only allows modification of:
/// - `display_name` (1-100 characters)
/// - `logo_url` (valid URL or null to clear)
/// - `custom_attributes` (max 10 keys, max 1KB total)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TenantUserUpdateSettingsRequest {
    /// Human-readable tenant name.
    /// Must be 1-100 characters if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// URL to tenant logo.
    /// Must be a valid URL format, or null to clear.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub logo_url: Option<Option<String>>,

    /// Custom key-value metadata.
    /// Max 10 keys, max 1KB total size.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub custom_attributes: Option<Value>,
}

impl TenantUserUpdateSettingsRequest {
    /// Maximum length for display_name.
    pub const MAX_DISPLAY_NAME_LENGTH: usize = 100;

    /// Maximum number of keys in custom_attributes.
    pub const MAX_CUSTOM_ATTRIBUTES_KEYS: usize = 10;

    /// Maximum total size of custom_attributes in bytes (1KB).
    pub const MAX_CUSTOM_ATTRIBUTES_SIZE: usize = 1024;

    /// Validate the request.
    ///
    /// Returns `Some((field, message))` if validation fails.
    #[must_use]
    pub fn validate(&self) -> Option<(String, String)> {
        // At least one field must be provided
        if self.display_name.is_none()
            && self.logo_url.is_none()
            && self.custom_attributes.is_none()
        {
            return Some((
                "request".to_string(),
                "At least one field must be provided".to_string(),
            ));
        }

        // Validate display_name
        if let Some(ref name) = self.display_name {
            if name.is_empty() {
                return Some((
                    "display_name".to_string(),
                    "display_name cannot be empty".to_string(),
                ));
            }
            if name.len() > Self::MAX_DISPLAY_NAME_LENGTH {
                return Some((
                    "display_name".to_string(),
                    format!(
                        "display_name cannot exceed {} characters",
                        Self::MAX_DISPLAY_NAME_LENGTH
                    ),
                ));
            }
        }

        // Validate logo_url
        if let Some(Some(ref url_str)) = self.logo_url {
            if !url_str.is_empty() && Url::parse(url_str).is_err() {
                return Some((
                    "logo_url".to_string(),
                    "Invalid URL format for logo_url".to_string(),
                ));
            }
        }

        // Validate custom_attributes
        if let Some(ref attrs) = self.custom_attributes {
            if !attrs.is_object() && !attrs.is_null() {
                return Some((
                    "custom_attributes".to_string(),
                    "custom_attributes must be a JSON object".to_string(),
                ));
            }

            if let Some(obj) = attrs.as_object() {
                // Check key count
                if obj.len() > Self::MAX_CUSTOM_ATTRIBUTES_KEYS {
                    return Some((
                        "custom_attributes".to_string(),
                        format!(
                            "custom_attributes cannot have more than {} keys",
                            Self::MAX_CUSTOM_ATTRIBUTES_KEYS
                        ),
                    ));
                }

                // Check total size
                let serialized = serde_json::to_string(attrs).unwrap_or_default();
                if serialized.len() > Self::MAX_CUSTOM_ATTRIBUTES_SIZE {
                    return Some((
                        "custom_attributes".to_string(),
                        format!(
                            "custom_attributes total size cannot exceed {} bytes",
                            Self::MAX_CUSTOM_ATTRIBUTES_SIZE
                        ),
                    ));
                }
            }
        }

        None
    }

    /// Convert to a settings JSON value for merging.
    #[must_use]
    pub fn to_settings_value(&self) -> Value {
        let mut obj = serde_json::Map::new();

        if let Some(ref name) = self.display_name {
            obj.insert("display_name".to_string(), Value::String(name.clone()));
        }

        if let Some(ref logo_opt) = self.logo_url {
            match logo_opt {
                Some(url) => obj.insert("logo_url".to_string(), Value::String(url.clone())),
                None => obj.insert("logo_url".to_string(), Value::Null),
            };
        }

        if let Some(ref attrs) = self.custom_attributes {
            obj.insert("custom_attributes".to_string(), attrs.clone());
        }

        Value::Object(obj)
    }

    /// Check if the request contains any restricted fields.
    ///
    /// This is a safety check to ensure tenant users don't try to modify
    /// fields they're not allowed to change.
    #[must_use]
    pub fn contains_restricted_fields(&self) -> Option<&'static str> {
        // This struct only has allowed fields, so no restricted fields can be present.
        // However, we keep this method for consistency and future-proofing.
        None
    }
}

/// Check if a raw JSON value contains restricted settings fields.
///
/// This is used to validate arbitrary JSON before processing.
#[must_use]
pub fn check_restricted_fields(value: &Value) -> Option<&'static str> {
    if let Some(obj) = value.as_object() {
        for field in RESTRICTED_SETTINGS_FIELDS {
            if obj.contains_key(*field) {
                return Some(field);
            }
        }
    }
    None
}

/// Request to update tenant settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    /// Settings to merge with existing settings.
    /// Keys are merged at the top level.
    #[schema(value_type = Object)]
    pub settings: Value,
}

impl UpdateSettingsRequest {
    /// Validate the request.
    #[must_use]
    pub fn validate(&self) -> Option<String> {
        // Settings must be an object
        if !self.settings.is_object() {
            return Some("settings must be a JSON object".to_string());
        }

        // Validate limits if present
        if let Some(limits) = self.settings.get("limits") {
            if !limits.is_object() {
                return Some("limits must be a JSON object".to_string());
            }

            // Check that limit values are positive integers or null
            if let Some(obj) = limits.as_object() {
                for (key, value) in obj {
                    if !value.is_null() && !value.is_i64() && !value.is_u64() {
                        return Some(format!("limits.{key} must be a positive integer or null"));
                    }
                    if let Some(v) = value.as_i64() {
                        if v < 0 {
                            return Some(format!("limits.{key} must be a positive integer"));
                        }
                    }
                }
            }
        }

        None
    }
}

/// Response after updating tenant settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateSettingsResponse {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Full settings after update.
    #[schema(value_type = Object)]
    pub settings: Value,

    /// When the settings were updated.
    pub updated_at: DateTime<Utc>,
}

/// Response for getting tenant settings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetSettingsResponse {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Current tenant settings.
    #[schema(value_type = Object)]
    pub settings: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_valid_settings() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "limits": {
                    "max_mau": 1000,
                    "max_api_calls": 500000
                }
            }),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_validate_null_limits() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "limits": {
                    "max_mau": null
                }
            }),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_validate_empty_object() {
        let request = UpdateSettingsRequest {
            settings: json!({}),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_validate_non_object() {
        let request = UpdateSettingsRequest {
            settings: json!("string"),
        };
        assert_eq!(
            request.validate(),
            Some("settings must be a JSON object".to_string())
        );
    }

    #[test]
    fn test_validate_limits_not_object() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "limits": "not an object"
            }),
        };
        assert_eq!(
            request.validate(),
            Some("limits must be a JSON object".to_string())
        );
    }

    #[test]
    fn test_validate_negative_limit() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "limits": {
                    "max_mau": -100
                }
            }),
        };
        assert_eq!(
            request.validate(),
            Some("limits.max_mau must be a positive integer".to_string())
        );
    }

    #[test]
    fn test_validate_string_limit() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "limits": {
                    "max_mau": "not a number"
                }
            }),
        };
        assert_eq!(
            request.validate(),
            Some("limits.max_mau must be a positive integer or null".to_string())
        );
    }

    #[test]
    fn test_validate_features_object() {
        let request = UpdateSettingsRequest {
            settings: json!({
                "features": {
                    "mfa_required": true,
                    "sso_enabled": false
                }
            }),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_update_response_serialization() {
        let response = UpdateSettingsResponse {
            tenant_id: Uuid::new_v4(),
            settings: json!({
                "limits": {"max_mau": 1000}
            }),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("settings"));
        assert!(json.contains("updated_at"));
    }

    #[test]
    fn test_get_response_serialization() {
        let response = GetSettingsResponse {
            tenant_id: Uuid::new_v4(),
            settings: json!({
                "limits": {"max_mau": 500}
            }),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("settings"));
        assert!(json.contains("max_mau"));
    }

    // ========================================================================
    // F-056: TenantUserUpdateSettingsRequest Tests
    // ========================================================================

    #[test]
    fn test_f056_tenant_user_update_display_name_valid() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: Some("My Company".to_string()),
            logo_url: None,
            custom_attributes: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_f056_tenant_user_update_display_name_empty() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: Some("".to_string()),
            logo_url: None,
            custom_attributes: None,
        };
        let result = request.validate();
        assert!(result.is_some());
        let (field, msg) = result.unwrap();
        assert_eq!(field, "display_name");
        assert!(msg.contains("cannot be empty"));
    }

    #[test]
    fn test_f056_tenant_user_update_display_name_too_long() {
        let long_name = "a".repeat(101);
        let request = TenantUserUpdateSettingsRequest {
            display_name: Some(long_name),
            logo_url: None,
            custom_attributes: None,
        };
        let result = request.validate();
        assert!(result.is_some());
        let (field, msg) = result.unwrap();
        assert_eq!(field, "display_name");
        assert!(msg.contains("cannot exceed 100 characters"));
    }

    #[test]
    fn test_f056_tenant_user_update_logo_url_valid() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: Some(Some("https://example.com/logo.png".to_string())),
            custom_attributes: None,
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_f056_tenant_user_update_logo_url_null_clears() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: Some(None),
            custom_attributes: None,
        };
        assert!(request.validate().is_none());

        // Verify it produces null in the settings value
        let value = request.to_settings_value();
        assert!(value.get("logo_url").unwrap().is_null());
    }

    #[test]
    fn test_f056_tenant_user_update_logo_url_invalid() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: Some(Some("not-a-valid-url".to_string())),
            custom_attributes: None,
        };
        let result = request.validate();
        assert!(result.is_some());
        let (field, msg) = result.unwrap();
        assert_eq!(field, "logo_url");
        assert!(msg.contains("Invalid URL format"));
    }

    #[test]
    fn test_f056_tenant_user_update_custom_attributes_valid() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: None,
            custom_attributes: Some(json!({
                "industry": "technology",
                "region": "eu-west"
            })),
        };
        assert!(request.validate().is_none());
    }

    #[test]
    fn test_f056_tenant_user_update_custom_attributes_too_many_keys() {
        let mut attrs = serde_json::Map::new();
        for i in 0..11 {
            attrs.insert(format!("key{i}"), json!("value"));
        }
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: None,
            custom_attributes: Some(Value::Object(attrs)),
        };
        let result = request.validate();
        assert!(result.is_some());
        let (field, msg) = result.unwrap();
        assert_eq!(field, "custom_attributes");
        assert!(msg.contains("cannot have more than 10 keys"));
    }

    #[test]
    fn test_f056_tenant_user_update_no_fields_provided() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: None,
            logo_url: None,
            custom_attributes: None,
        };
        let result = request.validate();
        assert!(result.is_some());
        let (field, msg) = result.unwrap();
        assert_eq!(field, "request");
        assert!(msg.contains("At least one field must be provided"));
    }

    #[test]
    fn test_f056_tenant_user_update_to_settings_value() {
        let request = TenantUserUpdateSettingsRequest {
            display_name: Some("New Name".to_string()),
            logo_url: Some(Some("https://example.com/logo.png".to_string())),
            custom_attributes: Some(json!({"key": "value"})),
        };
        let value = request.to_settings_value();

        assert_eq!(value.get("display_name").unwrap(), "New Name");
        assert_eq!(
            value.get("logo_url").unwrap(),
            "https://example.com/logo.png"
        );
        assert_eq!(value.get("custom_attributes").unwrap()["key"], "value");
    }

    #[test]
    fn test_f056_check_restricted_fields_plan_tier() {
        let value = json!({
            "plan_tier": "enterprise"
        });
        let result = check_restricted_fields(&value);
        assert_eq!(result, Some("plan_tier"));
    }

    #[test]
    fn test_f056_check_restricted_fields_limits() {
        let value = json!({
            "limits": {"max_mau": 10000}
        });
        let result = check_restricted_fields(&value);
        assert_eq!(result, Some("limits"));
    }

    #[test]
    fn test_f056_check_restricted_fields_security_settings() {
        let value = json!({
            "security_settings": {"mfa_required": true}
        });
        let result = check_restricted_fields(&value);
        assert_eq!(result, Some("security_settings"));
    }

    #[test]
    fn test_f056_check_restricted_fields_none() {
        let value = json!({
            "display_name": "My Company",
            "logo_url": "https://example.com/logo.png"
        });
        let result = check_restricted_fields(&value);
        assert!(result.is_none());
    }
}
