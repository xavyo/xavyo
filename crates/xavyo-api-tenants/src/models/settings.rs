//! Request and response models for tenant settings API.
//!
//! F-SETTINGS-API: Allows system admins to update tenant settings.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

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
                        return Some(format!("limits.{} must be a positive integer or null", key));
                    }
                    if let Some(v) = value.as_i64() {
                        if v < 0 {
                            return Some(format!("limits.{} must be a positive integer", key));
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
}
