//! Claims mapping service for transforming `IdP` claims to Xavyo attributes.

use crate::error::{FederationError, FederationResult};
use crate::models::ClaimMappingConfig;
use crate::services::auth_flow::IdTokenClaims;
use serde_json::Value;
use std::collections::HashMap;
use tracing::instrument;
use xavyo_db::models::TenantIdentityProvider;

/// Claims mapping service.
#[derive(Clone, Default)]
pub struct ClaimsService;

impl ClaimsService {
    /// Create a new claims service.
    #[must_use] 
    pub fn new() -> Self {
        Self
    }

    /// Map `IdP` claims to Xavyo attributes based on `IdP` configuration.
    #[instrument(skip(self, claims))]
    pub fn map_claims(
        &self,
        idp: &TenantIdentityProvider,
        claims: &IdTokenClaims,
    ) -> FederationResult<HashMap<String, Value>> {
        // Parse claim mapping from IdP config
        let mapping: ClaimMappingConfig =
            serde_json::from_value(idp.claim_mapping.clone()).unwrap_or_default();

        // Build claims map from IdTokenClaims
        let mut source_claims = claims.additional.clone();
        source_claims.insert("sub".to_string(), Value::String(claims.sub.clone()));
        source_claims.insert("iss".to_string(), Value::String(claims.iss.clone()));
        if let Some(email) = &claims.email {
            source_claims.insert("email".to_string(), Value::String(email.clone()));
        }
        if let Some(name) = &claims.name {
            source_claims.insert("name".to_string(), Value::String(name.clone()));
        }
        if let Some(given_name) = &claims.given_name {
            source_claims.insert("given_name".to_string(), Value::String(given_name.clone()));
        }
        if let Some(family_name) = &claims.family_name {
            source_claims.insert(
                "family_name".to_string(),
                Value::String(family_name.clone()),
            );
        }
        if let Some(picture) = &claims.picture {
            source_claims.insert("picture".to_string(), Value::String(picture.clone()));
        }

        // Apply mapping
        let mut result = HashMap::new();

        for entry in &mapping.mappings {
            let source_value = source_claims.get(&entry.source);

            if let Some(value) = source_value {
                // Apply transform if specified
                let transformed = self.apply_transform(value, entry.transform.as_deref())?;

                // Apply group mapping if specified
                let final_value = if let Some(group_map) = &entry.group_mapping {
                    self.apply_group_mapping(&transformed, group_map)?
                } else {
                    transformed
                };

                result.insert(entry.target.clone(), final_value);
            } else {
                // Handle missing claim
                if entry.required {
                    return Err(FederationError::MissingRequiredClaim(entry.source.clone()));
                }
                // Use default if provided
                if let Some(default) = &entry.default {
                    result.insert(entry.target.clone(), Value::String(default.clone()));
                }
            }
        }

        Ok(result)
    }

    /// Validate claim mapping configuration.
    pub fn validate_mapping(&self, mapping: &ClaimMappingConfig) -> FederationResult<()> {
        for entry in &mapping.mappings {
            // Validate source is not empty
            if entry.source.is_empty() {
                return Err(FederationError::InvalidClaimMapping(
                    "Source claim cannot be empty".to_string(),
                ));
            }

            // Validate target is not empty
            if entry.target.is_empty() {
                return Err(FederationError::InvalidClaimMapping(
                    "Target claim cannot be empty".to_string(),
                ));
            }

            // Validate transform if specified
            if let Some(transform) = &entry.transform {
                self.validate_transform(transform)?;
            }
        }

        Ok(())
    }

    /// Apply a transform to a claim value.
    fn apply_transform(&self, value: &Value, transform: Option<&str>) -> FederationResult<Value> {
        let Some(transform) = transform else {
            return Ok(value.clone());
        };

        match transform {
            "lowercase" => {
                if let Some(s) = value.as_str() {
                    Ok(Value::String(s.to_lowercase()))
                } else {
                    Ok(value.clone())
                }
            }
            "uppercase" => {
                if let Some(s) = value.as_str() {
                    Ok(Value::String(s.to_uppercase()))
                } else {
                    Ok(value.clone())
                }
            }
            "trim" => {
                if let Some(s) = value.as_str() {
                    Ok(Value::String(s.trim().to_string()))
                } else {
                    Ok(value.clone())
                }
            }
            "first" => {
                // Get first element if array
                if let Some(arr) = value.as_array() {
                    Ok(arr.first().cloned().unwrap_or(Value::Null))
                } else {
                    Ok(value.clone())
                }
            }
            "join" => {
                // Join array with comma
                if let Some(arr) = value.as_array() {
                    let parts: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    Ok(Value::String(parts.join(",")))
                } else {
                    Ok(value.clone())
                }
            }
            "split" => {
                // Split string by comma
                if let Some(s) = value.as_str() {
                    let parts: Vec<Value> = s
                        .split(',')
                        .map(|p| Value::String(p.trim().to_string()))
                        .collect();
                    Ok(Value::Array(parts))
                } else {
                    Ok(value.clone())
                }
            }
            _ => Err(FederationError::InvalidClaimMapping(format!(
                "Unknown transform: {transform}"
            ))),
        }
    }

    /// Validate a transform name.
    fn validate_transform(&self, transform: &str) -> FederationResult<()> {
        let valid_transforms = ["lowercase", "uppercase", "trim", "first", "join", "split"];
        if valid_transforms.contains(&transform) {
            Ok(())
        } else {
            Err(FederationError::InvalidClaimMapping(format!(
                "Invalid transform: {transform}. Valid options: {valid_transforms:?}"
            )))
        }
    }

    /// Apply group-to-role mapping.
    fn apply_group_mapping(
        &self,
        value: &Value,
        group_map: &HashMap<String, String>,
    ) -> FederationResult<Value> {
        // Handle single string value
        if let Some(s) = value.as_str() {
            if let Some(mapped) = group_map.get(s) {
                return Ok(Value::String(mapped.clone()));
            }
            return Ok(value.clone());
        }

        // Handle array of strings (groups)
        if let Some(arr) = value.as_array() {
            let mapped: Vec<Value> = arr
                .iter()
                .filter_map(|v| {
                    v.as_str().map(|s| {
                        if let Some(mapped) = group_map.get(s) {
                            Value::String(mapped.clone())
                        } else {
                            Value::String(s.to_string())
                        }
                    })
                })
                .collect();
            return Ok(Value::Array(mapped));
        }

        Ok(value.clone())
    }

    /// Extract the subject (`NameID`) from claims based on configuration.
    #[must_use] 
    pub fn extract_subject(&self, mapping: &ClaimMappingConfig, claims: &IdTokenClaims) -> String {
        // Check name_id configuration
        if let Some(name_id) = &mapping.name_id {
            // Build claims map
            let mut source_claims: HashMap<&str, &str> = HashMap::new();
            source_claims.insert("sub", &claims.sub);
            if let Some(email) = &claims.email {
                source_claims.insert("email", email);
            }

            // Use configured source
            if let Some(value) = source_claims.get(name_id.source.as_str()) {
                return (*value).to_string();
            }
        }

        // Default to sub
        claims.sub.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ClaimMappingEntry, NameIdConfig};

    fn make_claims() -> IdTokenClaims {
        IdTokenClaims {
            sub: "user123".to_string(),
            iss: "https://idp.example.com".to_string(),
            aud: Value::String("client123".to_string()),
            exp: 0,
            iat: 0,
            nonce: None,
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: Some("John Doe".to_string()),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            picture: None,
            additional: HashMap::new(),
        }
    }

    #[test]
    fn test_map_claims_basic() {
        let service = ClaimsService::new();
        let claims = make_claims();

        let mapping = ClaimMappingConfig {
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
            name_id: None,
        };

        let mut idp = TenantIdentityProvider::default_for_test();
        idp.claim_mapping = serde_json::to_value(&mapping).unwrap();

        let result = service.map_claims(&idp, &claims).unwrap();

        assert_eq!(result.get("email").unwrap(), "user@example.com");
        assert_eq!(result.get("display_name").unwrap(), "John Doe");
    }

    #[test]
    fn test_map_claims_with_default() {
        let service = ClaimsService::new();
        let claims = make_claims();

        let mapping = ClaimMappingConfig {
            mappings: vec![ClaimMappingEntry {
                source: "department".to_string(),
                target: "dept".to_string(),
                required: false,
                default: Some("Unknown".to_string()),
                transform: None,
                group_mapping: None,
            }],
            name_id: None,
        };

        let mut idp = TenantIdentityProvider::default_for_test();
        idp.claim_mapping = serde_json::to_value(&mapping).unwrap();

        let result = service.map_claims(&idp, &claims).unwrap();

        assert_eq!(result.get("dept").unwrap(), "Unknown");
    }

    #[test]
    fn test_map_claims_missing_required() {
        let service = ClaimsService::new();
        let claims = make_claims();

        let mapping = ClaimMappingConfig {
            mappings: vec![ClaimMappingEntry {
                source: "department".to_string(),
                target: "dept".to_string(),
                required: true,
                default: None,
                transform: None,
                group_mapping: None,
            }],
            name_id: None,
        };

        let mut idp = TenantIdentityProvider::default_for_test();
        idp.claim_mapping = serde_json::to_value(&mapping).unwrap();

        let result = service.map_claims(&idp, &claims);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_subject_default() {
        let service = ClaimsService::new();
        let claims = make_claims();
        let mapping = ClaimMappingConfig::default();

        let subject = service.extract_subject(&mapping, &claims);
        assert_eq!(subject, "user123");
    }

    #[test]
    fn test_extract_subject_email() {
        let service = ClaimsService::new();
        let claims = make_claims();
        let mapping = ClaimMappingConfig {
            mappings: vec![],
            name_id: Some(NameIdConfig {
                source: "email".to_string(),
                format: "emailAddress".to_string(),
            }),
        };

        let subject = service.extract_subject(&mapping, &claims);
        assert_eq!(subject, "user@example.com");
    }
}
