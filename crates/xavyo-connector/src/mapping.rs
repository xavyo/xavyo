//! Attribute Mapping types for provisioning.
//!
//! Defines how attributes are mapped between xavyo and target systems.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::DeprovisionAction;

/// A mapping configuration for a connector.
///
/// Defines how xavyo attributes map to target system attributes
/// for a specific object class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConfiguration {
    /// The object class this mapping applies to (e.g., "user", "group").
    pub object_class: String,

    /// Individual attribute mappings.
    pub attribute_mappings: Vec<MappingRule>,

    /// Correlation rules for finding existing accounts.
    pub correlation_rules: Vec<CorrelationRule>,

    /// Action to take when deprovisioning.
    #[serde(default)]
    pub deprovision_action: DeprovisionAction,
}

/// A single attribute mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingRule {
    /// Target attribute name in the target system.
    pub target_attribute: String,

    /// Source of the value for this attribute.
    pub source: AttributeSource,

    /// Optional transformation to apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<Transform>,

    /// Whether this mapping is required (fail if source is empty).
    #[serde(default)]
    pub required: bool,

    /// Whether to include this mapping in create operations.
    #[serde(default = "default_true")]
    pub on_create: bool,

    /// Whether to include this mapping in update operations.
    #[serde(default = "default_true")]
    pub on_update: bool,
}

fn default_true() -> bool {
    true
}

/// Source of an attribute value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AttributeSource {
    /// Value from a xavyo user attribute.
    Attribute {
        /// Name of the attribute in xavyo.
        name: String,
    },
    /// A constant value.
    Constant {
        /// The constant value.
        value: String,
    },
    /// Multiple attributes concatenated.
    Concat {
        /// List of attribute sources to concatenate.
        sources: Vec<AttributeSource>,
        /// Separator between values (default: empty).
        #[serde(default)]
        separator: String,
    },
    /// Expression-based value (for complex mappings).
    Expression {
        /// Expression string (simple template syntax).
        expression: String,
    },
    /// UUID generator.
    Uuid,
    /// Current timestamp.
    Timestamp,
}

/// Transformation to apply to an attribute value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transform {
    /// Convert to lowercase.
    Lowercase,
    /// Convert to uppercase.
    Uppercase,
    /// Trim whitespace.
    Trim,
    /// Replace occurrences.
    Replace {
        /// Pattern to find.
        from: String,
        /// Replacement value.
        to: String,
    },
    /// Substring extraction.
    Substring {
        /// Start index (0-based).
        start: usize,
        /// Optional end index.
        #[serde(skip_serializing_if = "Option::is_none")]
        end: Option<usize>,
    },
    /// Apply regex and capture group.
    Regex {
        /// Regular expression pattern.
        pattern: String,
        /// Capture group to use (1-based, default: 0 for whole match).
        #[serde(default)]
        group: usize,
    },
    /// Apply a default if value is empty/null.
    Default {
        /// Default value to use.
        value: String,
    },
    /// Format as email (append domain).
    EmailFormat {
        /// Domain to append (e.g., "@example.com").
        domain: String,
    },
    /// Format as DN (Distinguished Name).
    DnFormat {
        /// Template for DN (e.g., "uid={value},ou=users,dc=example,dc=com").
        template: String,
    },
    /// Chain multiple transforms.
    Chain {
        /// Ordered list of transforms to apply.
        transforms: Vec<Transform>,
    },
}

/// Correlation rule for finding existing accounts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Priority of this rule (lower = higher priority).
    #[serde(default)]
    pub priority: i32,

    /// Source attribute in xavyo.
    pub source_attribute: String,

    /// Target attribute in the target system.
    pub target_attribute: String,

    /// Match type for correlation.
    #[serde(default)]
    pub match_type: CorrelationMatchType,

    /// Whether this rule is case-sensitive.
    #[serde(default = "default_true")]
    pub case_sensitive: bool,
}

/// Match type for correlation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationMatchType {
    /// Exact match required.
    #[default]
    Exact,
    /// Prefix match.
    Prefix,
    /// Suffix match.
    Suffix,
    /// Contains match.
    Contains,
    /// Case-insensitive exact match.
    CaseInsensitive,
}

/// Result of evaluating a mapping against input attributes.
#[derive(Debug, Clone, Default)]
pub struct MappingResult {
    /// Successfully mapped attributes.
    pub attributes: HashMap<String, String>,
    /// Errors encountered during mapping.
    pub errors: Vec<MappingError>,
}

/// Error during mapping evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingError {
    /// The target attribute that failed.
    pub target_attribute: String,
    /// Error message.
    pub message: String,
    /// Whether this is a fatal error (required mapping failed).
    pub fatal: bool,
}

impl MappingResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a successful mapping.
    pub fn add(&mut self, target: String, value: String) {
        self.attributes.insert(target, value);
    }

    /// Add an error.
    pub fn add_error(&mut self, target: String, message: String, fatal: bool) {
        self.errors.push(MappingError {
            target_attribute: target,
            message,
            fatal,
        });
    }

    /// Check if there are any fatal errors.
    pub fn has_fatal_errors(&self) -> bool {
        self.errors.iter().any(|e| e.fatal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_rule_serialization() {
        let rule = MappingRule {
            target_attribute: "mail".to_string(),
            source: AttributeSource::Attribute {
                name: "email".to_string(),
            },
            transform: Some(Transform::Lowercase),
            required: true,
            on_create: true,
            on_update: true,
        };

        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"target_attribute\":\"mail\""));
        assert!(json.contains("\"type\":\"lowercase\""));

        let parsed: MappingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target_attribute, "mail");
        assert!(parsed.required);
    }

    #[test]
    fn test_attribute_source_variants() {
        // Constant source
        let source = AttributeSource::Constant {
            value: "active".to_string(),
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"type\":\"constant\""));

        // Concat source
        let source = AttributeSource::Concat {
            sources: vec![
                AttributeSource::Attribute {
                    name: "firstName".to_string(),
                },
                AttributeSource::Attribute {
                    name: "lastName".to_string(),
                },
            ],
            separator: " ".to_string(),
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"type\":\"concat\""));
        assert!(json.contains("\"separator\":\" \""));
    }

    #[test]
    fn test_transform_chain() {
        let transform = Transform::Chain {
            transforms: vec![Transform::Trim, Transform::Lowercase],
        };

        let json = serde_json::to_string(&transform).unwrap();
        assert!(json.contains("\"type\":\"chain\""));
        assert!(json.contains("\"type\":\"trim\""));
        assert!(json.contains("\"type\":\"lowercase\""));
    }

    #[test]
    fn test_correlation_rule() {
        let rule = CorrelationRule {
            priority: 1,
            source_attribute: "email".to_string(),
            target_attribute: "mail".to_string(),
            match_type: CorrelationMatchType::Exact,
            case_sensitive: false,
        };

        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"match_type\":\"exact\""));
        assert!(json.contains("\"case_sensitive\":false"));
    }

    #[test]
    fn test_deprovision_action_default() {
        let action = DeprovisionAction::default();
        assert_eq!(action, DeprovisionAction::Disable);

        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"disable\"");
    }

    #[test]
    fn test_mapping_result() {
        let mut result = MappingResult::new();
        result.add("mail".to_string(), "test@example.com".to_string());
        result.add("cn".to_string(), "Test User".to_string());

        assert_eq!(result.attributes.len(), 2);
        assert!(!result.has_fatal_errors());

        result.add_error(
            "uid".to_string(),
            "Required attribute missing".to_string(),
            true,
        );

        assert!(result.has_fatal_errors());
    }

    #[test]
    fn test_mapping_configuration() {
        let config = MappingConfiguration {
            object_class: "user".to_string(),
            attribute_mappings: vec![
                MappingRule {
                    target_attribute: "mail".to_string(),
                    source: AttributeSource::Attribute {
                        name: "email".to_string(),
                    },
                    transform: Some(Transform::Lowercase),
                    required: true,
                    on_create: true,
                    on_update: true,
                },
                MappingRule {
                    target_attribute: "cn".to_string(),
                    source: AttributeSource::Concat {
                        sources: vec![
                            AttributeSource::Attribute {
                                name: "firstName".to_string(),
                            },
                            AttributeSource::Attribute {
                                name: "lastName".to_string(),
                            },
                        ],
                        separator: " ".to_string(),
                    },
                    transform: None,
                    required: true,
                    on_create: true,
                    on_update: true,
                },
            ],
            correlation_rules: vec![CorrelationRule {
                priority: 1,
                source_attribute: "email".to_string(),
                target_attribute: "mail".to_string(),
                match_type: CorrelationMatchType::CaseInsensitive,
                case_sensitive: false,
            }],
            deprovision_action: DeprovisionAction::Disable,
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"object_class\": \"user\""));

        let parsed: MappingConfiguration = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.attribute_mappings.len(), 2);
        assert_eq!(parsed.correlation_rules.len(), 1);
    }
}
