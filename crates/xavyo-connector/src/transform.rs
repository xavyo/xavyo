//! Attribute Transformation Engine.
//!
//! Evaluates attribute mappings and transformations for provisioning.

use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;

use crate::mapping::{
    AttributeSource, MappingConfiguration, MappingResult, MappingRule, Transform,
};

/// Transformation engine for evaluating attribute mappings.
pub struct TransformEngine;

impl TransformEngine {
    /// Create a new transformation engine.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a complete mapping configuration against input attributes.
    #[must_use]
    pub fn evaluate(
        &self,
        config: &MappingConfiguration,
        source_attributes: &HashMap<String, String>,
        is_create: bool,
    ) -> MappingResult {
        let mut result = MappingResult::new();

        for rule in &config.attribute_mappings {
            // Skip based on operation type
            if is_create && !rule.on_create {
                continue;
            }
            if !is_create && !rule.on_update {
                continue;
            }

            match self.evaluate_rule(rule, source_attributes) {
                Ok(Some(value)) => {
                    result.add(rule.target_attribute.clone(), value);
                }
                Ok(None) => {
                    if rule.required {
                        result.add_error(
                            rule.target_attribute.clone(),
                            "Required attribute has no value".to_string(),
                            true,
                        );
                    }
                }
                Err(e) => {
                    result.add_error(rule.target_attribute.clone(), e, rule.required);
                }
            }
        }

        result
    }

    /// Evaluate a single mapping rule.
    pub fn evaluate_rule(
        &self,
        rule: &MappingRule,
        source_attributes: &HashMap<String, String>,
    ) -> Result<Option<String>, String> {
        // Get the source value
        let value = self.evaluate_source(&rule.source, source_attributes)?;

        // If no value and no transform, return None
        let Some(value) = value else {
            return Ok(None);
        };

        // Apply transform if present
        if let Some(transform) = &rule.transform {
            let transformed = self.apply_transform(transform, &value)?;
            if transformed.is_empty() {
                return Ok(None);
            }
            return Ok(Some(transformed));
        }

        if value.is_empty() {
            return Ok(None);
        }

        Ok(Some(value))
    }

    /// Evaluate an attribute source.
    pub fn evaluate_source(
        &self,
        source: &AttributeSource,
        attributes: &HashMap<String, String>,
    ) -> Result<Option<String>, String> {
        match source {
            AttributeSource::Attribute { name } => Ok(attributes.get(name).cloned()),
            AttributeSource::Constant { value } => Ok(Some(value.clone())),
            AttributeSource::Concat { sources, separator } => {
                let mut parts = Vec::new();
                for src in sources {
                    if let Some(value) = self.evaluate_source(src, attributes)? {
                        if !value.is_empty() {
                            parts.push(value);
                        }
                    }
                }
                if parts.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(parts.join(separator)))
                }
            }
            AttributeSource::Expression { expression } => {
                self.evaluate_expression(expression, attributes)
            }
            AttributeSource::Uuid => Ok(Some(Uuid::new_v4().to_string())),
            AttributeSource::Timestamp => Ok(Some(Utc::now().format("%Y%m%d%H%M%SZ").to_string())),
        }
    }

    /// Evaluate a simple expression.
    ///
    /// Supports `${attribute}` syntax for attribute substitution.
    /// Dotted keys like `${custom_attributes.department}` are supported
    /// for accessing flattened nested attributes.
    fn evaluate_expression(
        &self,
        expression: &str,
        attributes: &HashMap<String, String>,
    ) -> Result<Option<String>, String> {
        let mut result = expression.to_string();
        let mut has_value = false;

        // Find all ${...} patterns (supports dotted keys like custom_attributes.department)
        let re = Regex::new(r"\$\{([\w.]+)\}").map_err(|e| e.to_string())?;

        for cap in re.captures_iter(expression) {
            let full_match = &cap[0];
            let attr_name = &cap[1];

            if let Some(value) = attributes.get(attr_name) {
                result = result.replace(full_match, value);
                has_value = true;
            } else {
                result = result.replace(full_match, "");
            }
        }

        if has_value || !result.contains('$') {
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// Apply a transformation to a value.
    pub fn apply_transform(&self, transform: &Transform, value: &str) -> Result<String, String> {
        match transform {
            Transform::Lowercase => Ok(value.to_lowercase()),
            Transform::Uppercase => Ok(value.to_uppercase()),
            Transform::Trim => Ok(value.trim().to_string()),
            Transform::Replace { from, to } => Ok(value.replace(from, to)),
            Transform::Substring { start, end } => {
                let chars: Vec<char> = value.chars().collect();
                let start = (*start).min(chars.len());
                let end = end.map(|e| e.min(chars.len())).unwrap_or(chars.len());
                Ok(chars[start..end].iter().collect())
            }
            Transform::Regex { pattern, group } => {
                let re = Regex::new(pattern).map_err(|e| format!("Invalid regex: {e}"))?;
                if let Some(caps) = re.captures(value) {
                    if *group == 0 {
                        Ok(caps.get(0).map_or("", |m| m.as_str()).to_string())
                    } else {
                        Ok(caps.get(*group).map_or("", |m| m.as_str()).to_string())
                    }
                } else {
                    Ok(String::new())
                }
            }
            Transform::Default { value: default } => {
                if value.is_empty() {
                    Ok(default.clone())
                } else {
                    Ok(value.to_string())
                }
            }
            Transform::EmailFormat { domain } => {
                if value.contains('@') {
                    Ok(value.to_string())
                } else {
                    Ok(format!("{value}{domain}"))
                }
            }
            Transform::DnFormat { template } => Ok(template.replace("{value}", value)),
            Transform::Chain { transforms } => {
                let mut current = value.to_string();
                for t in transforms {
                    current = self.apply_transform(t, &current)?;
                }
                Ok(current)
            }
        }
    }
}

impl Default for TransformEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeprovisionAction;

    fn create_attributes() -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        attrs.insert("firstName".to_string(), "John".to_string());
        attrs.insert("lastName".to_string(), "Doe".to_string());
        attrs.insert("email".to_string(), "JOHN.DOE@EXAMPLE.COM".to_string());
        attrs.insert("username".to_string(), "johndoe".to_string());
        attrs
    }

    #[test]
    fn test_transform_lowercase() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(&Transform::Lowercase, "HELLO WORLD")
            .unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn test_transform_uppercase() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(&Transform::Uppercase, "hello world")
            .unwrap();
        assert_eq!(result, "HELLO WORLD");
    }

    #[test]
    fn test_transform_trim() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(&Transform::Trim, "  hello  ")
            .unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_transform_replace() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(
                &Transform::Replace {
                    from: " ".to_string(),
                    to: "_".to_string(),
                },
                "hello world",
            )
            .unwrap();
        assert_eq!(result, "hello_world");
    }

    #[test]
    fn test_transform_substring() {
        let engine = TransformEngine::new();

        // With end
        let result = engine
            .apply_transform(
                &Transform::Substring {
                    start: 0,
                    end: Some(5),
                },
                "hello world",
            )
            .unwrap();
        assert_eq!(result, "hello");

        // Without end
        let result = engine
            .apply_transform(
                &Transform::Substring {
                    start: 6,
                    end: None,
                },
                "hello world",
            )
            .unwrap();
        assert_eq!(result, "world");
    }

    #[test]
    fn test_transform_regex() {
        let engine = TransformEngine::new();

        // Extract domain from email
        let result = engine
            .apply_transform(
                &Transform::Regex {
                    pattern: r"@(.+)$".to_string(),
                    group: 1,
                },
                "john@example.com",
            )
            .unwrap();
        assert_eq!(result, "example.com");

        // Full match
        let result = engine
            .apply_transform(
                &Transform::Regex {
                    pattern: r"^\d+".to_string(),
                    group: 0,
                },
                "123abc456",
            )
            .unwrap();
        assert_eq!(result, "123");
    }

    #[test]
    fn test_transform_default() {
        let engine = TransformEngine::new();

        // Empty value uses default
        let result = engine
            .apply_transform(
                &Transform::Default {
                    value: "unknown".to_string(),
                },
                "",
            )
            .unwrap();
        assert_eq!(result, "unknown");

        // Non-empty value preserved
        let result = engine
            .apply_transform(
                &Transform::Default {
                    value: "unknown".to_string(),
                },
                "actual",
            )
            .unwrap();
        assert_eq!(result, "actual");
    }

    #[test]
    fn test_transform_email_format() {
        let engine = TransformEngine::new();

        // Add domain
        let result = engine
            .apply_transform(
                &Transform::EmailFormat {
                    domain: "@example.com".to_string(),
                },
                "johndoe",
            )
            .unwrap();
        assert_eq!(result, "johndoe@example.com");

        // Already has domain
        let result = engine
            .apply_transform(
                &Transform::EmailFormat {
                    domain: "@example.com".to_string(),
                },
                "john@other.com",
            )
            .unwrap();
        assert_eq!(result, "john@other.com");
    }

    #[test]
    fn test_transform_dn_format() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(
                &Transform::DnFormat {
                    template: "uid={value},ou=users,dc=example,dc=com".to_string(),
                },
                "johndoe",
            )
            .unwrap();
        assert_eq!(result, "uid=johndoe,ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_transform_chain() {
        let engine = TransformEngine::new();
        let result = engine
            .apply_transform(
                &Transform::Chain {
                    transforms: vec![
                        Transform::Trim,
                        Transform::Lowercase,
                        Transform::Replace {
                            from: " ".to_string(),
                            to: ".".to_string(),
                        },
                    ],
                },
                "  John DOE  ",
            )
            .unwrap();
        assert_eq!(result, "john.doe");
    }

    #[test]
    fn test_evaluate_source_attribute() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

        let source = AttributeSource::Attribute {
            name: "firstName".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("John".to_string()));
    }

    #[test]
    fn test_evaluate_source_constant() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

        let source = AttributeSource::Constant {
            value: "active".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("active".to_string()));
    }

    #[test]
    fn test_evaluate_source_concat() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

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
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("John Doe".to_string()));
    }

    #[test]
    fn test_evaluate_source_uuid() {
        let engine = TransformEngine::new();
        let attrs = HashMap::new();

        let source = AttributeSource::Uuid;
        let result = engine.evaluate_source(&source, &attrs).unwrap().unwrap();

        // Should be a valid UUID
        assert!(Uuid::parse_str(&result).is_ok());
    }

    #[test]
    fn test_evaluate_source_expression() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

        let source = AttributeSource::Expression {
            expression: "User: ${firstName} ${lastName}".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("User: John Doe".to_string()));
    }

    #[test]
    fn test_evaluate_rule() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

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

        let result = engine.evaluate_rule(&rule, &attrs).unwrap();
        assert_eq!(result, Some("john.doe@example.com".to_string()));
    }

    #[test]
    fn test_evaluate_full_configuration() {
        let engine = TransformEngine::new();
        let attrs = create_attributes();

        let config = MappingConfiguration {
            object_class: "inetOrgPerson".to_string(),
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
                MappingRule {
                    target_attribute: "uid".to_string(),
                    source: AttributeSource::Attribute {
                        name: "username".to_string(),
                    },
                    transform: None,
                    required: true,
                    on_create: true,
                    on_update: false, // Not on updates
                },
            ],
            correlation_rules: vec![],
            deprovision_action: DeprovisionAction::Disable,
        };

        // Create operation
        let result = engine.evaluate(&config, &attrs, true);
        assert!(!result.has_fatal_errors());
        assert_eq!(
            result.attributes.get("mail"),
            Some(&"john.doe@example.com".to_string())
        );
        assert_eq!(result.attributes.get("cn"), Some(&"John Doe".to_string()));
        assert_eq!(result.attributes.get("uid"), Some(&"johndoe".to_string()));

        // Update operation (uid should be excluded)
        let result = engine.evaluate(&config, &attrs, false);
        assert!(!result.has_fatal_errors());
        assert_eq!(
            result.attributes.get("mail"),
            Some(&"john.doe@example.com".to_string())
        );
        assert_eq!(result.attributes.get("cn"), Some(&"John Doe".to_string()));
        assert!(!result.attributes.contains_key("uid"));
    }

    #[test]
    fn test_evaluate_expression_dotted_keys() {
        let engine = TransformEngine::new();
        let mut attrs = create_attributes();
        // Simulate flattened custom_attributes
        attrs.insert(
            "custom_attributes.department".to_string(),
            "Engineering".to_string(),
        );
        attrs.insert(
            "custom_attributes.cost_center".to_string(),
            "CC-100".to_string(),
        );

        let source = AttributeSource::Expression {
            expression: "${firstName} from ${custom_attributes.department}".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("John from Engineering".to_string()));
    }

    #[test]
    fn test_evaluate_expression_dotted_key_only() {
        let engine = TransformEngine::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "custom_attributes.cost_center".to_string(),
            "CC-200".to_string(),
        );

        let source = AttributeSource::Expression {
            expression: "${custom_attributes.cost_center}".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("CC-200".to_string()));
    }

    #[test]
    fn test_evaluate_source_dotted_attribute_name() {
        let engine = TransformEngine::new();
        let mut attrs = HashMap::new();
        attrs.insert(
            "custom_attributes.employee_id".to_string(),
            "E12345".to_string(),
        );

        let source = AttributeSource::Attribute {
            name: "custom_attributes.employee_id".to_string(),
        };
        let result = engine.evaluate_source(&source, &attrs).unwrap();
        assert_eq!(result, Some("E12345".to_string()));
    }

    #[test]
    fn test_evaluate_missing_required() {
        let engine = TransformEngine::new();
        let attrs = HashMap::new(); // Empty attributes

        let config = MappingConfiguration {
            object_class: "user".to_string(),
            attribute_mappings: vec![MappingRule {
                target_attribute: "mail".to_string(),
                source: AttributeSource::Attribute {
                    name: "email".to_string(),
                },
                transform: None,
                required: true,
                on_create: true,
                on_update: true,
            }],
            correlation_rules: vec![],
            deprovision_action: DeprovisionAction::Disable,
        };

        let result = engine.evaluate(&config, &attrs, true);
        assert!(result.has_fatal_errors());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].target_attribute, "mail");
        assert!(result.errors[0].fatal);
    }
}
