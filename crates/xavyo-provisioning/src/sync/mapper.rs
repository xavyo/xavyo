//! Inbound mapping engine for transforming external attributes.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::error::{SyncError, SyncResult};

/// Direction of attribute mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingDirection {
    /// External system to internal (inbound).
    Inbound,
    /// Internal to external system (outbound).
    Outbound,
    /// Both directions.
    Bidirectional,
}

impl MappingDirection {
    /// Convert to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            MappingDirection::Inbound => "inbound",
            MappingDirection::Outbound => "outbound",
            MappingDirection::Bidirectional => "bidirectional",
        }
    }

    /// Check if this direction includes inbound.
    #[must_use]
    pub fn includes_inbound(&self) -> bool {
        matches!(
            self,
            MappingDirection::Inbound | MappingDirection::Bidirectional
        )
    }

    /// Check if this direction includes outbound.
    #[must_use]
    pub fn includes_outbound(&self) -> bool {
        matches!(
            self,
            MappingDirection::Outbound | MappingDirection::Bidirectional
        )
    }
}

impl std::fmt::Display for MappingDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for MappingDirection {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "inbound" => Ok(MappingDirection::Inbound),
            "outbound" => Ok(MappingDirection::Outbound),
            "bidirectional" => Ok(MappingDirection::Bidirectional),
            _ => Err(format!("Unknown mapping direction: {s}")),
        }
    }
}

/// An attribute mapping rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeMapping {
    /// Mapping ID.
    pub id: Uuid,
    /// External attribute name.
    pub external_attribute: String,
    /// Internal attribute name.
    pub internal_attribute: String,
    /// Mapping direction.
    pub direction: MappingDirection,
    /// Optional transformation expression.
    pub transform: Option<String>,
    /// Default value if external attribute is missing.
    pub default_value: Option<serde_json::Value>,
    /// Whether this mapping is required.
    pub required: bool,
}

impl AttributeMapping {
    /// Create a new simple mapping (no transformation).
    pub fn simple(external: impl Into<String>, internal: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            external_attribute: external.into(),
            internal_attribute: internal.into(),
            direction: MappingDirection::Bidirectional,
            transform: None,
            default_value: None,
            required: false,
        }
    }

    /// Create an inbound-only mapping.
    pub fn inbound(external: impl Into<String>, internal: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            external_attribute: external.into(),
            internal_attribute: internal.into(),
            direction: MappingDirection::Inbound,
            transform: None,
            default_value: None,
            required: false,
        }
    }

    /// Set required flag.
    #[must_use]
    pub fn with_required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }

    /// Set default value.
    #[must_use]
    pub fn with_default(mut self, default: serde_json::Value) -> Self {
        self.default_value = Some(default);
        self
    }

    /// Set transformation expression.
    pub fn with_transform(mut self, transform: impl Into<String>) -> Self {
        self.transform = Some(transform.into());
        self
    }
}

/// Result of mapping a set of attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingResult {
    /// Successfully mapped attributes.
    pub attributes: HashMap<String, serde_json::Value>,
    /// Attributes that couldn't be mapped.
    pub unmapped: Vec<String>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
}

impl MappingResult {
    /// Create a new empty result.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
            unmapped: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Check if mapping was successful (no unmapped required attributes).
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.unmapped.is_empty()
    }
}

impl Default for MappingResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Inbound mapper for transforming external attributes.
pub struct InboundMapper {
    /// Mappings by external attribute name.
    mappings: HashMap<String, AttributeMapping>,
}

impl InboundMapper {
    /// Create a new inbound mapper.
    #[must_use]
    pub fn new() -> Self {
        Self {
            mappings: HashMap::new(),
        }
    }

    /// Create from a list of mappings.
    #[must_use]
    pub fn from_mappings(mappings: Vec<AttributeMapping>) -> Self {
        let mut mapper = Self::new();
        for mapping in mappings {
            if mapping.direction.includes_inbound() {
                mapper.add_mapping(mapping);
            }
        }
        mapper
    }

    /// Add a mapping.
    pub fn add_mapping(&mut self, mapping: AttributeMapping) {
        self.mappings
            .insert(mapping.external_attribute.clone(), mapping);
    }

    /// Map external attributes to internal format.
    pub fn map(&self, external_attrs: &serde_json::Value) -> SyncResult<MappingResult> {
        let mut result = MappingResult::new();

        let obj = match external_attrs.as_object() {
            Some(o) => o,
            None => {
                return Err(SyncError::mapping(
                    "",
                    "External attributes must be an object",
                ));
            }
        };

        // Process each mapping
        for (ext_attr, mapping) in &self.mappings {
            if let Some(value) = obj.get(ext_attr) {
                // Apply transformation if present. Unknown transforms fail closed
                // (returning an error) rather than passing the raw value through —
                // silently dropping a transform produces wrong downstream values
                // with `success: true` (see deep review §2.5).
                let transformed = match &mapping.transform {
                    Some(expr) => apply_transforms(expr, ext_attr, value)?,
                    None => value.clone(),
                };

                result
                    .attributes
                    .insert(mapping.internal_attribute.clone(), transformed);
            } else if let Some(ref default) = mapping.default_value {
                // Use default value
                result
                    .attributes
                    .insert(mapping.internal_attribute.clone(), default.clone());
            } else if mapping.required {
                // Required attribute missing
                result.unmapped.push(ext_attr.clone());
            }
        }

        // Track unmapped external attributes
        for key in obj.keys() {
            if !self.mappings.contains_key(key) {
                result
                    .warnings
                    .push(format!("Unmapped external attribute: {key}"));
            }
        }

        Ok(result)
    }

    /// Get the internal attribute name for an external attribute.
    #[must_use]
    pub fn get_internal_name(&self, external: &str) -> Option<&str> {
        self.mappings
            .get(external)
            .map(|m| m.internal_attribute.as_str())
    }

    /// Get the number of mappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Check if there are no mappings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

impl Default for InboundMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply a `|`-separated chain of named string transforms to a JSON value.
///
/// Transforms operate on string values and are applied left to right
/// (`"lowercase|trim"` lowercases, then trims). Whitespace around each name and
/// empty steps (from a stray `|`) are tolerated. An unknown transform name or a
/// non-string input fails closed (returns `Err`) so a misconfigured transform
/// can never silently emit a wrong downstream value.
fn apply_transforms(
    expr: &str,
    attribute: &str,
    value: &serde_json::Value,
) -> SyncResult<serde_json::Value> {
    let mut current = value.as_str().map(str::to_owned).ok_or_else(|| {
        SyncError::mapping(
            attribute,
            format!("transform '{expr}' on attribute '{attribute}' requires a string value"),
        )
    })?;

    for step in expr.split('|') {
        let name = step.trim();
        if name.is_empty() {
            continue;
        }
        current = match name {
            "lowercase" => current.to_lowercase(),
            "uppercase" => current.to_uppercase(),
            "trim" => current.trim().to_owned(),
            other => {
                return Err(SyncError::mapping(
                    attribute,
                    format!(
                        "transform '{other}' on attribute '{attribute}' is not implemented; \
                         supported transforms: lowercase, uppercase, trim"
                    ),
                ));
            }
        };
    }

    Ok(serde_json::Value::String(current))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_direction_roundtrip() {
        for dir in [
            MappingDirection::Inbound,
            MappingDirection::Outbound,
            MappingDirection::Bidirectional,
        ] {
            let s = dir.as_str();
            let parsed: MappingDirection = s.parse().unwrap();
            assert_eq!(dir, parsed);
        }
    }

    #[test]
    fn test_direction_includes() {
        assert!(MappingDirection::Inbound.includes_inbound());
        assert!(!MappingDirection::Inbound.includes_outbound());
        assert!(!MappingDirection::Outbound.includes_inbound());
        assert!(MappingDirection::Outbound.includes_outbound());
        assert!(MappingDirection::Bidirectional.includes_inbound());
        assert!(MappingDirection::Bidirectional.includes_outbound());
    }

    #[test]
    fn test_simple_mapping() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("sAMAccountName", "username"));
        mapper.add_mapping(AttributeMapping::simple("mail", "email"));

        let external = serde_json::json!({
            "sAMAccountName": "jdoe",
            "mail": "john.doe@example.com"
        });

        let result = mapper.map(&external).unwrap();
        assert!(result.is_success());
        assert_eq!(
            result.attributes.get("username"),
            Some(&serde_json::json!("jdoe"))
        );
        assert_eq!(
            result.attributes.get("email"),
            Some(&serde_json::json!("john.doe@example.com"))
        );
    }

    #[test]
    fn test_mapping_with_default() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(
            AttributeMapping::simple("status", "active").with_default(serde_json::json!(true)),
        );

        let external = serde_json::json!({});
        let result = mapper.map(&external).unwrap();

        assert_eq!(
            result.attributes.get("active"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn test_required_mapping_missing() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("email", "email").with_required(true));

        let external = serde_json::json!({});
        let result = mapper.map(&external).unwrap();

        assert!(!result.is_success());
        assert!(result.unmapped.contains(&"email".to_string()));
    }

    #[test]
    fn test_unmapped_external_attributes() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("cn", "name"));

        let external = serde_json::json!({
            "cn": "John",
            "unknownAttr": "value"
        });

        let result = mapper.map(&external).unwrap();
        assert!(result.warnings.iter().any(|w| w.contains("unknownAttr")));
    }

    #[test]
    fn test_from_mappings() {
        let mappings = vec![
            AttributeMapping::inbound("ext1", "int1"),
            AttributeMapping {
                id: Uuid::new_v4(),
                external_attribute: "ext2".to_string(),
                internal_attribute: "int2".to_string(),
                direction: MappingDirection::Outbound, // Should be excluded
                transform: None,
                default_value: None,
                required: false,
            },
        ];

        let mapper = InboundMapper::from_mappings(mappings);
        assert_eq!(mapper.len(), 1);
        assert!(mapper.get_internal_name("ext1").is_some());
        assert!(mapper.get_internal_name("ext2").is_none());
    }

    #[test]
    fn test_mapping_with_transform_lowercase_trim() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(
            AttributeMapping::simple("email", "email").with_transform("lowercase|trim"),
        );

        let external = serde_json::json!({
            "email": "  JOHN.DOE@EXAMPLE.COM  "
        });

        let result = mapper.map(&external).unwrap();
        assert!(result.is_success());
        // lowercase then trim, applied left to right.
        assert_eq!(
            result.attributes.get("email").and_then(|v| v.as_str()),
            Some("john.doe@example.com")
        );
    }

    #[test]
    fn test_unknown_transform_fails_closed() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("email", "email").with_transform("rot13"));

        let external = serde_json::json!({ "email": "user@example.com" });

        let err = mapper.map(&external).unwrap_err();
        assert!(
            err.to_string().contains("not implemented"),
            "unknown transform must fail closed, got: {err}"
        );
    }

    #[test]
    fn test_transform_on_non_string_fails_closed() {
        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("age", "age").with_transform("trim"));

        let external = serde_json::json!({ "age": 42 });

        let err = mapper.map(&external).unwrap_err();
        assert!(
            err.to_string().contains("requires a string value"),
            "string transform on a non-string must fail closed, got: {err}"
        );
    }

    #[test]
    fn test_mapping_empty_and_len() {
        let mapper = InboundMapper::new();
        assert!(mapper.is_empty());
        assert_eq!(mapper.len(), 0);

        let mut mapper = InboundMapper::new();
        mapper.add_mapping(AttributeMapping::simple("a", "b"));
        assert!(!mapper.is_empty());
        assert_eq!(mapper.len(), 1);
    }

    #[test]
    fn test_mapping_result_default() {
        let result = MappingResult::default();
        assert!(result.is_success());
        assert!(result.attributes.is_empty());
        assert!(result.unmapped.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_mapping_direction_display() {
        assert_eq!(format!("{}", MappingDirection::Inbound), "inbound");
        assert_eq!(format!("{}", MappingDirection::Outbound), "outbound");
        assert_eq!(
            format!("{}", MappingDirection::Bidirectional),
            "bidirectional"
        );
    }

    #[test]
    fn test_mapping_direction_invalid() {
        let result: Result<MappingDirection, _> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_external_attributes() {
        let mapper = InboundMapper::new();
        let invalid = serde_json::json!("not an object");
        let result = mapper.map(&invalid);
        assert!(result.is_err());
    }
}
