//! Connector Framework schema types
//!
//! Types for representing target system schemas (object classes, attributes).
//! Includes support for schema discovery, versioning, and diff computation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Schema representing the structure of a target system.
///
/// A schema contains one or more object classes, each with their own
/// attributes and capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    /// The object classes available in this schema.
    pub object_classes: Vec<ObjectClass>,

    /// Schema configuration options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<SchemaConfig>,
}

/// Configuration options for schema handling (IGA best practices).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaConfig {
    /// Whether to use case-insensitive attribute name matching globally.
    /// IGA pattern: caseIgnoreAttributeNames
    #[serde(default)]
    pub case_ignore_attribute_names: bool,

    /// Whether to preserve native naming from the target system.
    /// When true, attribute names match exactly with target system.
    #[serde(default = "default_true")]
    pub preserve_native_naming: bool,

    /// List of attribute names known to be volatile.
    /// These attributes may change unexpectedly on the target system.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volatile_attributes: Vec<String>,

    /// The name of the primary identifier attribute (e.g., "uid" for LDAP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_identifier: Option<String>,

    /// Names of secondary identifier attributes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary_identifiers: Vec<String>,
}

impl Schema {
    /// Create a new empty schema.
    #[must_use]
    pub fn new() -> Self {
        Self {
            object_classes: Vec::new(),
            config: None,
        }
    }

    /// Create a schema with the given object classes.
    #[must_use]
    pub fn with_object_classes(object_classes: Vec<ObjectClass>) -> Self {
        Self {
            object_classes,
            config: None,
        }
    }

    /// Set schema configuration.
    #[must_use]
    pub fn with_config(mut self, config: SchemaConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Get the schema configuration, or defaults if not set.
    #[must_use]
    pub fn config(&self) -> SchemaConfig {
        self.config.clone().unwrap_or_default()
    }

    /// Add an object class to the schema.
    pub fn add_object_class(&mut self, object_class: ObjectClass) {
        self.object_classes.push(object_class);
    }

    /// Find an object class by name.
    #[must_use]
    pub fn get_object_class(&self, name: &str) -> Option<&ObjectClass> {
        self.object_classes.iter().find(|oc| oc.name == name)
    }

    /// Find an object class by name, with case-insensitive matching if configured.
    #[must_use]
    pub fn get_object_class_case_aware(&self, name: &str) -> Option<&ObjectClass> {
        let case_ignore = self
            .config
            .as_ref()
            .is_some_and(|c| c.case_ignore_attribute_names);
        if case_ignore {
            self.object_classes
                .iter()
                .find(|oc| oc.name.eq_ignore_ascii_case(name))
        } else {
            self.get_object_class(name)
        }
    }

    /// Check if an object class exists.
    #[must_use]
    pub fn has_object_class(&self, name: &str) -> bool {
        self.object_classes.iter().any(|oc| oc.name == name)
    }

    /// Check if an object class exists (case-aware matching).
    #[must_use]
    pub fn has_object_class_case_aware(&self, name: &str) -> bool {
        self.get_object_class_case_aware(name).is_some()
    }

    /// Get all volatile attributes across all object classes.
    #[must_use]
    pub fn volatile_attributes(&self) -> Vec<&SchemaAttribute> {
        self.object_classes
            .iter()
            .flat_map(|oc| oc.attributes.iter())
            .filter(|a| a.volatile)
            .collect()
    }

    /// Get all primary identifier attributes across all object classes.
    #[must_use]
    pub fn primary_identifiers(&self) -> Vec<&SchemaAttribute> {
        self.object_classes
            .iter()
            .flat_map(|oc| oc.attributes.iter())
            .filter(|a| a.is_primary_identifier())
            .collect()
    }

    /// Get all object class names.
    #[must_use]
    pub fn object_class_names(&self) -> Vec<&str> {
        self.object_classes
            .iter()
            .map(|oc| oc.name.as_str())
            .collect()
    }
}

impl Default for Schema {
    fn default() -> Self {
        Self::new()
    }
}

/// An object class in a target system schema.
///
/// Object classes define the types of objects that can be managed
/// (e.g., users, groups, accounts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectClass {
    /// Canonical name for this object class (used in xavyo).
    pub name: String,

    /// Native name in the target system (e.g., "inetOrgPerson" for LDAP).
    pub native_name: String,

    /// Optional display name for UI presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Description of this object class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Attributes belonging to this object class.
    pub attributes: Vec<SchemaAttribute>,

    /// Whether this object class supports create operations.
    #[serde(default = "default_true")]
    pub supports_create: bool,

    /// Whether this object class supports update operations.
    #[serde(default = "default_true")]
    pub supports_update: bool,

    /// Whether this object class supports delete operations.
    #[serde(default = "default_true")]
    pub supports_delete: bool,

    /// Auxiliary object classes (for LDAP).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auxiliary_classes: Vec<String>,

    /// Container path for objects of this class (e.g., "ou=users,dc=example,dc=com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,

    /// Parent class names for hierarchy (LDAP: SUP, e.g., ["organizationalPerson", "person", "top"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_classes: Vec<String>,

    /// Type of object class (structural, auxiliary, abstract).
    #[serde(default)]
    pub object_class_type: ObjectClassType,

    /// Attributes inherited from parent classes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_attributes: Vec<SchemaAttribute>,
}

fn default_true() -> bool {
    true
}

impl ObjectClass {
    /// Create a new object class with the given name.
    pub fn new(name: impl Into<String>, native_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            native_name: native_name.into(),
            display_name: None,
            description: None,
            attributes: Vec::new(),
            supports_create: true,
            supports_update: true,
            supports_delete: true,
            auxiliary_classes: Vec::new(),
            container: None,
            parent_classes: Vec::new(),
            object_class_type: ObjectClassType::default(),
            inherited_attributes: Vec::new(),
        }
    }

    /// Set the display name.
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add an attribute to this object class.
    pub fn add_attribute(&mut self, attribute: SchemaAttribute) {
        self.attributes.push(attribute);
    }

    /// Add an attribute using builder pattern.
    #[must_use]
    pub fn with_attribute(mut self, attribute: SchemaAttribute) -> Self {
        self.attributes.push(attribute);
        self
    }

    /// Find an attribute by name.
    #[must_use]
    pub fn get_attribute(&self, name: &str) -> Option<&SchemaAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Find an attribute by name with case-insensitive matching.
    #[must_use]
    pub fn get_attribute_case_insensitive(&self, name: &str) -> Option<&SchemaAttribute> {
        self.attributes
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
    }

    /// Find an attribute by name respecting each attribute's `case_insensitive` flag.
    #[must_use]
    pub fn get_attribute_case_aware(&self, name: &str) -> Option<&SchemaAttribute> {
        self.attributes.iter().find(|a| a.name_matches(name))
    }

    /// Check if an attribute exists.
    #[must_use]
    pub fn has_attribute(&self, name: &str) -> bool {
        self.attributes.iter().any(|a| a.name == name)
    }

    /// Check if an attribute exists (case-insensitive).
    #[must_use]
    pub fn has_attribute_case_insensitive(&self, name: &str) -> bool {
        self.get_attribute_case_insensitive(name).is_some()
    }

    /// Get the primary identifier attribute for this object class.
    #[must_use]
    pub fn primary_identifier(&self) -> Option<&SchemaAttribute> {
        self.attributes.iter().find(|a| a.is_primary_identifier())
    }

    /// Get all identifier attributes (primary and secondary).
    #[must_use]
    pub fn identifiers(&self) -> Vec<&SchemaAttribute> {
        self.attributes
            .iter()
            .filter(|a| a.is_identifier())
            .collect()
    }

    /// Get all volatile attributes.
    #[must_use]
    pub fn volatile_attributes(&self) -> Vec<&SchemaAttribute> {
        self.attributes.iter().filter(|a| a.volatile).collect()
    }

    /// Get all required attributes.
    #[must_use]
    pub fn required_attributes(&self) -> Vec<&SchemaAttribute> {
        self.attributes.iter().filter(|a| a.required).collect()
    }

    /// Get all writable attributes.
    #[must_use]
    pub fn writable_attributes(&self) -> Vec<&SchemaAttribute> {
        self.attributes.iter().filter(|a| a.writable).collect()
    }

    /// Set the container path.
    pub fn with_container(mut self, container: impl Into<String>) -> Self {
        self.container = Some(container.into());
        self
    }

    /// Set parent classes for hierarchy.
    #[must_use]
    pub fn with_parent_classes(mut self, parents: Vec<String>) -> Self {
        self.parent_classes = parents;
        self
    }

    /// Set the object class type.
    #[must_use]
    pub fn with_object_class_type(mut self, class_type: ObjectClassType) -> Self {
        self.object_class_type = class_type;
        self
    }

    /// Add inherited attributes from parent classes.
    #[must_use]
    pub fn with_inherited_attributes(mut self, attrs: Vec<SchemaAttribute>) -> Self {
        self.inherited_attributes = attrs;
        self
    }

    /// Get an attribute by name (including inherited).
    #[must_use]
    pub fn get_attribute_including_inherited(&self, name: &str) -> Option<&SchemaAttribute> {
        self.attributes
            .iter()
            .chain(self.inherited_attributes.iter())
            .find(|a| a.name == name)
    }

    /// Get all attributes (direct + inherited).
    #[must_use]
    pub fn all_attributes(&self) -> Vec<&SchemaAttribute> {
        self.attributes
            .iter()
            .chain(self.inherited_attributes.iter())
            .collect()
    }

    /// Total attribute count (direct + inherited).
    #[must_use]
    pub fn total_attribute_count(&self) -> usize {
        self.attributes.len() + self.inherited_attributes.len()
    }
}

/// Type of object class for LDAP/AD schemas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectClassType {
    /// Structural class - can be instantiated, one per object.
    #[default]
    Structural,
    /// Auxiliary class - can be added to structural class.
    Auxiliary,
    /// Abstract class - cannot be instantiated (e.g., "top").
    Abstract,
}

impl ObjectClassType {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectClassType::Structural => "structural",
            ObjectClassType::Auxiliary => "auxiliary",
            ObjectClassType::Abstract => "abstract",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "structural" => Some(ObjectClassType::Structural),
            "auxiliary" => Some(ObjectClassType::Auxiliary),
            "abstract" => Some(ObjectClassType::Abstract),
            _ => None,
        }
    }
}

impl std::fmt::Display for ObjectClassType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An attribute in an object class schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaAttribute {
    /// Canonical name for this attribute (used in xavyo).
    pub name: String,

    /// Native name in the target system (e.g., "givenName" for LDAP).
    pub native_name: String,

    /// Data type of this attribute.
    pub data_type: AttributeDataType,

    /// Whether this attribute can have multiple values.
    #[serde(default)]
    pub multi_valued: bool,

    /// Whether this attribute is required for create operations.
    #[serde(default)]
    pub required: bool,

    /// Whether this attribute can be read.
    #[serde(default = "default_true")]
    pub readable: bool,

    /// Whether this attribute can be written.
    #[serde(default = "default_true")]
    pub writable: bool,

    /// Whether this attribute is returned by default in search results.
    #[serde(default = "default_true")]
    pub returned_by_default: bool,

    /// Optional display name for UI presentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Description of this attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Possible values for enumerated attributes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_values: Vec<String>,

    /// Minimum length for string attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,

    /// Maximum length for string attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,

    /// Pattern (regex) for validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Identifier type for this attribute (IGA edge case).
    /// Primary identifiers are immutable, secondary can change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier_type: Option<IdentifierType>,

    /// Whether this attribute is volatile (IGA edge case).
    /// Volatile attributes may change unexpectedly on the target system.
    #[serde(default)]
    pub volatile: bool,

    /// Whether this attribute should use case-insensitive matching (IGA edge case).
    /// Common for LDAP attributes like uid, cn, sn.
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Identifier type for attributes (from IGA standards).
///
/// Primary identifiers (like UID in LDAP) are immutable and should never change.
/// Secondary identifiers (like CN) may change during object lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierType {
    /// Primary identifier - immutable, used for correlation.
    Primary,
    /// Secondary identifier - mutable, can change during lifecycle.
    Secondary,
}

impl SchemaAttribute {
    /// Create a new attribute with the given name and type.
    pub fn new(
        name: impl Into<String>,
        native_name: impl Into<String>,
        data_type: AttributeDataType,
    ) -> Self {
        Self {
            name: name.into(),
            native_name: native_name.into(),
            data_type,
            multi_valued: false,
            required: false,
            readable: true,
            writable: true,
            returned_by_default: true,
            display_name: None,
            description: None,
            allowed_values: Vec::new(),
            min_length: None,
            max_length: None,
            pattern: None,
            identifier_type: None,
            volatile: false,
            case_insensitive: false,
        }
    }

    /// Mark this attribute as multi-valued.
    #[must_use]
    pub fn multi_valued(mut self) -> Self {
        self.multi_valued = true;
        self
    }

    /// Mark this attribute as required.
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Mark this attribute as read-only.
    #[must_use]
    pub fn read_only(mut self) -> Self {
        self.writable = false;
        self
    }

    /// Mark this attribute as write-only (e.g., passwords).
    #[must_use]
    pub fn write_only(mut self) -> Self {
        self.readable = false;
        self.returned_by_default = false;
        self
    }

    /// Set the display name.
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set allowed values for enumerated attributes.
    #[must_use]
    pub fn with_allowed_values(mut self, values: Vec<String>) -> Self {
        self.allowed_values = values;
        self
    }

    /// Set string length constraints.
    #[must_use]
    pub fn with_length(mut self, min: Option<usize>, max: Option<usize>) -> Self {
        self.min_length = min;
        self.max_length = max;
        self
    }

    /// Set minimum length constraint only.
    #[must_use]
    pub fn with_min_length(mut self, min: usize) -> Self {
        self.min_length = Some(min);
        self
    }

    /// Set maximum length constraint only.
    #[must_use]
    pub fn with_max_length(mut self, max: usize) -> Self {
        self.max_length = Some(max);
        self
    }

    /// Set validation pattern.
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    /// Mark this attribute as a primary identifier (IGA edge case).
    /// Primary identifiers are immutable and used for correlation.
    #[must_use]
    pub fn as_primary_identifier(mut self) -> Self {
        self.identifier_type = Some(IdentifierType::Primary);
        self
    }

    /// Mark this attribute as a secondary identifier (IGA edge case).
    /// Secondary identifiers may change during object lifecycle.
    #[must_use]
    pub fn as_secondary_identifier(mut self) -> Self {
        self.identifier_type = Some(IdentifierType::Secondary);
        self
    }

    /// Mark this attribute as volatile (IGA edge case).
    /// Volatile attributes may change unexpectedly on the target system.
    #[must_use]
    pub fn volatile(mut self) -> Self {
        self.volatile = true;
        self
    }

    /// Mark this attribute as case-insensitive (IGA edge case).
    /// Common for LDAP attributes like uid, cn, sn.
    #[must_use]
    pub fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self
    }

    /// Check if this attribute is a primary identifier.
    #[must_use]
    pub fn is_primary_identifier(&self) -> bool {
        matches!(self.identifier_type, Some(IdentifierType::Primary))
    }

    /// Check if this attribute is any type of identifier.
    #[must_use]
    pub fn is_identifier(&self) -> bool {
        self.identifier_type.is_some()
    }

    /// Compare attribute name respecting case sensitivity setting.
    #[must_use]
    pub fn name_matches(&self, name: &str) -> bool {
        if self.case_insensitive {
            self.name.eq_ignore_ascii_case(name)
        } else {
            self.name == name
        }
    }

    /// Compare native name respecting case sensitivity setting.
    #[must_use]
    pub fn native_name_matches(&self, name: &str) -> bool {
        if self.case_insensitive {
            self.native_name.eq_ignore_ascii_case(name)
        } else {
            self.native_name == name
        }
    }
}

/// Data type for schema attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum AttributeDataType {
    /// String/text value.
    String,
    /// Integer value.
    Integer,
    /// Long integer value.
    Long,
    /// Boolean value.
    Boolean,
    /// Binary data (bytes).
    Binary,
    /// Date/time value.
    DateTime,
    /// Date value (no time component).
    Date,
    /// Timestamp (Unix epoch milliseconds).
    Timestamp,
    /// UUID/GUID value.
    Uuid,
    /// Distinguished Name (LDAP).
    Dn,
    /// Big integer (arbitrary precision).
    BigInteger,
    /// Decimal/float value.
    Decimal,
    /// JSON object.
    Json,
}

impl AttributeDataType {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AttributeDataType::String => "string",
            AttributeDataType::Integer => "integer",
            AttributeDataType::Long => "long",
            AttributeDataType::Boolean => "boolean",
            AttributeDataType::Binary => "binary",
            AttributeDataType::DateTime => "datetime",
            AttributeDataType::Date => "date",
            AttributeDataType::Timestamp => "timestamp",
            AttributeDataType::Uuid => "uuid",
            AttributeDataType::Dn => "dn",
            AttributeDataType::BigInteger => "biginteger",
            AttributeDataType::Decimal => "decimal",
            AttributeDataType::Json => "json",
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "string" | "varchar" | "text" | "char" => Some(AttributeDataType::String),
            "integer" | "int" | "int4" | "int32" => Some(AttributeDataType::Integer),
            "long" | "bigint" | "int8" | "int64" => Some(AttributeDataType::Long),
            "boolean" | "bool" => Some(AttributeDataType::Boolean),
            "binary" | "bytea" | "blob" | "bytes" => Some(AttributeDataType::Binary),
            "datetime" | "timestamp with time zone" | "timestamptz" => {
                Some(AttributeDataType::DateTime)
            }
            "date" => Some(AttributeDataType::Date),
            "timestamp" | "timestamp without time zone" => Some(AttributeDataType::Timestamp),
            "uuid" | "guid" => Some(AttributeDataType::Uuid),
            "dn" | "distinguishedname" => Some(AttributeDataType::Dn),
            "biginteger" | "numeric" => Some(AttributeDataType::BigInteger),
            "decimal" | "float" | "double" | "real" | "float8" => Some(AttributeDataType::Decimal),
            "json" | "jsonb" => Some(AttributeDataType::Json),
            _ => None,
        }
    }
}

impl std::fmt::Display for AttributeDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Schema Discovery Status Types
// ============================================================================

/// Current state of a schema discovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    /// No discovery in progress.
    #[default]
    Idle,
    /// Discovery is currently running.
    InProgress,
    /// Discovery completed successfully.
    Completed,
    /// Discovery failed.
    Failed,
}

impl DiscoveryState {
    /// Get the string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryState::Idle => "idle",
            DiscoveryState::InProgress => "in_progress",
            DiscoveryState::Completed => "completed",
            DiscoveryState::Failed => "failed",
        }
    }
}

impl std::fmt::Display for DiscoveryState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Status of a schema discovery operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryStatus {
    /// Connector ID.
    pub connector_id: Uuid,
    /// Current state.
    pub state: DiscoveryState,
    /// When discovery started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When discovery completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Progress percentage (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<i32>,
    /// Object class currently being discovered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_object_class: Option<String>,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Schema version number if completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i32>,
}

impl DiscoveryStatus {
    /// Create a new idle status.
    #[must_use]
    pub fn idle(connector_id: Uuid) -> Self {
        Self {
            connector_id,
            state: DiscoveryState::Idle,
            started_at: None,
            completed_at: None,
            progress_percent: None,
            current_object_class: None,
            error: None,
            version: None,
        }
    }

    /// Create a new in-progress status.
    #[must_use]
    pub fn in_progress(connector_id: Uuid) -> Self {
        Self {
            connector_id,
            state: DiscoveryState::InProgress,
            started_at: Some(Utc::now()),
            completed_at: None,
            progress_percent: Some(0),
            current_object_class: None,
            error: None,
            version: None,
        }
    }

    /// Update progress.
    #[must_use]
    pub fn with_progress(mut self, percent: i32, current_class: Option<String>) -> Self {
        self.progress_percent = Some(percent.clamp(0, 100));
        self.current_object_class = current_class;
        self
    }

    /// Mark as completed.
    #[must_use]
    pub fn completed(mut self, version: i32) -> Self {
        self.state = DiscoveryState::Completed;
        self.completed_at = Some(Utc::now());
        self.progress_percent = Some(100);
        self.version = Some(version);
        self
    }

    /// Mark as failed.
    #[must_use]
    pub fn failed(mut self, error: String) -> Self {
        self.state = DiscoveryState::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error);
        self
    }
}

// ============================================================================
// Schema Diff Types
// ============================================================================

/// Differences between two schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDiff {
    /// Source version number.
    pub from_version: i32,
    /// Target version number.
    pub to_version: i32,
    /// When source version was discovered.
    pub from_discovered_at: DateTime<Utc>,
    /// When target version was discovered.
    pub to_discovered_at: DateTime<Utc>,
    /// Summary of changes.
    pub summary: DiffSummary,
    /// Object class changes.
    pub object_class_changes: ObjectClassChanges,
    /// Attribute changes per object class.
    pub attribute_changes: HashMap<String, AttributeChanges>,
}

impl SchemaDiff {
    /// Create a new diff between two schemas.
    #[must_use]
    pub fn new(
        from_version: i32,
        to_version: i32,
        from_discovered_at: DateTime<Utc>,
        to_discovered_at: DateTime<Utc>,
    ) -> Self {
        Self {
            from_version,
            to_version,
            from_discovered_at,
            to_discovered_at,
            summary: DiffSummary::default(),
            object_class_changes: ObjectClassChanges::default(),
            attribute_changes: HashMap::new(),
        }
    }

    /// Compute the diff between two schemas.
    #[must_use]
    pub fn compute(
        from: &Schema,
        to: &Schema,
        from_version: i32,
        to_version: i32,
        from_discovered_at: DateTime<Utc>,
        to_discovered_at: DateTime<Utc>,
    ) -> Self {
        let mut diff = Self::new(
            from_version,
            to_version,
            from_discovered_at,
            to_discovered_at,
        );

        // Build maps for quick lookup
        let from_classes: HashMap<&str, &ObjectClass> = from
            .object_classes
            .iter()
            .map(|oc| (oc.name.as_str(), oc))
            .collect();
        let to_classes: HashMap<&str, &ObjectClass> = to
            .object_classes
            .iter()
            .map(|oc| (oc.name.as_str(), oc))
            .collect();

        // Find added and removed object classes
        for name in to_classes.keys() {
            if !from_classes.contains_key(name) {
                diff.object_class_changes.added.push(name.to_string());
                diff.summary.object_classes_added += 1;
            }
        }

        for name in from_classes.keys() {
            if !to_classes.contains_key(name) {
                diff.object_class_changes.removed.push(name.to_string());
                diff.summary.object_classes_removed += 1;
            }
        }

        // Compare attributes in common object classes
        for (name, from_oc) in &from_classes {
            if let Some(to_oc) = to_classes.get(name) {
                let attr_changes = Self::compute_attribute_changes(from_oc, to_oc);

                if !attr_changes.added.is_empty()
                    || !attr_changes.removed.is_empty()
                    || !attr_changes.modified.is_empty()
                {
                    // Check for breaking changes
                    for removed in &attr_changes.removed {
                        if from_oc
                            .attributes
                            .iter()
                            .any(|a| a.name == *removed && a.required)
                        {
                            diff.summary.has_breaking_changes = true;
                        }
                    }
                    for modified in &attr_changes.modified {
                        // Check if a non-required attribute became required (breaking)
                        for change in &modified.changes {
                            if change.property == "required"
                                && change.old_value == "false"
                                && change.new_value == "true"
                            {
                                diff.summary.has_breaking_changes = true;
                            }
                        }
                    }

                    diff.summary.attributes_added += attr_changes.added.len() as i32;
                    diff.summary.attributes_removed += attr_changes.removed.len() as i32;
                    diff.summary.attributes_modified += attr_changes.modified.len() as i32;
                    diff.attribute_changes
                        .insert(name.to_string(), attr_changes);
                }
            }
        }

        diff
    }

    /// Compute attribute changes between two object classes.
    fn compute_attribute_changes(from_oc: &ObjectClass, to_oc: &ObjectClass) -> AttributeChanges {
        let mut changes = AttributeChanges::default();

        // Build maps for quick lookup
        let from_attrs: HashMap<&str, &SchemaAttribute> = from_oc
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a))
            .collect();
        let to_attrs: HashMap<&str, &SchemaAttribute> = to_oc
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a))
            .collect();

        // Find added attributes
        for (name, attr) in &to_attrs {
            if !from_attrs.contains_key(name) {
                changes.added.push(AttributeAddition {
                    name: name.to_string(),
                    data_type: attr.data_type,
                    required: attr.required,
                });
            }
        }

        // Find removed attributes
        for name in from_attrs.keys() {
            if !to_attrs.contains_key(name) {
                changes.removed.push(name.to_string());
            }
        }

        // Find modified attributes
        for (name, from_attr) in &from_attrs {
            if let Some(to_attr) = to_attrs.get(name) {
                let property_changes = Self::compare_attributes(from_attr, to_attr);
                if !property_changes.is_empty() {
                    changes.modified.push(AttributeModification {
                        name: name.to_string(),
                        changes: property_changes,
                    });
                }
            }
        }

        changes
    }

    /// Compare two attributes and return list of property changes.
    fn compare_attributes(from: &SchemaAttribute, to: &SchemaAttribute) -> Vec<PropertyChange> {
        let mut changes = Vec::new();

        if from.data_type != to.data_type {
            changes.push(PropertyChange {
                property: "data_type".to_string(),
                old_value: from.data_type.as_str().to_string(),
                new_value: to.data_type.as_str().to_string(),
            });
        }

        if from.multi_valued != to.multi_valued {
            changes.push(PropertyChange {
                property: "multi_valued".to_string(),
                old_value: from.multi_valued.to_string(),
                new_value: to.multi_valued.to_string(),
            });
        }

        if from.required != to.required {
            changes.push(PropertyChange {
                property: "required".to_string(),
                old_value: from.required.to_string(),
                new_value: to.required.to_string(),
            });
        }

        if from.readable != to.readable {
            changes.push(PropertyChange {
                property: "readable".to_string(),
                old_value: from.readable.to_string(),
                new_value: to.readable.to_string(),
            });
        }

        if from.writable != to.writable {
            changes.push(PropertyChange {
                property: "writable".to_string(),
                old_value: from.writable.to_string(),
                new_value: to.writable.to_string(),
            });
        }

        changes
    }

    /// Check if there are any changes.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.summary.object_classes_added > 0
            || self.summary.object_classes_removed > 0
            || self.summary.attributes_added > 0
            || self.summary.attributes_removed > 0
            || self.summary.attributes_modified > 0
    }
}

/// Summary of changes between schema versions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DiffSummary {
    /// Number of object classes added.
    pub object_classes_added: i32,
    /// Number of object classes removed.
    pub object_classes_removed: i32,
    /// Number of attributes added (across all classes).
    pub attributes_added: i32,
    /// Number of attributes removed (across all classes).
    pub attributes_removed: i32,
    /// Number of attributes modified (across all classes).
    pub attributes_modified: i32,
    /// Whether changes include breaking changes (removed required attributes, etc.).
    pub has_breaking_changes: bool,
}

/// Changes to object classes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ObjectClassChanges {
    /// Names of added object classes.
    pub added: Vec<String>,
    /// Names of removed object classes.
    pub removed: Vec<String>,
}

/// Changes to attributes within an object class.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttributeChanges {
    /// Attributes that were added.
    pub added: Vec<AttributeAddition>,
    /// Names of attributes that were removed.
    pub removed: Vec<String>,
    /// Attributes that were modified.
    pub modified: Vec<AttributeModification>,
}

/// An attribute that was added.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttributeAddition {
    /// Attribute name.
    pub name: String,
    /// Attribute data type.
    pub data_type: AttributeDataType,
    /// Whether attribute is required.
    pub required: bool,
}

/// A modification to an existing attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AttributeModification {
    /// Attribute name.
    pub name: String,
    /// List of property changes.
    pub changes: Vec<PropertyChange>,
}

/// A change to a specific property of an attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PropertyChange {
    /// Property name (e.g., "required", "`multi_valued`").
    pub property: String,
    /// Old value.
    pub old_value: String,
    /// New value.
    pub new_value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_builder() {
        let schema = Schema::with_object_classes(vec![ObjectClass::new("user", "inetOrgPerson")
            .with_display_name("User")
            .with_attribute(
                SchemaAttribute::new("email", "mail", AttributeDataType::String).required(),
            )
            .with_attribute(SchemaAttribute::new(
                "first_name",
                "givenName",
                AttributeDataType::String,
            ))
            .with_attribute(
                SchemaAttribute::new("groups", "memberOf", AttributeDataType::Dn)
                    .multi_valued()
                    .read_only(),
            )]);

        assert!(schema.has_object_class("user"));
        assert!(!schema.has_object_class("group"));

        let user_class = schema.get_object_class("user").unwrap();
        assert_eq!(user_class.native_name, "inetOrgPerson");
        assert!(user_class.has_attribute("email"));
        assert!(user_class.get_attribute("email").unwrap().required);
        assert!(user_class.get_attribute("groups").unwrap().multi_valued);
        assert!(!user_class.get_attribute("groups").unwrap().writable);
    }

    #[test]
    fn test_object_class_capabilities() {
        let oc = ObjectClass::new("user", "person");
        assert!(oc.supports_create);
        assert!(oc.supports_update);
        assert!(oc.supports_delete);
    }

    #[test]
    fn test_attribute_data_type_parsing() {
        assert_eq!(
            AttributeDataType::parse_str("string"),
            Some(AttributeDataType::String)
        );
        assert_eq!(
            AttributeDataType::parse_str("VARCHAR"),
            Some(AttributeDataType::String)
        );
        assert_eq!(
            AttributeDataType::parse_str("integer"),
            Some(AttributeDataType::Integer)
        );
        assert_eq!(
            AttributeDataType::parse_str("boolean"),
            Some(AttributeDataType::Boolean)
        );
        assert_eq!(AttributeDataType::parse_str("unknown"), None);
    }

    #[test]
    fn test_required_attributes() {
        let oc = ObjectClass::new("user", "person")
            .with_attribute(
                SchemaAttribute::new("email", "mail", AttributeDataType::String).required(),
            )
            .with_attribute(SchemaAttribute::new(
                "phone",
                "telephoneNumber",
                AttributeDataType::String,
            ));

        let required = oc.required_attributes();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].name, "email");
    }

    #[test]
    fn test_schema_serialization() {
        let schema = Schema::with_object_classes(vec![ObjectClass::new("user", "inetOrgPerson")
            .with_attribute(
                SchemaAttribute::new("email", "mail", AttributeDataType::String).required(),
            )]);

        let json = serde_json::to_string(&schema).unwrap();
        let parsed: Schema = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.object_classes.len(), 1);
        assert_eq!(parsed.object_classes[0].name, "user");
    }

    // ============================================================================
    // IGA edge case Tests
    // ============================================================================

    #[test]
    fn test_primary_identifier() {
        let attr =
            SchemaAttribute::new("uid", "uid", AttributeDataType::String).as_primary_identifier();

        assert!(attr.is_primary_identifier());
        assert!(attr.is_identifier());
        assert_eq!(attr.identifier_type, Some(IdentifierType::Primary));
    }

    #[test]
    fn test_secondary_identifier() {
        let attr =
            SchemaAttribute::new("cn", "cn", AttributeDataType::String).as_secondary_identifier();

        assert!(!attr.is_primary_identifier());
        assert!(attr.is_identifier());
        assert_eq!(attr.identifier_type, Some(IdentifierType::Secondary));
    }

    #[test]
    fn test_volatile_attribute() {
        let attr = SchemaAttribute::new(
            "modifyTimestamp",
            "modifyTimestamp",
            AttributeDataType::DateTime,
        )
        .volatile()
        .read_only();

        assert!(attr.volatile);
        assert!(!attr.writable);
    }

    #[test]
    fn test_case_insensitive_attribute() {
        let attr = SchemaAttribute::new("uid", "uid", AttributeDataType::String).case_insensitive();

        assert!(attr.case_insensitive);
        assert!(attr.name_matches("uid"));
        assert!(attr.name_matches("UID"));
        assert!(attr.name_matches("Uid"));
        assert!(attr.native_name_matches("UID"));
    }

    #[test]
    fn test_case_sensitive_attribute() {
        let attr = SchemaAttribute::new("uid", "uid", AttributeDataType::String);

        assert!(!attr.case_insensitive);
        assert!(attr.name_matches("uid"));
        assert!(!attr.name_matches("UID"));
        assert!(!attr.name_matches("Uid"));
    }

    #[test]
    fn test_object_class_identifiers() {
        let oc = ObjectClass::new("user", "inetOrgPerson")
            .with_attribute(
                SchemaAttribute::new("uid", "uid", AttributeDataType::String)
                    .as_primary_identifier()
                    .required(),
            )
            .with_attribute(
                SchemaAttribute::new("cn", "cn", AttributeDataType::String)
                    .as_secondary_identifier(),
            )
            .with_attribute(SchemaAttribute::new(
                "email",
                "mail",
                AttributeDataType::String,
            ));

        let primary = oc.primary_identifier();
        assert!(primary.is_some());
        assert_eq!(primary.unwrap().name, "uid");

        let identifiers = oc.identifiers();
        assert_eq!(identifiers.len(), 2);
    }

    #[test]
    fn test_object_class_volatile_attributes() {
        let oc = ObjectClass::new("user", "inetOrgPerson")
            .with_attribute(
                SchemaAttribute::new(
                    "modifyTimestamp",
                    "modifyTimestamp",
                    AttributeDataType::DateTime,
                )
                .volatile()
                .read_only(),
            )
            .with_attribute(
                SchemaAttribute::new(
                    "createTimestamp",
                    "createTimestamp",
                    AttributeDataType::DateTime,
                )
                .volatile()
                .read_only(),
            )
            .with_attribute(SchemaAttribute::new(
                "email",
                "mail",
                AttributeDataType::String,
            ));

        let volatile = oc.volatile_attributes();
        assert_eq!(volatile.len(), 2);
    }

    #[test]
    fn test_object_class_case_insensitive_lookup() {
        let oc = ObjectClass::new("user", "inetOrgPerson").with_attribute(
            SchemaAttribute::new("uid", "uid", AttributeDataType::String).case_insensitive(),
        );

        // Case-sensitive lookup
        assert!(oc.get_attribute("uid").is_some());
        assert!(oc.get_attribute("UID").is_none());

        // Case-insensitive lookup
        assert!(oc.get_attribute_case_insensitive("uid").is_some());
        assert!(oc.get_attribute_case_insensitive("UID").is_some());
        assert!(oc.get_attribute_case_insensitive("Uid").is_some());

        // Case-aware lookup (respects attribute's case_insensitive flag)
        assert!(oc.get_attribute_case_aware("uid").is_some());
        assert!(oc.get_attribute_case_aware("UID").is_some());
    }

    #[test]
    fn test_schema_config_case_ignore() {
        let config = SchemaConfig {
            case_ignore_attribute_names: true,
            ..Default::default()
        };

        let schema = Schema::with_object_classes(vec![ObjectClass::new("User", "inetOrgPerson")])
            .with_config(config);

        // Case-sensitive lookup fails
        assert!(schema.get_object_class("user").is_none());
        // Case-aware lookup succeeds
        assert!(schema.get_object_class_case_aware("user").is_some());
        assert!(schema.get_object_class_case_aware("USER").is_some());
    }

    #[test]
    fn test_schema_config_volatile_attributes() {
        let config = SchemaConfig {
            volatile_attributes: vec!["modifyTimestamp".to_string(), "createTimestamp".to_string()],
            ..Default::default()
        };

        let schema = Schema::new().with_config(config);
        let cfg = schema.config();

        assert_eq!(cfg.volatile_attributes.len(), 2);
        assert!(cfg
            .volatile_attributes
            .contains(&"modifyTimestamp".to_string()));
    }

    #[test]
    fn test_schema_config_identifiers() {
        let config = SchemaConfig {
            primary_identifier: Some("entryUUID".to_string()),
            secondary_identifiers: vec!["uid".to_string(), "cn".to_string()],
            ..Default::default()
        };

        let schema = Schema::new().with_config(config);
        let cfg = schema.config();

        assert_eq!(cfg.primary_identifier, Some("entryUUID".to_string()));
        assert_eq!(cfg.secondary_identifiers.len(), 2);
    }

    #[test]
    fn test_schema_volatile_attributes() {
        let schema = Schema::with_object_classes(vec![ObjectClass::new("user", "inetOrgPerson")
            .with_attribute(
                SchemaAttribute::new(
                    "modifyTimestamp",
                    "modifyTimestamp",
                    AttributeDataType::DateTime,
                )
                .volatile(),
            )
            .with_attribute(SchemaAttribute::new(
                "email",
                "mail",
                AttributeDataType::String,
            ))]);

        let volatile = schema.volatile_attributes();
        assert_eq!(volatile.len(), 1);
        assert_eq!(volatile[0].name, "modifyTimestamp");
    }

    #[test]
    fn test_schema_primary_identifiers() {
        let schema = Schema::with_object_classes(vec![
            ObjectClass::new("user", "inetOrgPerson").with_attribute(
                SchemaAttribute::new("uid", "uid", AttributeDataType::String)
                    .as_primary_identifier(),
            ),
            ObjectClass::new("group", "groupOfNames").with_attribute(
                SchemaAttribute::new("cn", "cn", AttributeDataType::String).as_primary_identifier(),
            ),
        ]);

        let identifiers = schema.primary_identifiers();
        assert_eq!(identifiers.len(), 2);
    }

    #[test]
    fn test_identifier_type_serialization() {
        let attr = SchemaAttribute::new("uid", "uid", AttributeDataType::String)
            .as_primary_identifier()
            .volatile()
            .case_insensitive();

        let json = serde_json::to_string(&attr).unwrap();
        let parsed: SchemaAttribute = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.identifier_type, Some(IdentifierType::Primary));
        assert!(parsed.volatile);
        assert!(parsed.case_insensitive);
    }

    // ============================================================================
    // Schema Diff Tests (User Story 4)
    // ============================================================================

    fn create_test_schema_v1() -> Schema {
        Schema::with_object_classes(vec![
            ObjectClass::new("user", "inetOrgPerson")
                .with_attribute(
                    SchemaAttribute::new("uid", "uid", AttributeDataType::String).required(),
                )
                .with_attribute(SchemaAttribute::new(
                    "email",
                    "mail",
                    AttributeDataType::String,
                ))
                .with_attribute(
                    SchemaAttribute::new("name", "cn", AttributeDataType::String).required(),
                ),
            ObjectClass::new("group", "groupOfNames")
                .with_attribute(
                    SchemaAttribute::new("cn", "cn", AttributeDataType::String).required(),
                )
                .with_attribute(
                    SchemaAttribute::new("member", "member", AttributeDataType::Dn).multi_valued(),
                ),
        ])
    }

    fn create_test_schema_v2() -> Schema {
        Schema::with_object_classes(vec![
            ObjectClass::new("user", "inetOrgPerson")
                .with_attribute(
                    SchemaAttribute::new("uid", "uid", AttributeDataType::String).required(),
                )
                .with_attribute(
                    SchemaAttribute::new("email", "mail", AttributeDataType::String).required(),
                ) // Changed: now required
                .with_attribute(SchemaAttribute::new(
                    "phone",
                    "telephoneNumber",
                    AttributeDataType::String,
                )), // Added
            // Removed: name attribute
            ObjectClass::new("group", "groupOfNames")
                .with_attribute(
                    SchemaAttribute::new("cn", "cn", AttributeDataType::String).required(),
                )
                .with_attribute(
                    SchemaAttribute::new("member", "member", AttributeDataType::Dn).multi_valued(),
                ),
            ObjectClass::new("role", "organizationalRole") // Added object class
                .with_attribute(
                    SchemaAttribute::new("cn", "cn", AttributeDataType::String).required(),
                ),
        ])
    }

    #[test]
    fn test_schema_diff_no_changes() {
        let schema = create_test_schema_v1();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&schema, &schema, 1, 1, now, now);

        assert!(!diff.has_changes());
        assert_eq!(diff.summary.object_classes_added, 0);
        assert_eq!(diff.summary.object_classes_removed, 0);
        assert_eq!(diff.summary.attributes_added, 0);
        assert_eq!(diff.summary.attributes_removed, 0);
        assert_eq!(diff.summary.attributes_modified, 0);
    }

    #[test]
    fn test_schema_diff_object_class_added() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        assert!(diff.has_changes());
        assert_eq!(diff.summary.object_classes_added, 1);
        assert!(diff
            .object_class_changes
            .added
            .contains(&"role".to_string()));
    }

    #[test]
    fn test_schema_diff_attribute_added() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Check that "phone" attribute was added to "user" object class
        let user_changes = diff
            .attribute_changes
            .get("user")
            .expect("user changes should exist");
        assert!(user_changes.added.iter().any(|a| a.name == "phone"));
    }

    #[test]
    fn test_schema_diff_attribute_removed() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Check that "name" attribute was removed from "user" object class
        let user_changes = diff
            .attribute_changes
            .get("user")
            .expect("user changes should exist");
        assert!(user_changes.removed.contains(&"name".to_string()));
    }

    #[test]
    fn test_schema_diff_attribute_modified() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Check that "email" attribute was modified (required changed)
        let user_changes = diff
            .attribute_changes
            .get("user")
            .expect("user changes should exist");
        let email_mod = user_changes
            .modified
            .iter()
            .find(|m| m.name == "email")
            .expect("email modification should exist");

        let required_change = email_mod
            .changes
            .iter()
            .find(|c| c.property == "required")
            .expect("required change should exist");

        assert_eq!(required_change.old_value, "false");
        assert_eq!(required_change.new_value, "true");
    }

    #[test]
    fn test_schema_diff_breaking_changes() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Making email required is a breaking change (existing data might not have it)
        assert!(diff.summary.has_breaking_changes);
    }

    #[test]
    fn test_schema_diff_breaking_changes_removed_required() {
        let v1 = Schema::with_object_classes(vec![ObjectClass::new("user", "inetOrgPerson")
            .with_attribute(
                SchemaAttribute::new("uid", "uid", AttributeDataType::String).required(),
            )
            .with_attribute(
                SchemaAttribute::new("email", "mail", AttributeDataType::String).required(),
            )]);
        let v2 = Schema::with_object_classes(vec![
            ObjectClass::new("user", "inetOrgPerson").with_attribute(
                SchemaAttribute::new("uid", "uid", AttributeDataType::String).required(),
            ),
            // email is removed - breaking change!
        ]);
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Removing a required attribute is a breaking change
        assert!(diff.summary.has_breaking_changes);
    }

    #[test]
    fn test_schema_diff_summary_counts() {
        let v1 = create_test_schema_v1();
        let v2 = create_test_schema_v2();
        let now = Utc::now();

        let diff = SchemaDiff::compute(&v1, &v2, 1, 2, now, now);

        // Verify counts match actual changes
        assert_eq!(diff.summary.object_classes_added, 1); // role added
        assert_eq!(diff.summary.object_classes_removed, 0); // none removed

        // In user class: +phone, -name, ~email (required changed)
        assert!(diff.summary.attributes_added >= 1);
        assert!(diff.summary.attributes_removed >= 1);
        assert!(diff.summary.attributes_modified >= 1);
    }
}
