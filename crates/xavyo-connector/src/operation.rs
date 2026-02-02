//! Connector Framework operation types
//!
//! Types for CRUD operations: UIDs, attribute sets, deltas, filters, and pagination.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Unique identifier for an object in a target system.
///
/// Different systems use different identifier schemes:
/// - LDAP: Distinguished Name (DN) or entryUUID
/// - Database: Primary key column value
/// - REST: Resource ID
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Uid {
    /// The attribute name used as the identifier (e.g., "dn", "id", "uid").
    attribute_name: String,
    /// The actual value of the identifier.
    value: String,
}

impl Uid {
    /// Create a new UID with the given attribute name and value.
    pub fn new(attribute_name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            attribute_name: attribute_name.into(),
            value: value.into(),
        }
    }

    /// Create a UID using the default "uid" attribute name.
    pub fn from_value(value: impl Into<String>) -> Self {
        Self::new("uid", value)
    }

    /// Create a UID for LDAP Distinguished Name.
    pub fn from_dn(dn: impl Into<String>) -> Self {
        Self::new("dn", dn)
    }

    /// Create a UID for database primary key.
    pub fn from_id(id: impl Into<String>) -> Self {
        Self::new("id", id)
    }

    /// Get the attribute name.
    pub fn attribute_name(&self) -> &str {
        &self.attribute_name
    }

    /// Get the value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl std::fmt::Display for Uid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.attribute_name, self.value)
    }
}

/// A set of attributes for create operations or search results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeSet {
    /// Map of attribute name to attribute value(s).
    #[serde(flatten)]
    attributes: HashMap<String, AttributeValue>,
}

impl AttributeSet {
    /// Create a new empty attribute set.
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// Set an attribute value.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<AttributeValue>) {
        self.attributes.insert(name.into(), value.into());
    }

    /// Set an attribute using builder pattern.
    pub fn with(mut self, name: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.set(name, value);
        self
    }

    /// Get an attribute value.
    pub fn get(&self, name: &str) -> Option<&AttributeValue> {
        self.attributes.get(name)
    }

    /// Get a single-valued string attribute.
    pub fn get_string(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.as_string())
    }

    /// Get a multi-valued string attribute.
    pub fn get_strings(&self, name: &str) -> Option<Vec<&str>> {
        self.get(name).map(|v| v.as_strings())
    }

    /// Check if an attribute exists.
    pub fn has(&self, name: &str) -> bool {
        self.attributes.contains_key(name)
    }

    /// Remove an attribute.
    pub fn remove(&mut self, name: &str) -> Option<AttributeValue> {
        self.attributes.remove(name)
    }

    /// Get all attribute names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.attributes.keys().map(|s| s.as_str())
    }

    /// Get the number of attributes.
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Iterate over all attributes.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &AttributeValue)> {
        self.attributes.iter()
    }

    /// Convert to a HashMap.
    pub fn into_map(self) -> HashMap<String, AttributeValue> {
        self.attributes
    }
}

impl FromIterator<(String, AttributeValue)> for AttributeSet {
    fn from_iter<T: IntoIterator<Item = (String, AttributeValue)>>(iter: T) -> Self {
        Self {
            attributes: iter.into_iter().collect(),
        }
    }
}

/// A value for an attribute, which may be single or multi-valued.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// No value (null).
    Null,
    /// A single string value.
    String(String),
    /// A single integer value.
    Integer(i64),
    /// A single boolean value.
    Boolean(bool),
    /// A single floating-point value.
    Float(f64),
    /// Binary data (base64 encoded in JSON).
    Binary(Vec<u8>),
    /// Multiple values.
    Array(Vec<AttributeValue>),
    /// JSON object value.
    Object(serde_json::Map<String, Value>),
}

impl AttributeValue {
    /// Create a null value.
    pub fn null() -> Self {
        AttributeValue::Null
    }

    /// Check if this is a null value.
    pub fn is_null(&self) -> bool {
        matches!(self, AttributeValue::Null)
    }

    /// Get as a string if this is a single string value.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as strings (works for both single and multi-valued).
    pub fn as_strings(&self) -> Vec<&str> {
        match self {
            AttributeValue::String(s) => vec![s.as_str()],
            AttributeValue::Array(arr) => arr.iter().filter_map(|v| v.as_string()).collect(),
            _ => vec![],
        }
    }

    /// Get as an integer if this is an integer value.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            AttributeValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as a boolean if this is a boolean value.
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            AttributeValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as an array if this is multi-valued.
    pub fn as_array(&self) -> Option<&Vec<AttributeValue>> {
        match self {
            AttributeValue::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Check if this is multi-valued.
    pub fn is_multi_valued(&self) -> bool {
        matches!(self, AttributeValue::Array(_))
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        AttributeValue::String(s)
    }
}

impl From<&str> for AttributeValue {
    fn from(s: &str) -> Self {
        AttributeValue::String(s.to_string())
    }
}

impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        AttributeValue::Integer(i)
    }
}

impl From<i32> for AttributeValue {
    fn from(i: i32) -> Self {
        AttributeValue::Integer(i as i64)
    }
}

impl From<bool> for AttributeValue {
    fn from(b: bool) -> Self {
        AttributeValue::Boolean(b)
    }
}

impl From<f64> for AttributeValue {
    fn from(f: f64) -> Self {
        AttributeValue::Float(f)
    }
}

impl From<Vec<u8>> for AttributeValue {
    fn from(bytes: Vec<u8>) -> Self {
        AttributeValue::Binary(bytes)
    }
}

impl<T: Into<AttributeValue>> From<Vec<T>> for AttributeValue {
    fn from(vec: Vec<T>) -> Self {
        AttributeValue::Array(vec.into_iter().map(Into::into).collect())
    }
}

/// Changes to apply to an object during update operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeDelta {
    /// Attributes to add (or replace if single-valued).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub add: HashMap<String, AttributeValue>,

    /// Values to remove from multi-valued attributes.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub remove: HashMap<String, AttributeValue>,

    /// Attributes to replace entirely.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub replace: HashMap<String, AttributeValue>,

    /// Attributes to clear (remove all values).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clear: Vec<String>,
}

impl AttributeDelta {
    /// Create a new empty delta.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or set an attribute value.
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<AttributeValue>) -> &mut Self {
        self.add.insert(name.into(), value.into());
        self
    }

    /// Remove a value from a multi-valued attribute.
    pub fn remove(
        &mut self,
        name: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> &mut Self {
        self.remove.insert(name.into(), value.into());
        self
    }

    /// Replace an attribute value entirely.
    pub fn replace(
        &mut self,
        name: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> &mut Self {
        self.replace.insert(name.into(), value.into());
        self
    }

    /// Clear all values from an attribute.
    pub fn clear_attribute(&mut self, name: impl Into<String>) -> &mut Self {
        self.clear.push(name.into());
        self
    }

    /// Check if this delta has any changes.
    pub fn is_empty(&self) -> bool {
        self.add.is_empty()
            && self.remove.is_empty()
            && self.replace.is_empty()
            && self.clear.is_empty()
    }

    /// Get all affected attribute names.
    pub fn affected_attributes(&self) -> Vec<&str> {
        let mut names: Vec<&str> = Vec::new();
        names.extend(self.add.keys().map(|s| s.as_str()));
        names.extend(self.remove.keys().map(|s| s.as_str()));
        names.extend(self.replace.keys().map(|s| s.as_str()));
        names.extend(self.clear.iter().map(|s| s.as_str()));
        names.sort();
        names.dedup();
        names
    }
}

/// Filter for search operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Filter {
    /// Match objects where attribute equals value.
    Equals { attribute: String, value: String },

    /// Match objects where attribute contains value (substring).
    Contains { attribute: String, value: String },

    /// Match objects where attribute starts with value.
    StartsWith { attribute: String, value: String },

    /// Match objects where attribute ends with value.
    EndsWith { attribute: String, value: String },

    /// Match objects where attribute is greater than value.
    GreaterThan { attribute: String, value: String },

    /// Match objects where attribute is greater than or equal to value.
    GreaterThanOrEquals { attribute: String, value: String },

    /// Match objects where attribute is less than value.
    LessThan { attribute: String, value: String },

    /// Match objects where attribute is less than or equal to value.
    LessThanOrEquals { attribute: String, value: String },

    /// Match objects where attribute exists (has any value).
    Present { attribute: String },

    /// Logical AND of multiple filters.
    And { filters: Vec<Filter> },

    /// Logical OR of multiple filters.
    Or { filters: Vec<Filter> },

    /// Logical NOT of a filter.
    Not { filter: Box<Filter> },
}

impl Filter {
    /// Create an equals filter.
    pub fn eq(attribute: impl Into<String>, value: impl Into<String>) -> Self {
        Filter::Equals {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Create a contains filter.
    pub fn contains(attribute: impl Into<String>, value: impl Into<String>) -> Self {
        Filter::Contains {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Create a starts-with filter.
    pub fn starts_with(attribute: impl Into<String>, value: impl Into<String>) -> Self {
        Filter::StartsWith {
            attribute: attribute.into(),
            value: value.into(),
        }
    }

    /// Create a present (attribute exists) filter.
    pub fn present(attribute: impl Into<String>) -> Self {
        Filter::Present {
            attribute: attribute.into(),
        }
    }

    /// Create an AND filter.
    pub fn and(filters: Vec<Filter>) -> Self {
        Filter::And { filters }
    }

    /// Create an OR filter.
    pub fn or(filters: Vec<Filter>) -> Self {
        Filter::Or { filters }
    }

    /// Create a NOT filter (negation).
    pub fn negate(filter: Filter) -> Self {
        Filter::Not {
            filter: Box::new(filter),
        }
    }

    /// Combine this filter with another using AND.
    pub fn and_with(self, other: Filter) -> Self {
        match self {
            Filter::And { mut filters } => {
                filters.push(other);
                Filter::And { filters }
            }
            _ => Filter::And {
                filters: vec![self, other],
            },
        }
    }

    /// Combine this filter with another using OR.
    pub fn or_with(self, other: Filter) -> Self {
        match self {
            Filter::Or { mut filters } => {
                filters.push(other);
                Filter::Or { filters }
            }
            _ => Filter::Or {
                filters: vec![self, other],
            },
        }
    }
}

/// Pagination request for search operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRequest {
    /// Number of results to skip.
    #[serde(default)]
    pub offset: u32,

    /// Maximum number of results to return.
    pub page_size: u32,

    /// Optional sort attribute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<String>,

    /// Sort direction (ascending by default).
    #[serde(default)]
    pub ascending: bool,

    /// Opaque cursor for cursor-based pagination.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl PageRequest {
    /// Create a new page request with the given page size.
    pub fn new(page_size: u32) -> Self {
        Self {
            offset: 0,
            page_size,
            sort_by: None,
            ascending: true,
            cursor: None,
        }
    }

    /// Set the offset.
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Set the sort attribute.
    pub fn sorted_by(mut self, attribute: impl Into<String>, ascending: bool) -> Self {
        self.sort_by = Some(attribute.into());
        self.ascending = ascending;
        self
    }

    /// Set the cursor for cursor-based pagination.
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self::new(100)
    }
}

/// Result of a search operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// The matching objects.
    pub objects: Vec<AttributeSet>,

    /// Total number of matching objects (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<u64>,

    /// Cursor for the next page (if more results available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// Whether there are more results available.
    pub has_more: bool,
}

impl SearchResult {
    /// Create a new search result.
    pub fn new(objects: Vec<AttributeSet>) -> Self {
        Self {
            has_more: false,
            objects,
            total_count: None,
            next_cursor: None,
        }
    }

    /// Create an empty search result.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Set the total count.
    pub fn with_total_count(mut self, count: u64) -> Self {
        self.total_count = Some(count);
        self
    }

    /// Set the next cursor.
    pub fn with_next_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.next_cursor = Some(cursor.into());
        self.has_more = true;
        self
    }

    /// Get the number of objects in this page.
    pub fn count(&self) -> usize {
        self.objects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_creation() {
        let uid = Uid::new("dn", "cn=john,ou=users,dc=example,dc=com");
        assert_eq!(uid.attribute_name(), "dn");
        assert_eq!(uid.value(), "cn=john,ou=users,dc=example,dc=com");
        assert_eq!(uid.to_string(), "dn=cn=john,ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_attribute_set() {
        let attrs = AttributeSet::new()
            .with("email", "john@example.com")
            .with("age", 30i64)
            .with("active", true);

        assert_eq!(attrs.get_string("email"), Some("john@example.com"));
        assert_eq!(attrs.get("age").and_then(|v| v.as_integer()), Some(30));
        assert_eq!(attrs.get("active").and_then(|v| v.as_boolean()), Some(true));
        assert!(!attrs.has("nonexistent"));
    }

    #[test]
    fn test_multi_valued_attribute() {
        let mut attrs = AttributeSet::new();
        attrs.set(
            "groups",
            AttributeValue::Array(vec![
                AttributeValue::String("admins".to_string()),
                AttributeValue::String("users".to_string()),
            ]),
        );

        let groups = attrs.get_strings("groups").unwrap();
        assert_eq!(groups, vec!["admins", "users"]);
    }

    #[test]
    fn test_attribute_delta() {
        let mut delta = AttributeDelta::new();
        delta
            .add("email", "new@example.com")
            .replace("name", "John Doe")
            .clear_attribute("phone");

        assert!(!delta.is_empty());
        let affected = delta.affected_attributes();
        assert!(affected.contains(&"email"));
        assert!(affected.contains(&"name"));
        assert!(affected.contains(&"phone"));
    }

    #[test]
    fn test_filter_construction() {
        let filter = Filter::eq("email", "john@example.com")
            .and_with(Filter::present("active"))
            .and_with(Filter::negate(Filter::eq("status", "deleted")));

        // Verify it's an AND filter with 3 conditions
        if let Filter::And { filters } = filter {
            assert_eq!(filters.len(), 3);
        } else {
            panic!("Expected AND filter");
        }
    }

    #[test]
    fn test_page_request() {
        let page = PageRequest::new(50)
            .with_offset(100)
            .sorted_by("created_at", false);

        assert_eq!(page.offset, 100);
        assert_eq!(page.page_size, 50);
        assert_eq!(page.sort_by, Some("created_at".to_string()));
        assert!(!page.ascending);
    }

    #[test]
    fn test_search_result() {
        let result = SearchResult::new(vec![
            AttributeSet::new().with("id", "1"),
            AttributeSet::new().with("id", "2"),
        ])
        .with_total_count(100)
        .with_next_cursor("cursor_abc");

        assert_eq!(result.count(), 2);
        assert_eq!(result.total_count, Some(100));
        assert!(result.has_more);
        assert_eq!(result.next_cursor, Some("cursor_abc".to_string()));
    }

    #[test]
    fn test_attribute_set_serialization() {
        let attrs = AttributeSet::new()
            .with("email", "john@example.com")
            .with("age", 30i64);

        let json = serde_json::to_string(&attrs).unwrap();
        let parsed: AttributeSet = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.get_string("email"), Some("john@example.com"));
    }
}
