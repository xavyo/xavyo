//! Account/identity comparison for reconciliation.
//!
//! Compares accounts from target systems with identities in xavyo
//! to detect discrepancies.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::types::DiscrepancyType;

/// Result of comparing an account with an identity.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Type of discrepancy (None if match).
    pub discrepancy_type: Option<DiscrepancyType>,
    /// Mismatched attributes (if mismatch type).
    pub mismatched_attributes: Option<MismatchedAttributes>,
    /// External account UID.
    pub external_uid: String,
    /// Identity ID (if linked or correlated).
    pub identity_id: Option<Uuid>,
    /// Correlation matches (if any).
    pub correlation_matches: Vec<CorrelationMatch>,
}

impl ComparisonResult {
    /// Create a result indicating a match (no discrepancy).
    #[must_use]
    pub fn matched(external_uid: String, identity_id: Uuid) -> Self {
        Self {
            discrepancy_type: None,
            mismatched_attributes: None,
            external_uid,
            identity_id: Some(identity_id),
            correlation_matches: vec![],
        }
    }

    /// Create a result indicating a discrepancy.
    #[must_use]
    pub fn discrepancy(
        discrepancy_type: DiscrepancyType,
        external_uid: String,
        identity_id: Option<Uuid>,
    ) -> Self {
        Self {
            discrepancy_type: Some(discrepancy_type),
            mismatched_attributes: None,
            external_uid,
            identity_id,
            correlation_matches: vec![],
        }
    }

    /// Create a result indicating a mismatch with attribute differences.
    #[must_use]
    pub fn mismatch(
        external_uid: String,
        identity_id: Uuid,
        mismatched_attributes: MismatchedAttributes,
    ) -> Self {
        Self {
            discrepancy_type: Some(DiscrepancyType::Mismatch),
            mismatched_attributes: Some(mismatched_attributes),
            external_uid,
            identity_id: Some(identity_id),
            correlation_matches: vec![],
        }
    }

    /// Check if this is a match (no discrepancy).
    #[must_use]
    pub fn is_match(&self) -> bool {
        self.discrepancy_type.is_none()
    }

    /// Check if this is a collision (multiple matches).
    #[must_use]
    pub fn is_collision(&self) -> bool {
        matches!(self.discrepancy_type, Some(DiscrepancyType::Collision))
    }
}

/// Represents mismatched attributes between xavyo and target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchedAttributes {
    /// Map of attribute name to values (xavyo vs target).
    #[serde(flatten)]
    pub attributes: HashMap<String, AttributeDifference>,
}

impl MismatchedAttributes {
    /// Create new empty mismatched attributes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute difference.
    pub fn add(&mut self, name: String, xavyo_value: Option<String>, target_value: Option<String>) {
        self.attributes.insert(
            name,
            AttributeDifference {
                xavyo: xavyo_value,
                target: target_value,
            },
        );
    }

    /// Check if there are any mismatches.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    /// Get the number of mismatched attributes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Get attribute names.
    #[must_use]
    pub fn attribute_names(&self) -> Vec<&String> {
        self.attributes.keys().collect()
    }
}

impl Default for MismatchedAttributes {
    fn default() -> Self {
        Self::new()
    }
}

/// Difference between xavyo and target attribute values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDifference {
    /// Value in xavyo.
    pub xavyo: Option<String>,
    /// Value in target system.
    pub target: Option<String>,
}

/// Correlation match information.
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    /// Matched identity ID.
    pub identity_id: Uuid,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Rules that matched.
    pub matched_rules: Vec<String>,
}

/// Comparator for reconciliation.
pub struct AccountComparator {
    /// Attributes to compare (mapped names).
    comparison_attributes: HashSet<String>,
    /// Whether to ignore case in comparisons.
    ignore_case: bool,
}

impl AccountComparator {
    /// Create a new comparator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            comparison_attributes: HashSet::new(),
            ignore_case: true,
        }
    }

    /// Add attributes to compare.
    #[must_use]
    pub fn with_attributes(mut self, attributes: Vec<String>) -> Self {
        self.comparison_attributes = attributes.into_iter().collect();
        self
    }

    /// Set case sensitivity.
    #[must_use]
    pub fn with_case_sensitivity(mut self, case_sensitive: bool) -> Self {
        self.ignore_case = !case_sensitive;
        self
    }

    /// Compare target account attributes with xavyo identity attributes.
    ///
    /// Returns None if attributes match, Some(MismatchedAttributes) if they differ.
    #[must_use]
    pub fn compare_attributes(
        &self,
        xavyo_attrs: &JsonValue,
        target_attrs: &JsonValue,
    ) -> Option<MismatchedAttributes> {
        let mut mismatches = MismatchedAttributes::new();

        // If no comparison attributes specified, compare all common attributes
        let attrs_to_compare: Vec<String> = if self.comparison_attributes.is_empty() {
            self.collect_all_keys(xavyo_attrs, target_attrs)
        } else {
            self.comparison_attributes.iter().cloned().collect()
        };

        for attr in attrs_to_compare {
            let xavyo_val = self.extract_string_value(xavyo_attrs, &attr);
            let target_val = self.extract_string_value(target_attrs, &attr);

            if !self.values_equal(&xavyo_val, &target_val) {
                mismatches.add(attr, xavyo_val, target_val);
            }
        }

        if mismatches.is_empty() {
            None
        } else {
            Some(mismatches)
        }
    }

    /// Check if two values are equal (considering case sensitivity).
    fn values_equal(&self, val1: &Option<String>, val2: &Option<String>) -> bool {
        match (val1, val2) {
            (None, None) => true,
            (Some(v1), Some(v2)) => {
                if self.ignore_case {
                    v1.eq_ignore_ascii_case(v2)
                } else {
                    v1 == v2
                }
            }
            _ => false,
        }
    }

    /// Extract string value from JSON.
    fn extract_string_value(&self, json: &JsonValue, key: &str) -> Option<String> {
        json.get(key).and_then(|v| match v {
            JsonValue::String(s) => Some(s.clone()),
            JsonValue::Number(n) => Some(n.to_string()),
            JsonValue::Bool(b) => Some(b.to_string()),
            JsonValue::Null => None,
            _ => Some(v.to_string()),
        })
    }

    /// Collect all keys from both JSON objects.
    fn collect_all_keys(&self, json1: &JsonValue, json2: &JsonValue) -> Vec<String> {
        let mut keys: HashSet<String> = HashSet::new();

        if let Some(obj) = json1.as_object() {
            keys.extend(obj.keys().cloned());
        }
        if let Some(obj) = json2.as_object() {
            keys.extend(obj.keys().cloned());
        }

        keys.into_iter().collect()
    }
}

impl Default for AccountComparator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_comparison_result_matched() {
        let result = ComparisonResult::matched("uid=test".to_string(), Uuid::new_v4());
        assert!(result.is_match());
        assert!(!result.is_collision());
        assert!(result.discrepancy_type.is_none());
    }

    #[test]
    fn test_comparison_result_discrepancy() {
        let result =
            ComparisonResult::discrepancy(DiscrepancyType::Orphan, "uid=test".to_string(), None);
        assert!(!result.is_match());
        assert!(!result.is_collision());
        assert_eq!(result.discrepancy_type, Some(DiscrepancyType::Orphan));
    }

    #[test]
    fn test_comparison_result_collision() {
        let result =
            ComparisonResult::discrepancy(DiscrepancyType::Collision, "uid=test".to_string(), None);
        assert!(!result.is_match());
        assert!(result.is_collision());
    }

    #[test]
    fn test_mismatched_attributes() {
        let mut mismatches = MismatchedAttributes::new();
        assert!(mismatches.is_empty());
        assert_eq!(mismatches.len(), 0);

        mismatches.add(
            "email".to_string(),
            Some("john@company.com".to_string()),
            Some("jdoe@company.com".to_string()),
        );
        assert!(!mismatches.is_empty());
        assert_eq!(mismatches.len(), 1);

        let names = mismatches.attribute_names();
        assert!(names.contains(&&"email".to_string()));
    }

    #[test]
    fn test_comparator_matching_attributes() {
        let comparator =
            AccountComparator::new().with_attributes(vec!["email".to_string(), "name".to_string()]);

        let xavyo = json!({
            "email": "john@company.com",
            "name": "John Doe"
        });
        let target = json!({
            "email": "john@company.com",
            "name": "John Doe"
        });

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_none());
    }

    #[test]
    fn test_comparator_mismatching_attributes() {
        let comparator = AccountComparator::new()
            .with_attributes(vec!["email".to_string(), "department".to_string()]);

        let xavyo = json!({
            "email": "john@company.com",
            "department": "Engineering"
        });
        let target = json!({
            "email": "jdoe@company.com",
            "department": "IT"
        });

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_some());

        let mismatches = result.unwrap();
        assert_eq!(mismatches.len(), 2);
        assert!(mismatches.attributes.contains_key("email"));
        assert!(mismatches.attributes.contains_key("department"));
    }

    #[test]
    fn test_comparator_case_insensitive() {
        let comparator = AccountComparator::new().with_attributes(vec!["email".to_string()]);

        let xavyo = json!({ "email": "John@Company.com" });
        let target = json!({ "email": "john@company.com" });

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_none()); // Should match because ignore_case is true by default
    }

    #[test]
    fn test_comparator_case_sensitive() {
        let comparator = AccountComparator::new()
            .with_attributes(vec!["email".to_string()])
            .with_case_sensitivity(true);

        let xavyo = json!({ "email": "John@Company.com" });
        let target = json!({ "email": "john@company.com" });

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_some()); // Should not match because case sensitive
    }

    #[test]
    fn test_comparator_missing_attribute() {
        let comparator = AccountComparator::new()
            .with_attributes(vec!["email".to_string(), "phone".to_string()]);

        let xavyo = json!({ "email": "john@company.com", "phone": "123-456" });
        let target = json!({ "email": "john@company.com" }); // phone missing

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_some());

        let mismatches = result.unwrap();
        assert_eq!(mismatches.len(), 1);
        assert!(mismatches.attributes.contains_key("phone"));
    }

    #[test]
    fn test_comparator_null_values() {
        let comparator = AccountComparator::new().with_attributes(vec!["email".to_string()]);

        let xavyo = json!({ "email": null });
        let target = json!({ "email": null });

        let result = comparator.compare_attributes(&xavyo, &target);
        assert!(result.is_none()); // Both null should match
    }

    #[test]
    fn test_mismatched_attributes_serialization() {
        let mut mismatches = MismatchedAttributes::new();
        mismatches.add(
            "email".to_string(),
            Some("john@company.com".to_string()),
            Some("jdoe@company.com".to_string()),
        );

        let json = serde_json::to_string(&mismatches).unwrap();
        let deserialized: MismatchedAttributes = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.len(), 1);
        assert!(deserialized.attributes.contains_key("email"));
    }
}
