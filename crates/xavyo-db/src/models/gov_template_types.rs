//! Shared enum types for object template management (F058).

#![allow(clippy::derivable_impls)]

use serde::{Deserialize, Serialize};
use sqlx::Type;

/// Object types that templates can target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_object_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TemplateObjectType {
    /// User objects.
    User,
    /// Role objects.
    Role,
    /// Entitlement objects.
    Entitlement,
    /// Application objects.
    Application,
}

impl std::fmt::Display for TemplateObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Role => write!(f, "role"),
            Self::Entitlement => write!(f, "entitlement"),
            Self::Application => write!(f, "application"),
        }
    }
}

/// Object template lifecycle status (named distinctly from report `TemplateStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_object_template_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ObjectTemplateStatus {
    /// Template is being configured, not yet applied.
    Draft,
    /// Template is actively applied to matching objects.
    Active,
    /// Template is temporarily disabled.
    Disabled,
}

impl Default for ObjectTemplateStatus {
    fn default() -> Self {
        Self::Draft
    }
}

impl std::fmt::Display for ObjectTemplateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Active => write!(f, "active"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Rule types for template rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_rule_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TemplateRuleType {
    /// Static default value.
    Default,
    /// Computed from expression using other attributes.
    Computed,
    /// Validation check that must pass.
    Validation,
    /// Transform/normalize value.
    Normalization,
}

impl std::fmt::Display for TemplateRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "default"),
            Self::Computed => write!(f, "computed"),
            Self::Validation => write!(f, "validation"),
            Self::Normalization => write!(f, "normalization"),
        }
    }
}

/// Mapping strength for rules (IGA-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_strength", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TemplateStrength {
    /// Always enforced, cannot be overridden by user.
    Strong,
    /// Applied unless user explicitly sets a different value.
    Normal,
    /// Only applied if target attribute is empty/null.
    Weak,
}

impl Default for TemplateStrength {
    fn default() -> Self {
        Self::Normal
    }
}

impl std::fmt::Display for TemplateStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strong => write!(f, "strong"),
            Self::Normal => write!(f, "normal"),
            Self::Weak => write!(f, "weak"),
        }
    }
}

/// Scope types for template matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_scope_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TemplateScopeType {
    /// Applies to all objects of the type.
    Global,
    /// Applies to objects in a specific organization.
    Organization,
    /// Applies to objects with a specific category/type.
    Category,
    /// Applies when a condition expression matches.
    Condition,
}

impl std::fmt::Display for TemplateScopeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Organization => write!(f, "organization"),
            Self::Category => write!(f, "category"),
            Self::Condition => write!(f, "condition"),
        }
    }
}

/// Merge strategies for multi-source data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_merge_strategy", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateMergeStrategy {
    /// Ordered source priority list determines winner.
    SourcePrecedence,
    /// Most recent timestamp wins.
    TimestampWins,
    /// Combine all unique values (for multi-valued attributes).
    ConcatenateUnique,
    /// First non-null value is preserved.
    FirstWins,
    /// Only accept manual changes, reject automated sources.
    ManualOnly,
}

impl Default for TemplateMergeStrategy {
    fn default() -> Self {
        Self::SourcePrecedence
    }
}

impl std::fmt::Display for TemplateMergeStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourcePrecedence => write!(f, "source_precedence"),
            Self::TimestampWins => write!(f, "timestamp_wins"),
            Self::ConcatenateUnique => write!(f, "concatenate_unique"),
            Self::FirstWins => write!(f, "first_wins"),
            Self::ManualOnly => write!(f, "manual_only"),
        }
    }
}

/// Null handling options for merge policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_null_handling", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateNullHandling {
    /// Null means no value to merge (skip null sources).
    Merge,
    /// Null is treated as explicit empty (preserves null).
    PreserveEmpty,
}

impl Default for TemplateNullHandling {
    fn default() -> Self {
        Self::Merge
    }
}

impl std::fmt::Display for TemplateNullHandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Merge => write!(f, "merge"),
            Self::PreserveEmpty => write!(f, "preserve_empty"),
        }
    }
}

/// Time reference type for rule time constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_time_reference", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateTimeReference {
    /// Use `time_from/time_to` as absolute timestamps.
    #[default]
    Absolute,
    /// Interpret as offset from object creation time.
    RelativeToCreation,
}

impl std::fmt::Display for TemplateTimeReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absolute => write!(f, "absolute"),
            Self::RelativeToCreation => write!(f, "relative_to_creation"),
        }
    }
}

/// Operation types for template application events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "gov_template_operation", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TemplateOperation {
    /// Template applied during object creation.
    Create,
    /// Template applied during object update.
    Update,
}

impl std::fmt::Display for TemplateOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Update => write!(f, "update"),
        }
    }
}

/// Event types for template modification audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_template_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum TemplateEventType {
    /// Template was created.
    Created,
    /// Template was updated.
    Updated,
    /// Template was activated.
    Activated,
    /// Template was disabled.
    Disabled,
    /// Template was deleted.
    Deleted,
    /// A new version was created.
    VersionCreated,
    /// A rule was added to the template.
    RuleAdded,
    /// A rule was updated in the template.
    RuleUpdated,
    /// A rule was removed from the template.
    RuleRemoved,
    /// A scope was added to the template.
    ScopeAdded,
    /// A scope was removed from the template.
    ScopeRemoved,
    /// A merge policy was added to the template.
    MergePolicyAdded,
    /// A merge policy was updated in the template.
    MergePolicyUpdated,
    /// A merge policy was removed from the template.
    MergePolicyRemoved,
}

impl std::fmt::Display for TemplateEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Updated => write!(f, "updated"),
            Self::Activated => write!(f, "activated"),
            Self::Disabled => write!(f, "disabled"),
            Self::Deleted => write!(f, "deleted"),
            Self::VersionCreated => write!(f, "version_created"),
            Self::RuleAdded => write!(f, "rule_added"),
            Self::RuleUpdated => write!(f, "rule_updated"),
            Self::RuleRemoved => write!(f, "rule_removed"),
            Self::ScopeAdded => write!(f, "scope_added"),
            Self::ScopeRemoved => write!(f, "scope_removed"),
            Self::MergePolicyAdded => write!(f, "merge_policy_added"),
            Self::MergePolicyUpdated => write!(f, "merge_policy_updated"),
            Self::MergePolicyRemoved => write!(f, "merge_policy_removed"),
        }
    }
}

/// Built-in functions supported in template expressions.
pub const SUPPORTED_FUNCTIONS: &[&str] = &[
    "lowercase",
    "uppercase",
    "trim",
    "matches",
    "length",
    "substring",
    "concat",
    "replace",
    "split",
    "join",
    "contains",
    "starts_with",
    "ends_with",
    "is_empty",
    "is_null",
    "coalesce",
    "if",
];

/// Standard attributes available for user objects.
pub const USER_ATTRIBUTES: &[&str] = &[
    "id",
    "email",
    "username",
    "first_name",
    "last_name",
    "display_name",
    "department",
    "title",
    "manager_id",
    "employee_number",
    "employee_type",
    "location",
    "phone",
    "status",
    "created_at",
    "updated_at",
];

/// Standard attributes available for role objects.
pub const ROLE_ATTRIBUTES: &[&str] = &[
    "id",
    "name",
    "description",
    "owner_id",
    "risk_level",
    "application_id",
    "is_delegable",
    "status",
    "created_at",
    "updated_at",
];

/// Standard attributes available for entitlement objects.
pub const ENTITLEMENT_ATTRIBUTES: &[&str] = &[
    "id",
    "name",
    "description",
    "application_id",
    "entitlement_type",
    "risk_level",
    "status",
    "created_at",
    "updated_at",
];

/// Standard attributes available for application objects.
pub const APPLICATION_ATTRIBUTES: &[&str] = &[
    "id",
    "name",
    "description",
    "owner_id",
    "risk_level",
    "status",
    "created_at",
    "updated_at",
];

impl TemplateObjectType {
    /// Returns the standard attributes for this object type.
    #[must_use]
    pub fn standard_attributes(&self) -> &'static [&'static str] {
        match self {
            Self::User => USER_ATTRIBUTES,
            Self::Role => ROLE_ATTRIBUTES,
            Self::Entitlement => ENTITLEMENT_ATTRIBUTES,
            Self::Application => APPLICATION_ATTRIBUTES,
        }
    }

    /// Validates that an attribute is valid for this object type.
    #[must_use]
    pub fn is_valid_attribute(&self, attr: &str) -> bool {
        self.standard_attributes().contains(&attr)
    }
}

impl TemplateStrength {
    /// Returns the precedence of this strength (higher = stronger).
    #[must_use]
    pub fn precedence(&self) -> i32 {
        match self {
            Self::Strong => 3,
            Self::Normal => 2,
            Self::Weak => 1,
        }
    }

    /// Returns true if this strength overrides another.
    #[must_use]
    pub fn overrides(&self, other: &Self) -> bool {
        self.precedence() > other.precedence()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_status_default() {
        assert_eq!(ObjectTemplateStatus::default(), ObjectTemplateStatus::Draft);
    }

    #[test]
    fn test_template_strength_default() {
        assert_eq!(TemplateStrength::default(), TemplateStrength::Normal);
    }

    #[test]
    fn test_template_strength_precedence() {
        assert_eq!(TemplateStrength::Strong.precedence(), 3);
        assert_eq!(TemplateStrength::Normal.precedence(), 2);
        assert_eq!(TemplateStrength::Weak.precedence(), 1);
    }

    #[test]
    fn test_template_strength_overrides() {
        assert!(TemplateStrength::Strong.overrides(&TemplateStrength::Normal));
        assert!(TemplateStrength::Strong.overrides(&TemplateStrength::Weak));
        assert!(TemplateStrength::Normal.overrides(&TemplateStrength::Weak));
        assert!(!TemplateStrength::Weak.overrides(&TemplateStrength::Normal));
        assert!(!TemplateStrength::Normal.overrides(&TemplateStrength::Strong));
    }

    #[test]
    fn test_template_object_type_attributes() {
        assert!(TemplateObjectType::User.is_valid_attribute("email"));
        assert!(TemplateObjectType::User.is_valid_attribute("department"));
        assert!(!TemplateObjectType::User.is_valid_attribute("invalid_attr"));

        assert!(TemplateObjectType::Role.is_valid_attribute("risk_level"));
        assert!(TemplateObjectType::Entitlement.is_valid_attribute("application_id"));
        assert!(TemplateObjectType::Application.is_valid_attribute("owner_id"));
    }

    #[test]
    fn test_merge_strategy_default() {
        assert_eq!(
            TemplateMergeStrategy::default(),
            TemplateMergeStrategy::SourcePrecedence
        );
    }

    #[test]
    fn test_null_handling_default() {
        assert_eq!(TemplateNullHandling::default(), TemplateNullHandling::Merge);
    }

    #[test]
    fn test_template_object_type_display() {
        assert_eq!(TemplateObjectType::User.to_string(), "user");
        assert_eq!(TemplateObjectType::Role.to_string(), "role");
        assert_eq!(TemplateObjectType::Entitlement.to_string(), "entitlement");
        assert_eq!(TemplateObjectType::Application.to_string(), "application");
    }

    #[test]
    fn test_template_status_display() {
        assert_eq!(ObjectTemplateStatus::Draft.to_string(), "draft");
        assert_eq!(ObjectTemplateStatus::Active.to_string(), "active");
        assert_eq!(ObjectTemplateStatus::Disabled.to_string(), "disabled");
    }

    #[test]
    fn test_template_rule_type_display() {
        assert_eq!(TemplateRuleType::Default.to_string(), "default");
        assert_eq!(TemplateRuleType::Computed.to_string(), "computed");
        assert_eq!(TemplateRuleType::Validation.to_string(), "validation");
        assert_eq!(TemplateRuleType::Normalization.to_string(), "normalization");
    }

    #[test]
    fn test_template_event_type_display() {
        assert_eq!(TemplateEventType::Created.to_string(), "created");
        assert_eq!(TemplateEventType::RuleAdded.to_string(), "rule_added");
        assert_eq!(
            TemplateEventType::MergePolicyUpdated.to_string(),
            "merge_policy_updated"
        );
    }
}
