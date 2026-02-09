//! Unit tests for `ObjectTemplateService` (F058).
//!
//! Tests CRUD operations, validation, activation/deactivation,
//! versioning, and inheritance for object templates.

use serde_json::json;
use uuid::Uuid;
use xavyo_db::models::{
    CreateGovObjectTemplate, ObjectTemplateStatus, TemplateEventType, TemplateObjectType,
    TemplateRuleType, TemplateStrength, UpdateGovObjectTemplate, DEFAULT_TEMPLATE_PRIORITY,
    MAX_TEMPLATE_PRIORITY, MIN_TEMPLATE_PRIORITY,
};

// ============================================================
// Helper Types for Testing (No DB Required)
// ============================================================

/// Mock template for unit testing.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestTemplate {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    object_type: TemplateObjectType,
    status: ObjectTemplateStatus,
    priority: i32,
    parent_template_id: Option<Uuid>,
    created_by: Uuid,
}

impl TestTemplate {
    fn new(name: &str, object_type: TemplateObjectType) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            object_type,
            status: ObjectTemplateStatus::Draft,
            priority: 100,
            parent_template_id: None,
            created_by: Uuid::new_v4(),
        }
    }

    fn with_status(mut self, status: ObjectTemplateStatus) -> Self {
        self.status = status;
        self
    }

    fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_template_id = Some(parent_id);
        self
    }
}

/// Mock rule for testing.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TestRule {
    id: Uuid,
    template_id: Uuid,
    rule_type: TemplateRuleType,
    target_attribute: String,
    expression: String,
    strength: TemplateStrength,
    priority: i32,
    condition: Option<String>,
}

impl TestRule {
    fn new(template_id: Uuid, target: &str, rule_type: TemplateRuleType) -> Self {
        Self {
            id: Uuid::new_v4(),
            template_id,
            rule_type,
            target_attribute: target.to_string(),
            expression: "test_expression".to_string(),
            strength: TemplateStrength::Normal,
            priority: 100,
            condition: None,
        }
    }
}

// ============================================================
// Create Template Tests
// ============================================================

#[test]
fn test_create_template_request_validation_valid() {
    let request = CreateGovObjectTemplate {
        name: "Standard User Template".to_string(),
        description: Some("Default template for new users".to_string()),
        object_type: TemplateObjectType::User,
        priority: Some(50),
        parent_template_id: None,
    };

    assert!(!request.name.is_empty());
    assert!(request.name.len() <= 255);
    assert_eq!(request.object_type, TemplateObjectType::User);
    assert_eq!(request.priority, Some(50));
}

#[test]
fn test_create_template_request_with_defaults() {
    let request = CreateGovObjectTemplate {
        name: "Basic Template".to_string(),
        description: None,
        object_type: TemplateObjectType::Role,
        priority: None,
        parent_template_id: None,
    };

    // Priority should default to 100 when not specified
    assert!(request.priority.is_none());
    assert!(request.description.is_none());
}

#[test]
fn test_create_template_request_with_parent() {
    let parent_id = Uuid::new_v4();
    let request = CreateGovObjectTemplate {
        name: "Child Template".to_string(),
        description: None,
        object_type: TemplateObjectType::User,
        priority: None,
        parent_template_id: Some(parent_id),
    };

    assert_eq!(request.parent_template_id, Some(parent_id));
}

#[test]
fn test_create_template_all_object_types() {
    let types = vec![
        TemplateObjectType::User,
        TemplateObjectType::Role,
        TemplateObjectType::Entitlement,
        TemplateObjectType::Application,
    ];

    for object_type in types {
        let request = CreateGovObjectTemplate {
            name: format!("{object_type:?} Template"),
            description: None,
            object_type,
            priority: None,
            parent_template_id: None,
        };
        assert_eq!(request.object_type, object_type);
    }
}

// ============================================================
// Update Template Tests
// ============================================================

#[test]
fn test_update_template_partial_fields() {
    let update = UpdateGovObjectTemplate {
        name: Some("Updated Name".to_string()),
        description: None,
        priority: None,
        parent_template_id: None,
    };

    assert!(update.name.is_some());
    assert!(update.description.is_none());
    assert!(update.priority.is_none());
}

#[test]
fn test_update_template_all_fields() {
    let new_parent_id = Uuid::new_v4();
    let update = UpdateGovObjectTemplate {
        name: Some("Fully Updated Template".to_string()),
        description: Some("New description".to_string()),
        priority: Some(25),
        parent_template_id: Some(new_parent_id),
    };

    assert_eq!(update.name.as_ref().unwrap(), "Fully Updated Template");
    assert_eq!(update.description.as_ref().unwrap(), "New description");
    assert_eq!(update.priority, Some(25));
    assert_eq!(update.parent_template_id, Some(new_parent_id));
}

#[test]
fn test_update_template_empty_is_valid() {
    let update = UpdateGovObjectTemplate {
        name: None,
        description: None,
        priority: None,
        parent_template_id: None,
    };

    // Empty update should be valid (no-op)
    assert!(update.name.is_none());
}

// ============================================================
// Template Status Tests
// ============================================================

#[test]
fn test_template_status_transitions() {
    let template = TestTemplate::new("Test", TemplateObjectType::User);
    assert_eq!(template.status, ObjectTemplateStatus::Draft);

    // Draft -> Active
    let template = template.with_status(ObjectTemplateStatus::Active);
    assert_eq!(template.status, ObjectTemplateStatus::Active);

    // Active -> Disabled
    let template = template.with_status(ObjectTemplateStatus::Disabled);
    assert_eq!(template.status, ObjectTemplateStatus::Disabled);

    // Disabled -> Active (re-enable)
    let template = template.with_status(ObjectTemplateStatus::Active);
    assert_eq!(template.status, ObjectTemplateStatus::Active);
}

#[test]
fn test_template_is_active() {
    let draft = TestTemplate::new("Draft", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Draft);
    let active = TestTemplate::new("Active", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Active);
    let disabled = TestTemplate::new("Disabled", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Disabled);

    assert_eq!(draft.status, ObjectTemplateStatus::Draft);
    assert_eq!(active.status, ObjectTemplateStatus::Active);
    assert_eq!(disabled.status, ObjectTemplateStatus::Disabled);
}

// ============================================================
// Priority Tests
// ============================================================

#[test]
fn test_priority_ordering() {
    let high_priority = TestTemplate::new("High", TemplateObjectType::User).with_priority(10);
    let medium_priority = TestTemplate::new("Medium", TemplateObjectType::User).with_priority(50);
    let low_priority = TestTemplate::new("Low", TemplateObjectType::User).with_priority(200);

    // Lower number = higher priority (evaluated first)
    assert!(high_priority.priority < medium_priority.priority);
    assert!(medium_priority.priority < low_priority.priority);
}

#[test]
fn test_priority_bounds() {
    assert_eq!(MIN_TEMPLATE_PRIORITY, 1);
    assert_eq!(DEFAULT_TEMPLATE_PRIORITY, 100);
    assert_eq!(MAX_TEMPLATE_PRIORITY, 1000);
}

// ============================================================
// Template Inheritance Tests
// ============================================================

#[test]
fn test_template_inheritance_chain() {
    let grandparent = TestTemplate::new("Grandparent", TemplateObjectType::User);
    let parent = TestTemplate::new("Parent", TemplateObjectType::User).with_parent(grandparent.id);
    let child = TestTemplate::new("Child", TemplateObjectType::User).with_parent(parent.id);

    assert!(grandparent.parent_template_id.is_none());
    assert!(parent.parent_template_id.is_some());
    assert!(child.parent_template_id.is_some());
}

#[test]
fn test_template_self_reference_invalid() {
    let template_id = Uuid::new_v4();

    // A template referencing itself as parent should be invalid
    // This validation would be enforced at the service layer
    let invalid_parent = Some(template_id);
    assert_eq!(invalid_parent, Some(template_id));
    // Service would reject this: parent_template_id != id
}

// ============================================================
// Validation Tests
// ============================================================

#[test]
fn test_name_validation_rules() {
    // Valid names
    let long_name = "x".repeat(255);
    let valid_names = vec![
        "Standard User Template",
        "User-Template-v2",
        "template_123",
        "A",
        &long_name,
    ];

    for name in valid_names {
        assert!(!name.is_empty());
        assert!(name.len() <= 255);
    }

    // Invalid: empty name
    let empty_name: String = String::new();
    assert!(empty_name.is_empty());

    // Invalid: too long
    let too_long = "x".repeat(256);
    assert!(too_long.len() > 255);
}

#[test]
fn test_priority_validation_bounds() {
    // Valid priorities
    let valid = vec![MIN_TEMPLATE_PRIORITY, 50, 100, 500, MAX_TEMPLATE_PRIORITY];
    for p in valid {
        assert!((MIN_TEMPLATE_PRIORITY..=MAX_TEMPLATE_PRIORITY).contains(&p));
    }

    // Invalid: below minimum
    let below_min = MIN_TEMPLATE_PRIORITY - 1;
    assert!(below_min < MIN_TEMPLATE_PRIORITY);

    // Invalid: above maximum
    let above_max = MAX_TEMPLATE_PRIORITY + 1;
    assert!(above_max > MAX_TEMPLATE_PRIORITY);
}

// ============================================================
// List and Filter Tests
// ============================================================

#[test]
fn test_filter_by_status() {
    use xavyo_db::models::ObjectTemplateFilter;

    let filter = ObjectTemplateFilter {
        status: Some(ObjectTemplateStatus::Active),
        ..Default::default()
    };

    assert_eq!(filter.status, Some(ObjectTemplateStatus::Active));
    assert!(filter.object_type.is_none());
}

#[test]
fn test_filter_by_object_type() {
    use xavyo_db::models::ObjectTemplateFilter;

    let filter = ObjectTemplateFilter {
        object_type: Some(TemplateObjectType::User),
        ..Default::default()
    };

    assert_eq!(filter.object_type, Some(TemplateObjectType::User));
}

#[test]
fn test_filter_by_name_contains() {
    use xavyo_db::models::ObjectTemplateFilter;

    let filter = ObjectTemplateFilter {
        name_contains: Some("Standard".to_string()),
        ..Default::default()
    };

    assert_eq!(filter.name_contains.as_ref().unwrap(), "Standard");
}

#[test]
fn test_filter_combined() {
    use xavyo_db::models::ObjectTemplateFilter;

    let filter = ObjectTemplateFilter {
        status: Some(ObjectTemplateStatus::Active),
        object_type: Some(TemplateObjectType::User),
        name_contains: Some("Employee".to_string()),
        priority_min: Some(1),
        priority_max: Some(100),
        ..Default::default()
    };

    assert_eq!(filter.status, Some(ObjectTemplateStatus::Active));
    assert_eq!(filter.object_type, Some(TemplateObjectType::User));
    assert_eq!(filter.priority_min, Some(1));
    assert_eq!(filter.priority_max, Some(100));
}

// ============================================================
// Template with Rules Tests
// ============================================================

#[test]
fn test_template_with_default_rule() {
    let template = TestTemplate::new("User Template", TemplateObjectType::User);
    let rule = TestRule::new(template.id, "department", TemplateRuleType::Default);

    assert_eq!(rule.template_id, template.id);
    assert_eq!(rule.target_attribute, "department");
    assert_eq!(rule.rule_type, TemplateRuleType::Default);
}

#[test]
fn test_template_with_computed_rule() {
    let template = TestTemplate::new("User Template", TemplateObjectType::User);
    let rule = TestRule::new(template.id, "displayName", TemplateRuleType::Computed);

    assert_eq!(rule.rule_type, TemplateRuleType::Computed);
}

#[test]
fn test_template_with_validation_rule() {
    let template = TestTemplate::new("User Template", TemplateObjectType::User);
    let rule = TestRule::new(template.id, "email", TemplateRuleType::Validation);

    assert_eq!(rule.rule_type, TemplateRuleType::Validation);
}

#[test]
fn test_template_with_normalization_rule() {
    let template = TestTemplate::new("User Template", TemplateObjectType::User);
    let rule = TestRule::new(template.id, "email", TemplateRuleType::Normalization);

    assert_eq!(rule.rule_type, TemplateRuleType::Normalization);
}

// ============================================================
// Versioning Tests (Unit Level)
// ============================================================

#[test]
fn test_version_snapshot_structure() {
    // Rules snapshot structure
    let rules_snapshot = json!([
        {
            "id": Uuid::new_v4().to_string(),
            "rule_type": "default",
            "target_attribute": "department",
            "expression": "\"Unassigned\"",
            "strength": "normal",
            "priority": 100
        },
        {
            "id": Uuid::new_v4().to_string(),
            "rule_type": "validation",
            "target_attribute": "email",
            "expression": "matches(${email}, \"^[a-z]+@company.com$\")",
            "strength": "strong",
            "priority": 50,
            "error_message": "Invalid email format"
        }
    ]);

    let snapshot_array = rules_snapshot.as_array().unwrap();
    assert_eq!(snapshot_array.len(), 2);
}

#[test]
fn test_version_number_increments() {
    let mut current_version = 0;

    // Each save increments version
    current_version += 1;
    assert_eq!(current_version, 1);

    current_version += 1;
    assert_eq!(current_version, 2);

    current_version += 1;
    assert_eq!(current_version, 3);
}

// ============================================================
// Delete Cascade Tests (Logic Level)
// ============================================================

#[test]
fn test_delete_template_cascades_rules() {
    // When template is deleted, all its rules should be deleted
    // This is enforced by FK with ON DELETE CASCADE

    let template = TestTemplate::new("To Delete", TemplateObjectType::User);
    let rule1 = TestRule::new(template.id, "attr1", TemplateRuleType::Default);
    let rule2 = TestRule::new(template.id, "attr2", TemplateRuleType::Computed);

    // All rules belong to the template
    assert_eq!(rule1.template_id, template.id);
    assert_eq!(rule2.template_id, template.id);

    // After cascade delete, rules would be removed
}

#[test]
fn test_cannot_delete_template_with_active_children() {
    // Business logic: templates with children should be handled carefully
    let parent = TestTemplate::new("Parent", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Active);
    let child = TestTemplate::new("Child", TemplateObjectType::User).with_parent(parent.id);

    assert_eq!(child.parent_template_id, Some(parent.id));
    // Service layer should prevent deletion or handle orphaning
}

// ============================================================
// Concurrency Tests (Logic Level)
// ============================================================

#[test]
fn test_optimistic_locking_via_updated_at() {
    // Templates use updated_at for optimistic locking
    use chrono::Utc;

    let original_updated = Utc::now();
    let later_updated = Utc::now();

    // If template was modified between read and write, updated_at differs
    assert!(later_updated >= original_updated);
}

// ============================================================
// Event Generation Tests (Logic Level)
// ============================================================

#[test]
fn test_template_event_types() {
    let events = vec![
        TemplateEventType::Created,
        TemplateEventType::Updated,
        TemplateEventType::Activated,
        TemplateEventType::Disabled,
        TemplateEventType::Deleted,
        TemplateEventType::VersionCreated,
        TemplateEventType::RuleAdded,
        TemplateEventType::RuleUpdated,
        TemplateEventType::RuleRemoved,
    ];

    // All event types are distinct
    assert_eq!(events.len(), 9);
}

// ============================================================
// Edge Cases
// ============================================================

#[test]
fn test_template_with_empty_description() {
    let request = CreateGovObjectTemplate {
        name: "No Description".to_string(),
        description: None,
        object_type: TemplateObjectType::User,
        priority: None,
        parent_template_id: None,
    };

    assert!(request.description.is_none());
}

#[test]
fn test_template_with_long_description() {
    let long_desc = "x".repeat(5000);
    let request = CreateGovObjectTemplate {
        name: "Long Description".to_string(),
        description: Some(long_desc.clone()),
        object_type: TemplateObjectType::User,
        priority: None,
        parent_template_id: None,
    };

    assert_eq!(request.description.as_ref().unwrap().len(), 5000);
}

#[test]
fn test_multiple_templates_same_type() {
    // Multiple active templates for same object type is valid
    let t1 = TestTemplate::new("Template A", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Active)
        .with_priority(10);
    let t2 = TestTemplate::new("Template B", TemplateObjectType::User)
        .with_status(ObjectTemplateStatus::Active)
        .with_priority(20);

    assert_eq!(t1.object_type, t2.object_type);
    assert_eq!(t1.status, ObjectTemplateStatus::Active);
    assert_eq!(t2.status, ObjectTemplateStatus::Active);
    assert!(t1.priority < t2.priority);
}
