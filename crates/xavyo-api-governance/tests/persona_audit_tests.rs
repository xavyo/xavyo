//! Unit tests for `PersonaAuditService` search and reporting (F063 - T077).

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_db::models::{
    ArchetypeEventData, AttributesPropagatedEventData, ContextSwitchedEventData,
    PersonaAuditEventFilter, PersonaAuditEventType, PersonaCreatedEventData,
};

/// Test audit event filter defaults to empty (no filtering).
#[test]
fn test_audit_filter_default() {
    let filter = PersonaAuditEventFilter::default();
    assert!(filter.persona_id.is_none());
    assert!(filter.archetype_id.is_none());
    assert!(filter.event_type.is_none());
    assert!(filter.actor_id.is_none());
    assert!(filter.from_date.is_none());
    assert!(filter.to_date.is_none());
}

/// Test audit filter with `persona_id` set.
#[test]
fn test_audit_filter_by_persona() {
    let persona_id = Uuid::new_v4();
    let filter = PersonaAuditEventFilter {
        persona_id: Some(persona_id),
        ..Default::default()
    };
    assert_eq!(filter.persona_id, Some(persona_id));
    assert!(filter.archetype_id.is_none());
}

/// Test audit filter with `archetype_id` set.
#[test]
fn test_audit_filter_by_archetype() {
    let archetype_id = Uuid::new_v4();
    let filter = PersonaAuditEventFilter {
        archetype_id: Some(archetype_id),
        ..Default::default()
    };
    assert_eq!(filter.archetype_id, Some(archetype_id));
}

/// Test audit filter by event type.
#[test]
fn test_audit_filter_by_event_type() {
    let filter = PersonaAuditEventFilter {
        event_type: Some(PersonaAuditEventType::PersonaCreated),
        ..Default::default()
    };
    assert_eq!(
        filter.event_type,
        Some(PersonaAuditEventType::PersonaCreated)
    );
}

/// Test audit filter by actor.
#[test]
fn test_audit_filter_by_actor() {
    let actor_id = Uuid::new_v4();
    let filter = PersonaAuditEventFilter {
        actor_id: Some(actor_id),
        ..Default::default()
    };
    assert_eq!(filter.actor_id, Some(actor_id));
}

/// Test audit filter by date range.
#[test]
fn test_audit_filter_by_date_range() {
    let from_date = Utc::now() - Duration::days(7);
    let to_date = Utc::now();
    let filter = PersonaAuditEventFilter {
        from_date: Some(from_date),
        to_date: Some(to_date),
        ..Default::default()
    };
    assert_eq!(filter.from_date, Some(from_date));
    assert_eq!(filter.to_date, Some(to_date));
}

/// Test combined filter with multiple criteria.
#[test]
fn test_audit_filter_combined() {
    let persona_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let from_date = Utc::now() - Duration::days(30);

    let filter = PersonaAuditEventFilter {
        persona_id: Some(persona_id),
        actor_id: Some(actor_id),
        event_type: Some(PersonaAuditEventType::ContextSwitched),
        from_date: Some(from_date),
        ..Default::default()
    };

    assert_eq!(filter.persona_id, Some(persona_id));
    assert_eq!(filter.actor_id, Some(actor_id));
    assert_eq!(
        filter.event_type,
        Some(PersonaAuditEventType::ContextSwitched)
    );
    assert_eq!(filter.from_date, Some(from_date));
    assert!(filter.archetype_id.is_none());
    assert!(filter.to_date.is_none());
}

/// Test `PersonaCreatedEventData` structure.
#[test]
fn test_persona_created_event_data() {
    let persona_id = Uuid::new_v4();
    let archetype_id = Uuid::new_v4();
    let physical_user_id = Uuid::new_v4();
    let now = Utc::now();

    let data = PersonaCreatedEventData {
        persona_id,
        archetype_id,
        physical_user_id,
        persona_name: "test-persona".to_string(),
        initial_attributes: serde_json::json!({"key": "value"}),
        valid_from: now,
        valid_until: Some(now + Duration::days(30)),
    };

    assert_eq!(data.persona_id, persona_id);
    assert_eq!(data.archetype_id, archetype_id);
    assert_eq!(data.persona_name, "test-persona");
}

/// Test `ArchetypeEventData` structure.
#[test]
fn test_archetype_event_data() {
    let archetype_id = Uuid::new_v4();

    let data = ArchetypeEventData {
        archetype_id,
        name: "admin-archetype".to_string(),
        changes: Some(serde_json::json!({"field": "updated_value"})),
    };

    assert_eq!(data.archetype_id, archetype_id);
    assert_eq!(data.name, "admin-archetype");
    assert!(data.changes.is_some());
}

/// Test `ContextSwitchedEventData` structure.
#[test]
fn test_context_switched_event_data() {
    let session_id = Uuid::new_v4();
    let from_persona_id = Uuid::new_v4();
    let to_persona_id = Uuid::new_v4();

    let data = ContextSwitchedEventData {
        session_id,
        from_persona_id: Some(from_persona_id),
        to_persona_id: Some(to_persona_id),
        from_persona_name: Some("old-persona".to_string()),
        to_persona_name: Some("new-persona".to_string()),
        switch_reason: Some("Project assignment".to_string()),
        new_jwt_issued: true,
    };

    assert_eq!(data.session_id, session_id);
    assert_eq!(data.from_persona_id, Some(from_persona_id));
    assert_eq!(data.to_persona_id, Some(to_persona_id));
    assert_eq!(data.from_persona_name, Some("old-persona".to_string()));
    assert_eq!(data.to_persona_name, Some("new-persona".to_string()));
    assert!(data.new_jwt_issued);
}

/// Test `AttributesPropagatedEventData` structure.
#[test]
fn test_attributes_propagated_event_data() {
    let physical_user_id = Uuid::new_v4();
    let persona_id = Uuid::new_v4();
    let mut changed_attributes = serde_json::Map::new();
    changed_attributes.insert("department".to_string(), serde_json::json!("IT"));
    changed_attributes.insert("title".to_string(), serde_json::json!("Engineer"));

    let data = AttributesPropagatedEventData {
        physical_user_id,
        persona_id,
        changed_attributes,
        trigger: "user_update".to_string(),
    };

    assert_eq!(data.physical_user_id, physical_user_id);
    assert_eq!(data.persona_id, persona_id);
    assert_eq!(data.trigger, "user_update");
    assert_eq!(data.changed_attributes.len(), 2);
}

/// Test event type serialization.
#[test]
fn test_event_type_serialization() {
    let event_type = PersonaAuditEventType::PersonaCreated;
    let json = serde_json::to_string(&event_type).unwrap();
    assert!(json.contains("persona_created"));

    let event_type = PersonaAuditEventType::ContextSwitched;
    let json = serde_json::to_string(&event_type).unwrap();
    assert!(json.contains("context_switched"));

    let event_type = PersonaAuditEventType::PersonaExpired;
    let json = serde_json::to_string(&event_type).unwrap();
    assert!(json.contains("persona_expired"));
}

/// Test all event types are defined.
#[test]
fn test_all_event_types() {
    // Verify all event types exist and can be compared
    let event_types = [
        PersonaAuditEventType::ArchetypeCreated,
        PersonaAuditEventType::ArchetypeUpdated,
        PersonaAuditEventType::ArchetypeDeleted,
        PersonaAuditEventType::PersonaCreated,
        PersonaAuditEventType::PersonaActivated,
        PersonaAuditEventType::PersonaDeactivated,
        PersonaAuditEventType::PersonaExpired,
        PersonaAuditEventType::PersonaExtended,
        PersonaAuditEventType::PersonaArchived,
        PersonaAuditEventType::ContextSwitched,
        PersonaAuditEventType::ContextSwitchedBack,
        PersonaAuditEventType::AttributesPropagated,
        PersonaAuditEventType::EntitlementAdded,
        PersonaAuditEventType::EntitlementRemoved,
    ];

    assert_eq!(event_types.len(), 14);
}

/// Test filter date range validation (from < to).
#[test]
fn test_filter_date_range_valid() {
    let from_date = Utc::now() - Duration::days(7);
    let to_date = Utc::now();

    let filter = PersonaAuditEventFilter {
        from_date: Some(from_date),
        to_date: Some(to_date),
        ..Default::default()
    };

    // Verify from_date is before to_date
    assert!(filter.from_date.unwrap() < filter.to_date.unwrap());
}

/// Test event data JSON serialization roundtrip.
#[test]
fn test_event_data_json_roundtrip() {
    let original = PersonaCreatedEventData {
        persona_id: Uuid::new_v4(),
        archetype_id: Uuid::new_v4(),
        physical_user_id: Uuid::new_v4(),
        persona_name: "test-persona".to_string(),
        initial_attributes: serde_json::json!({"department": "IT", "level": 5}),
        valid_from: Utc::now(),
        valid_until: Some(Utc::now() + Duration::days(90)),
    };

    let json = serde_json::to_value(&original).unwrap();
    let roundtrip: PersonaCreatedEventData = serde_json::from_value(json).unwrap();

    assert_eq!(original.persona_id, roundtrip.persona_id);
    assert_eq!(original.persona_name, roundtrip.persona_name);
    assert_eq!(original.initial_attributes, roundtrip.initial_attributes);
}

/// Test `ContextSwitchedEventData` for switch-back scenario.
#[test]
fn test_context_switched_back_event_data() {
    let session_id = Uuid::new_v4();
    let from_persona_id = Uuid::new_v4();

    // Switch back to physical user (no to_persona_id)
    let data = ContextSwitchedEventData {
        session_id,
        from_persona_id: Some(from_persona_id),
        to_persona_id: None,
        from_persona_name: Some("admin-persona".to_string()),
        to_persona_name: None,
        switch_reason: Some("Session ended".to_string()),
        new_jwt_issued: true,
    };

    assert_eq!(data.from_persona_id, Some(from_persona_id));
    assert!(data.to_persona_id.is_none());
    assert!(data.to_persona_name.is_none());
}

/// Test filter with all fields populated.
#[test]
fn test_filter_all_fields() {
    let persona_id = Uuid::new_v4();
    let archetype_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let from_date = Utc::now() - Duration::days(30);
    let to_date = Utc::now();

    let filter = PersonaAuditEventFilter {
        persona_id: Some(persona_id),
        archetype_id: Some(archetype_id),
        event_type: Some(PersonaAuditEventType::PersonaCreated),
        actor_id: Some(actor_id),
        from_date: Some(from_date),
        to_date: Some(to_date),
    };

    assert_eq!(filter.persona_id, Some(persona_id));
    assert_eq!(filter.archetype_id, Some(archetype_id));
    assert_eq!(
        filter.event_type,
        Some(PersonaAuditEventType::PersonaCreated)
    );
    assert_eq!(filter.actor_id, Some(actor_id));
    assert_eq!(filter.from_date, Some(from_date));
    assert_eq!(filter.to_date, Some(to_date));
}
