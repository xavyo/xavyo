//! GDPR/Data Protection Metadata tests (F-067).
//!
//! Verifies struct construction, validation, serialization, and filtering
//! of GDPR metadata on entitlements.

use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovEntitlement, DataProtectionClassification, EntitlementFilter, GdprLegalBasis,
    GovEntitlement, GovEntitlementStatus, GovRiskLevel, UpdateGovEntitlement,
};

use xavyo_api_governance::models::{
    validate_gdpr_create, validate_gdpr_update, ClassifiedEntitlementDetail, EntitlementResponse,
    GdprReport, UserDataProtectionSummary,
};

/// Helper: build a GovEntitlement with given GDPR fields.
fn make_entitlement(
    name: &str,
    classification: DataProtectionClassification,
    legal_basis: Option<GdprLegalBasis>,
    retention_period_days: Option<i32>,
) -> GovEntitlement {
    GovEntitlement {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        application_id: Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        risk_level: GovRiskLevel::Low,
        status: GovEntitlementStatus::Active,
        owner_id: None,
        external_id: None,
        metadata: None,
        is_delegable: true,
        data_protection_classification: classification,
        legal_basis,
        retention_period_days,
        data_controller: None,
        data_processor: None,
        purposes: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// =============================================================================
// Phase 3: User Story 1 — Classify Entitlements
// =============================================================================

/// T011: Default classification is "none" for new GovEntitlement.
#[test]
fn test_data_protection_classification_default() {
    let ent = make_entitlement(
        "Test Entitlement",
        DataProtectionClassification::default(),
        None,
        None,
    );

    assert_eq!(
        ent.data_protection_classification,
        DataProtectionClassification::None
    );
    assert!(ent.legal_basis.is_none());
    assert!(ent.retention_period_days.is_none());
    assert!(ent.data_controller.is_none());
    assert!(ent.data_processor.is_none());
    assert!(ent.purposes.is_none());
}

/// T012: All GDPR fields are persisted on create.
#[test]
fn test_create_entitlement_with_gdpr_fields() {
    let input = CreateGovEntitlement {
        application_id: Uuid::new_v4(),
        name: "PII Access".to_string(),
        description: Some("Accesses personal data".to_string()),
        risk_level: GovRiskLevel::High,
        owner_id: None,
        external_id: None,
        metadata: None,
        is_delegable: true,
        data_protection_classification: DataProtectionClassification::Sensitive,
        legal_basis: Some(GdprLegalBasis::Consent),
        retention_period_days: Some(365),
        data_controller: Some("Acme Corp".to_string()),
        data_processor: Some("DataProc Inc".to_string()),
        purposes: Some(vec!["analytics".to_string(), "personalization".to_string()]),
    };

    assert_eq!(
        input.data_protection_classification,
        DataProtectionClassification::Sensitive
    );
    assert_eq!(input.legal_basis, Some(GdprLegalBasis::Consent));
    assert_eq!(input.retention_period_days, Some(365));
    assert_eq!(input.data_controller.as_deref(), Some("Acme Corp"));
    assert_eq!(input.data_processor.as_deref(), Some("DataProc Inc"));
    assert_eq!(input.purposes.as_ref().unwrap().len(), 2);
}

/// T013: Classification can be changed from none to personal/sensitive/special_category.
#[test]
fn test_update_entitlement_gdpr_classification() {
    let update = UpdateGovEntitlement {
        name: None,
        description: None,
        risk_level: None,
        status: None,
        owner_id: None,
        external_id: None,
        metadata: None,
        is_delegable: None,
        data_protection_classification: Some(DataProtectionClassification::SpecialCategory),
        legal_basis: Some(GdprLegalBasis::LegalObligation),
        retention_period_days: Some(730),
        data_controller: Some("Health Corp".to_string()),
        data_processor: None,
        purposes: Some(vec!["medical_records".to_string()]),
    };

    assert_eq!(
        update.data_protection_classification,
        Some(DataProtectionClassification::SpecialCategory)
    );
    assert_eq!(update.legal_basis, Some(GdprLegalBasis::LegalObligation));
    assert_eq!(update.retention_period_days, Some(730));
    assert_eq!(update.data_controller.as_deref(), Some("Health Corp"));
    assert!(update.data_processor.is_none());
    assert_eq!(update.purposes.as_ref().unwrap().len(), 1);

    // Verify all classification variants work
    for classification in [
        DataProtectionClassification::Personal,
        DataProtectionClassification::Sensitive,
        DataProtectionClassification::SpecialCategory,
    ] {
        let json = serde_json::to_string(&classification).unwrap();
        let deserialized: DataProtectionClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, classification);
    }
}

/// T014: Error when legal_basis is set but classification is "none".
#[test]
fn test_gdpr_validation_legal_basis_requires_classification() {
    // Create: legal_basis with classification=none should fail
    let result = validate_gdpr_create(
        Some(DataProtectionClassification::None),
        Some(GdprLegalBasis::Consent),
        None,
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("legal_basis requires data_protection_classification"));

    // Create: legal_basis with classification=personal should succeed
    let result = validate_gdpr_create(
        Some(DataProtectionClassification::Personal),
        Some(GdprLegalBasis::Consent),
        None,
    );
    assert!(result.is_ok());

    // Create: no legal_basis with classification=none should succeed
    let result = validate_gdpr_create(Some(DataProtectionClassification::None), None, None);
    assert!(result.is_ok());

    // Update: legal_basis with existing classification=none should fail
    let result = validate_gdpr_update(
        None,                               // not changing classification
        DataProtectionClassification::None, // existing is none
        Some(GdprLegalBasis::Contract),
        None,
    );
    assert!(result.is_err());

    // Update: legal_basis with new classification=sensitive should succeed
    let result = validate_gdpr_update(
        Some(DataProtectionClassification::Sensitive),
        DataProtectionClassification::None,
        Some(GdprLegalBasis::Contract),
        None,
    );
    assert!(result.is_ok());
}

/// T015: Error when retention_period_days is 0 or negative.
#[test]
fn test_gdpr_validation_retention_period_positive() {
    // Zero days should fail
    let result = validate_gdpr_create(Some(DataProtectionClassification::Personal), None, Some(0));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("retention_period_days must be a positive integer"));

    // Negative days should fail
    let result = validate_gdpr_create(
        Some(DataProtectionClassification::Personal),
        None,
        Some(-30),
    );
    assert!(result.is_err());

    // Positive days should succeed
    let result = validate_gdpr_create(
        Some(DataProtectionClassification::Personal),
        None,
        Some(365),
    );
    assert!(result.is_ok());

    // Update: negative days should fail
    let result = validate_gdpr_update(None, DataProtectionClassification::Personal, None, Some(-1));
    assert!(result.is_err());
}

// =============================================================================
// Phase 4: User Story 2 — Filter Entitlements by Classification
// =============================================================================

/// T016: EntitlementFilter correctly accepts classification filter.
#[test]
fn test_filter_entitlements_by_classification() {
    let filter = EntitlementFilter {
        data_protection_classification: Some(DataProtectionClassification::Sensitive),
        ..Default::default()
    };

    assert_eq!(
        filter.data_protection_classification,
        Some(DataProtectionClassification::Sensitive)
    );
    assert!(filter.application_id.is_none());
    assert!(filter.status.is_none());
    assert!(filter.risk_level.is_none());

    // Default filter has no classification
    let default_filter = EntitlementFilter::default();
    assert!(default_filter.data_protection_classification.is_none());
}

/// T017: Classification filter works combined with other filters.
#[test]
fn test_filter_classification_combined_with_other_filters() {
    let app_id = Uuid::new_v4();
    let filter = EntitlementFilter {
        application_id: Some(app_id),
        status: Some(GovEntitlementStatus::Active),
        data_protection_classification: Some(DataProtectionClassification::Personal),
        ..Default::default()
    };

    assert_eq!(filter.application_id, Some(app_id));
    assert_eq!(filter.status, Some(GovEntitlementStatus::Active));
    assert_eq!(
        filter.data_protection_classification,
        Some(DataProtectionClassification::Personal)
    );
}

// =============================================================================
// Phase 5: User Story 3 — GDPR Compliance Report
// =============================================================================

/// T023: GDPR report struct contains correct counts and structures.
#[test]
fn test_gdpr_report_classification_summary() {
    let tenant_id = Uuid::new_v4();

    let mut classification_summary = HashMap::new();
    classification_summary.insert("none".to_string(), 5);
    classification_summary.insert("personal".to_string(), 3);
    classification_summary.insert("sensitive".to_string(), 2);
    classification_summary.insert("special_category".to_string(), 1);

    let mut legal_basis_summary = HashMap::new();
    legal_basis_summary.insert("consent".to_string(), 4);
    legal_basis_summary.insert("contract".to_string(), 2);

    let detail = ClassifiedEntitlementDetail {
        entitlement_id: Uuid::new_v4(),
        entitlement_name: "Customer PII".to_string(),
        application_name: "CRM".to_string(),
        classification: DataProtectionClassification::Personal,
        legal_basis: Some(GdprLegalBasis::Consent),
        retention_period_days: Some(365),
        data_controller: Some("Acme Corp".to_string()),
        data_processor: Some("DataProc Inc".to_string()),
        purposes: Some(vec!["marketing".to_string()]),
        active_assignment_count: 42,
    };

    let report = GdprReport {
        tenant_id,
        generated_at: Utc::now(),
        total_entitlements: 11,
        classified_entitlements: 6,
        classification_summary: classification_summary.clone(),
        legal_basis_summary: legal_basis_summary.clone(),
        classified_entitlements_detail: vec![detail.clone()],
        entitlements_with_retention: vec![detail],
    };

    assert_eq!(report.tenant_id, tenant_id);
    assert_eq!(report.total_entitlements, 11);
    assert_eq!(report.classified_entitlements, 6);
    assert_eq!(report.classification_summary.get("personal"), Some(&3));
    assert_eq!(report.classification_summary.get("sensitive"), Some(&2));
    assert_eq!(report.legal_basis_summary.get("consent"), Some(&4));
    assert_eq!(report.classified_entitlements_detail.len(), 1);
    assert_eq!(report.entitlements_with_retention.len(), 1);
    assert_eq!(
        report.classified_entitlements_detail[0].active_assignment_count,
        42
    );

    // Verify JSON serialization round-trip
    let json = serde_json::to_string(&report).unwrap();
    let deserialized: GdprReport = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.total_entitlements, 11);
    assert_eq!(deserialized.classified_entitlements, 6);
}

// =============================================================================
// Phase 6: User Story 4 — Per-User Data Protection Summary
// =============================================================================

/// T027: UserDataProtectionSummary correctly aggregates classified entitlements.
#[test]
fn test_user_data_protection_summary() {
    let user_id = Uuid::new_v4();

    // Create some classified entitlements
    let ent1 = make_entitlement(
        "Customer Data",
        DataProtectionClassification::Personal,
        Some(GdprLegalBasis::Consent),
        Some(365),
    );
    let ent2 = make_entitlement(
        "Health Records",
        DataProtectionClassification::SpecialCategory,
        Some(GdprLegalBasis::LegalObligation),
        Some(3650),
    );

    let entitlements: Vec<EntitlementResponse> =
        vec![ent1, ent2].into_iter().map(Into::into).collect();

    let mut classifications = HashMap::new();
    classifications.insert("personal".to_string(), 1);
    classifications.insert("special_category".to_string(), 1);

    let summary = UserDataProtectionSummary {
        user_id,
        entitlements: entitlements.clone(),
        total_classified: 2,
        classifications: classifications.clone(),
    };

    assert_eq!(summary.user_id, user_id);
    assert_eq!(summary.total_classified, 2);
    assert_eq!(summary.entitlements.len(), 2);
    assert_eq!(summary.classifications.get("personal"), Some(&1));
    assert_eq!(summary.classifications.get("special_category"), Some(&1));

    // Verify GDPR fields are present in EntitlementResponse
    assert_eq!(
        entitlements[0].data_protection_classification,
        DataProtectionClassification::Personal
    );
    assert_eq!(entitlements[0].legal_basis, Some(GdprLegalBasis::Consent));
    assert_eq!(entitlements[0].retention_period_days, Some(365));

    // Verify JSON serialization
    let json = serde_json::to_string(&summary).unwrap();
    let deserialized: UserDataProtectionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.total_classified, 2);
}
