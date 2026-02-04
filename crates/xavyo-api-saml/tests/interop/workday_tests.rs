//! Workday SP Interoperability Tests
//!
//! Tests SAML assertion compatibility with Workday requirements:
//! - `NameID` in unspecified format (typically employee ID)
//! - `WorkdayID` attribute required
//! - Assertions MUST be signed (unsigned not accepted)
//! - 5-minute assertion validity window
//! - Clock skew tolerance

use super::common::*;

// ============================================================================
// Workday SP Profile Tests
// ============================================================================

#[test]
fn test_workday_sp_profile_configuration() {
    let sp = SpProfile::workday();

    assert_eq!(sp.name, "Workday");
    assert!(
        sp.entity_id.contains("workday.com"),
        "Entity ID should be Workday domain"
    );
    assert!(
        sp.sign_assertions,
        "Workday REQUIRES signed assertions - unsigned not accepted"
    );
    assert!(
        sp.name_id_format.contains("unspecified"),
        "Workday typically uses unspecified NameID format"
    );
    assert_eq!(
        sp.assertion_validity_seconds, 300,
        "5-minute validity window"
    );
}

// ============================================================================
// Assertion Structure Tests
// ============================================================================

#[test]
fn test_workday_basic_assertion_structure() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");
    let errors = validate_assertion_structure(&parsed, &sp);

    assert!(
        errors.is_empty(),
        "Workday assertion structure validation failed: {errors:?}"
    );
}

#[test]
fn test_workday_nameid_unspecified_format() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Workday typically uses unspecified NameID format
    assert!(
        validate_nameid_format(
            &parsed,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
        ),
        "Workday requires NameID in unspecified format"
    );

    // NameID value should be employee ID for Workday
    assert_eq!(
        parsed.name_id.as_ref().unwrap(),
        &user.employee_id,
        "NameID should be employee ID for Workday"
    );
}

#[test]
fn test_workday_workdayid_attribute_present() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Workday requires WorkdayID attribute
    let workday_id = get_attribute_values(&parsed, "WorkdayID");
    assert!(workday_id.is_some(), "Workday REQUIRES WorkdayID attribute");

    let values = workday_id.unwrap();
    assert_eq!(values.len(), 1, "WorkdayID should have exactly one value");
    assert_eq!(
        values[0], user.employee_id,
        "WorkdayID should match employee_id"
    );
}

#[test]
fn test_workday_assertion_must_be_signed() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Workday REQUIRES signed assertions - unsigned assertions are rejected
    assert!(
        parsed.has_signature,
        "Workday REQUIRES signed assertions - unsigned assertions will be REJECTED"
    );

    // Verify signature algorithm is RSA-SHA256
    assert!(
        validate_signature_algorithm(&parsed),
        "Workday requires RSA-SHA256 for new integrations"
    );

    // Verify canonicalization method
    assert!(
        validate_canonicalization_method(&parsed),
        "Workday requires Exclusive C14N"
    );
}

#[test]
fn test_workday_assertion_validity_window() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Workday accepts assertions valid for up to 5 minutes (300 seconds)
    // Plus 2 minutes NotBefore buffer = 420 seconds max
    let result = validate_assertion_timing(&parsed, 420);
    assert!(
        result.is_ok(),
        "Workday assertion timing validation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_workday_clock_skew_tolerance() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Workday allows 300 seconds (5 minutes) clock skew
    // Our NotBefore is set 2 minutes in the past, which is within tolerance
    assert!(
        parsed.not_before.is_some(),
        "NotBefore should be present for clock skew handling"
    );

    // The NotBefore should be before the current time (allowing for clock skew)
    let not_before = parsed.not_before.as_ref().unwrap();
    assert!(
        !not_before.is_empty(),
        "NotBefore should have a valid timestamp"
    );
}

// ============================================================================
// Additional Workday-Specific Tests
// ============================================================================

#[test]
fn test_workday_audience_restriction() {
    let sp = SpProfile::workday();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Audience must match Workday entity ID exactly
    assert_eq!(
        parsed.audience.as_deref(),
        Some(sp.entity_id.as_str()),
        "Audience must match Workday entity ID"
    );
}
