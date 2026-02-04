//! Salesforce SP Interoperability Tests
//!
//! Tests SAML assertion compatibility with Salesforce requirements:
//! - `NameID` in emailAddress format
//! - `FederationIdentifier` attribute
//! - User.Email attribute
//! - RSA-SHA256 signature algorithm
//! - Exclusive C14N canonicalization
//! - 5-minute assertion validity window

use super::common::*;

// ============================================================================
// Salesforce SP Profile Tests
// ============================================================================

#[test]
fn test_salesforce_sp_profile_configuration() {
    let sp = SpProfile::salesforce();

    assert_eq!(sp.name, "Salesforce");
    assert_eq!(sp.entity_id, "https://company.my.salesforce.com");
    assert_eq!(sp.acs_url, "https://company.my.salesforce.com/saml/acs");
    assert!(sp.sign_assertions, "Salesforce requires signed assertions");
    assert_eq!(
        sp.assertion_validity_seconds, 300,
        "5-minute validity window"
    );
}

// ============================================================================
// Assertion Structure Tests
// ============================================================================

#[test]
fn test_salesforce_basic_assertion_structure() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");
    let errors = validate_assertion_structure(&parsed, &sp);

    assert!(
        errors.is_empty(),
        "Salesforce assertion structure validation failed: {errors:?}"
    );

    // Verify required elements
    assert!(parsed.response_id.is_some(), "Response ID required");
    assert!(parsed.assertion_id.is_some(), "Assertion ID required");
    assert!(parsed.issuer.is_some(), "Issuer required");
    assert!(parsed.name_id.is_some(), "NameID required");
    assert!(parsed.not_before.is_some(), "NotBefore required");
    assert!(parsed.not_on_or_after.is_some(), "NotOnOrAfter required");
}

#[test]
fn test_salesforce_nameid_email_format() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Salesforce requires emailAddress format
    assert!(
        validate_nameid_format(
            &parsed,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        "Salesforce requires NameID in emailAddress format"
    );

    // NameID value should be the user's email
    assert_eq!(
        parsed.name_id.as_ref().unwrap(),
        &user.email,
        "NameID should be user's email"
    );
}

#[test]
fn test_salesforce_federation_identifier_attribute() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for FederationIdentifier attribute
    let fed_id = get_attribute_values(&parsed, "User.FederationIdentifier");
    assert!(
        fed_id.is_some(),
        "Salesforce requires User.FederationIdentifier attribute"
    );

    let values = fed_id.unwrap();
    assert_eq!(
        values.len(),
        1,
        "FederationIdentifier should have one value"
    );
    assert_eq!(
        values[0], user.federation_id,
        "FederationIdentifier should match user's federation_id"
    );
}

#[test]
fn test_salesforce_user_email_attribute() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for User.Email attribute
    let email = get_attribute_values(&parsed, "User.Email");
    assert!(email.is_some(), "Salesforce expects User.Email attribute");

    let values = email.unwrap();
    assert_eq!(values.len(), 1, "User.Email should have one value");
    assert_eq!(
        values[0], user.email,
        "User.Email should match user's email"
    );

    // Validate email format (basic check)
    assert!(values[0].contains('@'), "Email should contain @ symbol");
}

#[test]
fn test_salesforce_relaystate_preservation() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();

    // Generate response with InResponseTo (simulating SP-initiated SSO)
    let request_id = "_authn_req_12345";
    let xml = build_test_response(&sp, &user, Some(request_id));

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // InResponseTo should be preserved
    assert_eq!(
        parsed.in_response_to.as_deref(),
        Some(request_id),
        "InResponseTo should preserve the original request ID"
    );
}

#[test]
fn test_salesforce_signature_algorithm_rsa_sha256() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Salesforce requires signed assertions
    assert!(
        parsed.has_signature,
        "Salesforce requires signed assertions"
    );

    // Signature algorithm should be RSA-SHA256
    assert!(
        validate_signature_algorithm(&parsed),
        "Salesforce requires RSA-SHA256 signature algorithm"
    );
}

#[test]
fn test_salesforce_assertion_validity_window() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Salesforce accepts assertions valid for up to 5 minutes + clock skew
    // Our assertions should be within 5 minutes (300 seconds) + 2 min buffer = ~420 seconds max
    let result = validate_assertion_timing(&parsed, 420);
    assert!(
        result.is_ok(),
        "Assertion timing validation failed: {:?}",
        result.err()
    );
}

#[test]
fn test_salesforce_audience_restriction_matches_entity_id() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Audience should match SP entity_id exactly
    assert_eq!(
        parsed.audience.as_deref(),
        Some(sp.entity_id.as_str()),
        "Audience must match Salesforce entity ID exactly"
    );
}

// ============================================================================
// Additional Salesforce-Specific Tests
// ============================================================================

#[test]
fn test_salesforce_canonicalization_method() {
    let sp = SpProfile::salesforce();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Salesforce requires Exclusive C14N
    assert!(
        validate_canonicalization_method(&parsed),
        "Salesforce requires Exclusive C14N canonicalization"
    );
}
