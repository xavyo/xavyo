//! ServiceNow SP Interoperability Tests
//!
//! Tests SAML assertion compatibility with ServiceNow requirements:
//! - user_name, user_email, user_first_name, user_last_name attributes
//! - Multi-value Roles attribute for group membership
//! - SessionIndex in AuthnStatement
//! - NameID format respects SP metadata

use super::common::*;

// ============================================================================
// ServiceNow SP Profile Tests
// ============================================================================

#[test]
fn test_servicenow_sp_profile_configuration() {
    let sp = SpProfile::servicenow();

    assert_eq!(sp.name, "ServiceNow");
    assert_eq!(sp.entity_id, "https://company.service-now.com");
    assert_eq!(sp.acs_url, "https://company.service-now.com/navpage.do");
    assert!(sp.sign_assertions, "ServiceNow prefers signed assertions");
    assert_eq!(
        sp.group_attribute_name,
        Some("Roles".to_string()),
        "ServiceNow uses Roles for groups"
    );
}

// ============================================================================
// Assertion Structure Tests
// ============================================================================

#[test]
fn test_servicenow_basic_assertion_structure() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");
    let errors = validate_assertion_structure(&parsed, &sp);

    assert!(
        errors.is_empty(),
        "ServiceNow assertion structure validation failed: {:?}",
        errors
    );
}

#[test]
fn test_servicenow_user_name_attribute() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for user_name attribute
    let username = get_attribute_values(&parsed, "user_name");
    assert!(
        username.is_some(),
        "ServiceNow requires user_name attribute"
    );

    let values = username.unwrap();
    assert_eq!(values.len(), 1, "user_name should have one value");
    assert_eq!(
        values[0], user.username,
        "user_name should match user's username"
    );
}

#[test]
fn test_servicenow_user_email_attribute() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for user_email attribute
    let email = get_attribute_values(&parsed, "user_email");
    assert!(email.is_some(), "ServiceNow requires user_email attribute");

    let values = email.unwrap();
    assert_eq!(values.len(), 1, "user_email should have one value");
    assert_eq!(
        values[0], user.email,
        "user_email should match user's email"
    );
}

#[test]
fn test_servicenow_user_first_last_name_attributes() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for user_first_name
    let first_name = get_attribute_values(&parsed, "user_first_name");
    assert!(
        first_name.is_some(),
        "ServiceNow expects user_first_name attribute"
    );
    assert_eq!(first_name.unwrap()[0], user.first_name);

    // Check for user_last_name
    let last_name = get_attribute_values(&parsed, "user_last_name");
    assert!(
        last_name.is_some(),
        "ServiceNow expects user_last_name attribute"
    );
    assert_eq!(last_name.unwrap()[0], user.last_name);
}

#[test]
fn test_servicenow_multi_value_roles_attribute() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // Check for Roles attribute with multiple values
    let roles = get_attribute_values(&parsed, "Roles");
    assert!(
        roles.is_some(),
        "ServiceNow expects Roles attribute for groups"
    );

    let values = roles.unwrap();
    assert_eq!(
        values.len(),
        user.groups.len(),
        "Roles should have separate AttributeValue for each group"
    );

    // Each group should be present
    for group in &user.groups {
        assert!(
            values.contains(group),
            "Roles should contain group: {}",
            group
        );
    }
}

#[test]
fn test_servicenow_nameid_format_respects_metadata() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // ServiceNow typically uses emailAddress format
    assert!(
        validate_nameid_format(
            &parsed,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        ),
        "ServiceNow NameID format should match SP configuration"
    );
}

#[test]
fn test_servicenow_session_index_in_authn_statement() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // SessionIndex is important for ServiceNow session management
    assert!(
        parsed.session_index.is_some(),
        "ServiceNow requires SessionIndex in AuthnStatement"
    );

    // SessionIndex should be non-empty
    let session_index = parsed.session_index.unwrap();
    assert!(
        !session_index.is_empty(),
        "SessionIndex should not be empty"
    );
}

// ============================================================================
// Additional ServiceNow-Specific Tests
// ============================================================================

#[test]
fn test_servicenow_signature_present() {
    let sp = SpProfile::servicenow();
    let user = StandardTestUser::default();
    let xml = build_test_response(&sp, &user, None);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    assert!(
        parsed.has_signature,
        "ServiceNow prefers signed assertions"
    );
    assert!(
        validate_signature_algorithm(&parsed),
        "ServiceNow requires RSA-SHA256"
    );
}
