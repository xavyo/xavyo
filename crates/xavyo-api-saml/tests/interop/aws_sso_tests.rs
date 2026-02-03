//! AWS SSO (IAM Identity Center) Interoperability Tests
//!
//! Tests SAML assertion compatibility with AWS IAM Identity Center requirements:
//! - NameID in persistent format
//! - Role attribute with AWS namespace URI
//! - Role ARN pair format (role_arn,provider_arn)
//! - Multi-role support with separate AttributeValue elements
//! - RoleSessionName attribute
//! - SessionDuration attribute (900-43200 seconds)
//! - Audience urn:amazon:webservices

use super::common::*;

// ============================================================================
// AWS SSO SP Profile Tests
// ============================================================================

#[test]
fn test_aws_sso_sp_profile_configuration() {
    let sp = SpProfile::aws_sso();

    assert_eq!(sp.name, "AWS SSO");
    assert_eq!(sp.entity_id, "urn:amazon:webservices");
    assert_eq!(sp.acs_url, "https://signin.aws.amazon.com/saml");
    assert!(
        sp.name_id_format.contains("persistent"),
        "AWS SSO uses persistent NameID format"
    );
    assert!(sp.sign_assertions, "AWS SSO requires signed assertions");
}

// ============================================================================
// Assertion Structure Tests
// ============================================================================

#[test]
fn test_aws_sso_basic_assertion_structure() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");
    let errors = validate_assertion_structure(&parsed, &sp);

    assert!(
        errors.is_empty(),
        "AWS SSO assertion structure validation failed: {:?}",
        errors
    );
}

#[test]
fn test_aws_sso_nameid_persistent_format() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // AWS SSO requires persistent NameID format
    assert!(
        validate_nameid_format(
            &parsed,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        ),
        "AWS SSO requires NameID in persistent format"
    );

    // NameID should be unique and immutable (using UUID)
    assert!(
        parsed.name_id.is_some(),
        "NameID value should be present"
    );
}

#[test]
fn test_aws_sso_role_attribute_namespace_uri() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // AWS requires the exact namespace URI for Role attribute
    let role_attr = "https://aws.amazon.com/SAML/Attributes/Role";
    let roles = get_attribute_values(&parsed, role_attr);

    assert!(
        roles.is_some(),
        "AWS SSO requires Role attribute with exact namespace URI: {}",
        role_attr
    );
}

#[test]
fn test_aws_sso_role_arn_pair_format() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    let role_attr = "https://aws.amazon.com/SAML/Attributes/Role";
    let roles = get_attribute_values(&parsed, role_attr).expect("Role attribute required");

    // Each role value must be in format: role_arn,provider_arn
    for role_value in &roles {
        assert!(
            role_value.contains(','),
            "Role value must contain comma separator: {}",
            role_value
        );

        let parts: Vec<&str> = role_value.split(',').collect();
        assert_eq!(
            parts.len(),
            2,
            "Role value must have exactly 2 parts (role_arn,provider_arn)"
        );

        // First part should be role ARN
        assert!(
            parts[0].starts_with("arn:aws:iam::"),
            "First part must be IAM role ARN: {}",
            parts[0]
        );
        assert!(
            parts[0].contains(":role/"),
            "First part must contain :role/: {}",
            parts[0]
        );

        // Second part should be provider ARN
        assert!(
            parts[1].starts_with("arn:aws:iam::"),
            "Second part must be IAM provider ARN: {}",
            parts[1]
        );
        assert!(
            parts[1].contains(":saml-provider/"),
            "Second part must contain :saml-provider/: {}",
            parts[1]
        );
    }
}

#[test]
fn test_aws_sso_multi_role_separate_attribute_values() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    let role_attr = "https://aws.amazon.com/SAML/Attributes/Role";
    let roles = get_attribute_values(&parsed, role_attr).expect("Role attribute required");

    // User has 2 roles, each should be a separate AttributeValue
    assert_eq!(
        roles.len(),
        user.aws_roles.len(),
        "Each role should be a separate AttributeValue element (not comma-separated in one value)"
    );

    // Verify all configured roles are present
    for expected_role in &user.aws_roles {
        assert!(
            roles.contains(expected_role),
            "Missing role: {}",
            expected_role
        );
    }
}

#[test]
fn test_aws_sso_role_session_name_attribute() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // RoleSessionName is required by AWS
    let session_name_attr = "https://aws.amazon.com/SAML/Attributes/RoleSessionName";
    let session_name = get_attribute_values(&parsed, session_name_attr);

    assert!(
        session_name.is_some(),
        "AWS SSO requires RoleSessionName attribute"
    );

    let values = session_name.unwrap();
    assert_eq!(values.len(), 1, "RoleSessionName should have one value");
    assert_eq!(
        values[0], user.username,
        "RoleSessionName should be the username"
    );

    // RoleSessionName becomes the principal name in CloudTrail
    // Max 64 characters, must match [\w+=,.@-]*
    assert!(
        values[0].len() <= 64,
        "RoleSessionName must be <= 64 characters"
    );
}

#[test]
fn test_aws_sso_session_duration_attribute() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // SessionDuration is optional but commonly used
    let duration_attr = "https://aws.amazon.com/SAML/Attributes/SessionDuration";
    let duration = get_attribute_values(&parsed, duration_attr);

    assert!(
        duration.is_some(),
        "AWS SSO should have SessionDuration attribute when configured"
    );

    let values = duration.unwrap();
    assert_eq!(values.len(), 1, "SessionDuration should have one value");

    // Parse as integer and validate range (900-43200 seconds)
    let duration_seconds: i32 = values[0]
        .parse()
        .expect("SessionDuration must be a valid integer");

    assert!(
        (900..=43200).contains(&duration_seconds),
        "SessionDuration must be between 900 and 43200 seconds, got: {}",
        duration_seconds
    );
}

#[test]
fn test_aws_sso_audience_restriction_amazon_webservices() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    // AWS SSO requires specific audience
    assert_eq!(
        parsed.audience.as_deref(),
        Some("urn:amazon:webservices"),
        "AWS SSO requires Audience to be urn:amazon:webservices"
    );
}

// ============================================================================
// Additional AWS-Specific Tests
// ============================================================================

#[test]
fn test_aws_sso_signature_algorithm() {
    let sp = SpProfile::aws_sso();
    let user = AwsRoleTestUser::default();
    let xml = build_aws_test_response(&sp, &user);

    let parsed = parse_saml_xml(&xml).expect("Should parse SAML XML");

    assert!(parsed.has_signature, "AWS SSO requires signed assertions");
    assert!(
        validate_signature_algorithm(&parsed),
        "AWS SSO requires RSA-SHA256 (SHA-1 deprecated)"
    );
}
